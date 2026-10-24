// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/ua"
)

// blobPDS is a PublishedAction "Blob" whose target 1 "Reverse" takes a
// String and returns it reversed.
func blobPDS() *ua.PublishedDataSetDataType {
	return PublishedActions("Blob",
		[]Field{{Name: "Data", Type: ua.TypeIDString}},
		[]Field{{Name: "Reversed", Type: ua.TypeIDString}},
		ActionTargetOf(1, "Reverse"))
}

func reverseHandler(_ context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	s, _ := in[0].Value().(string)
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return []*ua.Variant{ua.MustVariant(string(r))}, ua.StatusGood
}

func blobTarget(conn string) ActionTarget {
	return ActionTarget{Connection: conn, PublisherID: uint16(1), DataSetWriterID: 100, ActionTargetID: 1,
		Timeout:               5 * time.Second,
		MaxNetworkMessageSize: 400,
		RequestMetaData:       MetaData("BlobRequest", Field{Name: "Data", Type: ua.TypeIDString}),
		ResponseMetaData:      MetaData("Blob", Field{Name: "Reversed", Type: ua.TypeIDString}),
	}
}

func blob(i int) string {
	return fmt.Sprintf("%04d:", i) + strings.Repeat(fmt.Sprintf("%c", 'a'+i%26), 6000)
}

// callBlobs calls the Reverse target with a large input from each
// Requestor, concurrently, and checks every result.
func callBlobs(t *testing.T, tg func(i int) ActionTarget, reqs ...*PubSub) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, 4*len(reqs))
	for i, req := range reqs {
		for j := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				in := blob(i*4 + j)
				res, err := req.CallAction(context.Background(), tg(i), []*ua.Variant{ua.MustVariant(in)})
				if err != nil {
					errs <- err
					return
				}
				want, _ := reverseHandler(context.Background(), []*ua.Variant{ua.MustVariant(in)})
				if res.Status != ua.StatusGood || len(res.Outputs) != 1 || res.Outputs[0].Value() != want[0].Value() {
					errs <- fmt.Errorf("call %d/%d: status %v, %d outputs", i, j, res.Status, len(res.Outputs))
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestE2EActionChunksUDP: requests and responses larger than the
// MaxNetworkMessageSize go as UADP chunks (Part 14 §7.2.4.4.4), unsecured
// and SignAndEncrypt, from two Requestors calling one writer concurrently;
// the chunks of their messages do not mix.
func TestE2EActionChunksUDP(t *testing.T) {
	t.Parallel()
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			respURL := fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t))
			var opts []Option
			g := WriterGroup("Actions", 10, 50*time.Millisecond, DataSetWriter("BlobWriter", 100, "Blob"))
			g.MaxNetworkMessageSize = 400
			if mode > ua.MessageSecurityModeNone {
				ks := regressKeys(t, "sg")
				opts = append(opts, WithKeySource("sg", regressSource(t, ks, "sg")))
				Secure(g, mode, "sg")
			}
			resp := startReal(t, NewConfiguration([]*ua.PublishedDataSetDataType{blobPDS()},
				AttachWriterGroups(UDPConnection("Responder", respURL, uint16(1)), g)),
				append(opts, WithActionHandler("Blob", 1, reverseHandler))...)
			var reqs []*PubSub
			for i := range 2 {
				url := fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t))
				reqs = append(reqs, startReal(t, NewConfiguration(nil, UDPConnection("Requestor", url, uint16(2+i))), opts...))
			}
			waitRunning(t, resp, "Responder")
			for _, req := range reqs {
				waitRunning(t, req, "Requestor")
			}
			waitResponder(t, resp)
			callBlobs(t, func(int) ActionTarget {
				tg := blobTarget("Requestor")
				tg.RequestAddress = respURL
				tg.ResendInterval = 200 * time.Millisecond
				tg.SecurityMode, tg.SecurityGroupID = mode, "sg"
				if mode == ua.MessageSecurityModeNone {
					tg.SecurityGroupID = ""
				}
				return tg
			}, reqs...)

			gid := mustID(t, resp, KindWriterGroup, mustID(t, resp, KindConnection, Root, "Responder"), "Actions")
			rc := actCounters(resp, mustID(t, resp, KindConnection, Root, "Responder"))
			require.Positive(t, actCounters(resp, gid).ChunksSent, "the responses are chunked")
			require.GreaterOrEqual(t, rc.ChunkedMessagesReceived, uint64(8), "the requests are reassembled")
			for _, req := range reqs {
				c := actCounters(req, mustID(t, req, KindConnection, Root, "Requestor"))
				require.Positive(t, c.ChunksSent, "the requests are chunked")
				require.Positive(t, c.ChunkedMessagesReceived, "the responses are reassembled")
				require.Zero(t, c.DecodeErrors)
			}
			require.Zero(t, rc.DecodeErrors)
		})
	}
}

// TestE2EActionChunksMQTT: UADP action messages larger than the
// MaxNetworkMessageSize are chunked over a broker too; JSON action messages
// cannot be chunked and a request that is too large fails.
func TestE2EActionChunksMQTT(t *testing.T) {
	t.Parallel()
	b := mqttbroker.New(mqttbroker.Options{})
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	queue := ActionRequestTopic("chunks", MappingUADP, "1", "Actions")
	g := WriterGroup("Actions", 10, 0, DataSetWriter("BlobWriter", 100, "Blob"))
	g.MaxNetworkMessageSize = 400
	g.TransportSettings = ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{QueueName: queue,
		RequestedDeliveryGuarantee: ua.BrokerTransportQoSAtLeastOnce})
	resp := startReal(t, NewConfiguration([]*ua.PublishedDataSetDataType{blobPDS()},
		AttachWriterGroups(MQTTConnection("Responder", b.URL(), uint16(1), MappingUADP), g)),
		WithActionHandler("Blob", 1, reverseHandler))
	req := startReal(t, NewConfiguration(nil, MQTTConnection("Requestor", b.URL(), uint16(2), MappingUADP)))
	waitRunning(t, resp, "Responder")
	waitRunning(t, req, "Requestor")
	waitResponder(t, resp)
	callBlobs(t, func(int) ActionTarget {
		tg := blobTarget("Requestor")
		tg.RequestAddress = queue
		return tg
	}, req)
	c := actCounters(req, mustID(t, req, KindConnection, Root, "Requestor"))
	require.Positive(t, c.ChunksSent)
	require.Positive(t, c.ChunkedMessagesReceived)

	// JSON: a request beyond the MaxNetworkMessageSize is not sent.
	jq := ActionRequestTopic("chunks", MappingJSON, "1", "Actions")
	jreq := startReal(t, NewConfiguration(nil, MQTTConnection("Requestor", b.URL(), uint16(3), MappingJSON)))
	waitRunning(t, jreq, "Requestor")
	tg := blobTarget("Requestor")
	tg.RequestAddress = jq
	tg.Timeout = time.Second
	_, err := jreq.CallAction(context.Background(), tg, []*ua.Variant{ua.MustVariant(blob(1))})
	require.ErrorIs(t, err, errTooLarge)
}
