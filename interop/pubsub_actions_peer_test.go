//go:build interop

// SPDX-License-Identifier: MIT

// PubSub Actions (Part 14 §5.4.2) through a real broker.
// COVERAGE.md: pubsub / pubsub.actions
//
// No other stack implements PubSub Actions (open62541 1.5.9 and
// Opc.Ua.PubSub 2.0.1 have none, the other peers no PubSub), so this is
// go-opcua to go-opcua through Eclipse Mosquitto: a client configures a
// PublishedAction with its connection, group and writer on a go-opcua server
// through the PubSubConfiguration file (ReserveIds, CloseAndUpdate,
// §9.1.3.7), a standalone Requestor discovers it from the retained
// ActionMetaData and calls it, with a UADP request that goes in chunks.

package interop

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func TestPubSubMQTT_Actions(t *testing.T) {
	broker := startMosquitto(t)
	connURL := fmt.Sprintf("mqtt://127.0.0.1:%d", broker)
	port := freePort(t)
	srv, err := server.New(
		server.EndPoint("127.0.0.1", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.WithPubSub(nil),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ctx := context.Background()
	c, err := opcua.NewClient(fmt.Sprintf("opc.tcp://127.0.0.1:%d", port), opcua.InsecureNoSecurity(), opcua.AutoReconnect(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	r := remote.New(c)

	n := psFresh()
	for i, m := range []pubsub.MessageMapping{pubsub.MappingUADP, pubsub.MappingJSON} {
		name := []string{"uadp", "json"}[i]
		t.Run(name, func(t *testing.T) {
			pub := fmt.Sprintf("interop-responder-%s-%d", name, n)
			prefix := fmt.Sprintf("go-opcua-interop/actions/%d", n)
			queue := pubsub.ActionRequestTopic(prefix, m, pub, "Actions")
			meta := pubsub.ActionMetaDataTopic(prefix, m, pub, "Actions", "ReverseWriter")
			dataSet := "Reverse-" + name
			srv.PubSub().SetActionHandler(dataSet, 1, func(_ context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
				s, ok := in[0].Value().(string)
				if !ok {
					return nil, ua.StatusBadTypeMismatch
				}
				return []*ua.Variant{ua.MustVariant(reverseString(s))}, ua.StatusGood
			})

			ids, err := r.ReserveIDs(ctx, transport.ProfileMQTTUADP, 1, 1)
			if err != nil {
				t.Fatalf("ReserveIds: %v", err)
			}
			w := pubsub.SetWriterQueue(pubsub.DataSetWriter("ReverseWriter", ids.DataSetWriterIDs[0], dataSet), "", meta)
			var g *ua.WriterGroupDataType
			if m == pubsub.MappingJSON {
				g = pubsub.JSONWriterGroup("Actions", ids.WriterGroupIDs[0], 0, queue, w)
			} else {
				g = pubsub.WriterGroup("Actions", ids.WriterGroupIDs[0], 0, w)
				g.TransportSettings = ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{QueueName: queue,
					RequestedDeliveryGuarantee: ua.BrokerTransportQoSAtLeastOnce})
			}
			action := pubsub.PublishedActions(dataSet, []pubsub.Field{{Name: "s", Type: ua.TypeIDString}}, []pubsub.Field{{Name: "r", Type: ua.TypeIDString}},
				pubsub.ActionTargetOf(1, "Reverse"))
			res, err := r.UpdateConfiguration(ctx, &ua.PubSubConfiguration2DataType{
				PublishedDataSets: []*ua.PublishedDataSetDataType{action},
				Connections:       []*ua.PubSubConnectionDataType{pubsub.AttachWriterGroups(pubsub.MQTTConnection("Responder-"+name, connURL, pub, m), g)},
			}, []*ua.PubSubConfigurationRefDataType{
				remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferencePubDataset, 0, 0, 0),
				remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceConnection, 0, 0, 0),
				remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceWriterGroup, 0, 0, 0),
				remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceWriter, 0, 0, 0),
			}, true)
			if err != nil {
				t.Fatalf("CloseAndUpdate: %v", err)
			}
			if !res.ChangesApplied {
				t.Fatalf("CloseAndUpdate applied nothing: %v", res.Results)
			}

			req := startRuntime(t, pubsub.NewConfiguration(nil, pubsub.MQTTConnection("Requestor", connURL, "interop-requestor-"+name, m)))
			reqConn, ok := req.Lookup(pubsub.KindConnection, pubsub.Root, "Requestor")
			if !ok {
				t.Fatal("no Requestor connection")
			}
			for deadline := time.Now().Add(psReceiveTimeout); ; time.Sleep(20 * time.Millisecond) {
				if st, err := req.Status(reqConn); err == nil && st.State == ua.PubSubStateOperational {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the Requestor connection did not become Operational")
				}
			}
			tg := pubsub.ActionTarget{Connection: "Requestor", PublisherID: pub, DataSetWriterID: ids.DataSetWriterIDs[0], ActionTargetID: 1,
				RequestAddress: queue, MetaDataAddress: meta, Timeout: 10 * time.Second}
			dctx, cancel := context.WithTimeout(ctx, psReceiveTimeout)
			defer cancel()
			md, err := req.DiscoverAction(dctx, tg)
			if err != nil {
				t.Fatalf("DiscoverAction: %v", err)
			}
			if got := md.Target(1); got == nil || got.Name != "Reverse" {
				t.Fatalf("discovered target %+v, want Reverse", got)
			}
			call := md.Apply(tg)
			in := "go-opcua interop " + name
			if m == pubsub.MappingUADP {
				// A request of 8 KB in chunks of at most 1 KB.
				in = strings.Repeat("abcdefgh", 1024)
				call.MaxNetworkMessageSize = 1024
			}
			out, err := req.CallAction(ctx, call, []*ua.Variant{ua.MustVariant(in)})
			if err != nil {
				t.Fatalf("CallAction: %v", err)
			}
			if out.Status != ua.StatusGood || len(out.Outputs) != 1 || out.Outputs[0].Value() != reverseString(in) {
				t.Fatalf("CallAction: status %v, outputs %v", out.Status, out.Outputs)
			}
			if m == pubsub.MappingUADP {
				st, err := req.Status(pubsub.Root)
				if err != nil {
					t.Fatal(err)
				}
				if st.Counters.ChunksSent < 8 {
					t.Errorf("the request went in %d chunks, want at least 8", st.Counters.ChunksSent)
				}
			}
		})
	}
}
