// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// PubSub Actions (Part 14 §5.4.2) with requests and responses larger than
// the MaxNetworkMessageSize, so chunked (§7.2.4.4.4), over a network that
// loses, duplicates, reorders, delays, truncates and (secured) corrupts
// the chunks, while forged action chunks come in.

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func reverseAction(_ context.Context, in []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	s, _ := in[0].Value().(string)
	return []*ua.Variant{ua.MustVariant(reverse(s))}, ua.StatusGood
}

// actionInput is the input of call n of requestor r: about 3 KB that
// differ for every call.
func actionInput(r, n int) string {
	return fmt.Sprintf("%d/%d:", r, n) + strings.Repeat(string(rune('a'+(r*7+n)%26)), 3000)
}

// forgedActionChunk encodes an action chunk of the Responder (a response
// to requestor) or of requestor (a request) that was never sent: random
// CorrelationData, offsets and sizes.
func forgedActionChunk(rng *rand.Rand, requestor uint64) ([]byte, error) {
	data := make([]byte, 1+rng.Intn(300))
	rng.Read(data)
	total := uint32(len(data) + rng.Intn(1<<14))
	rid := message.NewPublisherID(message.PublisherIDUInt16, requestor)
	corr := make([]byte, 1+rng.Intn(16))
	rng.Read(corr)
	nm := &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskPayloadHeader,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, 1),
		Action:      &message.ActionHeader{Type: message.ActionResponse, CorrelationData: corr, RequestorID: &rid},
		Messages:    []*message.DataSetMessage{{DataSetWriterID: 100}},
		Chunk: &message.Chunk{
			MessageSequenceNumber: uint16(rng.Intn(1 << 16)),
			ChunkOffset:           uint32(rng.Intn(int(total - uint32(len(data)) + 1))),
			TotalSize:             total,
			Data:                  data,
		},
	}
	if rng.Intn(2) == 0 {
		nm.PublisherID = rid
		nm.Action.Type, nm.Action.TimeoutHint = message.ActionRequest, 1000
	}
	return uadp.Encode(nm, nil)
}

// TestChaosActionChunks calls an Action with chunked requests and
// responses from two Requestors concurrently, unsecured and
// SignAndEncrypt, over an in-memory network with random faults and a
// flooder of forged action chunks. A call either returns the outputs of
// its own inputs or times out - never other outputs - and once the faults
// stop every call succeeds.
func TestChaosActionChunks(t *testing.T) {
	t.Parallel()
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			secured := mode > ua.MessageSecurityModeNone
			url := memURL(t)
			seg := mnet.segment(url)
			seg.seed(seed)

			opts := []pubsub.Option{pubsub.WithDiscovery(pubsub.DiscoveryOptions{Disabled: true}),
				pubsub.WithChunkReassembly(uadp.ReassemblerOptions{MaxMessageSize: 16 << 10, MaxPendingMessages: 32, MaxPublisherMessages: 16, Timeout: 500 * time.Millisecond})}
			g := pubsub.WriterGroup("Actions", 10, 50*time.Millisecond, pubsub.DataSetWriter("BlobWriter", 100, "Blob"))
			g.MaxNetworkMessageSize = 512
			if secured {
				ks := keyService(t, "sg", security.PolicyURIAes256CTR, time.Hour, 2, 2)
				pubsub.Secure(g, mode, "sg")
				opts = append(opts, pubsub.WithKeySource("sg", keySource(t, ks, "sg")))
			}
			resp := startRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pubsub.PublishedActions("Blob",
				[]pubsub.Field{{Name: "Data", Type: ua.TypeIDString}},
				[]pubsub.Field{{Name: "Reversed", Type: ua.TypeIDString}},
				pubsub.ActionTargetOf(1, "Reverse"))},
				pubsub.AttachWriterGroups(pubsub.UDPConnection("Responder", url, uint16(1)), g)),
				append(opts, pubsub.WithActionHandler("Blob", 1, reverseAction))...)
			var reqs []*pubsub.PubSub
			for i := range 2 {
				reqs = append(reqs, startRuntime(t, pubsub.NewConfiguration(nil, pubsub.UDPConnection("Requestor", url, uint16(2+i))), opts...))
			}
			waitState(t, resp, compID(t, resp, pubsub.KindWriterGroup, "Actions"), ua.PubSubStateOperational)
			for _, req := range reqs {
				waitState(t, req, compID(t, req, pubsub.KindConnection, "Requestor"), ua.PubSubStateOperational)
			}
			target := pubsub.ActionTarget{Connection: "Requestor", PublisherID: uint16(1), DataSetWriterID: 100, ActionTargetID: 1,
				Timeout: 2 * time.Second, ResendInterval: 100 * time.Millisecond, MaxNetworkMessageSize: 512,
				ResponseMetaData: pubsub.MetaData("Blob", pubsub.Field{Name: "Reversed", Type: ua.TypeIDString})}
			if secured {
				target.SecurityMode, target.SecurityGroupID = mode, "sg"
			}

			sink := &chaoskit.ErrSink{}
			var calls, ok, timeouts atomic.Int64
			call := func(r, n int, req *pubsub.PubSub) error {
				in := actionInput(r, n)
				calls.Add(1)
				res, err := req.CallAction(context.Background(), target, []*ua.Variant{ua.MustVariant(in)})
				switch {
				case errors.Is(err, pubsub.ErrActionTimeout):
					timeouts.Add(1)
					return err
				case err != nil:
					sink.Addf("call %d/%d: %v", r, n, err)
					return err
				case res.Status != ua.StatusGood || len(res.Outputs) != 1:
					sink.Addf("call %d/%d: status %v, %d outputs", r, n, res.Status, len(res.Outputs))
				case res.Outputs[0].Value() != reverse(in):
					sink.Addf("call %d/%d: the outputs of other inputs", r, n)
				default:
					ok.Add(1)
					return nil
				}
				return errors.New("bad result")
			}

			// The flooder: forged action chunks at about 1 kHz.
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var forged atomic.Int64
			wg.Add(1)
			go func() {
				defer wg.Done()
				frng := rand.New(rand.NewSource(seed + 1))
				tk := time.NewTicker(time.Millisecond)
				defer tk.Stop()
				for {
					select {
					case <-stop:
						return
					case <-tk.C:
					}
					b, err := forgedActionChunk(frng, uint64(2+frng.Intn(2)))
					if err != nil {
						continue
					}
					seg.inject(b)
					forged.Add(1)
				}
			}()

			// The callers: three per Requestor, calling while the faults go.
			callers := make(chan struct{})
			var cwg sync.WaitGroup
			for r, req := range reqs {
				for c := range 3 {
					cwg.Add(1)
					go func() {
						defer cwg.Done()
						for n := 0; ; n++ {
							select {
							case <-callers:
								return
							default:
							}
							_ = call(r, c*1000+n, req)
						}
					}()
				}
			}

			end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
			for time.Now().Before(end) {
				f, hold := randomFaults(rng, secured, time.Second)
				if f.blackhole {
					f, hold = faults{drop: 0.5}, 300*time.Millisecond
				}
				t.Logf("%s: %v for %v", time.Now().Format("15:04:05.000"), f, hold)
				seg.set(f)
				time.Sleep(hold)
			}
			seg.set(faults{})
			close(callers)
			if !chaoskit.WaitGroupTimeout(&cwg, 10*time.Second) {
				t.Fatalf("callers stuck\n%s", chaoskit.AllStacks())
			}
			close(stop)
			wg.Wait()

			// Clean network: every call succeeds.
			for r, req := range reqs {
				for n := range 3 {
					if err := call(r, 9000+n, req); err != nil {
						t.Errorf("call %d/%d after the faults: %v", r, n, err)
					}
				}
			}

			rc := status(t, resp, pubsub.Root).Counters
			t.Logf("segment: sent %d delivered %d dropped %d, forged %d", seg.sent.Load(), seg.delivered.Load(), seg.dropped.Load(), forged.Load())
			t.Logf("calls %d: ok %d, timed out %d", calls.Load(), ok.Load(), timeouts.Load())
			t.Logf("responder: %+v", rc)
			if rc.ChunksSent == 0 || rc.ChunkedMessagesReceived == 0 {
				t.Errorf("responder: %d chunks sent, %d chunked messages received", rc.ChunksSent, rc.ChunkedMessagesReceived)
			}
			// Unsigned forged chunks fail the security check before the
			// reassembly.
			if discarded := rc.ChunksDiscarded; secured && rc.DecodeErrors == 0 || !secured && discarded == 0 {
				t.Errorf("%d forged chunks, none discarded (%d decode errors, %d chunks discarded)", forged.Load(), rc.DecodeErrors, discarded)
			}
			for i, req := range reqs {
				c := status(t, req, pubsub.Root).Counters
				t.Logf("requestor %d: %+v", i, c)
				if c.ChunksSent == 0 || c.ChunkedMessagesReceived == 0 || c.EncodeErrors != 0 {
					t.Errorf("requestor %d: %d chunks sent, %d chunked messages received, %d encode errors", i, c.ChunksSent, c.ChunkedMessagesReceived, c.EncodeErrors)
				}
			}
			if rc.EncodeErrors != 0 {
				t.Errorf("responder: %d encode errors", rc.EncodeErrors)
			}
			sink.Report(t)
		})
	}
}
