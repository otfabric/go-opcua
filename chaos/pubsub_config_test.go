// SPDX-License-Identifier: MIT

package chaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestChaosPubSubConfigurationFile: sessions read, reserve ids and update
// the PubSubConfiguration file of a running server concurrently (Part 14
// §9.1.3.7) with random and malformed element operations, abandon open
// handles and drop their sessions. Contention is answered with
// Bad_NotWritable / Bad_NotReadable; nothing deadlocks, every configuration
// the runtime takes is valid, and the handles of closed sessions are freed.
func TestChaosPubSubConfigurationFile(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	wd := newWatchdog(t)
	udp := func() string { return fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t)) }
	action := pubsub.PublishedActions("Calc", []pubsub.Field{{Name: "A", Type: ua.TypeIDInt32}}, nil, pubsub.ActionTargetOf(1, "Run"))
	srv, surl := testutil.NewTestServer(t, server.WithPubSub(pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{action},
		pubsub.AttachWriterGroups(pubsub.UDPConnection("Base", udp(), uint16(1)),
			pubsub.WriterGroup("Actions", 1, 100*time.Millisecond, pubsub.DataSetWriter("CalcWriter", 1, "Calc"))))))
	rt := srv.PubSub()
	connURL := udp()

	// contention is the refusal of a method call another session's handle
	// causes.
	contention := func(err error) bool {
		return errors.Is(err, ua.StatusBadNotWritable) || errors.Is(err, ua.StatusBadNotReadable)
	}
	ops := []ua.PubSubConfigurationRefMask{
		ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskElementMatch,
		ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskElementMatch,
		ua.PubSubConfigurationRefMaskElementModify, ua.PubSubConfigurationRefMaskElementRemove,
	}

	deadline := time.Now().Add(chaosDuration(t))
	const workers = 5
	var sink errSink
	var wg sync.WaitGroup
	var applied, refused atomic.Int64
	for g := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g)))
			for n := 0; time.Now().Before(deadline); n++ {
				err := wd.do("configuration file", func() error {
					ctx, cancel := opCtx()
					defer cancel()
					c, err := opcua.NewClient(surl, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(false))
					if err != nil {
						return err
					}
					if err := c.Connect(ctx); err != nil {
						return fmt.Errorf("connect: %w", err)
					}
					defer func() { _ = c.Close(context.Background()) }()
					r := remote.New(c)
					for k := 0; k < 4; k++ {
						switch rng.Intn(5) {
						case 0:
							if _, err := r.ReadConfiguration(ctx); err != nil && !contention(err) {
								return fmt.Errorf("read: %w", err)
							}
						case 1:
							if _, err := r.ReserveIDs(ctx, transport.ProfileUDPUADP, uint16(rng.Intn(4)), uint16(rng.Intn(4))); err != nil {
								return fmt.Errorf("reserve: %w", err)
							}
						case 2:
							// Abandon a handle: the session closes with it.
							res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: remote.PubSubConfiguration,
								MethodID:       ua.NewNumericNodeID(0, id.PublishSubscribePubSubConfigurationOpen),
								InputArguments: []*ua.Variant{ua.MustVariant([]byte{0x01, 0x03, 0x06}[rng.Intn(3)])}})
							if err != nil {
								return fmt.Errorf("open: %w", err)
							}
							if sc := res.StatusCode; sc != ua.StatusOK && !contention(sc) {
								return fmt.Errorf("open: %v", sc)
							}
						default:
							name := fmt.Sprintf("g%d-%d", g, rng.Intn(3))
							conn := pubsub.UDPConnection("Base", connURL, uint16(1))
							if rng.Intn(4) == 0 {
								conn = pubsub.UDPConnection(name, connURL, nil)
							}
							conn.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup(name, 0, time.Duration(50+rng.Intn(100))*time.Millisecond,
								pubsub.DataSetWriter("", 0, []string{"Calc", "Nope"}[rng.Intn(2)]))}
							file := &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{conn},
								PublishedDataSets: []*ua.PublishedDataSetDataType{action}}
							var refs []*ua.PubSubConfigurationRefDataType
							if rng.Intn(2) == 0 {
								// A well-formed update: a group of its own on a
								// connection of its own (fails only if another
								// worker removed the connection meanwhile).
								own := pubsub.UDPConnection(fmt.Sprintf("w%d", g), connURL, nil)
								own.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup(fmt.Sprintf("g%d-%d-%d", g, n, k), 0, 100*time.Millisecond)}
								file.Connections = []*ua.PubSubConnectionDataType{own}
								refs = append(refs, remote.Ref(ua.PubSubConfigurationRefMaskElementAdd|ua.PubSubConfigurationRefMaskElementMatch,
									ua.PubSubConfigurationRefMaskReferenceConnection, 0, 0, 0),
									remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceWriterGroup, 0, 0, 0))
							}
							if len(refs) == 0 {
								for range 1 + rng.Intn(4) {
									kind := ua.PubSubConfigurationRefMask(1) << (4 + rng.Intn(9))
									op := ops[rng.Intn(len(ops))]
									if rng.Intn(10) == 0 {
										op = ua.PubSubConfigurationRefMask(rng.Intn(16))
									}
									refs = append(refs, remote.Ref(op, kind, uint16(rng.Intn(2)), uint16(rng.Intn(2)), uint16(rng.Intn(2))))
								}
							}
							res, err := r.UpdateConfiguration(ctx, file, refs, rng.Intn(2) == 0)
							if err != nil {
								if contention(err) {
									continue
								}
								return fmt.Errorf("update: %w", err)
							}
							if len(res.Results) != len(refs) {
								return fmt.Errorf("update: %d results for %d references", len(res.Results), len(refs))
							}
							if res.ChangesApplied {
								applied.Add(1)
							} else {
								refused.Add(1)
							}
						}
					}
					return nil
				})
				if err != nil {
					sink.addf("worker %d round %d: %v", g, n, err)
					return
				}
			}
		}()
	}
	wd.wait("configuration file", &wg)
	sink.report(t)
	t.Logf("updates applied %d, refused %d", applied.Load(), refused.Load())

	// After the storm a valid update applies, whatever the workers did.
	fr := remote.New(testutil.NewTestClient(t, surl))
	fc := pubsub.UDPConnection("Final", connURL, uint16(99))
	fc.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("FinalGroup", 0, 100*time.Millisecond)}
	ures, err := fr.UpdateConfiguration(context.Background(), &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{fc}},
		[]*ua.PubSubConfigurationRefDataType{
			remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceConnection, 0, 0, 0),
			remote.Ref(ua.PubSubConfigurationRefMaskElementAdd, ua.PubSubConfigurationRefMaskReferenceWriterGroup, 0, 0, 0),
		}, true)
	require.NoError(t, err)
	require.True(t, ures.ChangesApplied, "%v", ures.Results)
	fid, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "Final")
	require.True(t, ok)
	_, ok = rt.Lookup(pubsub.KindWriterGroup, fid, "FinalGroup")
	require.True(t, ok)

	// The runtime took only valid configurations, and the file shows it.
	final := rt.Configuration()
	require.NoError(t, pubsub.Validate(final))
	got, err := remote.New(testutil.NewTestClient(t, surl)).ReadConfiguration(context.Background())
	require.NoError(t, err)
	require.Len(t, got.Connections, len(final.Connections))
	require.Len(t, got.PublishedDataSets, len(final.PublishedDataSets))

	// All sessions are closed: their handles are freed, so a writer gets
	// exclusive access.
	c := testutil.NewTestClient(t, surl)
	res, err := c.Call(context.Background(), &ua.CallMethodRequest{ObjectID: remote.PubSubConfiguration,
		MethodID:       ua.NewNumericNodeID(0, id.PublishSubscribePubSubConfigurationOpen),
		InputArguments: []*ua.Variant{ua.MustVariant(byte(0x06))}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	cnt, err := c.Node(ua.NewNumericNodeID(0, id.PublishSubscribePubSubConfigurationOpenCount)).Value(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint16(1), cnt.Value())
}
