// SPDX-License-Identifier: MIT

package eth_test

import (
	"context"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport/eth"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// End-to-end tests of the Ethernet transport over an in-memory segment
// (eth.UseMemSegment): no raw socket access is needed, so they run
// everywhere. They cover what the real-socket tests can only cover as
// root: the runtime over Ethernet with multicast, broadcast and unicast
// addresses, VLAN tags, message security, NetworkMessages larger than a
// frame (chunks), loss and UADP discovery.

var (
	memN   = ua.NewStringNodeID(1, "eth-n")
	memBig = ua.NewStringNodeID(1, "eth-big")
)

// bigValue is the big field of sample n: 3000 bytes, more than a frame.
func bigValue(n int64) string {
	return strings.Repeat(fmt.Sprintf("<%d>", n), 3000/len(fmt.Sprintf("<%d>", n))+1)[:3000]
}

func memPDS() *ua.PublishedDataSetDataType {
	return pubsub.PublishedDataItems("pds", pubsub.Var("n", memN, ua.TypeIDInt64), pubsub.Var("big", memBig, ua.TypeIDString))
}

// memSource publishes a counter and the big value of the counter.
func memSource() pubsub.DataSource {
	var n atomic.Int64
	return pubsub.DataSourceFunc(func(_ context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue {
		v := n.Add(1)
		out := make([]*ua.DataValue, len(vars))
		for i, pv := range vars {
			var val any = v
			if pv.PublishedVariable.Equal(memBig) {
				val = bigValue(v)
			}
			out[i] = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(val)}
		}
		return out
	})
}

// memRecorder checks the received data sets: the big value must be the one
// of the counter, the counter must grow.
type memRecorder struct {
	mu   sync.Mutex
	last int64
	n    int
	errs []string
}

func (r *memRecorder) handle(ds *pubsub.ReceivedDataSet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	nf, bf := ds.Field("n"), ds.Field("big")
	if nf == nil || bf == nil || nf.Value == nil || bf.Value == nil {
		r.errs = append(r.errs, fmt.Sprintf("missing fields %+v", ds.Fields))
		return
	}
	n, _ := nf.Value.Value().(int64)
	b, _ := bf.Value.Value().(string)
	if b != bigValue(n) {
		r.errs = append(r.errs, fmt.Sprintf("sample %d: big value of %d bytes does not match", n, len(b)))
	}
	if n <= r.last {
		r.errs = append(r.errs, fmt.Sprintf("sample %d after %d", n, r.last))
	}
	r.last = n
	r.n++
}

func (r *memRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func (r *memRecorder) check(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.Empty(t, r.errs)
}

func memRuntime(t *testing.T, cfg *ua.PubSubConfigurationDataType, opts ...pubsub.Option) *pubsub.PubSub {
	t.Helper()
	require.NoError(t, pubsub.Validate(cfg))
	rt, err := pubsub.New(cfg, opts...)
	require.NoError(t, err)
	require.NoError(t, rt.Start(context.Background()))
	t.Cleanup(func() { _ = rt.Close() })
	return rt
}

func memCounters(t *testing.T, rt *pubsub.PubSub) pubsub.Counters {
	t.Helper()
	st, err := rt.Status(pubsub.Root)
	require.NoError(t, err)
	return st.Counters
}

func memRing(t *testing.T) *security.KeyRing {
	t.Helper()
	policy := security.Aes256CTR()
	ring := security.NewKeyRing("sg", policy)
	key := make([]byte, policy.KeyLength())
	_, err := rand.Read(key)
	require.NoError(t, err)
	require.NoError(t, ring.SetKeys(policy.URI(), 1, [][]byte{key}, time.Hour, time.Hour))
	return ring
}

// TestE2EEthernetMemory publishes data sets larger than an Ethernet frame
// over the in-memory segment, to a multicast group with a VLAN tag, to
// broadcast and to the unicast address of the interface, unsecured and with
// SignAndEncrypt: they arrive as chunks and are reassembled intact.
func TestE2EEthernetMemory(t *testing.T) {
	for _, url := range []string{"opc.eth://01-00-5e-7f-00-01:100.5", "opc.eth://ff-ff-ff-ff-ff-ff", "opc.eth://" + eth.MemInterfaceMAC() + ":0.3"} {
		for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSignAndEncrypt} {
			t.Run(fmt.Sprintf("%s/%v", url, mode), func(t *testing.T) {
				seg := eth.UseMemSegment(t)
				ring := memRing(t)
				wg := pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w", 1, "pds"))
				rg := pubsub.ReaderGroup("rg", pubsub.DataSetReader("r", uint16(3), 1, 1, pubsub.DataSetMetaDataOf(memPDS())))
				if mode > ua.MessageSecurityModeNone {
					pubsub.Secure(wg, mode, "sg")
					pubsub.Secure(rg, mode, "sg")
				}
				rec := &memRecorder{}
				sub := memRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.EthernetConnection("sub", url, eth.MemInterface, nil), rg)),
					pubsub.WithDataSetHandler(rec.handle), pubsub.WithKeySource("sg", ring))
				pub := memRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{memPDS()},
					pubsub.AttachWriterGroups(pubsub.EthernetConnection("pub", url, eth.MemInterface, uint16(3)), wg)),
					pubsub.WithDataSource(memSource()), pubsub.WithKeySource("sg", ring))
				require.Eventually(t, func() bool { return rec.count() >= 10 }, 20*time.Second, 5*time.Millisecond)
				rec.check(t)
				pc, sc := memCounters(t, pub), memCounters(t, sub)
				require.NotZero(t, pc.ChunksSent)
				require.Zero(t, pc.EncodeErrors)
				require.Zero(t, pc.SendErrors)
				require.NotZero(t, sc.ChunkedMessagesReceived)
				require.Zero(t, sc.DecodeErrors)
				require.NotZero(t, seg.Delivered.Load())
			})
		}
	}
}

// TestE2EEthernetMemoryLossy loses frames on the segment: messages whose
// chunks all arrive are delivered intact, the chunks of the others are
// discarded after the reassembly timeout, and delivery goes on.
func TestE2EEthernetMemoryLossy(t *testing.T) {
	seg := eth.UseMemSegment(t)
	var mu sync.Mutex
	rng := mrand.New(mrand.NewSource(1))
	seg.Drop = func([]byte) bool {
		mu.Lock()
		defer mu.Unlock()
		return rng.Float64() < 0.15
	}
	const url = "opc.eth://01-00-5e-7f-00-02"
	rec := &memRecorder{}
	sub := memRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.EthernetConnection("sub", url, eth.MemInterface, nil),
		pubsub.ReaderGroup("rg", pubsub.DataSetReader("r", uint16(3), 1, 1, pubsub.DataSetMetaDataOf(memPDS()))))),
		pubsub.WithDataSetHandler(rec.handle), pubsub.WithChunkReassembly(uadp.ReassemblerOptions{Timeout: 100 * time.Millisecond}))
	memRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{memPDS()},
		pubsub.AttachWriterGroups(pubsub.EthernetConnection("pub", url, eth.MemInterface, uint16(3)),
			pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w", 1, "pds")))),
		pubsub.WithDataSource(memSource()))
	require.Eventually(t, func() bool { return rec.count() >= 20 && memCounters(t, sub).ChunksDiscarded > 0 }, 20*time.Second, 5*time.Millisecond)
	rec.check(t)
	require.NotZero(t, seg.Dropped.Load())
}

// TestE2EEthernetMemoryDiscovery: a reader without DataSetMetaData learns
// it over Ethernet through UADP discovery (probe and announcement).
func TestE2EEthernetMemoryDiscovery(t *testing.T) {
	eth.UseMemSegment(t)
	const url = "opc.eth://01-00-5e-7f-00-03"
	rec := &memRecorder{}
	sub := memRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.EthernetConnection("sub", url, eth.MemInterface, nil),
		pubsub.ReaderGroup("rg", pubsub.DataSetReader("r", uint16(3), 1, 1, nil)))),
		pubsub.WithDataSetHandler(func(ds *pubsub.ReceivedDataSet) {
			if ds.Field("n") != nil {
				rec.handle(ds)
			}
		}))
	pub := memRuntime(t, pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{memPDS()},
		pubsub.AttachWriterGroups(pubsub.EthernetConnection("pub", url, eth.MemInterface, uint16(3)),
			pubsub.WriterGroup("wg", 1, 10*time.Millisecond, pubsub.DataSetWriter("w", 1, "pds")))),
		pubsub.WithDataSource(memSource()))
	require.Eventually(t, func() bool { return rec.count() >= 5 }, 20*time.Second, 5*time.Millisecond)
	rec.check(t)
	require.NotZero(t, memCounters(t, sub).DiscoveryRequestsSent)
	require.NotZero(t, memCounters(t, pub).DiscoveryResponsesSent)
}
