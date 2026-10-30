// SPDX-License-Identifier: MIT

package chaos

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// The tests in this file inject no faults. Every operation must therefore
// succeed: any error is a failure, not an "expected error".

// opCtx is the context for one fault-free operation. The timeout only guards
// against a hang; it is far above anything a healthy request needs.
func opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// errSink collects errors from worker goroutines.
type errSink struct {
	mu   sync.Mutex
	errs []string
}

func (s *errSink) addf(format string, args ...any) {
	s.mu.Lock()
	if len(s.errs) < 25 {
		s.errs = append(s.errs, fmt.Sprintf(format, args...))
	}
	s.mu.Unlock()
}

func (s *errSink) report(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.errs {
		t.Error(e)
	}
}

// mixedOp performs one randomly chosen service call on c and verifies the
// result. own is the index of a scratch node only this caller writes to, or
// -1 if it has none.
func mixedOp(e *env, c *opcua.Client, rng *rand.Rand, own int) error {
	ctx, cancel := opCtx()
	defer cancel()

	op := rng.Intn(6)
	if own < 0 && op == 0 {
		op = 1 // no exclusive scratch node: skip the read-back check
	}
	switch op {
	case 0: // write + read back on a node owned by this goroutine
		want := rng.Int31()
		sc, err := c.WriteNodeValue(ctx, e.scratchID(own), want)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
		if sc != ua.StatusOK {
			return fmt.Errorf("write: status %v", sc)
		}
		dv, err := c.ReadValue(ctx, e.scratchID(own))
		if err != nil {
			return fmt.Errorf("read back: %w", err)
		}
		if got := dv.Value.Value(); got != want {
			return fmt.Errorf("read back %v, want %v (response delivered to the wrong caller?)", got, want)
		}
	case 1: // read several nodes
		dvs, err := c.ReadValues(ctx, e.scratchID(0), e.counterID(0), e.scratchID(numScratch-1))
		if err != nil {
			return fmt.Errorf("read values: %w", err)
		}
		if len(dvs) != 3 {
			return fmt.Errorf("read values: got %d results", len(dvs))
		}
		for i, dv := range dvs {
			if dv.Status != ua.StatusOK {
				return fmt.Errorf("read values[%d]: status %v", i, dv.Status)
			}
		}
	case 2: // browse
		refs, err := c.BrowseAll(ctx, e.folderID())
		if err != nil {
			return fmt.Errorf("browse: %w", err)
		}
		if n := countLeaves(refs); n != numBrowse {
			return fmt.Errorf("browse: %d leaves, want %d", n, numBrowse)
		}
	case 3: // method call: the response must belong to this request
		n := int32(rng.Intn(1000))
		res, err := c.CallMethod(ctx, e.objectsID(), e.methodID(), n)
		if err != nil {
			return fmt.Errorf("call: %w", err)
		}
		if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != n*n {
			return fmt.Errorf("call(%d): unexpected result %v %v", n, res.StatusCode, res.OutputArguments)
		}
	case 4: // large multi-chunk response
		dv, err := c.ReadValue(ctx, e.blobID())
		if err != nil {
			return fmt.Errorf("read blob: %w", err)
		}
		if b, _ := dv.Value.Value().([]byte); len(b) != blobSize {
			return fmt.Errorf("read blob: %d bytes, want %d", len(b), blobSize)
		}
	case 5: // namespace array
		nss, err := c.NamespaceArray(ctx)
		if err != nil {
			return fmt.Errorf("namespace array: %w", err)
		}
		if len(nss) <= int(e.ns) {
			return fmt.Errorf("namespace array too short: %v", nss)
		}
	}
	return nil
}

// TestParallelOneClientMixedServices shares a single client between many
// goroutines that issue different services concurrently. Request/response
// matching must hold: every caller gets the answer to its own request.
func TestParallelOneClientMixedServices(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	c := e.connect(nil)

	const goroutines, iterations = 16, 25
	var sink errSink
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g)))
			for i := 0; i < iterations; i++ {
				if err := wd.do("mixedOp", func() error { return mixedOpShared(e, c, rng, g) }); err != nil {
					sink.addf("goroutine %d iteration %d: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	wd.wait("mixed workload", &wg)
	sink.report(t)

	closeClient(c, nil)
	e.requireServerDrained(settleLimit)
}

// TestParallelManyClients runs many independent clients against one server.
// Each has its own session and subscription and performs mixed services.
func TestParallelManyClients(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)

	const clients, iterations = 12, 15
	var sink errSink
	var wg sync.WaitGroup
	var stop atomic.Bool

	// counters advance while the clients are subscribed
	var bumpWG sync.WaitGroup
	bumpWG.Add(1)
	go func() {
		defer bumpWG.Done()
		for !stop.Load() {
			e.bump(0)
			time.Sleep(2 * time.Millisecond)
		}
	}()

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := newStateRecorder(fmt.Sprintf("c%d", i), true)
			c, err := e.dial(rec)
			if err != nil {
				sink.addf("client %d: connect: %v", i, err)
				return
			}
			ctx, cancel := opCtx()
			defer cancel()
			st, err := openStream(ctx, e, c, fmt.Sprintf("c%d", i), i%3, false, 0)
			if err != nil {
				sink.addf("client %d: stream: %v", i, err)
				return
			}
			rng := rand.New(rand.NewSource(seed + int64(i)))
			for it := 0; it < iterations; it++ {
				if err := wd.do("mixedOp", func() error { return mixedOpShared(e, c, rng, i) }); err != nil {
					sink.addf("client %d iteration %d: %v", i, it, err)
					break
				}
			}
			// the stream must be alive
			before := st.received.Load()
			if !eventually(settleLimit, func() bool { return st.received.Load() > before }) {
				sink.addf("client %d: subscription stopped delivering", i)
			}
			if err := st.sub.Cancel(ctx); err != nil {
				sink.addf("client %d: cancel: %v", i, err)
			}
			st.close()
			st.report(t)
			closeClient(c, rec)
			rec.check(t, true)
		}(i)
	}
	wd.wait("clients", &wg)
	stop.Store(true)
	wd.wait("server-side writer", &bumpWG)
	sink.report(t)
	e.requireServerDrained(settleLimit)
}

// mixedOpShared is mixedOp for callers that may share scratch nodes with
// other clients: only exclusive owners perform the write/read-back check.
func mixedOpShared(e *env, c *opcua.Client, rng *rand.Rand, owner int) error {
	if owner >= numScratch {
		owner = -1
	}
	return mixedOp(e, c, rng, owner)
}

// TestParallelSubscriptionChurn creates, modifies and cancels sibling
// subscriptions from many goroutines on one client while other goroutines
// hammer a single shared subscription with Monitor / Unmonitor /
// ModifySubscription / SetPublishingMode.
func TestParallelSubscriptionChurn(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	c := e.connect(nil)

	var sink errSink
	var stop atomic.Bool
	var bumpWG sync.WaitGroup
	bumpWG.Add(1)
	go func() {
		defer bumpWG.Done()
		for !stop.Load() {
			for i := 0; i < numCounters; i++ {
				e.bump(i)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// a long-lived stream that must keep flowing while its siblings churn
	ctx, cancel := opCtx()
	defer cancel()
	steady, err := openStream(ctx, e, c, "steady", 0, false, 0, 1)
	if err != nil {
		t.Fatalf("steady stream: %v", err)
	}

	// the shared subscription all "hammer" goroutines operate on
	sharedCh := make(chan *opcua.PublishNotificationData, 64)
	sharedDone := make(chan struct{})
	sharedStop := make(chan struct{})
	go func() {
		defer close(sharedDone)
		for {
			select {
			case <-sharedCh:
			case <-sharedStop:
				return
			}
		}
	}()
	shared, err := c.Subscribe(ctx, streamParams(), sharedCh)
	if err != nil {
		t.Fatalf("shared subscribe: %v", err)
	}

	const siblings, hammers, rounds = 6, 6, 8
	var wg sync.WaitGroup

	for g := 0; g < siblings; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				err := wd.do("sibling lifecycle", func() error {
					ctx, cancel := opCtx()
					defer cancel()
					st, err := openStream(ctx, e, c, fmt.Sprintf("sib%d.%d", g, r), r%2, false, g%numCounters)
					if err != nil {
						return err
					}
					defer st.close()
					if _, err := st.sub.ModifySubscription(ctx, opcua.SubscriptionParameters{
						Interval: 10 * time.Millisecond, MaxKeepAliveCount: 5, LifetimeCount: 3000,
					}); err != nil {
						return fmt.Errorf("modify: %w", err)
					}
					// the subscription must deliver the (changing) counter
					before := st.received.Load()
					if !eventually(settleLimit, func() bool { return st.received.Load() > before }) {
						return fmt.Errorf("sibling subscription %d delivered nothing", st.sub.SubscriptionID)
					}
					if err := st.sub.Cancel(ctx); err != nil {
						return fmt.Errorf("cancel: %w", err)
					}
					st.report(t)
					return nil
				})
				if err != nil {
					sink.addf("sibling %d round %d: %v", g, r, err)
					return
				}
			}
		}(g)
	}

	for g := 0; g < hammers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g)))
			for r := 0; r < rounds*2; r++ {
				err := wd.do("shared subscription op", func() error {
					ctx, cancel := opCtx()
					defer cancel()
					switch rng.Intn(3) {
					case 0:
						req := opcua.NewMonitoredItemCreateRequestWithDefaults(e.counterID(rng.Intn(numCounters)), ua.AttributeIDValue, uint32(g*1000+r))
						res, err := shared.Monitor(ctx, ua.TimestampsToReturnBoth, req)
						if err != nil {
							return fmt.Errorf("monitor: %w", err)
						}
						if res.Results[0].StatusCode != ua.StatusOK {
							return fmt.Errorf("monitor: status %v", res.Results[0].StatusCode)
						}
						ures, err := shared.Unmonitor(ctx, res.Results[0].MonitoredItemID)
						if err != nil {
							return fmt.Errorf("unmonitor: %w", err)
						}
						if ures.Results[0] != ua.StatusOK {
							return fmt.Errorf("unmonitor: status %v", ures.Results[0])
						}
					case 1:
						if _, err := shared.ModifySubscription(ctx, opcua.SubscriptionParameters{
							Interval:          time.Duration(10+rng.Intn(40)) * time.Millisecond,
							MaxKeepAliveCount: 5, LifetimeCount: 3000,
						}); err != nil {
							return fmt.Errorf("modify: %w", err)
						}
					case 2:
						res, err := shared.SetPublishingMode(ctx, rng.Intn(2) == 0)
						if err != nil {
							return fmt.Errorf("set publishing mode: %w", err)
						}
						if res.Results[0] != ua.StatusOK {
							return fmt.Errorf("set publishing mode: status %v", res.Results[0])
						}
					}
					return nil
				})
				if err != nil {
					sink.addf("hammer %d round %d: %v", g, r, err)
					return
				}
			}
		}(g)
	}
	wd.wait("subscription churn", &wg)
	sink.report(t)

	// the steady stream survived the churn of its siblings
	before := steady.received.Load()
	if !eventually(settleLimit, func() bool { return steady.received.Load() > before }) {
		t.Errorf("steady subscription stopped delivering after sibling churn")
	}

	// Cancel the shared subscription from several goroutines at once: exactly
	// one of them deletes it on the server, nobody panics or hangs.
	var cwg sync.WaitGroup
	var okCancels atomic.Int32
	for i := 0; i < 4; i++ {
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			_ = wd.do("concurrent cancel", func() error {
				ctx, cancel := opCtx()
				defer cancel()
				if err := shared.Cancel(ctx); err == nil {
					okCancels.Add(1)
				}
				return nil
			})
		}()
	}
	wd.wait("concurrent cancel", &cwg)
	if n := okCancels.Load(); n != 1 {
		t.Errorf("%d of 4 concurrent Cancel calls succeeded, want exactly 1", n)
	}
	close(sharedStop)
	<-sharedDone

	if err := steady.sub.Cancel(ctx); err != nil {
		t.Errorf("cancel steady: %v", err)
	}
	steady.close()
	steady.report(t)
	stop.Store(true)
	wd.wait("server-side writer", &bumpWG)

	if ids := c.SubscriptionIDs(); len(ids) != 0 {
		t.Errorf("client still tracks subscriptions %v after all were cancelled", ids)
	}
	if !eventually(settleLimit, func() bool { r := e.resources(); return r.Subscriptions == 0 && r.MonitoredItems == 0 }) {
		t.Errorf("server still holds subscription state after all were cancelled: %+v", e.resources())
	}
	closeClient(c, nil)
	e.requireServerDrained(settleLimit)
}

// TestParallelWritersConsistentStream lets several clients write unique
// values to the same node concurrently while several subscribers (on
// separate clients and as sibling subscriptions on one client) monitor it.
//
// The server applies the writes in some total order. Every subscriber must
// observe a subsequence of that order: no duplicates, no two subscribers
// disagreeing on the relative order of two values, and all of them ending on
// the value the node finally holds.
func TestParallelWritersConsistentStream(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)

	const writers, writesPerWriter = 4, 60
	ctx, cancel := opCtx()
	defer cancel()

	// subscribers: two clients with one subscription, one client with two
	subClients := []*opcua.Client{e.connect(nil), e.connect(nil), e.connect(nil)}
	var streams []*stream
	for i, c := range append(subClients, subClients[2]) {
		st, err := openStream(ctx, e, c, fmt.Sprintf("s%d", i), i%2*4, true, 0)
		if st != nil {
			st.setUnordered() // several writers: values arrive in server order, not numeric order
		}
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		streams = append(streams, st)
	}
	// wait for the initial value so that all streams are live
	for _, st := range streams {
		if !eventually(settleLimit, func() bool { return st.received.Load() > 0 }) {
			t.Fatalf("stream %s: no initial value", st.name)
		}
	}

	var next atomic.Int64
	next.Store(1000)
	var sink errSink
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wc := e.connect(nil)
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < writesPerWriter; i++ {
				v := next.Add(1)
				err := wd.do("write", func() error {
					ctx, cancel := opCtx()
					defer cancel()
					sc, err := wc.WriteNodeValue(ctx, e.counterID(0), v)
					if err == nil && sc != ua.StatusOK {
						err = sc
					}
					return err
				})
				if err != nil {
					sink.addf("writer %d: %v", w, err)
					return
				}
			}
		}(w)
	}
	wd.wait("writers", &wg)
	sink.report(t)

	dv, err := subClients[0].ReadValue(ctx, e.counterID(0))
	if err != nil {
		t.Fatalf("read final value: %v", err)
	}
	final, _ := dv.Value.Value().(int64)

	for _, st := range streams {
		if !eventually(settleLimit, func() bool { return st.lastValue(0) == final }) {
			t.Errorf("stream %s: last delivered value %d, node holds %d", st.name, st.lastValue(0), final)
		}
	}

	// pairwise order consistency
	hist := make([][]int64, len(streams))
	for i, st := range streams {
		h := st.history(0)
		// collapse adjacent duplicates (initial value may be reported twice)
		var d []int64
		for _, v := range h {
			if len(d) == 0 || d[len(d)-1] != v {
				d = append(d, v)
			}
		}
		seen := make(map[int64]bool, len(d))
		for _, v := range d {
			if seen[v] {
				t.Errorf("stream %s: value %d delivered twice (non-adjacent): %v", st.name, v, d)
				break
			}
			seen[v] = true
		}
		hist[i] = d
	}
	pos := make(map[int64]int, len(hist[0]))
	for i, v := range hist[0] {
		pos[v] = i
	}
	for i := 1; i < len(hist); i++ {
		prev := -1
		for _, v := range hist[i] {
			p, ok := pos[v]
			if !ok {
				continue
			}
			if p < prev {
				t.Errorf("streams %s and %s disagree on the order of value %d\n  %s: %v\n  %s: %v",
					streams[0].name, streams[i].name, v, streams[0].name, hist[0], streams[i].name, hist[i])
				break
			}
			prev = p
		}
	}

	for _, st := range streams {
		if err := st.sub.Cancel(ctx); err != nil {
			t.Errorf("cancel %s: %v", st.name, err)
		}
		st.close()
		st.report(t)
	}
}

// TestParallelSessionChurn opens and closes sessions from many goroutines.
// When the last client is gone the server must hold no client state.
func TestParallelSessionChurn(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)

	const goroutines, rounds = 6, 6
	var sink errSink
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g)))
			for r := 0; r < rounds; r++ {
				err := wd.do("session lifecycle", func() error {
					rec := newStateRecorder(fmt.Sprintf("g%d.r%d", g, r), false)
					c, err := opcua.NewClient(e.url(), append([]opcua.Option{opcua.InsecureNoSecurity()}, e.clientOptions(rec, opcua.AutoReconnect(false))...)...)
					if err != nil {
						return err
					}
					ctx, cancel := opCtx()
					defer cancel()
					if err := c.Connect(ctx); err != nil {
						return fmt.Errorf("connect: %w", err)
					}
					defer func() {
						closeClient(c, rec)
						rec.check(t, true)
					}()
					if rng.Intn(2) == 0 {
						return mixedOpShared(e, c, rng, numScratch)
					}
					// an extra session on the same channel, closed explicitly
					s, err := c.CreateSession(ctx, opcua.DefaultSessionConfig())
					if err != nil {
						return fmt.Errorf("create session: %w", err)
					}
					if err := c.ActivateSession(ctx, s); err != nil {
						return fmt.Errorf("activate session: %w", err)
					}
					if _, err := c.ReadValue(ctx, e.scratchID(0)); err != nil {
						return fmt.Errorf("read on second session: %w", err)
					}
					return nil
				})
				if err != nil {
					sink.addf("goroutine %d round %d: %v", g, r, err)
					return
				}
			}
		}(g)
	}
	wd.wait("session churn", &wg)
	sink.report(t)
	e.requireServerDrained(settleLimit)
}

// TestParallelLargeMessages interleaves multi-chunk requests and responses of
// many goroutines on one secure channel. Small buffers force every large
// message into dozens of chunks.
func TestParallelLargeMessages(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)

	const goroutines, iterations = 8, 6
	const payload = 96 * 1024

	// one writable ByteString node per goroutine
	ns := e.namespace()
	for g := 0; g < goroutines; g++ {
		n := ns.AddNewVariableStringNode(fmt.Sprintf("Big%d", g), []byte{0})
		ns.Objects().AddRef(n, id.HasComponent, true)
	}

	c := e.connect(nil, opcua.Dialer(&uacp.Dialer{ClientACK: &uacp.Acknowledge{
		ReceiveBufSize: 8192,
		SendBufSize:    8192,
	}}))

	var sink errSink
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			node := e.nodeID(fmt.Sprintf("Big%d", g))
			for i := 0; i < iterations; i++ {
				err := wd.do("large message", func() error {
					ctx, cancel := opCtx()
					defer cancel()
					// a payload that identifies its writer and iteration
					want := bytes.Repeat([]byte{byte(g), byte(i), 0x5A}, payload/3)
					sc, err := c.WriteNodeValue(ctx, node, want)
					if err != nil {
						return fmt.Errorf("write %d bytes: %w", len(want), err)
					}
					if sc != ua.StatusOK {
						return fmt.Errorf("write: status %v", sc)
					}
					dv, err := c.ReadValue(ctx, node)
					if err != nil {
						return fmt.Errorf("read: %w", err)
					}
					if got, _ := dv.Value.Value().([]byte); !bytes.Equal(got, want) {
						return fmt.Errorf("read back %d bytes that differ from the %d written (chunks of different messages mixed up?)", len(got), len(want))
					}
					// interleave with the shared blob and a tiny request
					blob, err := c.ReadValue(ctx, e.blobID())
					if err != nil {
						return fmt.Errorf("read blob: %w", err)
					}
					if b, _ := blob.Value.Value().([]byte); len(b) != blobSize {
						return fmt.Errorf("blob: %d bytes, want %d", len(b), blobSize)
					}
					res, err := c.CallMethod(ctx, e.objectsID(), e.methodID(), int32(g+i))
					if err != nil {
						return fmt.Errorf("call: %w", err)
					}
					if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != int32((g+i)*(g+i)) {
						return fmt.Errorf("call(%d): unexpected result %v %v", g+i, res.StatusCode, res.OutputArguments)
					}
					return nil
				})
				if err != nil {
					sink.addf("goroutine %d iteration %d: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	wd.wait("large messages", &wg)
	sink.report(t)
}

// TestParallelAddressSpaceMutation adds and deletes nodes (through the
// NodeManagement services and directly on the server) while other goroutines
// browse and read the same part of the address space.
func TestParallelAddressSpaceMutation(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	c := e.connect(nil)

	const mutators, readers, rounds = 3, 4, 10
	var sink errSink
	var stop atomic.Bool
	var wg, rwg sync.WaitGroup

	// client-side mutators: AddNodes / write / DeleteNodes
	for g := 0; g < mutators; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				name := fmt.Sprintf("Dyn%d_%d", g, r)
				nid := e.nodeID(name)
				err := wd.do("add/delete node", func() error {
					ctx, cancel := opCtx()
					defer cancel()
					add, err := c.AddNodes(ctx, &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{{
						ParentNodeID:       ua.NewExpandedNodeID(e.folderID(), "", 0),
						ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
						RequestedNewNodeID: ua.NewExpandedNodeID(nid, "", 0),
						BrowseName:         &ua.QualifiedName{NamespaceIndex: e.ns, Name: name},
						NodeClass:          ua.NodeClassVariable,
						TypeDefinition:     ua.NewNumericExpandedNodeID(0, 0),
					}}})
					if err != nil {
						return fmt.Errorf("add: %w", err)
					}
					if add.Results[0].StatusCode != ua.StatusOK {
						return fmt.Errorf("add: status %v", add.Results[0].StatusCode)
					}
					if sc, err := c.WriteNodeValue(ctx, nid, int32(r)); err != nil || sc != ua.StatusOK {
						return fmt.Errorf("write new node: status=%v err=%v", sc, err)
					}
					dv, err := c.ReadValue(ctx, nid)
					if err != nil {
						return fmt.Errorf("read new node: %w", err)
					}
					if dv.Value == nil || dv.Value.Value() != int32(r) {
						return fmt.Errorf("read new node: got %v want %d", dv.Value, r)
					}
					del, err := c.DeleteNodes(ctx, &ua.DeleteNodesRequest{NodesToDelete: []*ua.DeleteNodesItem{{NodeID: nid, DeleteTargetReferences: true}}})
					if err != nil {
						return fmt.Errorf("delete: %w", err)
					}
					if del.Results[0] != ua.StatusOK {
						return fmt.Errorf("delete: status %v", del.Results[0])
					}
					return nil
				})
				if err != nil {
					sink.addf("mutator %d round %d: %v", g, r, err)
					return
				}
			}
		}(g)
	}

	// server-side mutator: the embedding application grows the address space
	wg.Add(1)
	go func() {
		defer wg.Done()
		ns := e.namespace()
		folder := ns.Node(e.folderID())
		for r := 0; r < rounds*4; r++ {
			n := ns.AddNewVariableStringNode(fmt.Sprintf("Srv%d", r), int32(r))
			folder.AddRef(n, id.HasComponent, true)
			if r%3 == 0 {
				_ = ns.DeleteNode(n.ID())
			}
			time.Sleep(time.Millisecond)
		}
	}()

	// readers: browse the mutating folder and read stable + volatile nodes
	for g := 0; g < readers; g++ {
		rwg.Add(1)
		go func(g int) {
			defer rwg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g)))
			for !stop.Load() {
				err := wd.do("browse/read during mutation", func() error {
					ctx, cancel := opCtx()
					defer cancel()
					refs, err := c.BrowseAll(ctx, e.folderID())
					if err != nil {
						return fmt.Errorf("browse: %w", err)
					}
					if n := countLeaves(refs); n != numBrowse {
						return fmt.Errorf("browse: %d leaves, the %d static leaves must always be present", n, numBrowse)
					}
					// a node that may be deleted at any time: any status is fine,
					// a transport-level error is not
					ref := refs[rng.Intn(len(refs))]
					if _, err := c.ReadValue(ctx, ua.NewStringNodeID(e.ns, ref.NodeID.NodeID.StringID())); err != nil {
						return fmt.Errorf("read %v: %w", ref.NodeID, err)
					}
					dv, err := c.ReadValue(ctx, e.nodeID(fmt.Sprintf("Leaf%03d", rng.Intn(numBrowse))))
					if err != nil {
						return fmt.Errorf("read leaf: %w", err)
					}
					if dv.Status != ua.StatusOK {
						return fmt.Errorf("read leaf: status %v", dv.Status)
					}
					return nil
				})
				if err != nil {
					sink.addf("reader %d: %v", g, err)
					return
				}
			}
		}(g)
	}

	wd.wait("mutators", &wg)
	stop.Store(true)
	wd.wait("readers", &rwg)
	sink.report(t)
}

// TestParallelServerSideWritesAndReads updates values from the embedding
// application while clients read, write and monitor the same nodes.
func TestParallelServerSideWritesAndReads(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	c := e.connect(nil)

	ctx, cancel := opCtx()
	defer cancel()
	st, err := openStream(ctx, e, c, "srvwrites", 8, false, 0, 1, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	var sink errSink
	var wg sync.WaitGroup
	for i := 0; i < numCounters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 300; n++ {
				e.bump(i)
			}
		}(i)
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			last := int64(-1)
			for n := 0; n < 100; n++ {
				err := wd.do("read counter", func() error {
					ctx, cancel := opCtx()
					defer cancel()
					dv, err := c.ReadValue(ctx, e.counterID(g))
					if err != nil {
						return err
					}
					v, ok := dv.Value.Value().(int64)
					if !ok {
						return fmt.Errorf("counter value is %T", dv.Value.Value())
					}
					if v < last {
						return fmt.Errorf("counter %d read %d after %d", g, v, last)
					}
					last = v
					return nil
				})
				if err != nil {
					sink.addf("reader %d: %v", g, err)
					return
				}
			}
		}(g)
	}
	wd.wait("server-side writers and readers", &wg)
	sink.report(t)

	for i := 0; i < numCounters; i++ {
		want := e.counters[i].Load()
		if !eventually(settleLimit, func() bool { return st.lastValue(i) == want }) {
			t.Errorf("counter %d: subscription ended on %d, node holds %d", i, st.lastValue(i), want)
		}
	}
	if err := st.sub.Cancel(ctx); err != nil {
		t.Errorf("cancel: %v", err)
	}
	st.close()
	st.report(t)
}
