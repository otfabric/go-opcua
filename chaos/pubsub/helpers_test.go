// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/testport"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// defaultDuration is the length of the fault phase of a randomized scenario
// when CHAOS_DURATION is not set. The scenarios run in parallel; the package
// has to stay well inside the 120 s CI gives it under the race detector.
const defaultDuration = 2 * time.Second

// settle bounds the waits for an effect that follows within a few publishing
// intervals on an idle machine (first message, recovery, state change).
const settle = 15 * time.Second

// ---------------------------------------------------------------------------
// addresses
// ---------------------------------------------------------------------------

// freeUDPPort returns a UDP port that was free a moment ago.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	return testport.UDP(t)
}

func udpURL(port int) string { return fmt.Sprintf("opc.udp://127.0.0.1:%d", port) }

// ---------------------------------------------------------------------------
// published values
// ---------------------------------------------------------------------------

// The published data sets of the suite have three fields that a subscriber
// can check without knowing what was sent: n is a counter that the data
// source increments at every sample of the data set, chk names the data set
// and repeats n, and f is n/4. A delivered data set whose fields do not fit
// together was corrupted or mixed up; one whose n does not grow is a
// duplicate or stale.

func fieldNode(ds, field string) *ua.NodeID {
	return ua.NewStringNodeID(1, ds+"."+field)
}

func checkString(ds string, n int64) string { return fmt.Sprintf("%s#%d", ds, n) }

// counterPDS returns the published data set ds with the fields n, chk and f.
func counterPDS(ds string) *ua.PublishedDataSetDataType {
	return pubsub.PublishedDataItems(ds,
		pubsub.Var("n", fieldNode(ds, "n"), ua.TypeIDInt64),
		pubsub.Var("chk", fieldNode(ds, "chk"), ua.TypeIDString),
		pubsub.Var("f", fieldNode(ds, "f"), ua.TypeIDDouble))
}

// counterSource is the DataSource of the counter data sets.
type counterSource struct {
	mu sync.Mutex
	n  map[string]int64
}

func newCounterSource() *counterSource { return &counterSource{n: map[string]int64{}} }

func (s *counterSource) ReadPublishedData(_ context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue {
	out := make([]*ua.DataValue, len(vars))
	if len(vars) == 0 {
		return out
	}
	ds, _, _ := strings.Cut(vars[0].PublishedVariable.StringID(), ".")
	s.mu.Lock()
	s.n[ds]++
	n := s.n[ds]
	s.mu.Unlock()
	now := time.Now()
	for i, v := range vars {
		_, field, _ := strings.Cut(v.PublishedVariable.StringID(), ".")
		var val any
		switch field {
		case "n":
			val = n
		case "chk":
			val = checkString(ds, n)
		case "f":
			val = float64(n) / 4
		default:
			out[i] = &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadNodeIDUnknown}
			continue
		}
		dv := &ua.DataValue{Value: ua.MustVariant(val), SourceTimestamp: now}
		dv.UpdateMask()
		out[i] = dv
	}
	return out
}

// ---------------------------------------------------------------------------
// checking received data sets
// ---------------------------------------------------------------------------

// checker is a DataSetHandler that verifies every delivered data set of the
// counter data sets: the fields fit together and have their types, the
// sequence number and the counter of a writer only grow.
//
// The data set of a reader is the part of its name before "|".
type checker struct {
	sink *chaoskit.ErrSink

	mu      sync.Mutex
	streams map[string]*rstream
	total   atomic.Int64

	// restartEnd and restarting are maintained by a test whose operations
	// restart the readers (see restart): a restarted reader starts over
	// (Part 14 §7.2.2.3.4) and accepts a message the kernel delivers late
	// that its predecessor would have discarded as older. The order of
	// two data sets is only checked when no restart came between them.
	//
	// The runtime checks the order when it processes a message and calls
	// the handler later, after releasing its lock, so a restart can fall
	// between the two: the restarts are bounded by the Timestamp of the
	// earlier data set (taken by the publisher or at reception, before the
	// runtime processed it), not by the handler call.
	restartEnd atomic.Int64 // UnixNano of the end of the latest restart
	restarting atomic.Int64
}

// restart runs op, an operation that may restart the readers.
func (c *checker) restart(op func()) {
	c.restarting.Add(1)
	defer func() {
		end := time.Now().UnixNano()
		for {
			old := c.restartEnd.Load()
			if old >= end || c.restartEnd.CompareAndSwap(old, end) {
				break
			}
		}
		c.restarting.Add(-1)
	}()
	op()
}

// restartedSince reports whether a reader restart may have happened since
// t: one is in progress or ended after t.
func (c *checker) restartedSince(t time.Time) bool {
	if c.restarting.Load() != 0 {
		return true
	}
	end := c.restartEnd.Load()
	return end != 0 && end >= t.UnixNano()
}

type rstream struct {
	hasSeq bool
	seq    uint16
	n      int64
	count  int64
	last   time.Time
	prevTS time.Time // Timestamp of the last data set
}

func newChecker() *checker {
	return &checker{sink: &chaoskit.ErrSink{}, streams: map[string]*rstream{}}
}

func dsOfReader(name string) string {
	ds, _, _ := strings.Cut(name, "|")
	return ds
}

func (c *checker) handle(d *pubsub.ReceivedDataSet) {
	c.total.Add(1)
	ds := dsOfReader(d.ReaderName)
	key := fmt.Sprintf("%s/%s/%d/%d", d.ReaderName, d.PublisherID, d.WriterGroupID, d.DataSetWriterID)
	if d.MessageType != message.DataSetMessageKeyFrame {
		c.sink.Addf("%s: unexpected message type %v", key, d.MessageType)
		return
	}
	if !d.Complete {
		c.sink.Addf("%s: incomplete data set", key)
		return
	}
	if d.Status != ua.StatusGood {
		c.sink.Addf("%s: data set status %v", key, d.Status)
	}
	nv, chk, f := d.Field("n"), d.Field("chk"), d.Field("f")
	if nv == nil && chk == nil && f == nil && len(d.Fields) == 3 && d.Fields[0].Name == "" {
		// A reader without DataSetMetaData before it learned it: the
		// fields by position.
		nv, chk, f = d.Fields[0].Value, d.Fields[1].Value, d.Fields[2].Value
	}
	if nv == nil || chk == nil || f == nil || nv.Value == nil || chk.Value == nil || f.Value == nil {
		c.sink.Addf("%s: missing fields: %+v", key, d.Fields)
		return
	}
	n, ok1 := nv.Value.Value().(int64)
	s, ok2 := chk.Value.Value().(string)
	fv, ok3 := f.Value.Value().(float64)
	if !ok1 || !ok2 || !ok3 {
		c.sink.Addf("%s: field types %T %T %T", key, nv.Value.Value(), chk.Value.Value(), f.Value.Value())
		return
	}
	if s != checkString(ds, n) || fv != float64(n)/4 {
		c.sink.Addf("%s: corrupt data set n=%d chk=%q f=%v", key, n, s, fv)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.streams[key]
	if st == nil {
		st = &rstream{}
		c.streams[key] = st
	}
	ordered := st.count > 0 && !c.restartedSince(st.prevTS)
	st.prevTS = d.Timestamp
	if !ordered {
		st.hasSeq = false
	}
	if ordered && st.count > 0 && n <= st.n {
		c.sink.Addf("%s: counter went from %d to %d (seq %d after %d): duplicate or stale data set", key, st.n, n, d.SequenceNumber, st.seq)
	}
	seq := uint16(d.SequenceNumber)
	if st.hasSeq {
		if d := seq - st.seq; d == 0 || d >= 1<<14 {
			c.sink.Addf("%s: sequence number went from %d to %d", key, st.seq, seq)
		}
	}
	st.hasSeq = true
	st.seq = seq
	st.n = n
	st.count++
	st.last = time.Now()
}

// count returns the number of data sets delivered for a reader name prefix.
func (c *checker) count(reader string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n int64
	for k, st := range c.streams {
		if strings.HasPrefix(k, reader+"/") {
			n += st.count
		}
	}
	return n
}

// waitGrowth waits until every reader got at least more data sets.
func (c *checker) waitGrowth(t *testing.T, more int64, readers ...string) {
	t.Helper()
	base := make([]int64, len(readers))
	for i, r := range readers {
		base[i] = c.count(r)
	}
	ok := chaoskit.Eventually(settle, func() bool {
		for i, r := range readers {
			if c.count(r) < base[i]+more {
				return false
			}
		}
		return true
	})
	if !ok {
		for i, r := range readers {
			t.Errorf("reader %s: %d data sets after %d, want %d more", r, c.count(r), base[i], more)
		}
		t.FailNow()
	}
}

// ---------------------------------------------------------------------------
// state transitions
// ---------------------------------------------------------------------------

// stateLog records the state transitions of the readers of a runtime and
// checks that they are legal for a running reader.
type stateLog struct {
	sink *chaoskit.ErrSink

	mu    sync.Mutex
	stop  bool
	trans map[string][]ua.PubSubState
}

func newStateLog(sink *chaoskit.ErrSink) *stateLog {
	return &stateLog{sink: sink, trans: map[string][]ua.PubSubState{}}
}

func (l *stateLog) handle(ev pubsub.Event) {
	if ev.Type != pubsub.EventStateChanged || ev.Component.Kind != pubsub.KindDataSetReader {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.trans[ev.Component.Name] = append(l.trans[ev.Component.Name], ev.Component.State)
	if l.stop {
		return
	}
	from, to := ev.OldState, ev.Component.State
	legal := map[ua.PubSubState][]ua.PubSubState{
		ua.PubSubStateDisabled:       {ua.PubSubStatePreOperational, ua.PubSubStatePaused},
		ua.PubSubStatePaused:         {ua.PubSubStatePreOperational, ua.PubSubStateDisabled},
		ua.PubSubStatePreOperational: {ua.PubSubStateOperational, ua.PubSubStateError, ua.PubSubStatePaused, ua.PubSubStateDisabled},
		ua.PubSubStateOperational:    {ua.PubSubStateError, ua.PubSubStatePaused, ua.PubSubStateDisabled},
		ua.PubSubStateError:          {ua.PubSubStateOperational, ua.PubSubStatePaused, ua.PubSubStateDisabled},
	}
	ok := false
	for _, s := range legal[from] {
		if s == to {
			ok = true
		}
	}
	if !ok {
		l.sink.Addf("reader %s: illegal transition %v -> %v", ev.Component.Name, from, to)
	}
}

// count returns how often reader entered state s.
func (l *stateLog) count(reader string, s ua.PubSubState) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, x := range l.trans[reader] {
		if x == s {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// runtimes
// ---------------------------------------------------------------------------

// startRuntime creates and starts a runtime that is closed when the test
// ends (and must close within the bound).
func startRuntime(t *testing.T, cfg *ua.PubSubConfigurationDataType, opts ...pubsub.Option) *pubsub.PubSub {
	t.Helper()
	opts = append([]pubsub.Option{pubsub.WithLogger(chaoskit.Logger()), pubsub.WithRetryInterval(100 * time.Millisecond)}, opts...)
	if chaoskit.Logger() == nil {
		opts = opts[1:]
	}
	rt, err := pubsub.New(cfg, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeRuntime(t, rt) })
	return rt
}

// closeRuntime closes a runtime and fails the test if Close hangs.
func closeRuntime(t *testing.T, rt *pubsub.PubSub) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = rt.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(chaoskit.OpLimit):
		t.Errorf("DEADLOCK: PubSub.Close did not return within %v\n%s", chaoskit.OpLimit, chaoskit.AllStacks())
	}
}

// compID returns the id of a component by kind and name, anywhere in the
// runtime.
func compID(t *testing.T, rt *pubsub.PubSub, kind pubsub.ComponentKind, name string) pubsub.ComponentID {
	t.Helper()
	for _, c := range rt.Components() {
		if c.Kind == kind && c.Name == name {
			return c.ID
		}
	}
	t.Fatalf("no %v %q", kind, name)
	return 0
}

// waitState waits until a component is in one of the states.
func waitState(t *testing.T, rt *pubsub.PubSub, cid pubsub.ComponentID, states ...ua.PubSubState) {
	t.Helper()
	var last ua.PubSubState
	ok := chaoskit.Eventually(settle, func() bool {
		s, err := rt.State(cid)
		if err != nil {
			return false
		}
		last = s
		for _, x := range states {
			if s == x {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatalf("component %d is %v, want one of %v", cid, last, states)
	}
}

func status(t *testing.T, rt *pubsub.PubSub, cid pubsub.ComponentID) pubsub.Status {
	t.Helper()
	st, err := rt.Status(cid)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// keyService returns an in-process KeyService with the SecurityGroup sg.
func keyService(t *testing.T, sg, policy string, lifetime time.Duration, future, past uint32) *security.KeyService {
	t.Helper()
	ks := security.NewKeyService()
	if err := ks.AddSecurityGroup(security.SecurityGroupConfig{
		SecurityGroupID:   sg,
		SecurityPolicyURI: policy,
		KeyLifetime:       lifetime,
		MaxFutureKeyCount: future,
		MaxPastKeyCount:   past,
	}); err != nil {
		t.Fatal(err)
	}
	return ks
}

func keySource(t *testing.T, ks *security.KeyService, sg string) security.KeySource {
	t.Helper()
	src, err := ks.KeySource(sg)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// ---------------------------------------------------------------------------
// UDP fault relay
// ---------------------------------------------------------------------------

// faults is what the relay does to the datagrams it forwards. The
// probabilities are per datagram.
type faults struct {
	blackhole bool
	drop      float64
	dup       float64
	reorder   float64
	corrupt   float64
	truncate  float64
	delay     time.Duration // plus up to delay of jitter
}

func (f faults) String() string {
	if f == (faults{}) {
		return "clean"
	}
	if f.blackhole {
		return "blackhole"
	}
	var parts []string
	add := func(name string, p float64) {
		if p > 0 {
			parts = append(parts, fmt.Sprintf("%s=%.2f", name, p))
		}
	}
	add("drop", f.drop)
	add("dup", f.dup)
	add("reorder", f.reorder)
	add("corrupt", f.corrupt)
	add("truncate", f.truncate)
	if f.delay > 0 {
		parts = append(parts, "delay="+f.delay.String())
	}
	return strings.Join(parts, " ")
}

// relay forwards the datagrams of a publisher to a subscriber and disturbs
// them: it drops, duplicates, reorders, delays, corrupts and truncates
// datagrams, and lets a test inject datagrams of its own.
type relay struct {
	in   *net.UDPConn
	out  *net.UDPConn
	dest *net.UDPAddr

	f atomic.Pointer[faults]

	mu   sync.Mutex
	rng  *rand.Rand
	held []byte
	tap  [][]byte

	wg     sync.WaitGroup
	closed atomic.Bool

	forwarded, dropped, duplicated, reordered, corrupted, truncated atomic.Int64
}

const tapSize = 256

// newRelay starts a relay to 127.0.0.1:destPort. Publishers send to its URL.
func newRelay(t *testing.T, seed int64, destPort int) *relay {
	t.Helper()
	in, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	out, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = in.Close()
		t.Fatal(err)
	}
	r := &relay{in: in, out: out, dest: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: destPort}, rng: rand.New(rand.NewSource(seed))}
	r.f.Store(&faults{})
	r.wg.Add(1)
	go r.run()
	t.Cleanup(r.close)
	return r
}

func (r *relay) URL() string { return udpURL(r.in.LocalAddr().(*net.UDPAddr).Port) }

func (r *relay) set(f faults) {
	r.f.Store(&f)
	if f == (faults{}) {
		r.mu.Lock()
		held := r.held
		r.held = nil
		r.mu.Unlock()
		if held != nil {
			r.send(held)
		}
	}
}

// inject sends b to the subscriber, past all faults.
func (r *relay) inject(b []byte) { r.send(b) }

// captured returns copies of the last datagrams the publisher sent.
func (r *relay) captured() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.tap))
	for i, b := range r.tap {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

func (r *relay) close() {
	if r.closed.Swap(true) {
		return
	}
	_ = r.in.Close()
	r.wg.Wait()
	_ = r.out.Close()
}

func (r *relay) send(b []byte) {
	if r.closed.Load() {
		return
	}
	if _, err := r.out.WriteToUDP(b, r.dest); err == nil {
		r.forwarded.Add(1)
	}
}

func (r *relay) run() {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, _, err := r.in.ReadFromUDP(buf)
		if err != nil {
			if r.closed.Load() {
				return
			}
			continue
		}
		b := append([]byte(nil), buf[:n]...)
		f := r.f.Load()

		r.mu.Lock()
		if len(r.tap) == tapSize {
			r.tap = r.tap[1:]
		}
		r.tap = append(r.tap, append([]byte(nil), b...))
		roll := func(p float64) bool { return p > 0 && r.rng.Float64() < p }
		var sends [][]byte
		switch {
		case f.blackhole || roll(f.drop):
			r.dropped.Add(1)
		default:
			if roll(f.corrupt) {
				for range 1 + r.rng.Intn(3) {
					i := r.rng.Intn(len(b))
					b[i] ^= byte(1 + r.rng.Intn(255))
				}
				r.corrupted.Add(1)
			}
			if roll(f.truncate) && len(b) > 1 {
				b = b[:r.rng.Intn(len(b))]
				r.truncated.Add(1)
			}
			sends = append(sends, b)
			if roll(f.dup) {
				sends = append(sends, b)
				r.duplicated.Add(1)
			}
			if r.held != nil {
				sends = append(sends, r.held)
				r.held = nil
			} else if roll(f.reorder) {
				r.held, sends = b, sends[1:]
				r.reordered.Add(1)
			}
		}
		var delay time.Duration
		if f.delay > 0 {
			delay = f.delay + time.Duration(r.rng.Int63n(int64(f.delay)))
		}
		r.mu.Unlock()

		if len(sends) == 0 {
			continue
		}
		if delay == 0 {
			for _, s := range sends {
				r.send(s)
			}
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			time.Sleep(delay)
			for _, s := range sends {
				r.send(s)
			}
		}()
	}
}
