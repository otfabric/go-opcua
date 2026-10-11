// SPDX-License-Identifier: MIT

package datachange

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

const (
	stormClients       = 3
	stormSubsPerClient = 2
)

// stormSpecs is the fixed set of items every subscription of the fault
// scenario monitors: each trigger and deadband type, scalars and arrays,
// every kind of sampling interval, and index ranges.
func stormSpecs(e *env) []itemSpec {
	d, a, i := e.node(kindDouble, 0), e.node(kindAnalog, 0), e.node(kindInt32, 0)
	da, aa, ia := e.node(kindDoubleArray, 0), e.node(kindAnalogArray, 0), e.node(kindInt32Array, 0)
	const (
		status = ua.DataChangeTriggerStatus
		value  = ua.DataChangeTriggerStatusValue
		stamp  = ua.DataChangeTriggerStatusValueTimestamp
		none   = ua.DeadbandTypeNone
		abs    = ua.DeadbandTypeAbsolute
		pct    = ua.DeadbandTypePercent
	)
	specs := []itemSpec{
		{n: d, noFilter: true}, // every change: must stay the first, see silence
		{n: d, trigger: value, deadbandType: abs, deadband: 5},
		{n: d, trigger: stamp, deadbandType: none, samplingMS: samplingPublish},
		{n: a, trigger: value, deadbandType: pct, deadband: 5, samplingMS: samplingLongMS},
		{n: a, trigger: status, deadbandType: none},
		{n: i, trigger: value, deadbandType: abs, deadband: 4, samplingMS: samplingShortMS},
		{n: i, noFilter: true, samplingMS: samplingLongMS},
		{n: da, trigger: value, deadbandType: abs, deadband: 5, indexRange: "1:3"},
		{n: da, noFilter: true, indexRange: "4", samplingMS: samplingLongMS},
		{n: aa, trigger: value, deadbandType: pct, deadband: 10, samplingMS: samplingShortMS},
		{n: ia, trigger: stamp, deadbandType: abs, deadband: 4, indexRange: "0:1", samplingMS: samplingPublish},
		{n: ia, trigger: status, deadbandType: none, indexRange: "4"},
		{n: ia, trigger: stamp, deadbandType: none},
	}
	for k := range specs {
		specs[k].discardOldest = k%2 == 0
	}
	return specs
}

// stormClient is a long-lived client that must survive the whole storm.
type stormClient struct {
	name     string
	c        *opcua.Client
	rec      *chaoskit.StateRecorder
	trackers []*tracker

	mu       sync.Mutex
	outcomes map[opcua.SubscriptionRecoveryOutcome]int
}

func (sc *stormClient) recovered(ev opcua.SubscriptionRecoveryEvent) {
	sc.mu.Lock()
	sc.outcomes[ev.Outcome]++
	sc.mu.Unlock()
}

// storm is the fault scenario.
type storm struct {
	t    *testing.T
	e    *env
	seed int64
	wd   *chaoskit.Watchdog
	sink chaoskit.ErrSink

	clients []*stormClient
	items   []*item // the reporting items of all subscriptions
	silent  []*item // items that were taken out of Reporting mode

	stop    chan struct{}
	workers sync.WaitGroup
	writes  atomic.Int64

	// findings are the problems of the current run of the probe.
	findings []string
}

func (s *storm) findf(format string, args ...any) {
	s.findings = append(s.findings, fmt.Sprintf(format, args...))
}

// recoveries returns how often the clients reconnected or recovered a
// subscription so far.
func (s *storm) recoveries() int {
	n := 0
	for _, sc := range s.clients {
		n += sc.rec.Count(opcua.Reconnecting) + sc.rec.Count(opcua.Disconnected)
		sc.mu.Lock()
		for _, c := range sc.outcomes {
			n += c
		}
		sc.mu.Unlock()
	}
	return n
}

func (s *storm) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// sleep waits for d or until the writers are stopped.
func (s *storm) sleep(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.stop:
	case <-t.C:
	}
}

// stormParams are the subscription parameters of the scenario. The lifetime
// is 10 s without a Publish request: long enough for a client to come back
// after a fault, and short enough that a subscription the storm orphaned on
// the server is reclaimed while the test still runs.
func stormParams(interval time.Duration) *opcua.SubscriptionParameters {
	return &opcua.SubscriptionParameters{
		Interval:          interval,
		MaxKeepAliveCount: 5,
		LifetimeCount:     uint32(10 * time.Second / interval),
	}
}

func (s *storm) start() {
	s.t.Helper()
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	for ci := 0; ci < stormClients; ci++ {
		sc := &stormClient{name: fmt.Sprintf("p%d", ci), outcomes: make(map[opcua.SubscriptionRecoveryOutcome]int)}
		sc.rec = chaoskit.NewStateRecorder(sc.name, true)
		// A short request timeout lets calls swallowed by a blackhole return
		// quickly, a short secure channel lifetime forces token renewals, and
		// a short session timeout lets the server reclaim orphaned sessions.
		sc.c = s.e.connect(sc.rec,
			opcua.RequestTimeout(3*time.Second),
			opcua.Lifetime(2*time.Second),
			opcua.SessionTimeout(10*time.Second),
			opcua.WithSubscriptionRecoveryHandler(sc.recovered),
		)
		for si := 0; si < stormSubsPerClient; si++ {
			name := fmt.Sprintf("%s.s%d", sc.name, si)
			tr, err := newTracker(ctx, s.e, sc.c, name, stormParams([]time.Duration{50, 20}[si]*time.Millisecond), true, &s.sink)
			if err != nil {
				s.t.Fatal(err)
			}
			sc.trackers = append(sc.trackers, tr)
			items, err := tr.create(ctx, ua.MonitoringModeReporting, false, stormSpecs(s.e)...)
			if err != nil {
				s.t.Fatal(err)
			}
			s.items = append(s.items, items...)
			s.silence(ctx, tr, items[0])
		}
		s.clients = append(s.clients, sc)
	}

	for ni, n := range s.e.nodes {
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			rng := rand.New(rand.NewSource(s.seed + int64(1000+ni)))
			for !s.stopped() {
				if _, ok := s.e.randomSet(n, rng); ok {
					s.writes.Add(1)
				}
				s.sleep(time.Duration(2000+rng.Intn(4000)) * time.Microsecond)
			}
		}()
	}
}

// silence adds three items that must never deliver anything from now on: one
// that is switched from Reporting to Sampling, one that is switched from
// Reporting to Disabled, and one that is created Disabled. A subscription
// that is recreated after a fault has to bring them back in these modes.
//
// witness is a Reporting item without filter on the same node and in the
// same subscription. Once it has delivered a value written after the mode
// changes, everything the three items had queued before has been delivered.
func (s *storm) silence(ctx context.Context, tr *tracker, witness *item) {
	s.t.Helper()
	spec := itemSpec{n: witness.spec.n, noFilter: true, discardOldest: true}
	items, err := tr.create(ctx, ua.MonitoringModeReporting, false, spec, spec)
	if err != nil {
		s.t.Fatal(err)
	}
	disabled, err := tr.create(ctx, ua.MonitoringModeDisabled, false, spec)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := tr.setMode(ctx, items[0], ua.MonitoringModeSampling); err != nil {
		s.t.Fatal(err)
	}
	if err := tr.setMode(ctx, items[1], ua.MonitoringModeDisabled); err != nil {
		s.t.Fatal(err)
	}
	w, _ := s.e.set(spec.n, spec.n.uniform(60+float64(len(s.silent))), ua.StatusOK)
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last, ok := witness.lastSeen()
		return ok && last.seq >= w.seq
	}) {
		s.t.Fatalf("%v did not deliver write %d", witness, w.seq)
	}
	for _, it := range append(items, disabled...) {
		it.mu.Lock()
		it.silent = true
		it.mu.Unlock()
		s.silent = append(s.silent, it)
	}
}

// fault is one action of the monkey.
type fault struct {
	name   string
	weight int
	apply  func(s *storm, rng *rand.Rand, hold time.Duration)
}

func dir(rng *rand.Rand) testutil.Direction { return testutil.Direction(rng.Intn(2)) }

// faults are the faults that do not alter message contents.
var faults = []fault{
	{name: "drop all connections", weight: 4, apply: func(s *storm, _ *rand.Rand, _ time.Duration) {
		s.e.proxy.DropAll()
	}},
	{name: "half-close", weight: 3, apply: func(s *storm, rng *rand.Rand, _ time.Duration) {
		s.e.proxy.HalfClose(dir(rng))
	}},
	{name: "blackhole one direction", weight: 3, apply: func(s *storm, rng *rand.Rand, hold time.Duration) {
		d := dir(rng)
		s.e.proxy.SetBlackhole(d, true)
		time.Sleep(hold)
		s.e.proxy.SetBlackhole(d, false)
		// Bytes were swallowed, so the byte streams may be cut inside a
		// message. A real network would have lost the connection too.
		s.e.proxy.DropAll()
	}},
	{name: "blackhole both directions", weight: 2, apply: func(s *storm, _ *rand.Rand, hold time.Duration) {
		s.e.proxy.SetBlackhole(testutil.ClientToServer, true)
		s.e.proxy.SetBlackhole(testutil.ServerToClient, true)
		time.Sleep(hold)
		s.e.proxy.SetBlackhole(testutil.ClientToServer, false)
		s.e.proxy.SetBlackhole(testutil.ServerToClient, false)
		s.e.proxy.DropAll()
	}},
	{name: "latency and jitter", weight: 3, apply: func(s *storm, rng *rand.Rand, hold time.Duration) {
		s.e.proxy.SetLatency(time.Duration(1+rng.Intn(30))*time.Millisecond, time.Duration(rng.Intn(20))*time.Millisecond)
		time.Sleep(hold)
		s.e.proxy.SetLatency(0, 0)
	}},
	{name: "byte-level fragmentation", weight: 3, apply: func(s *storm, rng *rand.Rand, hold time.Duration) {
		s.e.proxy.SetFragment(1 + rng.Intn(7))
		time.Sleep(hold)
		s.e.proxy.SetFragment(0)
	}},
	{name: "bandwidth throttle", weight: 2, apply: func(s *storm, rng *rand.Rand, hold time.Duration) {
		s.e.proxy.SetThrottle((8 + rng.Intn(120)) * 1024)
		time.Sleep(hold)
		s.e.proxy.SetThrottle(0)
	}},
	{name: "truncate mid-message", weight: 3, apply: func(s *storm, rng *rand.Rand, _ time.Duration) {
		s.e.proxy.TruncateNext(dir(rng), 1+rng.Intn(200))
	}},
	{name: "server unreachable", weight: 3, apply: func(s *storm, _ *rand.Rand, hold time.Duration) {
		s.e.proxy.SetRefuse(true)
		s.e.proxy.DropAll()
		time.Sleep(hold)
		s.e.proxy.SetRefuse(false)
	}},
	{name: "server restart", weight: 3, apply: func(s *storm, _ *rand.Rand, hold time.Duration) {
		s.e.restartServer(hold / 4)
	}},
}

// monkey injects random faults for the given duration and then restarts the
// server once more, so that every subscription has to be recreated at least
// once whatever the random schedule was.
func (s *storm) monkey(d time.Duration) {
	rng := rand.New(rand.NewSource(s.seed))
	var pool []fault
	for _, f := range faults {
		for i := 0; i < f.weight; i++ {
			pool = append(pool, f)
		}
	}
	start := time.Now()
	for n := 0; time.Since(start) < d; n++ {
		f := pool[rng.Intn(len(pool))]
		hold := time.Duration(50+rng.Intn(550)) * time.Millisecond
		s.t.Logf("[%6.2fs] fault %d: %s", time.Since(start).Seconds(), n, f.name)
		f.apply(s, rng, hold)
		// leave some room between faults: sometimes enough to recover fully,
		// sometimes so little that the next fault hits a reconnect in progress
		time.Sleep(time.Duration(rng.Intn(400)) * time.Millisecond)
	}
	s.e.proxy.Heal()
	s.t.Logf("[%6.2fs] final server restart", time.Since(start).Seconds())
	s.e.restartServer(50 * time.Millisecond)
}

// verifyRecovery checks that, once the faults are gone, every client returns
// to Connected.
func (s *storm) verifyRecovery() bool {
	s.t.Helper()
	for _, sc := range s.clients {
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return sc.c.State() == opcua.Connected }) {
			s.t.Errorf("STUCK: client %s did not return to Connected within %v after the faults stopped; state=%v transitions=%v\n%s",
				sc.name, chaoskit.SettleLimit, sc.c.State(), sc.rec.Snapshot(), chaoskit.AllStacks())
			return false
		}
	}
	return true
}

// writeAll writes one value to every node and waits until every item has
// sampled it.
func (s *storm) writeAll(status ua.StatusCode, value func(n *node) any) map[*node]write {
	out := make(map[*node]write, len(s.e.nodes))
	for _, n := range s.e.nodes {
		w, ok := s.e.set(n, value(n), status)
		if !ok {
			s.t.Fatalf("no server is running")
		}
		out[n] = w
	}
	s.e.waitSamplerIdle()
	return out
}

// waitDelivered waits until every reporting item has delivered the write of
// its node in ws.
func (s *storm) waitDelivered(what string, ws map[*node]write) bool {
	s.t.Helper()
	pending := s.items
	chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		var still []*item
		for _, it := range pending {
			if last, ok := it.lastSeen(); !ok || last.seq != ws[it.spec.n].seq {
				still = append(still, it)
			}
		}
		pending = still
		return len(pending) == 0
	})
	for i, it := range pending {
		if i == 5 {
			s.findf("... and %d more", len(pending)-i)
			break
		}
		last, _ := it.lastSeen()
		s.findf("STUCK: %v did not deliver %s (write %d of its node) within %v: last delivered %v; server holds %+v",
			it, what, ws[it.spec.n].seq, chaoskit.SettleLimit, last.sample, s.e.resources())
	}
	return len(pending) == 0
}

// seqs returns the sequence numbers of the logged notifications from seq
// from on.
func seqs(log []seenValue, from int64) []int64 {
	out := []int64{}
	for _, v := range log {
		if v.seq >= from {
			out = append(out, v.seq)
		}
	}
	return out
}

// probe proves, by writing a scripted sequence of values, that every item
// still has its filter, sampling interval and index range after the storm.
// The writers are stopped, so what each item has to deliver is known exactly.
//
// That holds while nothing disturbs the subscriptions. A subscription that
// is recovered once more during the script (the storm is over, but nothing
// forbids it) starts over with its initial values; the script then proves
// nothing and is repeated.
func (s *storm) probe() {
	s.t.Helper()
	for attempt := 1; ; attempt++ {
		before := s.recoveries()
		s.findings = nil
		s.runProbe()
		if len(s.findings) == 0 {
			return
		}
		if s.recoveries() == before || attempt == 3 {
			for _, f := range s.findings {
				s.t.Error(f)
			}
			return
		}
		s.t.Logf("a subscription was recovered during attempt %d of the probe; repeating it", attempt)
	}
}

func (s *storm) runProbe() {
	const base = 40.0
	big := func(n *node) float64 { return 3 * n.kind.unit() }
	small := func(n *node) float64 {
		if n.kind.isInt() {
			return 1
		}
		return 0.4 * n.kind.unit()
	}

	// A change of status passes every filter: after this every item is at a
	// known value. It is also the proof that every item delivers again.
	s.writeAll(ua.StatusOK, func(n *node) any { return n.uniform(base + 1) })
	sync := s.writeAll(ua.StatusUncertainLastUsableValue, func(n *node) any { return n.uniform(base + 2) })
	if !s.waitDelivered("the first value after the storm", sync) {
		return
	}
	for _, it := range s.items {
		it.startLog()
	}

	// 1. Filter and index range: each step is sampled by every item before
	//    the next one is written, so what an item delivers is what its filter
	//    lets through of this list.
	steps := []probeStep{
		{"back to Good", ua.StatusOK, func(n *node) any { return n.uniform(base) }},
		{"a change below every deadband", ua.StatusOK, func(n *node) any { return n.uniform(base + small(n)) }},
		{"a change above every deadband", ua.StatusOK, func(n *node) any { return n.uniform(base + big(n)) }},
		{"the same value with a new timestamp", ua.StatusOK, func(n *node) any { return n.uniform(base + big(n)) }},
		{"a change outside every index range", ua.StatusOK, func(n *node) any {
			if n.kind.isArray() {
				return withElement(n.uniform(base+big(n)), arrayLen-1, big(n))
			}
			return n.uniform(base + big(n) - small(n))
		}},
		{"a change of status only", ua.StatusUncertainLastUsableValue, func(n *node) any { return n.last().value }},
	}
	script := make(map[*node][]write)
	end := make(map[*node]write)
	for _, st := range steps {
		for n, w := range s.writeAll(st.status, st.value) {
			script[n] = append(script[n], w)
			end[n] = w
		}
	}
	if !s.waitDelivered("the last step of the filter script", end) {
		return
	}
	for _, it := range s.items {
		flt := it.spec.resolve()
		ref := sync[it.spec.n].seen(it.spec.indexRange)
		want := []int64{}
		for _, w := range script[it.spec.n] {
			if cur := w.seen(it.spec.indexRange); flt.changed(ref, cur) {
				want = append(want, w.seq)
				ref = cur
			}
		}
		got := seqs(it.logged(), script[it.spec.n][0].seq)
		if !reflect.DeepEqual(got, want) {
			s.findf("FILTER NOT RESTORED: %v delivered steps %v of the script, filter %v lets %v through (steps: %s)",
				it, relative(got, script[it.spec.n]), flt, relative(want, script[it.spec.n]), stepNames(steps))
		}
	}

	// 2. Sampling interval: a burst of large changes, each of which passes
	//    every deadband.
	const burstLen = 40
	var burst map[*node][]write
	began := time.Now()
	for k := 0; k < burstLen; k++ {
		for _, n := range s.e.nodes {
			x := base - big(n)
			if k%2 == 1 {
				x = base + big(n)
			}
			w, _ := s.e.set(n, n.uniform(x), ua.StatusOK)
			if burst == nil {
				burst = make(map[*node][]write)
			}
			burst[n] = append(burst[n], w)
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.e.waitSamplerIdle()
	window := time.Since(began)
	done := s.writeAll(ua.StatusUncertainLastUsableValue, func(n *node) any { return n.uniform(base) })
	if !s.waitDelivered("the value after the burst", done) {
		return
	}
	for _, it := range s.items {
		bw := burst[it.spec.n]
		first, last := bw[0], bw[len(bw)-1]
		var got []seenValue
		overflow := false
		for _, v := range it.logged() {
			if v.seq >= first.seq && v.seq <= last.seq {
				got = append(got, v)
				overflow = overflow || v.overflow
			}
		}
		flt := it.spec.resolve()
		interval := it.current().interval
		switch {
		case len(got) == 0:
			s.findf("STUCK: %v delivered nothing of a burst of %d changes", it, burstLen)
		case flt.statusOnly:
			if len(got) != 1 {
				s.findf("FILTER NOT RESTORED: %v (status trigger) delivered %d values of a burst with one change of status", it, len(got))
			}
		case interval == 0:
			if len(got) != burstLen && !overflow {
				s.findf("SAMPLING INTERVAL NOT RESTORED: %v samples every change but delivered %d of %d", it, len(got), burstLen)
			}
		default:
			if limit := int(window/interval) + 1; len(got) > limit {
				s.findf("SAMPLING INTERVAL NOT RESTORED: %v delivered %d values of a burst of %v, at most %d fit a sampling interval of %v",
					it, len(got), window, limit, interval)
			}
			// The value the interval ends with is the latest one.
			if end := last.seen(it.spec.indexRange); flt.changed(got[len(got)-1].sample, end) {
				s.findf("STALE VALUE: %v delivered %v as the last value of the burst, the node ended at %v", it, got[len(got)-1].sample, end)
			}
		}
	}
}

// relative maps sequence numbers to the (1-based) step of the script.
func relative(got []int64, script []write) []int {
	out := []int{}
	for _, seq := range got {
		step := 0
		for i, w := range script {
			if w.seq == seq {
				step = i + 1
			}
		}
		out = append(out, step)
	}
	return out
}

// probeStep is one write of the filter script, applied to every node.
type probeStep struct {
	name   string
	status ua.StatusCode
	value  func(n *node) any
}

func stepNames(steps []probeStep) string {
	out := ""
	for i, st := range steps {
		out += fmt.Sprintf(" %d=%s;", i+1, st.name)
	}
	return out
}

// finish closes all clients and checks the invariants that hold after
// shutdown.
func (s *storm) finish(verifyLeaks func()) {
	s.t.Helper()
	recreated := 0
	for _, sc := range s.clients {
		_ = s.wd.Do("Close", func() error { chaoskit.CloseClient(sc.c, sc.rec); return nil })
		for _, tr := range sc.trackers {
			tr.close()
		}
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return sc.c.State() == opcua.Closed }) {
			s.t.Errorf("client %s: State() is %v after Close", sc.name, sc.c.State())
		}
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { last, ok := sc.rec.Last(); return ok && last == opcua.Closed }) {
			s.t.Errorf("client %s: last reported state after Close is not Closed: %v", sc.name, sc.rec.Snapshot())
		}
		sc.rec.Check(s.t, true)
		sc.mu.Lock()
		recreated += sc.outcomes[opcua.SubscriptionRecoveryRecreated]
		s.t.Logf("client %s: subscription recoveries %v, %d reconnects", sc.name, sc.outcomes, sc.rec.Count(opcua.Reconnecting))
		sc.mu.Unlock()
	}
	s.sink.Report(s.t)
	var received int64
	for _, sc := range s.clients {
		for _, tr := range sc.trackers {
			received += tr.received.Load()
			if es := tr.errs.String(); es != "ok=0" {
				s.t.Logf("%s: error notifications: %s", tr.name, es)
			}
		}
	}
	s.t.Logf("%d writes, %d notifications, %d subscription recreations", s.writes.Load(), received, recreated)
	if recreated < stormClients*stormSubsPerClient {
		s.t.Errorf("only %d subscriptions were recreated although the server was restarted under %d", recreated, stormClients*stormSubsPerClient)
	}
	s.e.requireDrained()
	s.e.stopServer()
	s.e.mu.Lock()
	old := append([]*server.Server(nil), s.e.old...)
	s.e.mu.Unlock()
	for i, srv := range old {
		requireSamplerStopped(s.t, srv, fmt.Sprintf("after server instance %d was closed", i+1))
	}
	s.e.proxy.Close()
	s.wd.Close()
	verifyLeaks()
}

// TestChaosFilterRecreation keeps filtered and sampled items alive on
// AutoReconnect clients while the monkey injects every fault that does not
// alter message contents: connection resets, half-closes, blackholes,
// latency, fragmentation, throttling, truncation, an unreachable and a
// restarting server.
//
// During the storm no delivered value may violate the filter of its item
// (judged so that lost notifications cannot be mistaken for a violation),
// be anything but a written value reduced to the index range, go backwards,
// or come from an item that is not in Reporting mode. Afterwards the clients
// must be Connected again and the recreated items must behave exactly as
// configured: a change below the deadband is not delivered and one above is,
// a change outside the index range is not delivered, a status change always
// is, and a burst of changes yields at most one value per sampling interval,
// ending with the latest. Finally the server, its sampler included, must
// hold nothing and no goroutine may be left.
func TestChaosFilterRecreation(t *testing.T) {
	verifyLeaks := chaoskit.LeakCheck(t)
	seed := chaoskit.Seed(t)
	s := &storm{
		t:    t,
		e:    newEnv(t, seed, 1),
		seed: seed,
		wd:   chaoskit.NewWatchdog(t),
		stop: make(chan struct{}),
	}
	s.start()
	s.monkey(chaoskit.Duration(t, 2500*time.Millisecond))
	recovered := s.verifyRecovery()
	close(s.stop)
	s.wd.Wait("writers", &s.workers)
	if recovered {
		s.probe()
	}
	s.finish(verifyLeaks)
}
