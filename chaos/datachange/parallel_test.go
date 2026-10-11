// SPDX-License-Identifier: MIT

package datachange

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// The tests in this file inject no faults. Every error is a failure.

const (
	parallelClients       = 3
	parallelSubsPerClient = 2
	parallelNodesPerKind  = 2
	parallelWildPerSub    = 3
	parallelServerWriters = 4
)

// longLived are the parameters of a subscription that must not expire in a
// fault-free test, however slow the machine is.
func longLived(interval time.Duration) *opcua.SubscriptionParameters {
	return &opcua.SubscriptionParameters{Interval: interval, MaxKeepAliveCount: 5, LifetimeCount: 6000}
}

// matrix returns one item per trigger, deadband type and shape (scalar or
// array), with the sampling intervals, index ranges and discard policies
// spread over them.
func matrix(e *env, perKind int) []itemSpec {
	var out []itemSpec
	for _, array := range []bool{false, true} {
		for _, trigger := range triggers {
			for _, dt := range []ua.DeadbandType{ua.DeadbandTypeNone, ua.DeadbandTypeAbsolute, ua.DeadbandTypePercent} {
				i := len(out)
				kind := []nodeKind{kindDouble, kindInt32}[i%2]
				deadband := 0.0
				switch dt {
				case ua.DeadbandTypePercent:
					kind, deadband = kindAnalog, 5
				case ua.DeadbandTypeAbsolute:
					deadband = kind.unit()
				case ua.DeadbandTypeNone:
				}
				if array {
					kind += kindDoubleArray
				}
				s := itemSpec{
					n:             e.node(kind, i%perKind),
					trigger:       trigger,
					deadbandType:  dt,
					deadband:      deadband,
					samplingMS:    samplings[i%len(samplings)],
					discardOldest: i%2 == 0,
				}
				if array {
					s.indexRange = indexRanges[i%len(indexRanges)]
				}
				out = append(out, s)
			}
		}
	}
	return out
}

// subject is a tracked subscription with the items the churn works on.
type subject struct {
	tr *tracker

	mu      sync.Mutex
	tracked []*item // operated on under item.ctl: every notification is judged
	wild    []*item // operated on without coordination
}

func (sj *subject) pick(rng *rand.Rand, wild bool) (int, *item) {
	sj.mu.Lock()
	defer sj.mu.Unlock()
	list := sj.tracked
	if wild {
		list = sj.wild
	}
	i := rng.Intn(len(list))
	return i, list[i]
}

func (sj *subject) replace(wild bool, slot int, it *item) {
	sj.mu.Lock()
	if wild {
		sj.wild[slot] = it
	} else {
		sj.tracked[slot] = it
	}
	sj.mu.Unlock()
}

func (sj *subject) live() (tracked, wild []*item) {
	sj.mu.Lock()
	defer sj.mu.Unlock()
	return append([]*item(nil), sj.tracked...), append([]*item(nil), sj.wild...)
}

type parallelRun struct {
	t    *testing.T
	e    *env
	seed int64
	wd   *chaoskit.Watchdog
	sink chaoskit.ErrSink

	clients  []*opcua.Client
	subjects []*subject

	stop    chan struct{}
	workers sync.WaitGroup
	ops     atomic.Int64
	writes  atomic.Int64
}

func (p *parallelRun) stopped() bool {
	select {
	case <-p.stop:
		return true
	default:
		return false
	}
}

// do runs one fault-free operation under the watchdog. Any error is a
// violation.
func (p *parallelRun) do(name string, fn func(ctx context.Context) error) bool {
	err := p.wd.Do(name, func() error {
		ctx, cancel := chaoskit.OpCtx()
		defer cancel()
		return fn(ctx)
	})
	p.ops.Add(1)
	if err != nil {
		p.sink.Addf("%s: %v", name, err)
		return false
	}
	return true
}

func randomMode(rng *rand.Rand) ua.MonitoringMode {
	switch r := rng.Intn(10); {
	case r < 7:
		return ua.MonitoringModeReporting
	case r < 9:
		return ua.MonitoringModeSampling
	default:
		return ua.MonitoringModeDisabled
	}
}

// churn changes the tracked items of sj, one operation per item at a time, in
// a way that keeps every notification attributable:
//
//   - modify: new filter, sampling interval and client handle;
//   - toggle between Sampling and Reporting, or enable a disabled item;
//   - disable, followed by a modify, so that everything the item reports
//     after it was disabled carries a new client handle;
//   - delete, and create another item in its place.
func (p *parallelRun) churn(sj *subject, rng *rand.Rand) {
	tr := sj.tr
	for !p.stopped() {
		slot, it := sj.pick(rng, false)
		if !it.ctl.TryLock() {
			continue
		}
		if !it.gone {
			switch op := rng.Intn(10); {
			case op < 4:
				p.do("ModifyMonitoredItems", func(ctx context.Context) error {
					return tr.modify(ctx, it, it.spec.randomFilter(rng), it.mode == ua.MonitoringModeDisabled)
				})
			case op < 6:
				mode := ua.MonitoringModeReporting
				if it.mode == ua.MonitoringModeReporting || (it.mode == ua.MonitoringModeDisabled && rng.Intn(3) == 0) {
					mode = ua.MonitoringModeSampling
				}
				p.do("SetMonitoringMode", func(ctx context.Context) error { return tr.setMode(ctx, it, mode) })
			case op < 8:
				if it.mode != ua.MonitoringModeDisabled {
					ok := p.do("SetMonitoringMode(Disabled)", func(ctx context.Context) error {
						return tr.setMode(ctx, it, ua.MonitoringModeDisabled)
					})
					if ok {
						p.do("ModifyMonitoredItems (disabled)", func(ctx context.Context) error {
							return tr.modify(ctx, it, it.spec.randomFilter(rng), true)
						})
					}
				}
			default:
				ok := p.do("DeleteMonitoredItems", func(ctx context.Context) error { return tr.remove(ctx, it) })
				if ok {
					spec := randomSpec(rng, p.e.nodes[rng.Intn(len(p.e.nodes))])
					p.do("CreateMonitoredItems", func(ctx context.Context) error {
						items, err := tr.create(ctx, randomMode(rng), false, spec)
						if err == nil {
							sj.replace(false, slot, items[0])
						}
						return err
					})
				}
			}
		}
		it.ctl.Unlock()
		time.Sleep(time.Duration(rng.Intn(3000)) * time.Microsecond)
	}
}

// goneError reports whether err says that the monitored item no longer
// exists. The wild workers race with each other's deletes, so they must
// expect it - and nothing else.
func goneError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unknown monitored item id")
}

// goneOrOK reports whether a result code is one a wild worker must expect.
func goneOrOK(sc ua.StatusCode) bool {
	return sc == ua.StatusOK || sc == ua.StatusBadMonitoredItemIDInvalid
}

// rampage operates on the wild items of sj without any coordination: several
// goroutines modify, switch and delete the same item at the same time. The
// only legal failure is that the item is already gone.
func (p *parallelRun) rampage(sj *subject, rng *rand.Rand) {
	tr := sj.tr
	for !p.stopped() {
		slot, it := sj.pick(rng, true)
		switch rng.Intn(5) {
		case 0, 1:
			p.do("wild ModifyMonitoredItems", func(ctx context.Context) error {
				spec := it.spec.randomFilter(rng)
				ep := tr.newEpoch(it, spec, false)
				res, err := tr.sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemModifyRequest{
					MonitoredItemID:     it.id,
					RequestedParameters: tr.parameters(spec, ep.handle),
				})
				if goneError(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if len(res.Results) != 1 || !goneOrOK(res.Results[0].StatusCode) {
					return fmt.Errorf("results %+v", res.Results)
				}
				return nil
			})
		case 2, 3:
			p.do("wild SetMonitoringMode", func(ctx context.Context) error {
				res, err := tr.sub.SetMonitoringMode(ctx, randomMode(rng), it.id)
				if goneError(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if len(res.Results) != 1 || !goneOrOK(res.Results[0]) {
					return fmt.Errorf("results %v", res.Results)
				}
				return nil
			})
		default:
			p.do("wild DeleteMonitoredItems", func(ctx context.Context) error {
				res, err := tr.sub.Unmonitor(ctx, it.id)
				if err != nil {
					return err
				}
				if len(res.Results) != 1 || !goneOrOK(res.Results[0]) {
					return fmt.Errorf("results %v", res.Results)
				}
				if res.Results[0] != ua.StatusOK {
					return nil // another worker deleted it and replaces it
				}
				items, err := tr.create(ctx, randomMode(rng), true, randomSpec(rng, it.spec.n))
				if err == nil {
					sj.replace(true, slot, items[0])
				}
				return err
			})
		}
		time.Sleep(time.Duration(rng.Intn(2000)) * time.Microsecond)
	}
}

func (p *parallelRun) start() {
	p.t.Helper()
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	specs := matrix(p.e, parallelNodesPerKind)
	for ci := 0; ci < parallelClients; ci++ {
		c := p.e.connect(nil)
		p.clients = append(p.clients, c)
		for si := 0; si < parallelSubsPerClient; si++ {
			idx := len(p.subjects)
			name := fmt.Sprintf("c%d.s%d", ci, si)
			tr, err := newTracker(ctx, p.e, c, name, longLived([]time.Duration{20, 50}[si]*time.Millisecond), false, &p.sink)
			if err != nil {
				p.t.Fatal(err)
			}
			sj := &subject{tr: tr}
			// Two subscriptions together hold the whole matrix.
			var mine []itemSpec
			for i, s := range specs {
				if i%2 == idx%2 {
					mine = append(mine, s)
				}
			}
			if sj.tracked, err = tr.create(ctx, ua.MonitoringModeReporting, false, mine...); err != nil {
				p.t.Fatal(err)
			}
			rng := rand.New(rand.NewSource(p.seed + int64(100+idx)))
			for w := 0; w < parallelWildPerSub; w++ {
				items, err := tr.create(ctx, ua.MonitoringModeReporting, true, randomSpec(rng, p.e.nodes[rng.Intn(len(p.e.nodes))]))
				if err != nil {
					p.t.Fatal(err)
				}
				sj.wild = append(sj.wild, items[0])
			}
			p.subjects = append(p.subjects, sj)
		}
	}

	spawn := func(seed int64, fn func(rng *rand.Rand)) {
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			fn(rand.New(rand.NewSource(p.seed + seed)))
		}()
	}
	for w := 0; w < parallelServerWriters; w++ {
		spawn(int64(1000+w), func(rng *rand.Rand) {
			for !p.stopped() {
				p.e.randomSet(p.e.nodes[rng.Intn(len(p.e.nodes))], rng)
				p.writes.Add(1)
				time.Sleep(time.Duration(200+rng.Intn(1300)) * time.Microsecond)
			}
		})
	}
	for ci, c := range p.clients {
		spawn(int64(2000+ci), func(rng *rand.Rand) {
			for !p.stopped() {
				n := p.e.nodes[rng.Intn(len(p.e.nodes))]
				p.do("Write", func(ctx context.Context) error { return p.e.clientWrite(ctx, c, n, rng) })
				p.writes.Add(1)
				time.Sleep(time.Duration(rng.Intn(1500)) * time.Microsecond)
			}
		})
	}
	for i, sj := range p.subjects {
		spawn(int64(3000+i), func(rng *rand.Rand) { p.churn(sj, rng) })
		for w := 0; w < 2; w++ {
			spawn(int64(4000+10*i+w), func(rng *rand.Rand) { p.rampage(sj, rng) })
		}
	}
}

// settle stops the workload, makes every tracked item report again, writes
// every node one last time and verifies that each item ends up with that
// value - unless its filter suppresses it relative to what it reported last.
func (p *parallelRun) settle() {
	p.t.Helper()
	close(p.stop)
	p.wd.Wait("workload", &p.workers)

	var live []*item
	for _, sj := range p.subjects {
		tracked, _ := sj.live()
		for _, it := range tracked {
			it.ctl.Lock()
			switch it.mode {
			case ua.MonitoringModeDisabled:
				// Nothing was sampled while the item was disabled. The next
				// change is reported whatever the filter.
				p.do("enable", func(ctx context.Context) error {
					if err := sj.tr.modify(ctx, it, it.spec, true); err != nil {
						return err
					}
					return sj.tr.setMode(ctx, it, ua.MonitoringModeReporting)
				})
			case ua.MonitoringModeSampling:
				p.do("report", func(ctx context.Context) error { return sj.tr.setMode(ctx, it, ua.MonitoringModeReporting) })
			case ua.MonitoringModeReporting:
			}
			it.ctl.Unlock()
			live = append(live, it)
		}
	}

	rng := rand.New(rand.NewSource(p.seed + 9000))
	final := make(map[*node]write)
	for _, n := range p.e.nodes {
		w, _ := p.e.randomSet(n, rng)
		final[n] = w
	}
	p.e.waitSamplerIdle()

	pending := live
	chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		still := pending[:0]
		for _, it := range pending {
			if !it.settledOn(final[it.spec.n]) {
				still = append(still, it)
			}
		}
		pending = still
		return len(pending) == 0
	})
	for _, it := range pending {
		last, has := it.lastSeen()
		ep := it.current()
		p.t.Errorf("STUCK: %v did not report the last written value %v: last reported %v (any: %v), filter %v, sampling interval %v, notifications since the last modification: %d",
			it, final[it.spec.n].seen(it.spec.indexRange), last.sample, has, ep.flt, ep.interval, ep.count)
	}
	for _, sj := range p.subjects {
		sj.tr.checkRates()
	}
}

// settledOn reports whether the item has reported w, or something that its
// filter does not distinguish from w.
func (it *item) settledOn(w write) bool {
	ep := it.current()
	it.mu.Lock()
	defer it.mu.Unlock()
	if !it.has || it.disabledSince(len(it.epochs)-1) {
		return false
	}
	return !ep.flt.changed(it.prev.sample, w.seen(it.spec.indexRange))
}

// finish deletes everything step by step and verifies that the server, and
// its sampler in particular, lets go of it.
func (p *parallelRun) finish() {
	p.t.Helper()
	srv := p.e.server()

	// Postpone samples: a second change within the sampling interval of an
	// item has to wait for the timer.
	rng := rand.New(rand.NewSource(p.seed + 9001))
	for round := 0; round < 2; round++ {
		for _, n := range p.e.nodes {
			p.e.randomSet(n, rng)
		}
	}
	p.t.Logf("sampler before the items are deleted: %+v", p.e.sampler())

	for _, sj := range p.subjects {
		tracked, wild := sj.live()
		var ids []uint32
		for _, it := range append(tracked, wild...) {
			ids = append(ids, it.id)
		}
		p.do("DeleteMonitoredItems (all)", func(ctx context.Context) error {
			res, err := sj.tr.sub.Unmonitor(ctx, ids...)
			if err != nil {
				return err
			}
			for i, sc := range res.Results {
				if sc != ua.StatusOK {
					return fmt.Errorf("item %d: %v", ids[i], sc)
				}
			}
			return nil
		})
	}
	// DeleteMonitoredItems is synchronous: the items are gone now, and with
	// them every postponed sample and the timer.
	if r := p.e.resources(); r.MonitoredItems != 0 {
		p.t.Errorf("server still holds %d monitored items after all were deleted", r.MonitoredItems)
	}
	if s := p.e.sampler(); s.Timers != 0 || s.Due != 0 {
		p.t.Errorf("SAMPLER LEAK after all monitored items were deleted: %+v", s)
	}
	requireSamplerStopped(p.t, srv, "after all monitored items were deleted")

	for _, sj := range p.subjects {
		p.do("DeleteSubscriptions", func(ctx context.Context) error { return sj.tr.sub.Cancel(ctx) })
	}
	for _, c := range p.clients {
		_ = p.wd.Do("Close", func() error { chaoskit.CloseClient(c, nil); return nil })
	}
	var received int64
	for _, sj := range p.subjects {
		sj.tr.close()
		received += sj.tr.received.Load()
	}
	p.sink.Report(p.t)
	p.t.Logf("%d writes, %d subscription and monitored item operations, %d notifications", p.writes.Load(), p.ops.Load(), received)
	if received == 0 {
		p.t.Errorf("no notification was delivered at all")
	}

	p.e.requireDrained()
	p.e.stopServer()
	requireSamplerStopped(p.t, srv, "after the server was closed")
}

// TestParallelFilterMatrix runs concurrent writers (server-side and through
// the Write service) against items of every trigger, deadband type, shape,
// sampling interval and index range, held by several subscriptions of
// several clients, while other goroutines create, modify, disable, enable and
// delete those items.
//
// It enforces: every notification satisfies the filter of its item relative
// to the previously reported value (with exactly the exceptions the server
// defines); values are the ones written; at most one sample per sampling
// interval; the last written value is reported unless the filter suppresses
// it; every call returns; and the sampler holds nothing once the items are
// deleted and once the server is closed.
func TestParallelFilterMatrix(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	p := &parallelRun{
		t:    t,
		e:    newEnv(t, seed, parallelNodesPerKind),
		seed: seed,
		wd:   chaoskit.NewWatchdog(t),
		stop: make(chan struct{}),
	}
	p.start()
	time.Sleep(chaoskit.Duration(t, 2*time.Second))
	p.settle()
	p.finish()
}

// requireSampler waits until the sampler of the current server is in the
// given state.
func requireSampler(t *testing.T, e *env, want testhook.ServerSampler, when string) {
	t.Helper()
	var last testhook.ServerSampler
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last = e.sampler()
		return last == want
	}) {
		t.Fatalf("sampler %s: %+v, want %+v", when, last, want)
	}
}

// TestSamplerStopsWithLastSampledItem verifies the life cycle of the shared
// sampler timer. The items have a sampling interval of an hour, so a
// postponed sample never becomes due by itself: when the timer is found
// stopped, it was stopped because nothing needs it any more.
func TestSamplerStopsWithLastSampledItem(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1, 1)
	wd := chaoskit.NewWatchdog(t)
	var sink chaoskit.ErrSink
	n := e.node(kindDouble, 0)
	value := 100.0

	subscribe := func(c *opcua.Client, name string) *tracker {
		t.Helper()
		ctx, cancel := chaoskit.OpCtx()
		defer cancel()
		tr, err := newTracker(ctx, e, c, name, longLived(50*time.Millisecond), false, &sink)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(tr.close)
		return tr
	}
	// postpone creates count items sampled once per hour and changes the
	// node, so that each of them has a sample waiting for the timer.
	postpone := func(tr *tracker, count int) []*item {
		t.Helper()
		ctx, cancel := chaoskit.OpCtx()
		defer cancel()
		specs := make([]itemSpec, count)
		for i := range specs {
			specs[i] = itemSpec{n: n, noFilter: true, samplingMS: samplingHourMS, discardOldest: true}
		}
		items, err := tr.create(ctx, ua.MonitoringModeReporting, false, specs...)
		if err != nil {
			t.Fatal(err)
		}
		value += 100
		e.set(n, value, ua.StatusOK)
		requireSampler(t, e, testhook.ServerSampler{Timers: 1, Due: count}, "with postponed samples")
		return items
	}
	call := func(name string, fn func(ctx context.Context) error) {
		t.Helper()
		if err := wd.Do(name, func() error {
			ctx, cancel := chaoskit.OpCtx()
			defer cancel()
			return fn(ctx)
		}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	idle := testhook.ServerSampler{}

	c := e.connect(nil)
	tr := subscribe(c, "main")

	// DeleteMonitoredItems: the timer stays for the items that are left and
	// goes with the last one.
	items := postpone(tr, 3)
	call("delete two", func(ctx context.Context) error {
		if err := tr.remove(ctx, items[0]); err != nil {
			return err
		}
		return tr.remove(ctx, items[1])
	})
	if got, want := e.sampler(), (testhook.ServerSampler{Timers: 1, Due: 1}); got != want {
		t.Fatalf("sampler after two of three items were deleted: %+v, want %+v", got, want)
	}
	call("delete the last", func(ctx context.Context) error { return tr.remove(ctx, items[2]) })
	if got := e.sampler(); got != idle {
		t.Fatalf("SAMPLER LEAK after the last sampled item was deleted: %+v", got)
	}
	// A deleted item is gone when the service returns.
	call("delete again", func(ctx context.Context) error {
		res, err := tr.sub.Unmonitor(ctx, items[2].id)
		if err != nil {
			return err
		}
		if len(res.Results) != 1 || res.Results[0] != ua.StatusBadMonitoredItemIDInvalid {
			return fmt.Errorf("second delete of the same item: %v, want BadMonitoredItemIdInvalid", res.Results)
		}
		return nil
	})

	// SetMonitoringMode(Disabled): a disabled item is not sampled.
	items = postpone(tr, 2)
	call("disable", func(ctx context.Context) error {
		for _, it := range items {
			if err := tr.setMode(ctx, it, ua.MonitoringModeDisabled); err != nil {
				return err
			}
		}
		return nil
	})
	if got := e.sampler(); got != idle {
		t.Fatalf("SAMPLER LEAK after the sampled items were disabled: %+v", got)
	}

	// ModifyMonitoredItems to "every change": the postponed sample is due at
	// once, is taken and delivered.
	items = postpone(tr, 1)
	call("modify", func(ctx context.Context) error {
		spec := items[0].spec
		spec.samplingMS = 0
		return tr.modify(ctx, items[0], spec, false)
	})
	requireSampler(t, e, idle, "after the sampling interval was set to 0")
	want := n.last()
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last, ok := items[0].lastSeen()
		return ok && last.seq == want.seq
	}) {
		last, _ := items[0].lastSeen()
		t.Fatalf("STUCK: the sample postponed before the modification was not delivered: last %v, want %v", last.sample, want)
	}

	// DeleteSubscriptions.
	tr2 := subscribe(c, "second")
	postpone(tr2, 2)
	call("delete subscription", func(ctx context.Context) error { return tr2.sub.Cancel(ctx) })
	requireSampler(t, e, idle, "after the subscription was deleted")

	// CloseSession.
	c2 := e.connect(nil)
	postpone(subscribe(c2, "other client"), 2)
	call("close client", func(context.Context) error { chaoskit.CloseClient(c2, nil); return nil })
	requireSampler(t, e, idle, "after the session was closed")

	// Server.Close with samples still postponed.
	postpone(tr, 2)
	srv := e.server()
	call("close server", func(context.Context) error { e.stopServer(); return nil })
	requireSamplerStopped(t, srv, "after the server was closed")
	if r := testhook.ServerResourcesOf(srv); r.MonitoredItems != 0 || r.Subscriptions != 0 {
		t.Errorf("closed server still holds %+v", r)
	}
	sink.Report(t)
}

// TestBuilderFilterAndSampling drives SubscriptionBuilder.DataChangeFilter
// and SamplingInterval end to end: the builder's items get the deadband and
// the sampling interval, and nothing else does.
func TestBuilderFilterAndSampling(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1, 1)
	c := e.connect(nil)
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	scalar, array := e.node(kindDouble, 0), e.node(kindDoubleArray, 0)
	plain := e.node(kindInt32, 0)
	sub, ch, err := c.NewSubscription().
		Interval(20*time.Millisecond).
		Monitor(plain.id).
		SamplingInterval(samplingLongMS*time.Millisecond).
		DataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 5).
		Monitor(scalar.id, array.id).
		Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Cancel(ctx) }()

	// The builder numbers the client handles in the order of Monitor.
	nodes := []*node{plain, scalar, array}
	var mu sync.Mutex
	got := make([][]int64, len(nodes))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case n := <-ch:
				dcn, ok := n.Value.(*ua.DataChangeNotification)
				if n.Error != nil || !ok {
					continue
				}
				mu.Lock()
				for _, mi := range dcn.MonitoredItems {
					if _, seq, ok := unstamp(mi.Value.SourceTimestamp); ok && int(mi.ClientHandle) < len(got) {
						got[mi.ClientHandle] = append(got[mi.ClientHandle], seq)
					}
				}
				mu.Unlock()
			}
		}
	}()
	defer func() { close(stop); <-done }()

	// Each step is sampled by every item before the next one is written.
	want := make([][]int64, len(nodes))
	step := func(report []bool, values ...any) {
		t.Helper()
		for i, n := range nodes {
			w, _ := e.set(n, values[i], ua.StatusOK)
			if report[i] {
				want[i] = append(want[i], w.seq)
			}
		}
		if !e.waitSamplerIdle() {
			t.FailNow()
		}
	}
	for i, n := range nodes {
		want[i] = append(want[i], n.last().seq) // the initial value
	}
	all, none := []bool{true, true, true}, []bool{true, false, false}
	step(all, int32(200), 60.0, array.uniform(60))
	step(none, int32(201), 62.0, withElement(array.uniform(60), 2, 4))   // within the deadband
	step(none, int32(202), 65.0, withElement(array.uniform(60), 2, 5))   // exactly the deadband
	step(all, int32(203), 65.1, withElement(array.uniform(60), 5, -5.5)) // beyond it, in one element
	step(all, int32(204), 10.0, array.uniform(10))

	equal := func() bool {
		mu.Lock()
		defer mu.Unlock()
		for i := range want {
			if fmt.Sprint(got[i]) != fmt.Sprint(want[i]) {
				return false
			}
		}
		return true
	}
	if !chaoskit.Eventually(chaoskit.SettleLimit, equal) {
		mu.Lock()
		defer mu.Unlock()
		for i, n := range nodes {
			t.Errorf("%s: delivered writes %v, want %v", n.name, got[i], want[i])
		}
	}
}
