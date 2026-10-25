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

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/fakeclock"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestChaosAlarmTimers: the server flips alarms with OnDelay, OffDelay,
// ReAlarmTime, branches and a shared FirstInGroup group while a goroutine
// advances the alarm clock (firing the delay and re-alarm timers), sessions
// acknowledge the alarms, read and reset the AlarmMetrics, and the proxy
// drops the connections. Every call returns Good, a Part 9 refusal or a
// connection error. Afterwards, with every alarm inactive and the delays
// over, no alarm is pending, no alarm is first in its group and the metrics
// counted the activations.
func TestChaosAlarmTimers(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	clk := fakeclock.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	e := newEnv(t, seed, server.WithAlarmClock(clk))
	wd := newWatchdog(t)
	srv := e.server()
	srv.SetAuditing(true)
	nsp := e.namespace()

	src := server.NewFolderNode(ua.NewStringNodeID(nsp.ID(), "TimerSource"), "TimerSource")
	nsp.AddNode(src)
	nsp.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	group, err := srv.AddAlarmGroup(server.AlarmGroupConfig{Name: "FirstOut", Namespace: nsp})
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := srv.AddAlarmMetrics(server.AlarmMetricsConfig{Namespace: nsp, Group: group.NodeID()})
	if err != nil {
		t.Fatal(err)
	}
	const numConds = 4
	conds := make([]*server.Condition, numConds)
	ids := make([]*ua.NodeID, numConds)
	for i := range conds {
		name := fmt.Sprintf("Timed%d", i)
		c, err := srv.AddCondition(server.ConditionConfig{Name: name, Source: src.ID(), NodeID: ua.NewStringNodeID(nsp.ID(), name),
			Branching: i%2 == 0, Silenceable: true, Latching: i == 3,
			OnDelay: time.Duration(i) * time.Second, OffDelay: time.Duration(numConds-i) * time.Second,
			ReAlarmTime: time.Duration(5+i) * time.Second, FirstInGroup: group.NodeID(),
			AudibleSound: &server.AudibleSound{Sound: []byte{byte(i)}}})
		if err != nil {
			t.Fatal(err)
		}
		conds[i], ids[i] = c, c.NodeID()
	}

	deadline := time.Now().Add(chaosDuration(t))
	var sink errSink
	var wg sync.WaitGroup
	var calls atomic.Int64

	// The process: alarms come and go.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed))
		for time.Now().Before(deadline) {
			c := conds[rng.Intn(numConds)]
			var err error
			switch rng.Intn(5) {
			case 0, 1, 2:
				err = c.SetActive(rng.Intn(2) == 0)
			case 3:
				on := rng.Intn(2) == 0
				err = c.Update(server.ConditionUpdate{AudibleEnabled: &on})
			default:
				if bs := c.Branches(); len(bs) > 8 {
					for _, b := range bs[:4] {
						if derr := c.DeleteBranch(b.BranchID); derr != nil && !errors.Is(derr, server.ErrBranchUnknown) {
							err = derr
						}
					}
				}
			}
			if err != nil {
				sink.addf("server flip: %v", err)
				return
			}
			time.Sleep(time.Duration(rng.Intn(3)) * time.Millisecond)
		}
	}()

	// Time passes: the delay and re-alarm timers fire.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed + 7))
		for time.Now().Before(deadline) {
			clk.Advance(time.Duration(rng.Intn(3000)) * time.Millisecond)
			time.Sleep(time.Duration(rng.Intn(2)) * time.Millisecond)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed + 99))
		for time.Now().Before(deadline) {
			time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
			e.proxy.DropAll()
		}
	}()

	const workers = 4
	for g := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g) + 1))
			for n := 0; time.Now().Before(deadline); n++ {
				err := wd.do("timer worker", func() error { return timerRound(e, rng, conds, metrics, &calls) })
				if err != nil {
					sink.addf("worker %d round %d: %v", g, n, err)
					return
				}
			}
		}()
	}
	wd.wait("alarm timers", &wg)
	sink.report(t)
	t.Logf("calls %d, metrics %+v", calls.Load(), metrics.Values())
	if t.Failed() {
		return
	}

	// Quiet: every alarm returns to normal once the delays are over.
	for _, c := range conds {
		if err := c.SetActive(false); err != nil {
			t.Fatal(err)
		}
	}
	clk.Advance(time.Duration(numConds+1) * time.Second)
	if n := clk.Pending(); n != 0 {
		t.Errorf("%d timers pending with every alarm inactive", n)
	}
	for _, c := range conds {
		st := c.State()
		if st.Active || st.PendingActive || st.PendingInactive || st.FirstInGroup {
			t.Errorf("%v: after the storm %+v", c.NodeID(), st)
		}
	}
	// The next activation is first in the group, the second is not.
	if err := conds[0].SetActive(true); err != nil {
		t.Fatal(err)
	}
	if err := conds[1].SetActive(true); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	if !conds[0].State().FirstInGroup || conds[1].State().FirstInGroup {
		t.Errorf("first in group: %v, %v", conds[0].State().FirstInGroup, conds[1].State().FirstInGroup)
	}
	v := metrics.Values()
	if v.AlarmCount == 0 || v.MaximumActiveState < 0 {
		t.Errorf("metrics after the storm: %+v", v)
	}
}

// timerRound runs one session: acknowledge and silence the alarms, read the
// AlarmMetrics and sometimes reset them.
func timerRound(e *env, rng *rand.Rand, conds []*server.Condition, m *server.AlarmMetrics, calls *atomic.Int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := opcua.NewClient(e.url(), e.clientOptions(nil, opcua.AutoReconnect(false), opcua.RequestTimeout(5*time.Second))...)
	if err != nil {
		return err
	}
	defer closeClient(c, nil)
	if err := c.Connect(ctx); err != nil {
		if isConnectionError(err) {
			return nil
		}
		return fmt.Errorf("connect: %w", err)
	}
	for range 1 + rng.Intn(8) {
		cond := conds[rng.Intn(len(conds))]
		var op string
		var err error
		switch rng.Intn(5) {
		case 0, 1:
			op, err = "acknowledge", c.Acknowledge(ctx, cond.NodeID(), cond.State().EventID, "chaos")
		case 2:
			op, err = "silence", c.Silence(ctx, cond.NodeID())
		case 3:
			var got *opcua.AlarmMetrics
			op = "read metrics"
			if got, err = c.ReadAlarmMetrics(ctx, m.NodeID()); err == nil && got.MaximumAlarmRate < got.CurrentAlarmRate {
				return fmt.Errorf("metrics: maximum rate %v below the current %v", got.MaximumAlarmRate, got.CurrentAlarmRate)
			}
		default:
			op, err = "reset metrics", c.ResetAlarmMetrics(ctx, m.NodeID())
		}
		calls.Add(1)
		if err != nil && !isConnectionError(err) && !alarmRefusal(err) && !errors.Is(err, ua.StatusBadInvalidState) {
			return fmt.Errorf("%s: %w", op, err)
		}
		if isConnectionError(err) {
			return nil
		}
	}
	return nil
}
