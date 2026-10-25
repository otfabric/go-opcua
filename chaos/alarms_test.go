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
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// alarmRefusals are the answers of the condition methods (Part 9 §5.5.4 -
// §5.7.4, §5.5.7) a client must expect when the state changed under it.
var alarmRefusals = []ua.StatusCode{
	ua.StatusBadEventIDUnknown,
	ua.StatusBadConditionBranchAlreadyAcked,
	ua.StatusBadConditionBranchAlreadyConfirmed,
	ua.StatusBadConditionDisabled,
	ua.StatusBadConditionAlreadyEnabled,
	ua.StatusBadConditionAlreadyDisabled,
	ua.StatusBadRefreshInProgress,
	ua.StatusBadNodeIDUnknown, // the temporary condition was removed
	ua.StatusBadMethodInvalid, // ... and its methods with it
}

func alarmRefusal(err error) bool {
	for _, sc := range alarmRefusals {
		if errors.Is(err, sc) {
			return true
		}
	}
	return false
}

// condStreamCheck verifies the condition events one subscription receives.
type condStreamCheck struct {
	last    map[string]time.Time // Time of the latest event per condition
	byEvent map[string]time.Time // Time per EventId
	latest  map[string][]byte    // latest EventId per condition
}

func newCondStreamCheck() *condStreamCheck {
	return &condStreamCheck{last: map[string]time.Time{}, byEvent: map[string]time.Time{}, latest: map[string][]byte{}}
}

// check validates one event: Retain follows the state (Part 9 §5.5.2), the
// events of a condition never go back in time, and an EventId always
// denotes the same event (a refresh repeats the latest one).
func (s *condStreamCheck) check(ev *opcua.ConditionEvent) error {
	if ev.IsRefreshStart() || ev.IsRefreshEnd() || ev.ConditionID == nil {
		return nil
	}
	key := ev.ConditionID.String()
	if ev.Enabled {
		if ev.Active == nil || ev.Acked == nil || ev.Confirmed == nil {
			return fmt.Errorf("%s: enabled condition without state: %+v", key, ev)
		}
		if want := *ev.Active || !*ev.Acked || !*ev.Confirmed; ev.Retain != want {
			return fmt.Errorf("%s: Retain %v with active=%v acked=%v confirmed=%v", key, ev.Retain, *ev.Active, *ev.Acked, *ev.Confirmed)
		}
	} else if ev.Retain || ev.Acked != nil {
		return fmt.Errorf("%s: disabled condition reports Retain=%v acked=%v", key, ev.Retain, ev.Acked)
	}
	if prev, ok := s.last[key]; ok && ev.Time.Before(prev) {
		return fmt.Errorf("%s: event time went back from %v to %v", key, prev, ev.Time)
	}
	if at, ok := s.byEvent[string(ev.EventID)]; ok && !at.Equal(ev.Time) {
		return fmt.Errorf("%s: EventId %x reported with times %v and %v", key, ev.EventID, at, ev.Time)
	}
	s.last[key] = ev.Time
	s.byEvent[string(ev.EventID)] = ev.Time
	s.latest[key] = ev.EventID
	return nil
}

// drain checks the events received so far without waiting for more.
func (s *condStreamCheck) drain(ch <-chan *opcua.PublishNotificationData) error {
	for {
		select {
		case msg := <-ch:
			if msg.Error != nil {
				continue
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, f := range enl.Events {
				ev, err := opcua.ParseConditionEvent(f)
				if err != nil {
					return err
				}
				if err := s.check(ev); err != nil {
					return err
				}
			}
		default:
			return nil
		}
	}
}

// TestChaosAlarms: sessions acknowledge, confirm, comment, disable/enable
// and refresh conditions concurrently while the server flips their states,
// removes and re-adds a condition, and the proxy drops the connections.
// Every method returns Good, a Part 9 refusal of a state that changed under
// the caller, or a connection error; every event a subscription receives
// is consistent (Retain follows the state, time never goes back per
// condition, an EventId denotes one event); afterwards a refresh reports
// exactly the retained conditions with their latest EventId.
func TestChaosAlarms(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	srv := e.server()
	nsp := e.namespace()

	src := server.NewFolderNode(ua.NewStringNodeID(nsp.ID(), "AlarmSource"), "AlarmSource")
	nsp.AddNode(src)
	nsp.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	const numConds = 6
	conds := make([]*server.Condition, numConds)
	for i := range conds {
		c, err := srv.AddCondition(server.ConditionConfig{Name: fmt.Sprintf("Alarm%d", i), Source: src.ID(),
			NodeID: ua.NewStringNodeID(nsp.ID(), fmt.Sprintf("Alarm%d", i)), Confirmable: true, Shelving: true})
		if err != nil {
			t.Fatal(err)
		}
		conds[i] = c
	}
	tempID := ua.NewStringNodeID(nsp.ID(), "Temp")
	addTemp := func() {
		if _, err := srv.AddCondition(server.ConditionConfig{Name: "Temp", Source: src.ID(), NodeID: tempID, Confirmable: true}); err != nil {
			t.Error(err)
		}
	}
	addTemp()
	ids := []*ua.NodeID{tempID}
	for _, c := range conds {
		ids = append(ids, c.NodeID())
	}

	deadline := time.Now().Add(chaosDuration(t))
	var sink errSink
	var wg sync.WaitGroup
	var events, acks atomic.Int64

	// The server flips the states.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed))
		for time.Now().Before(deadline) {
			c := conds[rng.Intn(numConds)]
			var err error
			switch rng.Intn(6) {
			case 0, 1:
				err = c.SetActive(rng.Intn(2) == 0)
			case 2:
				err = c.SetSeverity(uint16(1 + rng.Intn(1000)))
			case 3:
				if err = c.Disable(); errors.Is(err, ua.StatusBadConditionAlreadyDisabled) {
					err = c.Enable()
				}
				if alarmRefusal(err) {
					err = nil
				}
			case 4:
				err = srv.RemoveCondition(tempID)
				addTemp()
			default:
				err = c.Report()
			}
			if err != nil {
				sink.addf("server flip: %v", err)
				return
			}
			time.Sleep(time.Duration(rng.Intn(3)) * time.Millisecond)
		}
	}()

	// The proxy drops the connections now and then.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed + 99))
		for time.Now().Before(deadline) {
			time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
			e.proxy.DropAll()
		}
	}()

	const workers = 6
	for g := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g) + 1))
			for n := 0; time.Now().Before(deadline); n++ {
				err := wd.do("alarms worker", func() error { return alarmRound(e, rng, ids, &events, &acks) })
				if err != nil {
					sink.addf("worker %d round %d: %v", g, n, err)
					return
				}
			}
		}()
	}
	wd.wait("alarms", &wg)
	sink.report(t)
	t.Logf("events checked %d, acknowledged %d", events.Load(), acks.Load())
	if t.Failed() {
		return
	}

	// Quiet: a refresh of a new client reports the retained conditions with
	// their current state.
	c := e.connect(nil, opcua.AutoReconnect(false))
	ctx, cancel := opCtx()
	defer cancel()
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(opcua.NewConditionEventFilter(), ua.NewNumericNodeID(0, id.Server)).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.ConditionRefresh(ctx); err != nil {
		t.Fatal(err)
	}
	got := map[string]*opcua.ConditionEvent{}
	check := newCondStreamCheck()
	started := false
	for done := false; !done; {
		select {
		case msg := <-ch:
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, f := range enl.Events {
				ev, err := opcua.ParseConditionEvent(f)
				if err != nil {
					t.Fatal(err)
				}
				if err := check.check(ev); err != nil {
					t.Fatal(err)
				}
				switch {
				case ev.IsRefreshStart():
					started = true
				case ev.IsRefreshEnd():
					done = started
				case started:
					got[ev.ConditionID.String()] = ev
				}
			}
		case <-ctx.Done():
			t.Fatal("no RefreshEndEvent after the storm")
		}
	}
	want := 0
	for _, cond := range srv.Conditions() {
		st := cond.State()
		ev, ok := got[cond.NodeID().String()]
		if !st.Retain {
			if ok {
				t.Errorf("%v: not retained but refreshed", cond.NodeID())
			}
			continue
		}
		want++
		if !ok {
			t.Errorf("%v: retained but not refreshed: %+v", cond.NodeID(), st)
			continue
		}
		if string(ev.EventID) != string(st.EventID) || *ev.Acked != st.Acked || *ev.Active != st.Active || *ev.Confirmed != st.Confirmed {
			t.Errorf("%v: refreshed %x acked=%v active=%v confirmed=%v, state %x %+v", cond.NodeID(), ev.EventID, *ev.Acked, *ev.Active, *ev.Confirmed, st.EventID, st)
		}
	}
	if len(got) != want {
		t.Errorf("refresh reported %d conditions, %d are retained", len(got), want)
	}
	// Every retained condition can be acknowledged with its EventId.
	for _, cond := range srv.Conditions() {
		if st := cond.State(); st.Enabled && !st.Acked {
			if err := c.Acknowledge(ctx, cond.NodeID(), st.EventID, "final"); err != nil {
				t.Errorf("%v: final acknowledge: %v", cond.NodeID(), err)
			}
		}
	}
	_ = sub.Cancel(ctx)
	// The sessions of the dropped connections stay until their timeout
	// (Part 4 §5.6.2), so the server is not drained here.
}

// alarmRound is one session of a worker: subscribe to the condition events,
// refresh, and call random condition methods with the EventIds received.
func alarmRound(e *env, rng *rand.Rand, ids []*ua.NodeID, events, acks *atomic.Int64) error {
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
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(opcua.NewConditionEventFilter(), ua.NewNumericNodeID(0, id.Server)).Start(ctx)
	if err != nil {
		if isConnectionError(err) {
			return nil
		}
		return fmt.Errorf("subscribe: %w", err)
	}
	defer func() { _ = sub.Cancel(context.Background()) }()
	check := newCondStreamCheck()
	defer func() { events.Add(int64(len(check.byEvent))) }()
	ok := func(op string, err error) error {
		if err == nil || isConnectionError(err) || alarmRefusal(err) {
			return nil
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := ok("refresh", sub.ConditionRefresh(ctx)); err != nil {
		return err
	}
	for range 4 + rng.Intn(8) {
		if err := check.drain(ch); err != nil {
			return err
		}
		cid := ids[rng.Intn(len(ids))]
		evID := check.latest[cid.String()]
		if evID == nil {
			evID = []byte("unknown")
		}
		var op string
		switch rng.Intn(7) {
		case 0, 1:
			op, err = "acknowledge", c.Acknowledge(ctx, cid, evID, "ack")
		case 2:
			op, err = "confirm", c.Confirm(ctx, cid, evID, "")
		case 3:
			op, err = "comment", c.AddComment(ctx, cid, evID, fmt.Sprintf("c%d", rng.Intn(100)))
		case 4:
			op, err = "refresh", sub.ConditionRefresh(ctx)
		case 5:
			if rng.Intn(2) == 0 {
				op, err = "disable", c.DisableCondition(ctx, cid)
			} else {
				op, err = "enable", c.EnableCondition(ctx, cid)
			}
		default:
			op, err = "shelve", c.OneShotShelve(ctx, cid)
			if errors.Is(err, ua.StatusBadConditionAlreadyShelved) || errors.Is(err, ua.StatusBadNotFound) || errors.Is(err, ua.StatusBadNoMatch) {
				err = nil
			}
		}
		if err := ok(op, err); err != nil {
			return err
		}
		if op == "acknowledge" && err == nil {
			acks.Add(1)
		}
		if isConnectionError(err) {
			return nil
		}
	}
	return check.drain(ch)
}
