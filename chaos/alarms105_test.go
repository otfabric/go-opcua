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

// branchStreamCheck verifies the events of conditions with branches and the
// Part 9 1.05 states.
type branchStreamCheck struct {
	last    map[string]time.Time // per condition and branch
	byEvent map[string]time.Time
	latest  map[string][]byte // latest EventId per condition and branch
}

func newBranchStreamCheck() *branchStreamCheck {
	return &branchStreamCheck{last: map[string]time.Time{}, byEvent: map[string]time.Time{}, latest: map[string][]byte{}}
}

func branchKey(ev *opcua.ConditionEvent) string {
	k := ev.ConditionID.String()
	if ev.IsBranch() {
		k += "#" + ev.BranchID.String()
	}
	return k
}

// check validates one event: Retain follows the state of the condition or
// branch, SuppressedOrShelved follows SuppressedState and
// OutOfServiceState, time never goes back per condition and branch, and an
// EventId denotes one event.
func (s *branchStreamCheck) check(ev *opcua.ConditionEvent) error {
	if ev.IsRefreshStart() || ev.IsRefreshEnd() || ev.ConditionID == nil {
		return nil
	}
	key := branchKey(ev)
	if ev.Enabled {
		if ev.Active == nil || ev.Acked == nil || ev.Confirmed == nil || ev.Latched == nil || ev.Suppressed == nil || ev.OutOfService == nil {
			return fmt.Errorf("%s: enabled condition without state: %+v", key, ev)
		}
		want := !*ev.Acked || !*ev.Confirmed
		switch {
		case !ev.IsBranch():
			if want = want || *ev.Active || *ev.Latched; ev.Retain != want {
				return fmt.Errorf("%s: Retain %v with active=%v latched=%v acked=%v confirmed=%v", key, ev.Retain, *ev.Active, *ev.Latched, *ev.Acked, *ev.Confirmed)
			}
		case ev.Retain && !want:
			// A branch that needs nothing more ends (Retain false); one
			// that is deleted ends while it still needs something.
			return fmt.Errorf("%s: branch retained while acknowledged and confirmed", key)
		}
		if ev.SuppressedOrShelved == nil || *ev.SuppressedOrShelved != (*ev.Suppressed || *ev.OutOfService) {
			return fmt.Errorf("%s: SuppressedOrShelved %v with suppressed=%v outOfService=%v", key, ev.SuppressedOrShelved, *ev.Suppressed, *ev.OutOfService)
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
	if ev.Retain {
		s.latest[key] = ev.EventID
	} else {
		delete(s.latest, key)
	}
	return nil
}

func (s *branchStreamCheck) drain(ch <-chan *opcua.PublishNotificationData) error {
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
					// An audit event of the audit item.
					if _, aerr := opcua.ParseAuditConditionEvent(f); aerr == nil {
						continue
					}
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

// eventIDs returns the latest EventIds seen, in a stable order.
func (s *branchStreamCheck) eventIDs() [][]byte {
	out := make([][]byte, 0, len(s.latest))
	for _, v := range s.latest {
		out = append(out, v)
	}
	return out
}

// TestChaosAlarmBranches: sessions acknowledge and confirm conditions and
// their branches by EventId, suppress, take out of service, silence and
// reset them, with auditing on, while the server flips the states (each
// re-activation of an unacknowledged alarm creates a branch), a
// suppression group toggles and a member of it is removed and re-added,
// and the proxy drops the connections. Every method returns Good, a Part 9
// refusal or a connection error; every event is consistent; afterwards a
// refresh reports exactly the retained conditions and branches, and every
// branch ends when it is acknowledged and confirmed.
func TestChaosAlarmBranches(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	srv := e.server()
	srv.SetAuditing(true)
	nsp := e.namespace()

	src := server.NewFolderNode(ua.NewStringNodeID(nsp.ID(), "BranchSource"), "BranchSource")
	nsp.AddNode(src)
	nsp.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	group, err := srv.AddAlarmGroup(server.AlarmGroupConfig{Name: "Suppression", Namespace: nsp, Suppression: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg := func(name string) server.ConditionConfig {
		return server.ConditionConfig{Name: name, Source: src.ID(), NodeID: ua.NewStringNodeID(nsp.ID(), name),
			Confirmable: true, Branching: true, Suppressible: true, Serviceable: true, Silenceable: true, Latching: true,
			SuppressionGroups: []*ua.NodeID{group.NodeID()}}
	}
	const numConds = 4
	conds := make([]*server.Condition, numConds)
	for i := range conds {
		c, err := srv.AddCondition(cfg(fmt.Sprintf("Branchy%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		conds[i] = c
	}
	tempID := ua.NewStringNodeID(nsp.ID(), "BranchyTemp")
	addTemp := func() {
		if _, err := srv.AddCondition(cfg("BranchyTemp")); err != nil {
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
	var events, calls atomic.Int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed))
		for time.Now().Before(deadline) {
			c := conds[rng.Intn(numConds)]
			var err error
			switch rng.Intn(6) {
			case 0, 1, 2:
				err = c.SetActive(rng.Intn(2) == 0)
			case 3:
				err = group.SetSuppressing(rng.Intn(2) == 0)
			case 4:
				err = srv.RemoveCondition(tempID)
				addTemp()
			default:
				if len(c.Branches()) > 8 {
					// Keep the branches bounded: an operator would
					// acknowledge them.
					for _, b := range c.Branches()[:4] {
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed + 99))
		for time.Now().Before(deadline) {
			time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
			e.proxy.DropAll()
		}
	}()

	const workers = 5
	for g := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g) + 1))
			for n := 0; time.Now().Before(deadline); n++ {
				err := wd.do("branch worker", func() error { return branchRound(e, rng, ids, &events, &calls) })
				if err != nil {
					sink.addf("worker %d round %d: %v", g, n, err)
					return
				}
			}
		}()
	}
	wd.wait("alarm branches", &wg)
	sink.report(t)
	t.Logf("events checked %d, calls %d", events.Load(), calls.Load())
	if t.Failed() {
		return
	}

	// Quiet: a refresh reports the retained conditions and branches, once
	// the requests that the dropped workers left behind (an Acknowledge,
	// say) have changed them.
	e.settleRequests()
	c := e.connect(nil, opcua.AutoReconnect(false))
	ctx, cancel := opCtx()
	defer cancel()
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(opcua.NewConditionEventFilter(), ua.NewNumericNodeID(0, id.Server)).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Cancel(context.Background()) }()
	refresh := func() map[string]*opcua.ConditionEvent {
		if err := sub.ConditionRefresh(ctx); err != nil {
			t.Fatal(err)
		}
		got := map[string]*opcua.ConditionEvent{}
		check := newBranchStreamCheck()
		started := false
		for {
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
						if started {
							return got
						}
					case started:
						got[branchKey(ev)] = ev
					}
				}
			case <-ctx.Done():
				t.Fatal("no RefreshEndEvent after the storm")
			}
		}
	}
	got := refresh()
	want := 0
	for _, cond := range srv.Conditions() {
		states := append([]server.ConditionState{cond.State()}, cond.Branches()...)
		for _, st := range states {
			key := cond.NodeID().String()
			if st.BranchID != nil {
				key += "#" + st.BranchID.String()
			}
			ev, ok := got[key]
			if !st.Retain {
				if ok {
					t.Errorf("%s: not retained but refreshed", key)
				}
				continue
			}
			want++
			if !ok {
				t.Errorf("%s: retained but not refreshed: %+v", key, st)
				continue
			}
			if string(ev.EventID) != string(st.EventID) || *ev.Acked != st.Acked || *ev.Confirmed != st.Confirmed {
				t.Errorf("%s: refreshed %x acked=%v confirmed=%v, state %+v", key, ev.EventID, *ev.Acked, *ev.Confirmed, st)
			}
		}
	}
	if len(got) != want {
		t.Errorf("refresh reported %d conditions and branches, %d are retained", len(got), want)
	}
	// Every branch ends when it is acknowledged and confirmed.
	for _, cond := range srv.Conditions() {
		for _, b := range cond.Branches() {
			if !b.Acked {
				if err := c.Acknowledge(ctx, cond.NodeID(), b.EventID, "final"); err != nil {
					t.Errorf("%v: acknowledge branch: %v", b.BranchID, err)
				}
			}
			nb, ok := cond.Branch(b.BranchID)
			if !ok {
				continue
			}
			if err := c.Confirm(ctx, cond.NodeID(), nb.EventID, ""); err != nil {
				t.Errorf("%v: confirm branch: %v", b.BranchID, err)
			}
		}
		if n := len(cond.Branches()); n != 0 && cond.State().Enabled {
			t.Errorf("%v: %d branches left", cond.NodeID(), n)
		}
	}
}

// branchRefusals are the answers of the Part 9 1.05 methods and of the
// methods on branches that a client must expect when the state changed.
var branchRefusals = []ua.StatusCode{ua.StatusBadInvalidState}

// branchRound is one session of a worker.
func branchRound(e *env, rng *rand.Rand, ids []*ua.NodeID, events, calls *atomic.Int64) error {
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
	srvID := ua.NewNumericNodeID(0, id.Server)
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(opcua.NewConditionEventFilter(), srvID).
		MonitorEvents(opcua.NewAuditConditionEventFilter(), srvID).Start(ctx)
	if err != nil {
		if isConnectionError(err) {
			return nil
		}
		return fmt.Errorf("subscribe: %w", err)
	}
	defer func() { _ = sub.Cancel(context.Background()) }()
	check := newBranchStreamCheck()
	defer func() { events.Add(int64(len(check.byEvent))) }()
	ok := func(op string, err error) error {
		if err == nil || isConnectionError(err) || alarmRefusal(err) {
			return nil
		}
		for _, sc := range branchRefusals {
			if errors.Is(err, sc) {
				return nil
			}
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
		evID := []byte("unknown")
		if known := check.eventIDs(); len(known) > 0 {
			evID = known[rng.Intn(len(known))]
		}
		var op string
		switch rng.Intn(9) {
		case 0, 1:
			op, err = "acknowledge", c.Acknowledge(ctx, cid, evID, "ack")
		case 2:
			op, err = "confirm", c.Confirm(ctx, cid, evID, "")
		case 3:
			if rng.Intn(2) == 0 {
				op, err = "suppress", c.Suppress2(ctx, cid, "s")
			} else {
				op, err = "unsuppress", c.Unsuppress(ctx, cid)
			}
		case 4:
			if rng.Intn(2) == 0 {
				op, err = "remove from service", c.RemoveFromService(ctx, cid)
			} else {
				op, err = "place in service", c.PlaceInService2(ctx, cid, "p")
			}
		case 5:
			op, err = "silence", c.Silence(ctx, cid)
		case 6:
			op, err = "reset", c.Reset2(ctx, cid, "r")
		case 7:
			op, err = "refresh", sub.ConditionRefresh(ctx)
		default:
			var groups []*ua.NodeID
			groups, err = c.GetGroupMemberships(ctx, cid)
			op = "memberships"
			if err == nil && len(groups) > 1 {
				return fmt.Errorf("%v: %d group memberships, want 1", cid, len(groups))
			}
		}
		if err := ok(op, err); err != nil {
			return err
		}
		calls.Add(1)
		if isConnectionError(err) {
			return nil
		}
	}
	return check.drain(ch)
}
