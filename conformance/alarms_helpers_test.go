// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// alarmEnv is a server with a source object for conditions and a client.
type alarmEnv struct {
	srv    *server.Server
	url    string
	ns     *server.NodeNameSpace
	source *ua.NodeID
	c      *opcua.Client
}

func newAlarmEnv(t *testing.T, opts ...server.Option) *alarmEnv {
	t.Helper()
	srv, url := newServer(t, opts...)
	ns := server.NewNodeNameSpace(srv, "urn:conformance:alarms")
	src := server.NewFolderNode(ua.NewStringNodeID(ns.ID(), "Boiler"), "Boiler")
	ns.AddNode(src)
	ns.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	return &alarmEnv{srv: srv, url: url, ns: ns, source: src.ID(), c: newClient(t, url)}
}

// alarm adds a condition on the source.
func (e *alarmEnv) alarm(t *testing.T, cfg server.ConditionConfig) *server.Condition {
	t.Helper()
	if cfg.Source == nil {
		cfg.Source = e.source
	}
	if cfg.Name == "" {
		cfg.Name = "HighTemperature"
	}
	cond, err := e.srv.AddCondition(cfg)
	require.NoError(t, err)
	return cond
}

// condStream is an event item with NewConditionEventFilter.
type condStream struct {
	sub *opcua.Subscription
	ch  chan *opcua.PublishNotificationData
	buf []*opcua.ConditionEvent
}

// watch subscribes to the condition events of notifier (the Server object
// when nil).
func (e *alarmEnv) watch(t *testing.T, c *opcua.Client, notifier *ua.NodeID) *condStream {
	t.Helper()
	if notifier == nil {
		notifier = ua.NewNumericNodeID(0, id.Server)
	}
	sub, ch, err := c.NewSubscription().Interval(fastInterval).
		MonitorEvents(opcua.NewConditionEventFilter(), notifier).Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	return &condStream{sub: sub, ch: ch}
}

// next returns the next event that matches pred, skipping the others.
func (s *condStream) next(t *testing.T, what string, pred func(*opcua.ConditionEvent) bool) *opcua.ConditionEvent {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		for len(s.buf) > 0 {
			ev := s.buf[0]
			s.buf = s.buf[1:]
			if pred(ev) {
				return ev
			}
		}
		select {
		case msg := <-s.ch:
			require.NoError(t, msg.Error)
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, f := range enl.Events {
				ev, err := opcua.ParseConditionEvent(f)
				require.NoError(t, err)
				s.buf = append(s.buf, ev)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
			return nil
		}
	}
}

// refresh calls ConditionRefresh and returns the condition events between
// the RefreshStart and RefreshEnd events.
func (s *condStream) refresh(t *testing.T) []*opcua.ConditionEvent {
	t.Helper()
	require.NoError(t, s.sub.ConditionRefresh(context.Background()))
	return s.collectRefresh(t)
}

func (s *condStream) collectRefresh(t *testing.T) []*opcua.ConditionEvent {
	t.Helper()
	s.next(t, "RefreshStartEvent", (*opcua.ConditionEvent).IsRefreshStart)
	var out []*opcua.ConditionEvent
	for {
		ev := s.next(t, "RefreshEndEvent", func(*opcua.ConditionEvent) bool { return true })
		if ev.IsRefreshEnd() {
			return out
		}
		out = append(out, ev)
	}
}

// of matches the events of a condition.
func of(cond *server.Condition, more ...func(*opcua.ConditionEvent) bool) func(*opcua.ConditionEvent) bool {
	return func(ev *opcua.ConditionEvent) bool {
		if !cond.NodeID().Equal(ev.ConditionID) {
			return false
		}
		for _, m := range more {
			if !m(ev) {
				return false
			}
		}
		return true
	}
}

func is(p *bool, want bool) bool { return p != nil && *p == want }

func ptr[T any](v T) *T { return &v }
