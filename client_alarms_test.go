// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func TestConditionEventFilter(t *testing.T) {
	f := opcua.NewConditionEventFilter()
	fields := opcua.ConditionEventFields()
	require.Len(t, f.SelectClauses, len(fields)+1)
	cid := f.SelectClauses[0]
	require.Empty(t, cid.BrowsePath)
	require.Equal(t, ua.AttributeIDNodeID, cid.AttributeID)
	require.Equal(t, uint32(id.ConditionType), cid.TypeDefinitionID.IntID())
	for i, p := range fields {
		sc := f.SelectClauses[i+1]
		require.NotEmpty(t, sc.BrowsePath, p)
		names := make([]string, len(sc.BrowsePath))
		for j, q := range sc.BrowsePath {
			names[j] = q.Name
		}
		require.Equal(t, p, strings.Join(names, "/"))
	}
	require.Equal(t, uint32(id.AcknowledgeableConditionType), f.SelectClauses[17].TypeDefinitionID.IntID(), "AckedState/Id")

	_, err := opcua.ParseConditionEvent(nil)
	require.Error(t, err)
	_, err = opcua.ParseConditionEvent(&ua.EventFieldList{EventFields: []*ua.Variant{ua.MustVariant(int32(1))}})
	require.Error(t, err)

	// Null fields (e.g. events that are not condition events) parse to the
	// zero values.
	null := make([]*ua.Variant, len(fields)+1)
	null[2] = ua.MustVariant(ua.NewNumericNodeID(0, id.RefreshEndEventType))
	ev, err := opcua.ParseConditionEvent(&ua.EventFieldList{EventFields: null})
	require.NoError(t, err)
	require.True(t, ev.IsRefreshEnd())
	require.False(t, ev.IsRefreshStart())
	require.Nil(t, ev.Acked)
	require.Nil(t, ev.Quality)
}

// FuzzParseConditionEvent: any decodable EventFieldList parses or fails
// without a panic.
func FuzzParseConditionEvent(f *testing.F) {
	fields := make([]*ua.Variant, len(opcua.ConditionEventFields())+1)
	for i := range fields {
		fields[i] = ua.MustVariant(true)
	}
	fields[1] = ua.MustVariant([]byte{1, 2})
	fields[14] = ua.MustVariant(uint16(3))
	seed, err := ua.Encode(&ua.EventFieldList{ClientHandle: 1, EventFields: fields})
	require.NoError(f, err)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		var ev ua.EventFieldList
		if _, err := ua.Decode(b, &ev); err != nil {
			return
		}
		_, _ = opcua.ParseConditionEvent(&ev)
	})
}

// The client helpers against the server's conditions (Part 9).
func TestClientConditionMethods(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := server.NewNodeNameSpace(srv, "urn:test:client-alarms")
	src := server.NewFolderNode(ua.NewStringNodeID(ns.ID(), "Tank"), "Tank")
	ns.AddNode(src)
	ns.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	cond, err := srv.AddCondition(server.ConditionConfig{Name: "Overflow", Source: src.ID(), Confirmable: true, Shelving: true})
	require.NoError(t, err)
	plain, err := srv.AddCondition(server.ConditionConfig{Name: "Info", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.ConditionType)})
	require.NoError(t, err)
	require.NoError(t, cond.SetActive(true))

	c := testutil.NewTestClient(t, url)
	ctx := context.Background()
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(opcua.NewConditionEventFilter(), ua.NewNumericNodeID(0, id.Server)).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	var buf []*opcua.ConditionEvent
	next := func(pred func(*opcua.ConditionEvent) bool) *opcua.ConditionEvent {
		deadline := time.After(20 * time.Second)
		for {
			for len(buf) > 0 {
				ev := buf[0]
				buf = buf[1:]
				if pred(ev) {
					return ev
				}
			}
			select {
			case msg := <-ch:
				require.NoError(t, msg.Error)
				enl, ok := msg.Value.(*ua.EventNotificationList)
				if !ok {
					continue
				}
				for _, f := range enl.Events {
					ev, err := opcua.ParseConditionEvent(f)
					require.NoError(t, err)
					buf = append(buf, ev)
				}
			case <-deadline:
				t.Fatal("timed out waiting for a condition event")
				return nil
			}
		}
	}
	require.NoError(t, sub.ConditionRefresh(ctx))
	ev := next(func(ev *opcua.ConditionEvent) bool { return cond.NodeID().Equal(ev.ConditionID) })
	next((*opcua.ConditionEvent).IsRefreshEnd)

	require.NoError(t, c.Acknowledge(ctx, cond.NodeID(), ev.EventID, "ack"))
	ev = next(func(ev *opcua.ConditionEvent) bool { return ev.Acked != nil && *ev.Acked })
	require.NoError(t, c.Confirm(ctx, cond.NodeID(), ev.EventID, ""))
	ev = next(func(ev *opcua.ConditionEvent) bool { return ev.Confirmed != nil && *ev.Confirmed })
	require.NoError(t, c.AddComment(ctx, cond.NodeID(), ev.EventID, "note"))
	next(func(ev *opcua.ConditionEvent) bool { return ev.Comment != nil && ev.Comment.Text == "note" })
	require.NoError(t, c.TimedShelve(ctx, cond.NodeID(), time.Hour))
	require.NoError(t, c.Unshelve(ctx, cond.NodeID()))
	require.NoError(t, c.OneShotShelve(ctx, cond.NodeID()))
	require.NoError(t, c.DisableCondition(ctx, cond.NodeID()))
	require.NoError(t, c.EnableCondition(ctx, cond.NodeID()))

	// A ConditionType instance has no ShelvingState and no Acknowledge.
	require.Error(t, c.TimedShelve(ctx, plain.NodeID(), time.Hour))
	require.Error(t, c.OneShotShelve(ctx, plain.NodeID()))
	require.Error(t, c.Unshelve(ctx, plain.NodeID()))
	require.ErrorIs(t, c.Acknowledge(ctx, plain.NodeID(), ev.EventID, ""), ua.StatusBadMethodInvalid)

	// A closed client fails the calls.
	require.NoError(t, c.Close(ctx))
	require.Error(t, c.ConditionRefresh(ctx, 1))
}
