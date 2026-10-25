// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func TestParseConditionEvent105(t *testing.T) {
	n := len(opcua.ConditionEventFields()) + 1
	f := make([]*ua.Variant, n)
	f[10] = ua.MustVariant(ua.NewGUIDNodeID(1, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"))
	f[22] = ua.MustVariant(true)
	f[23] = ua.MustVariant(false)
	f[24] = ua.MustVariant(true)
	f[25] = ua.MustVariant(false)
	f[26] = ua.MustVariant(true)
	f[27] = ua.MustVariant(ua.NewLocalizedText("go?"))
	f[28] = ua.MustVariant(int32(2))
	ev, err := opcua.ParseConditionEvent(&ua.EventFieldList{EventFields: f})
	require.NoError(t, err)
	require.True(t, ev.IsBranch())
	require.True(t, *ev.Suppressed)
	require.False(t, *ev.OutOfService)
	require.True(t, *ev.Silenced)
	require.False(t, *ev.Latched)
	require.True(t, *ev.DialogActive)
	require.Equal(t, "go?", ev.Prompt.Text)
	require.Equal(t, int32(2), *ev.LastResponse)

	// A null BranchId in any numeric encoding is not a branch.
	for _, b := range []*ua.NodeID{nil, ua.NewTwoByteNodeID(0), ua.NewNumericNodeID(0, 0), ua.NewFourByteNodeID(0, 0)} {
		require.False(t, (&opcua.ConditionEvent{BranchID: b}).IsBranch(), "%v", b)
	}
	require.True(t, (&opcua.ConditionEvent{BranchID: ua.NewStringNodeID(0, "")}).IsBranch())

	// The fields of a v1.14.0 filter still parse.
	ev, err = opcua.ParseConditionEvent(&ua.EventFieldList{EventFields: make([]*ua.Variant, 22)})
	require.NoError(t, err)
	require.Nil(t, ev.Suppressed)
	require.Nil(t, ev.LastResponse)
}

func TestParseAuditConditionEvent(t *testing.T) {
	f := opcua.NewAuditConditionEventFilter()
	require.Len(t, f.SelectClauses, 17)
	require.Len(t, f.WhereClause.Elements, 1)
	_, err := opcua.ParseAuditConditionEvent(nil)
	require.Error(t, err)
	_, err = opcua.ParseAuditConditionEvent(&ua.EventFieldList{EventFields: make([]*ua.Variant, 3)})
	require.Error(t, err)
	vals := make([]*ua.Variant, 17)
	vals[5] = ua.MustVariant(ua.NewLocalizedText("m"))
	vals[15] = ua.MustVariant(int32(1))
	vals[16] = ua.MustVariant(1500.0)
	ev, err := opcua.ParseAuditConditionEvent(&ua.EventFieldList{EventFields: vals})
	require.NoError(t, err)
	require.Equal(t, "m", ev.Message)
	require.Equal(t, int32(1), *ev.SelectedResponse)
	require.Equal(t, 1500*time.Millisecond, *ev.ShelvingTime)
}

func TestClientConditionMethods105(t *testing.T) {
	srv, url := testutil.NewTestServer(t, server.WithAuditing(true))
	ns := server.NewNodeNameSpace(srv, "urn:test:client-alarms105")
	src := server.NewFolderNode(ua.NewStringNodeID(ns.ID(), "Tank"), "Tank")
	ns.AddNode(src)
	ns.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	cond, err := srv.AddCondition(server.ConditionConfig{Name: "Overflow", Source: src.ID(), Shelving: true,
		Suppressible: true, Serviceable: true, Silenceable: true, Latching: true})
	require.NoError(t, err)
	plain, err := srv.AddCondition(server.ConditionConfig{Name: "Info", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.ConditionType)})
	require.NoError(t, err)
	g, err := srv.AddAlarmGroup(server.AlarmGroupConfig{Name: "Area", Namespace: ns})
	require.NoError(t, err)
	require.NoError(t, g.AddMember(cond))

	c := testutil.NewTestClient(t, url)
	ctx := opcua.WithAuditEntryID(context.Background(), "e-1")
	cid := cond.NodeID()
	require.NoError(t, c.Suppress(ctx, cid))
	require.NoError(t, c.Unsuppress2(ctx, cid, "u"))
	require.NoError(t, c.Suppress2(ctx, cid, ""))
	require.NoError(t, c.Unsuppress(ctx, cid))
	require.NoError(t, c.RemoveFromService2(ctx, cid, "r"))
	require.NoError(t, c.PlaceInService(ctx, cid))
	require.NoError(t, c.RemoveFromService(ctx, cid))
	require.NoError(t, c.PlaceInService2(ctx, cid, "p"))
	require.NoError(t, c.Silence(ctx, cid))
	require.NoError(t, cond.SetActive(true))
	require.ErrorIs(t, c.Reset(ctx, cid), ua.StatusBadInvalidState)
	require.NoError(t, cond.SetActive(false))
	require.NoError(t, c.Reset2(ctx, cid, "done"))
	require.NoError(t, c.TimedShelve2(ctx, cid, time.Hour, "h"))
	require.NoError(t, c.OneShotShelve2(ctx, cid, ""))
	require.NoError(t, c.Unshelve2(ctx, cid, "x"))
	groups, err := c.GetGroupMemberships(ctx, cid)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.True(t, g.NodeID().Equal(groups[0]))

	// A ConditionType instance has none of them.
	require.Error(t, c.TimedShelve2(ctx, plain.NodeID(), time.Hour, ""))
	require.Error(t, c.OneShotShelve2(ctx, plain.NodeID(), ""))
	require.Error(t, c.Unshelve2(ctx, plain.NodeID(), ""))
	_, err = c.GetGroupMemberships(ctx, plain.NodeID())
	require.ErrorIs(t, err, ua.StatusBadMethodInvalid)
	require.ErrorIs(t, c.Respond(ctx, plain.NodeID(), 0), ua.StatusBadMethodInvalid)
	require.ErrorIs(t, c.Respond2(ctx, plain.NodeID(), 0, "x"), ua.StatusBadMethodInvalid)

	require.NoError(t, c.Close(ctx))
	_, err = c.GetGroupMemberships(ctx, cid)
	require.Error(t, err)
}
