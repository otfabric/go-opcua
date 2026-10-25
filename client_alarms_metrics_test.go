// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/fakeclock"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func TestParseConditionEventV117(t *testing.T) {
	t.Parallel()
	f := make([]*ua.Variant, len(opcua.ConditionEventFields())+1)
	f[29] = ua.MustVariant(true)
	f[30] = ua.MustVariant(int16(4))
	f[31] = ua.MustVariant(false)
	ev, err := opcua.ParseConditionEvent(&ua.EventFieldList{EventFields: f})
	require.NoError(t, err)
	require.True(t, *ev.AudibleEnabled)
	require.Equal(t, int16(4), *ev.ReAlarmRepeatCount)
	require.False(t, *ev.FirstInGroup)
	// The fields of a v1.17.0 filter still parse.
	ev, err = opcua.ParseConditionEvent(&ua.EventFieldList{EventFields: make([]*ua.Variant, 29)})
	require.NoError(t, err)
	require.Nil(t, ev.AudibleEnabled)
	require.Nil(t, ev.ReAlarmRepeatCount)
	_, err = opcua.ParseConditionEvent(&ua.EventFieldList{EventFields: make([]*ua.Variant, 30)})
	require.Error(t, err)
}

func TestClientAlarmMetrics(t *testing.T) {
	t.Parallel()
	clk := fakeclock.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	srv, url := testutil.NewTestServer(t, server.WithAlarmClock(clk))
	ns := server.NewNodeNameSpace(srv, "urn:test:client-alarm-metrics")
	src := server.NewFolderNode(ua.NewStringNodeID(ns.ID(), "Tank"), "Tank")
	ns.AddNode(src)
	ns.Objects().AddRef(src, server.RefTypeIDOrganizes, true)
	m, err := srv.AddAlarmMetrics(server.AlarmMetricsConfig{NodeID: ua.NewStringNodeID(ns.ID(), "Metrics"), RateMinutes: 10})
	require.NoError(t, err)
	cond, err := srv.AddCondition(server.ConditionConfig{Name: "Overflow", Source: src.ID(), ReAlarmTime: time.Minute})
	require.NoError(t, err)
	require.NoError(t, cond.SetActive(true))
	clk.Advance(90 * time.Second)
	require.NoError(t, cond.SetActive(false))

	c := testutil.NewTestClient(t, url)
	ctx := context.Background()
	got, err := c.ReadAlarmMetrics(ctx, m.NodeID())
	require.NoError(t, err)
	require.Equal(t, uint32(1), got.AlarmCount)
	require.Equal(t, uint32(1), got.MaximumReAlarmCount)
	require.Equal(t, 90*time.Second, got.MaximumActiveState)
	require.Equal(t, uint16(10), got.RateMinutes)
	require.Equal(t, 1.0, got.CurrentAlarmRate)
	require.True(t, got.StartTime.Equal(clk.Now().Add(-90*time.Second)))

	require.NoError(t, c.ResetAlarmMetrics(ctx, m.NodeID()))
	got, err = c.ReadAlarmMetrics(ctx, m.NodeID())
	require.NoError(t, err)
	require.Zero(t, got.AlarmCount)
	require.Error(t, c.ResetAlarmMetrics(ctx, cond.NodeID()))
	_, err = c.ReadAlarmMetrics(ctx, cond.NodeID())
	require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
	require.NoError(t, c.Close(ctx))
	_, err = c.ReadAlarmMetrics(ctx, m.NodeID())
	require.Error(t, err)
}
