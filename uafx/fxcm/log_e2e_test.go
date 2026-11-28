// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// logData returns the AdditionalData of r by name.
func logData(r *ua.LogRecord) map[string]any {
	out := map[string]any{}
	for _, d := range r.AdditionalData {
		out[d.Name] = d.Value.Value()
	}
	return out
}

// TestLogsE2E: a ConnectionManager with a ConnectionManagerLog and two
// AutomationComponents with an AutomationComponentLog (Part 81 §6.7.2,
// §6.2.2). The Manager passes a SpanContext with every call (§6.7.2, OPC
// 10000-26 §5.6.4), so that each record of an AutomationComponent has the
// span of the record of the call in the ConnectionManagerLog as its
// parent; the log has the calls per Connection (§6.7.3.2), the
// transitions (§6.9.2), the ProcessConnectionConfigurationSets calls
// (§6.7.5) and the errors of a run (§8.10).
func TestLogsE2E(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logged := fxserver.ConnectionOptions{Log: &fxserver.LogOptions{}}
	a, b := newAC(t, "a", logged), newAC(t, "b", logged)
	events := &eventLog{}
	m := newManager(t, fxcm.Options{Observer: events, TraceCalls: true})
	s := newCMServerWith(t, fxserver.ConnectionManagerOptions{Manager: m, Log: &fxserver.LogOptions{MaxRecords: 500}})
	cfg, err := m.Add(e2eConf(t, "Logged", a, b))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.NoError(t, m.Remove(ctx, cfg.Key()))

	// The Events: every call has a span of the run; the Connection of
	// the endpoints it carried; the CommandMask of an establish.
	var withConn, closes int
	traces := map[string]bool{}
	for _, e := range events.of(fxcm.EventCall) {
		require.NotNil(t, e.Trace)
		assert.NotZero(t, e.Trace.SpanID)
		traces[e.Trace.TraceID.String()] = true
		switch e.Method {
		case "EstablishConnections":
			assert.NotZero(t, e.CommandMask)
			if len(e.Connections) > 0 {
				assert.Equal(t, []string{"Motion"}, e.Connections)
				withConn++
			}
		case "CloseConnections":
			assert.Equal(t, []string{"Motion"}, e.Connections)
			closes++
		}
	}
	assert.Positive(t, withConn)
	assert.Equal(t, 2, closes, "one per AutomationComponent")
	assert.Len(t, traces, 2, "a TraceId per run: the establish and the remove")

	// The ConnectionManagerLog over the wire.
	s.cm.Flush()
	node, err := uafx.ConnectionManagerLog(ctx, s.c)
	require.NoError(t, err)
	require.True(t, node.Equal(s.cm.Log().Node()))
	all := ^ua.LogRecordMask(0)
	recs, err := uafx.ReadLog(ctx, s.c, node, uafx.GetRecordsRequest{RequestMask: all})
	require.NoError(t, err)
	spans := map[uint64]*ua.LogRecord{}
	var transitions []string
	for _, r := range recs {
		if r.TraceContext != nil && r.TraceContext.SpanID != 0 {
			spans[r.TraceContext.SpanID] = r
		}
		if r.EventType != nil && r.EventType.Namespace() == s.ns.CM && strings.Contains(r.SourceName, "To") {
			transitions = append(transitions, r.SourceName)
		}
	}
	assert.Equal(t, []string{"ReadyToProcessing", "ProcessingToReady", "ReadyToProcessing", "ProcessingToReady"}, transitions)

	// Each record of the AutomationComponents is a child span of a call
	// record of the ConnectionManager (OPC 10000-26 §5.6.3).
	for _, x := range []*ac{a, b} {
		acRecs := x.conns.Log(x.id(fxtest.ConnCtl)).Records()
		require.NotEmpty(t, acRecs)
		for _, r := range acRecs {
			tc := r.TraceContext
			require.NotNil(t, tc, r.Message.Text)
			p := spans[tc.ParentSpanID]
			require.NotNil(t, p, "the parent of %s", r.Message.Text)
			assert.Equal(t, p.TraceContext.TraceID.String(), tc.TraceID.String())
			assert.Equal(t, cmURI, tc.ParentIdentifier)
			assert.True(t, p.EventType.Equal(ua.NewNumericNodeID(0, id.AuditClientUpdateMethodResultEventType)))
			assert.Equal(t, strings.TrimPrefix(r.SourceName, "Method/"), strings.Fields(p.Message.Text)[0])
		}
	}

	// A set whose second server cannot be reached, processed by the
	// Method: the call record, the error of the Connection (§8.10).
	conf := e2eConf(t, "Broken", a, b)
	conf.ServerAddresses[1].Address = "opc.tcp://127.0.0.1:1"
	cfg2, err := m.Add(conf)
	require.NoError(t, err)
	s.cm.Flush()
	set, ok := s.cm.SetNode(cfg2.Key())
	require.True(t, ok)
	_, rs, err := uafx.ProcessConnectionConfigurationSets(ctx, s.c, uafx.ActionEstablishConnectionsEnabled, []*ua.NodeID{set})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)
	require.Eventually(t, func() bool { st, _ := m.Status(cfg2.Key()); return st.State == fxcm.StateError }, 30*time.Second, 10*time.Millisecond)
	var failures []fxcm.RunFailure
	for _, e := range events.of(fxcm.EventTransition) {
		if e.Set.String() == cfg2.Key().String() {
			failures = append(failures, e.Failures...)
		}
	}
	require.NotEmpty(t, failures)
	assert.Equal(t, "Motion", failures[0].Endpoint.Connection)

	s.cm.Flush()
	recs, err = uafx.ReadLog(ctx, s.c, node, uafx.GetRecordsRequest{RequestMask: all, MinimumSeverity: fxserver.SeverityInformation})
	require.NoError(t, err)
	var processed, failed bool
	for _, r := range recs {
		switch {
		case strings.HasPrefix(r.Message.Text, "ConnectionManager/ProcessConnection ActionEstablishConnectionsEnabled"):
			processed = true
			assert.True(t, r.SourceNode.Equal(set))
			assert.Equal(t, "urn:go-opcua:fxcm:operator", r.SourceName)
		case r.EventType != nil && r.EventType.Equal(ua.NewNumericNodeID(s.ns.CM, fxcmid.EstablishConnectionErrorEventType)):
			failed = true
			assert.True(t, r.SourceNode.Equal(set))
			assert.Equal(t, "Motion", r.SourceName)
			assert.Equal(t, fxserver.SeverityError, r.Severity)
			assert.Contains(t, r.Message.Text, failures[0].FxError.String())
			d := logData(r)
			assert.Equal(t, failures[0].Status, d["ErrorCode"])
			assert.Equal(t, ua.NewStringNodeID(s.ns.CM, set.StringID()+".Conn[Motion]").String(), d["ErrorCodeNode"].(*ua.NodeID).String())
		}
	}
	assert.True(t, processed, "the record of the Method call")
	assert.True(t, failed, "the record of the error")
}
