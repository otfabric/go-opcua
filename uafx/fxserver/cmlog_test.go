// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// find returns the records of l whose Message starts with prefix.
func find(l *fxserver.Log, prefix string) []*ua.LogRecord {
	var out []*ua.LogRecord
	for _, r := range l.Records() {
		if strings.HasPrefix(r.Message.Text, prefix) {
			out = append(out, r)
		}
	}
	return out
}

// TestConnectionManagerLog: with ConnectionManagerOptions.Log the
// ConnectionManager has a ConnectionManagerLog (Part 81 §6.7.2) with a
// record per set of every EditConnectionConfigurationSets and
// ProcessConnectionConfigurationSets call (§6.7.4, §6.7.5), one for a call
// without sets, one per SelectionList write (§6.8.2), one per transition
// with a HasEffect (§6.9.2) and one per error of a run (§8.10); the events
// of §8.4 and §8.6 get the ConditionClassId LogEntryConditionClassType.
func TestConnectionManagerLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true, Log: &fxserver.LogOptions{MaxRecords: 200}}, server.WithAuditing(true))
	audit := watchEvents(t, f.c, ua.NewNumericNodeID(0, id.Server), "EventType", "ConditionClassId")
	cmEvents := watchEvents(t, f.c, ua.NewNumericNodeID(f.ns.CM, fxcmid.FxRootConnectionManager), "EventType", "ConditionClassId")
	l := f.cm.Log()
	require.NotNil(t, l)
	node, err := uafx.ConnectionManagerLog(ctx, f.c)
	require.NoError(t, err)
	require.True(t, node.Equal(l.Node()))
	logEntry := ua.NewNumericNodeID(0, id.LogEntryConditionClassType).String()

	// Edit, with a SpanContext: a record per set, SourceName the client.
	editor := f.client(t, "urn:test:editor", true)
	trace := ua.NewGUID("0A1B2C3D-0000-4000-8000-00000000000A")
	_, _, err = uafx.EditConnectionConfigurationSets(opcua.WithSpanContext(ctx, &ua.SpanContextDataType{TraceID: trace, SpanID: 9}),
		editor, uafx.StartEditing, []*ua.NodeID{f.set, ua.NewStringNodeID(f.ns.CM, "nope")})
	require.NoError(t, err)
	ev := nextEvent(t, audit, ua.NewNumericNodeID(f.ns.Data, fxdataid.AuditUpdateMethodResultEventType))
	assert.Equal(t, logEntry, ev[1].Value().(*ua.NodeID).String())
	edits := find(l, "ConnectionManager/EditConnection StartEditing")
	require.Len(t, edits, 2)
	assert.True(t, edits[0].SourceNode.Equal(f.set))
	assert.Equal(t, "urn:test:editor", edits[0].SourceName)
	assert.Equal(t, fxserver.SeverityInformation, edits[0].Severity)
	require.NotNil(t, edits[0].TraceContext)
	assert.Equal(t, uint64(9), edits[0].TraceContext.ParentSpanID)
	assert.Equal(t, "urn:test:editor", edits[0].TraceContext.ParentIdentifier)
	assert.Equal(t, fxserver.SeverityError, edits[1].Severity)
	assert.Equal(t, map[string]any{"StatusCodeId": ua.StatusBadNodeIDUnknown, "ErrorCode": ua.StatusBadNodeIDUnknown}, data(edits[1]))

	// A SelectionList write: SourceNode the Variable, the old and new
	// values in the Message (§6.8.2).
	pi := f.node(".Flow[Flow1].PublishingInterval")
	require.Equal(t, ua.StatusOK, f.write(t, editor, pi, 20.0))
	ev = nextEvent(t, audit, ua.NewNumericNodeID(f.ns.CM, fxcmid.AuditUpdateConnectionConfigurationSetEventType))
	assert.Equal(t, logEntry, ev[1].Value().(*ua.NodeID).String())
	assert.Equal(t, ua.StatusBadOutOfRange, f.write(t, editor, pi, 30.0))
	writes := find(l, "PublishingInterval of Line1")
	require.Len(t, writes, 2)
	assert.True(t, writes[0].SourceNode.Equal(pi))
	assert.Equal(t, "PublishingInterval", writes[0].SourceName)
	assert.Contains(t, writes[0].Message.Text, "from 10 to 20")
	assert.Equal(t, map[string]any{"OldValue": 10.0, "NewValue": 20.0, "StatusCodeId": ua.StatusOK}, data(writes[0]))
	assert.Equal(t, ua.StatusBadOutOfRange, data(writes[1])["ErrorCode"])
	_, _ = f.edit(t, editor, uafx.CommitUpdates, f.set)

	// Calls without sets: one record, SourceNode the ConnectionManager.
	cm := ua.NewNumericNodeID(f.ns.CM, fxcmid.FxRootConnectionManager)
	_, _, err = uafx.EditConnectionConfigurationSets(ctx, f.c, 99, []*ua.NodeID{f.set})
	require.Error(t, err)
	_, _, err = uafx.ProcessConnectionConfigurationSets(ctx, f.c, 99, []*ua.NodeID{f.set})
	require.Error(t, err)
	res, err := f.c.Call(ctx, &ua.CallMethodRequest{ObjectID: cm,
		MethodID:       ua.NewNumericNodeID(f.ns.CM, fxcmid.FxRootConnectionManagerEditConnectionConfigurationSets),
		InputArguments: []*ua.Variant{ua.MustVariant(int32(uafx.StartEditing)), ua.MustVariant("x")}})
	require.NoError(t, err)
	require.NotEqual(t, ua.StatusOK, res.StatusCode)
	_, rs, err := uafx.EditConnectionConfigurationSets(ctx, f.c, uafx.DiscardUpdates, nil)
	require.NoError(t, err)
	require.Empty(t, rs)
	for _, p := range []string{"ConnectionManager/EditConnection FxEdit(99): ", "ConnectionManager/ProcessConnection FxProcess(99): ",
		"ConnectionManager/EditConnection : ", "ConnectionManager/EditConnection DiscardUpdates: "} {
		r := find(l, p)
		require.Len(t, r, 1, p)
		assert.True(t, r[0].SourceNode.Equal(cm), p)
	}

	// Process: the run fails, as no server is reachable.
	_, rs, err = uafx.ProcessConnectionConfigurationSets(ctx, f.c, uafx.ActionEstablishConnections, []*ua.NodeID{f.set})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)
	ev = nextEvent(t, cmEvents, ua.NewNumericNodeID(f.ns.CM, fxcmid.ConnectionConfigurationSetProcessingStartedEventType))
	assert.Equal(t, logEntry, ev[1].Value().(*ua.NodeID).String())
	nextEvent(t, cmEvents, ua.NewNumericNodeID(f.ns.CM, fxcmid.ConnectionConfigurationSetProcessingFailedEventType))
	f.cm.Flush()
	assert.Len(t, find(l, "ConnectionManager/ProcessConnection ActionEstablishConnections of "), 1)
	var started, failedTr *ua.LogRecord
	var errs []*ua.LogRecord
	for _, r := range l.Records() {
		switch {
		case r.SourceName == "ReadyToProcessing":
			started = r
		case r.SourceName == "ProcessingToError":
			failedTr = r
		case r.EventType.Equal(ua.NewNumericNodeID(f.ns.CM, fxcmid.EstablishConnectionErrorEventType)):
			errs = append(errs, r)
		}
	}
	require.NotNil(t, started)
	assert.True(t, started.SourceNode.Equal(f.set))
	assert.Contains(t, started.Message.Text, "from Ready to Processing")
	assert.Equal(t, map[string]any{"ConnectionConfigurationSetNode": f.set, "Name": "Line1", "Action": int32(uafx.ActionEstablishConnections)}, data(started))
	require.NotNil(t, failedTr)
	assert.Equal(t, fxserver.SeverityError, failedTr.Severity)
	require.Len(t, errs, 2, "one per endpoint of C1")
	assert.Equal(t, "C1", errs[0].SourceName)
	assert.Contains(t, errs[0].Message.Text, "Endpoint1")
	assert.Contains(t, errs[1].Message.Text, "Endpoint2")
	assert.Equal(t, f.node(".Conn[C1]").String(), data(errs[0])["ErrorCodeNode"].(*ua.NodeID).String())
	assert.Equal(t, int32(uafx.FxErrorTargetServerConnectionError), data(errs[0])["FxError"])
}

// TestConnectionManagerLogEvents: the records of the Events of the
// Manager that the tests cannot provoke over offlineDialer: the calls
// (§6.7.3.2) and the failures without a Connection (§8.10) or of a close
// (§8.11).
func TestConnectionManagerLogEvents(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Log: &fxserver.LogOptions{}})
	l := f.cm.Log()
	key := fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"}
	trace := &ua.TraceContextDataType{TraceID: ua.NewGUID("0A1B2C3D-0000-4000-8000-00000000000B"), SpanID: 5}
	fxserver.LogEvent(f.cm, fxcm.Event{Kind: fxcm.EventCall, Set: key, Method: "EstablishConnections", Address: "opc.tcp://plc1",
		Connections: []string{"C1", "C2"}, CommandMask: uafx.CreateConnectionEndpointCmd, Trace: trace})
	fxserver.LogEvent(f.cm, fxcm.Event{Kind: fxcm.EventCall, Set: key, Method: "EstablishConnections", Address: "opc.tcp://plc1",
		CommandMask: uafx.ReserveCommunicationIDsCmd, Status: ua.StatusUncertain})
	fxserver.LogEvent(f.cm, fxcm.Event{Kind: fxcm.EventCall, Set: fxcm.SetKey{Name: "Gone"}, Method: "CloseConnections", Address: "opc.tcp://plc2",
		Connections: []string{"C1"}, Err: errors.New("lost")})
	fxserver.LogEvent(f.cm, fxcm.Event{Kind: fxcm.EventTransition, Set: key, Transition: fxcm.ProcessingToReady, Action: fxcm.ActionRemoveSet,
		Failures: []fxcm.RunFailure{
			{Failure: fxcm.Failure{FxError: uafx.FxErrorRuntimeError, Status: ua.StatusBadInternalError}},
			{Endpoint: fxcm.EndpointRef{Connection: "C1", Endpoint: 1}, Failure: fxcm.Failure{FxError: uafx.FxErrorCloseConnectionError, Status: ua.StatusBadTimeout}},
			{Endpoint: fxcm.EndpointRef{Connection: "Unknown"}, Failure: fxcm.Failure{FxError: uafx.FxErrorCloseConnectionError, Status: ua.StatusBadTimeout}},
		}})
	// A transition without a HasEffect, of a set that is gone: no record
	// but the failure's.
	fxserver.LogEvent(f.cm, fxcm.Event{Kind: fxcm.EventTransition, Set: fxcm.SetKey{Name: "Gone"}, Transition: fxcm.ProcessingToReady,
		Failures: []fxcm.RunFailure{{Endpoint: fxcm.EndpointRef{Connection: "C1"}, Failure: fxcm.Failure{FxError: uafx.FxErrorCreateConnectionEndpointError, Status: ua.StatusBad}}}})
	fxserver.LogEvent(f.cm, fxcm.Event{Kind: fxcm.EventTransition, Set: key, Transition: 99})
	fxserver.LogEvent(f.cm, fxcm.Event{Kind: fxcm.EventSettle, Set: key})

	recs := l.Records()
	require.Len(t, recs, 9)
	cm := ua.NewNumericNodeID(f.ns.CM, fxcmid.FxRootConnectionManager)
	call := ua.NewNumericNodeID(0, id.AuditClientUpdateMethodResultEventType)

	for i, name := range []string{"C1", "C2"} {
		r := recs[i]
		assert.True(t, r.EventType.Equal(call))
		assert.True(t, r.SourceNode.Equal(f.set))
		assert.Equal(t, name, r.SourceName)
		assert.Equal(t, "EstablishConnections (CreateConnectionEndpoint) of "+name+" at opc.tcp://plc1: "+ua.StatusOK.Error(), r.Message.Text)
		assert.Same(t, trace, r.TraceContext)
		assert.Equal(t, map[string]any{"ServerAddress": "opc.tcp://plc1", "CommandMask": uint32(uafx.CreateConnectionEndpointCmd), "StatusCodeId": ua.StatusOK}, data(r))
	}
	assert.Equal(t, "ConnectionManager", recs[2].SourceName, "a call without endpoints")
	assert.Equal(t, fxserver.SeverityWarning, recs[2].Severity)
	assert.Equal(t, ua.StatusUncertain, data(recs[2])["ErrorCode"])

	assert.True(t, recs[3].SourceNode.Equal(cm), "the set is gone")
	assert.Equal(t, "CloseConnections of C1 at opc.tcp://plc2: lost", recs[3].Message.Text)
	assert.Equal(t, fxserver.SeverityError, recs[3].Severity)
	assert.NotContains(t, data(recs[3]), "CommandMask")

	tr := recs[4]
	assert.Equal(t, "ProcessingToReady", tr.SourceName)
	assert.Equal(t, int32(uafx.ActionRemoveConnections), data(tr)["Action"])
	assert.True(t, tr.EventType.Equal(ua.NewNumericNodeID(f.ns.CM, fxcmid.ConnectionConfigurationSetProcessingSucceededEventType)))

	run := recs[5]
	assert.Equal(t, "ConnectionManager", run.SourceName)
	assert.True(t, run.EventType.Equal(ua.NewNumericNodeID(f.ns.CM, fxcmid.EstablishConnectionErrorEventType)))
	assert.True(t, isNull(data(run)["ErrorCodeNode"].(*ua.NodeID)))
	assert.Equal(t, int32(uafx.FxErrorRuntimeError), data(run)["FxError"])

	cl := recs[6]
	assert.Equal(t, "C1", cl.SourceName)
	assert.True(t, cl.EventType.Equal(ua.NewNumericNodeID(f.ns.CM, fxcmid.CloseConnectionErrorEventType)))
	assert.Equal(t, "closing ActionRemoveConnections of C1, Endpoint1, failed: CloseConnectionError ("+ua.StatusBadTimeout.Error()+")", cl.Message.Text)
	assert.Equal(t, f.node(".Conn[C1]").String(), data(cl)["ErrorCodeNode"].(*ua.NodeID).String())
	assert.Equal(t, ua.StatusBadTimeout, data(cl)["ErrorCode"])

	assert.True(t, isNull(data(recs[7])["ErrorCodeNode"].(*ua.NodeID)), "no such Connection node")
	gone := recs[8]
	assert.True(t, gone.SourceNode.Equal(cm))
	assert.True(t, isNull(data(gone)["ErrorCodeNode"].(*ua.NodeID)), "no set, no Connection node")
}

// TestConnectionManagerLogErrors: a MinimumSeverity over 1000 and a NodeId
// of the log that is taken fail EnableConnectionManager; without
// ConnectionManagerOptions.Log there is no log.
func TestConnectionManagerLogErrors(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{})
	assert.Nil(t, f.cm.Log())
	_, err := uafx.ConnectionManagerLog(context.Background(), f.c)
	require.ErrorIs(t, err, uafx.ErrCall)

	_, err = fxserver.EnableConnectionManager(f.srv, f.ns, fxserver.ConnectionManagerOptions{Manager: f.m, Log: &fxserver.LogOptions{MinimumSeverity: 2000}})
	require.ErrorIs(t, err, fxserver.ErrLog)
	require.ErrorIs(t, err, fxserver.ErrConnectionManager)

	_, err = fxserver.EnableConnectionManager(f.srv, f.ns, fxserver.ConnectionManagerOptions{Manager: f.m, Log: &fxserver.LogOptions{}})
	require.ErrorIs(t, err, fxserver.ErrLog, "without TraceCalls")

	traced, err := fxcm.New(fxcm.Options{Dialer: offlineDialer{}, ApplicationURI: "urn:test:cm", TraceCalls: true, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = traced.Close() })
	srv := newServer(t)
	ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
	require.NoError(t, err)
	nsp, _ := srv.Namespace(int(ns.CM))
	nsp.AddNode(server.NewVariableNode(ua.NewStringNodeID(ns.CM, "cm.ConnectionManagerLog"), "x", 1))
	_, err = fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{Manager: traced, Log: &fxserver.LogOptions{}})
	require.ErrorIs(t, err, fxserver.ErrLog)
	assert.Nil(t, srv.Node(ua.NewStringNodeID(ns.CM, "cm.AggregatedCurrentState")), "dropped")
}
