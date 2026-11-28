// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// data returns the AdditionalData of r by name.
func data(r *ua.LogRecord) map[string]any {
	out := map[string]any{}
	for _, d := range r.AdditionalData {
		out[d.Name] = d.Value.Value()
	}
	return out
}

// watchConditionClass subscribes the client of f to the audit events of
// the Server object and returns their EventType and ConditionClassId.
func watchConditionClass(t *testing.T, c *opcua.Client) <-chan [2]*ua.NodeID {
	t.Helper()
	b := ua.NewEventFilter().SelectPaths("EventType", "ConditionClassId")
	b.Where(&ua.ContentFilterElement{
		FilterOperator: ua.FilterOperatorOfType,
		FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType))})},
	})
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(b.Build(), ua.NewNumericNodeID(0, id.Server)).Start(context.Background())
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
	out := make(chan [2]*ua.NodeID, 64)
	done, exited := make(chan struct{}), make(chan struct{})
	cleanup.Register(t, func() { close(done); <-exited })
	go func() {
		defer close(exited)
		for {
			var msg *opcua.PublishNotificationData
			select {
			case msg = <-ch:
			case <-done:
				return
			}
			if msg == nil {
				return
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, e := range enl.Events {
				var ev [2]*ua.NodeID
				ev[0], _ = e.EventFields[0].Value().(*ua.NodeID)
				ev[1], _ = e.EventFields[1].Value().(*ua.NodeID)
				select {
				case out <- ev:
				default:
				}
			}
		}
	}()
	return out
}

// nextClass returns the ConditionClassId of the next event of type typ.
func nextClass(t *testing.T, ch <-chan [2]*ua.NodeID, typ *ua.NodeID) *ua.NodeID {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-ch:
			if sameNode(ev[0], typ) {
				return ev[1]
			}
		case <-deadline:
			t.Fatalf("no event %v", typ)
		}
	}
}

// TestAutomationComponentLog: with ConnectionOptions.Log every
// AutomationComponent has an AutomationComponentLog (Part 81 §6.2.2, OPC
// 10000-26 §5.2) with a record for every EstablishConnections and
// CloseConnections call, with the TraceContext the client passed (§5.6.4),
// and for the cleanup of an endpoint (§6.6.2); the audit events get the
// ConditionClassId LogEntryConditionClassType (§8.2 to §8.4).
func TestAutomationComponentLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFX(t, fxserver.ConnectionOptions{Log: &fxserver.LogOptions{MaxRecords: 50, MinimumSeverity: 10}}, server.WithAuditing(true))
	events := watchConditionClass(t, f.c)
	l := f.conns.Log(f.id(ctlID))
	require.NotNil(t, l)
	assert.Nil(t, f.conns.Log(f.id(pumpID)))
	node, err := uafx.AutomationComponentLog(ctx, f.c, f.id(ctlID))
	require.NoError(t, err)
	require.True(t, node.Equal(l.Node()))

	// The LogObject: its type, Properties, GetRecords and the Logs folder
	// (OPC 10000-26 §5.2 Table 1, §7.3 Table 25).
	td := browse(t, f.c, node, id.HasTypeDefinition)
	require.Len(t, td, 1)
	assert.True(t, sameNode(ua.NewNumericNodeID(0, id.LogObjectType), td[0].NodeID.NodeID))
	gr := browse(t, f.c, node, id.HasComponent)
	require.Len(t, gr, 1)
	assert.Equal(t, "GetRecords", gr[0].BrowseName.Name)
	props := map[string]any{}
	for _, r := range browse(t, f.c, node, id.HasProperty) {
		dv, err := f.c.ReadValue(ctx, r.NodeID.NodeID)
		require.NoError(t, err)
		props[r.BrowseName.Name] = dv.Value.Value()
	}
	assert.Equal(t, map[string]any{"MaxRecords": uint32(50), "MinimumSeverity": uint16(10)}, props)
	var inLogs bool
	for _, r := range browse(t, f.c, ua.NewNumericNodeID(0, id.Logs), id.Organizes) {
		inLogs = inLogs || sameNode(r.NodeID.NodeID, node)
	}
	assert.True(t, inLogs, "the Logs folder organizes the log")

	trace := ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63")
	tctx := opcua.WithSpanContext(ctx, &ua.SpanContextDataType{TraceID: trace, SpanID: 7})
	r := f.fullRequest("Logged")
	r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = 50
	res, err := uafx.EstablishConnections(tctx, f.c, f.id(ctlID), r)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.Status)
	methodResult := ua.NewNumericNodeID(f.ns.Data, fxdataid.AuditUpdateMethodResultEventType)
	logEntry := ua.NewNumericNodeID(0, id.LogEntryConditionClassType)
	assert.True(t, sameNode(logEntry, nextClass(t, events, methodResult)))
	assert.Equal(t, ua.StatusBadInvalidArgument, f.callStatus(t, &uafx.EstablishConnectionsRequest{}))
	closeSC, _ := f.close(t, false, f.id(9999))
	require.NotEqual(t, ua.StatusOK, closeSC)

	// Operational, then not: the CleanupTimeout of 50 ms expires.
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	require.Eventually(t, func() bool { st, _ := f.conns.Status(ep); return st == uafx.ConnectionEndpointOperational }, 5*time.Second, 5*time.Millisecond)
	require.NoError(t, f.srv.PubSub().Disable(f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName)))
	assert.True(t, sameNode(logEntry, nextClass(t, events, ua.NewNumericNodeID(f.ns.AC, fxacid.AuditConnectionCleanupEventType))))
	require.Eventually(t, func() bool { return len(l.Records()) == 4 }, 5*time.Second, 5*time.Millisecond)

	all := ^ua.LogRecordMask(0)
	recs, err := uafx.ReadLog(ctx, f.c, node, uafx.GetRecordsRequest{RequestMask: all})
	require.NoError(t, err)
	require.Len(t, recs, 4)
	for i := 1; i < len(recs); i++ {
		assert.False(t, recs[i].Time.Before(recs[i-1].Time), "oldest first (§5.3)")
	}
	est, bad, closed, clean := recs[0], recs[1], recs[2], recs[3]
	assert.Equal(t, fxserver.SeverityInformation, est.Severity)
	assert.True(t, sameNode(methodResult, est.EventType))
	assert.True(t, sameNode(f.id(ctlID), est.SourceNode))
	assert.Equal(t, "Method/EstablishConnections", est.SourceName)
	assert.Equal(t, map[string]any{"StatusCodeId": ua.StatusOK}, data(est))
	require.NotNil(t, est.TraceContext)
	assert.Equal(t, trace.String(), est.TraceContext.TraceID.String())
	assert.Equal(t, uint64(7), est.TraceContext.ParentSpanID)
	assert.NotZero(t, est.TraceContext.SpanID)
	assert.NotEmpty(t, est.TraceContext.ParentIdentifier, "the ApplicationUri of the client (§5.6.3)")

	assert.Equal(t, fxserver.SeverityError, bad.Severity)
	assert.Equal(t, map[string]any{"StatusCodeId": ua.StatusBadInvalidArgument, "ErrorCode": ua.StatusBadInvalidArgument}, data(bad))
	assert.True(t, bad.TraceContext == nil || bad.TraceContext.SpanID == 0, "no SpanContext, no TraceContext")

	assert.Equal(t, "Method/CloseConnections", closed.SourceName)
	assert.Equal(t, map[string]any{"StatusCodeId": closeSC, "ErrorCode": closeSC}, data(closed))

	assert.Equal(t, fxserver.SeverityWarning, clean.Severity)
	assert.True(t, sameNode(ua.NewNumericNodeID(f.ns.AC, fxacid.AuditConnectionCleanupEventType), clean.EventType))
	assert.True(t, sameNode(f.id(motionID), clean.SourceNode))
	assert.Equal(t, "Logged", clean.SourceName)
	assert.Contains(t, clean.Message.Text, "CleanupTimeout")
	d := data(clean)
	assert.Equal(t, "Logged", d["RemovedEndpoint"])
	assert.Contains(t, d, "RelatedEndpoint")

	// RequestMask 0: Time, Severity and Message only (§5.8).
	recs, err = uafx.ReadLog(ctx, f.c, node, uafx.GetRecordsRequest{})
	require.NoError(t, err)
	require.Len(t, recs, 4)
	assert.Equal(t, est.Message.Text, recs[0].Message.Text)
	assert.Equal(t, est.Severity, recs[0].Severity)
	assert.True(t, isNull(recs[0].EventType))
	assert.True(t, isNull(recs[0].SourceNode))
	assert.Empty(t, recs[0].SourceName)
	assert.Empty(t, recs[0].AdditionalData)
	assert.True(t, recs[0].TraceContext == nil || recs[0].TraceContext.SpanID == 0)

	// The application adds its own records; the MinimumSeverity holds.
	l.Add(ua.LogRecord{Severity: 9, Message: ua.NewLocalizedText("below")})
	l.Add(ua.LogRecord{Severity: 500, Message: ua.NewLocalizedText("mine")})
	recs, err = uafx.ReadLog(ctx, f.c, node, uafx.GetRecordsRequest{MinimumSeverity: 300})
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.Equal(t, "mine", recs[0].Message.Text)
}

// TestLogFromNodeSet: an AutomationComponent whose instance has an
// AutomationComponentLog keeps it; the members it lacks are added.
func TestLogFromNodeSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	prepare := func(srv *server.Server) (fxserver.Namespaces, uint16, error) {
		ns, idx, err := fxtest.PrepareConnections(srv)
		if err != nil {
			return ns, idx, err
		}
		// A log with its MaxRecords, as a NodeSet would give it.
		ctl := srv.Node(ua.NewNumericNodeID(idx, ctlID))
		n := server.NewFolderNode(ua.NewStringNodeID(idx, "ctl.log"), "AutomationComponentLog")
		require.NoError(t, n.SetAttribute(ua.AttributeIDBrowseName, server.DataValueFromValue(&ua.QualifiedName{NamespaceIndex: ns.AC, Name: "AutomationComponentLog"})))
		nsp, _ := srv.Namespace(int(idx))
		nsp.AddNode(n)
		ctl.AddRef(n, server.RefTypeIDHasComponent, true)
		mr := server.NewVariableNode(ua.NewStringNodeID(idx, "ctl.log.max"), "MaxRecords", uint32(0))
		require.NoError(t, mr.SetAttribute(ua.AttributeIDBrowseName, server.DataValueFromValue(&ua.QualifiedName{Name: "MaxRecords"})))
		nsp.AddNode(mr)
		n.AddReference(mr, ua.NewNumericNodeID(0, id.HasProperty), true)
		return ns, idx, nil
	}
	f := newFXWith(t, prepare, fxserver.ConnectionOptions{Log: &fxserver.LogOptions{}})
	node, err := uafx.AutomationComponentLog(ctx, f.c, f.id(ctlID))
	require.NoError(t, err)
	assert.Equal(t, ua.NewStringNodeID(f.test, "ctl.log").String(), node.String())
	dv, err := f.c.ReadValue(ctx, ua.NewStringNodeID(f.test, "ctl.log.max"))
	require.NoError(t, err)
	assert.Equal(t, uint32(fxserver.DefaultLogMaxRecords), dv.Value.Value())
	res, err := uafx.GetRecords(ctx, f.c, node, uafx.GetRecordsRequest{})
	require.NoError(t, err)
	assert.Empty(t, res.Records)
	assert.Nil(t, res.ContinuationPoint)
}

// TestLogOptionsErrors: a MinimumSeverity over 1000, and a NodeId of the
// log that is taken, fail EnableConnections.
func TestLogOptionsErrors(t *testing.T) {
	t.Parallel()
	srv := newServer(t, server.WithPubSub(nil))
	ns, idx, err := fxtest.PrepareConnections(srv)
	require.NoError(t, err)
	_, err = fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{Log: &fxserver.LogOptions{MinimumSeverity: 1001}})
	require.ErrorIs(t, err, fxserver.ErrLog)
	require.ErrorIs(t, err, fxserver.ErrConnections)

	taken := server.NewVariableNode(ua.NewStringNodeID(idx, "uafx-log:"+ua.NewNumericNodeID(idx, ctlID).String()), "x", 1)
	nsp, _ := srv.Namespace(int(idx))
	nsp.AddNode(taken)
	_, err = fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{Log: &fxserver.LogOptions{}})
	require.ErrorIs(t, err, fxserver.ErrLog)
}

// TestCleanupFailureLogged: a cleanup whose close fails is an Error record
// with its ErrorCode; the cleanup that succeeds later a Warning (Part 81
// §6.6.2).
func TestCleanupFailureLogged(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{Log: &fxserver.LogOptions{}})
	fxserver.SetRetryCleanup(f.conns, 50*time.Millisecond)
	ep := f.operational(t, "Failing", 50)
	_, removeReader, _ := fxserver.RuntimeOps(f.conns)
	failing := make(chan struct{})
	fxserver.SetPubSubOps(f.conns, nil, func(id pubsub.ComponentID) error {
		select {
		case <-failing:
			return removeReader(id)
		default:
			return ua.StatusBadResourceUnavailable
		}
	}, nil)
	require.NoError(t, f.srv.PubSub().Disable(f.lookup(t, pubsub.KindDataSetWriter, pubConn, wgName, writerName)))
	l := f.conns.Log(f.id(ctlID))
	cleanups := func(sev uint16) []*ua.LogRecord {
		var out []*ua.LogRecord
		for _, r := range l.Records() {
			if r.SourceName == "Failing" && r.Severity == sev {
				out = append(out, r)
			}
		}
		return out
	}
	require.Eventually(t, func() bool { return len(cleanups(fxserver.SeverityError)) > 0 }, 10*time.Second, 5*time.Millisecond)
	r := cleanups(fxserver.SeverityError)[0]
	assert.Contains(t, r.Message.Text, "the removal failed")
	assert.Equal(t, ua.StatusBadResourceUnavailable, data(r)["ErrorCode"])
	close(failing)
	require.Eventually(t, func() bool { _, ok := f.conns.Status(ep); return !ok }, 10*time.Second, 5*time.Millisecond)
	require.Len(t, cleanups(fxserver.SeverityWarning), 1)
}
