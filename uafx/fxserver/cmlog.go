// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"fmt"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// Log returns the ConnectionManagerLog (Part 81 §6.7.2), nil without
// ConnectionManagerOptions.Log. The application may add its own records
// ("LogObject records can also be generated without the generation of an
// Event", §6.7.2).
func (c *ConnectionManager) Log() *Log { return c.records }

// addLog adds the ConnectionManagerLog of opts.Log.
func (c *ConnectionManager) addLog() error {
	l := newLog(*c.opts.Log)
	added, err := logNodes(c.srv, c.id, qn(c.ns.CM, "ConnectionManagerLog"), "cm.ConnectionManagerLog", l)
	c.nodes = append(c.nodes, added...)
	if err != nil {
		return err
	}
	c.records = l
	return nil
}

// logMethod records a call of EditConnectionConfigurationSets or
// ProcessConnectionConfigurationSets: "a LogRecord for each
// ConnectionConfigurationSet in the invocation of this Method", SourceNode
// the set, SourceName the ApplicationUri of the client, and a Message with
// "ConnectionManager/EditConnection", or "ConnectionManager/ProcessConnection"
// and the Action (§6.7.4, §6.7.5). A call that names no set, or whose
// arguments are wrong, is one record with SourceNode the ConnectionManager
// (§6.7.2: "LogRecords for all calls"). The StatusCodeId of the call or the
// set is AdditionalData (§8.4), with the ErrorCode of BaseLogEventType (OPC
// 10000-26 §6.3) when it is not Good.
func (c *ConnectionManager) logMethod(ctx context.Context, tag, action string, sets []*ua.NodeID, results []ua.StatusCode, sc ua.StatusCode) {
	l := c.records
	if l == nil {
		return
	}
	mc, _ := server.MethodCallerFromContext(ctx)
	var client string
	if mc != nil {
		client = mc.ClientApplicationURI
	}
	add := func(src *ua.NodeID, what string, sc ua.StatusCode) {
		data := []*ua.NameValuePair{nv("StatusCodeId", sc)}
		if sc != ua.StatusGood {
			data = append(data, nv("ErrorCode", sc))
		}
		l.Add(ua.LogRecord{
			Severity:       severityOf(sc),
			EventType:      ua.NewNumericNodeID(c.ns.Data, fxdataid.AuditUpdateMethodResultEventType),
			SourceNode:     src,
			SourceName:     client,
			Message:        ua.NewLocalizedText(fmt.Sprintf("%s %s%s: %s", tag, action, what, sc.Error())),
			TraceContext:   l.traceOf(mc),
			AdditionalData: data,
		})
	}
	if len(results) == 0 {
		add(c.id, "", sc)
		return
	}
	for i, n := range sets {
		add(n, fmt.Sprintf(" of %v", n), results[i])
	}
}

// logEvent records the Events of the Manager (§6.7.2): its
// EstablishConnections and CloseConnections calls, the errors of its runs
// (§8.10, §8.11) and the transitions of the set state machines (§6.9.2).
func (c *ConnectionManager) logEvent(e fxcm.Event) {
	l := c.records
	if l == nil {
		return
	}
	c.mu.Lock()
	s := c.sets[e.Set.String()]
	c.mu.Unlock()
	set := c.id
	if s != nil {
		set = s.id
	}
	switch e.Kind {
	case fxcm.EventCall:
		c.logCall(l, e, set)
	case fxcm.EventTransition:
		c.logTransition(l, e, s)
		for _, f := range e.Failures {
			c.logFailure(l, e, set, f)
		}
	default:
	}
}

// logCall records a call of the Manager, one record per Connection the call
// carried (§6.7.3.2): SourceNode the set, SourceName the BrowseName of the
// Connection, a Message with the action and the outcome, the ErrorCode for
// an error. Library interpretation of "the AdditionalData shall contain any
// related data that was passed in in the Call": the ServerAddress and, for
// EstablishConnections, the CommandMask, not the configuration structures.
// The TraceContext is the span the call passed to the AutomationComponent
// (§6.7.2, OPC 10000-26 §5.6.4).
func (c *ConnectionManager) logCall(l *Log, e fxcm.Event, set *ua.NodeID) {
	sc := e.Status
	outcome := sc.Error()
	if e.Err != nil {
		sc = fxcm.StatusOf(e.Err)
		outcome = e.Err.Error()
	}
	data := []*ua.NameValuePair{nv("ServerAddress", e.Address)}
	if e.Method == "EstablishConnections" {
		data = append(data, nv("CommandMask", uint32(e.CommandMask)))
	}
	data = append(data, nv("StatusCodeId", sc))
	if sc != ua.StatusGood {
		data = append(data, nv("ErrorCode", sc))
	}
	conns := e.Connections
	if len(conns) == 0 {
		conns = []string{"ConnectionManager"}
	}
	for _, cn := range conns {
		msg := fmt.Sprintf("%s of %s at %s: %s", e.Method, cn, e.Address, outcome)
		if e.Method == "EstablishConnections" {
			msg = fmt.Sprintf("%s (%s) of %s at %s: %s", e.Method, e.CommandMask, cn, e.Address, outcome)
		}
		l.Add(ua.LogRecord{
			Severity:       severityOf(sc),
			EventType:      ua.NewNumericNodeID(0, id.AuditClientUpdateMethodResultEventType),
			SourceNode:     set,
			SourceName:     cn,
			Message:        ua.NewLocalizedText(msg),
			TraceContext:   e.Trace,
			AdditionalData: data,
		})
	}
}

// logTransition records a transition with a HasEffect (§6.9.2):
// SourceNode the set, SourceName the BrowseName of the Transition, a
// Message with its FromState and ToState, and the
// ConnectionConfigurationSetNode, Name and Action of the processing events
// as AdditionalData (§8.6).
func (c *ConnectionManager) logTransition(l *Log, e fxcm.Event, s *cmSet) {
	t := e.Transition.Event()
	if t == 0 || s == nil {
		return
	}
	action := transitionAction(e.Action)
	sev := SeverityInformation
	if e.Transition == fxcm.ProcessingToError {
		sev = SeverityError
	}
	l.Add(ua.LogRecord{
		Severity:   sev,
		EventType:  ua.NewNumericNodeID(c.ns.CM, t),
		SourceNode: s.id,
		SourceName: e.Transition.String(),
		Message: ua.NewLocalizedText(fmt.Sprintf("%s of %s from %s to %s (%s)",
			e.Transition, s.key, e.Transition.From(), e.Transition.To(), action)),
		AdditionalData: []*ua.NameValuePair{
			nv("ConnectionConfigurationSetNode", s.id),
			nv("Name", s.key.Name),
			nv("Action", int32(action)),
		},
	})
}

// logFailure records a failure of a run (§8.10, §8.11): SourceNode the
// set, SourceName the BrowseName of the Connection or "ConnectionManager",
// a Message with the FxErrorEnum value, and the ErrorCode and ErrorCodeNode
// as AdditionalData. The EventType is CloseConnectionErrorEventType for a
// CloseConnectionError, EstablishConnectionErrorEventType otherwise; both
// are abstract, so the records are made without an Event (§6.7.2). Library
// interpretation: ErrorCodeNode is the Connection, which §8.11 requires for
// a close; the Manager does not report the node inside the Connection that
// failed, so for an establish it is the Connection too (§8.10: "It may be
// null if no specific Node is related").
func (c *ConnectionManager) logFailure(l *Log, e fxcm.Event, set *ua.NodeID, f fxcm.RunFailure) {
	typ, what := uint32(fxcmid.EstablishConnectionErrorEventType), "processing"
	if f.FxError == uafx.FxErrorCloseConnectionError {
		typ, what = fxcmid.CloseConnectionErrorEventType, "closing"
	}
	name := "ConnectionManager"
	node := ua.NewTwoByteNodeID(0)
	if f.Endpoint.Connection != "" {
		name = f.Endpoint.Connection
		if set.Type() == ua.NodeIDTypeString {
			cn := ua.NewStringNodeID(c.ns.CM, fmt.Sprintf("%s.Conn[%s]", set.StringID(), idPart(name)))
			if c.srv.Node(cn) != nil {
				node = cn
			}
		}
	}
	msg := fmt.Sprintf("%s %s of %s failed: %s (%s)", what, transitionAction(e.Action), name, f.FxError, f.Status.Error())
	if f.Endpoint.Endpoint > 0 {
		msg = fmt.Sprintf("%s %s of %s, Endpoint%d, failed: %s (%s)", what, transitionAction(e.Action), name, f.Endpoint.Endpoint, f.FxError, f.Status.Error())
	}
	l.Add(ua.LogRecord{
		Severity:   SeverityError,
		EventType:  ua.NewNumericNodeID(c.ns.CM, typ),
		SourceNode: set,
		SourceName: name,
		Message:    ua.NewLocalizedText(msg),
		AdditionalData: []*ua.NameValuePair{
			nv("ErrorCode", f.Status),
			nv("ErrorCodeNode", node),
			nv("FxError", int32(f.FxError)),
		},
	})
}

// logWrite records a write of a SelectionList Variable of a set (§6.8.2):
// SourceNode the Variable, SourceName its BrowseName, and a Message with
// the BrowseName of the set and the old and new values.
func (c *ConnectionManager) logWrite(s *cmSet, x *cmVar, old, nv *ua.DataValue, sc ua.StatusCode) {
	l := c.records
	if l == nil {
		return
	}
	data := []*ua.NameValuePair{
		{Name: "OldValue", Value: valueOf(old)},
		{Name: "NewValue", Value: valueOf(nv)},
		{Name: "StatusCodeId", Value: ua.MustVariant(sc)},
	}
	if sc != ua.StatusGood {
		data = append(data, &ua.NameValuePair{Name: "ErrorCode", Value: ua.MustVariant(sc)})
	}
	l.Add(ua.LogRecord{
		Severity:   severityOf(sc),
		EventType:  ua.NewNumericNodeID(c.ns.CM, fxcmid.AuditUpdateConnectionConfigurationSetEventType),
		SourceNode: x.id,
		SourceName: x.name,
		Message: ua.NewLocalizedText(fmt.Sprintf("%s of %s from %v to %v: %s",
			x.name, s.key.Name, valueOf(old).Value(), valueOf(nv).Value(), sc.Error())),
		AdditionalData: data,
	})
}

// valueOf is the Variant of dv, the null Variant for none.
func valueOf(dv *ua.DataValue) *ua.Variant {
	if dv == nil || dv.Value == nil {
		return &ua.Variant{}
	}
	return dv.Value
}

// transitionAction is the Action of the processing events of a run (§8.6):
// Remove and Reconcile are no FxProcessEnum value, they close what the set
// made, as ActionRemoveConnections does.
func transitionAction(a uafx.FxProcess) uafx.FxProcess {
	if a < 0 {
		return uafx.ActionRemoveConnections
	}
	return a
}
