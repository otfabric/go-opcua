// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// logCall records a call of EstablishConnections or CloseConnections in the
// AutomationComponentLog of ac: "the AutomationComponent shall produce
// LogRecords for all calls of the EstablishConnections and CloseConnections
// Methods", with the TraceContext of the client (Part 81 §6.2.2, OPC
// 10000-26 §5.6.4). The record carries what AuditUpdateMethodResultEventType
// does (§8.4: the StatusCodeId as AdditionalData), and for a call that is
// not Good the ErrorCode of BaseLogEventType (OPC 10000-26 §6.3), which
// §6.2.2 recommends.
func (c *Connections) logCall(ctx context.Context, ac *automationComponent, name string, sc ua.StatusCode) {
	l := ac.log
	if l == nil {
		return
	}
	mc, _ := server.MethodCallerFromContext(ctx)
	data := []*ua.NameValuePair{nv("StatusCodeId", sc)}
	if sc != ua.StatusGood {
		data = append(data, nv("ErrorCode", sc))
	}
	l.Add(ua.LogRecord{
		Severity:       severityOf(sc),
		EventType:      ua.NewNumericNodeID(c.ns.Data, fxdataid.AuditUpdateMethodResultEventType),
		SourceNode:     ac.id,
		SourceName:     "Method/" + name,
		Message:        ua.NewLocalizedText(name + " of " + ac.id.String() + ": " + sc.Error()),
		TraceContext:   l.traceOf(mc),
		AdditionalData: data,
	})
}

// logCleanup records the cleanup of e when its CleanupTimeout expired
// (Part 81 §6.6.2): SourceNode the FunctionalEntity, SourceName the
// BrowseName of the ConnectionEndpoint, a Message that tells the timeout,
// and the RemovedEndpoint and RelatedEndpoint of
// AuditConnectionCleanupEventType as AdditionalData (§8.3). A close that
// failed is an Error with its ErrorCode.
func (c *Connections) logCleanup(e *endpoint, sc ua.StatusCode, related *ua.Variant) {
	l := e.ac.log
	if l == nil {
		return
	}
	msg := "CleanupTimeout of the ConnectionEndpoint " + e.name + " expired: the Connection was closed and removed"
	data := []*ua.NameValuePair{nv("RemovedEndpoint", e.name), {Name: "RelatedEndpoint", Value: related}}
	sev := SeverityWarning
	if sc != ua.StatusGood {
		msg = "CleanupTimeout of the ConnectionEndpoint " + e.name + " expired: the removal failed (" + sc.Error() + "), it is tried again"
		data = append(data, nv("ErrorCode", sc))
		sev = SeverityError
	}
	l.Add(ua.LogRecord{
		Severity:       sev,
		EventType:      ua.NewNumericNodeID(c.ns.AC, fxacid.AuditConnectionCleanupEventType),
		SourceNode:     e.fe,
		SourceName:     e.name,
		Message:        ua.NewLocalizedText(msg),
		AdditionalData: data,
	})
}

// logEntryClass adds to the fields of an audit event the ConditionClassId
// LogEntryConditionClassType (OPC 10000-26 §6.5), which maps it to the
// records of a LogObject: "If AutomationComponentLog is supported, this
// AuditEvent shall set either the ConditionClassId or a ConditionSubClassId
// to LogEntryConditionClassType" (Part 81 §8.2 to §8.4, §8.6 for the
// ConnectionManagerLog).
func logEntryClass(fields map[string]*ua.Variant) map[string]*ua.Variant {
	fields["ConditionClassId"] = ua.MustVariant(ua.NewNumericNodeID(0, id.LogEntryConditionClassType))
	fields["ConditionClassName"] = ua.MustVariant(ua.NewLocalizedText("LogEntryConditionClassType"))
	return fields
}
