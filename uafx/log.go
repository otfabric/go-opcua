// SPDX-License-Identifier: MIT

package uafx

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// MaxLogTime is the EndTime GetRecords sends for a zero EndTime: the
// latest DateTime (OPC 10000-6 §5.2.2.5), so that the call has no end.
var MaxLogTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// GetRecordsRequest are the arguments of GetRecords (OPC 10000-26 §5.3
// Table 2).
type GetRecordsRequest struct {
	// StartTime and EndTime bound the Time of the records; a zero EndTime
	// is MaxLogTime.
	StartTime, EndTime time.Time
	// MaxReturnRecords is the most records of one call, 0 no limit of the
	// client (the server may return fewer, with a continuation point).
	MaxReturnRecords uint32
	// MinimumSeverity is the lowest Severity returned, 1 to 1000; 0 is 1.
	MinimumSeverity uint16
	// RequestMask selects the optional fields of the records (§5.8).
	RequestMask ua.LogRecordMask
	// ContinuationPoint is the ContinuationPointOut of the previous call,
	// nil on the first one.
	ContinuationPoint []byte
}

// GetRecordsResult is what GetRecords returns: the records, oldest first,
// and the continuation point for the rest, nil when there is none.
type GetRecordsResult struct {
	Records           []*ua.LogRecord
	ContinuationPoint []byte
}

// GetRecords calls the GetRecords Method of the LogObject log (OPC 10000-26
// §5.3), such as the AutomationComponentLog of an AutomationComponent or the
// ConnectionManagerLog (Part 81 §6.2.2, §6.7.2). A Bad status of the call
// (Table 3), such as Bad_ContinuationPointInvalid, is an error with the
// status in its chain.
func GetRecords(ctx context.Context, c *opcua.Client, log *ua.NodeID, req GetRecordsRequest) (*GetRecordsResult, error) {
	return getRecords(ctx, c, log, req)
}

func getRecords(ctx context.Context, c methodClient, log *ua.NodeID, req GetRecordsRequest) (*GetRecordsResult, error) {
	method, err := childOf(ctx, c, log, ua.NodeClassMethod, &ua.QualifiedName{Name: "GetRecords"})
	if err != nil {
		return nil, err
	}
	end := req.EndTime
	if end.IsZero() {
		end = MaxLogTime
	}
	sev := max(req.MinimumSeverity, 1)
	res, err := call(ctx, c, log, method, []*ua.Variant{
		ua.MustVariant(req.StartTime), ua.MustVariant(end), ua.MustVariant(req.MaxReturnRecords),
		ua.MustVariant(sev), ua.MustVariant(uint32(req.RequestMask)), ua.MustVariant(req.ContinuationPoint),
	})
	if err != nil {
		return nil, fmt.Errorf("GetRecords: %w", err)
	}
	if len(res.OutputArguments) != 2 || res.OutputArguments[0] == nil || res.OutputArguments[1] == nil {
		return nil, fmt.Errorf("%w: GetRecords: %d output arguments", ErrCall, len(res.OutputArguments))
	}
	eo, _ := res.OutputArguments[0].Value().(*ua.ExtensionObject)
	var recs *ua.LogRecordsDataType
	if eo != nil {
		recs, _ = eo.Value.(*ua.LogRecordsDataType)
	}
	if recs == nil {
		return nil, fmt.Errorf("%w: GetRecords: Results is not a LogRecordsDataType", ErrCall)
	}
	out := &GetRecordsResult{Records: recs.LogRecordArray}
	switch v := res.OutputArguments[1].Value().(type) {
	case []byte:
		if len(v) > 0 {
			out.ContinuationPoint = v
		}
	case nil:
	default:
		return nil, fmt.Errorf("%w: GetRecords: ContinuationPointOut is %T", ErrCall, v)
	}
	return out, nil
}

// ReadLog calls GetRecords with req until the server returns no
// continuation point, and returns the records, oldest first. The records
// added between two calls may or may not be in the result.
func ReadLog(ctx context.Context, c *opcua.Client, log *ua.NodeID, req GetRecordsRequest) ([]*ua.LogRecord, error) {
	return readLog(ctx, c, log, req)
}

func readLog(ctx context.Context, c methodClient, log *ua.NodeID, req GetRecordsRequest) ([]*ua.LogRecord, error) {
	var out []*ua.LogRecord
	for {
		res, err := getRecords(ctx, c, log, req)
		if err != nil {
			return out, err
		}
		out = append(out, res.Records...)
		if res.ContinuationPoint == nil {
			return out, nil
		}
		req.ContinuationPoint = res.ContinuationPoint
	}
}

// AutomationComponentLog returns the NodeId of the AutomationComponentLog
// of the AutomationComponent ac (Part 81 §6.2.2 Table 4), an error when the
// server has no AC namespace or ac has none.
func AutomationComponentLog(ctx context.Context, c *opcua.Client, ac *ua.NodeID) (*ua.NodeID, error) {
	return componentLog(ctx, c, ac, fxacid.NamespaceURI, "AutomationComponentLog")
}

// ConnectionManagerLog returns the NodeId of the ConnectionManagerLog of
// FxRoot.ConnectionManager (Part 81 §6.7.2 Table 77, §12.3), an error when
// the server has no CM namespace or the ConnectionManager has none.
func ConnectionManagerLog(ctx context.Context, c *opcua.Client) (*ua.NodeID, error) {
	return connectionManagerLog(ctx, c)
}

func connectionManagerLog(ctx context.Context, c methodClient) (*ua.NodeID, error) {
	ns, err := cmNamespace(ctx, c)
	if err != nil {
		return nil, err
	}
	return componentLog(ctx, c, ua.NewNumericNodeID(ns, fxcmid.FxRootConnectionManager), fxcmid.NamespaceURI, "ConnectionManagerLog")
}

func componentLog(ctx context.Context, c methodClient, parent *ua.NodeID, uri, name string) (*ua.NodeID, error) {
	if parent == nil {
		return nil, fmt.Errorf("%w: no node", ErrCall)
	}
	nsa, err := c.NamespaceArray(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: NamespaceArray: %w", ErrCall, err)
	}
	for i, u := range nsa {
		if u == uri && i <= 0xffff {
			return childOf(ctx, c, parent, ua.NodeClassObject, &ua.QualifiedName{NamespaceIndex: uint16(i), Name: name})
		}
	}
	return nil, fmt.Errorf("%w: the server has no namespace %s", ErrCall, uri)
}

// childOf returns the component of n of the NodeClass class with the
// BrowseName bn.
func childOf(ctx context.Context, c methodClient, n *ua.NodeID, class ua.NodeClass, bn *ua.QualifiedName) (*ua.NodeID, error) {
	if n == nil {
		return nil, fmt.Errorf("%w: no node", ErrCall)
	}
	res, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID: n, BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent), IncludeSubtypes: true,
			NodeClassMask: uint32(class), ResultMask: uint32(ua.BrowseResultMaskBrowseName),
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Browse: %w", ErrCall, err)
	}
	if len(res.Results) != 1 || res.Results[0] == nil {
		return nil, fmt.Errorf("%w: Browse: %d results", ErrCall, len(res.Results))
	}
	if sc := res.Results[0].StatusCode; sc != ua.StatusOK {
		return nil, fmt.Errorf("%w: Browse of %v: %w", ErrCall, n, sc)
	}
	for _, r := range res.Results[0].References {
		if r != nil && r.BrowseName != nil && r.BrowseName.Name == bn.Name && r.BrowseName.NamespaceIndex == bn.NamespaceIndex &&
			r.NodeID != nil && r.NodeID.NodeID != nil && r.NodeID.NamespaceURI == "" && r.NodeID.ServerIndex == 0 {
			return r.NodeID.NodeID, nil
		}
	}
	return nil, fmt.Errorf("%w: %v has no %s", ErrCall, n, bn.Name)
}
