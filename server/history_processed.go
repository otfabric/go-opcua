// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
)

// AggregateConfigProvider is optionally implemented by a HistoryProvider
// to give the configuration the Aggregates of a Variable are calculated
// with: the AggregateConfiguration of the Variable (Part 13 §4.2.1.2) and
// its Stepped Property (Part 11 §5.2.2). The aggregateConfiguration of a
// ReadProcessedDetails overrides it ([aggregate.Config.Override]). Without
// it the server uses [aggregate.DefaultConfig].
type AggregateConfigProvider interface {
	AggregateConfig(nodeID *ua.NodeID) aggregate.Config
}

// AggregateFunctionLister is optionally implemented by a
// [ProcessedHistoryReader] to list the AggregateFunction Objects it
// calculates; the server references them from the AggregateFunctions
// folder of the HistoryServerCapabilities (Part 11 §5.7.2). A
// ProcessedHistoryReader without it lists none. For a HistoryProvider that
// is no ProcessedHistoryReader the server calculates the Aggregates itself
// and lists [aggregate.Functions].
type AggregateFunctionLister interface {
	AggregateFunctions() []*ua.NodeID
}

// maxRawPages bounds the continuation points the server follows when it
// reads the raw values of a processed read from a provider.
const maxRawPages = 1 << 16

// historyAggregates returns the Aggregates processed reads of h support.
func historyAggregates(h HistoryProvider) []*ua.NodeID {
	switch p := h.(type) {
	case nil:
		return nil
	case AggregateFunctionLister:
		return p.AggregateFunctions()
	case ProcessedHistoryReader:
		return nil
	}
	return aggregate.Functions()
}

// processedRequest returns the request of a processed read: the
// ProcessingInterval is in milliseconds (Part 11 §6.5.4.1). One that is not
// a number or is negative is Bad_InvalidArgument; one too long for a
// time.Duration covers the whole range, as any interval at least as long as
// it does (Part 13 §5.4.2.2, Table 49).
func processedRequest(start, end time.Time, processingInterval float64, aggregateType *ua.NodeID, cfg aggregate.Config) (aggregate.Request, ua.StatusCode) {
	r := aggregate.Request{Aggregate: aggregateType, Start: start, End: end, Config: cfg}
	switch pi := processingInterval * float64(time.Millisecond); {
	case math.IsNaN(pi) || pi < 0:
		return r, ua.StatusBadInvalidArgument
	case pi >= math.MaxInt64:
		r.ProcessingInterval = 0
	default:
		r.ProcessingInterval = time.Duration(pi)
	}
	return r, r.Check()
}

// processedResult calculates r over raw as the HistoryReadResult of a
// processed read, a HistoryData with one value per interval.
func processedResult(r aggregate.Request, raw []*ua.DataValue) *ua.HistoryReadResult {
	values, st := r.Calculate(raw)
	if st != ua.StatusOK {
		return &ua.HistoryReadResult{StatusCode: st}
	}
	return &ua.HistoryReadResult{
		StatusCode:  ua.StatusOK,
		HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: values}),
	}
}

// readProcessed reads the Aggregate aggregateType of nodeID (Part 11
// §6.5.4). Processed values carry source timestamps only: "If a requested
// timestamp is set to anything but the source timestamp the operation shall
// return the Bad_TimestampToReturnInvalid StatusCode" (Part 13 §5.4.3.1);
// Both is accepted, as it holds the source timestamp. A
// [ProcessedHistoryReader] calculates the Aggregate itself; for any other
// provider the server calculates it from the raw values ReadRaw returns.
func readProcessed(h HistoryProvider, details *ua.ReadProcessedDetails, nodeID, aggregateType *ua.NodeID, ttr ua.TimestampsToReturn) (*ua.HistoryReadResult, error) {
	if ttr != ua.TimestampsToReturnSource && ttr != ua.TimestampsToReturnBoth {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadTimestampsToReturnInvalid}, nil
	}
	if reader, ok := h.(ProcessedHistoryReader); ok {
		return reader.ReadProcessed(nodeID, details.StartTime, details.EndTime, details.ProcessingInterval, aggregateType, details.AggregateConfiguration)
	}
	cfg := aggregateConfigOf(h, nodeID)
	r, st := processedRequest(details.StartTime, details.EndTime, details.ProcessingInterval, aggregateType, cfg.Override(details.AggregateConfiguration))
	if st != ua.StatusOK {
		return &ua.HistoryReadResult{StatusCode: st}, nil
	}
	from, to := r.Window(0, r.Intervals())
	raw, st, err := readRawRange(h, nodeID, from, to)
	if err != nil || isBad(st) {
		return &ua.HistoryReadResult{StatusCode: st}, err
	}
	return processedResult(r, raw), nil
}

// readRawRange reads every raw value of nodeID from from to to, following
// the continuation points of the provider. A read that stops early releases
// its continuation point.
func readRawRange(h HistoryProvider, nodeID *ua.NodeID, from, to time.Time) ([]*ua.DataValue, ua.StatusCode, error) {
	var raw []*ua.DataValue
	var cp []byte
	for range maxRawPages {
		res, err := h.ReadRaw(nodeID, from, to, 0, false, cp)
		if err != nil {
			return nil, ua.StatusBadInternalError, err
		}
		if res == nil {
			return nil, ua.StatusBadHistoryOperationUnsupported, nil
		}
		if isBad(res.StatusCode) {
			return nil, res.StatusCode, nil
		}
		if res.HistoryData != nil {
			if hd, ok := res.HistoryData.Value.(*ua.HistoryData); ok {
				raw = append(raw, hd.DataValues...)
			}
		}
		if cp = res.ContinuationPoint; len(cp) == 0 {
			return raw, ua.StatusOK, nil
		}
	}
	h.ReleaseContinuation(cp)
	return nil, ua.StatusBadInternalError, nil
}

// aggregateFunctionsFolder is the AggregateFunctions folder of the
// HistoryServerCapabilities: "All HistoryAggregates supported by the Server
// should be able to be browsed starting from this Object ... If the Server
// does not support Aggregates the Folder is left empty" (Part 11 §5.7.2).
const aggregateFunctionsFolder = id.HistoryServerCapabilitiesAggregateFunctions

// serverAggregateFunctionsFolder is the AggregateFunctions folder of the
// ServerCapabilities, "an entry point to browse to all AggregateFunctions
// supported by the Server" (Part 5 §6.3.2). The AggregateFilter of a
// MonitoredItem calculates every Aggregate of [aggregate.Functions] for any
// Variable, so the folder organizes them all.
const serverAggregateFunctionsFolder = id.ServerServerCapabilitiesAggregateFunctions

// bindAggregateFunctions makes the AggregateFunction Objects (Part 13
// §4.2.2) the server's own nodes, with "the Description Attribute ... is
// mandatory" set to the text of Part 13 Table 5, makes both
// AggregateFunctions folders its own nodes, and lets the folder of the
// ServerCapabilities organize the Aggregates.
func (s *Server) bindAggregateFunctions() {
	s.ownNode(aggregateFunctionsFolder)
	folder := s.ownNode(serverAggregateFunctionsFolder)
	for _, nid := range aggregate.Functions() {
		if n := s.ownNode(nid.IntID()); n != nil {
			n.SetDescription(aggregate.Description(nid), "en")
			if folder != nil {
				folder.AddRef(n, RefType(id.Organizes), true)
			}
		}
	}
}

// syncAggregateFunctions makes the AggregateFunctions folder organize the
// Aggregates processed reads of h support. Callers hold histMu.
func (s *Server) syncAggregateFunctions(h HistoryProvider) {
	folder := s.Node(ua.NewNumericNodeID(0, aggregateFunctionsFolder))
	if folder == nil {
		return
	}
	want := historyAggregates(h)
	listed := func(n *ua.NodeID) bool {
		for _, w := range want {
			if sameNodeID(w, n) {
				return true
			}
		}
		return false
	}
	organizes := ua.NewNumericNodeID(0, id.Organizes)
	for _, r := range folder.refsSnapshot() {
		if r.IsForward && sameNodeID(r.ReferenceTypeID, organizes) && r.NodeID != nil && !listed(r.NodeID.NodeID) {
			folder.RemoveRef(r.NodeID, organizes, true)
		}
	}
	for _, nid := range want {
		if n := s.Node(nid); n != nil {
			folder.AddRef(n, RefType(id.Organizes), true)
		}
	}
}
