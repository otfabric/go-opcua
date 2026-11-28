// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"slices"
	"time"

	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
)

// This file holds the AggregateFilter of data MonitoredItems (Part 4
// §7.22.4, Part 13 §4.3).
//
// Design. An aggregate item keeps the samples of its Variable as raw
// values instead of queueing them: the samples a data item without a
// filter would report, taken under the same sampling interval ("The
// samplingInterval of the MonitoringParameters ... defines how the Server
// should internally sample the underlying data source"). When the
// publishing timer of its Subscription expires, the item calculates every
// interval that has completed with server/aggregate and queues one value
// per interval: "The MonitoredItem only reports values for intervals that
// have completed when the publish timer expires. Unused data is carried
// over and used to calculate a value returned in the next publish" (Part 4
// §7.22.4). The calculation is that of a HistoryRead over the same raw
// values: "The calculation is done in the same manner as a historical read
// with the Partial Bit set" (Part 13 §4.3.2), so an interval holding the
// latest raw value is Partial and one after it is After End of Data.
//
// The intervals are startTime + n × processingInterval, the boundaries a
// HistoryRead of the same Aggregate uses (Part 4 §7.22.4). The server does
// not read history for a MonitoredItem: a startTime in the past is revised
// to the first boundary at or after the creation of the item.

// Revision policy of the processingInterval of an AggregateFilter, in
// milliseconds. "If the ProcessingInterval of 0 is passed in the
// MonitoredItemFilter it shall be revised to a suitable non-zero value"
// (Part 13 §5.4.3.1); the server takes the publishing interval of the
// Subscription, one value per publish.
const (
	minAggregateProcessingMS = 100.0
	maxAggregateProcessingMS = 24 * 3_600_000.0 // one day
)

// maxAggregateRaw bounds the raw values an aggregate item keeps between two
// calculations; beyond it the oldest are dropped.
const maxAggregateRaw = 1 << 16

// aggregateItem is the AggregateFilter state of a MonitoredItem. Guarded by
// MonitoredItemService.Mu.
type aggregateItem struct {
	fn  *ua.NodeID
	cfg aggregate.Config
	// pi is the revisedProcessingInterval, piMS the same in milliseconds as
	// it was returned.
	pi   time.Duration
	piMS float64
	// start is the revisedStartTime, next the start of the next interval
	// to calculate.
	start, next time.Time
	// raw holds the samples the next intervals are calculated from.
	raw []*ua.DataValue
}

// filterResult is the AggregateFilterResult of the item (Part 4 §7.22.4,
// Table 147).
func (a *aggregateItem) filterResult() *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.AggregateFilterResult{
		RevisedStartTime:              a.start,
		RevisedProcessingInterval:     a.piMS,
		RevisedAggregateConfiguration: a.cfg.AggregateConfiguration(),
	})
}

// aggregateFilterOf returns the AggregateFilter of a MonitoringFilter, nil
// for any other filter.
func aggregateFilterOf(eo *ua.ExtensionObject) *ua.AggregateFilter {
	if eo == nil {
		return nil
	}
	switch v := eo.Value.(type) {
	case *ua.AggregateFilter:
		return v
	case ua.AggregateFilter:
		return &v
	}
	return nil
}

// reviseProcessingInterval revises the processingInterval of an
// AggregateFilter: a missing one (0, negative or not a number) becomes the
// publishing interval (Part 13 §5.4.3.1), and "The
// revisedProcessingInterval shall be at least twice the
// revisedSamplingInterval for the MonitoredItem" (Part 4 §7.22.4, Table
// 147).
func reviseProcessingInterval(requestedMS, samplingMS, publishingMS float64) float64 {
	pi := requestedMS
	if math.IsNaN(pi) || math.IsInf(pi, 0) || pi <= 0 {
		pi = publishingMS
	}
	return min(max(pi, minAggregateProcessingMS, 2*samplingMS), maxAggregateProcessingMS)
}

// reviseAggregateStart revises the startTime of an AggregateFilter to the
// first boundary startTime + n × pi at or after now: "the startTime should
// remain in the same boundary (startTime + revisedProcessingInterval * n =
// revisedStartTime)" (Part 4 §7.22.4). A startTime in the future is kept;
// without a startTime, or one too far back for a time.Duration, the
// intervals start at now.
func reviseAggregateStart(start time.Time, pi time.Duration, now time.Time) time.Time {
	if !start.Before(now) {
		return start
	}
	d := now.Sub(start)
	if start.IsZero() || d > math.MaxInt64-pi {
		return now.Truncate(time.Millisecond)
	}
	n := d / pi
	if d%pi != 0 {
		n++
	}
	return start.Add(n * pi)
}

// aggregateConfig returns the configuration the Aggregates of nodeID are
// calculated with when a request does not override it: that of the
// history provider (Part 13 §4.3.1: "The default values used for
// MonitoredItem Aggregates are the same as those used for historical
// Aggregates"), or the defaults.
func (s *Server) aggregateConfig(nodeID *ua.NodeID) aggregate.Config {
	h, _ := s.history()
	return aggregateConfigOf(h, nodeID)
}

// aggregateConfigOf is the configuration of nodeID that h gives, the
// defaults when h is no AggregateConfigProvider.
func aggregateConfigOf(h HistoryProvider, nodeID *ua.NodeID) aggregate.Config {
	if p, ok := h.(AggregateConfigProvider); ok {
		return p.AggregateConfig(nodeID)
	}
	return aggregate.DefaultConfig()
}

// newAggregateItem validates the AggregateFilter of a data item and returns
// its state. cfg is the configuration of the Variable, which the filter
// may override.
//   - Bad_FilterNotAllowed when the item is not on the Value Attribute:
//     Aggregates are calculated from the values of a Variable.
//   - Bad_AggregateNotSupported for an Aggregate the server does not
//     calculate (Part 13 §5.3.2, Table 45).
//   - Bad_MonitoredItemFilterInvalid for an aggregateConfiguration that is
//     not valid (Part 13 §4.2.1.2).
//   - Bad_TimestampsToReturnInvalid unless the source timestamp is asked
//     for: "If a requested timestamp is set to anything but the source
//     timestamp the operation shall return the Bad_TimestampToReturnInvalid
//     StatusCode" (Part 13 §5.4.3.1). Both is accepted, as in a HistoryRead;
//     its ServerTimestamp "shall be the time of the end of the processing
//     interval" (Part 4 §7.22.4).
func newAggregateItem(rv *ua.ReadValueID, f *ua.AggregateFilter, cfg aggregate.Config, ts ua.TimestampsToReturn, samplingMS, publishingMS float64, now time.Time) (*aggregateItem, ua.StatusCode) {
	if rv.AttributeID != ua.AttributeIDValue {
		return nil, ua.StatusBadFilterNotAllowed
	}
	if !aggregate.Supported(f.AggregateType) {
		return nil, ua.StatusBadAggregateNotSupported
	}
	cfg = cfg.Override(f.AggregateConfiguration)
	if !cfg.Valid() {
		return nil, ua.StatusBadMonitoredItemFilterInvalid
	}
	if ts != ua.TimestampsToReturnSource && ts != ua.TimestampsToReturnBoth {
		return nil, ua.StatusBadTimestampsToReturnInvalid
	}
	piMS := reviseProcessingInterval(f.ProcessingInterval, samplingMS, publishingMS)
	pi := time.Duration(piMS * float64(time.Millisecond))
	start := reviseAggregateStart(f.StartTime, pi, now)
	return &aggregateItem{fn: f.AggregateType, cfg: cfg, pi: pi, piMS: piMS, start: start, next: start}, ua.StatusOK
}

// record keeps a sample of an aggregate item as a raw value.
// A raw value is stamped with its SourceTimestamp, the ServerTimestamp or
// the time of the sample, in that order; a sample with the status, value
// and SourceTimestamp of the previous one is the same raw value. Caller
// must hold s.Mu.
func (a *aggregateItem) record(dv *ua.DataValue, now time.Time) {
	if dv == nil {
		return
	}
	if dv.SourceTimestamp.IsZero() {
		dv.SourceTimestamp = dv.ServerTimestamp
		if dv.SourceTimestamp.IsZero() {
			dv.SourceTimestamp = now
		}
		dv.EncodingMask |= ua.DataValueSourceTimestamp
	}
	if n := len(a.raw); n > 0 && !(dataChangeFilter{timestamp: true}).changed(stateOf(a.raw[n-1]), stateOf(dv)) {
		return
	}
	a.raw = append(a.raw, dv)
	if len(a.raw) > maxAggregateRaw {
		a.raw = a.raw[len(a.raw)-maxAggregateRaw:]
	}
}

// prune drops the raw values the intervals from next on do not need: it
// keeps the values from next on and, before next, those back to the
// second value that is not Bad, which the bounding values of next are
// found with (Part 13 §3.1.8, §3.1.9).
func (a *aggregateItem) prune() {
	slices.SortStableFunc(a.raw, func(x, y *ua.DataValue) int { return x.SourceTimestamp.Compare(y.SourceTimestamp) })
	keep, _ := slices.BinarySearchFunc(a.raw, a.next, func(dv *ua.DataValue, t time.Time) int { return dv.SourceTimestamp.Compare(t) })
	for found := 0; keep > 0 && found < 2; {
		keep--
		if !isBad(a.raw[keep].Status) {
			found++
		}
	}
	a.raw = slices.Delete(a.raw, 0, keep)
}

// restart moves the intervals of an item that was not sampled to the first
// boundary at or after now, and forgets the raw values: the intervals in
// between were "not sampled or evaluated" (Part 4 §7.23, Table 148).
func (a *aggregateItem) restart(now time.Time) {
	a.raw = nil
	a.next = reviseAggregateStart(a.start, a.pi, now)
}

// calculateAggregates queues the values of the intervals that have
// completed by now for every aggregate item of the subscription that is
// sampled. The subscription calls it when its publishing timer expires.
func (s *MonitoredItemService) calculateAggregates(subID uint32, now time.Time) {
	if s.aggItems.Load() == 0 {
		return
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	for _, item := range s.Subs[subID] {
		if item != nil && item.agg != nil && item.Mode != ua.MonitoringModeDisabled {
			s.calculateAggregate(item, now)
		}
	}
}

// calculateAggregate queues one value per interval of the item that has
// completed by now. Its SourceTimestamp is that of the Aggregate, its
// ServerTimestamp the end of the interval (Part 4 §7.22.4). An Aggregate
// that cannot be calculated over the raw values (Bad_NotSupported for
// arrays, Part 11 §6.5.4.2) gives that status for each interval. Caller
// must hold s.Mu.
func (s *MonitoredItemService) calculateAggregate(item *MonitoredItem, now time.Time) {
	a := item.agg
	if now.Before(a.next) {
		return
	}
	n := now.Sub(a.next) / a.pi
	if n == 0 {
		return
	}
	if n > aggregate.MaxIntervals {
		// Intervals that no queue could hold; they cannot be reached with
		// a publishing interval of at most an hour.
		a.next = a.next.Add((n - aggregate.MaxIntervals) * a.pi)
		n = aggregate.MaxIntervals
	}
	r := aggregate.Request{Aggregate: a.fn, Start: a.next, End: a.next.Add(n * a.pi), ProcessingInterval: a.pi, Config: a.cfg}
	values, st := r.Calculate(a.raw)
	for i := range int(n) {
		start, end := r.Interval(i)
		dv := &ua.DataValue{EncodingMask: ua.DataValueStatusCode | ua.DataValueSourceTimestamp, Status: st, SourceTimestamp: start}
		if st == ua.StatusOK {
			dv = values[i]
		}
		dv.ServerTimestamp = end
		dv.EncodingMask |= ua.DataValueServerTimestamp
		_ = ua.ApplyTimestampsToReturn(dv, item.timestampsToReturn)
		item.enqueue(&ua.MonitoredItemNotification{ClientHandle: item.Req.RequestedParameters.ClientHandle, Value: dv})
	}
	a.next = r.End
	a.prune()
}

// createAggregateConfigs returns the configuration of the Variable of every
// item to create that has an AggregateFilter, by index.
func (s *MonitoredItemService) createAggregateConfigs(items []*ua.MonitoredItemCreateRequest) map[int]aggregate.Config {
	var out map[int]aggregate.Config
	for i, it := range items {
		if it == nil || it.ItemToMonitor == nil || it.RequestedParameters == nil || aggregateFilterOf(it.RequestedParameters.Filter) == nil {
			continue
		}
		if out == nil {
			out = make(map[int]aggregate.Config)
		}
		out[i] = s.SubService.srv.aggregateConfig(it.ItemToMonitor.NodeID)
	}
	return out
}

// modifyAggregateConfigs returns the configuration of the Variable of every
// item to modify that gets an AggregateFilter, by MonitoredItemId.
func (s *MonitoredItemService) modifyAggregateConfigs(items []*ua.MonitoredItemModifyRequest) map[uint32]aggregate.Config {
	nodes := make(map[uint32]*ua.NodeID)
	s.Mu.Lock()
	for _, it := range items {
		if it == nil || it.RequestedParameters == nil || aggregateFilterOf(it.RequestedParameters.Filter) == nil {
			continue
		}
		if mi := s.Items[it.MonitoredItemID]; mi != nil && !mi.isEvent {
			nodes[mi.ID] = mi.Req.ItemToMonitor.NodeID
		}
	}
	s.Mu.Unlock()
	out := make(map[uint32]aggregate.Config, len(nodes))
	for id, n := range nodes {
		out[id] = s.SubService.srv.aggregateConfig(n)
	}
	return out
}

// setAggregate gives a data item its new AggregateFilter state, nil for
// none. An item that gets an AggregateFilter keeps the current value as its
// first raw value; one that keeps one carries its raw values over to the
// new intervals; one that loses it reports the current value, as a new data
// item does (Part 4 §5.13.1.1). Caller must hold s.Mu.
func (s *MonitoredItemService) setAggregate(mi *MonitoredItem, agg *aggregateItem, now time.Time) {
	old := mi.agg
	switch {
	case old == nil && agg == nil:
		return
	case old == nil:
		s.aggItems.Add(1)
	case agg == nil:
		s.aggItems.Add(-1)
		mi.hasLast = false
	default:
		agg.raw = old.raw
	}
	mi.agg = agg
	if (old == nil || agg == nil) && mi.Mode != ua.MonitoringModeDisabled {
		s.sampleItem(mi, now, true)
	}
}
