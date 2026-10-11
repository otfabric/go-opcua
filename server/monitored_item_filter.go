// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"reflect"
	"slices"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// This file holds the data-change side of the MonitoredItem Service Set:
// the DataChangeFilter (Part 4 §7.22.2, Part 8 §7.2), the sampling interval
// (Part 4 §5.13.1.2) and the per-item IndexRange.
//
// Design. The server is exception based: the address space tells the
// MonitoredItemService that a node changed (ChangeNotification) and the
// service then samples the monitored items of that node. Nothing polls.
//
//   - Sampling interval 0 is the fastest supported "interval" and means
//     exactly that exception-based model: every change is sampled when it
//     happens (Part 4 §5.13.1.2).
//   - With a sampling interval T > 0 an item is sampled at most once per T.
//     A change that arrives when the item was last sampled at least T ago is
//     sampled right away, so a slowly changing value is reported without
//     added latency. A change that arrives earlier only marks the item as due
//     at lastSample+T; when that moment comes the then-current value is
//     sampled, which is the latest value of that interval.
//   - Due items of the whole service share one timer (armed for the earliest
//     due time, and only while something is due). There is no goroutine or
//     ticker per monitored item or per subscription, so a million idle items
//     cost nothing.
//
// Every sample runs through the item's filter and is compared with the last
// value that was queued for that item ("last cached value", §7.22.2).

// Sampling interval revision policy, in milliseconds.
const (
	// minSamplingIntervalMS is the shortest cyclic sampling interval. Shorter
	// positive requests are revised up to it; 0 selects exception-based
	// sampling instead.
	minSamplingIntervalMS = 1.0
	maxSamplingIntervalMS = maxPublishingIntervalMS
)

// reviseSamplingInterval applies Part 4 §5.13.1.2 / §7.21.1 to a requested
// sampling interval. publishingMS is the publishing interval of the
// subscription, used when the client asks for the default (a negative value).
func reviseSamplingInterval(requestedMS, publishingMS float64) float64 {
	switch {
	case math.IsNaN(requestedMS) || requestedMS < 0:
		requestedMS = publishingMS
	case requestedMS == 0:
		// Fastest practical rate: exception based, every change is sampled.
		return 0
	}
	if requestedMS < minSamplingIntervalMS {
		return minSamplingIntervalMS
	}
	if requestedMS > maxSamplingIntervalMS {
		return maxSamplingIntervalMS
	}
	return requestedMS
}

// dataChangeFilter is a validated DataChangeFilter.
//
// The zero value is the default filter, STATUS_VALUE without a deadband.
type dataChangeFilter struct {
	// statusOnly is the STATUS trigger, timestamp the STATUS_VALUE_TIMESTAMP
	// trigger; neither is STATUS_VALUE.
	statusOnly bool
	timestamp  bool
	// hasDeadband is set for an Absolute or Percent deadband; deadband is
	// then the absolute change that has to be exceeded (a Percent deadband
	// is resolved against the EURange when the filter is validated).
	hasDeadband bool
	deadband    float64
}

// defaultDataChangeFilter is what applies when the client sends no filter:
// "STATUS_VALUE is the default reporting behaviour" (Part 4 §7.22.2).
func defaultDataChangeFilter() dataChangeFilter {
	return dataChangeFilter{}
}

// sampleState is what the filter remembers of the last queued sample.
type sampleState struct {
	status   ua.StatusCode
	value    *ua.Variant
	sourceTS time.Time
}

func stateOf(dv *ua.DataValue) sampleState {
	if dv == nil {
		return sampleState{}
	}
	return sampleState{status: dv.Status, value: dv.Value, sourceTS: dv.SourceTimestamp}
}

// changed reports whether cur has to be reported given the last queued sample.
func (f dataChangeFilter) changed(last, cur sampleState) bool {
	// "Deadband is ignored if the status of the data item changes."
	if last.status != cur.status {
		return true
	}
	if f.statusOnly {
		return false
	}
	deadband := 0.0
	if f.hasDeadband {
		deadband = f.deadband
	}
	if variantChanged(last.value, cur.value, deadband) {
		return true
	}
	// "If a Deadband filter is specified, this trigger has the same
	// behaviour as STATUS_VALUE" (Part 4 §7.10).
	if f.timestamp && !f.hasDeadband {
		return !last.sourceTS.Equal(cur.sourceTS)
	}
	return false
}

// isNumericType reports whether t is one of the built-in Number types a
// deadband can be applied to.
func isNumericType(t ua.TypeID) bool {
	// SByte, Byte, Int16, UInt16, Int32, UInt32, Int64, UInt64, Float and
	// Double are the built-in types 2 to 11 (Part 6 §5.1.2).
	return t >= ua.TypeIDSByte && t <= ua.TypeIDDouble
}

// variantChanged compares two values. Numeric scalars and arrays are compared
// element by element against the deadband (0 = any change): a change is
// reported when any element moved by more than the deadband or when the
// array's size or dimensions changed. Everything else is compared for
// equality.
func variantChanged(a, b *ua.Variant, deadband float64) bool {
	if a == nil || b == nil {
		return (a == nil) != (b == nil)
	}
	if a.Type() != b.Type() {
		return true
	}
	av, bv := a.Value(), b.Value()
	if isNumericType(a.Type()) {
		if !slices.Equal(a.ArrayDimensions(), b.ArrayDimensions()) {
			return true
		}
		return numericChanged(reflect.ValueOf(av), reflect.ValueOf(bv), deadband)
	}
	return !reflect.DeepEqual(av, bv)
}

// numericChanged walks scalars and (nested) slices of Go numbers.
func numericChanged(a, b reflect.Value, deadband float64) bool {
	for a.Kind() == reflect.Interface {
		a = a.Elem()
	}
	for b.Kind() == reflect.Interface {
		b = b.Elem()
	}
	if a.Kind() != b.Kind() {
		return true
	}
	switch a.Kind() {
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() {
			return true
		}
		for i := 0; i < a.Len(); i++ {
			if numericChanged(a.Index(i), b.Index(i), deadband) {
				return true
			}
		}
		return false
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int:
		x, y := a.Int(), b.Int()
		if x < y {
			x, y = y, x
		}
		// The difference of two int64 always fits a uint64, so large values
		// that differ by little are not lost to float64 rounding.
		return float64(uint64(x)-uint64(y)) > deadband
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
		x, y := a.Uint(), b.Uint()
		if x < y {
			x, y = y, x
		}
		return float64(x-y) > deadband
	case reflect.Float32, reflect.Float64:
		x, y := a.Float(), b.Float()
		if math.IsNaN(x) || math.IsNaN(y) {
			// Entering or leaving NaN is one change; staying NaN is none
			// (Part 4 §7.10).
			return math.IsNaN(x) != math.IsNaN(y)
		}
		if x == y {
			return false // also covers equal infinities
		}
		return math.Abs(x-y) > deadband
	default:
		return !reflect.DeepEqual(a.Interface(), b.Interface())
	}
}

// parseDataChangeFilter validates the filter of a data monitored item and
// returns the filter to apply. The status codes are those of Part 4
// §5.13.2.4 and Part 8 §7.2.
func (s *MonitoredItemService) parseDataChangeFilter(rv *ua.ReadValueID, eo *ua.ExtensionObject) (dataChangeFilter, ua.StatusCode) {
	def := defaultDataChangeFilter()
	if eo == nil || eo.Value == nil {
		return def, ua.StatusOK
	}
	var f *ua.DataChangeFilter
	switch v := eo.Value.(type) {
	case *ua.DataChangeFilter:
		f = v
	case ua.DataChangeFilter:
		f = &v
	case *ua.EventFilter, ua.EventFilter:
		// An EventFilter only goes with the EventNotifier attribute.
		return def, ua.StatusBadFilterNotAllowed
	case *ua.AggregateFilter, ua.AggregateFilter:
		return def, ua.StatusBadMonitoredItemFilterUnsupported
	default:
		return def, ua.StatusBadMonitoredItemFilterInvalid
	}
	if f == nil {
		return def, ua.StatusOK
	}
	// A DataChangeFilter is defined for the Value attribute only.
	if rv.AttributeID != ua.AttributeIDValue {
		return def, ua.StatusBadFilterNotAllowed
	}
	var out dataChangeFilter
	switch f.Trigger {
	case ua.DataChangeTriggerStatus:
		out.statusOnly = true
	case ua.DataChangeTriggerStatusValue:
	case ua.DataChangeTriggerStatusValueTimestamp:
		out.timestamp = true
	default:
		return def, ua.StatusBadMonitoredItemFilterInvalid
	}
	switch ua.DeadbandType(f.DeadbandType) {
	case ua.DeadbandTypeNone:
		return out, ua.StatusOK
	case ua.DeadbandTypeAbsolute, ua.DeadbandTypePercent:
	default:
		return def, ua.StatusBadMonitoredItemFilterInvalid
	}

	percent := ua.DeadbandType(f.DeadbandType) == ua.DeadbandTypePercent
	if math.IsNaN(f.DeadbandValue) || f.DeadbandValue < 0 || (percent && f.DeadbandValue > 100) {
		return def, ua.StatusBadDeadbandFilterInvalid
	}
	// "This parameter applies only to Variables with any Number data type."
	if !s.hasNumericDataType(rv.NodeID) {
		return def, ua.StatusBadFilterNotAllowed
	}
	out.hasDeadband = true
	out.deadband = f.DeadbandValue
	if percent {
		// Part 8 §7.2: the deadband is a percentage of the EURange, so it is
		// only available for items that have that property (AnalogItemType).
		r := s.euRange(rv.NodeID)
		if r == nil {
			return def, ua.StatusBadMonitoredItemFilterUnsupported
		}
		out.deadband = f.DeadbandValue / 100 * math.Abs(r.High-r.Low)
	}
	return out, ua.StatusOK
}

// hasNumericDataType reports whether the Value of the variable is a Number:
// its DataType attribute is a built-in number or a subtype of Number. When the
// data type is not known or as vague as BaseDataType (for instance in a
// MapNamespace) the current value decides.
func (s *MonitoredItemService) hasNumericDataType(nodeid *ua.NodeID) bool {
	srv := s.SubService.srv
	ns, err := srv.Namespace(int(nodeid.Namespace()))
	if err != nil {
		return false
	}
	var dt *ua.NodeID
	if dv := ns.Attribute(nodeid, ua.AttributeIDDataType); dv != nil && dv.Status == ua.StatusOK && dv.Value != nil {
		switch v := dv.Value.Value().(type) {
		case *ua.NodeID:
			dt = v
		case *ua.ExpandedNodeID:
			if v != nil {
				dt = v.NodeID
			}
		}
	}
	vague := dt == nil || (dt.Namespace() == 0 && (dt.IntID() == 0 || dt.IntID() == id.BaseDataType))
	if !vague {
		if dt.Namespace() == 0 && isNumericType(ua.TypeID(dt.IntID())) {
			return true
		}
		return srv.isSubtypeOf(dt, ua.NewNumericNodeID(0, id.Number))
	}
	dv := ns.Attribute(nodeid, ua.AttributeIDValue)
	return dv != nil && dv.Value != nil && isNumericType(dv.Value.Type())
}

// euRange returns the value of the EURange property of the node, or nil when
// it has none.
func (s *MonitoredItemService) euRange(nodeid *ua.NodeID) *ua.Range {
	srv := s.SubService.srv
	ns, err := srv.Namespace(int(nodeid.Namespace()))
	if err != nil {
		return nil
	}
	res := ns.Browse(&ua.BrowseDescription{
		NodeID:          nodeid,
		BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasProperty),
		IncludeSubtypes: true,
		ResultMask:      uint32(ua.BrowseResultMaskAll),
	})
	if res == nil {
		return nil
	}
	for _, ref := range res.References {
		if ref == nil || ref.NodeID == nil || ref.NodeID.NodeID == nil ||
			ref.BrowseName == nil || ref.BrowseName.Name != "EURange" {
			continue
		}
		target := ref.NodeID.NodeID
		tns, err := srv.Namespace(int(target.Namespace()))
		if err != nil {
			continue
		}
		dv := tns.Attribute(target, ua.AttributeIDValue)
		if dv == nil || dv.Value == nil {
			continue
		}
		switch v := dv.Value.Value().(type) {
		case *ua.ExtensionObject:
			if v == nil {
				continue
			}
			switch r := v.Value.(type) {
			case *ua.Range:
				if r != nil {
					return r
				}
			case ua.Range:
				return &r
			}
		case *ua.Range:
			if v != nil {
				return v
			}
		}
	}
	return nil
}

// readSample reads the monitored attribute of an item, reduced to the item's
// IndexRange. The result is a private copy.
func (s *MonitoredItemService) readSample(item *MonitoredItem) *ua.DataValue {
	rv := item.Req.ItemToMonitor
	ns, err := s.SubService.srv.Namespace(int(rv.NodeID.Namespace()))
	if err != nil {
		s.SubService.srv.cfg.logger.Warn("error getting namespace", "namespace", rv.NodeID.Namespace(), "error", err)
		return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBad}
	}
	dv := ns.Attribute(rv.NodeID, rv.AttributeID)
	if dv == nil {
		return nil
	}
	// Copy so timestamp filtering / overflow bits do not mutate the node store.
	cp := *dv
	if item.indexRange == "" || cp.Value == nil {
		return &cp
	}
	sliced, st := ua.SliceVariantRead(cp.Value, item.indexRange)
	if st != ua.StatusOK {
		// The array may grow into the range later, so the item stays alive
		// and reports the status instead (Part 4 §5.13.2.4,
		// Bad_IndexRangeNoData).
		cp.Value = nil
		cp.EncodingMask &^= ua.DataValueValue
		cp.EncodingMask |= ua.DataValueStatusCode
		cp.Status = st
		return &cp
	}
	cp.Value = sliced
	return &cp
}

// sampleItem takes one sample of a data item and queues it when the filter
// lets it through. force skips the filter; it is used for the first sample of
// an item, which is always reported. Caller must hold s.Mu.
func (s *MonitoredItemService) sampleItem(item *MonitoredItem, now time.Time, force bool) {
	// This sample is the one a postponed sample was waiting for. Leaving the
	// postponed one pending would sample the item a second time within the
	// same sampling interval: a change can arrive after the interval ended
	// but before the sampler timer got to run.
	s.cancelDeferredSample(item)
	item.lastSampled = now
	dv := s.readSample(item)
	cur := stateOf(dv)
	if !force && item.hasLast && !item.filter.changed(item.last, cur) {
		return
	}
	item.last, item.hasLast = cur, true

	_ = ua.ApplyTimestampsToReturn(dv, item.timestampsToReturn)
	val := &ua.MonitoredItemNotification{
		ClientHandle: item.Req.RequestedParameters.ClientHandle,
		Value:        dv,
	}
	item.enqueue(val)
	// Sampling queues without waking Publish; Reporting wakes the publish loop.
	if item.Mode == ua.MonitoringModeReporting {
		select {
		case item.Sub.NotifyChannel <- val:
		default:
		}
	}
}

// deferSample marks the item as due for a sample at the given time and makes
// sure the sampler timer fires by then. Caller must hold s.Mu.
func (s *MonitoredItemService) deferSample(item *MonitoredItem, due time.Time) {
	if item.sampleDue.IsZero() {
		item.sampleDue = due
		if s.due == nil {
			s.due = make(map[uint32]*MonitoredItem)
		}
		s.due[item.ID] = item
	}
	s.armSampler(item.sampleDue)
}

// cancelDeferredSample forgets the postponed sample of an item, if any, and
// stops the sampler timer when no postponed sample is left: an idle service
// keeps no timer armed. Caller must hold s.Mu.
func (s *MonitoredItemService) cancelDeferredSample(item *MonitoredItem) {
	if item == nil {
		return
	}
	item.sampleDue = time.Time{}
	delete(s.due, item.ID)
	s.stopSamplerIfIdle()
}

// stopSamplerIfIdle stops the sampler timer when nothing is due. Caller must
// hold s.Mu.
func (s *MonitoredItemService) stopSamplerIfIdle() {
	if len(s.due) != 0 || s.samplerAt.IsZero() {
		return
	}
	s.samplerAt = time.Time{}
	if s.sampler != nil {
		// A callback that already fired finds nothing due.
		s.sampler.Stop()
	}
}

// armSampler (re)arms the one sampler timer of the service so that it fires
// no later than due. Caller must hold s.Mu.
func (s *MonitoredItemService) armSampler(due time.Time) {
	if !s.samplerAt.IsZero() && !due.Before(s.samplerAt) {
		return // already armed early enough
	}
	s.samplerAt = due
	d := time.Until(due)
	if d < 0 {
		d = 0
	}
	if s.sampler == nil {
		s.sampler = time.AfterFunc(d, s.runSampler)
		return
	}
	s.sampler.Reset(d)
}

// runSampler is the callback of the sampler timer: it samples every item that
// is due and re-arms the timer for the next one.
func (s *MonitoredItemService) runSampler() {
	s.samplerRuns.Add(1)
	defer s.samplerRuns.Add(-1)
	defer func() {
		// A value function of the application may panic; that must not end
		// the process.
		if r := recover(); r != nil {
			logPanic(s.SubService.srv.cfg.logger, "sampling monitored items", r)
		}
	}()
	s.Mu.Lock()
	defer s.Mu.Unlock()

	s.samplerAt = time.Time{}
	now := time.Now()
	var next time.Time
	for id, item := range s.due {
		if item.sampleDue.After(now) {
			if next.IsZero() || item.sampleDue.Before(next) {
				next = item.sampleDue
			}
			continue
		}
		delete(s.due, id)
		item.sampleDue = time.Time{}
		if s.Items[id] != item || item.Mode == ua.MonitoringModeDisabled {
			continue
		}
		s.sampleItem(item, now, false)
	}
	if !next.IsZero() {
		s.armSampler(next)
	}
}
