// SPDX-License-Identifier: MIT

package server

import (
	"math"
	"sort"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// Compile-time checks for optional history interfaces on *Historian.
var (
	_ HistoryDataUpdater     = (*Historian)(nil)
	_ RawHistoryDeleter      = (*Historian)(nil)
	_ AtTimeHistoryDeleter   = (*Historian)(nil)
	_ AtTimeHistoryReader    = (*Historian)(nil)
	_ ModifiedHistoryReader  = (*Historian)(nil)
	_ ProcessedHistoryReader = (*Historian)(nil)
)

type historyModification struct {
	value            *ua.DataValue
	modificationTime time.Time
	updateType       ua.HistoryUpdateType
}

// ensureModStore lazily allocates the per-historian modification log.
func (h *Historian) ensureModStore() {
	if h.modifications == nil {
		h.modifications = make(map[string][]historyModification)
	}
}

// UpdateData implements HistoryDataUpdater.
//
// Semantics (per HistoryUpdate PerformUpdateType):
//   - Insert: BadEntryExists when a sample at the SourceTimestamp exists; else insert
//   - Replace: BadNoEntryExists when missing; else replace value
//   - Update: insert when missing, replace when present (both succeed)
func (h *Historian) UpdateData(nodeID *ua.NodeID, perform ua.PerformUpdateType, values []*ua.DataValue) *ua.HistoryUpdateResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	nodeKey := nodeID.String()
	nh, ok := h.stores[nodeKey]
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}

	ops := make([]ua.StatusCode, len(values))
	h.ensureModStore()

	for i, dv := range values {
		if dv == nil || dv.Value == nil {
			ops[i] = ua.StatusBadInvalidArgument
			continue
		}
		ts := dv.SourceTimestamp
		if ts.IsZero() {
			ops[i] = ua.StatusBadInvalidArgument
			continue
		}
		idx := findSampleIndex(nh.samples, ts)
		exists := idx >= 0

		switch perform {
		case ua.PerformUpdateTypeInsert:
			if exists {
				ops[i] = ua.StatusBadEntryExists
				continue
			}
			nh.samples = insertSample(nh.samples, cloneDataValue(dv))
			trimSamples(nh)
			h.modifications[nodeKey] = append(h.modifications[nodeKey], historyModification{
				value: cloneDataValue(dv), modificationTime: time.Now().UTC(), updateType: ua.HistoryUpdateTypeInsert,
			})
			ops[i] = ua.StatusOK

		case ua.PerformUpdateTypeReplace:
			if !exists {
				ops[i] = ua.StatusBadNoEntryExists
				continue
			}
			nh.samples[idx] = cloneDataValue(dv)
			h.modifications[nodeKey] = append(h.modifications[nodeKey], historyModification{
				value: cloneDataValue(dv), modificationTime: time.Now().UTC(), updateType: ua.HistoryUpdateTypeReplace,
			})
			ops[i] = ua.StatusOK

		case ua.PerformUpdateTypeUpdate:
			if exists {
				nh.samples[idx] = cloneDataValue(dv)
				h.modifications[nodeKey] = append(h.modifications[nodeKey], historyModification{
					value: cloneDataValue(dv), modificationTime: time.Now().UTC(), updateType: ua.HistoryUpdateTypeReplace,
				})
			} else {
				nh.samples = insertSample(nh.samples, cloneDataValue(dv))
				trimSamples(nh)
				h.modifications[nodeKey] = append(h.modifications[nodeKey], historyModification{
					value: cloneDataValue(dv), modificationTime: time.Now().UTC(), updateType: ua.HistoryUpdateTypeInsert,
				})
			}
			ops[i] = ua.StatusOK

		default:
			ops[i] = ua.StatusBadHistoryOperationInvalid
		}
	}

	return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK, OperationResults: ops}
}

// DeleteRawModified implements RawHistoryDeleter. Modified-only deletes are unsupported.
func (h *Historian) DeleteRawModified(nodeID *ua.NodeID, isDeleteModified bool, startTime, endTime time.Time) *ua.HistoryUpdateResult {
	if isDeleteModified {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	nh, ok := h.stores[nodeID.String()]
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}

	reverse := !startTime.IsZero() && !endTime.IsZero() && startTime.After(endTime)
	lo, hi := startTime, endTime
	if reverse {
		lo, hi = endTime, startTime
	}

	kept := nh.samples[:0]
	for _, s := range nh.samples {
		ts := s.SourceTimestamp
		inRange := true
		if !lo.IsZero() && ts.Before(lo) {
			inRange = false
		}
		if !hi.IsZero() && !ts.Before(hi) && !ts.Equal(hi) {
			// inclusive end
			if ts.After(hi) {
				inRange = false
			}
		}
		if !inRange {
			kept = append(kept, s)
		}
	}
	nh.samples = kept
	return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK}
}

// DeleteAtTime implements AtTimeHistoryDeleter.
func (h *Historian) DeleteAtTime(nodeID *ua.NodeID, reqTimes []time.Time) *ua.HistoryUpdateResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	nh, ok := h.stores[nodeID.String()]
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}

	ops := make([]ua.StatusCode, len(reqTimes))
	for i, ts := range reqTimes {
		idx := findSampleIndex(nh.samples, ts)
		if idx < 0 {
			ops[i] = ua.StatusBadNoEntryExists
			continue
		}
		nh.samples = append(nh.samples[:idx], nh.samples[idx+1:]...)
		ops[i] = ua.StatusOK
	}
	return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK, OperationResults: ops}
}

// ReadAtTime implements AtTimeHistoryReader (nearest-previous / exact match).
func (h *Historian) ReadAtTime(nodeID *ua.NodeID, reqTimes []time.Time, useSimpleBounds bool) (*ua.HistoryReadResult, error) {
	_ = useSimpleBounds
	h.mu.Lock()
	defer h.mu.Unlock()

	nh, ok := h.stores[nodeID.String()]
	if !ok {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}

	out := make([]*ua.DataValue, len(reqTimes))
	for i, ts := range reqTimes {
		dv := nearestPrevious(nh.samples, ts)
		if dv == nil {
			out[i] = &ua.DataValue{
				EncodingMask:    ua.DataValueStatusCode | ua.DataValueSourceTimestamp,
				Status:          ua.StatusBadNoData,
				SourceTimestamp: ts,
			}
			continue
		}
		out[i] = cloneDataValue(dv)
	}
	return &ua.HistoryReadResult{
		StatusCode:  ua.StatusOK,
		HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: out}),
	}, nil
}

// ReadModified implements ModifiedHistoryReader.
func (h *Historian) ReadModified(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, continuationPoint []byte) (*ua.HistoryReadResult, error) {
	if len(continuationPoint) > 0 {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadContinuationPointInvalid}, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	nodeKey := nodeID.String()
	if _, ok := h.stores[nodeKey]; !ok {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}

	mods := h.modifications[nodeKey]
	var values []*ua.DataValue
	var infos []*ua.ModificationInfo
	for _, m := range mods {
		ts := m.value.SourceTimestamp
		if !startTime.IsZero() && ts.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && ts.After(endTime) {
			continue
		}
		values = append(values, cloneDataValue(m.value))
		infos = append(infos, &ua.ModificationInfo{
			ModificationTime: m.modificationTime,
			UpdateType:       m.updateType,
		})
		if numValues > 0 && uint32(len(values)) >= numValues {
			break
		}
	}
	return &ua.HistoryReadResult{
		StatusCode: ua.StatusOK,
		HistoryData: ua.NewExtensionObject(&ua.HistoryModifiedData{
			DataValues:        values,
			ModificationInfos: infos,
		}),
	}, nil
}

// ReadProcessed implements ProcessedHistoryReader for Average/Minimum/Maximum/Count.
func (h *Historian) ReadProcessed(nodeID *ua.NodeID, startTime, endTime time.Time, processingInterval float64, aggregateType *ua.NodeID, aggregateConfiguration *ua.AggregateConfiguration) (*ua.HistoryReadResult, error) {
	_ = aggregateConfiguration
	h.mu.Lock()
	defer h.mu.Unlock()

	nh, ok := h.stores[nodeID.String()]
	if !ok {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}
	if startTime.IsZero() || endTime.IsZero() || !endTime.After(startTime) {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationInvalid}, nil
	}
	if processingInterval <= 0 {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationInvalid}, nil
	}
	aggID := uint32(0)
	if aggregateType != nil {
		aggID = aggregateType.IntID()
	}
	switch aggID {
	case id.AggregateFunctionAverage, id.AggregateFunctionMinimum, id.AggregateFunctionMaximum, id.AggregateFunctionCount:
	default:
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}

	interval := time.Duration(processingInterval * float64(time.Millisecond))
	if interval <= 0 {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationInvalid}, nil
	}

	var out []*ua.DataValue
	for t0 := startTime; t0.Before(endTime); t0 = t0.Add(interval) {
		t1 := t0.Add(interval)
		if t1.After(endTime) {
			t1 = endTime
		}
		var nums []float64
		for _, s := range nh.samples {
			ts := s.SourceTimestamp
			if ts.Before(t0) || !ts.Before(t1) {
				continue
			}
			if f, ok := asFloat64(s.Value); ok {
				nums = append(nums, f)
			}
		}
		dv := &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueStatusCode,
			SourceTimestamp: t0,
			Status:          ua.StatusOK,
		}
		if len(nums) == 0 {
			dv.Status = ua.StatusBadNoData
			dv.EncodingMask &^= ua.DataValueValue
		} else {
			switch aggID {
			case id.AggregateFunctionCount:
				dv.Value = ua.MustVariant(uint32(len(nums)))
			case id.AggregateFunctionAverage:
				dv.Value = ua.MustVariant(mean(nums))
			case id.AggregateFunctionMinimum:
				dv.Value = ua.MustVariant(minFloat(nums))
			case id.AggregateFunctionMaximum:
				dv.Value = ua.MustVariant(maxFloat(nums))
			}
		}
		out = append(out, dv)
	}

	return &ua.HistoryReadResult{
		StatusCode:  ua.StatusOK,
		HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: out}),
	}, nil
}

func findSampleIndex(samples []*ua.DataValue, ts time.Time) int {
	for i, s := range samples {
		if s.SourceTimestamp.Equal(ts) {
			return i
		}
	}
	return -1
}

func insertSample(samples []*ua.DataValue, dv *ua.DataValue) []*ua.DataValue {
	samples = append(samples, dv)
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].SourceTimestamp.Before(samples[j].SourceTimestamp)
	})
	return samples
}

func trimSamples(nh *nodeHistory) {
	if len(nh.samples) > nh.maxSize {
		nh.samples = nh.samples[len(nh.samples)-nh.maxSize:]
	}
}

func cloneDataValue(dv *ua.DataValue) *ua.DataValue {
	if dv == nil {
		return nil
	}
	cp := *dv
	return &cp
}

func nearestPrevious(samples []*ua.DataValue, ts time.Time) *ua.DataValue {
	var best *ua.DataValue
	for _, s := range samples {
		if s.SourceTimestamp.After(ts) {
			continue
		}
		if best == nil || s.SourceTimestamp.After(best.SourceTimestamp) {
			best = s
		}
	}
	return best
}

func asFloat64(v *ua.Variant) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.Value().(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint32:
		return float64(n), true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}

func mean(vals []float64) float64 {
	var s float64
	for _, v := range vals {
		s += v
	}
	return s / float64(len(vals))
}

func minFloat(vals []float64) float64 {
	m := vals[0]
	for _, v := range vals[1:] {
		m = math.Min(m, v)
	}
	return m
}

func maxFloat(vals []float64) float64 {
	m := vals[0]
	for _, v := range vals[1:] {
		m = math.Max(m, v)
	}
	return m
}
