// SPDX-License-Identifier: MIT

package server

import (
	"slices"
	"sort"
	"time"

	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
)

// Compile-time checks for optional history interfaces on *Historian.
var (
	_ HistoryDataUpdater      = (*Historian)(nil)
	_ RawHistoryDeleter       = (*Historian)(nil)
	_ AtTimeHistoryDeleter    = (*Historian)(nil)
	_ AtTimeHistoryReader     = (*Historian)(nil)
	_ ModifiedHistoryReader   = (*Historian)(nil)
	_ ProcessedHistoryReader  = (*Historian)(nil)
	_ AggregateFunctionLister = (*Historian)(nil)
	_ AggregateConfigProvider = (*Historian)(nil)
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

// DeleteRawModified implements RawHistoryDeleter. Modified-only deletes are
// unsupported.
//
// The range is that of DeleteRawModifiedDetails (Part 11 §6.9.5.1): "Both
// startTime and endTime shall be defined. The startTime shall be less than
// the endTime, and values up to but not including the endTime are
// deleted. It is permissible for startTime = endTime, in which case the
// value at the startTime is deleted." A range without a defined start or
// end time, or that ends before it starts, deletes nothing and is
// Bad_HistoryOperationInvalid (see [checkDeleteRawRange]). A range without
// a sample is Bad_NoData (§6.9.5.2). The end time is excluded as by a raw
// read (ReadRaw), so a delete removes the samples a read of the same range
// returns.
func (h *Historian) DeleteRawModified(nodeID *ua.NodeID, isDeleteModified bool, startTime, endTime time.Time) *ua.HistoryUpdateResult {
	if st := checkDeleteRawRange(startTime, endTime); st != ua.StatusOK {
		return &ua.HistoryUpdateResult{StatusCode: st}
	}
	if isDeleteModified {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	nh, ok := h.stores[nodeID.String()]
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}

	kept := nh.samples[:0]
	deleted := 0
	for _, s := range nh.samples {
		if inRawDeleteRange(startTime, endTime, s.SourceTimestamp) {
			deleted++
			continue
		}
		kept = append(kept, s)
	}
	nh.samples = kept
	if deleted == 0 {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadNoData}
	}
	return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK}
}

// dateTimeEpoch is the earliest DateTime of OPC UA. A value at or before it
// is not a defined time: the binary encoding writes it as 0, which the
// decoder (ua.Buffer.ReadTime) returns as the zero time.Time, "the earliest
// time that can be represented on the platform", and such a time is an
// invalid value that "should be treated that way by applications" (Part 6
// §5.2.2.5). The JSON and XML decoders return the zero time.Time for
// 1601-01-01T00:00:00Z as well.
var dateTimeEpoch = time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC)

// checkDeleteRawRange checks the range of DeleteRawModifiedDetails, raw and
// modified deletes alike, before anything is deleted: "Both startTime and
// endTime shall be defined. The startTime shall be less than the endTime"
// (Part 11 §6.9.5.1), with startTime = endTime permitted. Part 11 names no
// StatusCode for a range that breaks this. Bad_HistoryOperationInvalid,
// "The history details parameter is not valid" (Part 4 §7.38.2, Table 179),
// is one of the operation level results of HistoryUpdate (Part 4 §5.11.5.4,
// Table 58); using it for the range is the choice of this implementation.
// Reads keep their open and reverse ranges (§6.5.3).
func checkDeleteRawRange(start, end time.Time) ua.StatusCode {
	if !start.After(dateTimeEpoch) || !end.After(dateTimeEpoch) || start.After(end) {
		return ua.StatusBadHistoryOperationInvalid
	}
	return ua.StatusOK
}

// inRawDeleteRange reports whether a sample at ts is in the range of a raw
// delete from start to end, a range [checkDeleteRawRange] accepts:
// [start, end), or the value at start when they are equal.
func inRawDeleteRange(start, end, ts time.Time) bool {
	if start.Equal(end) {
		return ts.Equal(start)
	}
	return !ts.Before(start) && ts.Before(end)
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

// ReadProcessed implements ProcessedHistoryReader: it calculates every
// Aggregate of [aggregate.Functions] over the samples of nodeID (Part 11
// §6.5.4, Part 13 §5.4), AnnotationCount over its Annotations, with the configuration of [Historian.AggregateConfig]
// overridden by aggregateConfiguration. A node without history is
// Bad_HistoryOperationUnsupported; the other results are those of
// [aggregate.Request.Check] and [aggregate.Request.Calculate].
func (h *Historian) ReadProcessed(nodeID *ua.NodeID, startTime, endTime time.Time, processingInterval float64, aggregateType *ua.NodeID, aggregateConfiguration *ua.AggregateConfiguration) (*ua.HistoryReadResult, error) {
	h.mu.Lock()
	nh, ok := h.stores[nodeID.String()]
	if !ok {
		h.mu.Unlock()
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}
	cfg := h.aggregateConfigLocked(nodeID)
	samples := slices.Clone(nh.samples)
	var annotations []*ua.DataValue
	if isAnnotationCount(aggregateType) {
		annotations = h.annotationsOfLocked(nodeID.String())
	}
	h.mu.Unlock()

	r, st := processedRequest(startTime, endTime, processingInterval, aggregateType, cfg.Override(aggregateConfiguration))
	if st != ua.StatusOK {
		return &ua.HistoryReadResult{StatusCode: st}, nil
	}
	return processedResult(r, samples, annotations), nil
}

// AggregateFunctions implements [AggregateFunctionLister]: the Historian
// calculates every Aggregate of [aggregate.Functions].
func (h *Historian) AggregateFunctions() []*ua.NodeID { return aggregate.Functions() }

// SetAggregateConfig sets the configuration the Aggregates of nodeID are
// calculated with: its AggregateConfiguration (Part 13 §4.2.1.2) and its
// Stepped Property (Part 11 §5.2.2). Without it a node uses
// [aggregate.DefaultConfig].
func (h *Historian) SetAggregateConfig(nodeID *ua.NodeID, cfg aggregate.Config) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.aggConfig == nil {
		h.aggConfig = make(map[string]aggregate.Config)
	}
	h.aggConfig[nodeID.String()] = cfg
}

// AggregateConfig implements [AggregateConfigProvider]: the configuration
// of [Historian.SetAggregateConfig], or [aggregate.DefaultConfig].
func (h *Historian) AggregateConfig(nodeID *ua.NodeID) aggregate.Config {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.aggregateConfigLocked(nodeID)
}

func (h *Historian) aggregateConfigLocked(nodeID *ua.NodeID) aggregate.Config {
	if cfg, ok := h.aggConfig[nodeID.String()]; ok {
		return cfg
	}
	return aggregate.DefaultConfig()
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
