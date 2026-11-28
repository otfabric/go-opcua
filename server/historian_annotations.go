// SPDX-License-Identifier: MIT

package server

import (
	"sort"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

var _ AnnotationHistoryProvider = (*Historian)(nil)

// UpdateAnnotations implements [AnnotationHistoryProvider]: the Historian
// keeps the Annotations of the nodes of its EnableNode, as many as their
// samples, one per SourceTimestamp (Part 11 §6.9.3.2). Per value
// (OperationResults, Part 11 §6.9.3.3 to §6.9.3.6):
//   - Insert: Bad_EntryExists when an Annotation has the timestamp; else
//     insert, Good_EntryInserted
//   - Replace: Bad_NoEntryExists when none has it; else replace,
//     Good_EntryReplaced
//   - Update: replace (Good_EntryReplaced) or insert (Good_EntryInserted)
//   - Remove: Bad_NoEntryExists when none has it; else remove, Good
//
// A full history drops its oldest Annotation for a new one; an Annotation
// older than all of a full history cannot be stored, Bad_OutOfRange. A
// value without a SourceTimestamp, or without an Annotation but for
// Remove, is Bad_InvalidArgument. A node that is not enabled is
// Bad_HistoryOperationUnsupported; a PerformUpdateType that is none of the
// four is Bad_InvalidArgument.
func (h *Historian) UpdateAnnotations(nodeID *ua.NodeID, perform ua.PerformUpdateType, values []*ua.DataValue) *ua.HistoryUpdateResult {
	switch perform {
	case ua.PerformUpdateTypeInsert, ua.PerformUpdateTypeReplace, ua.PerformUpdateTypeUpdate, ua.PerformUpdateTypeRemove:
	default:
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadInvalidArgument}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	key := nodeID.String()
	nh, ok := h.stores[key]
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}
	ah := h.annotations[key]
	if ah == nil {
		if h.annotations == nil {
			h.annotations = make(map[string]*nodeHistory)
		}
		ah = &nodeHistory{maxSize: nh.maxSize}
		h.annotations[key] = ah
	}
	ops := make([]ua.StatusCode, len(values))
	for i, dv := range values {
		if dv == nil || dv.SourceTimestamp.IsZero() || perform != ua.PerformUpdateTypeRemove && annotationOf(dv) == nil {
			ops[i] = ua.StatusBadInvalidArgument
			continue
		}
		idx := findSampleIndex(ah.samples, dv.SourceTimestamp)
		switch {
		case perform == ua.PerformUpdateTypeRemove:
			if idx < 0 {
				ops[i] = ua.StatusBadNoEntryExists
				continue
			}
			ah.samples = append(ah.samples[:idx], ah.samples[idx+1:]...)
			ops[i] = ua.StatusOK
		case idx >= 0 && perform == ua.PerformUpdateTypeInsert:
			ops[i] = ua.StatusBadEntryExists
		case idx >= 0:
			ah.samples[idx] = annotationValue(annotationOf(dv), dv.SourceTimestamp)
			ops[i] = ua.StatusGoodEntryReplaced
		case perform == ua.PerformUpdateTypeReplace:
			ops[i] = ua.StatusBadNoEntryExists
		case len(ah.samples) >= ah.maxSize && !dv.SourceTimestamp.After(ah.samples[0].SourceTimestamp):
			ops[i] = ua.StatusBadOutOfRange
		default:
			ah.samples = insertSample(ah.samples, annotationValue(annotationOf(dv), dv.SourceTimestamp))
			trimSamples(ah)
			ops[i] = ua.StatusGoodEntryInserted
		}
	}
	return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK, OperationResults: ops}
}

// ReadAnnotations implements [AnnotationHistoryProvider]: the Annotation at
// each time, Bad_NoData for a time without one. A node that is not enabled
// is Bad_HistoryOperationUnsupported.
func (h *Historian) ReadAnnotations(nodeID *ua.NodeID, reqTimes []time.Time) (*ua.HistoryReadResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := nodeID.String()
	if _, ok := h.stores[key]; !ok {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}
	var stored []*ua.DataValue
	if ah := h.annotations[key]; ah != nil {
		stored = ah.samples
	}
	out := make([]*ua.DataValue, len(reqTimes))
	for i, ts := range reqTimes {
		if idx := findSampleIndex(stored, ts); idx >= 0 {
			out[i] = cloneDataValue(stored[idx])
			continue
		}
		out[i] = &ua.DataValue{
			EncodingMask:    ua.DataValueStatusCode | ua.DataValueSourceTimestamp,
			Status:          ua.StatusBadNoData,
			SourceTimestamp: ts,
		}
	}
	return &ua.HistoryReadResult{
		StatusCode:  ua.StatusOK,
		HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: out}),
	}, nil
}

// ReadRawAnnotations implements [AnnotationHistoryProvider]: the
// Annotations of nodeID from startTime to endTime as [Historian.ReadRaw]
// reads samples, with its continuation points.
func (h *Historian) ReadRawAnnotations(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, continuationPoint []byte) (*ua.HistoryReadResult, error) {
	return h.readRaw(nodeID, true, startTime, endTime, numValues, false, continuationPoint)
}

// annotationsOfLocked returns a copy of the Annotations of a node. Caller
// holds h.mu.
func (h *Historian) annotationsOfLocked(key string) []*ua.DataValue {
	ah := h.annotations[key]
	if ah == nil {
		return nil
	}
	return append([]*ua.DataValue(nil), ah.samples...)
}

// withExtraData returns the sample of a raw read of node key, with the
// Extra Data bit when an Annotation has its timestamp. Caller holds h.mu.
func (h *Historian) withExtraData(key string, annotations bool, sample *ua.DataValue) *ua.DataValue {
	if annotations {
		return sample
	}
	ah := h.annotations[key]
	if ah == nil {
		return sample
	}
	i := sort.Search(len(ah.samples), func(i int) bool { return !ah.samples[i].SourceTimestamp.Before(sample.SourceTimestamp) })
	if i == len(ah.samples) || !ah.samples[i].SourceTimestamp.Equal(sample.SourceTimestamp) {
		return sample
	}
	c := cloneDataValue(sample)
	c.Status |= ua.StatusCodeHistorianExtraData | ua.StatusCodeInfoTypeDataValue
	c.EncodingMask |= ua.DataValueStatusCode
	return c
}
