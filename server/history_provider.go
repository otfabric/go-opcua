// SPDX-License-Identifier: MIT

package server

import (
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// HistoryProvider is the baseline server-facing HistoryRead surface (raw).
// Optional capabilities are discovered via type assertion on the same value.
type HistoryProvider interface {
	ReadRaw(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, returnBounds bool, continuationPoint []byte) (*ua.HistoryReadResult, error)
	ReleaseContinuation(continuationPoint []byte)
}

// HistoryDataUpdater optionally supports HistoryUpdate UpdateDataDetails.
type HistoryDataUpdater interface {
	UpdateData(nodeID *ua.NodeID, perform ua.PerformUpdateType, values []*ua.DataValue) *ua.HistoryUpdateResult
}

// RawHistoryDeleter optionally supports DeleteRawModifiedDetails (raw deletes).
// HistoryUpdate calls it only with a range Part 11 §6.9.5.1 allows, both
// times defined and startTime not after endTime; it answers any other
// range with Bad_HistoryOperationInvalid without calling the deleter.
type RawHistoryDeleter interface {
	DeleteRawModified(nodeID *ua.NodeID, isDeleteModified bool, startTime, endTime time.Time) *ua.HistoryUpdateResult
}

// AtTimeHistoryDeleter optionally supports DeleteAtTimeDetails.
type AtTimeHistoryDeleter interface {
	DeleteAtTime(nodeID *ua.NodeID, reqTimes []time.Time) *ua.HistoryUpdateResult
}

// AtTimeHistoryReader optionally supports ReadAtTimeDetails.
//
// Interpolation rule for the default [*Historian]: for each requested time,
// return the nearest previous sample (or exact match). If none exists, return
// a DataValue with StatusCode BadNoData.
type AtTimeHistoryReader interface {
	ReadAtTime(nodeID *ua.NodeID, reqTimes []time.Time, useSimpleBounds bool) (*ua.HistoryReadResult, error)
}

// ModifiedHistoryReader optionally supports ReadRawModifiedDetails with
// IsReadModified=true.
type ModifiedHistoryReader interface {
	ReadModified(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, continuationPoint []byte) (*ua.HistoryReadResult, error)
}

// ProcessedHistoryReader optionally supports ReadProcessedDetails.
// Aggregates are provider-owned; the server type-asserts this interface
// rather than pulling all raw samples generically for every backend.
type ProcessedHistoryReader interface {
	ReadProcessed(nodeID *ua.NodeID, startTime, endTime time.Time, processingInterval float64, aggregateType *ua.NodeID, aggregateConfiguration *ua.AggregateConfiguration) (*ua.HistoryReadResult, error)
}

// EventHistoryProvider optionally keeps the event history of notifiers
// (HistoricalEventNodes, Part 11 §5.4) and serves HistoryRead
// ReadEventDetails (Part 11 §6.5.2). The server hands it every event
// reported on a notifier whose EventNotifier attribute has the HistoryRead
// bit (Part 3 §5.4, Part 11 §5.4.4), and releases its continuation points
// through [HistoryProvider.ReleaseContinuation].
type EventHistoryProvider interface {
	// RecordEvent stores an event reported on notifier. A notifier the
	// provider keeps no history for ignores it. The provider owns ev
	// afterwards; the server does not change it.
	RecordEvent(notifier *ua.NodeID, ev *HistoricalEvent)

	// ReadEvents returns the events of notifier whose Time lies in the
	// range of startTime and endTime (Part 11 §6.5.2.2: oldest first, or
	// newest first when startTime is after endTime or only endTime is
	// given) and that match, at most numValues of them (0: no limit), and a
	// continuation point when more events match. A continued read passes
	// the continuation point and the same arguments. The status is Good,
	// Good_NoData without events, Bad_HistoryOperationUnsupported for a
	// notifier without event history and Bad_ContinuationPointInvalid for
	// an unknown continuation point. match is called without locks of the
	// provider held.
	ReadEvents(notifier *ua.NodeID, startTime, endTime time.Time, numValues uint32, match func(*HistoricalEvent) bool, continuationPoint []byte) ([]*HistoricalEvent, []byte, ua.StatusCode)
}

// EventHistoryUpdater optionally supports HistoryUpdate UpdateEventDetails
// (Part 11 §6.9.4). The server validates the details and builds the events:
// each has an EventId, and those to insert have an EventType and a Time.
//
// Semantics, per event (OperationResults):
//   - Insert: Bad_EntryExists when an event with the EventId exists; else
//     insert, Good_EntryInserted
//   - Replace: Bad_NoEntryExists when no event has the EventId; else
//     replace the event, Good_EntryReplaced
//   - Update: replace when an event has the EventId (Good_EntryReplaced),
//     else insert (Good_EntryInserted)
type EventHistoryUpdater interface {
	UpdateEvents(notifier *ua.NodeID, perform ua.PerformUpdateType, events []*HistoricalEvent) *ua.HistoryUpdateResult
}

// EventHistoryDeleter optionally supports HistoryUpdate DeleteEventDetails
// (Part 11 §6.9.7): it deletes the events with the EventIds, with one
// OperationResult per EventId (Bad_NoData when no event has it).
type EventHistoryDeleter interface {
	DeleteEvents(notifier *ua.NodeID, eventIDs [][]byte) *ua.HistoryUpdateResult
}

// AnnotationHistoryProvider optionally keeps the Annotations of
// HistoricalDataNodes (Part 11 §5.1.2; the Annotation DataType, §6.6.6).
// The server calls it with the NodeId of the node that has the
// Annotations Property ([Server.EnableAnnotations]), also when the client
// names the Property. An Annotation is a DataValue whose Value is a
// *ua.Annotation in an ExtensionObject and whose SourceTimestamp is the time
// of the value it annotates; the provider decides what makes an Annotation
// unique (§6.9.3.2), the default [*Historian] the timestamp.
//
// The server answers ReadRawModifiedDetails with IsReadModified on the
// Annotations Property with Bad_HistoryOperationUnsupported. The provider's
// continuation points are released through
// [HistoryProvider.ReleaseContinuation].
type AnnotationHistoryProvider interface {
	// UpdateAnnotations serves HistoryUpdate UpdateStructureDataDetails
	// (Part 11 §6.9.3) with one OperationResult per value: Insert is
	// Bad_EntryExists when the Annotation exists, Replace and Remove
	// Bad_NoEntryExists when it does not, Update replaces or inserts
	// (Good_EntryReplaced, Good_EntryInserted), and a time the history
	// cannot store is Bad_OutOfRange. The server has checked perform and
	// each value: every value has a SourceTimestamp, and an Annotation but
	// for Remove.
	UpdateAnnotations(nodeID *ua.NodeID, perform ua.PerformUpdateType, values []*ua.DataValue) *ua.HistoryUpdateResult

	// ReadAnnotations serves HistoryRead ReadAnnotationDataDetails (Part 11
	// §6.5.6): a HistoryData with the Annotation at each of reqTimes, in
	// their order, and a DataValue with a Bad StatusCode (Bad_NoData) for a
	// time without one.
	ReadAnnotations(nodeID *ua.NodeID, reqTimes []time.Time) (*ua.HistoryReadResult, error)

	// ReadRawAnnotations serves HistoryRead ReadRawModifiedDetails of the
	// Annotations Property (Part 11 §5.1.2): the Annotations from startTime
	// to endTime as [HistoryProvider.ReadRaw] reads values, at most
	// numValues of them (0: no limit) with a continuation point when more
	// match. The server also reads them for the AnnotationCount Aggregate
	// (Part 13 §5.4.3.20) of a provider that is no ProcessedHistoryReader.
	ReadRawAnnotations(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, continuationPoint []byte) (*ua.HistoryReadResult, error)
}
