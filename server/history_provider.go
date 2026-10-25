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
