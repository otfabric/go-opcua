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
