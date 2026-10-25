// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"iter"
	"time"

	"github.com/otfabric/go-opcua/internal/stats"
	"github.com/otfabric/go-opcua/ua"
)

// HistoryReleaseContinuationPoints releases the continuation points of
// HistoryRead calls the client does not continue: it sends a HistoryRead
// with releaseContinuationPoints set (Part 4 §5.10.3), which frees the
// points on the server and returns no history.
//
// details are the HistoryReadDetails of the reads the points came from, a
// pointer to one of the HistoryReadDetails structures (Part 11 §6.5), e.g.
// *ua.ReadRawModifiedDetails or *ua.ReadEventDetails; nodes are the
// nodes with the continuation points to release. The result holds the
// status of each node in the order of nodes: Good when the point was
// released, Bad_ContinuationPointInvalid for a point the server does not
// know (already used, released, expired, or of another session). Without
// nodes nothing is sent.
func (c *Client) HistoryReleaseContinuationPoints(ctx context.Context, details any, nodes ...*ua.HistoryReadValueID) ([]ua.StatusCode, error) {
	if len(nodes) == 0 {
		return nil, nil
	}
	switch details.(type) {
	case *ua.ReadRawModifiedDetails, *ua.ReadEventDetails, *ua.ReadEventDetails2, *ua.ReadEventDetailsSorted,
		*ua.ReadProcessedDetails, *ua.ReadAtTimeDetails, *ua.ReadAnnotationDataDetails:
	default:
		return nil, fmt.Errorf("opcua: history release: unknown HistoryReadDetails %T", details)
	}
	stats.Client().Add("HistoryReleaseContinuationPoints", 1)
	stats.Client().Add("HistoryReadValueID", int64(len(nodes)))

	req := &ua.HistoryReadRequest{
		HistoryReadDetails:        ua.NewExtensionObject(details),
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: true,
		NodesToRead:               nodes,
	}
	resp, err := send[ua.HistoryReadResponse](ctx, c, req)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != len(nodes) {
		return nil, ua.StatusBadUnknownResponse
	}
	out := make([]ua.StatusCode, len(resp.Results))
	for i, r := range resp.Results {
		if r == nil {
			return nil, ua.StatusBadUnknownResponse
		}
		out[i] = r.StatusCode
	}
	return out, nil
}

// ReadEventHistory reads the historical events of a HistoricalEventNode
// (an object or view with the HistoryRead bit of its EventNotifier, Part 11
// §5.4.4) with Time in the range of start and end: the fields filter
// selects of the events that pass its WhereClause (Part 11 §6.5.2).
//
// The events come oldest first, or newest first when start is after end
// (a reverse read). One of start and end may be the zero time when
// maxEvents is set: only start reads forward from start, only end reads
// backwards from end. maxEvents limits the number of events; 0 reads all
// events of the range. ReadEventHistory follows continuation points until
// it has maxEvents events or the history is exhausted, and releases the
// continuation point a server still holds for a truncated read.
//
// A node with Good_NoData returns no events and no error; a Bad status of
// the node is returned as the error (a [ua.StatusCode]).
func (c *Client) ReadEventHistory(ctx context.Context, nodeID *ua.NodeID, start, end time.Time, filter *ua.EventFilter, maxEvents uint32) ([]*ua.HistoryEventFieldList, error) {
	return collectHistory(c.eventHistory(ctx, nodeID, start, end, filter, maxEvents, maxEvents))
}

// ReadEventHistoryAll returns an iterator over the historical events of a
// HistoricalEventNode with Time in the range of start and end, as
// [Client.ReadEventHistory] reads them, that follows continuation points as
// the consumer asks for more events. pageSize is the NumValuesPerNode of
// each HistoryRead: the most events one call returns (0 lets the server
// decide; it is required when start or end is the zero time).
//
// When the consumer stops early, or ctx is done, while the server holds a
// continuation point for the read, the iterator releases it. A done ctx
// ends the iteration with ctx.Err(); when it cancelled a read in flight, the
// release is sent in the background, as the server may answer it only after
// the abandoned read.
func (c *Client) ReadEventHistoryAll(ctx context.Context, nodeID *ua.NodeID, start, end time.Time, filter *ua.EventFilter, pageSize uint32) iter.Seq2[*ua.HistoryEventFieldList, error] {
	return c.eventHistory(ctx, nodeID, start, end, filter, pageSize, 0)
}

func (c *Client) eventHistory(ctx context.Context, nodeID *ua.NodeID, start, end time.Time, filter *ua.EventFilter, numValues, limit uint32) iter.Seq2[*ua.HistoryEventFieldList, error] {
	details := &ua.ReadEventDetails{
		NumValuesPerNode: numValues,
		StartTime:        start,
		EndTime:          end,
		Filter:           filter,
	}
	return historyPages(ctx, c, nodeID, details, limit,
		func(ctx context.Context, nodes []*ua.HistoryReadValueID) (*ua.HistoryReadResponse, error) {
			return c.HistoryReadEvent(ctx, nodes, details)
		},
		func(r *ua.HistoryReadResult) ([]*ua.HistoryEventFieldList, error) {
			he, err := historyBody[ua.HistoryEvent](r, "HistoryEvent")
			if he == nil {
				return nil, err
			}
			return he.Events, nil
		})
}

// dataHistory reads raw values, as ReadHistory and ReadHistoryAll do.
func (c *Client) dataHistory(ctx context.Context, nodeID *ua.NodeID, start, end time.Time, numValues, limit uint32) iter.Seq2[*ua.DataValue, error] {
	details := &ua.ReadRawModifiedDetails{
		StartTime:        start,
		EndTime:          end,
		NumValuesPerNode: numValues,
		IsReadModified:   false,
		ReturnBounds:     false,
	}
	return historyPages(ctx, c, nodeID, details, limit,
		func(ctx context.Context, nodes []*ua.HistoryReadValueID) (*ua.HistoryReadResponse, error) {
			return c.HistoryReadRawModified(ctx, nodes, details)
		},
		func(r *ua.HistoryReadResult) ([]*ua.DataValue, error) {
			hd, err := historyBody[ua.HistoryData](r, "HistoryData")
			if hd == nil {
				return nil, err
			}
			return hd.DataValues, nil
		})
}

// collectHistory gathers the items of a history iterator.
func collectHistory[T any](seq iter.Seq2[T, error]) ([]T, error) {
	var out []T
	for v, err := range seq {
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// historyBody returns the history of a HistoryReadResult as a *T; nil
// without an error when the result has none (Good_NoData).
func historyBody[T any](r *ua.HistoryReadResult, name string) (*T, error) {
	if r.HistoryData == nil || r.HistoryData.Value == nil {
		return nil, nil
	}
	v, ok := r.HistoryData.Value.(*T)
	if !ok {
		return nil, fmt.Errorf("opcua: history read: expected *%s, got %T", name, r.HistoryData.Value)
	}
	return v, nil
}

// historyPages returns an iterator over the items of a single-node
// HistoryRead that follows continuation points: read sends one HistoryRead
// of the node, items takes the items out of its result. limit stops the
// iteration after that many items (0: no limit). A continuation point the
// server still holds when the iteration stops early (the consumer stops,
// limit is reached, ctx is done, or a result cannot be decoded) is
// released.
func historyPages[T any](ctx context.Context, c *Client, nodeID *ua.NodeID, details any, limit uint32,
	read func(context.Context, []*ua.HistoryReadValueID) (*ua.HistoryReadResponse, error),
	items func(*ua.HistoryReadResult) ([]T, error),
) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		var cp []byte
		release := func() {
			if len(cp) > 0 {
				c.releaseHistoryContinuation(ctx, details, nodeID, cp)
			}
		}
		n := uint32(0)
		for first := true; first || len(cp) > 0; first = false {
			if err := ctx.Err(); err != nil {
				release()
				yield(zero, err)
				return
			}
			resp, err := read(ctx, []*ua.HistoryReadValueID{{NodeID: nodeID, ContinuationPoint: cp}})
			if err != nil {
				if ctx.Err() != nil && len(cp) > 0 {
					// The read may not have reached the server, so the
					// point is released. The server may still be working
					// on the abandoned read and answer the release after
					// it: that is not waited for.
					go c.releaseHistoryContinuation(ctx, details, nodeID, cp)
				}
				yield(zero, err)
				return
			}
			if len(resp.Results) != 1 || resp.Results[0] == nil {
				yield(zero, ua.StatusBadUnexpectedError)
				return
			}
			result := resp.Results[0]
			if result.StatusCode&ua.StatusBad != 0 {
				yield(zero, result.StatusCode)
				return
			}
			cp = result.ContinuationPoint
			page, err := items(result)
			if err != nil {
				release()
				yield(zero, err)
				return
			}
			for _, v := range page {
				if !yield(v, nil) {
					release()
					return
				}
				n++
				if limit > 0 && n >= limit {
					release()
					return
				}
			}
		}
	}
}

// releaseHistoryContinuation releases the continuation point of an
// abandoned read. It runs after the consumer has stopped, maybe with ctx
// done, so it is sent without the cancellation of ctx, bounded by the
// request timeout; its outcome has no one to go to.
func (c *Client) releaseHistoryContinuation(ctx context.Context, details any, nodeID *ua.NodeID, cp []byte) {
	rctx := context.WithoutCancel(ctx)
	if d := c.cfg.sechan.RequestTimeout; d > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(rctx, d)
		defer cancel()
	}
	_, _ = c.HistoryReleaseContinuationPoints(rctx, details, &ua.HistoryReadValueID{NodeID: nodeID, ContinuationPoint: cp})
}
