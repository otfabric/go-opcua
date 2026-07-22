// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// HistoryProvider is the server-facing HistoryRead surface. The default
// implementation is [*Historian] (in-memory, process-lifetime only).
type HistoryProvider interface {
	ReadRaw(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, returnBounds bool, continuationPoint []byte) (*ua.HistoryReadResult, error)
	ReleaseContinuation(continuationPoint []byte)
}

// Historian is the default in-memory HistoryProvider.
//
// Retention is bounded: each EnableNode call sets a per-node ring buffer
// (default 1000 samples). Storage is not durable across process restarts.
// Continuation points expire after 30s and are capped at 100 active tokens.
type Historian struct {
	mu     sync.Mutex
	stores map[string]*nodeHistory // keyed by NodeID.String()

	// continuations stores active continuation points.
	continuations map[string]*historyContinuation
}

// Compile-time check that *Historian implements HistoryProvider.
var _ HistoryProvider = (*Historian)(nil)

type nodeHistory struct {
	samples []*ua.DataValue
	maxSize int
}

type historyContinuation struct {
	nodeKey   string
	startTime time.Time
	endTime   time.Time
	nextIndex int
	numValues uint32
	bounds    bool
	created   time.Time
}

const (
	defaultHistoryMaxSamples     = 1000
	historyContinuationTTL       = 30 * time.Second
	maxHistoryContinuationPoints = 100
)

// NewHistorian creates a new in-memory historian.
func NewHistorian() *Historian {
	return &Historian{
		stores:        make(map[string]*nodeHistory),
		continuations: make(map[string]*historyContinuation),
	}
}

// EnableNode registers a node for history recording with maxSamples capacity.
func (h *Historian) EnableNode(nodeID *ua.NodeID, maxSamples int) {
	if maxSamples <= 0 {
		maxSamples = defaultHistoryMaxSamples
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stores[nodeID.String()] = &nodeHistory{
		samples: make([]*ua.DataValue, 0, maxSamples),
		maxSize: maxSamples,
	}
}

// RecordValue stores a historical sample for a node. If the node is not
// enabled for history, the call is a no-op.
func (h *Historian) RecordValue(nodeID *ua.NodeID, dv *ua.DataValue) {
	h.mu.Lock()
	defer h.mu.Unlock()
	nh, ok := h.stores[nodeID.String()]
	if !ok {
		return
	}
	if dv.SourceTimestamp.IsZero() {
		dv.SourceTimestamp = time.Now()
		dv.EncodingMask |= ua.DataValueSourceTimestamp
	}
	if dv.ServerTimestamp.IsZero() {
		dv.ServerTimestamp = time.Now()
		dv.EncodingMask |= ua.DataValueServerTimestamp
	}
	if len(nh.samples) >= nh.maxSize {
		nh.samples = nh.samples[1:]
	}
	nh.samples = append(nh.samples, dv)
}

// IsEnabled reports whether the given node is enabled for history.
func (h *Historian) IsEnabled(nodeID *ua.NodeID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.stores[nodeID.String()]
	return ok
}

// ReadRaw implements ReadRawModifiedDetails for a single node.
// It returns the matching DataValues and a continuation point if results are truncated.
func (h *Historian) ReadRaw(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, returnBounds bool, continuationPoint []byte) (*ua.HistoryReadResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	nodeKey := nodeID.String()

	// Handle continuation point.
	var cont *historyContinuation
	if len(continuationPoint) > 0 {
		cpKey := hex.EncodeToString(continuationPoint)
		cont = h.continuations[cpKey]
		if cont == nil {
			return &ua.HistoryReadResult{
				StatusCode: ua.StatusBadContinuationPointInvalid,
			}, nil
		}
		delete(h.continuations, cpKey)
		nodeKey = cont.nodeKey
		startTime = cont.startTime
		endTime = cont.endTime
		numValues = cont.numValues
		returnBounds = cont.bounds
	}

	nh, ok := h.stores[nodeKey]
	if !ok {
		return &ua.HistoryReadResult{
			StatusCode: ua.StatusBadHistoryOperationUnsupported,
		}, nil
	}

	startIdx := 0
	if cont != nil {
		startIdx = cont.nextIndex
	}

	// Determine time range direction.
	reverse := !startTime.IsZero() && !endTime.IsZero() && startTime.After(endTime)

	// Collect matching samples.
	var matches []*ua.DataValue
	for i := startIdx; i < len(nh.samples); i++ {
		sample := nh.samples[i]
		ts := sample.SourceTimestamp

		if !startTime.IsZero() && !reverse && ts.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && !reverse && !ts.Before(endTime) {
			continue
		}
		if !startTime.IsZero() && reverse && ts.After(startTime) {
			continue
		}
		if !endTime.IsZero() && reverse && !ts.After(endTime) {
			continue
		}

		matches = append(matches, sample)

		if numValues > 0 && uint32(len(matches)) >= numValues {
			// Create continuation point for remaining data.
			if i+1 < len(nh.samples) {
				cpBytes := generateContinuationPoint()
				cpKey := hex.EncodeToString(cpBytes)
				h.continuations[cpKey] = &historyContinuation{
					nodeKey:   nodeKey,
					startTime: startTime,
					endTime:   endTime,
					nextIndex: i + 1,
					numValues: numValues,
					bounds:    returnBounds,
					created:   time.Now(),
				}
				h.cleanExpiredContinuations()

				if reverse {
					sort.Slice(matches, func(a, b int) bool {
						return matches[a].SourceTimestamp.After(matches[b].SourceTimestamp)
					})
				}
				histData := &ua.HistoryData{DataValues: matches}
				return &ua.HistoryReadResult{
					StatusCode:        ua.StatusOK,
					ContinuationPoint: cpBytes,
					HistoryData:       ua.NewExtensionObject(histData),
				}, nil
			}
			break
		}
	}

	if reverse {
		sort.Slice(matches, func(a, b int) bool {
			return matches[a].SourceTimestamp.After(matches[b].SourceTimestamp)
		})
	}

	// returnBounds is accepted and persisted on continuation points, but
	// interpolated/bounding values are not yet implemented for raw reads.

	histData := &ua.HistoryData{DataValues: matches}
	return &ua.HistoryReadResult{
		StatusCode:  ua.StatusOK,
		HistoryData: ua.NewExtensionObject(histData),
	}, nil
}

// ReleaseContinuation releases a continuation point without returning data.
func (h *Historian) ReleaseContinuation(continuationPoint []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cpKey := hex.EncodeToString(continuationPoint)
	delete(h.continuations, cpKey)
}

func (h *Historian) cleanExpiredContinuations() {
	now := time.Now()
	for k, v := range h.continuations {
		if now.Sub(v.created) > historyContinuationTTL {
			delete(h.continuations, k)
		}
	}
	if len(h.continuations) > maxHistoryContinuationPoints {
		// Evict oldest.
		var oldest string
		var oldestTime time.Time
		for k, v := range h.continuations {
			if oldest == "" || v.created.Before(oldestTime) {
				oldest = k
				oldestTime = v.created
			}
		}
		if oldest != "" {
			delete(h.continuations, oldest)
		}
	}
}

func generateContinuationPoint() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

// SetHistorian attaches a HistoryProvider for HistoryRead support.
// Pass nil to disable historical access (HistoryRead returns
// BadHistoryOperationUnsupported).
func (s *Server) SetHistorian(h HistoryProvider) {
	s.historian = h
}
