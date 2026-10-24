// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// histFill records n samples one second apart starting at base, with value i.
func histFill(h *Historian, nodeID *ua.NodeID, base time.Time, n int) {
	for i := 0; i < n; i++ {
		h.RecordValue(nodeID, &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
}

func histValues(t *testing.T, res *ua.HistoryReadResult) []float64 {
	t.Helper()
	require.Equal(t, ua.StatusOK, res.StatusCode)
	hd, ok := res.HistoryData.Value.(*ua.HistoryData)
	require.True(t, ok, "HistoryData is %T", res.HistoryData.Value)
	out := make([]float64, len(hd.DataValues))
	for i, dv := range hd.DataValues {
		out[i] = dv.Value.Value().(float64)
	}
	return out
}

func TestHistorianCov_DefaultCapacityAndTimestamps(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Cov.Default")
	h.EnableNode(nodeID, 0) // 0 → default capacity
	h.mu.Lock()
	require.Equal(t, defaultHistoryMaxSamples, h.stores[nodeID.String()].maxSize)
	h.mu.Unlock()

	// A sample without timestamps gets both stamped on recording.
	before := time.Now()
	dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(1.5)}
	h.RecordValue(nodeID, dv)
	require.False(t, dv.SourceTimestamp.Before(before))
	require.False(t, dv.ServerTimestamp.Before(before))
	require.NotZero(t, dv.EncodingMask&ua.DataValueSourceTimestamp)
	require.NotZero(t, dv.EncodingMask&ua.DataValueServerTimestamp)

	res, err := h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, nil)
	require.NoError(t, err)
	require.Equal(t, []float64{1.5}, histValues(t, res))
}

func TestHistorianCov_ReverseRead(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Cov.Reverse")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	histFill(h, nodeID, base, 10)

	// startTime > endTime: newest first, samples in (end, start].
	start, end := base.Add(7*time.Second), base.Add(2*time.Second)
	res, err := h.ReadRaw(nodeID, start, end, 0, false, nil)
	require.NoError(t, err)
	require.Empty(t, res.ContinuationPoint)
	require.Equal(t, []float64{7, 6, 5, 4, 3}, histValues(t, res))

	// Paged reverse read: the newest values come first and the pages continue
	// towards the oldest.
	res, err = h.ReadRaw(nodeID, start, end, 2, true, nil)
	require.NoError(t, err)
	require.Equal(t, []float64{7, 6}, histValues(t, res))
	require.NotEmpty(t, res.ContinuationPoint)
	res, err = h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, res.ContinuationPoint)
	require.NoError(t, err)
	require.Equal(t, []float64{5, 4}, histValues(t, res))
	require.NotEmpty(t, res.ContinuationPoint)
	res, err = h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, res.ContinuationPoint)
	require.NoError(t, err)
	// The older samples (2, 1, 0) are outside the range: last page.
	require.Equal(t, []float64{3}, histValues(t, res))
	require.Empty(t, res.ContinuationPoint)
}

func TestHistorianCov_ExactPageHasNoContinuation(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Cov.Exact")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	histFill(h, nodeID, base, 3)

	// The limit is reached on the last sample: no continuation point.
	res, err := h.ReadRaw(nodeID, time.Time{}, time.Time{}, 3, false, nil)
	require.NoError(t, err)
	require.Empty(t, res.ContinuationPoint)
	require.Equal(t, []float64{0, 1, 2}, histValues(t, res))
	h.mu.Lock()
	require.Empty(t, h.continuations)
	h.mu.Unlock()
}

func TestHistorianCov_ContinuationExpiryAndCap(t *testing.T) {
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Cov.Cap")
	h.EnableNode(nodeID, 100)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	histFill(h, nodeID, base, 5)

	newCP := func() []byte {
		t.Helper()
		res, err := h.ReadRaw(nodeID, time.Time{}, time.Time{}, 1, false, nil)
		require.NoError(t, err)
		require.NotEmpty(t, res.ContinuationPoint)
		return res.ContinuationPoint
	}

	// An expired continuation point is dropped the next time one is created.
	expired := newCP()
	h.mu.Lock()
	for _, c := range h.continuations {
		c.created = time.Now().Add(-2 * historyContinuationTTL)
	}
	h.mu.Unlock()
	_ = newCP()
	res, err := h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, expired)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, res.StatusCode)

	// Fill up to the cap, the first one being clearly the oldest.
	h.mu.Lock()
	for k := range h.continuations {
		delete(h.continuations, k)
	}
	h.mu.Unlock()
	oldest := newCP()
	h.mu.Lock()
	for _, c := range h.continuations {
		c.created = time.Now().Add(-time.Second)
	}
	h.mu.Unlock()
	var newest [][]byte
	for i := 0; i < maxHistoryContinuationPoints; i++ {
		newest = append(newest, newCP())
	}
	h.mu.Lock()
	require.Len(t, h.continuations, maxHistoryContinuationPoints)
	h.mu.Unlock()

	// The oldest was evicted, the newer ones still work.
	res, err = h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, oldest)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, res.StatusCode)
	res, err = h.ReadRaw(nodeID, time.Time{}, time.Time{}, 0, false, newest[len(newest)-1])
	require.NoError(t, err)
	require.Equal(t, []float64{1}, histValues(t, res))
}

func TestHistorianCov_SetHistorianNil(t *testing.T) {
	srv := newTestServer()
	svc := &AttributeService{srv: srv}
	h := NewHistorian()
	nodeID := ua.NewStringNodeID(2, "Cov.Detach")
	h.EnableNode(nodeID, 10)
	histFill(h, nodeID, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 2)

	read := func() ua.StatusCode {
		t.Helper()
		resp, err := svc.HistoryRead(context.Background(), nil, &ua.HistoryReadRequest{
			RequestHeader:      reqHeader(),
			HistoryReadDetails: ua.NewExtensionObject(&ua.ReadRawModifiedDetails{NumValuesPerNode: 10}),
			NodesToRead:        []*ua.HistoryReadValueID{{NodeID: nodeID}},
		}, 1)
		require.NoError(t, err)
		hr := resp.(*ua.HistoryReadResponse)
		require.Len(t, hr.Results, 1)
		return hr.Results[0].StatusCode
	}

	srv.SetHistorian(h)
	require.Equal(t, ua.StatusOK, read())
	srv.SetHistorian(nil)
	require.Nil(t, srv.historian)
	require.NotNil(t, srv.historyCPs, "a CP registry is kept so lookups do not crash")
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, read())
}
