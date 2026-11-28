// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// recordingDeleter is a history backend that records the raw deletes
// HistoryUpdate passes on.
type recordingDeleter struct {
	*Historian
	calls int
}

func (d *recordingDeleter) DeleteRawModified(*ua.NodeID, bool, time.Time, time.Time) *ua.HistoryUpdateResult {
	d.calls++
	return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK}
}

// TestHistoryUpdate_DeleteRawModifiedRangeChecked: HistoryUpdate refuses a
// DeleteRawModifiedDetails without a defined start or end time, or with
// startTime after endTime ("Both startTime and endTime shall be defined.
// The startTime shall be less than the endTime", Part 11 §6.9.5.1), with
// Bad_HistoryOperationInvalid in the result of that operation, raw and
// modified deletes alike, before any backend sees it. The other operations
// of the request are carried out.
func TestHistoryUpdate_DeleteRawModifiedRangeChecked(t *testing.T) {
	srv := newTestServer()
	svc := &AttributeService{srv: srv}
	backend := &recordingDeleter{Historian: NewHistorian()}
	srv.SetHistorian(backend)
	nodeID := ua.NewStringNodeID(2, "Hist.Range")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	valid := ua.DeleteRawModifiedDetails{NodeID: nodeID, StartTime: t0, EndTime: t0.Add(time.Second)}
	details := []*ua.ExtensionObject{
		ua.NewExtensionObject(&ua.DeleteRawModifiedDetails{NodeID: nodeID, StartTime: t0.Add(time.Second), EndTime: t0}),
		ua.NewExtensionObject(&ua.DeleteRawModifiedDetails{NodeID: nodeID, EndTime: t0}),
		ua.NewExtensionObject(&ua.DeleteRawModifiedDetails{NodeID: nodeID, StartTime: t0}),
		ua.NewExtensionObject(&ua.DeleteRawModifiedDetails{NodeID: nodeID, IsDeleteModified: true, StartTime: t0}),
		ua.NewExtensionObject(ua.DeleteRawModifiedDetails{NodeID: nodeID, StartTime: t0}),
		ua.NewExtensionObject(&valid),
		ua.NewExtensionObject(valid),
		ua.NewExtensionObject(&ua.DeleteRawModifiedDetails{NodeID: nodeID, StartTime: t0, EndTime: t0}),
	}
	resp, err := svc.HistoryUpdate(context.Background(), nil, &ua.HistoryUpdateRequest{
		RequestHeader: reqHeader(), HistoryUpdateDetails: details,
	}, 1)
	require.NoError(t, err)
	var got []ua.StatusCode
	for _, r := range resp.(*ua.HistoryUpdateResponse).Results {
		got = append(got, r.StatusCode)
	}
	bad := ua.StatusBadHistoryOperationInvalid
	require.Equal(t, []ua.StatusCode{bad, bad, bad, bad, bad, ua.StatusOK, ua.StatusOK, ua.StatusOK}, got)
	require.Equal(t, 3, backend.calls, "only the valid ranges reach the backend")
}

// TestCheckDeleteRawRange covers the null DateTime of each encoding: the
// zero time.Time, the epoch 1601-01-01 and anything before it.
func TestCheckDeleteRawRange(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name       string
		start, end time.Time
		want       ua.StatusCode
	}{
		{"valid", t0, t0.Add(time.Nanosecond), ua.StatusOK},
		{"equal", t0, t0, ua.StatusOK},
		{"just after the epoch", dateTimeEpoch.Add(100 * time.Nanosecond), t0, ua.StatusOK},
		{"reversed", t0.Add(time.Nanosecond), t0, ua.StatusBadHistoryOperationInvalid},
		{"zero start", time.Time{}, t0, ua.StatusBadHistoryOperationInvalid},
		{"zero end", t0, time.Time{}, ua.StatusBadHistoryOperationInvalid},
		{"epoch start", dateTimeEpoch, t0, ua.StatusBadHistoryOperationInvalid},
		{"before the epoch", dateTimeEpoch.Add(-time.Hour), t0, ua.StatusBadHistoryOperationInvalid},
	} {
		require.Equal(t, c.want, checkDeleteRawRange(c.start, c.end), c.name)
	}
}
