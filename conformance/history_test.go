// SPDX-License-Identifier: MIT

package conformance

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// The in-process server does not maintain a historical store; it must reply
// with BadHistoryOperationUnsupported per node rather than failing the whole
// service or panicking. These tests lock in that contract end to end.

func TestHistory_ReadRawModified(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := c.HistoryReadRawModified(ctx,
		[]*ua.HistoryReadValueID{{NodeID: f.Int32}},
		&ua.ReadRawModifiedDetails{
			StartTime: time.Now().Add(-time.Hour),
			EndTime:   time.Now(),
		},
	)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
}

func TestHistory_ReadHistory(t *testing.T) {
	c, f, ctx := setup(t)

	_, err := c.ReadHistory(ctx, f.Int32, time.Now().Add(-time.Hour), time.Now(), 0)
	require.Error(t, err)
	sc, ok := err.(ua.StatusCode)
	require.True(t, ok, "expected a StatusCode error, got %T", err)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, sc)
}

func TestHistory_ReadHistoryAll(t *testing.T) {
	c, f, ctx := setup(t)

	var sawErr error
	var count int
	for _, err := range c.ReadHistoryAll(ctx, f.Int32, time.Now().Add(-time.Hour), time.Now()) {
		if err != nil {
			sawErr = err
			break
		}
		count++
	}
	require.Error(t, sawErr)
	require.Equal(t, 0, count)
}

func TestHistory_Update(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := c.HistoryUpdateData(ctx, &ua.UpdateDataDetails{
		NodeID:               f.Int32,
		PerformInsertReplace: ua.PerformUpdateTypeInsert,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
}

// TestHistory_ReadVariants exercises the remaining HistoryRead detail types.
// Beyond confirming the unsupported contract, this ensures each detail
// ExtensionObject encodes on the client and decodes on the server.
func TestHistory_ReadVariants(t *testing.T) {
	c, f, ctx := setup(t)
	nodes := []*ua.HistoryReadValueID{{NodeID: f.Int32}}
	start := time.Now().Add(-time.Hour)
	end := time.Now()

	t.Run("Event", func(t *testing.T) {
		resp, err := c.HistoryReadEvent(ctx, nodes, &ua.ReadEventDetails{
			StartTime: start,
			EndTime:   end,
			Filter:    ua.NewEventFilter().Select("Message").Build(),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})

	t.Run("Processed", func(t *testing.T) {
		resp, err := c.HistoryReadProcessed(ctx, nodes, &ua.ReadProcessedDetails{
			StartTime:              start,
			EndTime:                end,
			ProcessingInterval:     1000,
			AggregateType:          []*ua.NodeID{ua.NewNumericNodeID(0, 0)},
			AggregateConfiguration: &ua.AggregateConfiguration{},
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})

	t.Run("AtTime", func(t *testing.T) {
		resp, err := c.HistoryReadAtTime(ctx, nodes, &ua.ReadAtTimeDetails{
			ReqTimes: []time.Time{start, end},
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})
}

// TestHistory_UpdateVariants exercises the remaining HistoryUpdate detail types.
func TestHistory_UpdateVariants(t *testing.T) {
	c, f, ctx := setup(t)

	t.Run("UpdateEvents", func(t *testing.T) {
		resp, err := c.HistoryUpdateEvents(ctx, &ua.UpdateEventDetails{
			NodeID:               f.Int32,
			PerformInsertReplace: ua.PerformUpdateTypeInsert,
			Filter:               ua.NewEventFilter().Select("Message").Build(),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})

	t.Run("DeleteRawModified", func(t *testing.T) {
		resp, err := c.HistoryDeleteRawModified(ctx, &ua.DeleteRawModifiedDetails{
			NodeID:    f.Int32,
			StartTime: time.Now().Add(-time.Hour),
			EndTime:   time.Now(),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})

	t.Run("DeleteAtTime", func(t *testing.T) {
		resp, err := c.HistoryDeleteAtTime(ctx, &ua.DeleteAtTimeDetails{
			NodeID:   f.Int32,
			ReqTimes: []time.Time{time.Now()},
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})

	t.Run("DeleteEvents", func(t *testing.T) {
		resp, err := c.HistoryDeleteEvents(ctx, &ua.DeleteEventDetails{
			NodeID:   f.Int32,
			EventIDs: [][]byte{{0x01, 0x02}},
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	})
}
