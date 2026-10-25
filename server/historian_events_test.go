// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// evBase is the Time of history event 0; event i is at evBase+i s.
var evBase = time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC)

func evAt(i int) time.Time { return evBase.Add(time.Duration(i) * time.Second) }

// hev returns the history event named name at Time t with Severity sev.
func hev(name string, t time.Time, sev uint16) *HistoricalEvent {
	return &HistoricalEvent{Fields: map[string]*ua.Variant{
		"EventId":   ua.MustVariant([]byte(name)),
		"EventType": ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType)),
		"Time":      ua.MustVariant(t),
		"Severity":  ua.MustVariant(sev),
	}}
}

// evNames returns the EventIds of events as strings.
func evNames(events []*HistoricalEvent) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = string(e.EventID())
	}
	return out
}

func names(from, to int) []string {
	var out []string
	if from <= to {
		for i := from; i <= to; i++ {
			out = append(out, fmt.Sprintf("e%d", i))
		}
	} else {
		for i := from; i >= to; i-- {
			out = append(out, fmt.Sprintf("e%d", i))
		}
	}
	return out
}

// eventHistorian returns a historian whose notifier holds events e0..e(n-1),
// event i at evAt(i) with Severity 100*(i+1).
func eventHistorian(t *testing.T, n int) (*Historian, *ua.NodeID) {
	t.Helper()
	h := NewHistorian()
	notifier := ua.NewStringNodeID(1, "Notifier")
	h.EnableEvents(notifier, 0)
	for i := n - 1; i >= 0; i-- { // out of order on purpose
		h.RecordEvent(notifier, hev(fmt.Sprintf("e%d", i), evAt(i), uint16(100*(i+1))))
	}
	return h, notifier
}

func readAll(t *testing.T, h *Historian, notifier *ua.NodeID, start, end time.Time, num uint32, match func(*HistoricalEvent) bool) ([]string, int) {
	t.Helper()
	var got []string
	var cp []byte
	pages := 0
	for {
		events, next, st := h.ReadEvents(notifier, start, end, num, match, cp)
		require.False(t, isBad(st), "status %v", st)
		got = append(got, evNames(events)...)
		pages++
		if len(next) == 0 {
			return got, pages
		}
		require.Less(t, pages, 100, "continuation never terminated")
		cp = next
	}
}

func TestHistorianEvents_Enable(t *testing.T) {
	h := NewHistorian()
	n := ua.NewStringNodeID(1, "N")
	require.False(t, h.EventsEnabled(n))
	h.EnableEvents(n, 0)
	require.True(t, h.EventsEnabled(n))
	require.Equal(t, defaultHistoryMaxEvents, h.events[n.String()].maxSize)

	// A zero Historian works too.
	var z Historian
	z.EnableEvents(n, 2)
	z.RecordEvent(n, hev("a", evAt(0), 1))
	events, _, st := z.ReadEvents(n, evAt(0), time.Time{}, 1, nil, nil)
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, []string{"a"}, evNames(events))
}

func TestHistorianEvents_Record(t *testing.T) {
	h, n := eventHistorian(t, 5)
	got, _ := readAll(t, h, n, evAt(0), evAt(100), 0, nil)
	require.Equal(t, names(0, 4), got, "stored in time order")

	// Events of the same Time keep the order they were stored in.
	h.RecordEvent(n, hev("same1", evAt(2), 1))
	h.RecordEvent(n, hev("same2", evAt(2), 1))
	got, _ = readAll(t, h, n, evAt(2), evAt(3), 0, nil)
	require.Equal(t, []string{"e2", "same1", "same2"}, got)
	got, _ = readAll(t, h, n, evAt(2), evAt(1), 0, nil)
	require.Equal(t, []string{"same2", "same1", "e2"}, got, "reverse: the latest first")

	// Ignored: nil events and notifiers without history.
	h.RecordEvent(n, nil)
	other := ua.NewStringNodeID(1, "Other")
	h.RecordEvent(other, hev("x", evAt(0), 1))
	require.False(t, h.EventsEnabled(other))
}

func TestHistorianEvents_Bounded(t *testing.T) {
	h := NewHistorian()
	n := ua.NewStringNodeID(1, "N")
	h.EnableEvents(n, 3)
	for i := range 5 {
		h.RecordEvent(n, hev(fmt.Sprintf("e%d", i), evAt(i), 1))
	}
	got, _ := readAll(t, h, n, evAt(0), evAt(100), 0, nil)
	require.Equal(t, names(2, 4), got, "the oldest events are dropped")

	// An event older than all events of a full history is not stored.
	h.RecordEvent(n, hev("old", evAt(0), 1))
	got, _ = readAll(t, h, n, evAt(0), evAt(100), 0, nil)
	require.Equal(t, names(2, 4), got)
	res := h.UpdateEvents(n, ua.PerformUpdateTypeInsert, []*HistoricalEvent{hev("old", evAt(0), 1)})
	require.Equal(t, []ua.StatusCode{ua.StatusBadOutOfRange}, res.OperationResults)

	// A newer one pushes the oldest out.
	h.RecordEvent(n, hev("e2b", evAt(2), 1))
	got, _ = readAll(t, h, n, evAt(0), evAt(100), 0, nil)
	require.Equal(t, []string{"e2b", "e3", "e4"}, got)
}

func TestHistorianEvents_Ranges(t *testing.T) {
	h, n := eventHistorian(t, 10)
	zero := time.Time{}
	tests := []struct {
		name       string
		start, end time.Time
		num        uint32
		want       []string
	}{
		{"forward start inclusive end exclusive", evAt(2), evAt(5), 0, names(2, 4)},
		{"forward between events", evAt(2).Add(time.Millisecond), evAt(5).Add(time.Millisecond), 0, names(3, 5)},
		{"reverse start inclusive end exclusive", evAt(7), evAt(3), 0, names(7, 4)},
		{"equal times: the events of that time", evAt(4), evAt(4), 0, []string{"e4"}},
		{"only start: forward", evAt(7), zero, 0, names(7, 9)},
		{"only start with a limit", evAt(2), zero, 3, names(2, 4)},
		{"only end: newest first up to end", zero, evAt(6), 3, names(6, 4)},
		{"forward limit keeps the oldest", evAt(0), evAt(100), 2, names(0, 1)},
		{"reverse limit keeps the newest", evAt(100), evAt(0).Add(-time.Second), 2, names(9, 8)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, _, st := h.ReadEvents(n, tc.start, tc.end, tc.num, nil, nil)
			require.Equal(t, ua.StatusOK, st)
			require.Equal(t, tc.want, evNames(events))
		})
	}

	t.Run("no events: Good_NoData", func(t *testing.T) {
		events, cp, st := h.ReadEvents(n, evAt(50), evAt(60), 0, nil, nil)
		require.Equal(t, ua.StatusGoodNoData, st)
		require.Empty(t, events)
		require.Empty(t, cp)
		_, _, st = h.ReadEvents(n, evAt(4).Add(time.Millisecond), evAt(4).Add(time.Millisecond), 0, nil, nil)
		require.Equal(t, ua.StatusGoodNoData, st)
	})

	t.Run("notifier without history", func(t *testing.T) {
		_, _, st := h.ReadEvents(ua.NewStringNodeID(1, "Nope"), evAt(0), evAt(1), 0, nil, nil)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, st)
	})
}

func TestHistorianEvents_Paging(t *testing.T) {
	h, n := eventHistorian(t, 10)

	t.Run("forward", func(t *testing.T) {
		got, pages := readAll(t, h, n, evAt(0), evAt(100), 4, nil)
		require.Equal(t, names(0, 9), got)
		require.Equal(t, 3, pages)
	})
	t.Run("reverse", func(t *testing.T) {
		got, pages := readAll(t, h, n, evAt(100), evAt(0).Add(-time.Second), 3, nil)
		require.Equal(t, names(9, 0), got)
		require.Equal(t, 4, pages)
	})
	t.Run("exact page: no continuation point", func(t *testing.T) {
		events, cp, st := h.ReadEvents(n, evAt(0), evAt(100), 10, nil, nil)
		require.Equal(t, ua.StatusOK, st)
		require.Len(t, events, 10)
		require.Empty(t, cp)
	})
	t.Run("the limit counts matching events", func(t *testing.T) {
		even := func(e *HistoricalEvent) bool { return e.Time().Second()%2 == 0 }
		got, pages := readAll(t, h, n, evAt(0), evAt(100), 2, even)
		require.Equal(t, []string{"e0", "e2", "e4", "e6", "e8"}, got)
		require.Equal(t, 3, pages)
		// No continuation point when no further event matches.
		events, cp, _ := h.ReadEvents(n, evAt(0), evAt(100), 5, even, nil)
		require.Len(t, events, 5)
		require.Empty(t, cp)
	})
	t.Run("continuation points are one-shot and bound to the notifier", func(t *testing.T) {
		_, cp, _ := h.ReadEvents(n, evAt(0), evAt(100), 2, nil, nil)
		require.NotEmpty(t, cp)
		_, _, st := h.ReadEvents(ua.NewStringNodeID(1, "Other"), evAt(0), evAt(100), 2, nil, cp)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, st)
		_, _, st = h.ReadEvents(n, evAt(0), evAt(100), 2, nil, cp)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, st, "consumed by the failed attempt")
		_, _, st = h.ReadEvents(n, evAt(0), evAt(100), 2, nil, []byte("garbage"))
		require.Equal(t, ua.StatusBadContinuationPointInvalid, st)
	})
	t.Run("release", func(t *testing.T) {
		_, cp, _ := h.ReadEvents(n, evAt(0), evAt(100), 2, nil, nil)
		h.ReleaseContinuation(cp)
		_, _, st := h.ReadEvents(n, evAt(0), evAt(100), 2, nil, cp)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, st)
	})
}

// Pages stay consistent while the history changes between them: an event
// before the last one returned is not returned, one after it is, and no
// event is returned twice.
func TestHistorianEvents_PagingWhileChanging(t *testing.T) {
	h, n := eventHistorian(t, 6)
	events, cp, _ := h.ReadEvents(n, evAt(0), evAt(100), 3, nil, nil)
	require.Equal(t, names(0, 2), evNames(events))

	h.RecordEvent(n, hev("early", evAt(1).Add(time.Millisecond), 1))
	h.RecordEvent(n, hev("late", evAt(4).Add(time.Millisecond), 1))
	h.DeleteEvents(n, [][]byte{[]byte("e3")})
	h.UpdateEvents(n, ua.PerformUpdateTypeReplace, []*HistoricalEvent{hev("e2", evAt(2), 7)})

	var got []string
	for len(cp) > 0 {
		events, cp, _ = h.ReadEvents(n, evAt(0), evAt(100), 3, nil, cp)
		got = append(got, evNames(events)...)
	}
	// e2 was replaced: it is stored again after the last key returned.
	require.Equal(t, []string{"e2", "e4", "late", "e5"}, got)
}

func TestHistorianEvents_ContinuationExpiry(t *testing.T) {
	h, n := eventHistorian(t, 3)
	_, cp, _ := h.ReadEvents(n, evAt(0), evAt(100), 1, nil, nil)
	h.mu.Lock()
	for _, c := range h.eventCPs {
		c.created = time.Now().Add(-2 * historyContinuationTTL)
	}
	h.cleanExpiredContinuations()
	require.Empty(t, h.eventCPs)
	h.mu.Unlock()
	_, _, st := h.ReadEvents(n, evAt(0), evAt(100), 1, nil, cp)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, st)

	for range maxHistoryContinuationPoints + 5 {
		_, _, _ = h.ReadEvents(n, evAt(0), evAt(100), 1, nil, nil)
	}
	h.mu.Lock()
	require.LessOrEqual(t, len(h.eventCPs), maxHistoryContinuationPoints)
	h.mu.Unlock()
}

func TestHistorianEvents_Update(t *testing.T) {
	h, n := eventHistorian(t, 3)
	ins := hev("new", evAt(10), 9)

	res := h.UpdateEvents(n, ua.PerformUpdateTypeInsert, []*HistoricalEvent{ins, hev("e1", evAt(1), 1), nil})
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted, ua.StatusBadEntryExists, ua.StatusBadInvalidArgument}, res.OperationResults)

	// Replace keeps the EventType and Time not given.
	repl := &HistoricalEvent{Fields: map[string]*ua.Variant{
		"EventId":  ua.MustVariant([]byte("e1")),
		"Severity": ua.MustVariant(uint16(999)),
	}}
	res = h.UpdateEvents(n, ua.PerformUpdateTypeReplace, []*HistoricalEvent{repl, hev("missing", evAt(1), 1)})
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusBadNoEntryExists}, res.OperationResults)
	events, _, _ := h.ReadEvents(n, evAt(1), evAt(1), 0, nil, nil)
	require.Len(t, events, 1)
	require.Equal(t, uint16(999), events[0].field("Severity"))
	require.True(t, evAt(1).Equal(events[0].Time()))
	require.NotNil(t, events[0].EventType())

	res = h.UpdateEvents(n, ua.PerformUpdateTypeUpdate, []*HistoricalEvent{hev("e2", evAt(20), 2), hev("upd", evAt(5), 5)})
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusGoodEntryInserted}, res.OperationResults)
	got, _ := readAll(t, h, n, evAt(0), evAt(100), 0, nil)
	require.Equal(t, []string{"e0", "e1", "upd", "new", "e2"}, got, "the replaced e2 moved to its new Time")

	res = h.UpdateEvents(n, ua.PerformUpdateTypeRemove, []*HistoricalEvent{hev("x", evAt(1), 1)})
	require.Equal(t, []ua.StatusCode{ua.StatusBadInvalidArgument}, res.OperationResults)

	res = h.UpdateEvents(ua.NewStringNodeID(1, "Nope"), ua.PerformUpdateTypeInsert, nil)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, res.StatusCode)
}

func TestHistorianEvents_Delete(t *testing.T) {
	h, n := eventHistorian(t, 4)
	h.RecordEvent(n, hev("e1", evAt(9), 1)) // a second event with EventId e1
	res := h.DeleteEvents(n, [][]byte{[]byte("e1"), []byte("nope"), nil, []byte("e3")})
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadNoData, ua.StatusBadNoData, ua.StatusOK}, res.OperationResults)
	got, _ := readAll(t, h, n, evAt(0), evAt(100), 0, nil)
	require.Equal(t, []string{"e0", "e2"}, got)

	res = h.DeleteEvents(ua.NewStringNodeID(1, "Nope"), nil)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, res.StatusCode)
}

// Recording, reading, paging, updating and deleting at the same time is
// race free and keeps the pages in time order without duplicates.
func TestHistorianEvents_Concurrent(t *testing.T) {
	h := NewHistorian()
	n := ua.NewStringNodeID(1, "N")
	h.EnableEvents(n, 200)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				name := fmt.Sprintf("w%d-%d", w, i)
				h.RecordEvent(n, hev(name, evAt(i), 1))
				if i%10 == 0 {
					h.UpdateEvents(n, ua.PerformUpdateTypeUpdate, []*HistoricalEvent{hev(name, evAt(i+1), 2)})
					h.DeleteEvents(n, [][]byte{[]byte(fmt.Sprintf("w%d-%d", w, i-5))})
				}
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				seen := map[string]bool{}
				var last time.Time
				var cp []byte
				for {
					events, next, st := h.ReadEvents(n, evAt(0), evAt(1000), 7, nil, cp)
					if isBad(st) {
						t.Errorf("read: %v", st)
						return
					}
					for _, e := range events {
						// A replaced event (Severity 2) is a new entry: it
						// may come again after the key of its old one.
						if seen[string(e.EventID())] && e.field("Severity") != uint16(2) {
							t.Errorf("event %s returned twice", e.EventID())
						}
						seen[string(e.EventID())] = true
						if e.Time().Before(last) {
							t.Errorf("event %s out of order", e.EventID())
						}
						last = e.Time()
					}
					if len(next) == 0 {
						break
					}
					cp = next
				}
			}
		}()
	}
	wg.Wait()
}
