// SPDX-License-Identifier: MIT

package history

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// The client's event history helpers (ReadEventHistory, ReadEventHistoryAll,
// HistoryReleaseContinuationPoints) against the event history of the
// go-opcua server (Part 4 §5.10.3, Part 11 §6.5.2).

// recordingHistorian is the built-in historian that records the
// continuation points its event reads hand out and the ones the server
// releases, so that the tests see on the server side what the client
// released.
type recordingHistorian struct {
	*server.Historian

	mu       sync.Mutex
	issued   [][]byte
	released [][]byte
}

func (r *recordingHistorian) ReadEvents(notifier *ua.NodeID, startTime, endTime time.Time, numValues uint32, match func(*server.HistoricalEvent) bool, cp []byte) ([]*server.HistoricalEvent, []byte, ua.StatusCode) {
	evs, next, st := r.Historian.ReadEvents(notifier, startTime, endTime, numValues, match, cp)
	if len(next) > 0 {
		r.mu.Lock()
		r.issued = append(r.issued, append([]byte(nil), next...))
		r.mu.Unlock()
	}
	return evs, next, st
}

func (r *recordingHistorian) ReleaseContinuation(cp []byte) {
	r.mu.Lock()
	r.released = append(r.released, append([]byte(nil), cp...))
	r.mu.Unlock()
	r.Historian.ReleaseContinuation(cp)
}

// lastIssued returns the newest continuation point of the provider and
// whether the server released it.
func (r *recordingHistorian) lastIssued(t *testing.T) (cp []byte, released bool) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.NotEmpty(t, r.issued)
	cp = r.issued[len(r.issued)-1]
	for _, rel := range r.released {
		if bytes.Equal(rel, cp) {
			return cp, true
		}
	}
	return cp, false
}

func (r *recordingHistorian) releasedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.released)
}

// requireReleased checks on the server that the newest continuation point
// of the provider was released: the release reached the provider and the
// point no longer continues a read.
func (r *recordingHistorian) requireReleased(t *testing.T, notifier *ua.NodeID) {
	t.Helper()
	cp, released := r.lastIssued(t)
	require.True(t, released, "the outstanding continuation point is released")
	_, _, st := r.Historian.ReadEvents(notifier, histAt(0), histAt(100), 0, nil, cp)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, st)
}

// clientEventSetup is eventHistorySetup with a recordingHistorian. Event 9
// has a field Temperature of the namespace of the fixture.
func clientEventSetup(t *testing.T, n int) (*opcua.Client, *testutil.Fixture, *recordingHistorian, string) {
	t.Helper()
	rh := &recordingHistorian{Historian: server.NewHistorian()}
	c, f, _, url := setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		rh.EnableEvents(f.EventObject, 100)
		srv.SetHistorian(rh)
		require.NoError(t, srv.EnableEventHistory(f.EventObject, server.EventHistoryOptions{Writable: true}))
		for i := range n {
			emitHistEvent(srv, f.EventObject, i)
		}
		require.NoError(t, srv.EmitBaseEvent(f.EventObject, &server.BaseEvent{
			EventID:    []byte("t"),
			EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
			SourceNode: f.EventObject,
			Time:       histAt(50),
			Severity:   1,
			Fields:     map[string]*ua.Variant{"Temperature": ua.MustVariant(21.5)},
		}))
	})
	return c, f, rh, url
}

func fieldIDs(t *testing.T, evs []*ua.HistoryEventFieldList) []string {
	t.Helper()
	out := []string{}
	for _, e := range evs {
		out = append(out, string(e.EventFields[0].Value().([]byte)))
	}
	return out
}

func TestHistoryEvents_ClientReadEventHistory(t *testing.T) {
	c, f, rh, _ := clientEventSetup(t, 10)
	ctx := context.Background()
	node := f.EventObject

	for _, tc := range []struct {
		name       string
		start, end time.Time
		max        uint32
		want       []string
	}{
		{"Forward", histAt(0), histAt(10), 0, evs(0, 9)},
		{"Reverse", histAt(9), histAt(0).Add(-time.Second), 0, evs(9, 0)},
		{"ForwardMax", histAt(0), histAt(10), 4, evs(0, 3)},
		{"ReverseMax", histAt(9), histAt(0), 3, evs(9, 7)},
		{"OnlyStartAndMax", histAt(2), time.Time{}, 3, evs(2, 4)},
		{"OnlyEndAndMaxReverse", time.Time{}, histAt(4), 2, evs(4, 3)},
		{"MaxBeyondHistory", histAt(0), histAt(10), 50, evs(0, 9)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.ReadEventHistory(ctx, node, tc.start, tc.end, evtSelect, tc.max)
			require.NoError(t, err)
			require.Equal(t, tc.want, fieldIDs(t, got))
			// Every field the filter selects is returned.
			require.Len(t, got[0].EventFields, len(evtSelect.SelectClauses))
		})
	}

	t.Run("MaxReleasesTheRest", func(t *testing.T) {
		// NumValuesPerNode stops the read with events left: the server holds a
		// continuation point, which the helper releases.
		before := rh.releasedCount()
		got, err := c.ReadEventHistory(ctx, node, histAt(0), histAt(10), evtSelect, 5)
		require.NoError(t, err)
		require.Equal(t, evs(0, 4), fieldIDs(t, got))
		require.Equal(t, before+1, rh.releasedCount())
		rh.requireReleased(t, node)
	})

	t.Run("GoodNoDataIsEmpty", func(t *testing.T) {
		got, err := c.ReadEventHistory(ctx, node, histAt(20), histAt(30), evtSelect, 0)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("BadNodeIsTheError", func(t *testing.T) {
		_, err := c.ReadEventHistory(ctx, f.MethodObject, histAt(0), histAt(10), evtSelect, 0)
		require.ErrorIs(t, err, ua.StatusBadHistoryOperationUnsupported)
		_, err = c.ReadEventHistory(ctx, ua.NewStringNodeID(f.NSIndex, "Nope"), histAt(0), histAt(10), evtSelect, 0)
		require.ErrorIs(t, err, ua.StatusBadNodeIDUnknown)
	})

	t.Run("InvalidDetailsAreTheError", func(t *testing.T) {
		_, err := c.ReadEventHistory(ctx, node, histAt(0), time.Time{}, evtSelect, 0)
		require.ErrorIs(t, err, ua.StatusBadHistoryOperationInvalid)
		_, err = c.ReadEventHistory(ctx, node, histAt(0), histAt(10), nil, 0)
		require.ErrorIs(t, err, ua.StatusBadEventFilterInvalid)
	})

	t.Run("SelectPathsOfANamespace", func(t *testing.T) {
		filter := ua.NewEventFilter().Select("EventId").SelectPaths(fmt.Sprintf("%d:Temperature", f.NSIndex)).Build()
		require.Equal(t, f.NSIndex, filter.SelectClauses[1].BrowsePath[0].NamespaceIndex)
		require.Equal(t, "Temperature", filter.SelectClauses[1].BrowsePath[0].Name)
		got, err := c.ReadEventHistory(ctx, node, histAt(50), histAt(50), filter, 0)
		require.NoError(t, err)
		require.Equal(t, []string{"t"}, fieldIDs(t, got))
		require.Equal(t, 21.5, got[0].EventFields[1].Value())
	})
}

func TestHistoryEvents_ClientReadEventHistoryAll(t *testing.T) {
	c, f, rh, _ := clientEventSetup(t, 10)
	ctx := context.Background()
	node := f.EventObject

	collect := func(t *testing.T, start, end time.Time, page uint32) []string {
		t.Helper()
		var got []*ua.HistoryEventFieldList
		for ev, err := range c.ReadEventHistoryAll(ctx, node, start, end, evtSelect, page) {
			require.NoError(t, err)
			got = append(got, ev)
		}
		return fieldIDs(t, got)
	}

	t.Run("FollowsContinuationPoints", func(t *testing.T) {
		require.Equal(t, evs(0, 9), collect(t, histAt(0), histAt(10), 3))
		require.Equal(t, evs(0, 9), collect(t, histAt(0), histAt(10), 0))
	})

	t.Run("ReversePages", func(t *testing.T) {
		require.Equal(t, evs(9, 0), collect(t, histAt(9), histAt(0).Add(-time.Second), 4))
		require.Equal(t, evs(9, 0), collect(t, time.Time{}, histAt(9), 3))
	})

	t.Run("GoodNoData", func(t *testing.T) {
		require.Empty(t, collect(t, histAt(20), histAt(30), 3))
	})

	t.Run("BadNode", func(t *testing.T) {
		var last error
		for _, err := range c.ReadEventHistoryAll(ctx, f.MethodObject, histAt(0), histAt(10), evtSelect, 3) {
			last = err
		}
		require.ErrorIs(t, last, ua.StatusBadHistoryOperationUnsupported)
	})

	for _, stop := range []int{1, 3, 5} {
		t.Run(fmt.Sprintf("EarlyStopAfter%dReleases", stop), func(t *testing.T) {
			before := rh.releasedCount()
			var got []*ua.HistoryEventFieldList
			for ev, err := range c.ReadEventHistoryAll(ctx, node, histAt(0), histAt(10), evtSelect, 3) {
				require.NoError(t, err)
				got = append(got, ev)
				if len(got) == stop {
					break
				}
			}
			require.Equal(t, evs(0, stop-1), fieldIDs(t, got))
			require.Equal(t, before+1, rh.releasedCount())
			rh.requireReleased(t, node)
		})
	}

	t.Run("ReverseEarlyStopReleases", func(t *testing.T) {
		for ev, err := range c.ReadEventHistoryAll(ctx, node, histAt(9), histAt(0), evtSelect, 2) {
			require.NoError(t, err)
			require.Equal(t, "e9", string(ev.EventFields[0].Value().([]byte)))
			break
		}
		rh.requireReleased(t, node)
	})

	t.Run("CancelReleases", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		var got []string
		var last error
		for ev, err := range c.ReadEventHistoryAll(cctx, node, histAt(0), histAt(10), evtSelect, 4) {
			if err != nil {
				last = err
				continue
			}
			got = append(got, fieldIDs(t, []*ua.HistoryEventFieldList{ev})...)
			cancel()
		}
		require.ErrorIs(t, last, context.Canceled)
		require.Equal(t, evs(0, 3), got, "the page in hand is delivered")
		rh.requireReleased(t, node)
		// The session is still usable.
		require.Equal(t, evs(0, 9), collect(t, histAt(0), histAt(10), 4))
	})

	t.Run("ExhaustedReadReleasesNothing", func(t *testing.T) {
		before := rh.releasedCount()
		require.Equal(t, evs(0, 9), collect(t, histAt(0), histAt(10), 5))
		require.Equal(t, before, rh.releasedCount())
	})
}

func TestHistoryEvents_ClientReleaseContinuationPoints(t *testing.T) {
	c, f, rh, url := clientEventSetup(t, 10)
	ctx := context.Background()
	node := f.EventObject
	d := &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(10), NumValuesPerNode: 4, Filter: evtSelect}

	first := readEvents(t, c, node, d, nil).ContinuationPoint
	second := readEvents(t, c, node, d, nil).ContinuationPoint
	require.NotEmpty(t, first)
	require.NotEmpty(t, second)

	// Another session cannot release them.
	other := newClient(t, url)
	st, err := other.HistoryReleaseContinuationPoints(ctx, d, &ua.HistoryReadValueID{NodeID: node, ContinuationPoint: first})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadContinuationPointInvalid}, st)

	before := rh.releasedCount()
	st, err = c.HistoryReleaseContinuationPoints(ctx, d,
		&ua.HistoryReadValueID{NodeID: node, ContinuationPoint: first},
		&ua.HistoryReadValueID{NodeID: node, ContinuationPoint: []byte("unknown")},
		&ua.HistoryReadValueID{NodeID: node, ContinuationPoint: second},
	)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadContinuationPointInvalid, ua.StatusOK}, st)
	require.Equal(t, before+2, rh.releasedCount(), "both reach the provider")

	// Released points continue no read and cannot be released again.
	require.Equal(t, ua.StatusBadContinuationPointInvalid, readEvents(t, c, node, d, first).StatusCode)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, readEvents(t, c, node, d, second).StatusCode)
	st, err = c.HistoryReleaseContinuationPoints(ctx, d, &ua.HistoryReadValueID{NodeID: node, ContinuationPoint: first})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadContinuationPointInvalid}, st)
}

// The value helpers follow and release continuation points as the event
// helpers do.
func TestHistory_ClientValueHelpersRelease(t *testing.T) {
	p := &pagingProvider{total: 11, page: 4}
	c, f, _, _ := setupWith(t, func(srv *server.Server, _ *testutil.Fixture) { srv.SetHistorian(p) })
	ctx := context.Background()
	released := func() int {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.released)
	}

	t.Run("ReadHistoryFollowsPages", func(t *testing.T) {
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(0), histAt(100), 0)
		require.NoError(t, err)
		require.Equal(t, seq(0, 10), floats(dvs))
		require.Zero(t, released())
	})

	t.Run("ReadHistoryMaxReleases", func(t *testing.T) {
		dvs, err := c.ReadHistory(ctx, f.HistoryVar, histAt(0), histAt(100), 6)
		require.NoError(t, err)
		require.Equal(t, seq(0, 5), floats(dvs))
		require.Equal(t, 1, released())
	})

	t.Run("ReadHistoryAllEarlyStopReleases", func(t *testing.T) {
		for _, err := range c.ReadHistoryAll(ctx, f.HistoryVar, histAt(0), histAt(100)) {
			require.NoError(t, err)
			break
		}
		require.Equal(t, 2, released())
		p.mu.Lock()
		last := p.released[len(p.released)-1]
		p.mu.Unlock()
		require.Equal(t, []byte{4, 0, 0, 0}, last, "the point after the first page")
	})
}
