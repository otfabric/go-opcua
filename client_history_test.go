// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// fakeHistory is a HistoryRead handler serving items 0..items-1 of every
// node in pages, as events (EventId "e<i>") or raw values (float64 i)
// depending on the details. It hands out continuation points, releases
// them, and records every request.
type fakeHistory struct {
	mu       sync.Mutex
	items    int
	page     uint32         // the most items of one page (0: NumValuesPerNode)
	open     map[string]int // continuation point → next item
	next     int
	released []string
	reqs     []*ua.HistoryReadRequest
	// override, when set, answers a read instead of the pages.
	override func(req *ua.HistoryReadRequest) ua.Response
	// hold, when set, is called (without the lock) before a continued read
	// is served; a read it returns false for is answered with
	// Bad_ContinuationPointInvalid and leaves the point open.
	hold func() bool
}

func newFakeHistory(t *testing.T, items int, page uint32) (*fakeHistory, *opcua.Client) {
	t.Helper()
	h := &fakeHistory{items: items, page: page, open: map[string]int{}}
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.HistoryReadRequestEncodingDefaultBinary: h.handle,
	})
	return h, connectCovClient(t, url, opcua.SkipNamespaceUpdate())
}

func (h *fakeHistory) handle(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
	req := r.(*ua.HistoryReadRequest)
	h.mu.Lock()
	h.reqs = append(h.reqs, req)
	override := h.override
	h.mu.Unlock()
	if override != nil && !req.ReleaseContinuationPoints {
		return override(req), nil
	}
	res := &ua.HistoryReadResponse{ResponseHeader: okHeader(req)}
	for _, n := range req.NodesToRead {
		res.Results = append(res.Results, h.serve(req, n))
	}
	return res, nil
}

func (h *fakeHistory) serve(req *ua.HistoryReadRequest, n *ua.HistoryReadValueID) *ua.HistoryReadResult {
	cp := string(n.ContinuationPoint)
	h.mu.Lock()
	hold := h.hold
	h.mu.Unlock()
	if cp != "" && !req.ReleaseContinuationPoints && hold != nil && !hold() {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadContinuationPointInvalid}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	from := 0
	if cp != "" {
		i, ok := h.open[cp]
		if !ok {
			return &ua.HistoryReadResult{StatusCode: ua.StatusBadContinuationPointInvalid}
		}
		delete(h.open, cp)
		if req.ReleaseContinuationPoints {
			h.released = append(h.released, cp)
			return &ua.HistoryReadResult{StatusCode: ua.StatusOK}
		}
		from = i
	}
	if req.ReleaseContinuationPoints {
		return &ua.HistoryReadResult{StatusCode: ua.StatusOK}
	}
	var num uint32
	events := false
	switch d := req.HistoryReadDetails.Value.(type) {
	case *ua.ReadEventDetails:
		num, events = d.NumValuesPerNode, true
	case *ua.ReadRawModifiedDetails:
		num = d.NumValuesPerNode
	}
	if h.page > 0 && (num == 0 || h.page < num) {
		num = h.page
	}
	to := h.items
	if num > 0 && from+int(num) < to {
		to = from + int(num)
	}
	res := &ua.HistoryReadResult{StatusCode: ua.StatusOK}
	if to < h.items {
		h.next++
		next := fmt.Sprintf("cp%d", h.next)
		h.open[next] = to
		res.ContinuationPoint = []byte(next)
	}
	if from >= to {
		res.StatusCode = ua.StatusGoodNoData
	}
	if events {
		he := &ua.HistoryEvent{}
		for i := from; i < to; i++ {
			he.Events = append(he.Events, &ua.HistoryEventFieldList{EventFields: []*ua.Variant{ua.MustVariant([]byte(fmt.Sprintf("e%d", i)))}})
		}
		res.HistoryData = ua.NewExtensionObject(he)
	} else {
		hd := &ua.HistoryData{}
		for i := from; i < to; i++ {
			hd.DataValues = append(hd.DataValues, valueDV(float64(i)))
		}
		res.HistoryData = ua.NewExtensionObject(hd)
	}
	return res
}

// state returns the open and released continuation points and the reads.
func (h *fakeHistory) state() (open int, released []string, reqs []*ua.HistoryReadRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.open), append([]string(nil), h.released...), append([]*ua.HistoryReadRequest(nil), h.reqs...)
}

var (
	fakeNode   = ua.NewStringNodeID(1, "history")
	fakeStart  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fakeEnd    = fakeStart.Add(time.Hour)
	fakeFilter = ua.NewEventFilter().Select("EventId").Build()
)

func eventNames(t *testing.T, evs []*ua.HistoryEventFieldList) []string {
	t.Helper()
	out := []string{}
	for _, e := range evs {
		out = append(out, string(e.EventFields[0].Value().([]byte)))
	}
	return out
}

func TestClientHistoryReleaseContinuationPoints(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, c := newFakeHistory(t, 10, 2)

	// two reads leave two points open
	var cps []*ua.HistoryReadValueID
	for range 2 {
		resp, err := c.HistoryReadEvent(ctx, []*ua.HistoryReadValueID{{NodeID: fakeNode}}, &ua.ReadEventDetails{StartTime: fakeStart, EndTime: fakeEnd, Filter: fakeFilter})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Results[0].ContinuationPoint)
		cps = append(cps, &ua.HistoryReadValueID{NodeID: fakeNode, ContinuationPoint: resp.Results[0].ContinuationPoint})
	}
	unknown := &ua.HistoryReadValueID{NodeID: fakeNode, ContinuationPoint: []byte("nope")}
	st, err := c.HistoryReleaseContinuationPoints(ctx, &ua.ReadEventDetails{}, cps[0], unknown, cps[1])
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadContinuationPointInvalid, ua.StatusOK}, st)
	open, released, reqs := h.state()
	require.Zero(t, open)
	require.Equal(t, []string{"cp1", "cp2"}, released)
	last := reqs[len(reqs)-1]
	require.True(t, last.ReleaseContinuationPoints)
	require.IsType(t, &ua.ReadEventDetails{}, last.HistoryReadDetails.Value)

	// releasing again: the points are gone
	st, err = c.HistoryReleaseContinuationPoints(ctx, &ua.ReadRawModifiedDetails{}, cps...)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadContinuationPointInvalid, ua.StatusBadContinuationPointInvalid}, st)

	// nothing to release: nothing is sent
	_, _, before := h.state()
	st, err = c.HistoryReleaseContinuationPoints(ctx, &ua.ReadEventDetails{})
	require.NoError(t, err)
	require.Nil(t, st)
	_, _, after := h.state()
	require.Len(t, after, len(before))

	// details that are no HistoryReadDetails
	_, err = c.HistoryReleaseContinuationPoints(ctx, nil, cps[0])
	require.ErrorContains(t, err, "unknown HistoryReadDetails <nil>")
	_, err = c.HistoryReleaseContinuationPoints(ctx, ua.ReadEventDetails{}, cps[0])
	require.ErrorContains(t, err, "unknown HistoryReadDetails ua.ReadEventDetails")
	for _, d := range []any{&ua.ReadEventDetails2{}, &ua.ReadEventDetailsSorted{}, &ua.ReadProcessedDetails{}, &ua.ReadAtTimeDetails{}, &ua.ReadAnnotationDataDetails{}} {
		st, err := c.HistoryReleaseContinuationPoints(ctx, d, &ua.HistoryReadValueID{NodeID: fakeNode, ContinuationPoint: []byte("gone")})
		require.NoError(t, err, "%T", d)
		require.Equal(t, []ua.StatusCode{ua.StatusBadContinuationPointInvalid}, st)
	}

	// a server answering with the wrong number of results
	for name, results := range map[string][]*ua.HistoryReadResult{
		"none": {},
		"two":  {{}, {}},
	} {
		t.Run(name, func(t *testing.T) {
			_, url := newScriptedServer(t, map[uint16]server.Handler{
				id.HistoryReadRequestEncodingDefaultBinary: respond(func(r ua.Request) ua.Response {
					return &ua.HistoryReadResponse{ResponseHeader: okHeader(r), Results: results}
				}),
			})
			c := connectCovClient(t, url, opcua.SkipNamespaceUpdate())
			_, err := c.HistoryReleaseContinuationPoints(ctx, &ua.ReadEventDetails{}, cps[0])
			require.ErrorIs(t, err, ua.StatusBadUnknownResponse)
		})
	}

	// a closed client
	require.NoError(t, c.Close(ctx))
	_, err = c.HistoryReleaseContinuationPoints(ctx, &ua.ReadEventDetails{}, cps[0])
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
}

func TestClientReadEventHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("AllPages", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 5, 2)
		evs, err := c.ReadEventHistory(ctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 0)
		require.NoError(t, err)
		require.Equal(t, []string{"e0", "e1", "e2", "e3", "e4"}, eventNames(t, evs))
		open, released, reqs := h.state()
		require.Zero(t, open)
		require.Empty(t, released)
		require.Len(t, reqs, 3)
		for _, r := range reqs {
			d := r.HistoryReadDetails.Value.(*ua.ReadEventDetails)
			require.Zero(t, d.NumValuesPerNode)
			require.True(t, d.StartTime.Equal(fakeStart))
			require.True(t, d.EndTime.Equal(fakeEnd))
			require.Len(t, d.Filter.SelectClauses, 1)
		}
	})

	t.Run("MaxAcrossPagesReleases", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 10, 2)
		evs, err := c.ReadEventHistory(ctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 3)
		require.NoError(t, err)
		require.Equal(t, []string{"e0", "e1", "e2"}, eventNames(t, evs))
		open, released, reqs := h.state()
		require.Zero(t, open, "the point of the truncated read is released")
		require.Equal(t, []string{"cp2"}, released)
		require.Len(t, reqs, 3)
		for _, r := range reqs {
			require.Equal(t, uint32(3), r.HistoryReadDetails.Value.(*ua.ReadEventDetails).NumValuesPerNode)
		}
	})

	t.Run("MaxEqualsHistory", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 4, 0)
		evs, err := c.ReadEventHistory(ctx, fakeNode, fakeStart, time.Time{}, fakeFilter, 4)
		require.NoError(t, err)
		require.Len(t, evs, 4)
		open, released, _ := h.state()
		require.Zero(t, open)
		require.Empty(t, released)
	})

	t.Run("GoodNoData", func(t *testing.T) {
		t.Parallel()
		_, c := newFakeHistory(t, 0, 0)
		evs, err := c.ReadEventHistory(ctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 0)
		require.NoError(t, err)
		require.Empty(t, evs)
	})
}

func TestClientReadEventHistoryAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("FollowsPages", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 5, 0)
		var got []*ua.HistoryEventFieldList
		for ev, err := range c.ReadEventHistoryAll(ctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 2) {
			require.NoError(t, err)
			got = append(got, ev)
		}
		require.Equal(t, []string{"e0", "e1", "e2", "e3", "e4"}, eventNames(t, got))
		_, released, reqs := h.state()
		require.Empty(t, released)
		require.Len(t, reqs, 3)
		require.Equal(t, uint32(2), reqs[0].HistoryReadDetails.Value.(*ua.ReadEventDetails).NumValuesPerNode)
	})

	for _, stopAfter := range []int{1, 2} {
		t.Run(fmt.Sprintf("EarlyStopAfter%dReleases", stopAfter), func(t *testing.T) {
			t.Parallel()
			h, c := newFakeHistory(t, 5, 0)
			var got []string
			for ev, err := range c.ReadEventHistoryAll(ctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 2) {
				require.NoError(t, err)
				got = append(got, eventNames(t, []*ua.HistoryEventFieldList{ev})...)
				if len(got) == stopAfter {
					break
				}
			}
			require.Len(t, got, stopAfter)
			open, released, _ := h.state()
			require.Zero(t, open)
			require.Equal(t, []string{"cp1"}, released)
		})
	}

	t.Run("CancelBetweenPagesReleases", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 5, 0)
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		var got int
		var last error
		for _, err := range c.ReadEventHistoryAll(cctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 2) {
			if err != nil {
				last = err
				continue
			}
			got++
			cancel()
		}
		require.ErrorIs(t, last, context.Canceled)
		require.Equal(t, 2, got, "the page read is delivered")
		open, released, _ := h.state()
		require.Zero(t, open)
		require.Equal(t, []string{"cp1"}, released)
	})

	t.Run("CancelDuringReadReleases", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 5, 0)
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		entered := make(chan struct{})
		abandoned := make(chan struct{})
		h.mu.Lock()
		h.hold = func() bool {
			// The continued read is still pending when the client gives up;
			// its answer only comes after the iteration ended, so it cannot
			// race the cancellation.
			close(entered)
			<-abandoned
			return false
		}
		h.mu.Unlock()
		go func() {
			<-entered
			cancel()
		}()
		var last error
		for _, err := range c.ReadEventHistoryAll(cctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 2) {
			if err != nil {
				last = err
			}
		}
		close(abandoned)
		require.ErrorIs(t, last, context.Canceled)
		require.Eventually(t, func() bool {
			_, released, _ := h.state()
			return len(released) == 1
		}, 10*time.Second, 10*time.Millisecond)
		open, released, _ := h.state()
		require.Zero(t, open)
		require.Equal(t, []string{"cp1"}, released)
	})

	t.Run("CancelledBeforeStart", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 5, 0)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		var last error
		for _, err := range c.ReadEventHistoryAll(cctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 2) {
			last = err
		}
		require.ErrorIs(t, last, context.Canceled)
		_, _, reqs := h.state()
		require.Empty(t, reqs)
	})
}

// The value helpers page and release like the event helpers.
func TestClientReadHistoryPaging(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	values := func(dvs []*ua.DataValue) []float64 {
		out := []float64{}
		for _, dv := range dvs {
			out = append(out, dv.Value.Value().(float64))
		}
		return out
	}

	t.Run("ReadHistoryFollowsPages", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 5, 2)
		dvs, err := c.ReadHistory(ctx, fakeNode, fakeStart, fakeEnd, 0)
		require.NoError(t, err)
		require.Equal(t, []float64{0, 1, 2, 3, 4}, values(dvs))
		dvs, err = c.ReadHistory(ctx, fakeNode, fakeStart, fakeEnd, 3)
		require.NoError(t, err)
		require.Equal(t, []float64{0, 1, 2}, values(dvs))
		open, released, _ := h.state()
		require.Zero(t, open)
		require.Len(t, released, 1)
	})

	t.Run("ReadHistoryAllEarlyStopReleases", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 5, 2)
		for _, err := range c.ReadHistoryAll(ctx, fakeNode, fakeStart, fakeEnd) {
			require.NoError(t, err)
			break
		}
		open, released, reqs := h.state()
		require.Zero(t, open)
		require.Equal(t, []string{"cp1"}, released)
		require.IsType(t, &ua.ReadRawModifiedDetails{}, reqs[len(reqs)-1].HistoryReadDetails.Value)
	})

	t.Run("GoodNoData", func(t *testing.T) {
		t.Parallel()
		_, c := newFakeHistory(t, 0, 0)
		dvs, err := c.ReadHistory(ctx, fakeNode, fakeStart, fakeEnd, 0)
		require.NoError(t, err)
		require.Empty(t, dvs)
	})
}

// Malformed and failing results end the event helpers with an error.
func TestClientReadEventHistoryMalformed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	result := func(r *ua.HistoryReadResult) func(*ua.HistoryReadRequest) ua.Response {
		return func(req *ua.HistoryReadRequest) ua.Response {
			return &ua.HistoryReadResponse{ResponseHeader: okHeader(req), Results: []*ua.HistoryReadResult{r}}
		}
	}
	for _, tc := range []struct {
		name    string
		answer  func(*ua.HistoryReadRequest) ua.Response
		wantErr error
		wantMsg string
		release bool
	}{
		{name: "NoResult", answer: func(req *ua.HistoryReadRequest) ua.Response {
			return &ua.HistoryReadResponse{ResponseHeader: okHeader(req)}
		}, wantErr: ua.StatusBadUnexpectedError},
		{name: "TwoResults", answer: func(req *ua.HistoryReadRequest) ua.Response {
			return &ua.HistoryReadResponse{ResponseHeader: okHeader(req), Results: []*ua.HistoryReadResult{{}, {}}}
		}, wantErr: ua.StatusBadUnexpectedError},
		{name: "BadNode", answer: result(&ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}), wantErr: ua.StatusBadHistoryOperationUnsupported},
		{name: "WrongKind", answer: result(&ua.HistoryReadResult{StatusCode: ua.StatusOK, ContinuationPoint: []byte("cp1"), HistoryData: historyData(1)}),
			wantMsg: "expected *HistoryEvent, got *ua.HistoryData", release: true},
		{name: "ServiceFault", answer: func(req *ua.HistoryReadRequest) ua.Response {
			hdr := okHeader(req)
			hdr.ServiceResult = ua.StatusBadHistoryOperationInvalid
			return &ua.HistoryReadResponse{ResponseHeader: hdr}
		}, wantErr: ua.StatusBadHistoryOperationInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, c := newFakeHistory(t, 5, 0)
			h.mu.Lock()
			h.override = tc.answer
			h.open["cp1"] = 0
			h.mu.Unlock()
			check := func(err error) {
				t.Helper()
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
				} else {
					require.ErrorContains(t, err, tc.wantMsg)
				}
			}
			_, err := c.ReadEventHistory(ctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 0)
			check(err)
			var last error
			for _, err := range c.ReadEventHistoryAll(ctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 0) {
				last = err
			}
			check(last)
			_, released, _ := h.state()
			if tc.release {
				require.Equal(t, []string{"cp1"}, released, "a page that cannot be decoded is abandoned")
			} else {
				require.Empty(t, released)
			}
		})
	}

	t.Run("NilHistoryIsEmpty", func(t *testing.T) {
		t.Parallel()
		h, c := newFakeHistory(t, 5, 0)
		h.mu.Lock()
		h.override = result(&ua.HistoryReadResult{StatusCode: ua.StatusGoodNoData})
		h.mu.Unlock()
		evs, err := c.ReadEventHistory(ctx, fakeNode, fakeStart, fakeEnd, fakeFilter, 0)
		require.NoError(t, err)
		require.Empty(t, evs)
		dvs, err := c.ReadHistory(ctx, fakeNode, fakeStart, fakeEnd, 0)
		require.NoError(t, err)
		require.Empty(t, dvs)
	})
}
