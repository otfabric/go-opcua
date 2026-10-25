// SPDX-License-Identifier: MIT

package chaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// histEventBase is the Time of the first event of TestChaosEventHistory.
var histEventBase = time.Date(2026, 5, 6, 7, 0, 0, 0, time.UTC)

// TestChaosEventHistory pages through the event history of a notifier with
// continuation points while the server reports events on it, clients delete
// events, abandon their reads, release their continuation points or close
// their sessions in the middle of a read, and the proxy drops the
// connections. Every page is in time order and continues the previous one
// without repeating an event; afterwards a fresh client reads a consistent
// history.
func TestChaosEventHistory(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	srv := e.server()
	nsp := e.namespace()

	notifier := server.NewFolderNode(ua.NewStringNodeID(nsp.ID(), "HistEvents"), "HistEvents")
	nsp.AddNode(notifier)
	nsp.Objects().AddRef(notifier, server.RefTypeIDOrganizes, true)
	const capacity = 400
	h := server.NewHistorian()
	h.EnableEvents(notifier.ID(), capacity)
	srv.SetHistorian(h)
	if err := srv.EnableEventHistory(notifier.ID(), server.EventHistoryOptions{Writable: true}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(chaosDuration(t))
	var sink errSink
	var wg sync.WaitGroup
	var emitted, pages, abandoned atomic.Int64

	// The server reports events.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed))
		for n := 0; time.Now().Before(deadline); n++ {
			_ = srv.EmitBaseEvent(notifier.ID(), &server.BaseEvent{
				EventID:   []byte(fmt.Sprintf("ev-%d", n)),
				EventType: ua.NewNumericNodeID(0, id.BaseEventType),
				Time:      histEventBase.Add(time.Duration(n) * time.Millisecond),
				Severity:  uint16(1 + rng.Intn(1000)),
			})
			emitted.Add(1)
			if n%8 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// The proxy drops the connections now and then.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed + 99))
		for time.Now().Before(deadline) {
			time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
			e.proxy.DropAll()
		}
	}()

	const workers = 6
	for g := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g) + 1))
			for n := 0; time.Now().Before(deadline); n++ {
				err := wd.do("event history worker", func() error {
					return eventHistoryRound(e, rng, notifier.ID(), &pages, &abandoned)
				})
				if err != nil {
					sink.addf("worker %d round %d: %v", g, n, err)
					return
				}
			}
		}()
	}
	wd.wait("event history", &wg)
	sink.report(t)
	t.Logf("events emitted %d, pages read %d, reads abandoned %d", emitted.Load(), pages.Load(), abandoned.Load())
	if t.Failed() {
		return
	}

	// Quiet: a fresh client reads the whole history in order, at most the
	// capacity.
	c := e.connect(nil, opcua.AutoReconnect(false))
	ctx, cancel := opCtx()
	defer cancel()
	ids, err := readEventHistory(ctx, c, notifier.ID(), 50, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 || len(ids) > capacity {
		t.Fatalf("history of %d events, capacity %d", len(ids), capacity)
	}
}

// histEventFilter selects the EventId and the Time.
var histEventFilter = ua.NewEventFilter().Select("EventId", "Time").Build()

// errAbandon ends a read in the middle.
var errAbandon = errors.New("abandoned")

// readEventHistory pages through the whole event history of notifier,
// numValues events per page, and checks that the pages continue each other
// in time order without repeating an event. stop, if set, may end the read
// after a page (with errAbandon), given the continuation point.
func readEventHistory(ctx context.Context, c *opcua.Client, notifier *ua.NodeID, numValues uint32, pages *atomic.Int64, stop func(cp []byte) bool) ([]string, error) {
	d := &ua.ReadEventDetails{StartTime: histEventBase, EndTime: histEventBase.Add(24 * time.Hour), NumValuesPerNode: numValues, Filter: histEventFilter}
	var ids []string
	var lastTime time.Time
	seen := map[string]bool{}
	var cp []byte
	for {
		resp, err := c.HistoryReadEvent(ctx, []*ua.HistoryReadValueID{{NodeID: notifier, ContinuationPoint: cp}}, d)
		if err != nil {
			return ids, err
		}
		r := resp.Results[0]
		if r.StatusCode != ua.StatusOK && r.StatusCode != ua.StatusGoodNoData {
			return ids, r.StatusCode
		}
		if pages != nil {
			pages.Add(1)
		}
		he, ok := r.HistoryData.Value.(*ua.HistoryEvent)
		if !ok {
			return ids, fmt.Errorf("history data %T", r.HistoryData.Value)
		}
		if numValues > 0 && len(he.Events) > int(numValues) {
			return ids, fmt.Errorf("page of %d events, NumValuesPerNode %d", len(he.Events), numValues)
		}
		for _, ev := range he.Events {
			id, _ := ev.EventFields[0].Value().([]byte)
			tm, _ := ev.EventFields[1].Value().(time.Time)
			if tm.Before(lastTime) || seen[string(id)] {
				return ids, fmt.Errorf("event %s at %v: out of order or repeated (last at %v)", id, tm, lastTime)
			}
			lastTime, seen[string(id)] = tm, true
			ids = append(ids, string(id))
		}
		if cp = r.ContinuationPoint; len(cp) == 0 {
			return ids, nil
		}
		if stop != nil && stop(cp) {
			return ids, errAbandon
		}
	}
}

// eventHistoryRound is one session of a worker of TestChaosEventHistory:
// a few paged reads, some abandoned (the continuation point left behind,
// released, or the session closed), and deletes.
func eventHistoryRound(e *env, rng *rand.Rand, notifier *ua.NodeID, pages, abandoned *atomic.Int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := opcua.NewClient(e.url(), e.clientOptions(nil, opcua.AutoReconnect(false), opcua.RequestTimeout(5*time.Second))...)
	if err != nil {
		return err
	}
	defer closeClient(c, nil)
	if err := c.Connect(ctx); err != nil {
		if isConnectionError(err) {
			return nil
		}
		return fmt.Errorf("connect: %w", err)
	}
	ok := func(op string, err error) error {
		// Continuation points are bounded per server (the oldest goes)
		// and the reads of abandoned sessions hold some until the
		// session times out: a read may find its continuation point gone.
		if err == nil || errors.Is(err, errAbandon) || isConnectionError(err) || errors.Is(err, ua.StatusBadContinuationPointInvalid) {
			return nil
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	for range 2 + rng.Intn(4) {
		var op string
		switch rng.Intn(5) {
		case 0:
			// Delete a few events, some long gone.
			ids := make([][]byte, 1+rng.Intn(4))
			for i := range ids {
				ids[i] = []byte(fmt.Sprintf("ev-%d", rng.Intn(5000)))
			}
			resp, err := c.HistoryDeleteEvents(ctx, &ua.DeleteEventDetails{NodeID: notifier, EventIDs: ids})
			if err == nil && resp.Results[0].StatusCode != ua.StatusOK {
				err = resp.Results[0].StatusCode
			}
			op = "delete"
			if err := ok(op, err); err != nil {
				return err
			}
			continue
		case 1:
			// Abandon the read, leaving its continuation point.
			op = "abandon"
			_, err = readEventHistory(ctx, c, notifier, uint32(1+rng.Intn(20)), pages, func([]byte) bool { return rng.Intn(3) == 0 })
		case 2:
			// Release the continuation point in the middle.
			op = "release"
			var relErr error
			_, err = readEventHistory(ctx, c, notifier, uint32(1+rng.Intn(20)), pages, func(cp []byte) bool {
				if rng.Intn(3) != 0 {
					return false
				}
				relErr = c.Send(ctx, &ua.HistoryReadRequest{
					HistoryReadDetails:        ua.NewExtensionObject(&ua.ReadEventDetails{StartTime: histEventBase, EndTime: histEventBase.Add(time.Hour), Filter: histEventFilter}),
					TimestampsToReturn:        ua.TimestampsToReturnBoth,
					ReleaseContinuationPoints: true,
					NodesToRead:               []*ua.HistoryReadValueID{{NodeID: notifier, ContinuationPoint: cp}},
				}, func(ua.Response) error { return nil })
				return true
			})
			if err := ok("release request", relErr); err != nil {
				return err
			}
		case 3:
			// Close the session in the middle of the read.
			op = "close"
			_, err = readEventHistory(ctx, c, notifier, uint32(1+rng.Intn(20)), pages, func([]byte) bool {
				if rng.Intn(4) != 0 {
					return false
				}
				_ = c.Close(ctx)
				return true
			})
			if errors.Is(err, errAbandon) {
				abandoned.Add(1)
				return nil
			}
		default:
			op = "read"
			_, err = readEventHistory(ctx, c, notifier, uint32(1+rng.Intn(50)), pages, nil)
		}
		if errors.Is(err, errAbandon) {
			abandoned.Add(1)
		}
		if err := ok(op, err); err != nil {
			return err
		}
	}
	return nil
}
