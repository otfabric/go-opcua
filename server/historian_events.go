// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"encoding/hex"
	"sort"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// Compile-time checks for the event history interfaces on *Historian.
var (
	_ EventHistoryProvider = (*Historian)(nil)
	_ EventHistoryUpdater  = (*Historian)(nil)
	_ EventHistoryDeleter  = (*Historian)(nil)
)

// defaultHistoryMaxEvents is the event history capacity of a notifier when
// EnableEvents is given none.
const defaultHistoryMaxEvents = 1000

// eventHistory is the event history of one notifier: the events ordered by
// Time, events of the same Time in the order they were stored.
type eventHistory struct {
	events  []*storedEvent
	maxSize int
}

// storedEvent is an event of an eventHistory with its ordering key.
type storedEvent struct {
	ev   *HistoricalEvent
	time time.Time
	seq  uint64
}

// after reports whether e comes after the key (t, seq) in time order.
func (e *storedEvent) after(t time.Time, seq uint64) bool {
	return e.time.After(t) || e.time.Equal(t) && e.seq > seq
}

// before reports whether e comes before the key (t, seq) in time order.
func (e *storedEvent) before(t time.Time, seq uint64) bool {
	return e.time.Before(t) || e.time.Equal(t) && e.seq < seq
}

// eventContinuation is the state of a continued event read: the read and
// the key of the last event returned. Continuing after the key, not at an
// index, keeps the pages consistent while events are stored, replaced or
// deleted in between: no event is returned twice and none that was there
// all the time is skipped.
type eventContinuation struct {
	notifierKey string
	startTime   time.Time
	endTime     time.Time
	numValues   uint32
	lastTime    time.Time
	lastSeq     uint64
	created     time.Time
}

// EnableEvents keeps the event history of notifier, at most maxEvents
// events (default 1000); a full history drops its oldest event. Events reach
// the history when the notifier is a HistoricalEventNode of the server
// ([Server.EnableEventHistory]) or through RecordEvent.
func (h *Historian) EnableEvents(notifier *ua.NodeID, maxEvents int) {
	if maxEvents <= 0 {
		maxEvents = defaultHistoryMaxEvents
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.events == nil {
		h.events = make(map[string]*eventHistory)
	}
	h.events[notifier.String()] = &eventHistory{maxSize: maxEvents}
}

// EventsEnabled reports whether the event history of notifier is kept.
func (h *Historian) EventsEnabled(notifier *ua.NodeID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.events[notifier.String()]
	return ok
}

// RecordEvent implements EventHistoryProvider. The event needs a Time to be
// stored; events of a notifier whose history is not kept are ignored.
func (h *Historian) RecordEvent(notifier *ua.NodeID, ev *HistoricalEvent) {
	if ev == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	eh, ok := h.events[notifier.String()]
	if !ok {
		return
	}
	h.insertEventLocked(eh, ev)
}

// insertEventLocked stores ev in eh in time order. A full history drops its
// oldest event; an event older than all events of a full history is not
// stored and false is returned.
func (h *Historian) insertEventLocked(eh *eventHistory, ev *HistoricalEvent) bool {
	t := ev.Time()
	if len(eh.events) >= eh.maxSize {
		if len(eh.events) > 0 && t.Before(eh.events[0].time) {
			return false
		}
		eh.events = eh.events[len(eh.events)-eh.maxSize+1:]
	}
	h.eventSeq++
	se := &storedEvent{ev: ev, time: t, seq: h.eventSeq}
	// Behind every event of the same Time: the latest stored comes last.
	i := sort.Search(len(eh.events), func(i int) bool { return eh.events[i].time.After(t) })
	eh.events = append(eh.events, nil)
	copy(eh.events[i+1:], eh.events[i:])
	eh.events[i] = se
	return true
}

// ReadEvents implements EventHistoryProvider.
//
// The range (Part 11 §6.5.2.2): with startTime before endTime the events
// from startTime (inclusive) to endTime (exclusive), oldest first; with
// startTime after endTime the events from startTime (inclusive) back to
// endTime (exclusive), newest first; with equal times the events of that
// Time. With only startTime the events from startTime on, oldest first;
// with only endTime the events up to endTime (inclusive), newest first.
func (h *Historian) ReadEvents(notifier *ua.NodeID, startTime, endTime time.Time, numValues uint32, match func(*HistoricalEvent) bool, continuationPoint []byte) ([]*HistoricalEvent, []byte, ua.StatusCode) {
	h.mu.Lock()
	nodeKey := notifier.String()
	var cont *eventContinuation
	if len(continuationPoint) > 0 {
		cpKey := hex.EncodeToString(continuationPoint)
		cont = h.eventCPs[cpKey]
		if cont == nil {
			h.mu.Unlock()
			return nil, nil, ua.StatusBadContinuationPointInvalid
		}
		delete(h.eventCPs, cpKey)
		if cont.notifierKey != nodeKey {
			// The continuation point of another notifier.
			h.mu.Unlock()
			return nil, nil, ua.StatusBadContinuationPointInvalid
		}
		startTime, endTime, numValues = cont.startTime, cont.endTime, cont.numValues
	}
	eh, ok := h.events[nodeKey]
	if !ok {
		h.mu.Unlock()
		return nil, nil, ua.StatusBadHistoryOperationUnsupported
	}
	r := newEventRange(startTime, endTime)
	// The candidates are taken under the lock and filtered without it:
	// match evaluates the filter of the client, which may consult the
	// address space and the access controller.
	candidates := r.collect(eh.events, cont)
	h.mu.Unlock()

	var out []*HistoricalEvent
	var last *storedEvent
	more := false
	for _, se := range candidates {
		if match != nil && !match(se.ev) {
			continue
		}
		if numValues > 0 && uint32(len(out)) >= numValues {
			more = true
			break
		}
		out = append(out, se.ev)
		last = se
	}

	var cp []byte
	if more {
		cp = generateContinuationPoint()
		h.mu.Lock()
		if h.eventCPs == nil {
			h.eventCPs = make(map[string]*eventContinuation)
		}
		h.eventCPs[hex.EncodeToString(cp)] = &eventContinuation{
			notifierKey: nodeKey,
			startTime:   startTime,
			endTime:     endTime,
			numValues:   numValues,
			lastTime:    last.time,
			lastSeq:     last.seq,
			created:     time.Now(),
		}
		h.cleanExpiredContinuations()
		h.mu.Unlock()
	}
	if len(out) == 0 {
		return nil, nil, ua.StatusGoodNoData
	}
	return out, cp, ua.StatusOK
}

// eventRange is the time range of an event read and its direction.
type eventRange struct {
	reverse bool
	// from is the inclusive bound the read starts at, to the bound it ends
	// at (exclusive; inclusive when exact is set). A zero time is no bound.
	from, to time.Time
	exact    bool
}

func newEventRange(startTime, endTime time.Time) eventRange {
	switch {
	case startTime.IsZero() && !endTime.IsZero():
		// Only endTime (with NumValuesPerNode): newest first, up to endTime.
		return eventRange{reverse: true, from: endTime}
	case !startTime.IsZero() && !endTime.IsZero() && startTime.After(endTime):
		return eventRange{reverse: true, from: startTime, to: endTime}
	default:
		return eventRange{from: startTime, to: endTime, exact: startTime.Equal(endTime)}
	}
}

// in reports whether t lies in the range.
func (r eventRange) in(t time.Time) bool {
	if r.reverse {
		return (r.from.IsZero() || !t.After(r.from)) && (r.to.IsZero() || t.After(r.to))
	}
	if r.exact {
		return r.from.IsZero() || t.Equal(r.from)
	}
	return (r.from.IsZero() || !t.Before(r.from)) && (r.to.IsZero() || t.Before(r.to))
}

// collect returns the events of the range in read order, after the last
// event of a continued read.
func (r eventRange) collect(events []*storedEvent, cont *eventContinuation) []*storedEvent {
	var out []*storedEvent
	if r.reverse {
		for i := len(events) - 1; i >= 0; i-- {
			se := events[i]
			if cont != nil && !se.before(cont.lastTime, cont.lastSeq) {
				continue
			}
			if r.in(se.time) {
				out = append(out, se)
			}
		}
		return out
	}
	for _, se := range events {
		if cont != nil && !se.after(cont.lastTime, cont.lastSeq) {
			continue
		}
		if r.in(se.time) {
			out = append(out, se)
		}
	}
	return out
}

// findEventLocked returns the index of the event with eventID, -1 if none.
func findEventLocked(eh *eventHistory, eventID []byte) int {
	if len(eventID) == 0 {
		return -1
	}
	for i, se := range eh.events {
		if bytes.Equal(se.ev.EventID(), eventID) {
			return i
		}
	}
	return -1
}

// UpdateEvents implements EventHistoryUpdater. A replaced event takes the
// fields given; EventId, EventType and Time not given are kept. An event
// older than every event of a full history is not inserted (Bad_OutOfRange,
// Part 11 §6.9.4.2).
func (h *Historian) UpdateEvents(notifier *ua.NodeID, perform ua.PerformUpdateType, events []*HistoricalEvent) *ua.HistoryUpdateResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	eh, ok := h.events[notifier.String()]
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}
	ops := make([]ua.StatusCode, len(events))
	for i, ev := range events {
		if ev == nil {
			ops[i] = ua.StatusBadInvalidArgument
			continue
		}
		idx := findEventLocked(eh, ev.EventID())
		switch {
		case perform == ua.PerformUpdateTypeInsert && idx >= 0:
			ops[i] = ua.StatusBadEntryExists
		case perform == ua.PerformUpdateTypeReplace && idx < 0:
			ops[i] = ua.StatusBadNoEntryExists
		case perform != ua.PerformUpdateTypeInsert && perform != ua.PerformUpdateTypeReplace && perform != ua.PerformUpdateTypeUpdate:
			ops[i] = ua.StatusBadInvalidArgument
		case idx >= 0:
			old := eh.events[idx].ev
			eh.events = append(eh.events[:idx], eh.events[idx+1:]...)
			h.insertEventLocked(eh, ev.replacing(old))
			ops[i] = ua.StatusGoodEntryReplaced
		case h.insertEventLocked(eh, ev):
			ops[i] = ua.StatusGoodEntryInserted
		default:
			ops[i] = ua.StatusBadOutOfRange
		}
	}
	return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK, OperationResults: ops}
}

// DeleteEvents implements EventHistoryDeleter: it deletes every event with
// one of the EventIds (Part 11 §6.9.7.2).
func (h *Historian) DeleteEvents(notifier *ua.NodeID, eventIDs [][]byte) *ua.HistoryUpdateResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	eh, ok := h.events[notifier.String()]
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
	}
	ops := make([]ua.StatusCode, len(eventIDs))
	for i, eventID := range eventIDs {
		ops[i] = ua.StatusBadNoData
		for idx := findEventLocked(eh, eventID); idx >= 0; idx = findEventLocked(eh, eventID) {
			eh.events = append(eh.events[:idx], eh.events[idx+1:]...)
			ops[i] = ua.StatusOK
		}
	}
	return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK, OperationResults: ops}
}
