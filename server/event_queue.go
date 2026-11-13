// SPDX-License-Identifier: MIT

package server

import (
	"slices"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// queuedEvent is an event waiting in the queue of an event item for a
// Publish. seq orders the events of all items of a subscription in the
// order they were queued.
type queuedEvent struct {
	seq      uint64
	ef       *ua.EventFieldList
	overflow bool // an EventQueueOverflowEventType event
}

// setEventQueue sets the revised QueueSize and DiscardOldest of an event item
// and trims its queue to the new size, keeping the newest events.
func (item *MonitoredItem) setEventQueue(size uint32, discardOldest bool) {
	sub := item.Sub
	if sub == nil {
		return
	}
	sub.evMu.Lock()
	defer sub.evMu.Unlock()
	item.evQueueSize = size
	item.evDiscardOldest = discardOldest
	if n := len(item.events) - int(size); n > 0 {
		item.events = slices.Delete(item.events, 0, n)
	}
}

// queueEvent queues the event ef for item, applying the QueueSize and
// DiscardOldest of the item (Part 4 §5.12.1.5). When the queue is full an
// EventQueueOverflowEventType event marks the place where events were lost:
// with DiscardOldest the oldest event is discarded and the overflow event
// heads the queue; otherwise the new event is discarded and the overflow
// event ends the queue. A queue holds at most one overflow event, so it
// never has more than QueueSize+1 entries. extra raises the bound to
// maxEventQueueSize (the events of a ConditionRefresh).
func (s *Subscription) queueEvent(item *MonitoredItem, ef *ua.EventFieldList, extra bool) {
	s.evMu.Lock()
	defer s.evMu.Unlock()
	s.evSeq++
	e := queuedEvent{seq: s.evSeq, ef: ef}

	size := int(item.evQueueSize)
	if size <= 0 {
		size = int(defaultEventQueueSize)
	}
	if extra {
		size = max(size, int(maxEventQueueSize))
	}
	if s.evItems == nil {
		s.evItems = make(map[*MonitoredItem]struct{})
	}
	s.evItems[item] = struct{}{}
	q := item.events
	live := len(q)
	hasMarker := false
	for _, x := range q {
		if x.overflow {
			hasMarker = true
			live--
		}
	}
	if live < size {
		item.events = append(q, e)
		return
	}
	if item.evDiscardOldest {
		// Discard the oldest real event; the overflow event takes its place
		// at the head of the queue.
		first := 0
		if len(q) > 0 && q[0].overflow {
			first = 1
		}
		dropped := q[first]
		q = slices.Delete(q, first, first+1)
		q = append(q, e)
		if !hasMarker {
			q = slices.Insert(q, 0, queuedEvent{seq: dropped.seq, ef: s.overflowEvent(item), overflow: true})
		}
		item.events = q
		return
	}
	// Keep the queue, discard the new event; the overflow event ends the
	// queue.
	if !hasMarker {
		item.events = append(q, queuedEvent{seq: e.seq, ef: s.overflowEvent(item), overflow: true})
	}
}

// overflowEvent builds the EventQueueOverflowEventType event of item with
// the fields its SelectClauses request. Its SourceNode is the Server object
// (Part 5 §6.4.33).
func (s *Subscription) overflowEvent(item *MonitoredItem) *ua.EventFieldList {
	ev := &BaseEvent{
		EventID:    newEventID(),
		EventType:  ua.NewNumericNodeID(0, id.EventQueueOverflowEventType),
		SourceNode: ua.NewNumericNodeID(0, id.Server),
		SourceName: "Internal/EventQueueOverflow",
		Time:       time.Now(),
		Message:    ua.NewLocalizedText("Event queue overflow"),
		Severity:   1,
	}
	var clauses []*ua.SimpleAttributeOperand
	if s.srv != nil && s.srv.srv != nil && s.srv.srv.eventItems != nil {
		if emi := s.srv.srv.eventItems.get(item.ID); emi != nil {
			clauses = emi.SelectClauses
		}
	}
	h := uint32(0)
	if item.Req != nil && item.Req.RequestedParameters != nil {
		h = item.Req.RequestedParameters.ClientHandle
	}
	return &ua.EventFieldList{ClientHandle: h, EventFields: selectEventFields(ev, clauses)}
}

// queueLooseEvent queues an event that was sent to EventNotifyChannel
// directly, without an item. Such events are bounded by maxEventQueueSize,
// the oldest being discarded.
func (s *Subscription) queueLooseEvent(ef *ua.EventFieldList) {
	s.evMu.Lock()
	defer s.evMu.Unlock()
	s.evSeq++
	if len(s.looseEvents) >= int(maxEventQueueSize) {
		s.looseEvents = slices.Delete(s.looseEvents, 0, 1)
	}
	s.looseEvents = append(s.looseEvents, queuedEvent{seq: s.evSeq, ef: ef})
}

// pendingEvents reports whether events wait for a Publish.
func (s *Subscription) pendingEvents() bool {
	s.evMu.Lock()
	defer s.evMu.Unlock()
	return len(s.looseEvents) > 0 || len(s.evItems) > 0
}

// dropEventQueue discards the queued events of item, which is being
// deleted.
func (s *Subscription) dropEventQueue(item *MonitoredItem) {
	s.evMu.Lock()
	defer s.evMu.Unlock()
	item.events = nil
	delete(s.evItems, item)
}

// takeEvents removes and returns the queued events of the subscription in
// the order they were queued, at most limit of them unless unlimited. more
// reports whether events are left (Part 4 §5.13.1.1 MoreNotifications).
func (s *Subscription) takeEvents(limit int, unlimited bool) (out []*ua.EventFieldList, more bool) {
	s.evMu.Lock()
	defer s.evMu.Unlock()

	type ref struct {
		seq   uint64
		queue *[]queuedEvent
	}
	var all []ref
	add := func(q *[]queuedEvent) {
		for _, e := range *q {
			all = append(all, ref{seq: e.seq, queue: q})
		}
	}
	add(&s.looseEvents)
	for it := range s.evItems {
		add(&it.events)
	}
	if len(all) == 0 {
		return nil, false
	}
	slices.SortFunc(all, func(a, b ref) int {
		switch {
		case a.seq < b.seq:
			return -1
		case a.seq > b.seq:
			return 1
		}
		return 0
	})
	n := len(all)
	if !unlimited && n > limit {
		n = limit
		more = true
	}
	// The events of one queue are in seq order, so the first n of all are
	// a prefix of every queue.
	taken := make(map[*[]queuedEvent]int)
	out = make([]*ua.EventFieldList, 0, n)
	for _, r := range all[:n] {
		q := *r.queue
		out = append(out, q[taken[r.queue]].ef)
		taken[r.queue]++
	}
	for q, k := range taken {
		rest := (*q)[k:]
		if len(rest) == 0 {
			*q = nil
		} else {
			*q = slices.Clone(rest)
		}
	}
	for it := range s.evItems {
		if len(it.events) == 0 {
			delete(s.evItems, it)
		}
	}
	return out, more
}
