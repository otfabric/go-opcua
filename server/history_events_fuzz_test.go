// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// fuzzEventStatuses are the statuses event history operations may answer.
var fuzzEventStatuses = []ua.StatusCode{
	ua.StatusOK, ua.StatusGoodNoData, ua.StatusGoodEntryInserted, ua.StatusGoodEntryReplaced, ua.StatusGoodDataIgnored,
	ua.StatusBadNodeIDInvalid, ua.StatusBadNodeIDUnknown, ua.StatusBadHistoryOperationUnsupported, ua.StatusBadNotWritable,
	ua.StatusBadContinuationPointInvalid, ua.StatusBadInvalidArgument, ua.StatusBadEventFilterInvalid,
	ua.StatusBadIndexRangeInvalid, ua.StatusBadArgumentsMissing, ua.StatusBadTypeDefinitionInvalid,
	ua.StatusBadSourceNodeIDInvalid, ua.StatusBadEntryExists, ua.StatusBadNoEntryExists, ua.StatusBadOutOfRange,
	ua.StatusBadNoData,
}

// FuzzHistoryEventDetails: whatever ReadEventDetails, UpdateEventDetails or
// DeleteEventDetails a client sends (decoded from the fuzz input), the
// HistoryRead and HistoryUpdate services never panic, answer one result per
// operation with a status of Part 11 §6.2 or Part 4 §5.10, and their
// responses encode.
func FuzzHistoryEventDetails(f *testing.F) {
	enc := func(v any) []byte {
		b, err := ua.Encode(v)
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	sel := ua.NewEventFilter().Select("EventId", "EventType", "Time", "Severity", "Message").SelectConditionID().Build()
	where := ua.NewEventFilter().Select("EventId").Where(&ua.ContentFilterElement{
		FilterOperator: ua.FilterOperatorOfType,
		FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType))})},
	}).Build()
	notifier := ua.NewStringNodeID(1, "Pump")
	f.Add(byte(0), enc(&ua.ReadEventDetails{StartTime: evAt(0), EndTime: evAt(9), NumValuesPerNode: 2, Filter: sel}))
	f.Add(byte(0), enc(&ua.ReadEventDetails{StartTime: evAt(9), EndTime: evAt(0), Filter: where}))
	f.Add(byte(0), enc(&ua.ReadEventDetails{EndTime: evAt(5), NumValuesPerNode: 3, Filter: sel}))
	f.Add(byte(1), enc(&ua.UpdateEventDetails{NodeID: notifier, PerformInsertReplace: ua.PerformUpdateTypeInsert, Filter: sel,
		EventData: []*ua.HistoryEventFieldList{{EventFields: []*ua.Variant{ua.MustVariant([]byte("x")), ua.MustVariant(ua.NewNumericNodeID(0, id.BaseEventType)),
			ua.MustVariant(evAt(3)), ua.MustVariant(uint16(5)), ua.MustVariant(ua.NewLocalizedText("m")), ua.MustVariant(nil)}}}}))
	f.Add(byte(1), enc(&ua.UpdateEventDetails{NodeID: notifier, PerformInsertReplace: ua.PerformUpdateTypeReplace, Filter: sel}))
	f.Add(byte(2), enc(&ua.DeleteEventDetails{NodeID: notifier, EventIDs: [][]byte{[]byte("e1"), nil}}))
	f.Add(byte(0), []byte("garbage"))
	f.Fuzz(func(t *testing.T, kind byte, b []byte) {
		if len(b) > 4096 {
			return
		}
		s, _, src := alarmTestServer(t)
		h := NewHistorian()
		h.EnableEvents(src.ID(), 8)
		s.SetHistorian(h)
		if err := s.EnableEventHistory(src.ID(), EventHistoryOptions{Writable: true}); err != nil {
			t.Fatal(err)
		}
		for i := range 5 {
			emitAt(s, src.ID(), fmt.Sprintf("e%d", i), i, nil)
		}
		svc := &AttributeService{srv: s}
		check := func(sc ua.StatusCode) {
			if !slices.Contains(fuzzEventStatuses, sc) {
				t.Fatalf("status %v", sc)
			}
		}
		switch kind % 3 {
		case 0:
			var d ua.ReadEventDetails
			if _, err := ua.Decode(b, &d); err != nil {
				return
			}
			var cp []byte
			for range 10 {
				resp, err := svc.HistoryRead(context.Background(), nil, &ua.HistoryReadRequest{
					RequestHeader:      reqHeader(),
					HistoryReadDetails: ua.NewExtensionObject(&d),
					NodesToRead:        []*ua.HistoryReadValueID{{NodeID: src.ID(), ContinuationPoint: cp}, {NodeID: ua.NewStringNodeID(9, "nope")}},
				}, 1)
				if err != nil {
					t.Fatal(err)
				}
				hr := resp.(*ua.HistoryReadResponse)
				if _, err := ua.Encode(hr); err != nil {
					t.Fatalf("encode: %v", err)
				}
				if sr := hr.ResponseHeader.ServiceResult; sr != ua.StatusOK {
					if sr != ua.StatusBadHistoryOperationInvalid && sr != ua.StatusBadEventFilterInvalid {
						t.Fatalf("service result %v", sr)
					}
					return
				}
				if len(hr.Results) != 2 {
					t.Fatalf("%d results", len(hr.Results))
				}
				for _, r := range hr.Results {
					check(r.StatusCode)
				}
				if cp = hr.Results[0].ContinuationPoint; len(cp) == 0 {
					return
				}
			}
		case 1:
			var d ua.UpdateEventDetails
			if _, err := ua.Decode(b, &d); err != nil {
				return
			}
			if d.NodeID == nil || d.NodeID.Namespace() == src.ID().Namespace() {
				d.NodeID = src.ID()
			}
			res := historyUpdate(t, svc, &d)[0]
			check(res.StatusCode)
			for _, op := range res.OperationResults {
				check(op)
			}
			if res.StatusCode == ua.StatusOK && len(res.OperationResults) != len(d.EventData) {
				t.Fatalf("%d operation results for %d events", len(res.OperationResults), len(d.EventData))
			}
		default:
			var d ua.DeleteEventDetails
			if _, err := ua.Decode(b, &d); err != nil {
				return
			}
			d.NodeID = src.ID()
			res := historyUpdate(t, svc, &d)[0]
			check(res.StatusCode)
			if len(res.OperationResults) != len(d.EventIDs) {
				t.Fatalf("%d operation results for %d EventIds", len(res.OperationResults), len(d.EventIDs))
			}
		}
		// The history stays ordered and within its bound.
		events, _, _ := h.ReadEvents(src.ID(), time.Unix(1, 0), time.Time{}, 0, nil, nil)
		if len(events) > 8 {
			t.Fatalf("%d events, bound 8", len(events))
		}
		for i := 1; i < len(events); i++ {
			if events[i].Time().Before(events[i-1].Time()) {
				t.Fatalf("event %d out of order", i)
			}
		}
	})
}

// FuzzEventHistoryStore: any sequence of records, inserts, replaces,
// deletes and paged reads keeps the store ordered and bounded, and a paged
// read returns what one unpaged read returns.
func FuzzEventHistoryStore(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{0, 0, 0, 3, 3, 1, 2, 4, 9, 9, 7})
	f.Add([]byte{5, 200, 4, 17, 0, 255, 6, 3, 1})
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 256 {
			return
		}
		h := NewHistorian()
		n := ua.NewStringNodeID(1, "N")
		h.EnableEvents(n, 16)
		for i := 0; i+1 < len(ops); i += 2 {
			arg := int(ops[i+1])
			name := fmt.Sprintf("e%d", arg%24)
			switch ops[i] % 5 {
			case 0:
				h.RecordEvent(n, hev(name, evAt(arg%40), uint16(arg)))
			case 1:
				h.UpdateEvents(n, ua.PerformUpdateTypeInsert, []*HistoricalEvent{hev(name, evAt(arg%40), 1)})
			case 2:
				h.UpdateEvents(n, ua.PerformUpdateType(arg%5), []*HistoricalEvent{hev(name, evAt(arg%40), 2)})
			case 3:
				h.DeleteEvents(n, [][]byte{[]byte(name)})
			default:
				start, end := evAt(arg%40), evAt((arg*7)%40)
				all, _, st := h.ReadEvents(n, start, end, 0, nil, nil)
				if st != ua.StatusOK && st != ua.StatusGoodNoData {
					t.Fatalf("read: %v", st)
				}
				var paged []*HistoricalEvent
				var cp []byte
				for {
					page, next, st := h.ReadEvents(n, start, end, uint32(1+arg%4), nil, cp)
					if st != ua.StatusOK && st != ua.StatusGoodNoData {
						t.Fatalf("paged read: %v", st)
					}
					paged = append(paged, page...)
					if len(next) == 0 {
						break
					}
					cp = next
				}
				if !slices.Equal(evNames(all), evNames(paged)) {
					t.Fatalf("paged %v, unpaged %v", evNames(paged), evNames(all))
				}
			}
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		eh := h.events[n.String()]
		if len(eh.events) > eh.maxSize {
			t.Fatalf("%d events, bound %d", len(eh.events), eh.maxSize)
		}
		for i := 1; i < len(eh.events); i++ {
			if !eh.events[i].after(eh.events[i-1].time, eh.events[i-1].seq) {
				t.Fatalf("event %d out of order", i)
			}
		}
	})
}
