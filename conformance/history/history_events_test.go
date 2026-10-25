// SPDX-License-Identifier: MIT

package history

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Historical events (Part 11 §5.4, §6.5.2, §6.9.4, §6.9.7) end to end: the
// go-opcua client against the built-in historian of the go-opcua server.

// evtSelect selects the fields the tests read back.
var evtSelect = ua.NewEventFilter().Select("EventId", "EventType", "Time", "Severity", "Message").Build()

// eventHistorySetup starts a server whose EventObject is a writable
// HistoricalEventNode holding events e0..e(n-1): event i at histAt(i), of
// SystemEventType when i is 3, else BaseEventType, with Severity 100*(i+1).
func eventHistorySetup(t *testing.T, n int) (*opcua.Client, *testutil.Fixture, *server.Server, string) {
	t.Helper()
	return setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		h := server.NewHistorian()
		h.EnableEvents(f.EventObject, 100)
		srv.SetHistorian(h)
		require.NoError(t, srv.EnableEventHistory(f.EventObject, server.EventHistoryOptions{Writable: true}))
		for i := range n {
			emitHistEvent(srv, f.EventObject, i)
		}
	})
}

func emitHistEvent(srv *server.Server, notifier *ua.NodeID, i int) {
	typ := uint32(id.BaseEventType)
	if i == 3 {
		typ = id.SystemEventType
	}
	_ = srv.EmitBaseEvent(notifier, &server.BaseEvent{
		EventID:    []byte(fmt.Sprintf("e%d", i)),
		EventType:  ua.NewNumericNodeID(0, typ),
		SourceNode: notifier,
		SourceName: "EventObject",
		Time:       histAt(i),
		Message:    ua.NewLocalizedText(fmt.Sprintf("event %d", i)),
		Severity:   uint16(100 * (i + 1)),
	})
}

// readEvents performs one HistoryRead of events and returns its result.
func readEvents(t *testing.T, c *opcua.Client, node *ua.NodeID, d *ua.ReadEventDetails, cp []byte) *ua.HistoryReadResult {
	t.Helper()
	resp, err := c.HistoryReadEvent(context.Background(), []*ua.HistoryReadValueID{{NodeID: node, ContinuationPoint: cp}}, d)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	return resp.Results[0]
}

// eventIDs returns the EventIds (the first field) of the events of r.
func eventIDs(t *testing.T, r *ua.HistoryReadResult) []string {
	t.Helper()
	require.False(t, r.StatusCode&0x80000000 != 0, "status %v", r.StatusCode)
	require.NotNil(t, r.HistoryData)
	he, ok := r.HistoryData.Value.(*ua.HistoryEvent)
	require.True(t, ok, "expected *ua.HistoryEvent, got %T", r.HistoryData.Value)
	out := []string{}
	for _, e := range he.Events {
		out = append(out, string(e.EventFields[0].Value().([]byte)))
	}
	return out
}

func evs(from, to int) []string {
	out := []string{}
	for _, v := range seq(from, to) {
		out = append(out, fmt.Sprintf("e%d", int(v)))
	}
	return out
}

func TestHistoryEvents_Read(t *testing.T) {
	c, f, _, _ := eventHistorySetup(t, 6)
	node := f.EventObject

	t.Run("FieldsRoundTrip", func(t *testing.T) {
		r := readEvents(t, c, node, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(1), Filter: evtSelect}, nil)
		require.Equal(t, ua.StatusOK, r.StatusCode)
		he := r.HistoryData.Value.(*ua.HistoryEvent)
		require.Len(t, he.Events, 1)
		fields := he.Events[0].EventFields
		require.Equal(t, []byte("e0"), fields[0].Value())
		require.True(t, ua.NewNumericNodeID(0, id.BaseEventType).Equal(fields[1].Value().(*ua.NodeID)))
		require.True(t, histAt(0).Equal(fields[2].Value().(time.Time)))
		require.Equal(t, uint16(100), fields[3].Value())
		require.Equal(t, "event 0", fields[4].Value().(*ua.LocalizedText).Text)
	})

	for _, tc := range []struct {
		name       string
		start, end time.Time
		num        uint32
		want       []string
	}{
		{"StartInclusiveEndExclusive", histAt(1), histAt(4), 0, evs(1, 3)},
		{"Reverse", histAt(4), histAt(1), 0, evs(4, 2)},
		{"EqualTimes", histAt(2), histAt(2), 0, evs(2, 2)},
		{"OnlyStartAndNum", histAt(2), time.Time{}, 2, evs(2, 3)},
		{"OnlyEndAndNumReverse", time.Time{}, histAt(4), 2, evs(4, 3)},
		{"ForwardNumKeepsOldest", histAt(0), histAt(100), 2, evs(0, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := readEvents(t, c, node, &ua.ReadEventDetails{StartTime: tc.start, EndTime: tc.end, NumValuesPerNode: tc.num, Filter: evtSelect}, nil)
			require.Equal(t, tc.want, eventIDs(t, r))
		})
	}

	t.Run("GoodNoData", func(t *testing.T) {
		r := readEvents(t, c, node, &ua.ReadEventDetails{StartTime: histAt(50), EndTime: histAt(60), Filter: evtSelect}, nil)
		require.Equal(t, ua.StatusGoodNoData, r.StatusCode)
		require.Empty(t, eventIDs(t, r))
	})

	t.Run("WhereOfType", func(t *testing.T) {
		filter := ua.NewEventFilter().Select("EventId").Where(&ua.ContentFilterElement{
			FilterOperator: ua.FilterOperatorOfType,
			FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(ua.NewNumericNodeID(0, id.SystemEventType))})},
		}).Build()
		r := readEvents(t, c, node, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(100), Filter: filter}, nil)
		require.Equal(t, []string{"e3"}, eventIDs(t, r))
	})

	t.Run("WhereSeverity", func(t *testing.T) {
		filter := ua.NewEventFilter().Select("EventId").Where(&ua.ContentFilterElement{
			FilterOperator: ua.FilterOperatorGreaterThanOrEqual,
			FilterOperands: []*ua.ExtensionObject{
				ua.NewExtensionObject(&ua.SimpleAttributeOperand{TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
					BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}, AttributeID: ua.AttributeIDValue}),
				ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(uint16(400))}),
			},
		}).Build()
		r := readEvents(t, c, node, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(100), Filter: filter}, nil)
		require.Equal(t, evs(3, 5), eventIDs(t, r))
	})

	t.Run("UnknownFieldIsNull", func(t *testing.T) {
		filter := ua.NewEventFilter().Select("EventId", "NoSuchField").Build()
		r := readEvents(t, c, node, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(1), Filter: filter}, nil)
		require.Nil(t, r.HistoryData.Value.(*ua.HistoryEvent).Events[0].EventFields[1].Value())
	})

	t.Run("NodeWithoutEventHistory", func(t *testing.T) {
		r := readEvents(t, c, f.MethodObject, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(1), Filter: evtSelect}, nil)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, r.StatusCode)
		r = readEvents(t, c, ua.NewStringNodeID(f.NSIndex, "Nope"), &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(1), Filter: evtSelect}, nil)
		require.Equal(t, ua.StatusBadNodeIDUnknown, r.StatusCode)
	})

	t.Run("InvalidDetails", func(t *testing.T) {
		for name, d := range map[string]*ua.ReadEventDetails{
			"OnlyStart": {StartTime: histAt(0), Filter: evtSelect},
			"NoFilter":  {StartTime: histAt(0), EndTime: histAt(1)},
		} {
			_, err := c.HistoryReadEvent(context.Background(), []*ua.HistoryReadValueID{{NodeID: node}}, d)
			require.Error(t, err, name)
		}
		_, err := c.HistoryReadEvent(context.Background(), []*ua.HistoryReadValueID{{NodeID: node}}, &ua.ReadEventDetails{StartTime: histAt(0), Filter: evtSelect})
		require.ErrorIs(t, err, ua.StatusBadHistoryOperationInvalid)
		_, err = c.HistoryReadEvent(context.Background(), []*ua.HistoryReadValueID{{NodeID: node}}, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(1), Filter: &ua.EventFilter{}})
		require.ErrorIs(t, err, ua.StatusBadEventFilterInvalid)
	})
}

func TestHistoryEvents_ContinuationPoints(t *testing.T) {
	c, f, _, url := eventHistorySetup(t, 10)
	node := f.EventObject
	d := &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(100), NumValuesPerNode: 4, Filter: evtSelect}

	t.Run("PagesThroughAllEvents", func(t *testing.T) {
		var got []string
		var cp []byte
		pages := 0
		for {
			r := readEvents(t, c, node, d, cp)
			got = append(got, eventIDs(t, r)...)
			pages++
			if cp = r.ContinuationPoint; len(cp) == 0 {
				break
			}
			require.Less(t, pages, 10)
		}
		require.Equal(t, evs(0, 9), got)
		require.Equal(t, 3, pages)
	})

	t.Run("ReversePaging", func(t *testing.T) {
		rd := &ua.ReadEventDetails{StartTime: histAt(100), EndTime: histAt(0).Add(-time.Second), NumValuesPerNode: 3, Filter: evtSelect}
		var got []string
		var cp []byte
		for {
			r := readEvents(t, c, node, rd, cp)
			got = append(got, eventIDs(t, r)...)
			if cp = r.ContinuationPoint; len(cp) == 0 {
				break
			}
		}
		require.Equal(t, evs(9, 0), got)
	})

	t.Run("OneShotAndRelease", func(t *testing.T) {
		r := readEvents(t, c, node, d, nil)
		cp := r.ContinuationPoint
		require.NotEmpty(t, cp)
		require.Equal(t, evs(4, 7), eventIDs(t, readEvents(t, c, node, d, cp)))
		require.Equal(t, ua.StatusBadContinuationPointInvalid, readEvents(t, c, node, d, cp).StatusCode)

		cp = readEvents(t, c, node, d, nil).ContinuationPoint
		req := &ua.HistoryReadRequest{
			HistoryReadDetails:        ua.NewExtensionObject(d),
			TimestampsToReturn:        ua.TimestampsToReturnBoth,
			ReleaseContinuationPoints: true,
			NodesToRead:               []*ua.HistoryReadValueID{{NodeID: node, ContinuationPoint: cp}},
		}
		resp := mustSendRaw[ua.HistoryReadResponse](t, c, req)
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, readEvents(t, c, node, d, cp).StatusCode)
		// A released continuation point is no longer valid, also for release (Part 4 §5.10.3).
		resp = mustSendRaw[ua.HistoryReadResponse](t, c, req)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, resp.Results[0].StatusCode)
	})

	t.Run("BoundToTheSession", func(t *testing.T) {
		cp := readEvents(t, c, node, d, nil).ContinuationPoint
		other := newClient(t, url)
		require.Equal(t, ua.StatusBadContinuationPointInvalid, readEvents(t, other, node, d, cp).StatusCode)
		// Another session cannot release it either.
		rel := mustSendRaw[ua.HistoryReadResponse](t, other, &ua.HistoryReadRequest{
			HistoryReadDetails:        ua.NewExtensionObject(d),
			TimestampsToReturn:        ua.TimestampsToReturnBoth,
			ReleaseContinuationPoints: true,
			NodesToRead:               []*ua.HistoryReadValueID{{NodeID: node, ContinuationPoint: cp}},
		})
		require.Equal(t, ua.StatusBadContinuationPointInvalid, rel.Results[0].StatusCode)
		require.Equal(t, evs(4, 7), eventIDs(t, readEvents(t, c, node, d, cp)), "still valid for its own session")
	})

	t.Run("SessionCloseReleases", func(t *testing.T) {
		other := newClient(t, url)
		cp := readEvents(t, other, node, d, nil).ContinuationPoint
		require.NoError(t, other.Close(context.Background()))
		require.Equal(t, ua.StatusBadContinuationPointInvalid, readEvents(t, c, node, d, cp).StatusCode)
	})
}

// Events reported while a subscription monitors the notifier reach both the
// subscription and the history.
func TestHistoryEvents_LiveAndHistory(t *testing.T) {
	c, f, srv, _ := eventHistorySetup(t, 0)
	ctx := context.Background()
	sub, ch, err := c.NewSubscription().Interval(fastInterval).
		MonitorEvents(ua.NewEventFilter().Select("EventId").Build(), f.EventObject).Start(ctx)
	require.NoError(t, err)
	defer func() { _ = sub.Cancel(ctx) }()

	emitHistEvent(srv, f.EventObject, 7)
	live := nextEvents(t, ch)
	require.NotEmpty(t, live)
	require.Equal(t, []byte("e7"), live[0].EventFields[0].Value())
	r := readEvents(t, c, f.EventObject, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(100), Filter: evtSelect}, nil)
	require.Equal(t, []string{"e7"}, eventIDs(t, r))
}

func TestHistoryEvents_Update(t *testing.T) {
	c, f, _, _ := eventHistorySetup(t, 3)
	ctx := context.Background()
	node := f.EventObject
	base := ua.NewNumericNodeID(0, id.BaseEventType)
	sel := ua.NewEventFilter().Select("EventId", "EventType", "Time", "Severity").Build()
	row := func(name string, i int, sev uint16) *ua.HistoryEventFieldList {
		return &ua.HistoryEventFieldList{EventFields: []*ua.Variant{
			ua.MustVariant([]byte(name)), ua.MustVariant(base), ua.MustVariant(histAt(i)), ua.MustVariant(sev),
		}}
	}
	all := func() []string {
		return eventIDs(t, readEvents(t, c, node, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(100), Filter: evtSelect}, nil))
	}
	severity := func(i int) uint16 {
		r := readEvents(t, c, node, &ua.ReadEventDetails{StartTime: histAt(i), EndTime: histAt(i), Filter: evtSelect}, nil)
		return r.HistoryData.Value.(*ua.HistoryEvent).Events[0].EventFields[3].Value().(uint16)
	}

	resp, err := c.HistoryUpdateEvents(ctx, &ua.UpdateEventDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeInsert, Filter: sel,
		EventData: []*ua.HistoryEventFieldList{row("i5", 5, 1), row("e1", 9, 1)}})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted, ua.StatusBadEntryExists}, resp.Results[0].OperationResults)
	require.Equal(t, []string{"e0", "e1", "e2", "i5"}, all())

	resp, err = c.HistoryUpdateEvents(ctx, &ua.UpdateEventDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeReplace, Filter: sel,
		EventData: []*ua.HistoryEventFieldList{row("e1", 1, 42), row("nope", 1, 1)}})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusBadNoEntryExists}, resp.Results[0].OperationResults)
	require.Equal(t, uint16(42), severity(1))

	resp, err = c.HistoryUpdateEvents(ctx, &ua.UpdateEventDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeUpdate, Filter: sel,
		EventData: []*ua.HistoryEventFieldList{row("e2", 2, 77), row("u6", 6, 1)}})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusGoodEntryInserted}, resp.Results[0].OperationResults)
	require.Equal(t, uint16(77), severity(2))

	resp, err = c.HistoryDeleteEvents(ctx, &ua.DeleteEventDetails{NodeID: node, EventIDs: [][]byte{[]byte("e0"), []byte("gone")}})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadNoData}, resp.Results[0].OperationResults)
	require.Equal(t, []string{"e1", "e2", "i5", "u6"}, all())

	t.Run("DetailsErrors", func(t *testing.T) {
		resp, err := c.HistoryUpdateEvents(ctx,
			&ua.UpdateEventDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeRemove, Filter: sel},
			&ua.UpdateEventDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeInsert, Filter: ua.NewEventFilter().Select("EventId").Build()},
			&ua.UpdateEventDetails{NodeID: node, PerformInsertReplace: ua.PerformUpdateTypeReplace, Filter: ua.NewEventFilter().Select("Time").Build()},
			&ua.UpdateEventDetails{NodeID: f.MethodObject, PerformInsertReplace: ua.PerformUpdateTypeInsert, Filter: sel},
		)
		require.NoError(t, err)
		got := []ua.StatusCode{}
		for _, r := range resp.Results {
			got = append(got, r.StatusCode)
		}
		require.Equal(t, []ua.StatusCode{ua.StatusBadInvalidArgument, ua.StatusBadArgumentsMissing, ua.StatusBadArgumentsMissing, ua.StatusBadHistoryOperationUnsupported}, got)
	})
}

func TestHistoryEvents_ReadOnlyNotifier(t *testing.T) {
	c, f, _, _ := setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		h := server.NewHistorian()
		h.EnableEvents(f.EventObject, 0)
		srv.SetHistorian(h)
		require.NoError(t, srv.EnableEventHistory(f.EventObject, server.EventHistoryOptions{}))
	})
	resp, err := c.HistoryDeleteEvents(context.Background(), &ua.DeleteEventDetails{NodeID: f.EventObject, EventIDs: [][]byte{{1}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNotWritable, resp.Results[0].StatusCode)

	// The EventNotifier attribute shows the history bits (Part 11 §5.4.4).
	v, err := c.Node(f.EventObject).Attribute(context.Background(), ua.AttributeIDEventNotifier)
	require.NoError(t, err)
	require.Equal(t, byte(ua.EventNotifierTypeSubscribeToEvents|ua.EventNotifierTypeHistoryRead), v.Value())

	// The HistoricalEventFilter Property (Part 11 §5.4.2) is browsable.
	res, err := c.Node(f.EventObject).TranslateBrowsePathInNamespaceToNodeID(context.Background(), 0, "HistoricalEventFilter")
	require.NoError(t, err)
	fv, err := c.Node(res).Value(context.Background())
	require.NoError(t, err)
	eo, ok := fv.Value().(*ua.ExtensionObject)
	require.True(t, ok, "%T", fv.Value())
	require.IsType(t, &ua.EventFilter{}, eo.Value)
}

func TestHistoryEvents_ServerCapabilities(t *testing.T) {
	read := func(c *opcua.Client, nid uint32) bool {
		v, err := c.Node(ua.NewNumericNodeID(0, nid)).Value(context.Background())
		require.NoError(t, err)
		return v.Value().(bool)
	}
	caps := []uint32{
		id.HistoryServerCapabilitiesAccessHistoryEventsCapability, id.HistoryServerCapabilitiesInsertEventCapability,
		id.HistoryServerCapabilitiesReplaceEventCapability, id.HistoryServerCapabilitiesUpdateEventCapability,
		id.HistoryServerCapabilitiesDeleteEventCapability, id.HistoryServerCapabilitiesAccessHistoryDataCapability,
	}
	c, _, srv, _ := setupWith(t, nil)
	for _, n := range caps {
		require.False(t, read(c, n), id.Name(n))
	}
	srv.SetHistorian(server.NewHistorian())
	for _, n := range caps {
		require.True(t, read(c, n), id.Name(n))
	}
}

// The HistoryRead of events is refused when it has more nodes than
// MaxNodesPerHistoryReadEvents.
func TestHistoryEvents_TooManyNodes(t *testing.T) {
	c, f, _, _ := eventHistorySetup(t, 1)
	nodes := make([]*ua.HistoryReadValueID, 33)
	for i := range nodes {
		nodes[i] = &ua.HistoryReadValueID{NodeID: f.EventObject}
	}
	_, err := c.HistoryReadEvent(context.Background(), nodes, &ua.ReadEventDetails{StartTime: histAt(0), EndTime: histAt(1), Filter: evtSelect})
	require.True(t, errors.Is(err, ua.StatusBadTooManyOperations), "%v", err)
}
