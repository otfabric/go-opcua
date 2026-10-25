// SPDX-License-Identifier: MIT

package subscription

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// --- filter construction helpers -------------------------------------------

func fieldOperand(name string) *ua.ExtensionObject {
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.SimpleAttributeOperandEncodingDefaultBinary),
		Value: ua.SimpleAttributeOperand{
			TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
			BrowsePath:       []*ua.QualifiedName{{Name: name}},
			AttributeID:      ua.AttributeIDValue,
		},
	}
}

// eventFilter builds an EventFilter selecting the given fields with a where
// clause made of the given elements (element 0 is the root).
func eventFilter(fields []string, where ...*ua.ContentFilterElement) *ua.ExtensionObject {
	b := ua.NewEventFilter().Select(fields...)
	f := b.Build()
	f.WhereClause = &ua.ContentFilter{Elements: where}
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.EventFilterEncodingDefaultBinary),
		Value:        f,
	}
}

// eventRig is a session with one subscription used for event tests.
type eventRig struct {
	t   *testing.T
	c   *opcua.Client
	f   *testutil.Fixture
	sub *rawSub
}

func newEventRig(t *testing.T, f *testutil.Fixture, url string) *eventRig {
	t.Helper()
	c := newClient(t, url)
	return &eventRig{t: t, c: c, f: f, sub: newRawSub(t, c, rawSubParams{})}
}

// addItem creates an event monitored item and returns its id and filter result.
func (r *eventRig) addItem(handle uint32, filter *ua.ExtensionObject) (uint32, *ua.EventFilterResult) {
	r.t.Helper()
	res := r.sub.createItems(ua.TimestampsToReturnNeither, itemSpec{
		node: r.f.EventObject, attr: ua.AttributeIDEventNotifier, handle: handle, queue: 10, discard: true, filter: filter,
	})
	require.Equal(r.t, ua.StatusOK, res[0].StatusCode)
	require.NotNil(r.t, res[0].FilterResult)
	efr, ok := res[0].FilterResult.Value.(*ua.EventFilterResult)
	require.True(r.t, ok, "FilterResult must be an EventFilterResult, got %T", res[0].FilterResult.Value)
	return res[0].MonitoredItemID, efr
}

func (r *eventRig) emit(ev *server.BaseEvent) {
	r.t.Helper()
	if ev.Time == nil {
		ev.Time = time.Now().UTC()
	}
	if ev.EventType == nil {
		ev.EventType = ua.NewNumericNodeID(0, id.BaseEventType)
	}
	require.NoError(r.t, r.f.Srv.EmitBaseEvent(r.f.EventObject, ev))
}

// collectUntil reads Publish responses until an event for sentinelHandle whose
// first field equals sentinel arrives. It returns, per client handle, the first
// field of every event received, in arrival order.
func (r *eventRig) collectUntil(sentinelHandle uint32, sentinel any) map[uint32][]any {
	r.t.Helper()
	got := map[uint32][]any{}
	done := false
	eventually(r.t, func() bool {
		for _, ev := range eventsOf(publish(r.t, r.c)) {
			require.NotEmpty(r.t, ev.EventFields)
			v := ev.EventFields[0].Value()
			got[ev.ClientHandle] = append(got[ev.ClientHandle], v)
			if ev.ClientHandle == sentinelHandle && v == sentinel {
				done = true
			}
		}
		return done
	}, "sentinel event")
	return got
}

func eventSetup(t *testing.T) (*testutil.Fixture, string) {
	t.Helper()
	srv, url := newServer(t)
	return testutil.AddFixture(t, srv), url
}

// TestEvents_SelectClauses verifies every standard BaseEventType field, a
// user-defined field and an unknown field are resolved by SelectClauses in the
// order requested.
func TestEvents_SelectClauses(t *testing.T) {
	f, url := eventSetup(t)
	rig := newEventRig(t, f, url)

	fields := []string{"EventId", "EventType", "SourceNode", "SourceName", "Time", "Message", "Severity", "AlarmLevel", "NoSuchField"}
	_, efr := rig.addItem(1, eventFilter(fields))
	require.Len(t, efr.SelectClauseResults, len(fields))
	for i, st := range efr.SelectClauseResults {
		require.Equal(t, ua.StatusOK, st, "select clause %d", i)
	}

	when := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	rig.emit(&server.BaseEvent{
		EventID:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
		EventType:  f.CustomEventType,
		SourceNode: f.EventObject,
		SourceName: "EventSource",
		Time:       when,
		Message:    ua.NewLocalizedText("boiler overheated"),
		Severity:   750,
		Fields:     map[string]*ua.Variant{"AlarmLevel": ua.MustVariant(float64(98.6))},
	})

	evs := eventsOf(publish(t, rig.c))
	require.Len(t, evs, 1)
	require.Equal(t, uint32(1), evs[0].ClientHandle)
	got := evs[0].EventFields
	require.Len(t, got, len(fields))
	require.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, got[0].Value())
	require.Equal(t, f.CustomEventType.String(), got[1].Value().(*ua.NodeID).String())
	require.Equal(t, f.EventObject.String(), got[2].Value().(*ua.NodeID).String())
	require.Equal(t, "EventSource", got[3].Value())
	require.True(t, when.Equal(got[4].Value().(time.Time)))
	require.Equal(t, "boiler overheated", got[5].Value().(*ua.LocalizedText).Text)
	require.Equal(t, uint16(750), got[6].Value())
	require.Equal(t, float64(98.6), got[7].Value())
	require.Nil(t, got[8].Value(), "an unknown field resolves to null")
}

// TestEvents_WhereClauseOperators verifies each operator the server evaluates
// for event filters by emitting a spread of severities and checking exactly
// which events pass.
func TestEvents_WhereClauseOperators(t *testing.T) {
	f, url := eventSetup(t)
	sev := func(name string) *ua.ExtensionObject { return fieldOperand(name) }
	severities := []uint16{100, 300, 500, 700, 900}

	cases := []struct {
		name  string
		where []*ua.ContentFilterElement
		want  []uint16
	}{
		{"NoWhereClause", nil, []uint16{100, 300, 500, 700, 900}},
		{"Equals", []*ua.ContentFilterElement{
			element(ua.FilterOperatorEquals, sev("Severity"), lit(uint16(500)))}, []uint16{500}},
		{"EqualsWithNumericConversion", []*ua.ContentFilterElement{
			element(ua.FilterOperatorEquals, sev("Severity"), lit(int64(500)))}, []uint16{500}},
		{"GreaterThan", []*ua.ContentFilterElement{
			element(ua.FilterOperatorGreaterThan, sev("Severity"), lit(uint16(500)))}, []uint16{700, 900}},
		{"LessThan", []*ua.ContentFilterElement{
			element(ua.FilterOperatorLessThan, sev("Severity"), lit(uint16(500)))}, []uint16{100, 300}},
		{"GreaterThanOrEqual", []*ua.ContentFilterElement{
			element(ua.FilterOperatorGreaterThanOrEqual, sev("Severity"), lit(uint16(500)))}, []uint16{500, 700, 900}},
		{"LessThanOrEqual", []*ua.ContentFilterElement{
			element(ua.FilterOperatorLessThanOrEqual, sev("Severity"), lit(uint16(500)))}, []uint16{100, 300, 500}},
		{"And", []*ua.ContentFilterElement{
			element(ua.FilterOperatorAnd, elementOperand(1), elementOperand(2)),
			element(ua.FilterOperatorGreaterThan, sev("Severity"), lit(uint16(100))),
			element(ua.FilterOperatorLessThan, sev("Severity"), lit(uint16(900)))}, []uint16{300, 500, 700}},
		{"Or", []*ua.ContentFilterElement{
			element(ua.FilterOperatorOr, elementOperand(1), elementOperand(2)),
			element(ua.FilterOperatorEquals, sev("Severity"), lit(uint16(100))),
			element(ua.FilterOperatorEquals, sev("Severity"), lit(uint16(900)))}, []uint16{100, 900}},
		{"Not", []*ua.ContentFilterElement{
			element(ua.FilterOperatorNot, elementOperand(1)),
			element(ua.FilterOperatorEquals, sev("Severity"), lit(uint16(500)))}, []uint16{100, 300, 700, 900}},
		{"NestedAndOrNot", []*ua.ContentFilterElement{
			// (sev >= 300 AND NOT(sev == 500)) OR sev == 100
			element(ua.FilterOperatorOr, elementOperand(1), elementOperand(4)),
			element(ua.FilterOperatorAnd, elementOperand(2), elementOperand(3)),
			element(ua.FilterOperatorGreaterThanOrEqual, sev("Severity"), lit(uint16(300))),
			element(ua.FilterOperatorNot, elementOperand(5)),
			element(ua.FilterOperatorEquals, sev("Severity"), lit(uint16(100))),
			element(ua.FilterOperatorEquals, sev("Severity"), lit(uint16(500)))}, []uint16{100, 300, 700, 900}},
		{"StringEquals", []*ua.ContentFilterElement{
			element(ua.FilterOperatorEquals, sev("SourceName"), lit("src-700"))}, []uint16{700}},
		{"StringOrdering", []*ua.ContentFilterElement{
			element(ua.FilterOperatorGreaterThan, sev("SourceName"), lit("src-500"))}, []uint16{700, 900}},
		{"CustomFieldComparison", []*ua.ContentFilterElement{
			// Half is severity/2 as a Double.
			element(ua.FilterOperatorLessThanOrEqual, sev("Half"), lit(float64(150)))}, []uint16{100, 300}},
		{"LiteralOnLeft", []*ua.ContentFilterElement{
			element(ua.FilterOperatorGreaterThan, lit(uint16(500)), sev("Severity"))}, []uint16{100, 300}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newEventRig(t, f, url)
			_, efr := rig.addItem(1, eventFilter([]string{"Severity"}, tc.where...))
			if efr.WhereClauseResult != nil {
				for i, er := range efr.WhereClauseResult.ElementResults {
					require.Equal(t, ua.StatusOK, er.StatusCode, "where element %d", i)
				}
			}
			// Unfiltered observer, registered second, so its copy of each event
			// is queued after the copy for the item under test.
			rig.addItem(2, eventFilter([]string{"Severity"}))

			for _, s := range severities {
				rig.emit(&server.BaseEvent{
					Severity:   s,
					SourceName: "src-" + itoa(int(s)),
					Fields:     map[string]*ua.Variant{"Half": ua.MustVariant(float64(s) / 2)},
				})
			}
			got := rig.collectUntil(2, uint16(900))

			want := make([]any, len(tc.want))
			for i, s := range tc.want {
				want[i] = s
			}
			if len(want) == 0 {
				require.Empty(t, got[1])
			} else {
				require.Equal(t, want, got[1])
			}
			require.Equal(t, []any{uint16(100), uint16(300), uint16(500), uint16(700), uint16(900)}, got[2],
				"the unfiltered observer sees every event, in order")
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestEvents_OfType verifies OfType filtering along the event type hierarchy,
// for standard and for user-defined event types.
func TestEvents_OfType(t *testing.T) {
	f, url := eventSetup(t)
	base := ua.NewNumericNodeID(0, id.BaseEventType)
	system := ua.NewNumericNodeID(0, id.SystemEventType)
	audit := ua.NewNumericNodeID(0, id.AuditEventType)

	// Events are identified by their severity.
	emitted := []struct {
		typ *ua.NodeID
		sev uint16
	}{
		{base, 1},
		{system, 2},
		{audit, 3},
		{f.CustomEventType, 4},
		{f.CustomEventSubType, 5},
	}

	for _, tc := range []struct {
		name   string
		ofType *ua.NodeID
		want   []uint16
	}{
		{"BaseEventTypeMatchesAll", base, []uint16{1, 2, 3, 4, 5}},
		{"StandardSubtype", system, []uint16{2}},
		{"CustomTypeIncludesItsSubtype", f.CustomEventType, []uint16{4, 5}},
		{"CustomLeafType", f.CustomEventSubType, []uint16{5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newEventRig(t, f, url)
			filter := ua.NewEventFilter().Select("Severity").Where(ua.OfType(tc.ofType)).Build()
			_, efr := rig.addItem(1, ua.NewExtensionObject(filter))
			require.Len(t, efr.WhereClauseResult.ElementResults, 1)
			require.Equal(t, ua.StatusOK, efr.WhereClauseResult.ElementResults[0].StatusCode)
			require.Equal(t, []ua.StatusCode{ua.StatusOK}, efr.WhereClauseResult.ElementResults[0].OperandStatusCodes)
			rig.addItem(2, eventFilter([]string{"Severity"}))

			for _, e := range emitted {
				rig.emit(&server.BaseEvent{EventType: e.typ, Severity: e.sev})
			}
			got := rig.collectUntil(2, uint16(5))
			want := make([]any, len(tc.want))
			for i, s := range tc.want {
				want[i] = s
			}
			require.Equal(t, want, got[1])
		})
	}

	t.Run("CombinedWithSeverity", func(t *testing.T) {
		rig := newEventRig(t, f, url)
		rig.addItem(1, eventFilter([]string{"Severity"},
			element(ua.FilterOperatorAnd, elementOperand(1), elementOperand(2)),
			element(ua.FilterOperatorOfType, lit(f.CustomEventType)),
			element(ua.FilterOperatorGreaterThan, fieldOperand("Severity"), lit(uint16(4))),
		))
		rig.addItem(2, eventFilter([]string{"Severity"}))
		for _, e := range emitted {
			rig.emit(&server.BaseEvent{EventType: e.typ, Severity: e.sev})
		}
		got := rig.collectUntil(2, uint16(5))
		require.Equal(t, []any{uint16(5)}, got[1])
	})
}

// TestEvents_FilterValidation verifies the EventFilterResult and status codes
// returned for malformed or unsupported filters.
func TestEvents_FilterValidation(t *testing.T) {
	f, url := eventSetup(t)
	rig := newEventRig(t, f, url)

	create := func(filter *ua.ExtensionObject) *ua.MonitoredItemCreateResult {
		return rig.sub.createItems(ua.TimestampsToReturnNeither, itemSpec{
			node: f.EventObject, attr: ua.AttributeIDEventNotifier, handle: 1, queue: 1, filter: filter,
		})[0]
	}

	t.Run("NoSelectClauses", func(t *testing.T) {
		res := create(eventFilter(nil))
		require.Equal(t, ua.StatusBadEventFilterInvalid, res.StatusCode)
		require.Zero(t, res.MonitoredItemID)
	})

	t.Run("NotAnEventFilter", func(t *testing.T) {
		res := create(ua.NewExtensionObject(&ua.DataChangeFilter{Trigger: ua.DataChangeTriggerStatusValue}))
		require.Equal(t, ua.StatusBadEventFilterInvalid, res.StatusCode)
	})

	whereResult := func(where ...*ua.ContentFilterElement) []*ua.ContentFilterElementResult {
		t.Helper()
		_, efr := rig.addItem(9, eventFilter([]string{"Severity"}, where...))
		require.NotNil(t, efr.WhereClauseResult)
		require.Len(t, efr.WhereClauseResult.ElementResults, len(where))
		return efr.WhereClauseResult.ElementResults
	}

	t.Run("OperandCountMismatch", func(t *testing.T) {
		for _, el := range []*ua.ContentFilterElement{
			element(ua.FilterOperatorEquals, fieldOperand("Severity")),
			element(ua.FilterOperatorOfType),
			element(ua.FilterOperatorAnd, elementOperand(0)),
			element(ua.FilterOperatorNot, elementOperand(0), elementOperand(0)),
		} {
			res := whereResult(el)
			require.Equal(t, ua.StatusBadFilterOperandCountMismatch, res[0].StatusCode, "operator %v", el.FilterOperator)
		}
	})

	t.Run("OfTypeUnknownType", func(t *testing.T) {
		res := whereResult(element(ua.FilterOperatorOfType, lit(ua.NewNumericNodeID(0, id.Server))))
		require.Equal(t, ua.StatusBadFilterOperandInvalid, res[0].StatusCode)
		require.Equal(t, []ua.StatusCode{ua.StatusBadFilterOperandInvalid}, res[0].OperandStatusCodes)

		res = whereResult(element(ua.FilterOperatorOfType, lit(f.Int32)))
		require.Equal(t, ua.StatusBadFilterOperandInvalid, res[0].StatusCode, "a variable is not an event type")

		res = whereResult(element(ua.FilterOperatorOfType, lit("not a node id")))
		require.Equal(t, ua.StatusBadFilterOperandInvalid, res[0].StatusCode)
	})

	t.Run("UnsupportedOperatorReported", func(t *testing.T) {
		res := whereResult(
			element(ua.FilterOperatorLike, fieldOperand("SourceName"), lit("src%")),
			element(ua.FilterOperatorEquals, fieldOperand("Severity"), lit(uint16(1))),
		)
		require.Equal(t, ua.StatusBadFilterOperatorUnsupported, res[0].StatusCode)
		require.Equal(t, ua.StatusOK, res[1].StatusCode)
	})
}

// TestEvents_ModifyFilter verifies ModifyMonitoredItems replaces the event
// filter (select and where clauses) of a live item.
func TestEvents_ModifyFilter(t *testing.T) {
	f, url := eventSetup(t)
	rig := newEventRig(t, f, url)
	id1, _ := rig.addItem(1, eventFilter([]string{"Severity"}))
	rig.addItem(2, eventFilter([]string{"Severity"}))

	rig.emit(&server.BaseEvent{Severity: 10, Message: ua.NewLocalizedText("first")})
	got := rig.collectUntil(2, uint16(10))
	require.Equal(t, []any{uint16(10)}, got[1])

	// New filter: select Message first, only severities above 500, new handle.
	res := mustSendRaw[ua.ModifyMonitoredItemsResponse](t, rig.c, &ua.ModifyMonitoredItemsRequest{
		SubscriptionID:     rig.sub.id,
		TimestampsToReturn: ua.TimestampsToReturnNeither,
		ItemsToModify: []*ua.MonitoredItemModifyRequest{{
			MonitoredItemID: id1,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle: 7,
				QueueSize:    10,
				Filter: eventFilter([]string{"Message", "Severity"},
					element(ua.FilterOperatorGreaterThan, fieldOperand("Severity"), lit(uint16(500)))),
			},
		}},
	})
	require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)

	rig.emit(&server.BaseEvent{Severity: 400, Message: ua.NewLocalizedText("filtered out")})
	rig.emit(&server.BaseEvent{Severity: 600, Message: ua.NewLocalizedText("passes")})

	var mine []*ua.EventFieldList
	done := false
	eventually(t, func() bool {
		for _, ev := range eventsOf(publish(t, rig.c)) {
			switch ev.ClientHandle {
			case 7:
				mine = append(mine, ev)
			case 1:
				t.Fatalf("event delivered with the pre-modify client handle")
			case 2:
				if ev.EventFields[0].Value() == uint16(600) {
					done = true
				}
			}
		}
		return done
	}, "observer saw the last event")
	require.Len(t, mine, 1)
	require.Len(t, mine[0].EventFields, 2)
	require.Equal(t, "passes", mine[0].EventFields[0].Value().(*ua.LocalizedText).Text)
	require.Equal(t, uint16(600), mine[0].EventFields[1].Value())
}

// TestEvents_MonitoringModeAndDelete verifies event items honour the
// monitoring mode and stop reporting once deleted.
func TestEvents_MonitoringModeAndDelete(t *testing.T) {
	f, url := eventSetup(t)
	rig := newEventRig(t, f, url)
	id1, _ := rig.addItem(1, eventFilter([]string{"Severity"}))
	rig.addItem(2, eventFilter([]string{"Severity"}))

	rig.emit(&server.BaseEvent{Severity: 1})
	require.Equal(t, []any{uint16(1)}, rig.collectUntil(2, uint16(1))[1])

	require.Equal(t, []ua.StatusCode{ua.StatusOK}, rig.sub.setMode(ua.MonitoringModeDisabled, id1))
	rig.emit(&server.BaseEvent{Severity: 2})
	require.Empty(t, rig.collectUntil(2, uint16(2))[1], "disabled event item must not report")

	require.Equal(t, []ua.StatusCode{ua.StatusOK}, rig.sub.setMode(ua.MonitoringModeReporting, id1))
	rig.emit(&server.BaseEvent{Severity: 3})
	require.Equal(t, []any{uint16(3)}, rig.collectUntil(2, uint16(3))[1])

	del := mustSendRaw[ua.DeleteMonitoredItemsResponse](t, rig.c, &ua.DeleteMonitoredItemsRequest{
		SubscriptionID: rig.sub.id, MonitoredItemIDs: []uint32{id1},
	})
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, del.Results)
	eventually(t, func() bool {
		return rig.sub.setMode(ua.MonitoringModeReporting, id1)[0] == ua.StatusBadMonitoredItemIDInvalid
	}, "event item deleted")
	rig.emit(&server.BaseEvent{Severity: 4})
	require.Empty(t, rig.collectUntil(2, uint16(4))[1], "deleted event item must not report")
}

// TestEvents_OrderingAndMixedNotifications verifies events keep their emission
// order within one Publish response, and that data changes and events of the
// same subscription travel in the same notification message.
func TestEvents_OrderingAndMixedNotifications(t *testing.T) {
	f, url := eventSetup(t)
	rig := newEventRig(t, f, url)
	rig.sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 50, queue: 1, discard: true})
	rig.sub.primeItem(int32(42))
	rig.addItem(1, eventFilter([]string{"Severity", "Message"}))

	// Hold publishing back so everything accumulates into one message.
	rig.sub.setPublishing(false)
	for i := uint16(1); i <= 20; i++ {
		rig.emit(&server.BaseEvent{Severity: i, Message: ua.NewLocalizedText("event " + itoa(int(i)))})
	}
	writeInt32(t, rig.c, f.Int32, 4242)
	rig.sub.setPublishing(true)

	var p *ua.PublishResponse
	eventually(t, func() bool { p = publish(t, rig.c); return !isKeepAlive(p) }, "combined notification")

	require.Len(t, p.NotificationMessage.NotificationData, 2, "one DataChangeNotification and one EventNotificationList")
	_, isData := p.NotificationMessage.NotificationData[0].Value.(*ua.DataChangeNotification)
	_, isEvents := p.NotificationMessage.NotificationData[1].Value.(*ua.EventNotificationList)
	require.True(t, isData)
	require.True(t, isEvents)

	require.Equal(t, []any{int32(4242)}, values(dataOf(t, p)))
	evs := eventsOf(p)
	require.Len(t, evs, 20)
	for i, ev := range evs {
		require.Equal(t, uint32(1), ev.ClientHandle)
		require.Equal(t, uint16(i+1), ev.EventFields[0].Value())
		require.Equal(t, "event "+itoa(i+1), ev.EventFields[1].Value().(*ua.LocalizedText).Text)
	}
}

// TestEvents_FanOutAcrossSessions verifies one emitted event reaches every
// subscription monitoring the source, each with its own select clauses, and
// that other event sources are not affected.
func TestEvents_FanOutAcrossSessions(t *testing.T) {
	f, url := eventSetup(t)
	a := newEventRig(t, f, url)
	b := newEventRig(t, f, url)
	a.addItem(1, eventFilter([]string{"Severity"}))
	b.addItem(2, eventFilter([]string{"Message", "SourceName"}))

	// A monitored item on a different notifier must stay silent.
	other := newEventRig(t, f, url)
	res := other.sub.createItems(ua.TimestampsToReturnNeither, itemSpec{
		node: f.Plant, attr: ua.AttributeIDEventNotifier, handle: 3, queue: 1, filter: eventFilter([]string{"Severity"}),
	})
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	otherKeepAlive := mustSendRaw[ua.ModifySubscriptionResponse](t, other.c, &ua.ModifySubscriptionRequest{
		SubscriptionID: other.sub.id, RequestedPublishingInterval: 10, RequestedMaxKeepAliveCount: 1, RequestedLifetimeCount: 1000,
	})
	require.Equal(t, uint32(1), otherKeepAlive.RevisedMaxKeepAliveCount)

	a.emit(&server.BaseEvent{Severity: 321, Message: ua.NewLocalizedText("fan-out"), SourceName: "src"})

	ea := eventsOf(publish(t, a.c))
	require.Len(t, ea, 1)
	require.Equal(t, uint32(1), ea[0].ClientHandle)
	require.Equal(t, uint16(321), ea[0].EventFields[0].Value())

	eb := eventsOf(publish(t, b.c))
	require.Len(t, eb, 1)
	require.Equal(t, uint32(2), eb[0].ClientHandle)
	require.Equal(t, "fan-out", eb[0].EventFields[0].Value().(*ua.LocalizedText).Text)
	require.Equal(t, "src", eb[0].EventFields[1].Value())

	for i := 0; i < 3; i++ {
		require.True(t, isKeepAlive(publish(t, other.c)), "an unrelated notifier must not receive the event")
	}
}

// TestEvents_BuilderAndHighLevelAPI drives events through the client's
// subscription builder and the ua.EventFilter builder.
func TestEvents_BuilderAndHighLevelAPI(t *testing.T) {
	c, f, ctx := setup(t)

	filter := ua.NewEventFilter().
		Select("Message", "Severity").
		Where(ua.Field("Severity").GreaterThan(uint16(500))).
		Build()
	sub, ch, err := c.NewSubscription().
		Interval(fastInterval).
		MonitorEvents(filter, f.EventObject).
		Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	for _, s := range []uint16{100, 600, 400, 900} {
		require.NoError(t, f.Srv.EmitBaseEvent(f.EventObject, &server.BaseEvent{
			EventType: ua.NewNumericNodeID(0, id.BaseEventType),
			Time:      time.Now().UTC(),
			Severity:  s,
			Message:   ua.NewLocalizedText("sev " + itoa(int(s))),
		}))
	}

	var got []uint16
	for len(got) < 2 {
		for _, ev := range nextEvents(t, ch) {
			require.Len(t, ev.EventFields, 2)
			sev := ev.EventFields[1].Value().(uint16)
			require.Equal(t, "sev "+itoa(int(sev)), ev.EventFields[0].Value().(*ua.LocalizedText).Text)
			got = append(got, sev)
		}
	}
	require.Equal(t, []uint16{600, 900}, got)
}
