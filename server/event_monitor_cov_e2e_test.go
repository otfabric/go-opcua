// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestEventMonitorCovOfTypeOverTheWire subscribes to events with an OfType
// filter on a user-defined event type hierarchy and checks that the server
// validates the filter and delivers only events of that type or a subtype.
func TestEventMonitorCovOfTypeOverTheWire(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	ns := server.NewNodeNameSpace(srv, "urn:cov:events")
	mk := func(name string, class ua.NodeClass, extra map[ua.AttributeID]*ua.DataValue) *server.Node {
		a := map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:   server.DataValueFromValue(uint32(class)),
			ua.AttributeIDBrowseName:  server.DataValueFromValue(attrs.BrowseName(name)),
			ua.AttributeIDDisplayName: server.DataValueFromValue(attrs.DisplayName(name, "en")),
		}
		for k, v := range extra {
			a[k] = v
		}
		n := server.NewNode(ua.NewStringNodeID(ns.ID(), name), a, nil, nil)
		ns.AddNode(n)
		return n
	}
	source := mk("Source", ua.NodeClassObject, map[ua.AttributeID]*ua.DataValue{
		ua.AttributeIDEventNotifier: server.DataValueFromValue(byte(1)),
	})
	other := mk("OtherSource", ua.NodeClassObject, map[ua.AttributeID]*ua.DataValue{
		ua.AttributeIDEventNotifier: server.DataValueFromValue(byte(1)),
	})
	tank := mk("TankEventType", ua.NodeClassObjectType, nil)
	overflow := mk("TankOverflowEventType", ua.NodeClassObjectType, nil)
	tank.AddRef(overflow, id.HasSubtype, true)
	variable := ns.AddNewVariableStringNode("NotAType", int32(1))
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })

	c := testutil.NewTestClient(t, srv.Endpoints()[0].EndpointURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	notifyCh := make(chan *opcua.PublishNotificationData, 32)
	sub, _, err := c.NewSubscription().Interval(20 * time.Millisecond).NotifyChannel(notifyCh).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	monitor := func(node *ua.NodeID, handle uint32, f *ua.EventFilter) *ua.MonitoredItemCreateResult {
		t.Helper()
		res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
			ItemToMonitor:  &ua.ReadValueID{NodeID: node, AttributeID: ua.AttributeIDEventNotifier},
			MonitoringMode: ua.MonitoringModeReporting,
			RequestedParameters: &ua.MonitoringParameters{
				ClientHandle: handle, Filter: ua.NewExtensionObject(f), QueueSize: 10, DiscardOldest: true,
			},
		})
		require.NoError(t, err)
		require.Len(t, res.Results, 1)
		return res.Results[0]
	}

	good := monitor(source.ID(), 1, ua.NewEventFilter().
		Select("EventId", "EventType", "SourceNode", "Time", "Severity").
		Where(ua.OfType(tank.ID())).Build())
	require.Equal(t, ua.StatusOK, good.StatusCode)

	// OfType a node that is not an ObjectType, and one that does not exist:
	// the filter is accepted with the element results telling why.
	bad := monitor(other.ID(), 2, &ua.EventFilter{
		SelectClauses: []*ua.SimpleAttributeOperand{{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}}},
		WhereClause: &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
			ua.OfType(variable.ID()),
			ua.OfType(ua.NewStringNodeID(ns.ID(), "Missing")),
		}},
	})
	require.Equal(t, ua.StatusOK, bad.StatusCode)
	efr, ok := bad.FilterResult.Value.(*ua.EventFilterResult)
	require.True(t, ok, "FilterResult is %T", bad.FilterResult.Value)
	require.Len(t, efr.WhereClauseResult.ElementResults, 2)
	for _, er := range efr.WhereClauseResult.ElementResults {
		require.Equal(t, ua.StatusBadFilterOperandInvalid, er.StatusCode)
	}

	emit := func(evID string, typ *ua.NodeID) {
		t.Helper()
		require.NoError(t, srv.EmitBaseEvent(source.ID(), &server.BaseEvent{
			EventID: []byte(evID), EventType: typ, SourceNode: source.ID(), SourceName: "Source",
			Time: time.Now(), Message: ua.NewLocalizedText(evID), Severity: 100,
		}))
	}
	// Events are delivered in order: if the unrelated events got through,
	// they would arrive before the matching one.
	emit("base", ua.NewNumericNodeID(0, id.BaseEventType))
	emit("system", ua.NewNumericNodeID(0, id.SystemEventType))
	emit("overflow", overflow.ID())

	var ids []string
	var fields []*ua.Variant
	for len(ids) == 0 {
		select {
		case msg := <-notifyCh:
			require.NoError(t, msg.Error)
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, ev := range enl.Events {
				require.Equal(t, uint32(1), ev.ClientHandle)
				ids = append(ids, string(ev.EventFields[0].Value().([]byte)))
				fields = ev.EventFields
			}
		case <-ctx.Done():
			t.Fatal("timeout waiting for the event")
		}
	}
	require.Equal(t, []string{"overflow"}, ids)
	require.Len(t, fields, 5)
	require.True(t, overflow.ID().Equal(fields[1].Value().(*ua.NodeID)))
	require.True(t, source.ID().Equal(fields[2].Value().(*ua.NodeID)))
	require.IsType(t, time.Time{}, fields[3].Value())
	require.Equal(t, uint16(100), fields[4].Value())
}
