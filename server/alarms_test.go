// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func TestAlarmsConditionsSupported(t *testing.T) {
	require.True(t, AlarmsConditionsSupported())
	require.Equal(t, uint32(id.AcknowledgeableConditionType), AcknowledgeableConditionTypeNodeID.IntID())
}

// alarmTestServer is a server without network with a source node.
func alarmTestServer(t *testing.T) (*Server, *NodeNameSpace, *Node) {
	t.Helper()
	s := newTestServer()
	ns := NewNodeNameSpace(s, "urn:test:alarms")
	src := NewFolderNode(ua.NewStringNodeID(ns.ID(), "Pump"), "Pump")
	ns.AddNode(src)
	ns.Objects().AddRef(src, RefTypeIDOrganizes, true)
	return s, ns, src
}

func TestAddConditionErrors(t *testing.T) {
	s, ns, src := alarmTestServer(t)
	for name, cfg := range map[string]ConditionConfig{
		"no source":      {Name: "A"},
		"no name":        {Source: src.ID()},
		"unknown source": {Name: "A", Source: ua.NewStringNodeID(ns.ID(), "nope")},
		"not a condition type": {Name: "A", Source: src.ID(),
			Type: ua.NewNumericNodeID(0, id.BaseEventType)},
		"ns0 source without namespace": {Name: "A", Source: ua.NewNumericNodeID(0, id.Server)},
	} {
		_, err := s.AddCondition(cfg)
		require.Error(t, err, name)
	}
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), NodeID: ua.NewStringNodeID(ns.ID(), "A")})
	require.NoError(t, err)
	_, err = s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), NodeID: c.NodeID()})
	require.Error(t, err, "the node exists")
	require.Equal(t, "A", c.Name())
	require.True(t, c.Source().Equal(src.ID()))
	require.Equal(t, uint32(id.AlarmConditionType), c.TypeID().IntID(), "default type")

	got, ok := s.Condition(c.NodeID())
	require.True(t, ok)
	require.Same(t, c, got)
	_, ok = s.Condition(nil)
	require.False(t, ok)
	require.Len(t, s.Conditions(), 1)

	require.Error(t, s.RemoveCondition(ua.NewStringNodeID(ns.ID(), "nope")))
	require.NoError(t, s.RemoveCondition(c.NodeID()))
	require.Nil(t, s.Node(c.NodeID()))
	require.ErrorIs(t, c.SetActive(true), ErrConditionRemoved)
	require.Equal(t, ua.StatusBadNodeIDUnknown, c.setEnabled(false))
}

// A condition of the Server object (namespace 0) works on this server's own
// copy of the node.
func TestAddConditionOnServerObject(t *testing.T) {
	s, ns, _ := alarmTestServer(t)
	shared := s.Node(ua.NewNumericNodeID(0, id.Server))
	c, err := s.AddCondition(ConditionConfig{Name: "System", Source: ua.NewNumericNodeID(0, id.Server), Namespace: ns,
		ConditionClassID: ua.NewNumericNodeID(0, id.SystemConditionClassType)})
	require.NoError(t, err)
	require.Len(t, c.targets, 1)
	require.Equal(t, "Server", c.sourceName)
	require.Equal(t, "SystemConditionClassType", c.className.Text)
	require.False(t, hasForwardRef(shared, c.NodeID(), id.HasCondition), "the shared node is not changed")
	require.True(t, hasForwardRef(s.Node(ua.NewNumericNodeID(0, id.Server)), c.NodeID(), id.HasCondition))
}

func TestConditionUpdateChecks(t *testing.T) {
	s, _, src := alarmTestServer(t)
	plain, err := s.AddCondition(ConditionConfig{Name: "Plain", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.ConditionType)})
	require.NoError(t, err)
	ack, err := s.AddCondition(ConditionConfig{Name: "Ack", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)})
	require.NoError(t, err)
	alarm, err := s.AddCondition(ConditionConfig{Name: "Alarm", Source: src.ID()})
	require.NoError(t, err)

	tr, l, n := true, LimitHigh, NonExclusiveLimits{}
	require.ErrorIs(t, plain.SetActive(true), ErrConditionNotAlarm)
	require.ErrorIs(t, plain.SetSuppressed(true), ErrConditionNotAlarm)
	require.ErrorIs(t, plain.Update(ConditionUpdate{Acked: &tr}), ErrConditionUnsupport)
	require.ErrorIs(t, ack.Update(ConditionUpdate{Confirmed: &tr}), ErrConditionUnsupport)
	require.ErrorIs(t, alarm.SetSuppressed(true), ErrConditionUnsupport)
	require.ErrorIs(t, ack.SetRetain(true), ErrConditionUnsupport)
	require.ErrorIs(t, alarm.Update(ConditionUpdate{Limit: &l}), ErrConditionUnsupport)
	require.ErrorIs(t, alarm.Update(ConditionUpdate{NonExclusiveLimits: &n}), ErrConditionUnsupport)
	require.ErrorIs(t, alarm.EvaluateLimits(1), ErrConditionUnsupport)

	// ConditionType: the application sets Retain.
	require.False(t, plain.State().Retain)
	require.NoError(t, plain.SetRetain(true))
	require.True(t, plain.State().Retain)

	// AcknowledgeableConditionType: an unacknowledged state is retained.
	f := false
	require.NoError(t, ack.Update(ConditionUpdate{Acked: &f}))
	require.True(t, ack.State().Retain)

	require.NoError(t, alarm.SetQuality(ua.StatusUncertain))
	require.NoError(t, alarm.SetMessage("m"))
	require.NoError(t, alarm.SetSeverity(800))
	require.NoError(t, alarm.Report())
	st := alarm.State()
	require.Equal(t, ua.StatusUncertain, st.Quality)
	require.Equal(t, "m", st.Message.Text)
	require.Equal(t, uint16(800), st.Severity)
	require.Equal(t, uint16(500), st.LastSeverity)

	require.ErrorIs(t, alarm.Enable(), ua.StatusBadConditionAlreadyEnabled)
	require.NoError(t, alarm.Disable())
	require.ErrorIs(t, alarm.Disable(), ua.StatusBadConditionAlreadyDisabled)
	require.NoError(t, alarm.SetActive(true), "a disabled condition takes changes")
	require.False(t, alarm.State().Retain, "a disabled condition is not retained")
	require.NoError(t, alarm.Enable())
	require.True(t, alarm.State().Retain)
}

func TestConditionLimits(t *testing.T) {
	s, _, src := alarmTestServer(t)
	hh, h, lo, ll := 100.0, 80.0, 20.0, 0.0
	limits := AlarmLimits{HighHigh: &hh, High: &h, Low: &lo, LowLow: &ll}
	ex, err := s.AddCondition(ConditionConfig{Name: "Ex", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.ExclusiveLimitAlarmType), Limits: limits})
	require.NoError(t, err)
	for v, want := range map[float64]LimitState{150: LimitHighHigh, 90: LimitHigh, 50: LimitNone, 10: LimitLow, -5: LimitLowLow} {
		require.NoError(t, ex.EvaluateLimits(v))
		require.Equal(t, want, ex.State().Limit, "%v", v)
		require.Equal(t, want != LimitNone, ex.State().Active)
	}
	// LowLow -> Low is a transition of the state machine (the map order
	// above is random: start from LowLow).
	require.NoError(t, ex.EvaluateLimits(-5))
	require.NoError(t, ex.EvaluateLimits(10))
	ex.mu.RLock()
	ev := ex.eventLocked()
	ex.mu.RUnlock()
	require.Equal(t, ua.NewNumericNodeID(0, id.ExclusiveLimitStateMachineTypeLowLowToLow), ev.Fields["LimitState/LastTransition/Id"].Value())
	require.Equal(t, "LowLowToLow", ev.Fields["LimitState/LastTransition"].Value().(*ua.LocalizedText).Text)
	require.Equal(t, 80.0, ev.Fields["HighLimit"].Value())

	nx, err := s.AddCondition(ConditionConfig{Name: "Nx", Source: src.ID(), Type: ua.NewNumericNodeID(0, id.NonExclusiveLimitAlarmType), Limits: AlarmLimits{High: &h, Low: &lo}})
	require.NoError(t, err)
	require.NoError(t, nx.EvaluateLimits(90))
	require.Equal(t, NonExclusiveLimits{High: true}, nx.State().NonExclusiveLimits)
	require.True(t, nx.State().Active)
	nx.mu.RLock()
	ev = nx.eventLocked()
	nx.mu.RUnlock()
	require.Contains(t, ev.Fields, "HighState/Id")
	require.NotContains(t, ev.Fields, "HighHighState/Id", "no HighHigh limit configured")
	require.NoError(t, nx.EvaluateLimits(50))
	require.False(t, nx.State().Active)
}

func TestShelvingAndLimitNames(t *testing.T) {
	for st, want := range map[ShelvingState]string{Unshelved: "Unshelved", TimedShelved: "TimedShelved", OneShotShelved: "OneShotShelved"} {
		require.Equal(t, want, st.String())
		require.NotZero(t, st.stateID())
	}
	for l, want := range map[LimitState]string{LimitNone: "", LimitHighHigh: "HighHigh", LimitHigh: "High", LimitLow: "Low", LimitLowLow: "LowLow"} {
		require.Equal(t, want, l.String())
		require.Equal(t, l == LimitNone, l.stateID() == 0)
	}
	states := []ShelvingState{Unshelved, TimedShelved, OneShotShelved}
	for _, a := range states {
		for _, b := range states {
			require.Equal(t, a == b, shelvingTransitionID(a, b) == 0, "%v -> %v", a, b)
		}
	}
	require.Zero(t, exclusiveLimitTransitionID(LimitNone, LimitHigh))
	require.NotZero(t, exclusiveLimitTransitionID(LimitLow, LimitLowLow))
	require.NotZero(t, exclusiveLimitTransitionID(LimitHighHigh, LimitHigh))
	require.NotZero(t, exclusiveLimitTransitionID(LimitHigh, LimitHighHigh))
}

func callerCtx(tok ua.IdentityToken) context.Context {
	return context.WithValue(context.Background(), methodCallerKey{}, &MethodCaller{SessionID: ua.NewNumericNodeID(1, 1), Identity: tok})
}

func TestClientUserID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	require.Equal(t, "", clientUserID(context.Background()))
	require.Equal(t, "Anonymous", clientUserID(callerCtx(&ua.AnonymousIdentityToken{})))
	require.Equal(t, "bob", clientUserID(callerCtx(&ua.UserNameIdentityToken{UserName: "bob"})))
	require.Equal(t, "CN=operator", clientUserID(callerCtx(&ua.X509IdentityToken{CertificateData: der})))
	require.Equal(t, "X509", clientUserID(callerCtx(&ua.X509IdentityToken{CertificateData: []byte{1}})))
	require.Equal(t, "IssuedToken", clientUserID(callerCtx(&ua.IssuedIdentityToken{})))
}

func TestConditionMethodArguments(t *testing.T) {
	s, _, src := alarmTestServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), Shelving: true, Confirmable: true})
	require.NoError(t, err)
	ctx := callerCtx(nil)
	ack := c.actionMethod(actionAcknowledge)
	for name, args := range map[string][]*ua.Variant{
		"none":         nil,
		"nil":          {nil, nil},
		"bad event id": {ua.MustVariant("x"), ua.MustVariant(ua.NewLocalizedText(""))},
		"bad comment":  {ua.MustVariant([]byte{1}), ua.MustVariant(int32(1))},
	} {
		_, sc := ack(ctx, nil, nil, args)
		require.NotEqual(t, ua.StatusOK, sc, name)
	}
	// A null Comment variant is accepted.
	_, sc := ack(ctx, nil, nil, []*ua.Variant{ua.MustVariant(c.State().EventID), ua.MustVariant(nil)})
	require.Equal(t, ua.StatusBadConditionBranchAlreadyAcked, sc, "an inactive alarm is acknowledged")

	timed := c.shelveMethod(TimedShelved)
	for name, args := range map[string][]*ua.Variant{
		"none":     nil,
		"type":     {ua.MustVariant("x")},
		"negative": {ua.MustVariant(-1.0)},
		"huge":     {ua.MustVariant(1e300)},
	} {
		_, sc := timed(ctx, nil, nil, args)
		require.NotEqual(t, ua.StatusOK, sc, name)
	}

	_, sc = s.conditionRefreshMethod(ctx, nil, nil, nil)
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	_, sc = s.conditionRefreshMethod(ctx, nil, nil, []*ua.Variant{ua.MustVariant("x")})
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = s.conditionRefresh2Method(ctx, nil, nil, nil)
	require.Equal(t, ua.StatusBadArgumentsMissing, sc)
	_, sc = s.conditionRefresh2Method(ctx, nil, nil, []*ua.Variant{ua.MustVariant("x"), ua.MustVariant(uint32(1))})
	require.Equal(t, ua.StatusBadTypeMismatch, sc)
	_, sc = s.conditionRefreshMethod(ctx, nil, nil, []*ua.Variant{ua.MustVariant(uint32(99))})
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, sc)
	_, sc = s.conditionRefresh2Method(context.Background(), nil, nil, []*ua.Variant{ua.MustVariant(uint32(1)), ua.MustVariant(uint32(1))})
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, sc, "no caller")

	// The removed condition refuses its methods.
	require.NoError(t, s.RemoveCondition(c.NodeID()))
	_, sc = c.enableMethod(false)(ctx, nil, nil, nil)
	require.Equal(t, ua.StatusBadNodeIDUnknown, sc)
	_, sc = c.shelveMethod(OneShotShelved)(ctx, nil, nil, nil)
	require.Equal(t, ua.StatusBadNodeIDUnknown, sc)
	_, sc = ack(ctx, nil, nil, []*ua.Variant{ua.MustVariant([]byte{1}), ua.MustVariant(nil)})
	require.Equal(t, ua.StatusBadNodeIDUnknown, sc)
}

// The condition methods go through the access control of the Call service.
func TestConditionMethodsAccessControl(t *testing.T) {
	s, _, src := alarmTestServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID()})
	require.NoError(t, err)
	require.NoError(t, c.SetActive(true))
	s.cfg.accessController = readOnlyController{}
	svc := &MethodService{srv: s}
	resp, err := svc.Call(context.Background(), nil, &ua.CallRequest{RequestHeader: reqHeader(), MethodsToCall: []*ua.CallMethodRequest{{
		ObjectID: c.NodeID(), MethodID: ua.NewNumericNodeID(0, id.AcknowledgeableConditionTypeAcknowledge),
		InputArguments: []*ua.Variant{ua.MustVariant(c.State().EventID), ua.MustVariant(ua.NewLocalizedText(""))},
	}}}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadUserAccessDenied, resp.(*ua.CallResponse).Results[0].StatusCode)
	require.False(t, c.State().Acked)
}

// The event of a condition resolves multi-segment paths and the
// ConditionId.
func TestConditionEventFields(t *testing.T) {
	s, _, src := alarmTestServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), InputNode: src.ID()})
	require.NoError(t, err)
	c.mu.RLock()
	ev := c.eventLocked()
	c.mu.RUnlock()
	clauses := []*ua.SimpleAttributeOperand{
		{BrowsePath: []*ua.QualifiedName{{Name: "AckedState"}, {Name: "Id"}}, AttributeID: ua.AttributeIDValue},
		{AttributeID: ua.AttributeIDNodeID},
		{AttributeID: ua.AttributeIDValue},
		nil,
		{BrowsePath: []*ua.QualifiedName{nil, {Name: "Id"}}, AttributeID: ua.AttributeIDValue},
		{BrowsePath: []*ua.QualifiedName{{Name: "InputNode"}}, AttributeID: ua.AttributeIDValue},
	}
	got := selectEventFields(ev, clauses)
	require.Equal(t, true, got[0].Value())
	require.Equal(t, c.NodeID(), got[1].Value())
	require.Nil(t, got[2].Value())
	require.Nil(t, got[3].Value())
	require.Nil(t, got[4].Value())
	require.Equal(t, src.ID(), got[5].Value())
	// No ConditionId on other events.
	require.Nil(t, resolveEventClause(&BaseEvent{}, &ua.SimpleAttributeOperand{AttributeID: ua.AttributeIDNodeID}).Value())

	// The OfType of a namespace 0 alarm type is a known event type.
	require.True(t, s.isKnownEventType(ua.NewNumericNodeID(0, id.OffNormalAlarmType)))
	require.True(t, s.isKnownEventType(ua.NewNumericNodeID(0, id.RefreshStartEventType)))
	require.False(t, s.isKnownEventType(ua.NewNumericNodeID(0, id.FolderType)))
}

func TestAlarmManagerClose(t *testing.T) {
	s, _, src := alarmTestServer(t)
	c, err := s.AddCondition(ConditionConfig{Name: "A", Source: src.ID(), Shelving: true})
	require.NoError(t, err)
	require.NoError(t, c.SetActive(true))
	_, sc := c.shelveMethod(TimedShelved)(callerCtx(nil), nil, nil, []*ua.Variant{ua.MustVariant(60_000.0)})
	require.Equal(t, ua.StatusOK, sc)
	s.alarms.close()
	c.mu.RLock()
	timer := c.st.shelveTimer
	c.mu.RUnlock()
	require.Nil(t, timer)
	// An expired timer of an old generation does nothing.
	c.shelveExpired(0)
	require.Equal(t, TimedShelved, c.State().Shelving)
}

// The events of conditions wait for room in a full subscription queue; other
// events are dropped.
func TestDeliverToItemFullQueue(t *testing.T) {
	s := newTestServer()
	sub := &Subscription{EventNotifyChannel: make(chan *ua.EventFieldList), shutdown: make(chan struct{})}
	item := &MonitoredItem{ID: 1, Sub: sub, Req: &ua.MonitoredItemCreateRequest{RequestedParameters: &ua.MonitoringParameters{ClientHandle: 9}}}
	s.eventItems.register(1, &EventMonitoredItem{SelectClauses: []*ua.SimpleAttributeOperand{{BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}}}})
	ev := &BaseEvent{Severity: 7}

	s.deliverToItem(item, ev, false, false) // nobody reads: dropped

	got := make(chan *ua.EventFieldList)
	go func() { got <- <-sub.EventNotifyChannel }()
	s.deliverToItem(item, ev, false, true)
	ef := <-got
	require.Equal(t, uint32(9), ef.ClientHandle)
	require.Equal(t, uint16(7), ef.EventFields[0].Value())

	close(sub.shutdown)
	s.deliverToItem(item, ev, false, true) // the subscription ended: returns
	s.deliverToItem(&MonitoredItem{ID: 2, Sub: sub}, ev, false, true)
}
