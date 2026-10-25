// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestDiagnostics_TransportProfile(t *testing.T) {
	require.Contains(t, transportProfileOf("opc.tcp://h:4840"), "uatcp-uasc-uabinary")
	require.Contains(t, transportProfileOf("opc.wss://h/ua"), "wss-uasc-uabinary")
	require.Contains(t, transportProfileOf("https://h/ua"), "https-uabinary")
	require.Contains(t, transportProfileOf(""), "uatcp")
}

func TestDiagnostics_IsStatus(t *testing.T) {
	require.True(t, isStatus(nil))
	require.True(t, isStatus(ua.StatusBadInternalError))
	require.False(t, isStatus(errors.New("x")))
	require.True(t, isBad(ua.StatusBadInternalError))
	require.False(t, isBad(ua.StatusUncertain))
	require.True(t, isSecurityStatus(ua.StatusBadIdentityTokenRejected))
	require.True(t, isAuthorizationStatus(ua.StatusBadUserAccessDenied))
	require.False(t, isAuthorizationStatus(ua.StatusOK))
	require.Equal(t, ua.StatusBadUnexpectedError, statusOfResult(nil, errors.New("x")))
	require.Equal(t, ua.StatusBadTimeout, statusOfResult(nil, ua.StatusBadTimeout))
	require.Equal(t, ua.StatusOK, statusOfResult(&ua.ReadResponse{}, nil))
}

func TestDiagnostics_VariantValue(t *testing.T) {
	require.IsType(t, &ua.ExtensionObject{}, variantValue((*ua.ServiceCounterDataType)(nil)))
	require.IsType(t, &ua.ExtensionObject{}, variantValue(&ua.ServiceCounterDataType{TotalCount: 1}))
	require.IsType(t, &ua.ExtensionObject{}, variantValue((*ua.ApplicationDescription)(nil)))
	require.Equal(t, int32(3), variantValue(ua.MessageSecurityModeSignAndEncrypt))
	require.Equal(t, ua.NewTwoByteNodeID(0), variantValue((*ua.NodeID)(nil)))
	n := ua.NewNumericNodeID(1, 2)
	require.Equal(t, n, variantValue(n))
	require.Equal(t, "x", variantValue("x"))

	// The value functions of a missing structure and an unknown field.
	dv := structValue(func() any { return (*ua.SessionDiagnosticsDataType)(nil) })()
	require.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
	dv = fieldValue(func() any { return nil }, "SessionName")()
	require.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
	dv = fieldValue(func() any { return (*ua.SessionDiagnosticsDataType)(nil) }, "SessionName")()
	require.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
	dv = fieldValue(func() any { return &ua.SessionDiagnosticsDataType{} }, "NoSuchField")()
	require.Equal(t, ua.StatusBadNotReadable, dv.Status)
	dv = fieldValue(func() any { return ua.SessionDiagnosticsDataType{SessionName: "s"} }, "sessionname")()
	require.Equal(t, "s", dv.Value.Value())
}

func TestDiagnostics_UserOf(t *testing.T) {
	u, m := userOf(&ua.UserNameIdentityToken{UserName: "bob", Password: []byte("secret")})
	require.Equal(t, "bob", u)
	require.Equal(t, "UserName", m)
	p, err := testpki.Get()
	require.NoError(t, err)
	u, m = userOf(&ua.X509IdentityToken{CertificateData: p.UserCert})
	require.NotEmpty(t, u)
	require.Equal(t, "Certificate", m)
	u, m = userOf(&ua.X509IdentityToken{CertificateData: []byte("junk")})
	require.Empty(t, u)
	require.Equal(t, "Certificate", m)
	u, m = userOf(&ua.IssuedIdentityToken{TokenData: []byte("secret")})
	require.Empty(t, u)
	require.Equal(t, "IssuedToken", m)
	u, m = userOf(nil)
	require.Empty(t, u)
	require.Equal(t, "Anonymous", m)
}

func TestDiagnostics_SubCounters(t *testing.T) {
	s := newTestServer()
	d := s.diag
	require.NotNil(t, d)
	for i := uint32(1); i <= 100; i++ {
		d.subCounters(i).modify.Add(1)
	}
	require.NotNil(t, d.peekSubCounters(5))
	d.maybePruneSubCounters() // 100 counters, no subscriptions: pruned
	require.Nil(t, d.peekSubCounters(5))
	c := d.subCounters(7)
	c.modify.Add(3)
	c.notifications.Add(3)
	c.reset()
	require.Zero(t, c.modify.Load())
	require.Zero(t, c.notifications.Load())
	d.pruneSubCounters(map[uint32]bool{7: true})
	require.NotNil(t, d.peekSubCounters(7))

	// Publish responses are counted for known subscriptions only.
	d.publishResponse(&ua.PublishResponse{SubscriptionID: 8})
	d.publishResponse(&ua.ReadResponse{})
	d.publishResponse(&ua.PublishResponse{SubscriptionID: 7})
	d.publishResponse(&ua.PublishResponse{SubscriptionID: 7, NotificationMessage: &ua.NotificationMessage{SequenceNumber: 4}})
	require.Equal(t, uint32(4), c.nextSeq.Load())
	d.publishResponse(&ua.PublishResponse{SubscriptionID: 7, NotificationMessage: &ua.NotificationMessage{SequenceNumber: 4, NotificationData: []*ua.ExtensionObject{
		nil,
		ua.NewExtensionObject(&ua.DataChangeNotification{MonitoredItems: make([]*ua.MonitoredItemNotification, 2)}),
		ua.NewExtensionObject(&ua.EventNotificationList{Events: make([]*ua.EventFieldList, 3)}),
	}}})
	require.Equal(t, uint32(3), c.publishRequests.Load())
	require.Equal(t, uint32(5), c.nextSeq.Load())
	require.Equal(t, uint32(1), c.dataChanges.Load())
	require.Equal(t, uint32(1), c.events.Load())
	require.Equal(t, uint32(5), c.notifications.Load())

	var nilDiag *serverDiagnostics
	nilDiag.publishResponse(&ua.PublishResponse{})
	require.Equal(t, ua.StatusOK, nilDiag.checkRead(nil, ua.NewNumericNodeID(0, 1)))
	require.Nil(t, (*MonitoredItemService)(nil).diagnostics())
	require.Nil(t, (&MonitoredItemService{}).diagnostics())
}

func TestDiagnostics_Access(t *testing.T) {
	s := newTestServer()
	d := s.diag
	ns := int(d.sessionNamespace())
	require.Equal(t, ns, d.diagnosticsNamespace())

	guid := "0B2D6AB4-61F4-4E8F-9E10-6E8B1F4E3E01"
	me := &session{ID: ua.NewGUIDNodeID(uint16(ns), guid)}
	other := &session{ID: ua.NewGUIDNodeID(uint16(ns), "1B2D6AB4-61F4-4E8F-9E10-6E8B1F4E3E01")}
	cfgAdmin := &session{roles: []*ua.NodeID{nil, ua.NewNumericNodeID(1, uint32(ua.RoleSecurityAdmin)), ua.RoleConfigureAdmin.NodeID()}}
	secAdmin := &session{roles: []*ua.NodeID{ua.RoleSecurityAdmin.NodeID()}}

	obj := ua.NewGUIDNodeID(uint16(ns), guid)
	diagVar := ua.NewStringNodeID(uint16(ns), guid+".SessionDiagnostics.SessionName")
	secVar := ua.NewStringNodeID(uint16(ns), guid+".SessionSecurityDiagnostics")
	for _, tc := range []struct {
		sess *session
		nid  *ua.NodeID
		want ua.StatusCode
	}{
		{me, obj, ua.StatusOK},
		{me, diagVar, ua.StatusOK},
		{me, secVar, ua.StatusOK},
		{other, obj, ua.StatusBadUserAccessDenied},
		{other, secVar, ua.StatusBadUserAccessDenied},
		{nil, diagVar, ua.StatusBadUserAccessDenied},
		{cfgAdmin, diagVar, ua.StatusOK},
		{cfgAdmin, secVar, ua.StatusBadUserAccessDenied},
		{secAdmin, secVar, ua.StatusOK},
		{secAdmin, diagVar, ua.StatusOK},
		{other, ua.NewNumericNodeID(uint16(ns), 5), ua.StatusOK},
	} {
		require.Equal(t, tc.want, d.checkRead(tc.sess, tc.nid), "%v %v", tc.sess, tc.nid)
	}
	arr := ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSessionsDiagnosticsSummarySessionSecurityDiagnosticsArray)
	require.Equal(t, ua.StatusBadUserAccessDenied, d.checkRead(me, arr))
	require.Equal(t, ua.StatusBadUserAccessDenied, d.checkRead(cfgAdmin, arr))
	require.Equal(t, ua.StatusOK, d.checkRead(secAdmin, arr))
	require.Equal(t, ua.StatusOK, d.checkRead(me, ua.NewNumericNodeID(5, 1)))
	require.Equal(t, ua.StatusOK, d.checkRead(me, nil))

	flag := ua.NewNumericNodeID(0, id.ServerServerDiagnosticsEnabledFlag)
	require.Equal(t, ua.StatusBadUserAccessDenied, d.checkWrite(me, flag))
	require.Equal(t, ua.StatusOK, d.checkWrite(cfgAdmin, flag))
	require.Equal(t, ua.StatusOK, d.checkWrite(me, ua.NewNumericNodeID(0, 1)))
	ctx := context.Background()
	require.Equal(t, ua.StatusBadUserAccessDenied, s.checkWrite(ctx, me, flag))
	require.Equal(t, ua.StatusBadUserAccessDenied, s.checkRead(ctx, other, obj))
	require.Equal(t, ua.StatusBadUserAccessDenied, s.checkBrowse(ctx, other, obj))
	require.Equal(t, ua.StatusOK, s.checkBrowse(ctx, me, obj))

	require.False(t, hasRole(nil, ua.RoleSecurityAdmin))
	require.False(t, isEnabledFlag(nil))
	require.False(t, isEnabledFlag(&ua.WriteValue{NodeID: flag, AttributeID: ua.AttributeIDDisplayName}))
	require.True(t, isEnabledFlag(&ua.WriteValue{NodeID: flag, AttributeID: ua.AttributeIDValue}))

	wv := func(v any, rng string) *ua.WriteValue {
		w := &ua.WriteValue{NodeID: flag, AttributeID: ua.AttributeIDValue, IndexRange: rng, Value: &ua.DataValue{}}
		if v != nil {
			w.Value.Value = ua.MustVariant(v)
		}
		return w
	}
	require.Equal(t, ua.StatusBadIndexRangeInvalid, d.writeEnabledFlag(wv(true, "0")))
	require.Equal(t, ua.StatusBadTypeMismatch, d.writeEnabledFlag(wv(nil, "")))
	require.Equal(t, ua.StatusBadTypeMismatch, d.writeEnabledFlag(&ua.WriteValue{NodeID: flag}))
	require.Equal(t, ua.StatusBadTypeMismatch, d.writeEnabledFlag(wv("yes", "")))
	require.Equal(t, ua.StatusOK, d.writeEnabledFlag(wv(false, "")))
	require.False(t, d.enabled.Load())
	require.Equal(t, ua.StatusOK, d.writeEnabledFlag(wv(true, "")))
	require.True(t, d.enabled.Load())

	// Browsing SessionsDiagnosticsSummary hides the objects of other sessions.
	summary := ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSessionsDiagnosticsSummary)
	refs := func() *ua.BrowseResult {
		return &ua.BrowseResult{References: []*ua.ReferenceDescription{
			{NodeID: ua.NewExpandedNodeID(obj, "", 0)},
			{NodeID: ua.NewExpandedNodeID(other.ID, "", 0)},
			{NodeID: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 1), "", 0)},
			nil,
		}}
	}
	res := refs()
	d.filterBrowse(me, summary, res)
	require.Len(t, res.References, 3)
	res = refs()
	d.filterBrowse(secAdmin, summary, res)
	require.Len(t, res.References, 4)
	res = refs()
	d.filterBrowse(me, ua.NewNumericNodeID(0, 85), res)
	require.Len(t, res.References, 4)
	d.filterBrowse(me, summary, nil)

	require.Empty(t, diagnosticsOwner(ua.NewNumericNodeID(1, 1)))
	require.Equal(t, "abc", diagnosticsOwner(ua.NewStringNodeID(1, "ABC")))
}

// TestDiagnostics_NamespaceBeforeSessions verifies that the diagnostics
// namespace is created with the first session, after the namespaces of the
// application, and that an existing one is reused.
func TestDiagnostics_NamespaceBeforeSessions(t *testing.T) {
	s := newTestServer()
	require.Equal(t, -1, s.diag.diagnosticsNamespace())
	app := NewNodeNameSpace(s, "urn:app")
	require.Equal(t, uint16(1), app.ID())
	pre := NewNodeNameSpace(s, DiagnosticsNamespaceURI)
	require.Equal(t, pre.ID(), s.diag.sessionNamespace())
	require.Equal(t, int(pre.ID()), s.diag.diagnosticsNamespace())
	require.Equal(t, 0, s.diag.sessionObjectCount())
}
