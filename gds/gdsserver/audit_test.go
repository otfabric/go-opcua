// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// auditFields are the fields the audit tests select.
var auditFields = []string{"EventType", "SourceName", "Status", "ClientUserId", "MethodId",
	"InputArguments", "OutputArguments", "CertificateGroup", "CertificateType"}

type auditEvent map[string]any

// auditEvents subscribes to the audit events of the Server object of the
// client.
func auditEvents(t *testing.T, c *opcua.Client) func() auditEvent {
	t.Helper()
	ctx := context.Background()
	f := ua.NewEventFilter().TypeDefinition(ua.NewNumericNodeID(0, id.BaseEventType))
	for _, name := range auditFields {
		f.SelectPaths(name)
	}
	f.Where(&ua.ContentFilterElement{
		FilterOperator: ua.FilterOperatorOfType,
		FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(ua.NewNumericNodeID(0, id.AuditUpdateMethodEventType))})},
	})
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(f.Build(), ua.NewNumericNodeID(0, id.Server)).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	var buf []auditEvent
	return func() auditEvent {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for len(buf) == 0 {
			select {
			case msg := <-ch:
				require.NoError(t, msg.Error)
				enl, ok := msg.Value.(*ua.EventNotificationList)
				if !ok {
					continue
				}
				for _, ev := range enl.Events {
					m := auditEvent{}
					for i, name := range auditFields {
						if i < len(ev.EventFields) && ev.EventFields[i] != nil {
							m[name] = ev.EventFields[i].Value()
						}
					}
					buf = append(buf, m)
				}
			case <-deadline:
				t.Fatal("no audit event")
			}
		}
		ev := buf[0]
		buf = buf[1:]
		return ev
	}
}

// TestAudit: the methods of the Directory report the audit events of the
// GDS NodeSet, without the password and the private key.
func TestAudit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{AutoApprove: true}, server.WithAuditing(true))
	ctx := ctxT(t)
	next := auditEvents(t, e.dial(dialOpts{user: userSecurityAdmin}))
	typeOf := func(ev auditEvent) uint32 {
		t.Helper()
		n, ok := ev["EventType"].(*ua.NodeID)
		require.True(t, ok, "%v", ev)
		require.Equal(t, e.gds.Namespace(), n.Namespace())
		return n.IntID()
	}

	appID, err := e.admin().RegisterApplication(ctx, record("urn:otfabric:test:audit"))
	require.NoError(t, err)
	ev := next()
	require.Equal(t, uint32(gdsid.ApplicationRegistrationChangedAuditEventType), typeOf(ev))
	require.Equal(t, "Method/RegisterApplication", ev["SourceName"])
	require.Equal(t, true, ev["Status"])
	require.Equal(t, userDiscoveryAdmin, ev["ClientUserId"])

	ca := e.caAdmin()
	reqID, err := ca.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{PrivateKeyFormat: gds.PrivateKeyFormatPFX, PrivateKeyPassword: "secret"})
	require.NoError(t, err)
	ev = next()
	require.Equal(t, uint32(gdsid.CertificateRequestedAuditEventType), typeOf(ev))
	require.True(t, e.gds.DefaultApplicationGroup().Equal(ev["CertificateGroup"].(*ua.NodeID)))
	require.True(t, p256Type.Equal(ev["CertificateType"].(*ua.NodeID)))
	in := ev["InputArguments"].([]*ua.Variant)
	require.Len(t, in, 7)
	require.Equal(t, "PFX", in[5].Value())
	require.Nil(t, in[6].Value(), "the password is left out")

	res, err := ca.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	ev = next()
	require.Equal(t, uint32(gdsid.CertificateDeliveredAuditEventType), typeOf(ev))
	out := ev["OutputArguments"].([]*ua.Variant)
	require.Len(t, out, 3)
	require.Equal(t, res.Certificate, out[0].Value())
	require.Nil(t, out[1].Value(), "the private key is left out")

	require.NoError(t, ca.RevokeCertificate(ctx, appID, res.Certificate))
	ev = next()
	require.Equal(t, uint32(gdsid.CertificateRevokedAuditEventType), typeOf(ev))

	// A failure is reported too.
	_, err = ca.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{CertificateGroup: e.gds.DefaultUserTokenGroup()})
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	ev = next()
	require.Equal(t, uint32(gdsid.CertificateRequestedAuditEventType), typeOf(ev))
	require.Equal(t, false, ev["Status"])
	require.True(t, e.gds.DefaultUserTokenGroup().Equal(ev["CertificateGroup"].(*ua.NodeID)))
	require.True(t, ev["CertificateType"].(*ua.NodeID).Equal(ua.NewTwoByteNodeID(0)))

	require.NoError(t, e.admin().UnregisterApplication(ctx, appID))
	ev = next()
	require.Equal(t, uint32(gdsid.ApplicationRegistrationChangedAuditEventType), typeOf(ev))
	require.Equal(t, "Method/UnregisterApplication", ev["SourceName"])
}

// TestAudit_Waiting: a FinishRequest of a request that waits for approval
// reports nothing; auditing off reports nothing.
func TestAudit_Waiting(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{}, server.WithAuditing(true))
	ctx := ctxT(t)
	next := auditEvents(t, e.dial(dialOpts{user: userSecurityAdmin}))
	appID, err := e.admin().RegisterApplication(ctx, record("urn:otfabric:test:audit"))
	require.NoError(t, err)
	require.Equal(t, "Method/RegisterApplication", next()["SourceName"])
	ca := e.caAdmin()
	reqID, err := ca.StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	require.Equal(t, "Method/StartNewKeyPairRequest", next()["SourceName"])
	_, err = ca.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadNothingToDo)
	require.NoError(t, e.gds.ApproveRequest(ctx, e.gds.RequestID(reqID), false))
	_, err = ca.FinishRequest(ctx, appID, reqID)
	require.Error(t, err)
	ev := next()
	require.Equal(t, "Method/FinishRequest", ev["SourceName"], "the rejected request, not the waiting one")
	require.Equal(t, false, ev["Status"])

	e.srv.SetAuditing(false)
	_, err = e.admin().RegisterApplication(ctx, record("urn:otfabric:test:audit2"))
	require.NoError(t, err)
	e.srv.SetAuditing(true)
	_, err = e.admin().RegisterApplication(ctx, record("urn:otfabric:test:audit3"))
	require.NoError(t, err)
	ev = next()
	require.Equal(t, "Method/RegisterApplication", ev["SourceName"])
	in := ev["InputArguments"].([]*ua.Variant)
	require.Len(t, in, 1)
	rec, ok := in[0].Value().(*ua.ExtensionObject)
	require.True(t, ok)
	r, err := gds.DecodeApplicationRecord(e.gds.Namespace(), rec)
	require.NoError(t, err)
	require.Equal(t, "urn:otfabric:test:audit3", r.ApplicationURI, "the event of the second call")
}

// TestAudit_RBAC: under the RBACAccessController the audit events of the
// GDS reach the sessions whose roles have ReceiveEvents on the event type
// (the SecurityAdmin, by the GDS NodeSet), and the RolePermissions of the
// methods apply.
func TestAudit_RBAC(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{AutoApprove: true}, server.WithAuditing(true), server.WithAccessController(server.NewRBACAccessController(nil)))
	ctx := ctxT(t)
	plainEvents := auditEvents(t, e.dial(dialOpts{user: userPlain}))
	next := auditEvents(t, e.dial(dialOpts{user: userSecurityAdmin}))
	appID, err := e.admin().RegisterApplication(ctx, record("urn:otfabric:test:rbac"))
	require.NoError(t, err)
	require.Equal(t, "Method/RegisterApplication", next()["SourceName"])

	// The NodeSet gives the CertificateAuthorityAdmin Call on the request
	// methods; a user without a GDS role may not register.
	reqID, err := e.caAdmin().StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	require.Equal(t, "Method/StartNewKeyPairRequest", next()["SourceName"])
	_, err = e.caAdmin().FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	require.Equal(t, "Method/FinishRequest", next()["SourceName"])
	_, err = e.pull(dialOpts{user: userPlain}).RegisterApplication(ctx, record("urn:otfabric:test:rbac2"))
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	// The session without the SecurityAdmin role got none of them: the
	// next event it sees is one the server emits to everybody.
	require.NoError(t, e.srv.EmitBaseEvent(ua.NewNumericNodeID(0, id.Server), &server.BaseEvent{
		EventID: []byte("marker"), EventType: ua.NewNumericNodeID(0, id.AuditUpdateMethodEventType),
		SourceName: "marker", Time: time.Now(), Severity: 1}))
	require.Equal(t, "marker", plainEvents()["SourceName"])
	require.Equal(t, "marker", next()["SourceName"])
}
