// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// diagnosticsServer starts a server whose user "admin" has the SecurityAdmin
// role, "config" the ConfigureAdmin role and "op" the Operator role;
// anonymous users have none. login connects anonymously over None, and as a
// user over Basic256Sha256 SignAndEncrypt (SessionSecurityDiagnosticsArray
// requires encryption).
func diagnosticsServer(t *testing.T, opts ...server.Option) (*server.Server, string, func(user string, opts ...opcua.Option) *opcua.Client) {
	t.Helper()
	roleFor := map[string]ua.WellKnownRole{
		"admin":  ua.RoleSecurityAdmin,
		"config": ua.RoleConfigureAdmin,
		"op":     ua.RoleOperator,
	}
	all := append([]server.Option{
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(user, pass string) error {
			if _, ok := roleFor[user]; ok && pass == user+"-pw" {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if u, ok := tok.(*ua.UserNameIdentityToken); ok {
				return []*ua.NodeID{roleFor[u.UserName].NodeID()}
			}
			return server.DefaultRoleMapper(tok)
		}),
	}, opts...)
	srv, url := newServer(t, secureServerOpts(t, all...)...)
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	login := func(user string, opts ...opcua.Option) *opcua.Client {
		if user == "" {
			return newClient(t, url, opts...)
		}
		return newClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeUserName), append([]opcua.Option{
			opcua.AuthUsername(user, user+"-pw"),
			opcua.SessionName(user + "-session"),
		}, opts...)...)...)
	}
	return srv, url, login
}

// TestDiagnostics_ServerSummary verifies the live ServerDiagnosticsSummary
// (Part 5 §6.3.3, §12.9): session and subscription counts follow the
// clients, and rejected requests are counted.
func TestDiagnostics_ServerSummary(t *testing.T) {
	_, url := newServer(t)
	ctx := context.Background()
	c := newClient(t, url)

	on, err := c.ServerDiagnosticsEnabled(ctx)
	require.NoError(t, err)
	require.True(t, on, "diagnostics are enabled by default")

	sum, err := c.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(1), sum.CurrentSessionCount)
	require.Equal(t, uint32(1), sum.CumulatedSessionCount)
	require.Zero(t, sum.CurrentSubscriptionCount)

	// A second session and a subscription.
	c2 := newClient(t, url)
	sub, err := c2.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Second}, make(chan *opcua.PublishNotificationData, 8))
	require.NoError(t, err)
	sum, err = c.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(2), sum.CurrentSessionCount)
	require.Equal(t, uint32(2), sum.CumulatedSessionCount)
	require.Equal(t, uint32(1), sum.CurrentSubscriptionCount)
	require.Equal(t, uint32(1), sum.CumulatedSubscriptionCount)
	require.Equal(t, uint32(1), sum.PublishingIntervalCount)

	// Each component variable carries its member of the summary.
	dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsServerDiagnosticsSummaryCurrentSessionCount))
	require.NoError(t, err)
	require.Equal(t, uint32(2), dv.Value.Value())

	// A rejected request.
	before := sum.RejectedRequestsCount
	_, err = c.Read(ctx, badRead())
	require.ErrorIs(t, err, ua.StatusBadTimestampsToReturnInvalid)
	sum, err = c.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.Equal(t, before+1, sum.RejectedRequestsCount)

	// Closing the second session removes it and its subscription.
	require.NoError(t, sub.Cancel(ctx))
	require.NoError(t, c2.Close(ctx))
	eventually(t, func() bool {
		sum, err = c.ServerDiagnosticsSummary(ctx)
		return err == nil && sum.CurrentSessionCount == 1 && sum.CurrentSubscriptionCount == 0
	}, "the closed session leaves the summary")
	require.Equal(t, uint32(2), sum.CumulatedSessionCount)
	require.Equal(t, uint32(1), sum.CumulatedSubscriptionCount)
}

// TestDiagnostics_RejectedSessions verifies that failed ActivateSession
// calls are counted as rejected and security rejected sessions.
func TestDiagnostics_RejectedSessions(t *testing.T) {
	_, url, login := diagnosticsServer(t)
	ctx := context.Background()
	ep := endpointFor(t, url, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)

	_, err := dialClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("admin", "wrong"))
	require.Error(t, err)

	c := login("admin")
	sum, err := c.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, sum.RejectedSessionCount, uint32(1))
	require.GreaterOrEqual(t, sum.SecurityRejectedSessionCount, uint32(1))
	require.Equal(t, uint32(1), sum.CurrentSessionCount)
}

// TestDiagnostics_SessionObjects verifies the SessionDiagnosticsObject of
// every session (Part 5 §6.3.5): it is created and removed with the session,
// its NodeId is the SessionId, and its variables describe the session.
func TestDiagnostics_SessionObjects(t *testing.T) {
	srv, _, login := diagnosticsServer(t)
	ctx := context.Background()
	admin := login("admin")
	op := login("op")

	// The own SessionDiagnostics.
	sd, err := op.SessionDiagnosticsOf(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, "op-session", sd.SessionName)
	require.True(t, sd.SessionID.Equal(op.Session().SessionID()))
	require.NotZero(t, sd.TotalRequestCount.TotalCount)
	require.NotNil(t, sd.ClientDescription)
	require.NotEmpty(t, sd.ClientDescription.ApplicationURI)

	// Requests are counted per service.
	_, err = op.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)
	sd2, err := op.SessionDiagnosticsOf(ctx, nil)
	require.NoError(t, err)
	require.Greater(t, sd2.ReadCount.TotalCount, sd.ReadCount.TotalCount)
	require.Greater(t, sd2.TotalRequestCount.TotalCount, sd.TotalRequestCount.TotalCount)

	// The own security diagnostics: no secrets, the user and the policy.
	sec, err := op.SessionSecurityDiagnosticsOf(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, "op", sec.ClientUserIDOfSession)
	require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, sec.SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, sec.SecurityMode)
	require.Equal(t, pki(t).ClientCert, sec.ClientCertificate)
	require.Equal(t, "UserName", sec.AuthenticationMechanism)

	// An administrator sees both sessions in the arrays and by browsing.
	all, err := admin.SessionDiagnostics(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
	secs, err := admin.SessionSecurityDiagnostics(ctx)
	require.NoError(t, err)
	require.Len(t, secs, 2)
	other, err := admin.SessionDiagnosticsOf(ctx, op.Session().SessionID())
	require.NoError(t, err)
	require.Equal(t, "op-session", other.SessionName)
	require.Len(t, browseSessionObjects(t, admin), 2)

	// Another session's diagnostics are not for a non-administrator.
	_, err = op.SessionDiagnosticsOf(ctx, admin.Session().SessionID())
	require.Error(t, err)
	_, err = op.SessionSecurityDiagnostics(ctx)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	objs := browseSessionObjects(t, op)
	require.Len(t, objs, 1, "a session browses only its own diagnostics object")
	require.True(t, objs[0].Equal(op.Session().SessionID()))

	// Closing a session removes its object.
	opID := op.Session().SessionID()
	require.NoError(t, op.Close(ctx))
	eventually(t, func() bool { return len(browseSessionObjects(t, admin)) == 1 }, "the closed session's object is removed")
	_, err = admin.SessionDiagnosticsOf(ctx, opID)
	require.Error(t, err)
	require.Nil(t, srv.Node(opID))
}

// badRead returns a Read the server rejects as a whole.
func badRead() *ua.ReadRequest {
	return &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturn(99),
		NodesToRead:        []*ua.ReadValueID{{NodeID: ua.NewNumericNodeID(0, id.ServerServerStatusState), AttributeID: ua.AttributeIDValue}},
	}
}

// browseSessionObjects browses SessionsDiagnosticsSummary for the
// SessionDiagnosticsObjects.
func browseSessionObjects(t *testing.T, c *opcua.Client) []*ua.NodeID {
	t.Helper()
	refs, err := c.Node(ua.NewNumericNodeID(0, id.ServerServerDiagnosticsSessionsDiagnosticsSummary)).ReferencedNodes(context.Background(), id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassObject, true)
	require.NoError(t, err)
	var out []*ua.NodeID
	for _, r := range refs {
		out = append(out, r.ID)
	}
	return out
}

// TestDiagnostics_Subscriptions verifies SubscriptionDiagnosticsArray and
// SamplingIntervalDiagnosticsArray.
func TestDiagnostics_Subscriptions(t *testing.T) {
	c, f, _, _ := setupWith(t, nil)
	ctx := context.Background()

	ch := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth, opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1))
	require.NoError(t, err)
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth, opcua.NewMonitoredItemCreateRequestWithDefaults(f.Double, ua.AttributeIDValue, 2))
	require.NoError(t, err)
	nextDataChanges(t, ch)

	subs, err := c.SubscriptionDiagnostics(ctx)
	require.NoError(t, err)
	require.Len(t, subs, 1)
	sd := subs[0]
	require.Equal(t, sub.SubscriptionID, sd.SubscriptionID)
	require.True(t, sd.SessionID.Equal(c.Session().SessionID()))
	require.Equal(t, uint32(2), sd.MonitoredItemCount)
	require.True(t, sd.PublishingEnabled)
	require.NotZero(t, sd.DataChangeNotificationsCount)

	samp, err := c.SamplingIntervalDiagnostics(ctx)
	require.NoError(t, err)
	var items uint32
	for _, s := range samp {
		items += s.MonitoredItemCount
	}
	require.Equal(t, uint32(2), items)

	// The subscription in the session's object.
	sess, err := c.SessionDiagnosticsOf(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, uint32(1), sess.CurrentSubscriptionsCount)
	require.Equal(t, uint32(2), sess.CurrentMonitoredItemsCount)
	require.NotZero(t, sess.CreateMonitoredItemsCount.TotalCount)

	require.NoError(t, sub.Cancel(ctx))
	subs, err = c.SubscriptionDiagnostics(ctx)
	require.NoError(t, err)
	require.Empty(t, subs)
}

// TestDiagnostics_EnabledFlag verifies that only administrators change
// EnabledFlag, that disabling empties the arrays and removes the session
// objects, and that enabling resets the counters.
func TestDiagnostics_EnabledFlag(t *testing.T) {
	srv, _, login := diagnosticsServer(t)
	ctx := context.Background()
	anon := login("")
	cfg := login("config")

	err := anon.SetServerDiagnosticsEnabled(ctx, false)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	err = login("op").SetServerDiagnosticsEnabled(ctx, false)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	_, err = anon.Read(ctx, badRead()) // a rejected request
	require.Error(t, err)

	require.NoError(t, cfg.SetServerDiagnosticsEnabled(ctx, false))
	require.False(t, srv.ServerDiagnosticsEnabled())
	on, err := anon.ServerDiagnosticsEnabled(ctx)
	require.NoError(t, err)
	require.False(t, on)
	frozen, err := anon.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.NotZero(t, frozen.RejectedRequestsCount)

	// Disabled: the counters stand still, the arrays are empty and the
	// session objects are gone.
	_, err = anon.Read(ctx, badRead())
	require.Error(t, err)
	sum, err := anon.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.Equal(t, frozen, sum)
	sessions, err := anon.SessionDiagnostics(ctx)
	require.NoError(t, err)
	require.Empty(t, sessions)
	require.Empty(t, browseSessionObjects(t, cfg))
	_, err = anon.SessionDiagnosticsOf(ctx, nil)
	require.Error(t, err)

	// Enabled again: the counters restart and the objects come back.
	require.NoError(t, cfg.SetServerDiagnosticsEnabled(ctx, true))
	sum, err = anon.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.Zero(t, sum.RejectedRequestsCount)
	require.Equal(t, uint32(3), sum.CurrentSessionCount)
	require.GreaterOrEqual(t, sum.CumulatedSessionCount, sum.CurrentSessionCount)
	require.Len(t, browseSessionObjects(t, cfg), 3)
	_, err = anon.SessionDiagnosticsOf(ctx, nil)
	require.NoError(t, err)

	// EnabledFlag only takes a Boolean.
	st, err := cfg.WriteValue(ctx, ua.NewNumericNodeID(0, id.ServerServerDiagnosticsEnabledFlag), &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1))})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadTypeMismatch, st)
}

// TestDiagnostics_Disabled verifies a server started with diagnostics off.
func TestDiagnostics_Disabled(t *testing.T) {
	srv, url := newServer(t, server.WithServerDiagnostics(false))
	ctx := context.Background()
	c := newClient(t, url)
	on, err := c.ServerDiagnosticsEnabled(ctx)
	require.NoError(t, err)
	require.False(t, on)
	sum, err := c.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.Zero(t, sum.CurrentSessionCount)
	require.Zero(t, srv.ServerDiagnosticsSummary().CumulatedSessionCount)
	subs, err := c.SubscriptionDiagnostics(ctx)
	require.NoError(t, err)
	require.Empty(t, subs)
	samp, err := c.SamplingIntervalDiagnostics(ctx)
	require.NoError(t, err)
	require.Empty(t, samp)

	srv.SetServerDiagnosticsEnabled(true)
	sum, err = c.ServerDiagnosticsSummary(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(1), sum.CurrentSessionCount)
	_, err = c.SessionDiagnosticsOf(ctx, nil)
	require.NoError(t, err)
}

// TestDiagnostics_ReturnDiagnostics verifies DiagnosticInfo (Part 4 §7.12):
// the server returns the diagnostics the RequestHeader asks for, with their
// strings in the string table, and the client resolves them.
func TestDiagnostics_ReturnDiagnostics(t *testing.T) {
	_, f, _, url := setupWith(t, nil)
	ctx := context.Background()
	c := newClient(t, url, opcua.ReturnDiagnostics(ua.ReturnDiagnosticsAll))
	plain := newClient(t, url)
	unknown := ua.NewNumericNodeID(0, 999999)

	read := &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: f.Int32, AttributeID: ua.AttributeIDValue},
		{NodeID: unknown, AttributeID: ua.AttributeIDValue},
	}}
	var resp *ua.ReadResponse
	require.NoError(t, c.Send(ctx, read, func(r ua.Response) error {
		resp = r.(*ua.ReadResponse)
		return nil
	}))
	require.Len(t, resp.Results, 2)
	require.Len(t, resp.DiagnosticInfos, 2, "one DiagnosticInfo per operation")
	require.Nil(t, resp.ResponseHeader.Diagnostic(resp.DiagnosticInfos[0]), "a good operation has no diagnostics")
	d := resp.ResponseHeader.Diagnostic(resp.DiagnosticInfos[1])
	require.NotNil(t, d)
	require.Equal(t, "BadNodeIdUnknown", d.SymbolicID)
	require.Equal(t, "http://opcfoundation.org/UA/", d.NamespaceURI)
	require.NotEmpty(t, d.LocalizedText)
	require.Contains(t, d.AdditionalInfo, unknown.String())
	require.NotEmpty(t, resp.ResponseHeader.StringTable)

	// Without the option the server returns none.
	read2 := &ua.ReadRequest{NodesToRead: read.NodesToRead}
	var resp2 *ua.ReadResponse
	require.NoError(t, plain.Send(ctx, read2, func(r ua.Response) error {
		resp2 = r.(*ua.ReadResponse)
		return nil
	}))
	require.Empty(t, resp2.DiagnosticInfos)
	require.Empty(t, resp2.ResponseHeader.StringTable)

	// A rejected request fails with a *ServiceError that carries the
	// service diagnostics and unwraps to the StatusCode.
	_, err := c.Read(ctx, badRead())
	require.ErrorIs(t, err, ua.StatusBadTimestampsToReturnInvalid)
	var se *opcua.ServiceError
	require.True(t, errors.As(err, &se))
	require.Equal(t, ua.StatusBadTimestampsToReturnInvalid, se.StatusCode)
	require.Equal(t, "BadTimestampsToReturnInvalid", se.Diagnostic.SymbolicID)
	require.Contains(t, err.Error(), "BadTimestampsToReturnInvalid")

	_, err = plain.Read(ctx, badRead())
	require.ErrorIs(t, err, ua.StatusBadTimestampsToReturnInvalid)
	require.False(t, errors.As(err, &se), "no diagnostics without the option")

	// A request can ask for diagnostics of its own.
	read3 := &ua.ReadRequest{
		RequestHeader: &ua.RequestHeader{ReturnDiagnostics: ua.OperationLevelSymbolicID},
		NodesToRead:   read.NodesToRead,
	}
	var resp3 *ua.ReadResponse
	require.NoError(t, plain.Send(ctx, read3, func(r ua.Response) error {
		resp3 = r.(*ua.ReadResponse)
		return nil
	}))
	require.Len(t, resp3.DiagnosticInfos, 2)
	d = resp3.ResponseHeader.Diagnostic(resp3.DiagnosticInfos[1])
	require.Equal(t, "BadNodeIdUnknown", d.SymbolicID)
	require.Empty(t, d.LocalizedText, "only the bits asked for")
	require.Empty(t, d.AdditionalInfo)
}

// TestDiagnostics_NoSecretsInDiagnostics verifies that a rejected login
// leaks neither the password into the session diagnostics nor internals
// into DiagnosticInfo.
func TestDiagnostics_NoSecretsInDiagnostics(t *testing.T) {
	_, _, login := diagnosticsServer(t)
	ctx := context.Background()
	admin := login("admin", opcua.ReturnDiagnostics(ua.ReturnDiagnosticsAll))
	secs, err := admin.SessionSecurityDiagnostics(ctx)
	require.NoError(t, err)
	require.Len(t, secs, 1)
	require.Equal(t, "admin", secs[0].ClientUserIDOfSession)
	for _, h := range secs[0].ClientUserIDHistory {
		require.NotContains(t, h, "admin-pw")
	}
	var resp *ua.WriteResponse
	require.NoError(t, admin.Send(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID:      ua.NewStringNodeID(1, "no such node"),
		AttributeID: ua.AttributeIDValue,
		Value:       &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(0))},
	}}}, func(r ua.Response) error {
		resp = r.(*ua.WriteResponse)
		return nil
	}))
	require.Len(t, resp.DiagnosticInfos, 1)
	require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[0])
	d := resp.ResponseHeader.Diagnostic(resp.DiagnosticInfos[0])
	require.Equal(t, "BadNodeIdUnknown", d.SymbolicID)
	require.Contains(t, d.AdditionalInfo, "no such node")
	for _, s := range resp.ResponseHeader.StringTable {
		require.NotContains(t, s, "goroutine")
		require.NotContains(t, s, ".go:")
	}
}
