// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// sessionAuditFields are the fields the audit watcher selects, in order.
var sessionAuditFields = []string{
	"EventType", "SourceName", "Status", "ClientUserId", "StatusCodeId",
	"SessionId", "SecureChannelId", "UserIdentityToken", "RequestType", "ClientAuditEntryId",
}

type sessionAudit struct {
	typ        uint32
	source     string
	status     bool
	user       string
	code       ua.StatusCode
	sessionID  *ua.NodeID
	channelID  string
	identity   any
	auditEntry string
}

// watchSessionAudit subscribes c to the audit events of the Server object.
func watchSessionAudit(t *testing.T, c *opcua.Client) <-chan sessionAudit {
	t.Helper()
	b := ua.NewEventFilter().SelectPaths(sessionAuditFields...)
	b.Where(&ua.ContentFilterElement{
		FilterOperator: ua.FilterOperatorOfType,
		FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(ua.NewNumericNodeID(0, id.AuditSecurityEventType))})},
	})
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(b.Build(), ua.NewNumericNodeID(0, id.Server)).Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	out := make(chan sessionAudit, 256)
	done, exited := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(done); <-exited })
	go func() {
		defer close(exited)
		for {
			var msg *opcua.PublishNotificationData
			select {
			case msg = <-ch:
			case <-done:
				return
			}
			if msg == nil {
				return
			}
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, e := range enl.Events {
				f := e.EventFields
				a := sessionAudit{}
				if n, ok := f[0].Value().(*ua.NodeID); ok {
					a.typ = n.IntID()
				}
				a.source, _ = f[1].Value().(string)
				a.status, _ = f[2].Value().(bool)
				a.user, _ = f[3].Value().(string)
				a.code, _ = f[4].Value().(ua.StatusCode)
				a.sessionID, _ = f[5].Value().(*ua.NodeID)
				a.channelID, _ = f[6].Value().(string)
				if eo, ok := f[7].Value().(*ua.ExtensionObject); ok {
					a.identity = eo.Value
				}
				a.auditEntry, _ = f[9].Value().(string)
				out <- a
			}
		}
	}()
	return out
}

// next returns the next audit event from source.
func nextAudit(t *testing.T, ch <-chan sessionAudit, source string) sessionAudit {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case a := <-ch:
			if a.source == source {
				return a
			}
		case <-deadline:
			t.Fatalf("no audit event %s", source)
		}
	}
}

// The SecureChannel and Session service sets report their audit events
// (Part 4 §6.5.5, §6.5.6; Part 5 §6.4): a client that connects and closes,
// and one whose password is wrong.
func TestSessionAudit_Lifecycle(t *testing.T) {
	t.Parallel()
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(user, pass string) error {
			if pass != "secret" {
				return ua.StatusBadUserAccessDenied
			}
			return nil
		}),
		server.WithAuditing(true),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	url := srv.Endpoints()[0].EndpointURL
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	watcher := observedClient(t, ctx, url)
	t.Cleanup(func() { _ = watcher.Close(context.Background()) })
	audit := watchSessionAudit(t, watcher)

	newClient := func(opts ...opcua.Option) *opcua.Client {
		c, err := opcua.NewClient(url, append([]opcua.Option{opcua.InsecureNoSecurity(), opcua.AutoReconnect(false)}, opts...)...)
		require.NoError(t, err)
		return c
	}

	c := newClient(opcua.AuthUsername("alice", "secret"), opcua.AuthPolicyID("username_none"))
	require.NoError(t, c.Connect(ctx))
	sid := c.Session().SessionID()

	open := nextAudit(t, audit, "SecureChannel/OpenSecureChannel")
	require.Equal(t, uint32(id.AuditOpenSecureChannelEventType), open.typ)
	require.True(t, open.status)
	require.Equal(t, "System/OpenSecureChannel", open.user)
	require.NotEmpty(t, open.channelID)

	create := nextAudit(t, audit, "Session/CreateSession")
	require.Equal(t, uint32(id.AuditCreateSessionEventType), create.typ)
	require.True(t, create.status)
	require.Equal(t, "System/CreateSession", create.user)
	require.Equal(t, sid.String(), create.sessionID.String())
	require.Equal(t, open.channelID, create.channelID)

	act := nextAudit(t, audit, "Session/ActivateSession")
	require.Equal(t, uint32(id.AuditActivateSessionEventType), act.typ)
	require.True(t, act.status)
	require.Equal(t, "alice", act.user)
	tok, ok := act.identity.(*ua.UserNameIdentityToken)
	require.True(t, ok, "%T", act.identity)
	require.Equal(t, "alice", tok.UserName)
	require.Empty(t, tok.Password, "the password is not included (Part 5 §6.4.10)")

	require.NoError(t, c.Close(ctx))
	closed := nextAudit(t, audit, "Session/CloseSession")
	require.Equal(t, uint32(id.AuditSessionEventType), closed.typ)
	require.True(t, closed.status)
	require.Equal(t, sid.String(), closed.sessionID.String())
	ch := nextAudit(t, audit, "SecureChannel/CloseSecureChannel")
	require.Equal(t, uint32(id.AuditChannelEventType), ch.typ)
	require.Equal(t, open.channelID, ch.channelID)

	// A wrong password: the ActivateSession event says so, with the user
	// the client tried and the ClientAuditEntryId of the request.
	bad := newClient(opcua.AuthUsername("mallory", "guess"), opcua.AuthPolicyID("username_none"))
	require.Error(t, bad.Connect(ctx))
	_ = bad.Close(ctx)
	fail := nextAudit(t, audit, "Session/ActivateSession")
	require.False(t, fail.status)
	require.Equal(t, ua.StatusBadUserAccessDenied, fail.code)
	require.Equal(t, "mallory", fail.user)
	tok, ok = fail.identity.(*ua.UserNameIdentityToken)
	require.True(t, ok)
	require.Empty(t, tok.Password)
	require.NotNil(t, fail.sessionID)
	// The session the client could not activate ends with its timeout or
	// the server; it is not reported as closed by the client.
}

// Auditing off: no audit events, but the server works as before.
func TestSessionAudit_Off(t *testing.T) {
	t.Parallel()
	rec := &eventRecorder{}
	srv, url := observedServer(t, rec)
	require.False(t, srv.Auditing())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := observedClient(t, ctx, url)
	require.NoError(t, c.Close(ctx))
	rec.wait(t, "session-closed", 1)
}
