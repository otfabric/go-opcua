// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

type observedEvent struct {
	kind     string // opened, closed, activated, session-closed
	remote   net.Addr
	duration time.Duration
	info     server.SessionInfo
	reason   server.SessionCloseReason
}

// eventRecorder is a SessionObserver that records every call.
type eventRecorder struct {
	mu     sync.Mutex
	events []observedEvent
}

func (r *eventRecorder) add(e observedEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *eventRecorder) OnConnectionOpened(remote net.Addr) {
	r.add(observedEvent{kind: "opened", remote: remote})
}

func (r *eventRecorder) OnConnectionClosed(remote net.Addr, d time.Duration) {
	r.add(observedEvent{kind: "closed", remote: remote, duration: d})
}

func (r *eventRecorder) OnSessionActivated(info server.SessionInfo) {
	r.add(observedEvent{kind: "activated", info: info})
}

func (r *eventRecorder) OnSessionClosed(info server.SessionInfo, reason server.SessionCloseReason) {
	r.add(observedEvent{kind: "session-closed", info: info, reason: reason})
}

// wait returns the events of kind once there are n of them.
func (r *eventRecorder) wait(t *testing.T, kind string, n int) []observedEvent {
	t.Helper()
	var got []observedEvent
	require.Eventually(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		got = got[:0]
		for _, e := range r.events {
			if e.kind == kind {
				got = append(got, e)
			}
		}
		return len(got) >= n
	}, 10*time.Second, 10*time.Millisecond, "waiting for %d %q events", n, kind)
	return got
}

func observedServer(t *testing.T, rec *eventRecorder) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.WithSessionObserver(rec),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return srv, srv.Endpoints()[0].EndpointURL
}

func observedClient(t *testing.T, ctx context.Context, url string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	c, err := opcua.NewClient(url, append([]opcua.Option{
		opcua.InsecureNoSecurity(),
		opcua.AutoReconnect(false),
		opcua.DialTimeout(30 * time.Second),
		opcua.RequestTimeout(30 * time.Second),
	}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	return c
}

// TestSessionObserver_ClientLifecycle connects a client, re-activates its
// session and closes it: every event arrives once, with the client's
// description and address.
func TestSessionObserver_ClientLifecycle(t *testing.T) {
	t.Parallel()
	rec := &eventRecorder{}
	_, url := observedServer(t, rec)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := observedClient(t, ctx, url,
		opcua.ApplicationName("observer test"),
		opcua.ApplicationURI("urn:test:observer"),
		opcua.SessionName("observer session"),
	)

	opened := rec.wait(t, "opened", 1)
	require.NotNil(t, opened[0].remote)
	tcp, ok := opened[0].remote.(*net.TCPAddr)
	require.True(t, ok, "%T", opened[0].remote)
	require.True(t, tcp.IP.IsLoopback(), tcp.String())

	act := rec.wait(t, "activated", 1)[0].info
	require.Equal(t, c.Session().SessionID().String(), act.ID.String())
	require.Equal(t, "observer session", act.Name)
	require.Equal(t, "observer test", act.Client.ApplicationName.Text)
	require.Equal(t, "urn:test:observer", act.Client.ApplicationURI)
	require.Equal(t, url, act.EndpointURL)
	require.Equal(t, opened[0].remote.String(), act.RemoteAddr.String())
	require.Equal(t, ua.SecurityPolicyURINone, act.SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeNone, act.SecurityMode)
	require.Equal(t, ua.UserTokenTypeAnonymous, act.IdentityType)
	require.Empty(t, act.User)
	require.False(t, act.Reactivated)
	require.False(t, act.Activated.Before(act.Created))

	// The application activates the session again.
	sess, err := c.DetachSession(ctx)
	require.NoError(t, err)
	require.NoError(t, c.ActivateSession(ctx, sess))
	re := rec.wait(t, "activated", 2)[1].info
	require.Equal(t, act.ID.String(), re.ID.String())
	require.True(t, re.Reactivated)
	require.Equal(t, act.Created, re.Created)

	require.NoError(t, c.Close(ctx))

	closed := rec.wait(t, "session-closed", 1)[0]
	require.Equal(t, server.SessionClosedByClient, closed.reason)
	require.Equal(t, act.ID.String(), closed.info.ID.String())
	require.Equal(t, "observer session", closed.info.Name)

	conn := rec.wait(t, "closed", 1)[0]
	require.Equal(t, opened[0].remote.String(), conn.remote.String())
	require.Positive(t, conn.duration)
}

// TestSessionObserver_ServerShutdown: the sessions and connections of the
// clients that are still connected end when the server is closed.
func TestSessionObserver_ServerShutdown(t *testing.T) {
	t.Parallel()
	rec := &eventRecorder{}
	srv, url := observedServer(t, rec)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := observedClient(t, ctx, url)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	rec.wait(t, "activated", 1)

	require.NoError(t, srv.Close())

	closed := rec.wait(t, "session-closed", 1)[0]
	require.Equal(t, server.SessionClosedByServer, closed.reason)
	rec.wait(t, "closed", 1)
}

// TestSessionObserver_SessionTimeout: a session the client neither uses nor
// closes, as after a lost connection, is reported as timed out.
func TestSessionObserver_SessionTimeout(t *testing.T) {
	t.Parallel()
	rec := &eventRecorder{}
	_, url := observedServer(t, rec)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := observedClient(t, ctx, url, opcua.SessionTimeout(200*time.Millisecond))
	act := rec.wait(t, "activated", 1)[0].info

	// Leave the session behind: the client closes its connection only.
	_, err := c.DetachSession(ctx)
	require.NoError(t, err)
	require.NoError(t, c.Close(ctx))

	closed := rec.wait(t, "session-closed", 1)[0]
	require.Equal(t, server.SessionTimedOut, closed.reason)
	require.Equal(t, act.ID.String(), closed.info.ID.String())
}
