// SPDX-License-Identifier: MIT

package session

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

// sessionEvents records what a SessionObserver is told.
type sessionEvents struct {
	server.BaseSessionObserver
	mu        sync.Mutex
	opened    []net.Addr
	closed    []net.Addr
	activated []server.SessionInfo
	ended     map[string]server.SessionCloseReason // by SessionId
}

func (e *sessionEvents) OnConnectionOpened(remote net.Addr) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.opened = append(e.opened, remote)
}

func (e *sessionEvents) OnConnectionClosed(remote net.Addr, _ time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = append(e.closed, remote)
}

func (e *sessionEvents) OnSessionActivated(info server.SessionInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activated = append(e.activated, info)
}

func (e *sessionEvents) OnSessionClosed(info server.SessionInfo, reason server.SessionCloseReason) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ended == nil {
		e.ended = make(map[string]server.SessionCloseReason)
	}
	e.ended[info.ID.String()] = reason
}

func (e *sessionEvents) activation(id *ua.NodeID) (server.SessionInfo, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, info := range e.activated {
		if info.ID.Equal(id) {
			return info, true
		}
	}
	return server.SessionInfo{}, false
}

func (e *sessionEvents) endReason(id *ua.NodeID) (server.SessionCloseReason, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.ended[id.String()]
	return r, ok
}

func (e *sessionEvents) closedCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.closed)
}

// TestSession_ObserverReportsLifecycle checks the session observer against
// the session state machine of Part 4 §5.6 over a secured channel: the
// session is reported once activated (§5.6.3) with the security of its
// channel and the client's CreateSession description, and its end with
// CloseSession (§5.6.4) and with the session timeout (§5.6.2), which a
// lost connection does not shortcut.
func TestSession_ObserverReportsLifecycle(t *testing.T) {
	events := &sessionEvents{}
	_, url := secureServer(t, server.WithSessionObserver(events))
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	ctx := context.Background()

	t.Run("CloseSession", func(t *testing.T) {
		c := newClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeAnonymous),
			opcua.SessionName("conformance observer"), opcua.AutoReconnect(false))...)
		sid := c.Session().SessionID()

		info, ok := events.activation(sid)
		require.True(t, ok, "ActivateSession is reported before its response")
		require.Equal(t, "conformance observer", info.Name)
		require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, info.SecurityPolicyURI)
		require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, info.SecurityMode)
		require.NotNil(t, info.RemoteAddr)
		require.NotNil(t, info.Client)

		closedBefore := events.closedCount()
		require.NoError(t, c.Close(ctx))
		eventually(t, func() bool {
			r, ok := events.endReason(sid)
			return ok && r == server.SessionClosedByClient
		}, "CloseSession is reported as closed by the client")
		eventually(t, func() bool { return events.closedCount() > closedBefore }, "the connection end is reported")
	})

	t.Run("Timeout", func(t *testing.T) {
		c := newClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeAnonymous),
			opcua.SessionTimeout(200*time.Millisecond), opcua.AutoReconnect(false))...)
		sid := c.Session().SessionID()

		// The client goes away without CloseSession: only the timeout ends
		// the session.
		_, err := c.DetachSession(ctx)
		require.NoError(t, err)
		require.NoError(t, c.Close(ctx))
		eventually(t, func() bool {
			r, ok := events.endReason(sid)
			return ok && r == server.SessionTimedOut
		}, "the session timeout is reported")
	})
}
