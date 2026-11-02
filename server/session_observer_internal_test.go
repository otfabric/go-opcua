// SPDX-License-Identifier: MIT

package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

type closedEvent struct {
	info   SessionInfo
	reason SessionCloseReason
}

// closeRecorder records the sessions reported closed.
type closeRecorder struct {
	BaseSessionObserver
	mu     sync.Mutex
	closed []closedEvent
}

func (r *closeRecorder) OnSessionClosed(info SessionInfo, reason SessionCloseReason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, closedEvent{info, reason})
}

func (r *closeRecorder) reasons() map[string]SessionCloseReason {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]SessionCloseReason, len(r.closed))
	for _, e := range r.closed {
		out[e.info.Name] = e.reason
	}
	return out
}

// newObservedSession creates a session named name in the broker of s and,
// if activate, activates it as ActivateSession does.
func newObservedSession(s *Server, name string, activate bool) *session {
	sess := s.sb.NewSession()
	sess.obs.describe(sess.ID, &ua.CreateSessionRequest{SessionName: name})
	if activate {
		reactivated := sess.activated.Swap(true)
		s.observeSessionActivated(nil, sess, reactivated)
	}
	return sess
}

// TestSessionObserver_CloseReasons checks the reason of each way a session
// ends: CloseSession, the session timeout and the shutdown of the server.
// A session that was never activated is not reported.
func TestSessionObserver_CloseReasons(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	rec := &closeRecorder{}
	s.cfg.sessionObserver = rec

	byClient := newObservedSession(s, "by-client", true)
	timedOut := newObservedSession(s, "timed-out", true)
	newObservedSession(s, "by-server", true)
	newObservedSession(s, "never-activated", false)

	require.NoError(t, s.sb.Close(byClient.AuthTokenID))

	timedOut.setTimeout(time.Millisecond)
	expired := s.sb.reapExpired(time.Now().Add(time.Second))
	require.Len(t, expired, 1)

	s.sb.closeAll()

	require.Equal(t, map[string]SessionCloseReason{
		"by-client": SessionClosedByClient,
		"timed-out": SessionTimedOut,
		"by-server": SessionClosedByServer,
	}, rec.reasons())
}

// TestSessionObserver_SessionInfo checks what an activation records.
func TestSessionObserver_SessionInfo(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	rec := &closeRecorder{}
	s.cfg.sessionObserver = rec

	sess := s.sb.NewSession()
	sess.obs.describe(sess.ID, &ua.CreateSessionRequest{
		SessionName:       "info",
		EndpointURL:       "opc.tcp://localhost:4840",
		ClientDescription: &ua.ApplicationDescription{ApplicationName: &ua.LocalizedText{Text: "app"}},
	})
	sess.identityToken = &ua.UserNameIdentityToken{UserName: "alice"}
	sess.activated.Store(true)
	info := sess.obs.activate(nil, sess.identityToken, true, time.Now())

	require.Equal(t, sess.ID, info.ID)
	require.Equal(t, "info", info.Name)
	require.Equal(t, "app", info.Client.ApplicationName.Text)
	require.Equal(t, "opc.tcp://localhost:4840", info.EndpointURL)
	require.Equal(t, ua.UserTokenTypeUserName, info.IdentityType)
	require.Equal(t, "alice", info.User)
	require.True(t, info.Reactivated)
	require.Nil(t, info.RemoteAddr, "no secure channel")
	require.False(t, info.Created.IsZero())
	require.False(t, info.Activated.Before(info.Created))
}

func TestIdentityTypeOf(t *testing.T) {
	t.Parallel()
	for tok, want := range map[ua.IdentityToken]ua.UserTokenType{
		&ua.AnonymousIdentityToken{}: ua.UserTokenTypeAnonymous,
		&ua.UserNameIdentityToken{}:  ua.UserTokenTypeUserName,
		&ua.X509IdentityToken{}:      ua.UserTokenTypeCertificate,
		&ua.IssuedIdentityToken{}:    ua.UserTokenTypeIssuedToken,
	} {
		require.Equal(t, want, tokenTypeOf(tok))
	}
	require.Equal(t, ua.UserTokenTypeAnonymous, tokenTypeOf(nil))
}

func TestSessionCloseReason_String(t *testing.T) {
	t.Parallel()
	require.Equal(t, "closed by client", SessionClosedByClient.String())
	require.Equal(t, "timed out", SessionTimedOut.String())
	require.Equal(t, "closed by server", SessionClosedByServer.String())
	require.Equal(t, "unknown", SessionCloseReason(0).String())
}

// panickingObserver panics in every method.
type panickingObserver struct{}

func (panickingObserver) OnConnectionOpened(net.Addr)                     { panic("opened") }
func (panickingObserver) OnConnectionClosed(net.Addr, time.Duration)      { panic("closed") }
func (panickingObserver) OnSessionActivated(SessionInfo)                  { panic("activated") }
func (panickingObserver) OnSessionClosed(SessionInfo, SessionCloseReason) { panic("session closed") }
func (panickingObserver) OnRejected(Rejection)                            { panic("rejected") }

// TestSessionObserver_PanicIsRecovered: a panicking observer does not take
// the connection, the session or the server down.
func TestSessionObserver_PanicIsRecovered(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	s.cfg.sessionObserver = panickingObserver{}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4840}

	require.NotPanics(t, func() {
		s.observeConnectionOpened(addr)
		s.observeConnectionClosed(addr, time.Now())
		sess := newObservedSession(s, "panic", true)
		require.NoError(t, s.sb.Close(sess.AuthTokenID))
		s.observeRejected(Rejection{Service: RejectedActivateSession})
	})
}

// TestSessionObserver_None: without an observer nothing is called, and an
// activation is still recorded for a later observer-less close.
func TestSessionObserver_None(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4840}

	require.NotPanics(t, func() {
		s.observeConnectionOpened(addr)
		s.observeConnectionClosed(addr, time.Now())
		sess := newObservedSession(s, "none", true)
		require.Equal(t, "none", sess.obs.snapshot().Name)
		require.NoError(t, s.sb.Close(sess.AuthTokenID))
	})
}

func TestBaseSessionObserver(t *testing.T) {
	t.Parallel()
	var o SessionObserver = BaseSessionObserver{}
	require.NotPanics(t, func() {
		o.OnConnectionOpened(nil)
		o.OnConnectionClosed(nil, 0)
		o.OnSessionActivated(SessionInfo{})
		o.OnSessionClosed(SessionInfo{}, SessionClosedByClient)
	})
}

func TestWithSessionObserver(t *testing.T) {
	t.Parallel()
	rec := &closeRecorder{}
	var cfg serverConfig
	require.NoError(t, WithSessionObserver(rec)(&cfg))
	require.Same(t, rec, cfg.sessionObserver)
	require.NoError(t, WithSessionObserver(nil)(&cfg))
	require.Nil(t, cfg.sessionObserver)
}

// Every SessionInfo is a copy: an observer that changes the client
// description it was given changes neither the session nor later events.
func TestSessionObserver_InfoIsCopy(t *testing.T) {
	t.Parallel()
	var o sessionObs
	o.describe(ua.NewNumericNodeID(1, 1), &ua.CreateSessionRequest{
		SessionName: "s",
		ClientDescription: &ua.ApplicationDescription{
			ApplicationName: ua.NewLocalizedText("app"),
			DiscoveryURLs:   []string{"opc.tcp://a"},
		},
	})
	got := o.activate(nil, nil, false, time.Now())
	got.Client.ApplicationURI = "changed"
	got.Client.ApplicationName.Text = "changed"
	got.Client.DiscoveryURLs[0] = "changed"

	again := o.snapshot()
	require.Empty(t, again.Client.ApplicationURI)
	require.Equal(t, "app", again.Client.ApplicationName.Text)
	require.Equal(t, []string{"opc.tcp://a"}, again.Client.DiscoveryURLs)

	var empty sessionObs
	require.Nil(t, empty.snapshot().Client, "no description, nothing to copy")
}
