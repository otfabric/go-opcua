// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// A request keeps its session alive when it arrives, not only once the
// handler gets to it: requests are handled one at a time, and one waiting
// behind a slow request must not let its session time out (Part 4 §5.6.2
// counts from the last request the server received).
//
// Before the fix the session was touched by the handler only, so a session
// whose request was queued behind a blocked handler stayed idle.
func TestSessionTouchedWhenRequestArrives(t *testing.T) {
	srv, err := New(EndPoint("localhost", 0),
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	ns, obj := addTestNamespace(srv)
	methodID := ua.NewStringNodeID(ns.ID(), "block")
	method := NewFolderNode(methodID, "block")
	method.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(method)
	obj.AddRef(method, RefType(id.HasComponent), true)
	entered := make(chan struct{})
	release := make(chan struct{})
	srv.RegisterMethod(obj.ID(), methodID, func(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		close(entered)
		<-release
		return nil, ua.StatusOK
	})
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	url := srv.Endpoints()[0].EndpointURL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func() *opcua.Client {
		c, err := opcua.NewClient(url, opcua.InsecureNoSecurity(),
			opcua.AutoReconnect(false), opcua.RequestTimeout(30*time.Second))
		require.NoError(t, err)
		require.NoError(t, c.Connect(ctx))
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	sessions := func() map[*session]bool {
		srv.sb.mu.Lock()
		defer srv.sb.mu.Unlock()
		m := map[*session]bool{}
		for _, s := range srv.sb.s {
			m[s] = true
		}
		return m
	}

	blocker := connect()
	before := sessions()
	waiter := connect()
	var sess *session
	for s := range sessions() {
		if !before[s] {
			sess = s
		}
	}
	require.NotNil(t, sess, "the second client's session")

	// The blocker occupies the request handler.
	called := make(chan error, 1)
	go func() {
		_, err := blocker.Call(ctx, &ua.CallMethodRequest{ObjectID: obj.ID(), MethodID: methodID})
		called <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("the method handler was not called")
	}

	// The waiter's session has been idle for most of its timeout; its
	// request now waits behind the blocked handler.
	timeout := time.Duration(sess.timeout.Load())
	require.Greater(t, timeout, time.Minute)
	backdate(sess, time.Now().Add(-timeout+time.Minute))
	read := make(chan error, 1)
	go func() {
		_, err := waiter.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{
			NodeID: ua.NewNumericNodeID(0, id.ServerServerStatus), AttributeID: ua.AttributeIDValue,
		}}})
		read <- err
	}()
	require.Eventually(t, func() bool { return sess.idle(time.Now()) < timeout/2 },
		10*time.Second, time.Millisecond, "the queued request did not count as activity")
	for _, s := range srv.sb.reapExpired(time.Now()) {
		require.NotSame(t, sess, s, "the session with a queued request was reaped")
	}

	close(release)
	require.NoError(t, <-called)
	require.NoError(t, <-read)
}

// A request for a session whose timeout has elapsed does not revive it,
// although the reaper, which runs periodically, has not removed it yet: the
// session is closed once its timeout has elapsed (Part 4 §5.6.2).
//
// Before the fix the arriving request and the session lookup restarted the
// timeout of the expired session, and its client could go on using it.
func TestExpiredSessionNotRevived(t *testing.T) {
	sb := newSessionBroker(slog.New(slog.DiscardHandler))
	sess := sb.NewSession()
	sess.setTimeout(time.Second)
	backdate(sess, time.Now().Add(-2*time.Second))

	sb.touchToken(sess.AuthTokenID)
	require.True(t, sess.expired(time.Now()), "the arriving request revived the session")
	require.Nil(t, sb.Session(sess.AuthTokenID), "the lookup returned an expired session")
	require.True(t, sess.expired(time.Now()), "the lookup revived the session")
	require.Equal(t, []*session{sess}, sb.reapExpired(time.Now()))

	// A session that has not timed out is still found and touched.
	live := sb.NewSession()
	live.setTimeout(time.Minute)
	backdate(live, time.Now().Add(-30*time.Second))
	sb.touchToken(live.AuthTokenID)
	require.Less(t, live.idle(time.Now()), time.Second)
	require.Same(t, live, sb.Session(live.AuthTokenID))
}

// backdate sets the last activity of s to t, also when that is earlier than
// the activity recorded so far, which touchAt does not do.
func backdate(s *session, t time.Time) {
	s.lastActivity.Store(int64(t.Sub(monoEpoch)))
}

// The last activity of a session only moves forward.
//
// Regression (conformance TestSession_TimeoutEnforced under load): a request
// read the clock when it arrived and recorded the time after a later request
// had recorded its own, taking the activity back by however long it waited
// in between. A session in use could time out.
func TestSessionActivityOnlyMovesForward(t *testing.T) {
	sb := newSessionBroker(slog.New(slog.DiscardHandler))
	sess := sb.NewSession()
	now := time.Now()
	sess.touchAt(now)
	sess.touchAt(now.Add(-time.Minute))
	require.Equal(t, time.Duration(0), sess.idle(now))
	sess.touchAt(now.Add(time.Second))
	require.Equal(t, -time.Second, sess.idle(now))
}
