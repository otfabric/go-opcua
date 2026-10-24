// SPDX-License-Identifier: MIT

package server

import (
	"context"
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
		EnableSecurity("None", ua.MessageSecurityModeNone),
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
		c, err := opcua.NewClient(url, opcua.SecurityMode(ua.MessageSecurityModeNone),
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

	// The waiter's session has been idle for a long time; its request now
	// waits behind the blocked handler.
	idleSince := time.Now().Add(-time.Hour)
	sess.touchAt(idleSince)
	read := make(chan error, 1)
	go func() {
		_, err := waiter.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{
			NodeID: ua.NewNumericNodeID(0, id.ServerServerStatus), AttributeID: ua.AttributeIDValue,
		}}})
		read <- err
	}()
	require.Eventually(t, func() bool { return sess.idle(time.Now()) < time.Minute },
		10*time.Second, time.Millisecond, "the queued request did not count as activity")
	for _, s := range srv.sb.reapExpired(time.Now()) {
		require.NotSame(t, sess, s, "the session with a queued request was reaped")
	}

	close(release)
	require.NoError(t, <-called)
	require.NoError(t, <-read)
}
