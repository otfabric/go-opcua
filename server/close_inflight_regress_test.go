// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestClose_RequestInFlightLeavesNothing handles a CreateSession and a
// CreateSubscription request after the server was closed, the way the
// dispatcher does with a request it took off a channel just before Close:
// Close does not wait for it.
//
// Regression (found by chaos/reverse): the session was kept by the closed
// server, where nothing would ever time it out, and the subscription would
// have started a goroutine that nothing stops.
func TestClose_RequestInFlightLeavesNothing(t *testing.T) {
	srv, err := New(
		EndPoint("localhost", 0),
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))

	// A session from before the shutdown, for the late CreateSubscription.
	sessions := &SessionService{srv: srv}
	create := func() (*ua.CreateSessionResponse, error) {
		resp, err := sessions.CreateSession(context.Background(), scNone(), &ua.CreateSessionRequest{
			RequestHeader:           reqHeader(),
			EndpointURL:             "opc.tcp://localhost:4840",
			RequestedSessionTimeout: 60000,
			ClientNonce:             make([]byte, 32),
		}, 1)
		if err != nil {
			return nil, err
		}
		return resp.(*ua.CreateSessionResponse), nil
	}
	early, err := create()
	require.NoError(t, err)
	sess := srv.sb.Session(early.AuthenticationToken)
	require.NotNil(t, sess)

	require.NoError(t, srv.Close())
	require.Equal(t, testhook.ServerResources{}, testhook.ServerResourcesOf(srv))

	_, _ = create()
	require.Equal(t, 0, testhook.ServerResourcesOf(srv).Sessions, "a closed server keeps no session")

	hdr := reqHeader()
	hdr.AuthenticationToken = early.AuthenticationToken
	srv.sb.mu.Lock()
	srv.sb.s[early.AuthenticationToken.String()] = sess // as if the lookup had happened before Close
	srv.sb.mu.Unlock()
	_, err = srv.SubscriptionService.CreateSubscription(context.Background(), scNone(), &ua.CreateSubscriptionRequest{
		RequestHeader:               hdr,
		RequestedPublishingInterval: 100,
		RequestedLifetimeCount:      30,
		RequestedMaxKeepAliveCount:  10,
		PublishingEnabled:           true,
	}, 2)
	require.ErrorIs(t, err, ua.StatusBadShutdown)
	require.Equal(t, 0, testhook.ServerResourcesOf(srv).Subscriptions, "a closed server starts no subscription")
	srv.sb.closeAll()

	// A server that is started again works as before.
	require.NoError(t, srv.Start(context.Background()))
	again, err := create()
	require.NoError(t, err)
	require.NotNil(t, srv.sb.Session(again.AuthenticationToken))
	require.NoError(t, srv.Close())
}
