// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestTransferSubscriptions_AnswersThePublishRequestOfTheOldSession: when a
// subscription is transferred, a Publish request that is queued in the
// session it leaves is answered (with a keep-alive of the subscription).
//
// Regression (found with chaos TestRegressionReactivatedSessionKeepsSubscriptions
// without the race detector): the request stayed queued in a session that
// had no subscription left to answer it. A client that replaced its session
// and took its subscriptions along waited for the request timeout before it
// published in the new session, and received nothing until then.
func TestTransferSubscriptions_AnswersThePublishRequestOfTheOldSession(t *testing.T) {
	srv, err := New(
		EndPoint("localhost", 0),
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	defer func() { _ = srv.Close() }()

	sessions := &SessionService{srv: srv}
	newSession := func() *ua.RequestHeader {
		resp, err := sessions.CreateSession(context.Background(), scNone(), &ua.CreateSessionRequest{
			RequestHeader:           reqHeader(),
			EndpointURL:             "opc.tcp://localhost:4840",
			RequestedSessionTimeout: 60000,
			ClientNonce:             make([]byte, 32),
		}, 1)
		require.NoError(t, err)
		h := reqHeader()
		h.AuthenticationToken = resp.(*ua.CreateSessionResponse).AuthenticationToken
		return h
	}
	oldHeader, newHeader := newSession(), newSession()
	oldSession := srv.sb.peek(oldHeader.AuthenticationToken)
	newSessionObj := srv.sb.peek(newHeader.AuthenticationToken)
	require.NotNil(t, oldSession)
	require.NotNil(t, newSessionObj)

	subs := srv.SubscriptionService
	// A subscription of the old session (not running: nothing publishes
	// during the test).
	const id = 77
	sub := NewSubscription()
	sub.srv = subs
	sub.ID = id
	sub.Session = oldSession
	subs.Mu.Lock()
	subs.Subs[id] = sub
	subs.Mu.Unlock()
	defer func() {
		subs.Mu.Lock()
		delete(subs.Subs, id)
		subs.Mu.Unlock()
	}()

	// The client's Publish request waits in the old session.
	oldSession.PublishRequests <- PubReq{Req: &ua.PublishRequest{RequestHeader: oldHeader}, ID: 3}

	resp, err := subs.TransferSubscriptions(context.Background(), scNone(), &ua.TransferSubscriptionsRequest{
		RequestHeader:   newHeader,
		SubscriptionIDs: []uint32{id, id + 1000},
	}, 4)
	require.NoError(t, err)
	results := resp.(*ua.TransferSubscriptionsResponse).Results
	require.Equal(t, ua.StatusOK, results[0].StatusCode)
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, results[1].StatusCode)

	subs.Mu.Lock()
	owner, _ := subs.Subs[id].sessionChannel()
	subs.Mu.Unlock()
	require.Same(t, newSessionObj, owner, "the subscription belongs to the requesting session")
	require.Empty(t, oldSession.PublishRequests, "the Publish request of the old session was answered")

	// A session cannot be asked for without a valid session.
	_, err = subs.TransferSubscriptions(context.Background(), scNone(), &ua.TransferSubscriptionsRequest{
		RequestHeader:   reqHeader(),
		SubscriptionIDs: []uint32{id},
	}, 5)
	require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)
}
