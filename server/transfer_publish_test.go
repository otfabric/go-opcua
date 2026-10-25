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
// session it leaves is answered (with the StatusChangeNotification that announces the transfer).
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

// TestTransferSubscriptions_AnnouncesTheTransferToTheOldSession: the session
// a subscription leaves gets a StatusChangeNotification with
// Good_SubscriptionTransferred (Part 4 §5.13.7) with its next Publish request
// when none is queued, carrying the subscription's next sequence number; its
// Publish requests after that, with no subscription left, get
// Bad_NoSubscription.
func TestTransferSubscriptions_AnnouncesTheTransferToTheOldSession(t *testing.T) {
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
	require.NotNil(t, oldSession)
	oldSession.activated.Store(true)

	subs := srv.SubscriptionService
	const id = 78
	sub := NewSubscription()
	sub.srv = subs
	sub.ID = id
	sub.Session = oldSession
	sub.seq.Store(11)
	subs.Mu.Lock()
	subs.Subs[id] = sub
	subs.Mu.Unlock()
	defer func() {
		subs.Mu.Lock()
		delete(subs.Subs, id)
		subs.Mu.Unlock()
	}()

	resp, err := subs.TransferSubscriptions(context.Background(), scNone(), &ua.TransferSubscriptionsRequest{
		RequestHeader:   newHeader,
		SubscriptionIDs: []uint32{id},
	}, 4)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.(*ua.TransferSubscriptionsResponse).Results[0].StatusCode)

	publish := func() (ua.Response, error) {
		return subs.Publish(context.Background(), scNone(), &ua.PublishRequest{
			RequestHeader:                oldHeader,
			SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{},
		}, 5)
	}
	r, err := publish()
	require.NoError(t, err)
	pub, ok := r.(*ua.PublishResponse)
	require.True(t, ok, "got %T", r)
	require.Equal(t, uint32(id), pub.SubscriptionID)
	require.Equal(t, uint32(12), pub.NotificationMessage.SequenceNumber, "the next sequence number, not consumed")
	require.Len(t, pub.NotificationMessage.NotificationData, 1)
	sc, ok := pub.NotificationMessage.NotificationData[0].Value.(*ua.StatusChangeNotification)
	require.True(t, ok)
	require.Equal(t, ua.StatusGoodSubscriptionTransferred, sc.Status)

	_, err = publish()
	require.ErrorIs(t, err, ua.StatusBadNoSubscription)
}

// TestTransferSubscriptions_BackDropsTheStaleAnnouncement: a subscription
// that leaves a session while no Publish request is queued there, and comes
// back before one arrives, is not announced as transferred to that session:
// the client would take the notification for the loss of the subscription it
// has again.
//
// Regression (chaos TestRegressionReactivatedSessionKeepsSubscriptions): the
// client replaced a detached session and took its subscription along, the
// application re-activated the old session and the subscription came back;
// the first Publish request of the old session got the notification of the
// first transfer, and the client forgot the subscription.
func TestTransferSubscriptions_BackDropsTheStaleAnnouncement(t *testing.T) {
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
	aHeader, bHeader := newSession(), newSession()
	a := srv.sb.peek(aHeader.AuthenticationToken)
	require.NotNil(t, a)
	a.activated.Store(true)

	subs := srv.SubscriptionService
	const id = 79
	sub := NewSubscription()
	sub.srv = subs
	sub.ID = id
	sub.Session = a
	subs.Mu.Lock()
	subs.Subs[id] = sub
	subs.Mu.Unlock()
	defer func() {
		subs.Mu.Lock()
		delete(subs.Subs, id)
		subs.Mu.Unlock()
	}()

	transfer := func(to *ua.RequestHeader) {
		t.Helper()
		resp, err := subs.TransferSubscriptions(context.Background(), scNone(), &ua.TransferSubscriptionsRequest{
			RequestHeader:   to,
			SubscriptionIDs: []uint32{id},
		}, 4)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, resp.(*ua.TransferSubscriptionsResponse).Results[0].StatusCode)
	}
	transfer(bHeader)
	transfer(aHeader)

	// The subscription is a's again: the Publish request waits for it.
	r, err := subs.Publish(context.Background(), scNone(), &ua.PublishRequest{
		RequestHeader:                aHeader,
		SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{},
	}, 5)
	require.NoError(t, err)
	require.Nil(t, r, "queued, not answered with the first transfer's notification")
	require.Len(t, a.PublishRequests, 1)
	<-a.PublishRequests
}
