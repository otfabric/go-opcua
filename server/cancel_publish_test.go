// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestCancel_AnswersCancelledPublishRequest: Cancel answers the Publish
// request it cancels with Bad_RequestCancelledByClient and returns
// cancelCount 1 (Part 4 §5.7.5).
//
// Regression: the cancelled request was dropped from the queue without a
// response, so the client waited for its request timeout.
func TestCancel_AnswersCancelledPublishRequest(t *testing.T) {
	srv, err := New(EndPoint("localhost", 0),
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL, opcua.InsecureNoSecurity(),
		opcua.AutoReconnect(false), opcua.RequestTimeout(30*time.Second))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	// A subscription that publishes nothing during the test, so that the
	// Publish request stays queued.
	var created *ua.CreateSubscriptionResponse
	require.NoError(t, c.Send(ctx, &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: 60000,
		RequestedLifetimeCount:      3000,
		RequestedMaxKeepAliveCount:  1000,
		PublishingEnabled:           true,
	}, func(r ua.Response) error {
		created = r.(*ua.CreateSubscriptionResponse)
		return nil
	}))
	require.Equal(t, ua.StatusOK, created.ResponseHeader.ServiceResult)

	srv.sb.mu.Lock()
	var sess *session
	for _, s := range srv.sb.s {
		sess = s
	}
	srv.sb.mu.Unlock()
	require.NotNil(t, sess)

	published := make(chan error, 1)
	go func() {
		published <- c.Send(ctx, &ua.PublishRequest{SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{}}, func(ua.Response) error { return nil })
	}()
	require.Eventually(t, func() bool { return len(sess.PublishRequests) == 1 }, 10*time.Second, time.Millisecond)
	// The client chooses the RequestHandle: read it from the queue.
	pr := <-sess.PublishRequests
	sess.PublishRequests <- pr
	handle := pr.Req.RequestHeader.RequestHandle

	var cancelled *ua.CancelResponse
	require.NoError(t, c.Send(ctx, &ua.CancelRequest{RequestHandle: handle}, func(r ua.Response) error {
		cancelled = r.(*ua.CancelResponse)
		return nil
	}))
	require.Equal(t, uint32(1), cancelled.CancelCount)

	select {
	case err := <-published:
		require.ErrorIs(t, err, ua.StatusBadRequestCancelledByClient)
	case <-ctx.Done():
		t.Fatal("the cancelled Publish request was not answered")
	}
	require.Empty(t, sess.PublishRequests)
}

// TestCancel_KeepsOtherPublishRequests: Cancel cancels every queued request
// with the handle and keeps the others queued, in their order.
func TestCancel_KeepsOtherPublishRequests(t *testing.T) {
	srv := newTestServer()
	svc := &SessionService{srv: srv}
	sess := srv.sb.NewSession()
	queue := func(handle, id uint32) {
		sess.PublishRequests <- PubReq{Req: &ua.PublishRequest{RequestHeader: &ua.RequestHeader{RequestHandle: handle}}, ID: id}
	}
	queue(7, 1)
	queue(8, 2)
	queue(7, 3)
	queue(9, 4)
	sess.PublishRequests <- PubReq{ID: 5} // no request: never matches

	resp, err := svc.Cancel(context.Background(), nil, &ua.CancelRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 1, AuthenticationToken: sess.AuthTokenID},
		RequestHandle: 7,
	}, 1)
	require.NoError(t, err)
	require.Equal(t, uint32(2), resp.(*ua.CancelResponse).CancelCount)

	require.Len(t, sess.PublishRequests, 3)
	var ids []uint32
	for range 3 {
		ids = append(ids, (<-sess.PublishRequests).ID)
	}
	require.Equal(t, []uint32{2, 4, 5}, ids)

	// Without a session nothing is cancelled.
	resp, err = svc.Cancel(context.Background(), nil, &ua.CancelRequest{RequestHeader: reqHeader(), RequestHandle: 7}, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(0), resp.(*ua.CancelResponse).CancelCount)
}

// TestRequeuePublishRequests_FullQueue: a request that finds the queue full
// when Cancel puts it back is answered, not lost: the queue keeps the ones
// that fit.
func TestRequeuePublishRequests_FullQueue(t *testing.T) {
	srv := newTestServer()
	sess := &session{PublishRequests: make(chan PubReq, 1)}
	srv.requeuePublishRequests(sess, []PubReq{
		{Req: &ua.PublishRequest{RequestHeader: &ua.RequestHeader{RequestHandle: 1}}, ID: 1},
		{Req: &ua.PublishRequest{RequestHeader: &ua.RequestHeader{RequestHandle: 2}}, ID: 2},
	}, nil)
	require.Len(t, sess.PublishRequests, 1)
	require.Equal(t, uint32(1), (<-sess.PublishRequests).ID)
}
