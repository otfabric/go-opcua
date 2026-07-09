// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSubscription(srv *Server) (*SubscriptionService, *Subscription, *ua.RequestHeader) {
	sess := srv.sb.NewSession()
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.Session = sess
	sub.ID = 1
	sub.RevisedPublishingInterval = 100
	sub.RevisedLifetimeCount = 10
	sub.RevisedMaxKeepAliveCount = 3
	sub.running = true

	srv.SubscriptionService.Mu.Lock()
	srv.SubscriptionService.Subs[sub.ID] = sub
	srv.SubscriptionService.Mu.Unlock()

	hdr := &ua.RequestHeader{
		RequestHandle:       1,
		AuthenticationToken: sess.AuthTokenID,
	}
	return srv.SubscriptionService, sub, hdr
}

func TestSubscriptionService_Republish(t *testing.T) {
	srv := newTestServer()
	svc, sub, hdr := newTestSubscription(srv)

	t.Run("republish with no stored messages returns not available", func(t *testing.T) {
		req := &ua.RepublishRequest{
			RequestHeader:            hdr,
			SubscriptionID:           sub.ID,
			RetransmitSequenceNumber: 1,
		}
		resp, err := svc.Republish(context.Background(), nil, req, 1)
		require.NoError(t, err)

		repResp := resp.(*ua.RepublishResponse)
		assert.Equal(t, ua.StatusBadMessageNotAvailable, repResp.ResponseHeader.ServiceResult)
	})

	t.Run("republish returns stored message", func(t *testing.T) {
		msg := &ua.NotificationMessage{
			SequenceNumber: 5,
			PublishTime:    time.Now(),
		}
		sub.storeSentMessage(msg)

		req := &ua.RepublishRequest{
			RequestHeader:            hdr,
			SubscriptionID:           sub.ID,
			RetransmitSequenceNumber: 5,
		}
		resp, err := svc.Republish(context.Background(), nil, req, 2)
		require.NoError(t, err)

		repResp := resp.(*ua.RepublishResponse)
		assert.Equal(t, ua.StatusOK, repResp.ResponseHeader.ServiceResult)
		require.NotNil(t, repResp.NotificationMessage)
		assert.Equal(t, uint32(5), repResp.NotificationMessage.SequenceNumber)
	})

	t.Run("republish unknown subscription", func(t *testing.T) {
		req := &ua.RepublishRequest{
			RequestHeader:            hdr,
			SubscriptionID:           999,
			RetransmitSequenceNumber: 1,
		}
		resp, err := svc.Republish(context.Background(), nil, req, 3)
		require.NoError(t, err)

		repResp := resp.(*ua.RepublishResponse)
		assert.Equal(t, ua.StatusBadSubscriptionIDInvalid, repResp.ResponseHeader.ServiceResult)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.Republish(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestSubscriptionService_TransferSubscriptions(t *testing.T) {
	srv := newTestServer()
	svc, sub, hdr := newTestSubscription(srv)

	t.Run("transfer existing subscription", func(t *testing.T) {
		req := &ua.TransferSubscriptionsRequest{
			RequestHeader:     hdr,
			SubscriptionIDs:   []uint32{sub.ID},
			SendInitialValues: false,
		}
		resp, err := svc.TransferSubscriptions(context.Background(), nil, req, 1)
		require.NoError(t, err)

		transResp := resp.(*ua.TransferSubscriptionsResponse)
		assert.Equal(t, ua.StatusOK, transResp.ResponseHeader.ServiceResult)
		require.Len(t, transResp.Results, 1)
		assert.Equal(t, ua.StatusOK, transResp.Results[0].StatusCode)
	})

	t.Run("transfer nonexistent subscription", func(t *testing.T) {
		req := &ua.TransferSubscriptionsRequest{
			RequestHeader:     hdr,
			SubscriptionIDs:   []uint32{999},
			SendInitialValues: false,
		}
		resp, err := svc.TransferSubscriptions(context.Background(), nil, req, 2)
		require.NoError(t, err)

		transResp := resp.(*ua.TransferSubscriptionsResponse)
		require.Len(t, transResp.Results, 1)
		assert.Equal(t, ua.StatusBadSubscriptionIDInvalid, transResp.Results[0].StatusCode)
	})

	t.Run("transfer multiple subscriptions mixed", func(t *testing.T) {
		req := &ua.TransferSubscriptionsRequest{
			RequestHeader:     hdr,
			SubscriptionIDs:   []uint32{sub.ID, 999},
			SendInitialValues: false,
		}
		resp, err := svc.TransferSubscriptions(context.Background(), nil, req, 3)
		require.NoError(t, err)

		transResp := resp.(*ua.TransferSubscriptionsResponse)
		require.Len(t, transResp.Results, 2)
		assert.Equal(t, ua.StatusOK, transResp.Results[0].StatusCode)
		assert.Equal(t, ua.StatusBadSubscriptionIDInvalid, transResp.Results[1].StatusCode)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.TransferSubscriptions(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestSubscription_RetransmissionQueue(t *testing.T) {
	sub := NewSubscription()

	t.Run("store and retrieve message", func(t *testing.T) {
		msg := &ua.NotificationMessage{SequenceNumber: 1}
		sub.storeSentMessage(msg)

		got := sub.getSentMessage(1)
		require.NotNil(t, got)
		assert.Equal(t, uint32(1), got.SequenceNumber)
	})

	t.Run("retrieve nonexistent returns nil", func(t *testing.T) {
		got := sub.getSentMessage(999)
		assert.Nil(t, got)
	})

	t.Run("queue evicts oldest when full", func(t *testing.T) {
		sub2 := NewSubscription()
		for i := uint32(1); i <= maxRetransmissionQueueSize+5; i++ {
			sub2.storeSentMessage(&ua.NotificationMessage{SequenceNumber: i})
		}

		nums := sub2.availableSequenceNumbers()
		assert.Len(t, nums, maxRetransmissionQueueSize)

		// Oldest messages should have been evicted.
		for i := uint32(1); i <= 5; i++ {
			assert.Nil(t, sub2.getSentMessage(i), "message %d should have been evicted", i)
		}
		// Newest should still be available.
		assert.NotNil(t, sub2.getSentMessage(maxRetransmissionQueueSize+5))
	})
}

// TestDeleteSubscriptions_NilSession verifies that DeleteSubscriptions does not
// panic when the server has no session matching the request token.
func TestDeleteSubscriptions_NilSession(t *testing.T) {
	srv := newTestServer()
	svc, sub, _ := newTestSubscription(srv)

	// Build a header with an auth token that doesn't match any live session.
	badHdr := &ua.RequestHeader{
		RequestHandle:       99,
		AuthenticationToken: ua.NewByteStringNodeID(0, []byte("bad-token")),
	}
	req := &ua.DeleteSubscriptionsRequest{
		RequestHeader:   badHdr,
		SubscriptionIDs: []uint32{sub.ID},
	}

	require.NotPanics(t, func() {
		resp, err := svc.DeleteSubscriptions(context.Background(), nil, req, 1)
		require.NoError(t, err)
		r := resp.(*ua.DeleteSubscriptionsResponse)
		// Session was nil so the subscription ownership check must reject it.
		require.Equal(t, ua.StatusBadSessionIDInvalid, r.Results[0])
	})
}

// TestSubscription_Run_NilSession verifies that a subscription goroutine with a
// nil session exits cleanly rather than panicking.
func TestSubscription_Run_NilSession(t *testing.T) {
	srv := newTestServer()
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.Session = nil // intentionally nil
	sub.ID = 42
	sub.RevisedPublishingInterval = 10
	sub.RevisedLifetimeCount = 3
	sub.RevisedMaxKeepAliveCount = 2
	sub.running = true

	srv.SubscriptionService.Mu.Lock()
	srv.SubscriptionService.Subs[sub.ID] = sub
	srv.SubscriptionService.Mu.Unlock()

	// run() should return promptly (nil session early-exit) without panicking.
	done := make(chan struct{})
	go func() {
		defer close(done)
		sub.run()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sub.run() did not exit within 1s for nil session")
	}
}

// TestSubscription_Keepalive_NilChannel verifies that keepalive returns an
// error rather than panicking when Channel is nil.
func TestSubscription_Keepalive_NilChannel(t *testing.T) {
	srv := newTestServer()
	sess := srv.sb.NewSession()
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sub.Session = sess
	sub.Channel = nil // intentionally nil
	sub.ID = 43

	pubreq := PubReq{
		Req: &ua.PublishRequest{RequestHeader: &ua.RequestHeader{RequestHandle: 1}},
		ID:  1,
	}
	err := sub.keepalive(pubreq)
	require.Error(t, err, "keepalive with nil channel must return an error, not panic")
}
