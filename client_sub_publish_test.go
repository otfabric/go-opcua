// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withPublishHook(t *testing.T, fn func(context.Context, *Client) (*ua.PublishResponse, error)) {
	t.Helper()
	prev := publishRequestFn
	publishRequestFn = fn
	t.Cleanup(func() { publishRequestFn = prev })
}

func TestPublish_ErrorSwitch(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	fatalCases := []struct {
		name string
		err  error
	}{
		{"eof", io.EOF},
		{"session_not_activated", ua.StatusBadSessionNotActivated},
		{"session_id_invalid", ua.StatusBadSessionIDInvalid},
		{"server_not_connected", ua.StatusBadServerNotConnected},
		{"no_subscription", ua.StatusBadNoSubscription},
	}
	for _, tc := range fatalCases {
		t.Run(tc.name, func(t *testing.T) {
			withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
				return nil, tc.err
			})
			got := c.publish(context.Background())
			require.ErrorIs(t, got, tc.err)
		})
	}

	t.Run("sequence_number_unknown_ignored", func(t *testing.T) {
		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return nil, ua.StatusBadSequenceNumberUnknown
		})
		require.NoError(t, c.publish(context.Background()))
	})

	t.Run("timeout_ignored", func(t *testing.T) {
		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return nil, ua.StatusBadTimeout
		})
		require.NoError(t, c.publish(context.Background()))
	})

	t.Run("too_many_publish_requests_cancelled", func(t *testing.T) {
		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return nil, ua.StatusBadTooManyPublishRequests
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got := c.publish(ctx)
		require.ErrorIs(t, got, context.Canceled)
	})

	t.Run("too_many_publish_requests_backoff", func(t *testing.T) {
		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return nil, ua.StatusBadTooManyPublishRequests
		})
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		got := c.publish(ctx)
		require.Error(t, got)
		assert.Less(t, time.Since(start), 500*time.Millisecond)
	})

	t.Run("unexpected_error_no_response", func(t *testing.T) {
		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return nil, assert.AnError
		})
		require.ErrorIs(t, c.publish(context.Background()), assert.AnError)
	})

	t.Run("error_with_response_notifies_one", func(t *testing.T) {
		sub, ch := newNotifyTestSub(42)
		c.subMux.Lock()
		c.subs[42] = sub
		c.subMux.Unlock()
		t.Cleanup(func() {
			c.subMux.Lock()
			delete(c.subs, 42)
			c.subMux.Unlock()
		})

		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return &ua.PublishResponse{SubscriptionID: 42}, assert.AnError
		})
		require.ErrorIs(t, c.publish(context.Background()), assert.AnError)
		select {
		case msg := <-ch:
			require.ErrorIs(t, msg.Error, assert.AnError)
		case <-time.After(time.Second):
			t.Fatal("expected per-subscription error notification")
		}
	})

	t.Run("error_with_response_notifies_all", func(t *testing.T) {
		a, ach := newNotifyTestSub(1)
		b, bch := newNotifyTestSub(2)
		c.subMux.Lock()
		c.subs[1] = a
		c.subs[2] = b
		c.subMux.Unlock()
		t.Cleanup(func() {
			c.subMux.Lock()
			delete(c.subs, 1)
			delete(c.subs, 2)
			c.subMux.Unlock()
		})

		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return &ua.PublishResponse{SubscriptionID: 0}, assert.AnError
		})
		require.ErrorIs(t, c.publish(context.Background()), assert.AnError)
		for _, ch := range []<-chan *PublishNotificationData{ach, bch} {
			select {
			case msg := <-ch:
				require.ErrorIs(t, msg.Error, assert.AnError)
			case <-time.After(time.Second):
				t.Fatal("expected broadcast error notification")
			}
		}
	})

	t.Run("success_unknown_subscription", func(t *testing.T) {
		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return &ua.PublishResponse{
				SubscriptionID: 999,
				Results:        nil,
				NotificationMessage: &ua.NotificationMessage{
					SequenceNumber:   1,
					NotificationData: nil,
				},
			}, nil
		})
		require.NoError(t, c.publish(context.Background()))
	})

	t.Run("success_delivers_notification", func(t *testing.T) {
		sub, ch := newNotifyTestSub(7)
		sub.nextSeq = 1
		c.subMux.Lock()
		c.subs[7] = sub
		c.pendingAcks = nil
		c.subMux.Unlock()
		t.Cleanup(func() {
			c.subMux.Lock()
			delete(c.subs, 7)
			c.subMux.Unlock()
		})

		dcn := &ua.DataChangeNotification{}
		withPublishHook(t, func(context.Context, *Client) (*ua.PublishResponse, error) {
			return &ua.PublishResponse{
				SubscriptionID: 7,
				Results:        []ua.StatusCode{},
				NotificationMessage: &ua.NotificationMessage{
					SequenceNumber: 1,
					NotificationData: []*ua.ExtensionObject{
						{Value: dcn},
					},
				},
			}, nil
		})
		require.NoError(t, c.publish(context.Background()))
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			assert.Equal(t, dcn, msg.Value)
		case <-time.After(time.Second):
			t.Fatal("expected data-change notification")
		}
		assert.Equal(t, uint32(2), sub.nextSeq)
	})
}
