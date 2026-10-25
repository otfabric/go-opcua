// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A CreateSubscription request that fails may still have created the
// subscription on the server, where it lives on in the session with nobody
// knowing its id (found by chaos/reverse, which also has the end-to-end
// test). The client recognizes it by a Publish response for a subscription
// it does not know and has it deleted. These are the rules for telling it
// apart from the unknown subscriptions that are none of its business.
func TestPublishLoop_UnknownSubscriptionIsDeletedOnlyAfterALostCreate(t *testing.T) {
	t.Parallel()
	c := newNotifyTestClient(t)
	ctx := context.Background()
	keepAlive := func(id uint32) *ua.PublishResponse {
		return &ua.PublishResponse{
			SubscriptionID:      id,
			Results:             []ua.StatusCode{},
			NotificationMessage: &ua.NotificationMessage{SequenceNumber: 1},
		}
	}

	// No request ever failed: an unknown subscription is one the caller
	// cancelled a moment ago and is left alone.
	assert.Zero(t, c.deliverPublishResponse(ctx, keepAlive(9)), "no CreateSubscription request failed")

	// A request failed without a connection: it is counted.
	_, err := c.createSubscription(ctx, &ua.CreateSubscriptionRequest{})
	require.Error(t, err)
	require.Equal(t, int32(1), c.subCreatesLost.Load())
	assert.Equal(t, uint32(9), c.deliverPublishResponse(ctx, keepAlive(9)), "the subscription the failed request left behind")

	// While Subscribe has a subscription that is not registered yet, the
	// unknown subscription may be that one: its first notification can
	// overtake the registration.
	c.subCreating.Add(1)
	assert.Zero(t, c.deliverPublishResponse(ctx, keepAlive(9)), "a subscription is being created")
	c.subCreating.Add(-1)

	// A subscription the client knows is never a candidate.
	sub, _ := newNotifyTestSub(7)
	c.subMux.Lock()
	c.subs[7] = sub
	c.subMux.Unlock()
	assert.Zero(t, c.deliverPublishResponse(ctx, keepAlive(7)), "a known subscription")

	// Nor is anything while a recovery is in progress: the subscriptions are
	// being recreated then.
	c.setPublishRecovering(true)
	assert.Zero(t, c.deliverPublishResponse(ctx, keepAlive(9)), "during a recovery")
	c.setPublishRecovering(false)
	assert.Equal(t, uint32(9), c.deliverPublishResponse(ctx, keepAlive(9)))

	// Deleting fails without a connection; the request stays counted, so the
	// next keep-alive message of the subscription triggers another attempt.
	c.deleteOrphanSubscription(ctx, 9)
	assert.Equal(t, int32(1), c.subCreatesLost.Load())
}
