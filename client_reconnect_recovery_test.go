// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithSubscriptionRecoveryHandler_OptionRegistered verifies that
// WithSubscriptionRecoveryHandler stores the callback in Config correctly.
func TestWithSubscriptionRecoveryHandler_OptionRegistered(t *testing.T) {
	var received []SubscriptionRecoveryEvent

	c, err := NewClient("opc.tcp://example.com:4840",
		WithSubscriptionRecoveryHandler(func(ev SubscriptionRecoveryEvent) {
			received = append(received, ev)
		}),
	)
	require.NoError(t, err)

	// The handler must be wired into the client.
	require.NotNil(t, c.recoveryFunc, "recoveryFunc must be set on the client")
}

// TestNotifyRecovery_DeliversEvent verifies that notifyRecovery invokes the
// registered handler with the supplied event.
func TestNotifyRecovery_DeliversEvent(t *testing.T) {
	var received []SubscriptionRecoveryEvent

	c, err := NewClient("opc.tcp://example.com:4840",
		WithSubscriptionRecoveryHandler(func(ev SubscriptionRecoveryEvent) {
			received = append(received, ev)
		}),
	)
	require.NoError(t, err)

	want := SubscriptionRecoveryEvent{
		SubscriptionID:           42,
		Outcome:                  SubscriptionRecoveryTransferred,
		AvailableSequenceNumbers: []uint32{1, 2, 3},
		Detail:                   "transferred successfully",
	}
	c.notifyRecovery(want)

	require.Len(t, received, 1, "handler must be called exactly once")
	assert.Equal(t, want, received[0])
}

// TestNotifyRecovery_NilHandler_NoPanic verifies that notifyRecovery is safe
// when no handler is registered.
func TestNotifyRecovery_NilHandler_NoPanic(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	require.Nil(t, c.recoveryFunc)

	// Must not panic.
	assert.NotPanics(t, func() {
		c.notifyRecovery(SubscriptionRecoveryEvent{
			SubscriptionID: 1,
			Outcome:        SubscriptionRecoveryRecreated,
			Detail:         "recreated",
		})
	})
}

// TestNotifyRecovery_AllOutcomes verifies all defined outcome constants can be
// delivered through the handler without error.
func TestNotifyRecovery_AllOutcomes(t *testing.T) {
	outcomes := []SubscriptionRecoveryOutcome{
		SubscriptionRecoveryTransferred,
		SubscriptionRecoveryRepublished,
		SubscriptionRecoveryRecreated,
		SubscriptionRecoveryPartial,
		SubscriptionRecoveryUnrecoverableGap,
	}

	var received []SubscriptionRecoveryEvent
	c, err := NewClient("opc.tcp://example.com:4840",
		WithSubscriptionRecoveryHandler(func(ev SubscriptionRecoveryEvent) {
			received = append(received, ev)
		}),
	)
	require.NoError(t, err)

	for i, o := range outcomes {
		c.notifyRecovery(SubscriptionRecoveryEvent{
			SubscriptionID: uint32(i + 1),
			Outcome:        o,
			Detail:         string(o),
		})
	}

	require.Len(t, received, len(outcomes))
	for i, ev := range received {
		assert.Equal(t, outcomes[i], ev.Outcome)
	}
}

// TestSendRepublishRequests_GapDetected verifies that sendRepublishRequests
// sets gapDetected when the subscription's nextSeq is absent from availableSeq.
// The test exercises the gap-detection logic without a live connection by
// populating a Subscription directly and invoking sendRepublishRequests with a
// mismatched availableSeq; the first iteration hits the nil-session guard and
// returns immediately, but the gap flag is already set.
func TestSendRepublishRequests_GapDetected(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	sub := &Subscription{
		SubscriptionID: 99,
		nextSeq:        5,
	}

	// availableSeq does not contain nextSeq=5 → gap must be detected.
	// The call returns immediately because there is no active session.
	rr, _ := c.sendRepublishRequests(context.Background(), sub, []uint32{1, 2, 3})
	assert.True(t, rr.gapDetected, "gapDetected must be set when nextSeq is absent from availableSeq")
	assert.Equal(t, 0, rr.republishedCount, "no notifications can be republished without a session")
}

// TestSendRepublishRequests_NoGap verifies that sendRepublishRequests does NOT
// set gapDetected when nextSeq is present in availableSeq.
func TestSendRepublishRequests_NoGap(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	sub := &Subscription{
		SubscriptionID: 99,
		nextSeq:        2,
	}

	// availableSeq contains nextSeq=2 → no gap.
	rr, _ := c.sendRepublishRequests(context.Background(), sub, []uint32{1, 2, 3})
	assert.False(t, rr.gapDetected, "gapDetected must be false when nextSeq is in availableSeq")
}

// TestSendRepublishRequests_EmptyAvailable verifies that sendRepublishRequests
// does NOT set gapDetected when availableSeq is empty (server may have no buffer).
func TestSendRepublishRequests_EmptyAvailable(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	sub := &Subscription{
		SubscriptionID: 99,
		nextSeq:        1,
	}

	rr, _ := c.sendRepublishRequests(context.Background(), sub, nil)
	assert.False(t, rr.gapDetected, "gapDetected must be false when availableSeq is empty")
}
