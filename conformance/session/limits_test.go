// SPDX-License-Identifier: MIT

package session

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestSession_Limits: CreateSession past the session limit is
// Bad_TooManySessions (Part 4 §5.6.2), CreateSubscription past the
// per-session or the server-wide limit Bad_TooManySubscriptions (§5.13.2),
// and the limits are published in ServerCapabilities (Part 5 §6.3.2).
func TestSession_Limits(t *testing.T) {
	_, url := newServer(t,
		server.WithMaxSessions(2),
		server.WithMaxSubscriptions(3),
		server.WithMaxSubscriptionsPerSession(2),
	)
	ctx := context.Background()
	c1 := newClient(t, url)
	c2 := newClient(t, url)

	for nid, want := range map[uint32]uint32{
		id.ServerServerCapabilitiesMaxSessions:                2,
		id.ServerServerCapabilitiesMaxSubscriptions:           3,
		id.ServerServerCapabilitiesMaxSubscriptionsPerSession: 2,
	} {
		v, err := c1.Node(ua.NewNumericNodeID(0, nid)).Value(ctx)
		require.NoError(t, err)
		require.Equal(t, want, v.Value(), "capability i=%d", nid)
	}

	c3, err := dialClient(t, url)
	require.ErrorIs(t, err, ua.StatusBadTooManySessions)
	if c3 != nil {
		_ = c3.Close(ctx)
	}

	subscribe := func(c *opcua.Client) error {
		_, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *opcua.PublishNotificationData, 1))
		return err
	}
	require.NoError(t, subscribe(c1))
	require.NoError(t, subscribe(c1))
	require.ErrorIs(t, subscribe(c1), ua.StatusBadTooManySubscriptions, "per session")
	require.NoError(t, subscribe(c2))
	require.ErrorIs(t, subscribe(c2), ua.StatusBadTooManySubscriptions, "server-wide")

	// A closed session frees its place.
	require.NoError(t, c2.Close(ctx))
	eventually(t, func() bool {
		c, err := dialClient(t, url)
		if err != nil {
			return false
		}
		_ = c.Close(ctx)
		return true
	}, "a session place after Close")
}
