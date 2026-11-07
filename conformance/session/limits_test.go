// SPDX-License-Identifier: MIT

package session

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
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

// TestSession_LimitReclaimsAbandoned: a client that loses its connection
// leaves its session behind until the session times out. A full server
// closes the session whose secure channel is gone to make room for a new
// client; a session on an open channel stays (TestSession_Limits).
func TestSession_LimitReclaimsAbandoned(t *testing.T) {
	_, url := newServer(t, server.WithMaxSessions(1))
	ctx := context.Background()
	proxy := testutil.NewChaosProxy(t, strings.TrimPrefix(url, "opc.tcp://"), 1)
	lost := newClient(t, proxy.EndpointURL(), opcua.SessionTimeout(30*time.Minute))
	_, err := lost.Node(ua.NewNumericNodeID(0, id.ServerServerStatusState)).Value(ctx)
	require.NoError(t, err)

	// The connection goes, the session stays on the server.
	proxy.SetRefuse(true)
	proxy.DropAll()

	var c *opcua.Client
	eventually(t, func() bool {
		c, err = dialClient(t, url)
		return err == nil
	}, "a new session once the old one's channel is gone")
	_, err = c.Node(ua.NewNumericNodeID(0, id.ServerServerStatusState)).Value(ctx)
	require.NoError(t, err)

	// The server is full again, of a session on an open channel.
	other, err := dialClient(t, url)
	require.ErrorIs(t, err, ua.StatusBadTooManySessions)
	if other != nil {
		_ = other.Close(ctx)
	}
}
