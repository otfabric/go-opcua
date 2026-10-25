// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestPubSubConfigurationMethods configures the PubSub of a server through
// the PublishSubscribe methods (Part 14 §9), with an authorizer that only
// lets callers on an encrypted channel remove connections.
func TestPubSubConfigurationMethods(t *testing.T) {
	_, url := newServer(t,
		server.WithPubSub(nil),
		server.WithPubSubAuthorizer(func(_ context.Context, caller *server.MethodCaller, method string) ua.StatusCode {
			if method == "RemoveConnection" && caller.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
				return ua.StatusBadSecurityModeInsufficient
			}
			return ua.StatusOK
		}))
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()
	r := remote.New(c)

	conn, err := r.AddConnection(ctx, pubsub.UDPConnection("c", "opc.udp://127.0.0.1:1", uint16(1)))
	require.NoError(t, err)
	state, err := r.State(ctx, conn)
	require.NoError(t, err)
	require.Contains(t, []ua.PubSubState{ua.PubSubStatePreOperational, ua.PubSubStateOperational, ua.PubSubStateError}, state)
	require.ErrorIs(t, r.RemoveConnection(ctx, conn), ua.StatusBadSecurityModeInsufficient)

	refs, err := c.Node(ua.NewNumericNodeID(0, id.PublishSubscribe)).References(ctx, id.HasPubSubConnection, ua.BrowseDirectionForward, ua.NodeClassObject, false)
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.Equal(t, conn, refs[0].NodeID.NodeID)
}
