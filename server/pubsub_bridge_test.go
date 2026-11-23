// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// bridgeServer is a server with PubSub and a Method that runs fn with the
// context of the call, as a Method of a companion specification would.
type bridgeServer struct {
	srv *server.Server
	url string
	fn  func(ctx context.Context) ua.StatusCode
}

var bridgeMethod = ua.NewStringNodeID(0, "bridge-test")

func newBridgeServer(t *testing.T, opts ...server.Option) *bridgeServer {
	t.Helper()
	b := &bridgeServer{}
	b.srv, b.url = testutil.NewTestServer(t, opts...)
	b.srv.RegisterMethod(nid(id.Server), bridgeMethod, func(ctx context.Context, _, _ *ua.NodeID, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, b.fn(ctx)
	})
	return b
}

func (b *bridgeServer) call(t *testing.T, fn func(ctx context.Context) ua.StatusCode) ua.StatusCode {
	t.Helper()
	b.fn = fn
	c := testutil.NewTestClient(t, b.url)
	return psCall(t, c, nid(id.Server), bridgeMethod).StatusCode
}

func bridgeConfig(name string) *ua.PubSubConfiguration2DataType {
	conn := pubsub.UDPConnection(name, "opc.udp://239.0.0.1:4840", uint16(7))
	conn.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("G", 0, time.Second)}
	return &ua.PubSubConfiguration2DataType{Connections: []*ua.PubSubConnectionDataType{conn}}
}

// TestPubSubBridge: ReservePubSubIDs and UpdatePubSubConfiguration act as
// ReserveIds and CloseAndUpdate (Part 14 §9.1.3.7.4, §9.1.3.7.5) for the
// session of a Method call, and Revert undoes an update.
func TestPubSubBridge(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t, server.WithPubSub(nil))
	rt := b.srv.PubSub()

	var res *server.PubSubIDReservation
	require.Equal(t, ua.StatusOK, b.call(t, func(ctx context.Context) ua.StatusCode {
		var sc ua.StatusCode
		res, sc = b.srv.ReservePubSubIDs(ctx, 1, 2)
		return sc
	}))
	require.Equal(t, []uint16{0x8000}, res.WriterGroupIDs)
	require.Equal(t, []uint16{0x8000, 0x8001}, res.DataSetWriterIDs)
	require.NotNil(t, res.DefaultPublisherID)

	var u *server.PubSubConfigurationUpdate
	require.Equal(t, ua.StatusOK, b.call(t, func(ctx context.Context) ua.StatusCode {
		var sc ua.StatusCode
		u, sc = b.srv.UpdatePubSubConfiguration(ctx, bridgeConfig("A"), true,
			[]*ua.PubSubConfigurationRefDataType{{ConfigurationMask: refAdd | refConn}, {ConfigurationMask: refAdd | refWG}})
		return sc
	}))
	require.True(t, u.ChangesApplied)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, u.ReferenceResults)
	require.Len(t, u.ConfigurationObjects, 2)
	require.Len(t, u.ConfigurationValues, 2)
	_, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, "A")
	require.True(t, ok)

	require.NoError(t, u.Revert())
	_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, "A")
	require.False(t, ok)
	require.NoError(t, u.Revert(), "a second Revert does nothing")
	require.NoError(t, (*server.PubSubConfigurationUpdate)(nil).Revert())

	// A change after the update: Revert leaves the configuration alone.
	require.Equal(t, ua.StatusOK, b.call(t, func(ctx context.Context) ua.StatusCode {
		var sc ua.StatusCode
		u, sc = b.srv.UpdatePubSubConfiguration(ctx, bridgeConfig("B"), false, []*ua.PubSubConfigurationRefDataType{{ConfigurationMask: refAdd | refConn}})
		return sc
	}))
	_, err := rt.AddConnection(pubsub.UDPConnection("Other", "opc.udp://239.0.0.1:4840", uint16(8)))
	require.NoError(t, err)
	require.True(t, errors.Is(u.Revert(), server.ErrPubSubChanged))
	_, ok = rt.Lookup(pubsub.KindConnection, pubsub.Root, "B")
	require.True(t, ok)

	// A match changes nothing; Revert of it does nothing.
	require.Equal(t, ua.StatusOK, b.call(t, func(ctx context.Context) ua.StatusCode {
		var sc ua.StatusCode
		u, sc = b.srv.UpdatePubSubConfiguration(ctx, bridgeConfig("B"), false, []*ua.PubSubConfigurationRefDataType{{ConfigurationMask: refMatch | refConn}})
		return sc
	}))
	require.False(t, u.ChangesApplied)
	require.NoError(t, u.Revert())

	// Argument errors.
	for name, want := range map[string]ua.StatusCode{"nil": ua.StatusBadTypeMismatch, "norefs": ua.StatusBadNothingToDo} {
		cfg := bridgeConfig("C")
		if name == "nil" {
			cfg = nil
		}
		require.Equal(t, want, b.call(t, func(ctx context.Context) ua.StatusCode {
			_, sc := b.srv.UpdatePubSubConfiguration(ctx, cfg, false, nil)
			return sc
		}), name)
	}

	// Outside a Method call there is no session.
	_, sc := b.srv.ReservePubSubIDs(context.Background(), 1, 1)
	require.Equal(t, ua.StatusBadSessionIDInvalid, sc)
}

// denyCall is an AccessController that denies the Method deny.
type denyCall struct {
	server.DefaultAccessController
	deny uint32
}

func (d denyCall) CheckCall(_ context.Context, _ *server.Session, m *ua.NodeID) ua.StatusCode {
	if m.Equal(nid(d.deny)) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

// TestPubSubBridgeAccess: the bridge checks what a call of ReserveIds or
// CloseAndUpdate by the same session would: the AccessController, the
// AccessRestrictions of the Method node and the PubSubAuthorizer.
func TestPubSubBridgeAccess(t *testing.T) {
	t.Parallel()
	refs := []*ua.PubSubConfigurationRefDataType{{ConfigurationMask: refAdd | refConn}}
	update := func(b *bridgeServer) func(ctx context.Context) ua.StatusCode {
		return func(ctx context.Context) ua.StatusCode {
			_, sc := b.srv.UpdatePubSubConfiguration(ctx, bridgeConfig("X"), false, refs)
			return sc
		}
	}
	reserve := func(b *bridgeServer) func(ctx context.Context) ua.StatusCode {
		return func(ctx context.Context) ua.StatusCode {
			_, sc := b.srv.ReservePubSubIDs(ctx, 1, 1)
			return sc
		}
	}

	t.Run("no pubsub", func(t *testing.T) {
		t.Parallel()
		b := newBridgeServer(t)
		require.Equal(t, ua.StatusBadNotSupported, b.call(t, update(b)))
		require.Equal(t, ua.StatusBadNotSupported, b.call(t, reserve(b)))
	})
	t.Run("access controller", func(t *testing.T) {
		t.Parallel()
		b := newBridgeServer(t, server.WithPubSub(nil), server.WithAccessController(denyCall{deny: id.PublishSubscribePubSubConfigurationCloseAndUpdate}))
		require.Equal(t, ua.StatusBadUserAccessDenied, b.call(t, update(b)))
		require.Equal(t, ua.StatusOK, b.call(t, reserve(b)))
	})
	t.Run("authorizer", func(t *testing.T) {
		t.Parallel()
		var names []string
		b := newBridgeServer(t, server.WithPubSub(nil), server.WithPubSubAuthorizer(func(_ context.Context, c *server.MethodCaller, m string) ua.StatusCode {
			names = append(names, m)
			if c == nil || c.SessionID == nil {
				return ua.StatusBadInternalError
			}
			return ua.StatusBadUserAccessDenied
		}))
		require.Equal(t, ua.StatusBadUserAccessDenied, b.call(t, update(b)))
		require.Equal(t, ua.StatusBadUserAccessDenied, b.call(t, reserve(b)))
		require.Equal(t, []string{"CloseAndUpdate", "ReserveIds"}, names)
	})
	t.Run("access restrictions", func(t *testing.T) {
		t.Parallel()
		b := newBridgeServer(t, server.WithPubSub(nil))
		n := b.srv.Node(nid(id.PublishSubscribePubSubConfigurationCloseAndUpdate))
		require.NotNil(t, n)
		require.NoError(t, n.SetAttribute(ua.AttributeIDAccessRestrictions, server.DataValueFromValue(uint16(ua.AccessRestrictionTypeSigningRequired))))
		require.Equal(t, ua.StatusBadSecurityModeInsufficient, b.call(t, update(b)))
	})
}
