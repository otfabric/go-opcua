// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// denyWrite is an AccessController that denies every Write.
type denyWrite struct{ server.DefaultAccessController }

func (denyWrite) CheckWrite(context.Context, *server.Session, *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}

// TestWriteValue: WriteValue writes for the session of a Method call with
// the checks of the Write service.
func TestWriteValue(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t)
	ns := server.NewNodeNameSpace(b.srv, "write-value")
	rw := ns.AddNewVariableStringNode("rw", 1.0)
	rwLevel := byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite)
	require.NoError(t, rw.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(rwLevel)))
	require.NoError(t, rw.SetAttribute(ua.AttributeIDUserAccessLevel, server.DataValueFromValue(rwLevel)))
	ro := ns.AddNewVariableStringNode("ro", 1.0)
	require.NoError(t, ro.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))
	write := func(n *ua.NodeID, v any) ua.StatusCode {
		return b.call(t, func(ctx context.Context) ua.StatusCode { return b.srv.WriteValue(ctx, n, ua.MustVariant(v)) })
	}

	require.Equal(t, ua.StatusOK, write(rw.ID(), 2.0))
	require.Equal(t, 2.0, rw.Value().Value.Value())
	require.Equal(t, ua.StatusBadNotWritable, write(ro.ID(), 2.0))
	require.Equal(t, ua.StatusBadNodeIDUnknown, write(ua.NewStringNodeID(ns.ID(), "nosuch"), 2.0))
	require.Equal(t, ua.StatusBadNodeIDUnknown, write(ua.NewStringNodeID(99, "nosuch"), 2.0))
	require.Equal(t, ua.StatusBadNodeIDInvalid, b.call(t, func(ctx context.Context) ua.StatusCode { return b.srv.WriteValue(ctx, nil, nil) }))

	var got *server.ValueWrite
	rw.SetValueWriter(func(_ context.Context, w *server.ValueWrite) ua.StatusCode { got = w; return ua.StatusBadOutOfRange })
	require.Equal(t, ua.StatusBadOutOfRange, write(rw.ID(), 3.0))
	require.NotNil(t, got)
	require.Equal(t, 3.0, got.Value.Value.Value())
	require.NotNil(t, got.Session)

	require.Equal(t, ua.StatusBadSessionIDInvalid, b.srv.WriteValue(context.Background(), rw.ID(), ua.MustVariant(1.0)))

	d := newBridgeServer(t, server.WithAccessController(denyWrite{}))
	dns := server.NewNodeNameSpace(d.srv, "write-value")
	n := dns.AddNewVariableStringNode("rw", 1.0)
	require.NoError(t, n.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(rwLevel)))
	require.Equal(t, ua.StatusBadUserAccessDenied, d.call(t, func(ctx context.Context) ua.StatusCode { return d.srv.WriteValue(ctx, n.ID(), ua.MustVariant(2.0)) }))
}

// denyRead is an AccessController that denies every Read outside
// namespace 0.
type denyRead struct{ server.DefaultAccessController }

func (denyRead) CheckRead(_ context.Context, _ *server.Session, n *ua.NodeID) ua.StatusCode {
	if n != nil && n.Namespace() != 0 {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

// TestReadValue: ReadValue reads for the session of a Method call with the
// checks of the Read service.
func TestReadValue(t *testing.T) {
	t.Parallel()
	b := newBridgeServer(t)
	ns := server.NewNodeNameSpace(b.srv, "read-value")
	rd := ns.AddNewVariableStringNode("rd", 4.5)
	hidden := ns.AddNewVariableStringNode("hidden", 1.0)
	require.NoError(t, hidden.SetAttribute(ua.AttributeIDUserAccessLevel, server.DataValueFromValue(byte(0))))
	none := ns.AddNewVariableStringNode("none", 1.0)
	require.NoError(t, none.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(byte(0))))
	secret := ns.AddNewVariableStringNode("secret", 1.0)
	require.NoError(t, secret.SetAttribute(ua.AttributeIDAccessRestrictions,
		server.DataValueFromValue(uint16(ua.AccessRestrictionTypeEncryptionRequired))))
	read := func(n *ua.NodeID) (any, ua.StatusCode) {
		var got any
		sc := b.call(t, func(ctx context.Context) ua.StatusCode {
			dv, sc := b.srv.ReadValue(ctx, n)
			if dv != nil {
				got = dv.Value.Value()
			}
			return sc
		})
		return got, sc
	}

	v, sc := read(rd.ID())
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, 4.5, v)
	_, sc = read(hidden.ID())
	require.Equal(t, ua.StatusBadUserAccessDenied, sc)
	_, sc = read(none.ID())
	require.Equal(t, ua.StatusBadNotReadable, sc)
	_, sc = read(secret.ID())
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, sc)
	_, sc = read(ua.NewStringNodeID(ns.ID(), "nosuch"))
	require.Equal(t, ua.StatusBadNodeIDUnknown, sc)
	_, sc = read(nil)
	require.Equal(t, ua.StatusBadNodeIDInvalid, sc)
	_, sc = b.srv.ReadValue(context.Background(), rd.ID())
	require.Equal(t, ua.StatusBadSessionIDInvalid, sc)

	d := newBridgeServer(t, server.WithAccessController(denyRead{}))
	dns := server.NewNodeNameSpace(d.srv, "read-value")
	n := dns.AddNewVariableStringNode("rd", 1.0)
	require.Equal(t, ua.StatusBadUserAccessDenied, d.call(t, func(ctx context.Context) ua.StatusCode {
		_, sc := d.srv.ReadValue(ctx, n.ID())
		return sc
	}))
}
