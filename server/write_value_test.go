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
