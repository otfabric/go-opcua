// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestBuiltinNodeSetValuesAreNotSharedBetweenServers: the built-in node set
// is parsed and its values are decoded once per process. The decoded
// Variants used to be handed to every server, so the arrays and structures
// in them were one piece of memory for the whole process: an application
// that modified what Node.Value returned - an element of EnumStrings, a
// field of an Argument - changed the value in every other server, and in
// every server created afterwards.
func TestBuiltinNodeSetValuesAreNotSharedBetweenServers(t *testing.T) {
	newServer := func() *Server {
		t.Helper()
		s, err := New(EndPoint("localhost", 0))
		require.NoError(t, err)
		return s
	}
	texts := func(s *Server) []*ua.LocalizedText {
		t.Helper()
		v, err := s.Node(ua.NewNumericNodeID(0, id.ServerStateEnumStrings)).Attribute(ua.AttributeIDValue)
		require.NoError(t, err)
		return v.Value.Value.Value().([]*ua.LocalizedText)
	}
	args := func(s *Server) []*ua.ExtensionObject {
		t.Helper()
		v, err := s.Node(ua.NewNumericNodeID(0, id.ServerGetMonitoredItemsInputArguments)).Attribute(ua.AttributeIDValue)
		require.NoError(t, err)
		return v.Value.Value.Value().([]*ua.ExtensionObject)
	}

	a, b := newServer(), newServer()
	require.Equal(t, "Running", texts(a)[0].Text)
	require.Equal(t, "Running", texts(b)[0].Text)
	require.Equal(t, "SubscriptionId", args(b)[0].Value.(*ua.Argument).Name)

	// Every way to write through what server a hands out.
	ta := texts(a)
	ta[0].Text = "HACKED"                     // the element itself
	ta[1] = ua.NewLocalizedText("REPLACED")   // the slice
	args(a)[0].Value.(*ua.Argument).Name = "" // a structure in an ExtensionObject
	args(a)[0].Value = nil                    // the ExtensionObject

	// Server a serves what was done to it ...
	require.Equal(t, "HACKED", texts(a)[0].Text)
	require.Equal(t, "REPLACED", texts(a)[1].Text)
	require.Nil(t, args(a)[0].Value)

	// ... and nobody else does: the server next to it, a later one.
	c := newServer()
	for name, s := range map[string]*Server{"other server": b, "later server": c} {
		require.Equal(t, "Running", texts(s)[0].Text, name)
		require.Equal(t, "Failed", texts(s)[1].Text, name)
		require.Equal(t, "SubscriptionId", args(s)[0].Value.(*ua.Argument).Name, name)
	}

	// A node keeps serving one value: reading does not decode again.
	require.Same(t, texts(b)[0], texts(b)[0])

	// Replacing the value of a node stays on that server as well.
	n := b.Node(ua.NewNumericNodeID(0, id.ServerStateEnumStrings))
	require.NoError(t, n.SetAttribute(ua.AttributeIDValue, DataValueFromValue([]*ua.LocalizedText{ua.NewLocalizedText("X")})))
	require.Equal(t, "X", texts(b)[0].Text)
	require.Equal(t, "Running", texts(c)[0].Text)
}
