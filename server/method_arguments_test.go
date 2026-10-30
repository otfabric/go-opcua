// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestSetMethodArguments_Errors(t *testing.T) {
	var nilNode *Node
	require.ErrorIs(t, nilNode.SetMethodArguments(nil, nil), ua.StatusBadNodeIDUnknown)

	obj := NewFolderNode(ua.NewStringNodeID(1, "o"), "o")
	require.ErrorIs(t, obj.SetMethodArguments(nil, nil), ua.StatusBadNodeClassInvalid)

	m := NewFolderNode(ua.NewStringNodeID(1, "m"), "m")
	m.SetNodeClass(ua.NodeClassMethod)
	require.ErrorIs(t, m.SetMethodArguments(nil, nil), ua.StatusBadNodeIDUnknown, "not in a namespace")

	srv, err := New(InsecureNoSecurity())
	require.NoError(t, err)
	ns := NewNodeNameSpace(srv, "urn:test")
	ns.AddNode(m)
	require.ErrorIs(t, m.SetMethodArguments([]*ua.Argument{nil}, nil), ua.StatusBadInvalidArgument)
	require.NoError(t, m.SetMethodArguments([]*ua.Argument{{Name: "x"}}, nil))
	require.NotNil(t, ns.Node(ua.NewStringNodeID(ns.ID(), "m.InputArguments")))
	require.Nil(t, ns.Node(ua.NewStringNodeID(ns.ID(), "m.OutputArguments")))
}

func TestChildIdentifier(t *testing.T) {
	require.Equal(t, "square", childIdentifier(ua.NewStringNodeID(2, "square")))
	require.Equal(t, "i=7", childIdentifier(ua.NewNumericNodeID(2, 7)))
	require.Equal(t, "i=7", childIdentifier(ua.NewNumericNodeID(0, 7)))
	require.Equal(t, "ns=1;s=x", childIdentifier(ua.NewStringNodeID(3, "ns=1;s=x")), "a string identifier is kept as it is")

	require.Equal(t, "ns=1;s=Demo.HistoricalEventFilter", childPropertyID(ua.NewStringNodeID(1, "Demo"), "HistoricalEventFilter").String())
	require.Equal(t, "ns=2;s=i=7001.HistoricalEventFilter", childPropertyID(ua.NewNumericNodeID(2, 7001), "HistoricalEventFilter").String())
}
