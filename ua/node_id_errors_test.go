// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/json"
	"encoding/xml"
	stderrors "errors"
	"testing"

	"github.com/otfabric/go-opcua/errors"
	"github.com/stretchr/testify/require"
)

func TestParseNodeID_RejectsExpandedForms(t *testing.T) {
	// A plain NodeID cannot carry a namespace URI or a server index.
	n, err := ParseNodeID("nsu=http://example.com/;i=1")
	require.True(t, stderrors.Is(err, errors.ErrInvalidNamespace))
	require.Nil(t, n)

	n, err = ParseNodeID("svr=2;i=1")
	require.True(t, stderrors.Is(err, errors.ErrInvalidNodeID))
	require.Nil(t, n)

	require.Panics(t, func() { MustParseNodeID("ns=abc;i=1") })
	require.Equal(t, NewNumericNodeID(2, 70000).String(), MustParseNodeID("ns=2;i=70000").String())
}

func TestNodeID_SetterRanges(t *testing.T) {
	four := NewFourByteNodeID(1, 2)
	err := four.SetNamespace(256)
	require.True(t, stderrors.Is(err, errors.ErrInvalidNodeID))
	require.Equal(t, uint16(1), four.Namespace(), "a rejected namespace must not be applied")
	err = four.SetIntID(70000)
	require.True(t, stderrors.Is(err, errors.ErrInvalidNodeID))
	require.Equal(t, uint32(2), four.IntID())

	two := NewTwoByteNodeID(3)
	require.True(t, stderrors.Is(two.SetIntID(256), errors.ErrInvalidNodeID))
	require.True(t, stderrors.Is(two.SetNamespace(1), errors.ErrInvalidNodeID))
	require.NoError(t, two.SetNamespace(0))
	require.Equal(t, uint32(3), two.IntID())

	require.True(t, stderrors.Is(NewStringNodeID(1, "a").SetIntID(1), errors.ErrInvalidNodeID))
}

func TestNodeID_UnmarshalErrors(t *testing.T) {
	var n NodeID
	require.Error(t, json.Unmarshal([]byte(`42`), &n), "a node id must be a JSON string")
	err := json.Unmarshal([]byte(`"ns=x;i=1"`), &n)
	require.Error(t, err)
	require.Equal(t, NodeID{}, n, "a failed unmarshal must leave the target untouched")

	err = xml.Unmarshal([]byte(`<NodeID>i=1</Other>`), &n)
	require.Error(t, err, "malformed XML")
	err = xml.Unmarshal([]byte(`<NodeID>ns=x;i=1</NodeID>`), &n)
	require.Error(t, err)
	require.Equal(t, NodeID{}, n)
}

func TestNewNodeIDFromExpandedNodeID_GUIDWithoutData4(t *testing.T) {
	src := &ExpandedNodeID{NodeID: &NodeID{mask: NodeIDTypeGUID, ns: 3, gid: &GUID{Data1: 1, Data2: 2, Data3: 3}}}
	got := NewNodeIDFromExpandedNodeID(src)
	require.Equal(t, NodeIDTypeGUID, got.Type())
	require.Equal(t, uint16(3), got.Namespace())
	require.NotSame(t, src.NodeID.gid, got.gid, "the GUID must be copied")
	require.Equal(t, &GUID{Data1: 1, Data2: 2, Data3: 3}, got.gid)
}
