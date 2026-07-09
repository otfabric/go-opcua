// SPDX-License-Identifier: MIT

package refs

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestHasSubtype(t *testing.T) {
	typeID := ua.NewNumericExpandedNodeID(0, id.BaseObjectType)
	ref := HasSubtype(typeID)
	require.NotNil(t, ref)
	require.True(t, ref.IsForward)
	require.Equal(t, uint32(id.HasSubtype), ref.ReferenceTypeID.IntID())
	require.Equal(t, typeID, ref.TypeDefinition)
}

func TestOrganizes(t *testing.T) {
	nid := ua.NewStringNodeID(2, "TestNode")
	typeID := ua.NewNumericExpandedNodeID(0, id.BaseVariableType)
	ref := Organizes(nid, "TestNode", "Test Node", typeID)
	require.NotNil(t, ref)
	require.True(t, ref.IsForward)
	require.Equal(t, uint32(id.Organizes), ref.ReferenceTypeID.IntID())
	require.Equal(t, "TestNode", ref.BrowseName.Name)
	require.Equal(t, "Test Node", ref.DisplayName.Text)
	require.Equal(t, typeID, ref.TypeDefinition)
}
