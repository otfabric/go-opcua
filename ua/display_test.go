// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/stretchr/testify/assert"
)

func TestReferenceTypeDisplayName(t *testing.T) {
	assert.Equal(t, "", ReferenceTypeDisplayName(nil))
	assert.Equal(t, "HasComponent", ReferenceTypeDisplayName(NewNumericNodeID(0, id.HasComponent)))
	assert.Contains(t, ReferenceTypeDisplayName(NewNumericNodeID(3, 99)), "ns=3")
}

func TestTypeDefinitionDisplayName(t *testing.T) {
	assert.Equal(t, "", TypeDefinitionDisplayName(nil))
	assert.Equal(t, "BaseDataVariableType", TypeDefinitionDisplayName(NewNumericNodeID(0, id.BaseDataVariableType)))
	assert.Equal(t, "ServerType", TypeDefinitionDisplayName(NewNumericNodeID(0, id.ServerType)))
}

func TestDataTypeDisplayName(t *testing.T) {
	assert.Equal(t, "", DataTypeDisplayName(nil))
	assert.Equal(t, "Int32", DataTypeDisplayName(NewNumericNodeID(0, id.Int32)))
}

func TestStandardNodeID(t *testing.T) {
	nid, ok := StandardNodeID("ObjectsFolder")
	assert.True(t, ok)
	assert.Equal(t, uint32(id.ObjectsFolder), nid.IntID())

	_, ok = StandardNodeID("not-a-real-node")
	assert.False(t, ok)
}
