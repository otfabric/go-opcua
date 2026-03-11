// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package opcua

import (
	"testing"

	"github.com/otfabric/opcua/id"
	"github.com/otfabric/opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestReferenceTypeDisplayName(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		require.Equal(t, "", ReferenceTypeDisplayName(nil))
	})
	t.Run("well-known ns=0", func(t *testing.T) {
		nid := ua.NewNumericNodeID(0, 47) // HasComponent
		require.Equal(t, "HasComponent", ReferenceTypeDisplayName(nid))
		nid = ua.NewNumericNodeID(0, 35) // Organizes
		require.Equal(t, "Organizes", ReferenceTypeDisplayName(nid))
	})
	t.Run("unknown ns=0 falls back to NodeID string", func(t *testing.T) {
		nid := ua.NewNumericNodeID(0, 99999)
		require.Equal(t, nid.String(), ReferenceTypeDisplayName(nid))
	})
	t.Run("non-zero namespace falls back to NodeID string", func(t *testing.T) {
		nid := ua.NewNumericNodeID(1, 47)
		require.Equal(t, nid.String(), ReferenceTypeDisplayName(nid))
	})
}

func TestDataTypeDisplayName(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		require.Equal(t, "", DataTypeDisplayName(nil))
	})
	t.Run("well-known ns=0", func(t *testing.T) {
		nid := ua.NewNumericNodeID(0, 10) // Float
		require.Equal(t, "Float", DataTypeDisplayName(nid))
		nid = ua.NewNumericNodeID(0, 12) // String
		require.Equal(t, "String", DataTypeDisplayName(nid))
		nid = ua.NewNumericNodeID(0, 294) // UtcTime
		require.Equal(t, "UtcTime", DataTypeDisplayName(nid))
	})
	t.Run("unknown ns=0 falls back to NodeID string", func(t *testing.T) {
		nid := ua.NewNumericNodeID(0, 99999)
		require.Equal(t, nid.String(), DataTypeDisplayName(nid))
	})
	t.Run("non-zero namespace falls back to NodeID string", func(t *testing.T) {
		nid := ua.NewNumericNodeID(1, 10)
		require.Equal(t, nid.String(), DataTypeDisplayName(nid))
	})
}

func TestStandardNodeID(t *testing.T) {
	t.Run("short aliases", func(t *testing.T) {
		nid, ok := StandardNodeID("CurrentTime")
		require.True(t, ok)
		require.True(t, nid.Equal(ua.NewNumericNodeID(0, id.Server_ServerStatus_CurrentTime)))
		nid, ok = StandardNodeID("ServerStatus")
		require.True(t, ok)
		require.True(t, nid.Equal(ua.NewNumericNodeID(0, id.Server_ServerStatus)))
		nid, ok = StandardNodeID("Objects")
		require.True(t, ok)
		require.True(t, nid.Equal(ua.NewNumericNodeID(0, id.ObjectsFolder)))
	})
	t.Run("full name", func(t *testing.T) {
		nid, ok := StandardNodeID("Server")
		require.True(t, ok)
		require.True(t, nid.Equal(ua.NewNumericNodeID(0, id.Server)))
	})
	t.Run("unknown returns false", func(t *testing.T) {
		nid, ok := StandardNodeID("UnknownNode")
		require.False(t, ok)
		require.Nil(t, nid)
	})
}

func TestTypeDefinitionDisplayName(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		require.Equal(t, "", TypeDefinitionDisplayName(nil))
	})
	t.Run("VariableType ns=0", func(t *testing.T) {
		nid := ua.NewNumericNodeID(0, 68) // PropertyType
		require.Equal(t, "PropertyType", TypeDefinitionDisplayName(nid))
	})
	t.Run("ObjectType ns=0", func(t *testing.T) {
		nid := ua.NewNumericNodeID(0, 61) // FolderType
		require.Equal(t, "FolderType", TypeDefinitionDisplayName(nid))
	})
	t.Run("unknown ns=0 falls back to NodeID string", func(t *testing.T) {
		nid := ua.NewNumericNodeID(0, 99999)
		require.Equal(t, nid.String(), TypeDefinitionDisplayName(nid))
	})
	t.Run("non-zero namespace falls back to NodeID string", func(t *testing.T) {
		nid := ua.NewNumericNodeID(1, 68)
		require.Equal(t, nid.String(), TypeDefinitionDisplayName(nid))
	})
}
