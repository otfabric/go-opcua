// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// ns0Write writes v to the Value of the ns0 node i through the Write service
// without a session.
func ns0Write(t *testing.T, s *Server, i uint32, v any) ua.StatusCode {
	t.Helper()
	resp, err := (&AttributeService{srv: s}).Write(context.Background(), nil, &ua.WriteRequest{
		RequestHeader: reqHeader(),
		NodesToWrite: []*ua.WriteValue{{
			NodeID:      ua.NewNumericNodeID(0, i),
			AttributeID: ua.AttributeIDValue,
			Value:       &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
		}},
	}, 1)
	require.NoError(t, err)
	return resp.(*ua.WriteResponse).Results[0]
}

func TestServerObjectVariablesNotWritable(t *testing.T) {
	s := newTestServer()
	for _, tc := range []struct {
		name string
		id   uint32
		v    any
	}{
		// Built by the server.
		{"CurrentTime", id.ServerServerStatusCurrentTime, int64(0)},
		{"NamespaceArray", id.ServerNamespaceArray, []string{"urn:x"}},
		{"ServerStatus.State", id.ServerServerStatusState, int32(1)},
		{"BuildInfo.ProductName", id.ServerServerStatusBuildInfoProductName, "x"},
		{"MaxNodesPerRead", id.ServerServerCapabilitiesOperationLimitsMaxNodesPerRead, uint32(1)},
		// Imported without an AccessLevel attribute.
		{"ServiceLevel", id.ServerServiceLevel, byte(0)},
		{"Auditing", id.ServerAuditing, true},
		{"RedundancySupport", id.ServerServerRedundancyRedundancySupport, int32(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, ua.StatusBadNotWritable, ns0Write(t, s, tc.id, tc.v))
			n := s.Node(ua.NewNumericNodeID(0, tc.id))
			require.NotNil(t, n)
			al, err := n.Attribute(ua.AttributeIDAccessLevel)
			require.NoError(t, err)
			require.Equal(t, byte(ua.AccessLevelTypeCurrentRead), al.Value.Value.Value())
		})
	}
}

func TestServerObjectVariablesNotWritableUnderRBAC(t *testing.T) {
	s := newTestServer()
	s.cfg.accessController = &RBACAccessController{srv: s}
	for _, i := range []uint32{
		id.ServerServerStatusCurrentTime,
		id.ServerNamespaceArray,
		id.ServerServerStatusState,
		id.ServerServerCapabilitiesOperationLimitsMaxNodesPerRead,
	} {
		require.Equal(t, ua.StatusBadNotWritable, ns0Write(t, s, i, int32(0)), "i=%d", i)
	}
}
