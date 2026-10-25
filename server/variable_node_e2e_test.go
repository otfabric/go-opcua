// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestNewVariableNode_Client reads the attributes NewVariableNode gives a
// variable over the wire: the DataType of the value, its ValueRank and a
// BrowseName in the namespace of the node.
func TestNewVariableNode_Client(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	ns := server.NewNodeNameSpace(srv, "urn:test:variable-attributes")
	scalar := ns.AddNewVariableStringNode("Scalar", 1.5)
	array := ns.AddNewVariableStringNode("Array", []int32{1, 2, 3})
	dynamic := ns.AddNewVariableStringNode("Dynamic", func() *ua.DataValue { return server.DataValueFromValue("x") })

	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, tc := range []struct {
		n    *server.Node
		dt   uint32
		rank int32
	}{{scalar, id.Double, -1}, {array, id.Int32, 1}, {dynamic, id.String, -2}} {
		attrs, err := c.Node(tc.n.ID()).Attributes(ctx, ua.AttributeIDBrowseName, ua.AttributeIDDataType, ua.AttributeIDValueRank)
		require.NoError(t, err)
		require.Equal(t, ns.ID(), attrs[0].Value.QualifiedName().NamespaceIndex)
		require.Equal(t, tc.dt, attrs[1].Value.NodeID().IntID(), tc.n.ID().String())
		require.Equal(t, tc.rank, attrs[2].Value.Value())
	}
}
