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

// TestSetMethodArguments_Client gives a method its arguments with
// SetMethodArguments and reads them back with Client.MethodArguments, browses
// the Properties and calls the method, whose inputs the server checks
// against them.
func TestSetMethodArguments_Client(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	ns := server.NewNodeNameSpace(srv, "urn:test:method-arguments")
	root, err := srv.Namespace(0)
	require.NoError(t, err)
	root.Objects().AddRef(ns.Objects(), id.HasComponent, true)

	objID := ua.NewStringNodeID(ns.ID(), "Calc")
	obj := server.NewFolderNode(objID, "Calc")
	ns.AddNode(obj)
	ns.Objects().AddRef(obj, id.HasComponent, true)

	methodID := ua.NewNumericNodeID(ns.ID(), 7001)
	method := server.NewFolderNode(methodID, "Add")
	method.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(method)
	obj.AddRef(method, id.HasComponent, true)

	in := []*ua.Argument{
		{Name: "a", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1, Description: ua.NewLocalizedText("first")},
		{Name: "b", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1, Description: ua.NewLocalizedText("second")},
	}
	out := []*ua.Argument{{Name: "sum", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1, Description: ua.NewLocalizedText("a+b")}}
	// Set twice: the second call replaces the first.
	require.NoError(t, method.SetMethodArguments(out, nil))
	require.NoError(t, method.SetMethodArguments(in, out))
	srv.RegisterMethod(objID, methodID, func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return []*ua.Variant{ua.MustVariant(int32(args[0].Int() + args[1].Int()))}, ua.StatusOK
	})

	c := testutil.NewTestClient(t, url)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gotIn, gotOut, err := c.MethodArguments(ctx, objID, methodID)
	require.NoError(t, err)
	require.Len(t, gotIn, 2)
	require.Len(t, gotOut, 1)
	require.Equal(t, "a", gotIn[0].Name)
	require.Equal(t, "b", gotIn[1].Name)
	require.Equal(t, "sum", gotOut[0].Name)
	require.Equal(t, uint32(id.Int32), gotOut[0].DataType.IntID())

	// The Properties as Part 3 §5.7 describes them.
	refs, err := c.Node(methodID).References(ctx, id.HasProperty, ua.BrowseDirectionForward, ua.NodeClassVariable, true)
	require.NoError(t, err)
	require.Len(t, refs, 2)
	for _, r := range refs {
		require.Equal(t, uint16(0), r.BrowseName.NamespaceIndex)
		require.Equal(t, uint32(id.PropertyType), r.TypeDefinition.NodeID.IntID(), r.BrowseName.Name)
		prop := c.Node(r.NodeID.NodeID)
		attrs, err := prop.Attributes(ctx, ua.AttributeIDDataType, ua.AttributeIDValueRank, ua.AttributeIDArrayDimensions)
		require.NoError(t, err)
		require.Equal(t, uint32(id.Argument), attrs[0].Value.NodeID().IntID())
		require.Equal(t, int32(1), attrs[1].Value.Value())
	}
	require.Equal(t, "i=7001.InputArguments", refs[0].NodeID.NodeID.StringID())

	res, err := c.CallMethod(ctx, objID, methodID, int32(2), int32(3))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, int64(5), res.OutputArguments[0].Int())
	// One argument short: the server checks the call against InputArguments.
	res, err = c.CallMethod(ctx, objID, methodID, int32(2))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadArgumentsMissing, res.StatusCode)

	// Without arguments the Properties go away.
	require.NoError(t, method.SetMethodArguments(nil, nil))
	gotIn, gotOut, err = c.MethodArguments(ctx, objID, methodID)
	require.NoError(t, err)
	require.Empty(t, gotIn)
	require.Empty(t, gotOut)
	require.Nil(t, ns.Node(ua.NewStringNodeID(ns.ID(), "i=7001.InputArguments")))
}
