// SPDX-License-Identifier: MIT

package conformance

import (
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestMisc_ServerStatus(t *testing.T) {
	c, _, ctx := setup(t)

	status, err := c.ServerStatus(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	require.False(t, status.CurrentTime.IsZero())
}

func TestMisc_Namespaces(t *testing.T) {
	c, f, ctx := setup(t)

	arr, err := c.NamespaceArray(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, arr)
	require.Equal(t, "http://opcfoundation.org/UA/", arr[0])

	idx, err := c.FindNamespace(ctx, "http://otfabric.com/conformance")
	require.NoError(t, err)
	require.Equal(t, f.NSIndex, idx)

	require.NoError(t, c.UpdateNamespaces(ctx))

	uri, err := c.NamespaceURI(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, "http://opcfoundation.org/UA/", uri)

	_, err = c.NamespaceURI(ctx, 60000)
	require.Error(t, err)

	require.NotEmpty(t, c.Namespaces())
}

func TestMisc_Discovery(t *testing.T) {
	c, _, ctx := setup(t)

	eps, err := c.GetEndpoints(ctx)
	require.NoError(t, err)
	require.NotNil(t, eps)
	require.NotEmpty(t, eps.Endpoints)

	servers, err := c.FindServers(ctx)
	require.NoError(t, err)
	require.NotNil(t, servers)
}

// TestServiceFault_ReturnsError exercises services that answer with a
// ServiceFault. QueryFirst/QueryNext are now implemented, but these particular
// empty requests are still rejected at the argument level (NothingToDo and an
// invalid continuation point respectively), and FindServersOnNetwork is
// unsupported.
//
// This is a regression test for a previous bug where a request that failed to
// decode server-side tore down the whole secure channel without responding,
// so the caller blocked until its full RequestTimeout (and Client.Close then
// blocked too). The server now returns a ServiceFault for request-scoped
// errors and keeps the channel alive, so each call fails fast.
func TestServiceFault_ReturnsError(t *testing.T) {
	c, _, ctx := setup(t)

	_, err := c.QueryFirst(ctx, &ua.QueryFirstRequest{})
	require.Error(t, err)

	_, err = c.QueryNext(ctx, &ua.QueryNextRequest{})
	require.Error(t, err)

	_, err = c.FindServersOnNetwork(ctx)
	require.Error(t, err)

	// An operation-level ServiceFault must leave the connection usable: a
	// normal request on the same client must still succeed. (Regression test
	// for the monitor tearing down the channel on any non-OK ServiceResult.)
	status, err := c.ServerStatus(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
}

func TestMisc_ClientAccessors(t *testing.T) {
	c, f, _ := setup(t)

	require.Equal(t, ua.SecurityPolicyURINone, c.SecurityPolicy())
	require.Equal(t, ua.MessageSecurityModeNone, c.SecurityMode())
	require.Equal(t, opcua.Connected, c.State())
	require.NotNil(t, c.SecureChannel())
	require.NotNil(t, c.Session())
	require.NotNil(t, c.Node(f.Int32))
	require.NotNil(t, c.NodeFromExpandedNodeID(ua.NewExpandedNodeID(f.Int32, "", 0)))
	require.Empty(t, c.SubscriptionIDs()) // no subscriptions yet
}

func TestMisc_SendLowLevel(t *testing.T) {
	c, f, ctx := setup(t)

	var got *ua.ReadResponse
	err := c.Send(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        []*ua.ReadValueID{{NodeID: f.Int32, AttributeID: ua.AttributeIDValue}},
	}, func(r ua.Response) error {
		got = r.(*ua.ReadResponse)
		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, int32(42), got.Results[0].Value.Value())
}

func TestMisc_NodeFromPathInNamespace(t *testing.T) {
	c, _, ctx := setup(t)

	// Resolve a well-known namespace-0 path (browse names use namespace 0).
	node, err := c.NodeFromPathInNamespace(ctx, 0, "Server.ServerStatus")
	require.NoError(t, err)
	require.NotNil(t, node)
	require.NotNil(t, node.ID)
}

func TestMisc_NodeFromQualifiedPathError(t *testing.T) {
	c, _, ctx := setup(t)

	_, err := c.NodeFromQualifiedPath(ctx, "Server") // missing namespace prefix
	require.Error(t, err)
}

func TestMisc_NodeIntrospection(t *testing.T) {
	c, f, ctx := setup(t)

	// Use the access-controlled node which has AccessLevel attributes set.
	n := c.Node(f.Writable)

	summary, err := n.Summary(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassVariable, summary.NodeClass)

	nc, err := n.NodeClass(ctx)
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassVariable, nc)

	bn, err := n.BrowseName(ctx)
	require.NoError(t, err)
	require.Equal(t, "Writable", bn.Name)

	dn, err := n.DisplayName(ctx)
	require.NoError(t, err)
	require.NotNil(t, dn)

	desc, err := n.Description(ctx)
	require.NoError(t, err)
	require.NotNil(t, desc)

	dt, err := n.DataType(ctx)
	require.NoError(t, err)
	require.NotNil(t, dt)

	al, err := n.AccessLevel(ctx)
	require.NoError(t, err)
	_ = al

	has, err := n.HasAccessLevel(ctx, ua.AccessLevelTypeCurrentRead)
	require.NoError(t, err)
	require.True(t, has)

	ual, err := n.UserAccessLevel(ctx)
	require.NoError(t, err)
	_ = ual

	_, err = n.HasUserAccessLevel(ctx, ua.AccessLevelTypeCurrentRead)
	require.NoError(t, err)

	attrs, err := n.Attributes(ctx, ua.AttributeIDValue, ua.AttributeIDNodeClass)
	require.NoError(t, err)
	require.Len(t, attrs, 2)

	_, err = n.Attribute(ctx, ua.AttributeIDValue)
	require.NoError(t, err)

	refs, err := n.ReferencedNodes(ctx, id.HierarchicalReferences, ua.BrowseDirectionInverse, ua.NodeClassAll, true)
	require.NoError(t, err)
	_ = refs
}

func TestMisc_NodeWalk(t *testing.T) {
	c, f, ctx := setup(t)

	n := c.Node(f.MethodObject)

	var count int
	for _, err := range n.Walk(ctx) {
		require.NoError(t, err)
		count++
		if count > 200 {
			break
		}
	}
	require.Positive(t, count)

	count = 0
	for wr, err := range n.WalkLimit(ctx, 1) {
		require.NoError(t, err)
		require.LessOrEqual(t, wr.Depth, 1)
		count++
		if count > 200 {
			break
		}
	}
	require.Positive(t, count)

	seen := map[string]struct{}{}
	for wr, err := range n.WalkLimitDedup(ctx, 2) {
		require.NoError(t, err)
		_, dup := seen[wr.Ref.NodeID.String()]
		require.False(t, dup)
		seen[wr.Ref.NodeID.String()] = struct{}{}
	}

	results, err := n.BrowseWithDepth(ctx, opcua.BrowseWithDepthOptions{MaxDepth: 1, IncludeSubtypes: true})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	td, err := n.TypeDefinition(ctx)
	require.NoError(t, err)
	_ = td
}
