package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/opcua"
	"github.com/otfabric/opcua/testutil"
	"github.com/otfabric/opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestReadValue(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	dv, err := c.ReadValue(ctx, ua.NewStringNodeID(ns.ID(), "IntVar"))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)
	require.Equal(t, int32(42), dv.Value.Value())
}

func TestReadValues(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	results, err := c.ReadValues(ctx,
		ua.NewStringNodeID(ns.ID(), "IntVar"),
		ua.NewStringNodeID(ns.ID(), "FloatVar"),
		ua.NewStringNodeID(ns.ID(), "StringVar"),
	)
	require.NoError(t, err)
	require.Len(t, results, 3)
	require.Equal(t, int32(42), results[0].Value.Value())
	require.Equal(t, float64(3.14), results[1].Value.Value())
	require.Equal(t, "hello", results[2].Value.Value())
}

func TestReadMulti(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	items := []opcua.ReadItem{
		{NodeID: ua.NewStringNodeID(ns.ID(), "IntVar"), AttributeID: ua.AttributeIDValue},
		{NodeID: ua.NewStringNodeID(ns.ID(), "FloatVar"), AttributeID: ua.AttributeIDValue},
		{NodeID: ua.NewStringNodeID(ns.ID(), "StringVar"), AttributeID: ua.AttributeIDValue},
	}
	results, err := c.ReadMulti(ctx, items)
	require.NoError(t, err)
	require.Len(t, results, 3)
	require.Equal(t, ua.StatusOK, results[0].StatusCode)
	require.Equal(t, int32(42), results[0].DataValue.Value.Value())
	require.Equal(t, ua.StatusOK, results[1].StatusCode)
	require.Equal(t, float64(3.14), results[1].DataValue.Value.Value())
	require.Equal(t, ua.StatusOK, results[2].StatusCode)
	require.Equal(t, "hello", results[2].DataValue.Value.Value())
}

func TestReadMultiChunking(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Request more than default chunk size (32) to trigger chunking
	var items []opcua.ReadItem
	for i := 0; i < 5; i++ {
		items = append(items, opcua.ReadItem{NodeID: ua.NewStringNodeID(ns.ID(), "IntVar"), AttributeID: ua.AttributeIDValue})
	}
	results, err := c.ReadMulti(ctx, items, opcua.ReadMultiWithChunkSize(2))
	require.NoError(t, err)
	require.Len(t, results, 5)
	for i := range results {
		require.Equal(t, ua.StatusOK, results[i].StatusCode)
		require.Equal(t, int32(42), results[i].DataValue.Value.Value())
	}
}

func TestReadMultiEmptyItems(t *testing.T) {
	c, _ := opcua.NewClient("opc.tcp://localhost:4840")
	ctx := context.Background()
	results, err := c.ReadMulti(ctx, nil)
	require.NoError(t, err)
	require.Nil(t, results)
	results, err = c.ReadMulti(ctx, []opcua.ReadItem{})
	require.NoError(t, err)
	require.Nil(t, results)
}

func TestReadMultiMixedAttributes(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	nodeID := ua.NewStringNodeID(ns.ID(), "IntVar")
	items := []opcua.ReadItem{
		{NodeID: nodeID, AttributeID: ua.AttributeIDValue},
		{NodeID: nodeID, AttributeID: ua.AttributeIDDisplayName},
		{NodeID: nodeID, AttributeID: ua.AttributeIDNodeClass},
	}
	results, err := c.ReadMulti(ctx, items)
	require.NoError(t, err)
	require.Len(t, results, 3)
	require.Equal(t, ua.StatusOK, results[0].StatusCode)
	require.Equal(t, int32(42), results[0].DataValue.Value.Value())
	require.Equal(t, ua.StatusOK, results[1].StatusCode)
	require.NotNil(t, results[1].DataValue.Value.Value()) // DisplayName LocalizedText
	require.Equal(t, ua.StatusOK, results[2].StatusCode)
	require.NotNil(t, results[2].DataValue.Value.Value())
}

func TestWriteValue(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	nodeID := ua.NewStringNodeID(ns.ID(), "IntVar")

	status, err := c.WriteValue(ctx, nodeID, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(99)),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	// Verify the write took effect.
	dv, err := c.ReadValue(ctx, nodeID)
	require.NoError(t, err)
	require.Equal(t, int32(99), dv.Value.Value())
}

func TestWriteValues(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	statuses, err := c.WriteValues(ctx,
		&ua.WriteValue{
			NodeID:      ua.NewStringNodeID(ns.ID(), "IntVar"),
			AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        ua.MustVariant(int32(100)),
			},
		},
		&ua.WriteValue{
			NodeID:      ua.NewStringNodeID(ns.ID(), "FloatVar"),
			AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        ua.MustVariant(float64(2.72)),
			},
		},
	)
	require.NoError(t, err)
	require.Len(t, statuses, 2)
	require.Equal(t, ua.StatusOK, statuses[0])
	require.Equal(t, ua.StatusOK, statuses[1])
}

func TestBrowseAll(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Browse the root Objects folder — should have children.
	refs, err := c.BrowseAll(ctx, ua.NewNumericNodeID(0, 85)) // ObjectsFolder
	require.NoError(t, err)
	require.NotEmpty(t, refs, "ObjectsFolder should have child references")
}

func TestWithConnStateHandler(t *testing.T) {
	var got []opcua.ConnState
	_, err := opcua.NewClient("opc.tcp://example.com:4840",
		opcua.WithConnStateHandler(func(s opcua.ConnState) {
			got = append(got, s)
		}),
	)
	require.NoError(t, err)
	// The handler is registered; no state change until Connect is called,
	// and the initial state (Closed) is set without triggering callbacks.
	require.Empty(t, got)
}

func TestSubscriptionBuilder(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	sub, notifyCh, err := c.NewSubscription().
		Interval(100 * time.Millisecond).
		LifetimeCount(10000).
		MaxKeepAliveCount(3000).
		Monitor(ua.NewStringNodeID(ns.ID(), "IntVar")).
		Start(ctx)
	require.NoError(t, err)
	require.NotNil(t, sub)
	require.NotNil(t, notifyCh)
	require.NotZero(t, sub.SubscriptionID)

	// Write a new value to trigger a data change notification.
	status, err := c.WriteValue(ctx, ua.NewStringNodeID(ns.ID(), "IntVar"), &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(77)),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	// Wait for a notification (data change or keep-alive).
	select {
	case msg := <-notifyCh:
		require.NoError(t, msg.Error)
	case <-time.After(5 * time.Second):
		// Keep-alives are acceptable — the data change may or may
		// not have been delivered depending on server timing.
	}

	require.NoError(t, sub.Cancel(ctx))
}

func TestSubscriptionBuilder_NoMonitor(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	sub, notifyCh, err := c.NewSubscription().
		Interval(200 * time.Millisecond).
		Start(ctx)
	require.NoError(t, err)
	require.NotNil(t, sub)
	require.NotNil(t, notifyCh)
	require.NoError(t, sub.Cancel(ctx))
}

func TestNodeSummary(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Get summary of the Server node (i=2253)
	n := c.Node(ua.NewNumericNodeID(0, 2253))
	summary, err := n.Summary(ctx)
	require.NoError(t, err)
	require.NotNil(t, summary)
	require.Equal(t, "Server", summary.DisplayName.Text)
	require.Equal(t, ua.NodeClassObject, summary.NodeClass)
}

func TestNodeTypeDefinition(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Server node (i=2253) should have a type definition
	n := c.Node(ua.NewNumericNodeID(0, 2253))
	td, err := n.TypeDefinition(ctx)
	require.NoError(t, err)
	require.NotNil(t, td)
}

func TestNodeDataType(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	n := c.Node(ua.NewStringNodeID(ns.ID(), "IntVar"))
	dt, err := n.DataType(ctx)
	require.NoError(t, err)
	require.NotNil(t, dt)
}

func TestNodeWalk(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Walk from Objects folder (i=85)
	n := c.Node(ua.NewNumericNodeID(0, 85))
	var count int
	for wr, err := range n.Walk(ctx) {
		require.NoError(t, err)
		require.NotNil(t, wr.Ref)
		count++
		if count > 100 {
			break // safety limit
		}
	}
	require.Greater(t, count, 0, "Walk should yield at least one result")
}

func TestNodeWalkLimit(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	n := c.Node(ua.NewNumericNodeID(0, 85)) // Objects folder
	maxDepth := 2
	var count int
	var seenDepth2 bool
	for wr, err := range n.WalkLimit(ctx, maxDepth) {
		require.NoError(t, err)
		require.NotNil(t, wr.Ref)
		require.LessOrEqual(t, wr.Depth, maxDepth, "WalkLimit must not yield depth > maxDepth")
		if wr.Depth == 2 {
			seenDepth2 = true
		}
		count++
		if count > 200 {
			break
		}
	}
	require.Greater(t, count, 0, "WalkLimit should yield at least one result")
	require.True(t, seenDepth2, "WalkLimit with maxDepth=2 should yield at least one result at depth 2")
}

func TestNodeWalkLimitDedup(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	n := c.Node(ua.NewNumericNodeID(0, 85)) // Objects folder
	maxDepth := 3
	seen := make(map[string]struct{})
	var count int
	for wr, err := range n.WalkLimitDedup(ctx, maxDepth) {
		require.NoError(t, err)
		require.NotNil(t, wr.Ref)
		require.LessOrEqual(t, wr.Depth, maxDepth, "WalkLimitDedup must not yield depth > maxDepth")
		key := wr.Ref.NodeID.String()
		_, ok := seen[key]
		require.False(t, ok, "WalkLimitDedup must not yield duplicate NodeID %q", key)
		seen[key] = struct{}{}
		count++
		if count > 300 {
			break
		}
	}
	require.Greater(t, count, 0, "WalkLimitDedup should yield at least one result")
}

func TestNodeBrowseWithDepth(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	n := c.Node(ua.NewNumericNodeID(0, 85)) // Objects folder
	opts := opcua.BrowseWithDepthOptions{
		MaxDepth:        2,
		IncludeSubtypes: true,
	}
	results, err := n.BrowseWithDepth(ctx, opts)
	require.NoError(t, err)
	require.Greater(t, len(results), 0, "BrowseWithDepth should return at least one result")
	for _, r := range results {
		require.NotNil(t, r.Ref, "each result should have a reference")
		require.LessOrEqual(t, r.Depth, opts.MaxDepth, "depth must not exceed MaxDepth")
	}
}

func TestNodeBrowseWithDepthMaxDepthZero(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	n := c.Node(ua.NewNumericNodeID(0, 85))
	opts := opcua.BrowseWithDepthOptions{
		MaxDepth:        0,
		IncludeSubtypes: true,
	}
	results, err := n.BrowseWithDepth(ctx, opts)
	require.NoError(t, err)
	for _, r := range results {
		require.Equal(t, 0, r.Depth, "MaxDepth 0 should only return depth 0")
	}
}

func TestNodeBrowseWithDepthInverse(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	n := c.Node(ua.NewNumericNodeID(0, 85))
	opts := opcua.BrowseWithDepthOptions{
		MaxDepth:        1,
		Direction:       ua.BrowseDirectionInverse,
		IncludeSubtypes: true,
	}
	results, err := n.BrowseWithDepth(ctx, opts)
	require.NoError(t, err)
	// Inverse from Objects folder may yield parents; just ensure no panic and depths are 0 or 1
	for _, r := range results {
		require.NotNil(t, r.Ref)
		require.GreaterOrEqual(t, r.Depth, 0)
		require.LessOrEqual(t, r.Depth, 1)
	}
}

func TestClientServerStatus(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	status, err := c.ServerStatus(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	require.False(t, status.CurrentTime.IsZero())
}

func TestClientSecurityAccessors(t *testing.T) {
	c, err := opcua.NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer c.Close(context.Background())

	require.Equal(t, ua.SecurityPolicyURINone, c.SecurityPolicy())
	require.Equal(t, ua.MessageSecurityModeNone, c.SecurityMode())
}

func TestClientWriteAttribute(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	nodeID := ua.NewStringNodeID(ns.ID(), "IntVar")
	status, err := c.WriteAttribute(ctx, nodeID, ua.AttributeIDValue, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(123)),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	// Verify
	dv, err := c.ReadValue(ctx, nodeID)
	require.NoError(t, err)
	require.Equal(t, int32(123), dv.Value.Value())
}

func TestClientWriteNodeValue(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	nodeID := ua.NewStringNodeID(ns.ID(), "IntVar")
	status, err := c.WriteNodeValue(ctx, nodeID, int32(999))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	// Verify
	dv, err := c.ReadValue(ctx, nodeID)
	require.NoError(t, err)
	require.Equal(t, int32(999), dv.Value.Value())
}

func TestClientNamespaceURI(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Namespace 0 should always be the standard OPC-UA namespace
	uri, err := c.NamespaceURI(ctx, 0)
	require.NoError(t, err)
	require.NotEmpty(t, uri)

	// Out of bounds should error
	_, err = c.NamespaceURI(ctx, 65535)
	require.Error(t, err)
}

func TestNodeFromPath(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Standard path from Objects folder (namespace 0): "Server" is a well-known child
	node, err := c.NodeFromPath(ctx, "Server")
	require.NoError(t, err)
	require.NotNil(t, node)
	require.NotNil(t, node.ID)
}

func TestNodeFromPathInNamespace(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := testutil.AddTestNodes(t, srv)
	require.NotNil(t, ns)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	// Path from Objects folder: TestNodes (custom namespace Objects node) then IntVar.
	// Browse names from the test server use namespace 0.
	node, err := c.NodeFromPathInNamespace(ctx, 0, "TestNodes.IntVar")
	require.NoError(t, err)
	require.NotNil(t, node)
	v, err := node.Value(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(42), v.Value())
}

func TestNodeFromQualifiedPath(t *testing.T) {
	t.Run("invalid path no namespace prefix", func(t *testing.T) {
		_, url := testutil.NewTestServer(t)
		c := testutil.NewTestClient(t, url)
		_, err := c.NodeFromQualifiedPath(context.Background(), "Server")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing namespace prefix")
	})
	t.Run("invalid path namespace not numeric", func(t *testing.T) {
		_, url := testutil.NewTestServer(t)
		c := testutil.NewTestClient(t, url)
		_, err := c.NodeFromQualifiedPath(context.Background(), "x:Server")
		require.Error(t, err)
		require.Contains(t, err.Error(), "namespace")
	})
	t.Run("empty path", func(t *testing.T) {
		_, url := testutil.NewTestServer(t)
		c := testutil.NewTestClient(t, url)
		_, err := c.NodeFromQualifiedPath(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("valid single segment", func(t *testing.T) {
		_, url := testutil.NewTestServer(t)
		c := testutil.NewTestClient(t, url)
		node, err := c.NodeFromQualifiedPath(context.Background(), "0:Server")
		require.NoError(t, err)
		require.NotNil(t, node)
		require.NotNil(t, node.ID)
	})
	t.Run("valid multi segment", func(t *testing.T) {
		_, url := testutil.NewTestServer(t)
		c := testutil.NewTestClient(t, url)
		node, err := c.NodeFromQualifiedPath(context.Background(), "0:Server.0:ServerStatus")
		require.NoError(t, err)
		require.NotNil(t, node)
		require.NotNil(t, node.ID)
	})
}
