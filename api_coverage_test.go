// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func setupFixture(t *testing.T) (*opcua.Client, *testutil.Fixture, context.Context) {
	t.Helper()
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	return c, f, context.Background()
}

func TestGetEndpoints(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	resp, err := c.GetEndpoints(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Endpoints)
}

func TestFindServers(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	resp, err := c.FindServers(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Servers)
}

func TestFindServersOnNetwork(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()

	_, err := c.FindServersOnNetwork(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)
}

func TestNamespaceArray(t *testing.T) {
	c, f, ctx := setupFixture(t)

	namespaces, err := c.NamespaceArray(ctx)
	require.NoError(t, err)
	require.Contains(t, namespaces, "http://otfabric.com/conformance")

	require.NoError(t, c.UpdateNamespaces(ctx))
	require.Contains(t, c.Namespaces(), "http://otfabric.com/conformance")
	_ = f
}

func TestSessionNegotiatedFields(t *testing.T) {
	c, _, ctx := setupFixture(t)
	_ = ctx

	sess := c.Session()
	require.NotNil(t, sess)
	require.NotNil(t, sess.SessionID())
	require.NotEmpty(t, sess.ServerEndpoints())
	_ = sess.RevisedTimeout()
	_ = sess.MaxRequestMessageSize()
}

func TestDetachSession(t *testing.T) {
	c, _, ctx := setupFixture(t)

	sess, err := c.DetachSession(ctx)
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Nil(t, c.Session())

	require.NoError(t, c.Close(ctx))
}

func TestSetPublishingMode(t *testing.T) {
	c, f, ctx := setupFixture(t)

	sub, _, err := c.NewSubscription().Interval(100 * time.Millisecond).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	resp, err := c.SetPublishingMode(ctx, true, sub.SubscriptionID)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.ResponseHeader.ServiceResult)
	_ = f
}

func TestFixtureScalarReads(t *testing.T) {
	c, f, ctx := setupFixture(t)

	dvs, err := c.ReadValues(ctx,
		f.Bool, f.SByte, f.Byte, f.Int16, f.Uint16, f.Int32, f.Uint32,
		f.Int64, f.Uint64, f.Float, f.Double, f.String, f.ByteString,
		f.Int32Array, f.StringArray,
	)
	require.NoError(t, err)
	require.Len(t, dvs, 15)
	for _, dv := range dvs {
		require.Equal(t, ua.StatusOK, dv.Status)
	}
}

func TestFindNamespace(t *testing.T) {
	c, f, ctx := setupFixture(t)

	idx, err := c.FindNamespace(ctx, "http://otfabric.com/conformance")
	require.NoError(t, err)
	require.Equal(t, f.NSIndex, idx)

	_, err = c.FindNamespace(ctx, "http://example.com/does-not-exist")
	require.Error(t, err)
}

func TestRegisterUnregisterNodes(t *testing.T) {
	c, f, ctx := setupFixture(t)

	resp, err := c.RegisterNodes(ctx, &ua.RegisterNodesRequest{
		NodesToRegister: []*ua.NodeID{f.Int32, f.Double},
	})
	require.NoError(t, err)
	require.Len(t, resp.RegisteredNodeIDs, 2)

	unreg, err := c.UnregisterNodes(ctx, &ua.UnregisterNodesRequest{
		NodesToUnregister: resp.RegisteredNodeIDs,
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, unreg.ResponseHeader.ServiceResult)
}

func TestBrowseNext(t *testing.T) {
	c, f, ctx := setupFixture(t)

	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          f.MethodObject,
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
			NodeClassMask:   uint32(ua.NodeClassAll),
		}},
		RequestedMaxReferencesPerNode: 1,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)

	cp := resp.Results[0].ContinuationPoint
	if len(cp) == 0 {
		t.Skip("server returned all references in one page")
	}

	next, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{
		ContinuationPoints:        [][]byte{cp},
		ReleaseContinuationPoints: false,
	})
	require.NoError(t, err)
	require.Len(t, next.Results, 1)
	require.Equal(t, ua.StatusOK, next.Results[0].StatusCode)
}

func TestQueryFirstAndNext(t *testing.T) {
	c, f, ctx := setupFixture(t)

	resp, err := c.QueryFirst(ctx, &ua.QueryFirstRequest{
		NodeTypes: []*ua.NodeTypeDescription{{
			TypeDefinitionNode: ua.NewExpandedNodeID(f.CustomVarType, "", 0),
			IncludeSubTypes:    true,
			DataToReturn:       []*ua.QueryDataDescription{{AttributeID: ua.AttributeIDValue}},
		}},
		MaxDataSetsToReturn: 2,
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.ResponseHeader.ServiceResult)
	require.Len(t, resp.QueryDataSets, 2)
	require.NotEmpty(t, resp.ContinuationPoint)

	next, err := c.QueryNext(ctx, &ua.QueryNextRequest{
		ContinuationPoint: resp.ContinuationPoint,
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, next.ResponseHeader.ServiceResult)
	require.NotEmpty(t, next.QueryDataSets)
}

func TestCallMethodAndArguments(t *testing.T) {
	c, f, ctx := setupFixture(t)

	result, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(7))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, result.StatusCode)
	require.Equal(t, int32(49), result.OutputArguments[0].Value())

	inputs, outputs, err := c.MethodArguments(ctx, f.MethodObject, f.SquareMethod)
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.Equal(t, "n", inputs[0].Name)
	require.Len(t, outputs, 1)
	require.Equal(t, "result", outputs[0].Name)
}

func TestSubscriptionBuilderMonitorEvents(t *testing.T) {
	c, f, ctx := setupFixture(t)

	filter := ua.NewEventFilter().
		Select("Message", "Severity").
		Where(ua.Field("Severity").GreaterThanOrEqual(uint16(0))).
		Build()

	sub, notifyCh, err := c.NewSubscription().
		Interval(100*time.Millisecond).
		MonitorEvents(filter, f.EventObject).
		Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	require.NotNil(t, notifyCh)

	time.Sleep(200 * time.Millisecond)
	require.NoError(t, f.EmitTestEvent(
		ua.MustVariant("something happened"),
		ua.MustVariant(uint16(500)),
	))

	deadline := time.After(8 * time.Second)
	for {
		select {
		case msg := <-notifyCh:
			require.NoError(t, msg.Error)
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			require.NotEmpty(t, enl.Events)
			return
		case <-deadline:
			t.Fatal("timed out waiting for event notification")
		}
	}
}

func TestWithMetrics(t *testing.T) {
	m := &captureMetrics{}
	c, err := opcua.NewClient("opc.tcp://example.com:4840", opcua.WithMetrics(m))
	require.NoError(t, err)
	_ = c.Close(context.Background())
}

type captureMetrics struct{}

func (c *captureMetrics) OnRequest(service string)                           {}
func (c *captureMetrics) OnResponse(service string, d time.Duration)         {}
func (c *captureMetrics) OnError(service string, d time.Duration, err error) {}
func (c *captureMetrics) OnTimeout(service string, d time.Duration)          {}

func TestNodeString(t *testing.T) {
	c, f, ctx := setupFixture(t)
	node := c.Node(f.Int32)
	require.Equal(t, f.Int32.String(), node.String())

	v, err := node.Value(ctx)
	require.NoError(t, err)
	require.NotNil(t, v)
}

func TestSubscriptionStats(t *testing.T) {
	c, f, ctx := setupFixture(t)

	sub, _, err := c.NewSubscription().Interval(100 * time.Millisecond).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	_, err = sub.Stats(ctx)
	// The test server does not expose SubscriptionDiagnosticsArray as a readable value.
	require.Error(t, err)
}
