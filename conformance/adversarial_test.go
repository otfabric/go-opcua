// SPDX-License-Identifier: MIT

package conformance

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// The adversarial tests feed malformed, unexpected, or boundary inputs to the
// server and assert it responds with a sane status code rather than panicking,
// hanging, or corrupting state.

func TestAdversarial_ReadUnknownNode(t *testing.T) {
	c, f, ctx := setup(t)

	dv, err := c.ReadValue(ctx, ua.NewStringNodeID(f.NSIndex, "does-not-exist"))
	require.NoError(t, err, "transport must succeed")
	require.NotEqual(t, ua.StatusOK, dv.Status, "unknown node must not read OK")
}

func TestAdversarial_ReadUnknownNamespace(t *testing.T) {
	c, _, ctx := setup(t)

	dv, err := c.ReadValue(ctx, ua.NewStringNodeID(60000, "ghost"))
	require.NoError(t, err)
	require.NotEqual(t, ua.StatusOK, dv.Status)
}

func TestAdversarial_ReadInvalidAttribute(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := c.Read(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        []*ua.ReadValueID{{NodeID: f.Int32, AttributeID: ua.AttributeID(9999)}},
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.NotEqual(t, ua.StatusOK, resp.Results[0].Status)
}

func TestAdversarial_ReadEmptyBatch(t *testing.T) {
	c, _, ctx := setup(t)

	resp, err := c.Read(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        []*ua.ReadValueID{},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Empty(t, resp.Results)
}

func TestAdversarial_ReadLargeBatch(t *testing.T) {
	c, f, ctx := setup(t)

	const n = 500
	items := make([]opcua.ReadItem, n)
	for i := range items {
		items[i] = opcua.ReadItem{NodeID: f.Int32, AttributeID: ua.AttributeIDValue}
	}
	results, err := c.ReadMulti(ctx, items)
	require.NoError(t, err)
	require.Len(t, results, n)
	for i := range results {
		require.Equal(t, ua.StatusOK, results[i].StatusCode)
	}
}

func TestAdversarial_WriteUnknownNode(t *testing.T) {
	c, f, ctx := setup(t)

	status, err := c.WriteValue(ctx, ua.NewStringNodeID(f.NSIndex, "nope"), &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(1)),
	})
	require.NoError(t, err)
	require.NotEqual(t, ua.StatusOK, status)
}

func TestAdversarial_BrowseUnknownNode(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := c.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          ua.NewStringNodeID(f.NSIndex, "unknown"),
			BrowseDirection: ua.BrowseDirectionForward,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
		RequestedMaxReferencesPerNode: 100,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.NotEqual(t, ua.StatusOK, resp.Results[0].StatusCode)
}

func TestAdversarial_CallUnknownObjectAndMethod(t *testing.T) {
	c, f, ctx := setup(t)

	res, err := c.Call(ctx, &ua.CallMethodRequest{
		ObjectID: ua.NewStringNodeID(f.NSIndex, "no-object"),
		MethodID: ua.NewStringNodeID(f.NSIndex, "no-method"),
	})
	require.NoError(t, err)
	require.NotEqual(t, ua.StatusOK, res.StatusCode)
}

func TestAdversarial_CallTooManyArguments(t *testing.T) {
	c, f, ctx := setup(t)

	// Square expects exactly one argument.
	res, err := c.Call(ctx, &ua.CallMethodRequest{
		ObjectID: f.MethodObject,
		MethodID: f.SquareMethod,
		InputArguments: []*ua.Variant{
			ua.MustVariant(int32(2)), ua.MustVariant(int32(3)), ua.MustVariant(int32(4)),
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, ua.StatusOK, res.StatusCode)
}

func TestAdversarial_MonitorUnknownNode(t *testing.T) {
	c, f, ctx := setup(t)

	sub, _, err := c.NewSubscription().Interval(100 * time.Millisecond).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	resp, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(
			ua.NewStringNodeID(f.NSIndex, "ghost-monitor"), ua.AttributeIDValue, 1),
	)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	// The server may accept the item or reject it, but must not panic and must
	// return a result for it.
	require.NotNil(t, resp.Results[0])
}

func TestAdversarial_WriteWrongTypePreservesValue(t *testing.T) {
	c, f, ctx := setup(t)

	// Writing a mismatched type must be rejected and must not corrupt the value.
	_, err := c.WriteValue(ctx, f.Double, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant("wrong"),
	})
	require.NoError(t, err)

	dv, err := c.ReadValue(ctx, f.Double)
	require.NoError(t, err)
	require.Equal(t, float64(3.14159), dv.Value.Value())
}
