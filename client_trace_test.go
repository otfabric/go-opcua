// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestWithSpanContext passes a SpanContext in the AdditionalHeader of a
// Call (OPC 10000-26 §5.6.4) and reads it from the MethodCaller.
func TestWithSpanContext(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t)
	obj, method := ua.NewNumericNodeID(0, id.ObjectsFolder), ua.NewStringNodeID(0, "go-opcua.trace")
	var mu sync.Mutex
	var got []*ua.SpanContextDataType
	srv.RegisterMethod(obj, method, func(ctx context.Context, _, _ *ua.NodeID, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		mc, ok := server.MethodCallerFromContext(ctx)
		require.True(t, ok)
		mu.Lock()
		got = append(got, mc.SpanContext)
		mu.Unlock()
		return nil, ua.StatusOK
	})
	c := testutil.NewTestClient(t, url)
	trace := ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63")
	for _, ctx := range []context.Context{
		opcua.WithSpanContext(context.Background(), &ua.SpanContextDataType{TraceID: trace, SpanID: 7}),
		context.Background(),
		// SpanId 0 is invalid (§5.6.2): nothing is sent.
		opcua.WithSpanContext(context.Background(), &ua.SpanContextDataType{TraceID: trace}),
		opcua.WithSpanContext(context.Background(), nil),
	} {
		res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: obj, MethodID: method})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, res.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, got, 4)
	require.NotNil(t, got[0])
	require.Equal(t, uint64(7), got[0].SpanID)
	require.Equal(t, trace.String(), got[0].TraceID.String())
	require.Nil(t, got[1])
	require.Nil(t, got[2])
	require.Nil(t, got[3])
}
