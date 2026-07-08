// SPDX-License-Identifier: MIT

package conformance

import (
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestAttribute_ReadScalars(t *testing.T) {
	c, f, ctx := setup(t)

	cases := []struct {
		name   string
		nodeID *ua.NodeID
		want   any
	}{
		{"Bool", f.Bool, true},
		{"SByte", f.SByte, int8(-7)},
		{"Byte", f.Byte, byte(200)},
		{"Int16", f.Int16, int16(-1234)},
		{"Uint16", f.Uint16, uint16(4321)},
		{"Int32", f.Int32, int32(42)},
		{"Uint32", f.Uint32, uint32(4242)},
		{"Int64", f.Int64, int64(-9_000_000_000)},
		{"Uint64", f.Uint64, uint64(9_000_000_000)},
		{"Float", f.Float, float32(3.5)},
		{"Double", f.Double, float64(3.14159)},
		{"String", f.String, "hello"},
		{"ByteString", f.ByteString, []byte{0x01, 0x02, 0x03}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dv, err := c.ReadValue(ctx, tc.nodeID)
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, dv.Status)
			require.Equal(t, tc.want, dv.Value.Value())
		})
	}
}

func TestAttribute_ReadArrays(t *testing.T) {
	c, f, ctx := setup(t)

	dv, err := c.ReadValue(ctx, f.Int32Array)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)
	require.Equal(t, []int32{1, 2, 3, 4, 5}, dv.Value.Value())

	dv, err = c.ReadValue(ctx, f.StringArray)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dv.Status)
	require.Equal(t, []string{"a", "b", "c"}, dv.Value.Value())
}

func TestAttribute_ReadValues(t *testing.T) {
	c, f, ctx := setup(t)

	results, err := c.ReadValues(ctx, f.Int32, f.Double, f.String)
	require.NoError(t, err)
	require.Len(t, results, 3)
	require.Equal(t, int32(42), results[0].Value.Value())
	require.Equal(t, float64(3.14159), results[1].Value.Value())
	require.Equal(t, "hello", results[2].Value.Value())
}

func TestAttribute_ReadRaw(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := c.Read(ctx, &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead: []*ua.ReadValueID{
			{NodeID: f.Int32, AttributeID: ua.AttributeIDValue},
			{NodeID: f.Int32, AttributeID: ua.AttributeIDNodeClass},
			{NodeID: f.Int32, AttributeID: ua.AttributeIDDisplayName},
		},
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 3)
	require.Equal(t, ua.StatusOK, resp.Results[0].Status)
	require.Equal(t, int32(42), resp.Results[0].Value.Value())
	require.Equal(t, ua.StatusOK, resp.Results[1].Status)
	require.Equal(t, ua.StatusOK, resp.Results[2].Status)
}

func TestAttribute_ReadMulti(t *testing.T) {
	c, f, ctx := setup(t)

	items := []opcua.ReadItem{
		{NodeID: f.Int32, AttributeID: ua.AttributeIDValue},
		{NodeID: f.Double, AttributeID: ua.AttributeIDValue},
		{NodeID: f.String, AttributeID: ua.AttributeIDValue},
	}
	results, err := c.ReadMulti(ctx, items)
	require.NoError(t, err)
	require.Len(t, results, 3)
	require.Equal(t, int32(42), results[0].DataValue.Value.Value())
	require.Equal(t, float64(3.14159), results[1].DataValue.Value.Value())
	require.Equal(t, "hello", results[2].DataValue.Value.Value())
}

func TestAttribute_ReadMultiChunked(t *testing.T) {
	c, f, ctx := setup(t)

	var items []opcua.ReadItem
	for i := 0; i < 10; i++ {
		items = append(items, opcua.ReadItem{NodeID: f.Int32, AttributeID: ua.AttributeIDValue})
	}
	results, err := c.ReadMulti(ctx, items, opcua.ReadMultiWithChunkSize(3))
	require.NoError(t, err)
	require.Len(t, results, 10)
	for i := range results {
		require.Equal(t, ua.StatusOK, results[i].StatusCode)
		require.Equal(t, int32(42), results[i].DataValue.Value.Value())
	}
}

func TestAttribute_WriteValueRoundTrip(t *testing.T) {
	c, f, ctx := setup(t)

	status, err := c.WriteValue(ctx, f.Int32, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(4711)),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	dv, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(4711), dv.Value.Value())
}

func TestAttribute_WriteNodeValueRoundTrip(t *testing.T) {
	c, f, ctx := setup(t)

	status, err := c.WriteNodeValue(ctx, f.String, "changed")
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	dv, err := c.ReadValue(ctx, f.String)
	require.NoError(t, err)
	require.Equal(t, "changed", dv.Value.Value())
}

func TestAttribute_WriteRaw(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := c.Write(ctx, &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{{
			NodeID:      f.Int32,
			AttributeID: ua.AttributeIDValue,
			Value:       &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(555))},
		}},
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, ua.StatusOK, resp.Results[0])

	dv, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(555), dv.Value.Value())
}

func TestAttribute_WriteValues(t *testing.T) {
	c, f, ctx := setup(t)

	statuses, err := c.WriteValues(ctx,
		&ua.WriteValue{NodeID: f.Int32, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(1))}},
		&ua.WriteValue{NodeID: f.Double, AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(float64(2))}},
	)
	require.NoError(t, err)
	require.Len(t, statuses, 2)
	require.Equal(t, ua.StatusOK, statuses[0])
	require.Equal(t, ua.StatusOK, statuses[1])
}

func TestAttribute_WriteAttribute(t *testing.T) {
	c, f, ctx := setup(t)

	status, err := c.WriteAttribute(ctx, f.Int32, ua.AttributeIDValue, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant(int32(321)),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	dv, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(321), dv.Value.Value())
}

func TestAttribute_AccessControl(t *testing.T) {
	c, f, ctx := setup(t)

	t.Run("read-only readable", func(t *testing.T) {
		dv, err := c.ReadValue(ctx, f.ReadOnly)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, dv.Status)
	})

	t.Run("read-only not writable", func(t *testing.T) {
		status, err := c.WriteValue(ctx, f.ReadOnly, &ua.DataValue{
			EncodingMask: ua.DataValueValue,
			Value:        ua.MustVariant(int32(999)),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadUserAccessDenied, status)
	})

	t.Run("no-access denied on read", func(t *testing.T) {
		dv, err := c.ReadValue(ctx, f.NoAccess)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadUserAccessDenied, dv.Status)
	})
}
