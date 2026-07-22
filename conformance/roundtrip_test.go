// SPDX-License-Identifier: MIT

package conformance

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

// addFreshNode creates a brand-new variable node via the AddNodes service and
// returns its id. A freshly-added node holds no typed value, so the first write
// is not subject to the server's type-match check and may carry any type.
func addFreshNode(t *testing.T, c *opcua.Client, f *testutil.Fixture, ctx context.Context, name string) *ua.NodeID {
	t.Helper()
	nid := ua.NewStringNodeID(f.NSIndex, "rt_"+name)
	resp, err := c.AddNodes(ctx, &ua.AddNodesRequest{
		NodesToAdd: []*ua.AddNodesItem{{
			ParentNodeID:       ua.NewExpandedNodeID(f.MethodObject, "", 0),
			ReferenceTypeID:    ua.NewNumericNodeID(0, id.HasComponent),
			RequestedNewNodeID: ua.NewExpandedNodeID(nid, "", 0),
			BrowseName:         &ua.QualifiedName{NamespaceIndex: f.NSIndex, Name: "rt_" + name},
			NodeClass:          ua.NodeClassVariable,
			TypeDefinition:     ua.NewNumericExpandedNodeID(0, 0),
		}},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	return nid
}

// TestRoundTrip_Values writes a value to a node and reads it back, asserting the
// value survives the full path: client encode -> server decode -> server store
// -> server encode -> client decode. This is the highest-value adversarial
// check for a protocol library because it exercises both sides of the codec for
// every supported Variant type.
func TestRoundTrip_Values(t *testing.T) {
	c, f, ctx := setup(t)

	cases := []struct {
		name string
		val  any
	}{
		{"Bool", true},
		{"BoolFalse", false},
		{"SByte", int8(-128)},
		{"Byte", byte(255)},
		{"Int16", int16(-32768)},
		{"Uint16", uint16(65535)},
		{"Int32", int32(-2147483648)},
		{"Uint32", uint32(4294967295)},
		{"Int64", int64(-9223372036854775808)},
		{"Uint64", uint64(18446744073709551615)},
		{"Float", float32(-3.4e38)},
		{"Double", float64(1.7e308)},
		{"FloatZero", float32(0)},
		{"String", "the quick brown fox"},
		{"StringEmpty", ""},
		{"StringUnicode", "héllo wörld 你好 🦊"},
		{"ByteString", []byte{0x00, 0xff, 0x10, 0x20}},
		{"StatusCode", ua.StatusBadInternalError},
		{"NodeIDNumeric", ua.NewNumericNodeID(2, 4711)},
		{"NodeIDString", ua.NewStringNodeID(3, "some.node")},
		{"QualifiedName", &ua.QualifiedName{NamespaceIndex: 1, Name: "qn"}},
		{"LocalizedText", ua.NewLocalizedText("hello")},
		{"Int32Array", []int32{-1, 0, 1, 2, 3}},
		{"StringArray", []string{"a", "", "c"}},
		{"DoubleArray", []float64{1.5, 2.5, 3.5}},
		{"BoolArray", []bool{true, false, true}},
		{"EmptyInt32Array", []int32{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nid := addFreshNode(t, c, f, ctx, tc.name)

			v, err := ua.NewVariant(tc.val)
			require.NoError(t, err, "construct variant")

			status, err := c.WriteValue(ctx, nid, &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        v,
			})
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, status)

			dv, err := c.ReadValue(ctx, nid)
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, dv.Status)
			require.Equal(t, tc.val, dv.Value.Value())
		})
	}
}

func TestRoundTrip_DateTime(t *testing.T) {
	c, f, ctx := setup(t)
	nid := addFreshNode(t, c, f, ctx, "DateTime")

	// OPC UA DateTime has 100ns resolution; round so equality is exact.
	want := time.Date(2026, 7, 8, 12, 34, 56, 700_000_000, time.UTC)

	v, err := ua.NewVariant(want)
	require.NoError(t, err)

	status, err := c.WriteValue(ctx, nid, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        v,
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)

	dv, err := c.ReadValue(ctx, nid)
	require.NoError(t, err)
	got, ok := dv.Value.Value().(time.Time)
	require.True(t, ok, "expected time.Time, got %T", dv.Value.Value())
	require.True(t, want.Equal(got), "want %v got %v", want, got)
}

// TestRoundTrip_TypeMismatchOnRewrite documents the server's type-match check:
// once a node holds a typed value, a write with a different Go type is rejected
// with StatusBadTypeMismatch (IEC 62541-4 Write Service).
func TestRoundTrip_TypeMismatchOnRewrite(t *testing.T) {
	c, f, ctx := setup(t)

	// f.Int32 already holds an int32; writing a string must be rejected.
	status, err := c.WriteValue(ctx, f.Int32, &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant("not an int"),
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadTypeMismatch, status)

	// The original value must be intact.
	dv, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())
}
