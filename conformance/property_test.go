// SPDX-License-Identifier: MIT

package conformance

import (
	"reflect"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// anyValueGen draws a random value of one of the common OPC UA scalar/array
// types. NaN floats are excluded so equality checks are meaningful.
func anyValueGen() *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		switch rapid.IntRange(0, 10).Draw(t, "kind") {
		case 0:
			return rapid.Bool().Draw(t, "bool")
		case 1:
			return int8(rapid.Int32Range(-128, 127).Draw(t, "i8"))
		case 2:
			return byte(rapid.Int32Range(0, 255).Draw(t, "u8"))
		case 3:
			return int16(rapid.Int32Range(-32768, 32767).Draw(t, "i16"))
		case 4:
			return rapid.Int32().Draw(t, "i32")
		case 5:
			return rapid.Int64().Draw(t, "i64")
		case 6:
			return rapid.Uint32().Draw(t, "u32")
		case 7:
			return rapid.Uint64().Draw(t, "u64")
		case 8:
			return rapid.Float64Range(-1e12, 1e12).Draw(t, "f64")
		case 9:
			return rapid.String().Draw(t, "str")
		default:
			return rapid.SliceOf(rapid.Int32()).Draw(t, "i32slice")
		}
	})
}

// TestProperty_VariantCodec is a pure codec property: any supported value must
// survive Variant Encode -> Decode unchanged. This exercises the encoder and
// decoder directly with a very wide range of random inputs.
func TestProperty_VariantCodec(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		val := anyValueGen().Draw(rt, "value")

		v, err := ua.NewVariant(val)
		if err != nil {
			rt.Fatalf("NewVariant(%T): %v", val, err)
		}
		b, err := v.Encode()
		if err != nil {
			rt.Fatalf("encode(%T): %v", val, err)
		}
		var out ua.Variant
		if _, err := out.Decode(b); err != nil {
			rt.Fatalf("decode(%T): %v", val, err)
		}
		if !reflect.DeepEqual(val, out.Value()) {
			rt.Fatalf("round-trip mismatch: type %T\n want: %#v\n got:  %#v", val, val, out.Value())
		}
	})
}

// TestProperty_NodeIDCodec checks that every NodeID flavour survives encode/decode.
func TestProperty_NodeIDCodec(t *testing.T) {
	gen := rapid.Custom(func(t *rapid.T) *ua.NodeID {
		switch rapid.IntRange(0, 3).Draw(t, "kind") {
		case 0:
			return ua.NewNumericNodeID(
				uint16(rapid.IntRange(0, 65535).Draw(t, "ns")),
				rapid.Uint32().Draw(t, "id"))
		case 1:
			return ua.NewStringNodeID(
				uint16(rapid.IntRange(0, 65535).Draw(t, "ns")),
				rapid.String().Draw(t, "id"))
		case 2:
			return ua.NewByteStringNodeID(
				uint16(rapid.IntRange(0, 65535).Draw(t, "ns")),
				rapid.SliceOf(rapid.Byte()).Draw(t, "id"))
		default:
			return ua.NewGUIDNodeID(
				uint16(rapid.IntRange(0, 65535).Draw(t, "ns")),
				"12345678-90ab-cdef-1234-567890abcdef")
		}
	})

	rapid.Check(t, func(rt *rapid.T) {
		nid := gen.Draw(rt, "nodeid")
		b, err := nid.Encode()
		if err != nil {
			rt.Fatalf("encode nodeid: %v", err)
		}
		var out ua.NodeID
		if _, err := out.Decode(b); err != nil {
			rt.Fatalf("decode nodeid: %v", err)
		}
		if nid.String() != out.String() {
			rt.Fatalf("nodeid round-trip mismatch: want %s got %s", nid.String(), out.String())
		}
	})
}

// TestProperty_WriteReadIdentity is a server round-trip property: writing a
// random int64 and reading it back must be the identity function.
func TestProperty_WriteReadIdentity(t *testing.T) {
	c, f, ctx := setup(t)
	nid := addFreshNode(t, c, f, ctx, "prop_i64")

	// Seed with an int64 so the type-match check is satisfied on every write.
	_, err := c.WriteValue(ctx, nid, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int64(0))})
	require.NoError(t, err)

	rapid.Check(t, func(rt *rapid.T) {
		want := rapid.Int64().Draw(rt, "value")

		status, err := c.WriteValue(ctx, nid, &ua.DataValue{
			EncodingMask: ua.DataValueValue,
			Value:        ua.MustVariant(want),
		})
		if err != nil {
			rt.Fatalf("write: %v", err)
		}
		if status != ua.StatusOK {
			rt.Fatalf("write status: %v", status)
		}
		dv, err := c.ReadValue(ctx, nid)
		if err != nil {
			rt.Fatalf("read: %v", err)
		}
		if got := dv.Value.Value(); got != want {
			rt.Fatalf("round-trip mismatch: want %d got %v", want, got)
		}
	})
}

// TestProperty_ReadMultiChunkInvariance checks that ReadMulti returns the same
// results regardless of the chunk size used to split the batch.
func TestProperty_ReadMultiChunkInvariance(t *testing.T) {
	c, f, ctx := setup(t)

	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 20).Draw(rt, "n")
		chunk := rapid.IntRange(1, 10).Draw(rt, "chunk")

		items := make([]opcua.ReadItem, n)
		for i := range items {
			items[i] = opcua.ReadItem{NodeID: f.Int32, AttributeID: ua.AttributeIDValue}
		}
		results, err := c.ReadMulti(ctx, items, opcua.ReadMultiWithChunkSize(uint32(chunk)))
		if err != nil {
			rt.Fatalf("readmulti: %v", err)
		}
		if len(results) != n {
			rt.Fatalf("expected %d results, got %d", n, len(results))
		}
		for i := range results {
			if results[i].StatusCode != ua.StatusOK {
				rt.Fatalf("item %d status %v", i, results[i].StatusCode)
			}
			if results[i].DataValue.Value.Value() != int32(42) {
				rt.Fatalf("item %d value %v", i, results[i].DataValue.Value.Value())
			}
		}
	})
}
