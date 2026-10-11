// SPDX-License-Identifier: MIT

// JSON and XML DataEncoding through the public API only (Part 6 §5.4, §5.3).
//
// The exhaustive codec tests live in package ua, next to the implementation.
// These tests check what an application sees: the exported functions, values
// built with the exported constructors, and custom structures registered
// with ua.RegisterExtensionObject from another package.
package conformance

import (
	"bytes"
	"math"
	"reflect"
	"testing"
	"time"
	"unicode"

	"github.com/otfabric/go-opcua/internal/testutil/customtypes"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// codecValueGen draws scalars, arrays and matrices of the common built-in
// types, including the values JSON and XML have no number for.
func codecValueGen() *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		float := rapid.OneOf(rapid.Float64(), rapid.SampledFrom([]float64{math.NaN(), math.Inf(1), math.Inf(-1), 0, -1.5}))
		text := rapid.StringOf(rapid.RuneFrom(nil, rapidXMLRunes))
		when := rapid.Custom(func(t *rapid.T) time.Time {
			// 1700 .. 9000, in the 100ns resolution of DateTime
			return time.Unix(rapid.Int64Range(-8_520_336_000, 221_845_392_000).Draw(t, "sec"),
				int64(rapid.IntRange(0, 9_999_999).Draw(t, "ticks"))*100).UTC()
		})
		switch rapid.IntRange(0, 13).Draw(t, "kind") {
		case 0:
			return rapid.Bool().Draw(t, "bool")
		case 1:
			return rapid.Int64().Draw(t, "i64")
		case 2:
			return rapid.Uint64().Draw(t, "u64")
		case 3:
			return float.Draw(t, "f64")
		case 4:
			return float32(rapid.Float32().Draw(t, "f32"))
		case 5:
			return text.Draw(t, "str")
		case 6:
			return when.Draw(t, "time")
		case 7:
			return rapid.SliceOfN(rapid.Byte(), 1, 16).Draw(t, "bytes")
		case 8:
			return ua.NewStringNodeID(uint16(rapid.IntRange(0, 9).Draw(t, "ns")), text.Draw(t, "id"))
		case 9:
			return ua.NewLocalizedTextWithLocale(text.Draw(t, "text"), rapid.SampledFrom([]string{"", "en", "de-DE"}).Draw(t, "locale"))
		case 10:
			return rapid.SliceOf(rapid.Int32()).Draw(t, "i32slice")
		case 11:
			return rapid.SliceOf(text).Draw(t, "strslice")
		case 12:
			rows, cols := rapid.IntRange(1, 3).Draw(t, "rows"), rapid.IntRange(1, 3).Draw(t, "cols")
			m := make([][]float64, rows)
			for i := range m {
				m[i] = rapid.SliceOfN(float, cols, cols).Draw(t, "row")
			}
			return m
		default:
			return ua.StatusCode(rapid.Uint32().Draw(t, "status"))
		}
	})
}

// rapidXMLRunes are the characters XML 1.0 can carry.
var rapidXMLRunes = &unicode.RangeTable{
	R16: []unicode.Range16{{Lo: 0x09, Hi: 0x0A, Stride: 1}, {Lo: 0x0D, Hi: 0x0D, Stride: 1}, {Lo: 0x20, Hi: 0xD7FF, Stride: 1}, {Lo: 0xE000, Hi: 0xFFFD, Stride: 1}},
	R32: []unicode.Range32{{Lo: 0x10000, Hi: 0x10FFFF, Stride: 1}},
}

// TestProperty_VariantJSONXML: binary -> JSON -> binary and binary -> XML ->
// binary keep a Variant byte for byte, in every JSON form that can be decoded.
func TestProperty_VariantJSONXML(t *testing.T) {
	forms := []ua.JSONForm{ua.JSONCompact, ua.JSONVerbose, ua.JSONLegacyReversible}
	rapid.Check(t, func(rt *rapid.T) {
		v, err := ua.NewVariant(codecValueGen().Draw(rt, "value"))
		if err != nil {
			rt.Fatal(err)
		}
		want, err := v.Encode()
		if err != nil {
			rt.Fatal(err)
		}
		for _, form := range forms {
			doc, err := ua.EncodeJSON(v, ua.WithJSONForm(form))
			if err != nil {
				rt.Fatalf("EncodeJSON: %v", err)
			}
			var back ua.Variant
			if err := ua.DecodeJSON(doc, &back); err != nil {
				rt.Fatalf("DecodeJSON(%s): %v", doc, err)
			}
			if got, _ := back.Encode(); !bytes.Equal(want, got) {
				rt.Fatalf("JSON form %d changed the value\n doc:  %s\n want: %x\n got:  %x", form, doc, want, got)
			}
		}
		doc, err := ua.EncodeXML(v)
		if err != nil {
			rt.Fatalf("EncodeXML: %v", err)
		}
		var back ua.Variant
		if err := ua.DecodeXML(doc, &back); err != nil {
			rt.Fatalf("DecodeXML(%s): %v", doc, err)
		}
		if got, _ := back.Encode(); !bytes.Equal(want, got) {
			rt.Fatalf("XML changed the value\n doc:  %s\n want: %x\n got:  %x", doc, want, got)
		}
	})
}

// TestProperty_DataValueJSONXML does the same for a DataValue with any
// combination of its optional fields.
func TestProperty_DataValueJSONXML(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		dv := &ua.DataValue{
			Status:            ua.StatusCode(rapid.SampledFrom([]uint32{0, 0x80340000, 0x40920000}).Draw(rt, "status")),
			SourcePicoseconds: uint16(rapid.IntRange(0, 9999).Draw(rt, "srcPico")),
			ServerPicoseconds: uint16(rapid.IntRange(0, 9999).Draw(rt, "srvPico")),
		}
		if rapid.Bool().Draw(rt, "hasValue") {
			v, err := ua.NewVariant(codecValueGen().Draw(rt, "value"))
			if err != nil {
				rt.Fatal(err)
			}
			dv.Value = v
		}
		if rapid.Bool().Draw(rt, "hasSource") {
			dv.SourceTimestamp = time.Unix(rapid.Int64Range(0, 4_000_000_000).Draw(rt, "src"), 0).UTC()
		}
		if rapid.Bool().Draw(rt, "hasServer") {
			dv.ServerTimestamp = time.Unix(rapid.Int64Range(0, 4_000_000_000).Draw(rt, "srv"), 0).UTC()
		}
		dv.UpdateMask()
		want, err := dv.Encode()
		if err != nil {
			rt.Fatal(err)
		}

		doc, err := ua.EncodeJSON(dv)
		if err != nil {
			rt.Fatalf("EncodeJSON: %v", err)
		}
		var fromJSON ua.DataValue
		if err := ua.DecodeJSON(doc, &fromJSON); err != nil {
			rt.Fatalf("DecodeJSON(%s): %v", doc, err)
		}
		if got, _ := fromJSON.Encode(); !bytes.Equal(want, got) {
			rt.Fatalf("JSON changed the value\n doc:  %s\n want: %x\n got:  %x", doc, want, got)
		}

		doc, err = ua.EncodeXML(dv)
		if err != nil {
			rt.Fatalf("EncodeXML: %v", err)
		}
		var fromXML ua.DataValue
		if err := ua.DecodeXML(doc, &fromXML); err != nil {
			rt.Fatalf("DecodeXML(%s): %v", doc, err)
		}
		if got, _ := fromXML.Encode(); !bytes.Equal(want, got) {
			rt.Fatalf("XML changed the value\n doc:  %s\n want: %x\n got:  %x", doc, want, got)
		}
	})
}

// TestCustomTypes_JSONXML: structures registered by another package with
// ua.RegisterExtensionObject - and nothing else - survive JSON and XML, as a
// structure, inside an ExtensionObject and in an array of them.
func TestCustomTypes_JSONXML(t *testing.T) {
	flat := &customtypes.FlatStruct{Temperature: 21.5, Pressure: 1013, Label: "ok"}
	array := &customtypes.ArrayStruct{Name: "values", Values: []int32{1, -2, 3}}
	nested := &customtypes.NestedStruct{ID: 7, Inner: *flat, Active: true}

	t.Run("documents", func(t *testing.T) {
		doc, err := ua.EncodeJSON(nested)
		require.NoError(t, err)
		require.Equal(t, `{"ID":7,"Inner":{"Temperature":21.5,"Pressure":1013,"Label":"ok"},"Active":true}`, string(doc))

		doc, err = ua.EncodeJSON(ua.NewExtensionObject(array))
		require.NoError(t, err)
		require.Equal(t, `{"UaTypeId":"ns=2;i=3003","Name":"values","Values":[1,-2,3]}`, string(doc))

		doc, err = ua.EncodeXML(ua.NewExtensionObject(flat), ua.WithoutXMLNamespace())
		require.NoError(t, err)
		require.Equal(t, `<ExtensionObject><TypeId><Identifier>ns=2;i=3002</Identifier></TypeId><Body><FlatStruct><Temperature>21.5</Temperature><Pressure>1013</Pressure><Label>ok</Label></FlatStruct></Body></ExtensionObject>`, string(doc))
	})

	for name, v := range map[string]any{"flat": flat, "array": array, "nested": nested} {
		t.Run(name, func(t *testing.T) {
			for _, form := range []ua.JSONForm{ua.JSONCompact, ua.JSONVerbose, ua.JSONLegacyReversible} {
				doc, err := ua.EncodeJSON(v, ua.WithJSONForm(form))
				require.NoError(t, err)
				back := reflect.New(reflect.TypeOf(v).Elem()).Interface()
				require.NoError(t, ua.DecodeJSON(doc, back), "%s", doc)
				require.Equal(t, v, back, "%s", doc)
			}
			doc, err := ua.EncodeXML(v)
			require.NoError(t, err)
			back := reflect.New(reflect.TypeOf(v).Elem()).Interface()
			require.NoError(t, ua.DecodeXML(doc, back), "%s", doc)
			require.Equal(t, v, back, "%s", doc)
		})
	}

	t.Run("in a Variant", func(t *testing.T) {
		v := ua.MustVariant([]*ua.ExtensionObject{
			ua.NewExtensionObject(flat), ua.NewExtensionObject(array), ua.NewExtensionObject(nested),
		})
		want, err := v.Encode()
		require.NoError(t, err)

		for _, form := range []ua.JSONForm{ua.JSONCompact, ua.JSONVerbose, ua.JSONLegacyReversible} {
			doc, err := ua.EncodeJSON(v, ua.WithJSONForm(form))
			require.NoError(t, err)
			var back ua.Variant
			require.NoError(t, ua.DecodeJSON(doc, &back), "%s", doc)
			got, err := back.Encode()
			require.NoError(t, err)
			require.Equal(t, want, got, "%s", doc)
			require.Equal(t, nested, back.Value().([]*ua.ExtensionObject)[2].Value)
		}

		doc, err := ua.EncodeXML(v)
		require.NoError(t, err)
		var back ua.Variant
		require.NoError(t, ua.DecodeXML(doc, &back), "%s", doc)
		got, err := back.Encode()
		require.NoError(t, err)
		require.Equal(t, want, got, "%s", doc)
		require.Equal(t, array, back.Value().([]*ua.ExtensionObject)[1].Value)
	})
}
