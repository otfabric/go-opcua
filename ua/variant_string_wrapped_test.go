// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVariantString_WrappedTypes(t *testing.T) {
	tests := []struct {
		name string
		v    interface{}
		want string
	}{
		{"extension object with body", &ExtensionObject{Value: &AnonymousIdentityToken{PolicyID: "anon"}}, "&{anon}"},
		{
			"extension object without body",
			&ExtensionObject{TypeID: NewFourByteExpandedNodeID(0, 321)},
			"ExtensionObject(TypeID=i=321)",
		},
		{"nil extension object", (*ExtensionObject)(nil), "null"},
		{"data value", &DataValue{EncodingMask: DataValueValue, Value: MustVariant(int32(12))}, "12"},
		{"data value without value", &DataValue{}, "null"},
		{"nil data value", (*DataValue)(nil), "null"},
		{"nested variant", MustVariant("inner"), "inner"},
		{"nil nested variant", (*Variant)(nil), "null"},
		{"nil diagnostic info", (*DiagnosticInfo)(nil), "null"},
		{"array of extension objects", []*ExtensionObject{nil, {TypeID: NewFourByteExpandedNodeID(0, 7)}}, "[null, ExtensionObject(TypeID=i=7)]"},
		{"array of data values", []*DataValue{{Value: MustVariant(true)}, nil}, "[true, null]"},
		{"array of variants", []*Variant{MustVariant(uint16(3)), MustVariant("x")}, "[3, x]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, MustVariant(tt.v).String())
		})
	}

	// A diagnostic info is rendered with the default struct formatting.
	di := &DiagnosticInfo{EncodingMask: DiagnosticInfoSymbolicID, SymbolicID: 42}
	s := MustVariant(di).String()
	require.Contains(t, s, "42")
	require.NotEqual(t, "null", s)
}

func TestNewVariant_RejectsUnsupportedValues(t *testing.T) {
	type custom struct{ A int }
	for name, v := range map[string]interface{}{
		"struct":             custom{A: 1},
		"slice of struct":    []custom{{A: 1}},
		"map":                map[string]int{"a": 1},
		"jagged matrix":      [][]int32{{1, 2}, {3}},
		"nested unsupported": [][]custom{{{A: 1}}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := NewVariant(v)
			require.Error(t, err)
			require.Nil(t, got)
			require.Panics(t, func() { MustVariant(v) })
		})
	}
}

func TestVariant_ByteArrayAccessor(t *testing.T) {
	// Only a one-dimensional Byte array has a ByteArray representation.
	require.Nil(t, MustVariant([]int32{1, 2}).ByteArray())
	require.Nil(t, MustVariant(int32(1)).ByteArray())
	require.Nil(t, MustVariant([][]int32{{1}, {2}}).ByteArray())
}
