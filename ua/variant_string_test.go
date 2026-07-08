// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
	"time"
)

func TestVariantString(t *testing.T) {
	tests := []struct {
		name string
		v    *Variant
		want string
	}{
		{"null", MustVariant(nil), "null"},
		{"bool true", MustVariant(true), "true"},
		{"bool false", MustVariant(false), "false"},
		{"int8", MustVariant(int8(-42)), "-42"},
		{"uint8", MustVariant(uint8(255)), "255"},
		{"int16", MustVariant(int16(-1000)), "-1000"},
		{"uint16", MustVariant(uint16(65535)), "65535"},
		{"int32", MustVariant(int32(123456)), "123456"},
		{"uint32", MustVariant(uint32(4294967295)), "4294967295"},
		{"int64", MustVariant(int64(-9876543210)), "-9876543210"},
		{"uint64", MustVariant(uint64(18446744073709551615)), "18446744073709551615"},
		{"float32", MustVariant(float32(3.14)), "3.14"},
		{"float64", MustVariant(float64(2.718281828)), "2.718281828"},
		{"string", MustVariant("hello world"), "hello world"},
		{"empty string", MustVariant(""), ""},
		{"datetime", MustVariant(time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)), "2024-01-15T10:30:00Z"},
		{"guid", MustVariant(NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63")), "72962B91-FA75-4AE6-8D28-B404DC7DAF63"},
		{"bytestring", MustVariant([]byte{0xDE, 0xAD, 0xBE, 0xEF}), "deadbeef"},
		{"bytestring empty", MustVariant([]byte{}), ""},
		{"nodeid numeric", MustVariant(NewNumericNodeID(0, 85)), "i=85"},
		{"nodeid string", MustVariant(NewStringNodeID(2, "Temp")), "ns=2;s=Temp"},
		{"status good", MustVariant(StatusGood), "StatusGood"},
		{"qualname ns0", MustVariant(&QualifiedName{NamespaceIndex: 0, Name: "Value"}), "Value"},
		{"qualname ns2", MustVariant(&QualifiedName{NamespaceIndex: 2, Name: "Temp"}), "2:Temp"},
		{"localized text", MustVariant(&LocalizedText{Text: "Hello"}), "Hello"},
		{"nil nodeid", MustVariant((*NodeID)(nil)), "null"},
		{"nil qualname", MustVariant((*QualifiedName)(nil)), "null"},
		{"nil localized", MustVariant((*LocalizedText)(nil)), "null"},
		{"nil guid", MustVariant((*GUID)(nil)), "null"},
		{"int32 array", MustVariant([]int32{1, 2, 3}), "[1, 2, 3]"},
		{"string array", MustVariant([]string{"a", "b"}), "[a, b]"},
		{"bool array", MustVariant([]bool{true, false}), "[true, false]"},
		{"float64 array", MustVariant([]float64{1.5, 2.5}), "[1.5, 2.5]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.v.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
