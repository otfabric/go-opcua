// SPDX-License-Identifier: MIT

package ua

import (
	"testing"
	"time"
)

func TestParseVariant(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		typeID TypeID
		want   string // expected Variant.String() output
	}{
		{"bool true", "true", TypeIDBoolean, "true"},
		{"bool false", "false", TypeIDBoolean, "false"},
		{"bool 1", "1", TypeIDBoolean, "true"},
		{"bool 0", "0", TypeIDBoolean, "false"},
		{"bool TRUE", "TRUE", TypeIDBoolean, "true"},
		{"sbyte", "-42", TypeIDSByte, "-42"},
		{"byte", "255", TypeIDByte, "255"},
		{"int16", "-1000", TypeIDInt16, "-1000"},
		{"uint16", "65535", TypeIDUint16, "65535"},
		{"int32", "123456", TypeIDInt32, "123456"},
		{"uint32", "4294967295", TypeIDUint32, "4294967295"},
		{"int64", "-9876543210", TypeIDInt64, "-9876543210"},
		{"uint64", "18446744073709551615", TypeIDUint64, "18446744073709551615"},
		{"float", "3.14", TypeIDFloat, "3.14"},
		{"double", "2.718281828", TypeIDDouble, "2.718281828"},
		{"string", "hello world", TypeIDString, "hello world"},
		{"empty string", "", TypeIDString, ""},
		{"datetime", "2024-01-15T10:30:00Z", TypeIDDateTime, "2024-01-15T10:30:00Z"},
		{"guid", "72962B91-FA75-4AE6-8D28-B404DC7DAF63", TypeIDGUID, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"},
		{"bytestring", "deadbeef", TypeIDByteString, "deadbeef"},
		{"bytestring empty", "", TypeIDByteString, ""},
		{"xmlelement", "<tag>val</tag>", TypeIDXMLElement, "<tag>val</tag>"},
		{"nodeid", "ns=2;s=Temp", TypeIDNodeID, "ns=2;s=Temp"},
		{"nodeid numeric", "i=85", TypeIDNodeID, "i=85"},
		{"statuscode hex", "0x00000000", TypeIDStatusCode, "StatusGood"},
		{"statuscode name", "StatusBadNodeIDUnknown", TypeIDStatusCode, "StatusBadNodeIDUnknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseVariant(tt.input, tt.typeID)
			if err != nil {
				t.Fatalf("ParseVariant(%q, %v): %v", tt.input, tt.typeID, err)
			}
			got := v.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseVariantRoundTrip(t *testing.T) {
	// Verify round-trip: String() -> ParseVariant -> String() is stable
	tests := []struct {
		name   string
		v      *Variant
		typeID TypeID
	}{
		{"bool", MustVariant(true), TypeIDBoolean},
		{"int32", MustVariant(int32(42)), TypeIDInt32},
		{"float64", MustVariant(float64(3.14)), TypeIDDouble},
		{"string", MustVariant("test"), TypeIDString},
		{"datetime", MustVariant(time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)), TypeIDDateTime},
		{"nodeid", MustVariant(NewNumericNodeID(0, 85)), TypeIDNodeID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.v.String()
			v2, err := ParseVariant(s, tt.typeID)
			if err != nil {
				t.Fatalf("ParseVariant(%q, %v): %v", s, tt.typeID, err)
			}
			s2 := v2.String()
			if s != s2 {
				t.Errorf("round trip failed: %q -> %q", s, s2)
			}
		})
	}
}

func TestParseVariantErrors(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		typeID TypeID
	}{
		{"invalid bool", "maybe", TypeIDBoolean},
		{"invalid int32", "abc", TypeIDInt32},
		{"invalid float", "not-a-number", TypeIDFloat},
		{"invalid datetime", "not-a-date", TypeIDDateTime},
		{"invalid guid", "not-a-guid", TypeIDGUID},
		{"invalid bytestring", "xyz!", TypeIDByteString},
		{"invalid statuscode", "UnknownStatusName", TypeIDStatusCode},
		{"unsupported type", "value", TypeID(99)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseVariant(tt.input, tt.typeID)
			if err == nil {
				t.Errorf("ParseVariant(%q, %v) expected error, got nil", tt.input, tt.typeID)
			}
		})
	}
}
