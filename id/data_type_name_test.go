// SPDX-License-Identifier: MIT

package id

import (
	"testing"
)

func TestDataTypeName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{1, "Boolean"},
		{10, "Float"},
		{11, "Double"},
		{12, "String"},
		{3, "Byte"},
		{5, "UInt16"},
		{6, "Int32"},
		{13, "DateTime"},
		{294, "UtcTime"},
		{0, ""},
		{99999, ""},
	}
	for _, tt := range tests {
		got := DataTypeName(tt.id)
		if got != tt.want {
			t.Errorf("DataTypeName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
