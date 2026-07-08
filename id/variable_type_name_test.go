// SPDX-License-Identifier: MIT

package id

import (
	"testing"
)

func TestVariableTypeName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{68, "PropertyType"},
		{63, "BaseDataVariableType"},
		{0, ""},
		{99999, ""},
	}
	for _, tt := range tests {
		got := VariableTypeName(tt.id)
		if got != tt.want {
			t.Errorf("VariableTypeName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
