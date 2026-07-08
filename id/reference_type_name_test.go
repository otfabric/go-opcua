// SPDX-License-Identifier: MIT

package id

import (
	"testing"
)

func TestReferenceTypeName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{47, "HasComponent"},
		{35, "Organizes"},
		{46, "HasProperty"},
		{48, "HasNotifier"},
		{40, "HasTypeDefinition"},
		{31, "References"},
		{33, "HierarchicalReferences"},
		{0, ""},
		{99999, ""},
	}
	for _, tt := range tests {
		got := ReferenceTypeName(tt.id)
		if got != tt.want {
			t.Errorf("ReferenceTypeName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
