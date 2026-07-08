// SPDX-License-Identifier: MIT

package id

import (
	"testing"
)

func TestObjectTypeName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{58, "BaseObjectType"},
		{61, "FolderType"},
		{0, ""},
		{99999, ""},
	}
	for _, tt := range tests {
		got := ObjectTypeName(tt.id)
		if got != tt.want {
			t.Errorf("ObjectTypeName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
