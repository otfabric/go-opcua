// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

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
