// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package id

import (
	"testing"
)

func TestObjectName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{ObjectsFolder, "ObjectsFolder"},
		{RootFolder, "RootFolder"},
		{Server, "Server"},
		{0, ""},
		{99999, ""},
	}
	for _, tt := range tests {
		got := ObjectName(tt.id)
		if got != tt.want {
			t.Errorf("ObjectName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
