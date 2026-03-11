// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package id

import (
	"testing"
)

func TestMethodName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{Server_GetMonitoredItems, "Server_GetMonitoredItems"},
		{0, ""},
		{99999, ""},
	}
	for _, tt := range tests {
		got := MethodName(tt.id)
		if got != tt.want {
			t.Errorf("MethodName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
