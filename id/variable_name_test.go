// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package id

import (
	"testing"
)

func TestVariableName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{Server_ServerStatus, "Server_ServerStatus"},
		{Server_ServerStatus_CurrentTime, "Server_ServerStatus_CurrentTime"},
		{0, ""},
		{99999, ""},
	}
	for _, tt := range tests {
		got := VariableName(tt.id)
		if got != tt.want {
			t.Errorf("VariableName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
