// SPDX-License-Identifier: MIT

package id

import (
	"testing"
)

func TestVariableName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{ServerServerStatus, "Server_ServerStatus"},
		{ServerServerStatusCurrentTime, "Server_ServerStatus_CurrentTime"},
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
