// SPDX-License-Identifier: MIT

package id

import (
	"testing"
)

func TestMethodName(t *testing.T) {
	tests := []struct {
		id   uint32
		want string
	}{
		{ServerGetMonitoredItems, "Server_GetMonitoredItems"},
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
