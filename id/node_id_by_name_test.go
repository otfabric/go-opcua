// SPDX-License-Identifier: MIT

package id

import (
	"testing"
)

func TestNodeIDByName(t *testing.T) {
	tests := []struct {
		name   string
		wantID uint32
		wantOK bool
	}{
		{"CurrentTime", ServerServerStatusCurrentTime, true},
		{"ServerStatus", ServerServerStatus, true},
		{"Objects", ObjectsFolder, true},
		{"Server", Server, true},
		{"ObjectsFolder", ObjectsFolder, true},
		{"Server_ServerStatus_CurrentTime", ServerServerStatusCurrentTime, true},
		{"unknown", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotOK := NodeIDByName(tt.name)
			if gotOK != tt.wantOK || gotID != tt.wantID {
				t.Errorf("NodeIDByName(%q) = (%d, %v), want (%d, %v)", tt.name, gotID, gotOK, tt.wantID, tt.wantOK)
			}
		})
	}
}
