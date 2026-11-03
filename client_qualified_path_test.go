// SPDX-License-Identifier: MIT

package opcua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The namespace index of a QualifiedName is a UInt16 (Part 6 §5.2.2.13): a
// larger index must be rejected, not truncated into another namespace.
func TestParseQualifiedPath_NamespaceRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path    string
		wantNS  uint16
		wantErr bool
	}{
		{path: "0:x", wantNS: 0},
		{path: "65535:x", wantNS: 65535},
		{path: "65536:x", wantErr: true},
		{path: "70000:x", wantErr: true},
		{path: "-1:x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			got, err := parseQualifiedPath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, tt.wantNS, got[0].NamespaceIndex)
			require.Equal(t, "x", got[0].Name)
		})
	}
}
