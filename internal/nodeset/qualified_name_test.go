// SPDX-License-Identifier: MIT

package nodeset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseQualifiedName: the string form of a QualifiedName (Part 6
// §5.1.12): a name without a prefix is in namespace 0, a prefix of digits
// and a colon is the namespace index, and the name may hold colons.
func TestParseQualifiedName(t *testing.T) {
	for _, c := range []struct {
		in   string
		ns   uint16
		name string
	}{
		{"InputArguments", 0, "InputArguments"},
		{"Default Binary", 0, "Default Binary"},
		{"0:3DVector", 0, "3DVector"},
		{"3DVector", 0, "3DVector"},
		{"1:Tank", 1, "Tank"},
		{"3:Hello:World", 3, "Hello:World"},
		{"65535:Max", 65535, "Max"},
		{":x", 0, ":x"},
		{"1:", 1, ""},
		{"", 0, ""},
	} {
		ns, name, err := ParseQualifiedName(c.in)
		require.NoError(t, err, c.in)
		assert.Equal(t, c.ns, ns, c.in)
		assert.Equal(t, c.name, name, c.in)
	}
	_, _, err := ParseQualifiedName("65536:Big")
	assert.ErrorContains(t, err, "not a UInt16")
}
