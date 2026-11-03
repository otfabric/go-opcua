// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// testOptionSet64 is a named uint64, which the codecs treat as an enumeration
// or option set. It is not registered, so it has no symbols.
type testOptionSet64 uint64

type testOptionSet64Holder struct {
	Mask testOptionSet64
}

// TestEnum_Uint64HighBit: a UInt64 enumeration or option set with bit 63 set
// is written as the unsigned number, not as a negative one, and reads back.
func TestEnum_Uint64HighBit(t *testing.T) {
	t.Parallel()
	in := testOptionSet64Holder{Mask: 1<<63 | 5}

	j, err := EncodeJSON(&in)
	require.NoError(t, err)
	require.Contains(t, string(j), "9223372036854775813")
	var jout testOptionSet64Holder
	require.NoError(t, DecodeJSON(j, &jout))
	require.Equal(t, in, jout)

	x, err := EncodeXML(&in)
	require.NoError(t, err)
	require.Contains(t, string(x), "9223372036854775813")
	var xout testOptionSet64Holder
	require.NoError(t, DecodeXML(x, &xout))
	require.Equal(t, in, xout)
}
