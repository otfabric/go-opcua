// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGUID(t *testing.T) {
	g := NewGUID("1111AAAA-22BB-33CC-44DD-55EE77FF9900")
	require.NotNil(t, g)
	assert.Equal(t, "1111AAAA-22BB-33CC-44DD-55EE77FF9900", g.String())

	assert.Nil(t, NewGUID("not-hex"))
	assert.Nil(t, NewGUID("abcd"))
}

func TestGUIDEncodeDecode(t *testing.T) {
	orig := NewGUID("1111AAAA-22BB-33CC-44DD-55EE77FF9900")
	encoded, err := orig.Encode()
	require.NoError(t, err)

	var got GUID
	n, err := got.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, len(encoded), n)
	assert.Equal(t, orig.String(), got.String())
}
