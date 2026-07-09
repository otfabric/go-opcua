// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalizedTextString(t *testing.T) {
	assert.Equal(t, "", (*LocalizedText)(nil).String())
	lt := &LocalizedText{Text: "Hello", Locale: "en"}
	lt.UpdateMask()
	assert.Contains(t, lt.String(), "Hello")
}

func TestLocalizedTextEncodeDecode(t *testing.T) {
	orig := &LocalizedText{Text: "Temp", Locale: "en-US"}
	orig.UpdateMask()
	encoded, err := orig.Encode()
	require.NoError(t, err)

	var got LocalizedText
	n, err := got.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, len(encoded), n)
	assert.Equal(t, orig.Text, got.Text)
	assert.Equal(t, orig.Locale, got.Locale)
}
