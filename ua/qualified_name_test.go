// SPDX-License-Identifier: MIT

package ua

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQualifiedNameString(t *testing.T) {
	assert.Equal(t, "", (*QualifiedName)(nil).String())
	assert.Equal(t, "Server", (&QualifiedName{Name: "Server"}).String())
	assert.Equal(t, "2:Temp", (&QualifiedName{NamespaceIndex: 2, Name: "Temp"}).String())
}

func TestQualifiedNameEncodeDecode(t *testing.T) {
	orig := &QualifiedName{NamespaceIndex: 3, Name: "Pressure"}
	encoded, err := orig.Encode()
	require.NoError(t, err)

	var got QualifiedName
	n, err := got.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, len(encoded), n)
	assert.Equal(t, orig.NamespaceIndex, got.NamespaceIndex)
	assert.Equal(t, orig.Name, got.Name)
}

func TestQualifiedNameNullEncode(t *testing.T) {
	var q *QualifiedName
	encoded, err := q.Encode()
	require.NoError(t, err)
	var got QualifiedName
	_, err = got.Decode(encoded)
	require.NoError(t, err)
}
