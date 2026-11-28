// SPDX-License-Identifier: MIT

package fxcm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAppendOnce: the Connections of an Event name each Connection once,
// however many of its endpoints a call carries.
func TestAppendOnce(t *testing.T) {
	t.Parallel()
	s := appendOnce(nil, "C1")
	s = appendOnce(s, "C2")
	s = appendOnce(s, "C1")
	assert.Equal(t, []string{"C1", "C2"}, s)
}
