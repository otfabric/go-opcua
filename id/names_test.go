// SPDX-License-Identifier: MIT

package id

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	assert.Equal(t, "ObjectsFolder", Name(ObjectsFolder))
	assert.Equal(t, "BaseDataVariableType", Name(BaseDataVariableType))
	assert.Equal(t, "999999999", Name(999999999))
}
