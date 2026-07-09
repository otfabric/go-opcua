// SPDX-License-Identifier: MIT

package attrs

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
)

func TestBrowseName(t *testing.T) {
	qn := BrowseName("Temperature")
	assert.Equal(t, "Temperature", qn.Name)
}

func TestDisplayName(t *testing.T) {
	lt := DisplayName("Temp", "en-US")
	assert.Equal(t, "Temp", lt.Text)
	assert.Equal(t, "en-US", lt.Locale)
}

func TestInverseName(t *testing.T) {
	lt := InverseName("Inv", "de-DE")
	assert.Equal(t, "Inv", lt.Text)
	assert.Equal(t, "de-DE", lt.Locale)
}

func TestNodeClass(t *testing.T) {
	assert.Equal(t, uint32(ua.NodeClassVariable), NodeClass(ua.NodeClassVariable))
}

func TestDataType(t *testing.T) {
	id := ua.NewNumericNodeID(0, 6)
	exp := DataType(id)
	assert.True(t, exp.NodeID.Equal(id))
}
