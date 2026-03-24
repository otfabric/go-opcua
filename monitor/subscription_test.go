package monitor

import (
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNodeMonitor(t *testing.T) {
	c, err := opcua.NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	m, err := NewNodeMonitor(c)
	require.NoError(t, err)
	assert.NotNil(t, m)
}

func TestNodeMonitor_SetErrorHandler(t *testing.T) {
	c, err := opcua.NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	m, err := NewNodeMonitor(c)
	require.NoError(t, err)

	called := false
	m.SetErrorHandler(func(_ *opcua.Client, _ *Subscription, _ error) {
		called = true
	})
	_ = called
	assert.NotNil(t, m.errHandlerCB)
}

func TestSubscription_Counters(t *testing.T) {
	// Verify that a zero-value subscription returns zero counters
	s := &Subscription{
		closed:     make(chan struct{}),
		handles:    make(map[uint32]*ua.NodeID),
		itemLookup: make(map[uint32]Item),
	}
	assert.Equal(t, uint64(0), s.Delivered())
	assert.Equal(t, uint64(0), s.Dropped())
}
