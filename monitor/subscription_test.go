// SPDX-License-Identifier: MIT

package monitor

import (
	"errors"
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

func TestNewNodeMonitor_nilClient(t *testing.T) {
	m, err := NewNodeMonitor(nil)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Nil(t, m.client)
}

func TestItemAccessors(t *testing.T) {
	nid := ua.NewNumericNodeID(0, 42)
	it := Item{id: 7, nodeID: nid}
	assert.Equal(t, uint32(7), it.ID())
	assert.True(t, it.NodeID().Equal(nid))
}

func TestItemError(t *testing.T) {
	nid := ua.NewStringNodeID(2, "ghost")
	err := &ItemError{NodeID: nid, StatusCode: ua.StatusBadNodeIDUnknown}
	require.Contains(t, err.Error(), "ghost")
	require.True(t, errors.Is(err, ua.StatusBadNodeIDUnknown))

	var itemErr *ItemError
	require.True(t, errors.As(err, &itemErr))
	require.Equal(t, nid.String(), itemErr.NodeID.String())
}

func TestParseNodeSlice(t *testing.T) {
	ids, err := parseNodeSlice("i=1", "ns=2;s=foo")
	require.NoError(t, err)
	require.Len(t, ids, 2)
	assert.True(t, ids[0].Equal(ua.NewNumericNodeID(0, 1)))
	assert.True(t, ids[1].Equal(ua.NewStringNodeID(2, "foo")))

	_, err = parseNodeSlice("ns=0;i=not-a-number")
	require.Error(t, err)

	ids, err = parseNodeSlice()
	require.NoError(t, err)
	assert.Empty(t, ids)
}
