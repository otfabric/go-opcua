// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_StateTransitions(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	assert.Equal(t, Closed, c.State())

	// Cannot send when disconnected
	err = c.Send(context.Background(), &ua.ReadRequest{}, func(ua.Response) error { return nil })
	assert.Equal(t, ua.StatusBadServerNotConnected, err)
}

func TestClient_ConnectToBadAddress(t *testing.T) {
	c, err := NewClient("opc.tcp://192.0.2.1:4840")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = c.Dial(ctx)
	assert.Error(t, err)
}

func TestClient_CloseIdempotent(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)

	// Closing a client that was never connected should not panic
	err = c.Close(context.Background())
	assert.NoError(t, err)

	// Double close should also be safe
	err = c.Close(context.Background())
	assert.NoError(t, err)
}

func TestClient_StateCallback(t *testing.T) {
	var states []ConnState
	c, err := NewClient("opc.tcp://example.com:4840",
		WithConnStateHandler(func(s ConnState) {
			states = append(states, s)
		}),
	)
	require.NoError(t, err)

	_ = c.Close(context.Background())
	assert.Contains(t, states, Closed)
}

// TestConnState_String verifies all state names.
func TestConnState_String(t *testing.T) {
	tests := []struct {
		state ConnState
		want  string
	}{
		{Closed, "Closed"},
		{Connected, "Connected"},
		{Connecting, "Connecting"},
		{Disconnected, "Disconnected"},
		{Reconnecting, "Reconnecting"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.state.String())
		})
	}
}

// TestClient_StateTransitions_Full verifies setState correctly transitions
// between all valid states and delivers to both channel and function callbacks.
func TestClient_StateTransitions_Full(t *testing.T) {
	transitions := []ConnState{Connecting, Connected, Disconnected, Reconnecting, Connected, Closed}

	stateCh := make(chan ConnState, len(transitions))
	var funcStates []ConnState

	c, err := NewClient("opc.tcp://example.com:4840",
		WithConnStateChan(stateCh),
		WithConnStateHandler(func(s ConnState) {
			funcStates = append(funcStates, s)
		}),
	)
	require.NoError(t, err)

	ctx := context.Background()
	for _, s := range transitions {
		c.setState(ctx, s)
		assert.Equal(t, s, c.State())
	}

	// Verify all transitions were delivered to the channel.
	close(stateCh)
	var chanStates []ConnState
	for s := range stateCh {
		chanStates = append(chanStates, s)
	}
	assert.Equal(t, transitions, chanStates)
	assert.Equal(t, transitions, funcStates)
}

// TestClient_SubscriptionIDs_Empty verifies empty client has no subscriptions.
func TestClient_SubscriptionIDs_Empty(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()

	ids := c.SubscriptionIDs()
	assert.Empty(t, ids)
}

// TestClient_Read_Disconnected verifies Read returns a status error
// when client is not connected.
func TestClient_Read_Disconnected(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()

	_, err = c.Read(context.Background(), &ua.ReadRequest{})
	assert.Equal(t, ua.StatusBadServerNotConnected, err)
}

// TestClient_Write_Disconnected verifies Write returns a status error
// when client is not connected.
func TestClient_Write_Disconnected(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()

	_, err = c.Write(context.Background(), &ua.WriteRequest{})
	assert.Equal(t, ua.StatusBadServerNotConnected, err)
}

// TestClient_Browse_Disconnected verifies Browse returns a status error
// when client is not connected.
func TestClient_Browse_Disconnected(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()

	_, err = c.Browse(context.Background(), &ua.BrowseRequest{})
	assert.Equal(t, ua.StatusBadServerNotConnected, err)
}

// TestClient_Call_Disconnected verifies Call returns a status error
// when client is not connected.
func TestClient_Call_Disconnected(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()

	_, err = c.Call(context.Background(), &ua.CallMethodRequest{})
	assert.Equal(t, ua.StatusBadServerNotConnected, err)
}

// TestClient_Subscribe_Disconnected verifies Subscribe returns a status error
// when client is not connected.
func TestClient_Subscribe_Disconnected(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()

	ch := make(chan *PublishNotificationData, 1)
	_, err = c.Subscribe(context.Background(), &SubscriptionParameters{}, ch)
	assert.Equal(t, ua.StatusBadServerNotConnected, err)
}

// TestClient_HistoryRead_Disconnected verifies HistoryRead fails when disconnected.
func TestClient_HistoryRead_Disconnected(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()

	_, err = c.HistoryReadRawModified(context.Background(), nil, nil)
	assert.Equal(t, ua.StatusBadServerNotConnected, err)
}

// TestClient_AutoReconnect_DefaultEnabled verifies auto-reconnect is on by default.
func TestClient_AutoReconnect_DefaultEnabled(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()
	assert.True(t, c.cfg.sechan.AutoReconnect)
}

// TestClient_AutoReconnect_Disabled verifies auto-reconnect can be disabled.
func TestClient_AutoReconnect_Disabled(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840", AutoReconnect(false))
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()
	assert.False(t, c.cfg.sechan.AutoReconnect)
}

// TestClient_ReconnectInterval_Custom verifies the reconnect interval option.
func TestClient_ReconnectInterval_Custom(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840", ReconnectInterval(5*time.Second))
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()
	assert.Equal(t, 5*time.Second, c.cfg.sechan.ReconnectInterval)
}

// TestClient_Namespaces_Default verifies default namespace list exists.
func TestClient_Namespaces_Default(t *testing.T) {
	c, err := NewClient("opc.tcp://example.com:4840")
	require.NoError(t, err)
	defer func() { _ = c.Close(context.Background()) }()

	ns := c.Namespaces()
	assert.NotNil(t, ns)
}
