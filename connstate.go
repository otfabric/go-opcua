// SPDX-License-Identifier: MIT

package opcua

// ConnState represents the connection state of an OPC-UA [Client].
//
// Monitor state changes by providing a callback via [WithConnStateHandler].
type ConnState uint8

const (
	// Closed indicates the client is not connected. This is the initial state
	// and the final state after [Client.Close] or a failed reconnection.
	Closed ConnState = iota
	// Connected indicates the client has an active session and is ready for operations.
	Connected
	// Connecting indicates the client is establishing its first connection.
	Connecting
	// Disconnected indicates the connection was lost. If AutoReconnect is
	// enabled, the client will transition to Reconnecting.
	Disconnected
	// Reconnecting indicates the client is attempting to recover a lost connection.
	// On success it transitions to Connected; on failure to Closed.
	Reconnecting
)
