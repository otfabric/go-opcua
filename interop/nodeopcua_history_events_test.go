//go:build interop

// SPDX-License-Identifier: MIT

// Historical events (Part 11 §6.5.2, §6.9.4, §6.9.7; CLIENT_CONTRACT §17):
// the node-opcua client against the go-opcua fixture s=History.Events. The
// node-opcua server historizes variables only (§17.3).
// The assertions are in history_events_test.go.
// COVERAGE.md: history / history.read.events, history.read.events.continuation,
// history.read.events.filter, history.update.events, history.delete.events

package interop

import (
	"testing"
)

func TestGoServer_NodeOpcuaClient_HistoryReadEvents(t *testing.T) {
	t.Run("coverage/history.read.events/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerReadsGoEvents(t, nodeOpcuaEventClient)
	})
}

func TestGoServer_NodeOpcuaClient_HistoryReadEventsContinuation(t *testing.T) {
	t.Run("coverage/history.read.events.continuation/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerContinuesGoEvents(t, nodeOpcuaEventClient)
	})
}

func TestGoServer_NodeOpcuaClient_HistoryReadEventsFilter(t *testing.T) {
	t.Run("coverage/history.read.events.filter/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerFiltersGoEvents(t, nodeOpcuaEventClient)
	})
}

func TestGoServer_NodeOpcuaClient_HistoryUpdateEvents(t *testing.T) {
	t.Run("coverage/history.update.events/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerUpdatesGoEvents(t, nodeOpcuaEventClient)
	})
}

func TestGoServer_NodeOpcuaClient_HistoryDeleteEvents(t *testing.T) {
	t.Run("coverage/history.delete.events/node-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerDeletesGoEvents(t, nodeOpcuaEventClient)
	})
}
