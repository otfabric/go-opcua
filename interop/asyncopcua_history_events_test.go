//go:build interop

// SPDX-License-Identifier: MIT

// Historical events (Part 11 §6.5.2, §6.9.4, §6.9.7; CLIENT_CONTRACT §17):
// the async-opcua client against the go-opcua fixture s=History.Events.
// async-opcua has no event history server (§17.5).
// The assertions are in history_events_test.go.
// COVERAGE.md: history / history.read.events, history.read.events.continuation,
// history.read.events.filter, history.update.events, history.delete.events

package interop

import (
	"testing"
)

func TestGoServer_AsyncOpcuaClient_HistoryReadEvents(t *testing.T) {
	t.Run("coverage/history.read.events/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerReadsGoEvents(t, asyncOpcuaEventClient)
	})
}

func TestGoServer_AsyncOpcuaClient_HistoryReadEventsContinuation(t *testing.T) {
	t.Run("coverage/history.read.events.continuation/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerContinuesGoEvents(t, asyncOpcuaEventClient)
	})
}

func TestGoServer_AsyncOpcuaClient_HistoryReadEventsFilter(t *testing.T) {
	t.Run("coverage/history.read.events.filter/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerFiltersGoEvents(t, asyncOpcuaEventClient)
	})
}

func TestGoServer_AsyncOpcuaClient_HistoryUpdateEvents(t *testing.T) {
	t.Run("coverage/history.update.events/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerUpdatesGoEvents(t, asyncOpcuaEventClient)
	})
}

func TestGoServer_AsyncOpcuaClient_HistoryDeleteEvents(t *testing.T) {
	t.Run("coverage/history.delete.events/async-opcua-client-to-go-server", func(t *testing.T) {
		assertPeerDeletesGoEvents(t, asyncOpcuaEventClient)
	})
}
