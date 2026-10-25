//go:build interop

// SPDX-License-Identifier: MIT

// Historical events (Part 11 §6.5.2, §6.9.4, §6.9.7; CLIENT_CONTRACT §17):
// the open62541 and Milo clients against the go-opcua fixture
// s=History.Events. Neither stack has an event history server (§17.5).
// The assertions are in history_events_test.go.
// COVERAGE.md: history / history.read.events, history.read.events.continuation,
// history.read.events.filter, history.update.events, history.delete.events

package interop

import (
	"testing"
)

func TestGoServer_Open62541Client_HistoryReadEvents(t *testing.T) {
	t.Run("coverage/history.read.events/open62541-client-to-go-server", func(t *testing.T) {
		assertPeerReadsGoEvents(t, open62541EventClient)
	})
}

func TestGoServer_Open62541Client_HistoryReadEventsContinuation(t *testing.T) {
	t.Run("coverage/history.read.events.continuation/open62541-client-to-go-server", func(t *testing.T) {
		assertPeerContinuesGoEvents(t, open62541EventClient)
	})
}

func TestGoServer_Open62541Client_HistoryReadEventsFilter(t *testing.T) {
	t.Run("coverage/history.read.events.filter/open62541-client-to-go-server", func(t *testing.T) {
		assertPeerFiltersGoEvents(t, open62541EventClient)
	})
}

func TestGoServer_Open62541Client_HistoryUpdateEvents(t *testing.T) {
	t.Run("coverage/history.update.events/open62541-client-to-go-server", func(t *testing.T) {
		assertPeerUpdatesGoEvents(t, open62541EventClient)
	})
}

func TestGoServer_Open62541Client_HistoryDeleteEvents(t *testing.T) {
	t.Run("coverage/history.delete.events/open62541-client-to-go-server", func(t *testing.T) {
		assertPeerDeletesGoEvents(t, open62541EventClient)
	})
}

func TestGoServer_MiloClient_HistoryReadEvents(t *testing.T) {
	t.Run("coverage/history.read.events/milo-client-to-go-server", func(t *testing.T) {
		assertPeerReadsGoEvents(t, miloEventClient)
	})
}

func TestGoServer_MiloClient_HistoryReadEventsContinuation(t *testing.T) {
	t.Run("coverage/history.read.events.continuation/milo-client-to-go-server", func(t *testing.T) {
		assertPeerContinuesGoEvents(t, miloEventClient)
	})
}

func TestGoServer_MiloClient_HistoryReadEventsFilter(t *testing.T) {
	t.Run("coverage/history.read.events.filter/milo-client-to-go-server", func(t *testing.T) {
		assertPeerFiltersGoEvents(t, miloEventClient)
	})
}

func TestGoServer_MiloClient_HistoryUpdateEvents(t *testing.T) {
	t.Run("coverage/history.update.events/milo-client-to-go-server", func(t *testing.T) {
		assertPeerUpdatesGoEvents(t, miloEventClient)
	})
}

func TestGoServer_MiloClient_HistoryDeleteEvents(t *testing.T) {
	t.Run("coverage/history.delete.events/milo-client-to-go-server", func(t *testing.T) {
		assertPeerDeletesGoEvents(t, miloEventClient)
	})
}
