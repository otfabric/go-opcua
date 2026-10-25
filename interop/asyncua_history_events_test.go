//go:build interop

// SPDX-License-Identifier: MIT

// Historical events (Part 11 §6.5.2, §6.9.4, §6.9.7; CLIENT_CONTRACT §17)
// with asyncua 2.1.0: the asyncua client against the go-opcua fixture
// s=History.Events, the go-opcua client against the asyncua fixture (read
// only; its deviations in §17.4).
// The assertions are in history_events_test.go.
// COVERAGE.md: history / history.read.events, history.read.events.continuation,
// history.read.events.filter, history.update.events, history.delete.events

package interop

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

func TestGoServer_AsyncuaClient_HistoryReadEvents(t *testing.T) {
	t.Run("coverage/history.read.events/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerReadsGoEvents(t, asyncuaEventClient)
	})
}

func TestGoServer_AsyncuaClient_HistoryReadEventsContinuation(t *testing.T) {
	t.Run("coverage/history.read.events.continuation/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerContinuesGoEvents(t, asyncuaEventClient)
	})
}

func TestGoServer_AsyncuaClient_HistoryReadEventsFilter(t *testing.T) {
	t.Run("coverage/history.read.events.filter/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerFiltersGoEvents(t, asyncuaEventClient)
	})
}

func TestGoServer_AsyncuaClient_HistoryUpdateEvents(t *testing.T) {
	t.Run("coverage/history.update.events/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerUpdatesGoEvents(t, asyncuaEventClient)
	})
}

func TestGoServer_AsyncuaClient_HistoryDeleteEvents(t *testing.T) {
	t.Run("coverage/history.delete.events/asyncua-client-to-go-server", func(t *testing.T) {
		assertPeerDeletesGoEvents(t, asyncuaEventClient)
	})
}

// startAsyncuaEventServer starts the asyncua server, gated on its fixture
// s=History.Events (history-events; read only).
func startAsyncuaEventServer(t *testing.T) *serverHandle {
	t.Helper()
	requireServerFeature(t, asyncuaEnv, defaultAsyncuaImage, "history-events")
	return startAsyncuaServer(t)
}

func TestAsyncuaServer_HistoryReadEvents(t *testing.T) {
	t.Run("coverage/history.read.events/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaEventServer(t)
		// asyncua answers an empty range with Good, not Good_NoData (§17.4).
		assertGoReadsPeerEvents(t, h.endpoint, ua.StatusOK)
	})
}

func TestAsyncuaServer_HistoryReadEventsContinuation(t *testing.T) {
	t.Run("coverage/history.read.events.continuation/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaEventServer(t)
		// asyncua's continuation points are stateless: a released point
		// still continues the read (§17.4).
		assertGoContinuesPeerEvents(t, h.endpoint, false)
	})
}

func TestAsyncuaServer_HistoryReadEventsFilter(t *testing.T) {
	t.Run("coverage/history.read.events.filter/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaEventServer(t)
		// asyncua's OfType compares the event type exactly (§17.4).
		assertGoFiltersPeerEvents(t, h.endpoint, false)
	})
}

// TestAsyncuaServer_HistoryUpdateEvents pins the refusal of HistoryUpdate by
// asyncua 2.1.0: Bad_UserAccessDenied, for UpdateEventDetails and
// DeleteEventDetails alike (§17.4); the ledger rows are unsupported.
func TestAsyncuaServer_HistoryUpdateEvents(t *testing.T) {
	t.Run("coverage/history.update.events/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaEventServer(t)
		assertGoHistoryUpdateRefused(t, h.endpoint, false, ua.StatusBadUserAccessDenied)
	})
	t.Run("coverage/history.delete.events/go-client-to-asyncua-server", func(t *testing.T) {
		h := startAsyncuaEventServer(t)
		assertGoHistoryUpdateRefused(t, h.endpoint, true, ua.StatusBadUserAccessDenied)
	})
}
