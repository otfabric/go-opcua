//go:build interop

// SPDX-License-Identifier: MIT

// Historical events (Part 11 §6.5.2, §6.9.4, §6.9.7; CLIENT_CONTRACT §17)
// with UA-.NETStandard 2.0.1: the dotnet client against the go-opcua fixture
// s=History.Events, the go-opcua client against the dotnet fixture (read and
// update, §17.2).
// The assertions are in history_events_test.go.
// COVERAGE.md: history / history.read.events, history.read.events.continuation,
// history.read.events.filter, history.update.events, history.delete.events

package interop

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
)

func TestGoServer_DotnetClient_HistoryReadEvents(t *testing.T) {
	t.Run("coverage/history.read.events/dotnet-client-to-go-server", func(t *testing.T) {
		assertPeerReadsGoEvents(t, dotnetEventClient)
	})
}

func TestGoServer_DotnetClient_HistoryReadEventsContinuation(t *testing.T) {
	t.Run("coverage/history.read.events.continuation/dotnet-client-to-go-server", func(t *testing.T) {
		assertPeerContinuesGoEvents(t, dotnetEventClient)
	})
}

func TestGoServer_DotnetClient_HistoryReadEventsFilter(t *testing.T) {
	t.Run("coverage/history.read.events.filter/dotnet-client-to-go-server", func(t *testing.T) {
		assertPeerFiltersGoEvents(t, dotnetEventClient)
	})
}

func TestGoServer_DotnetClient_HistoryUpdateEvents(t *testing.T) {
	t.Run("coverage/history.update.events/dotnet-client-to-go-server", func(t *testing.T) {
		assertPeerUpdatesGoEvents(t, dotnetEventClient)
	})
}

func TestGoServer_DotnetClient_HistoryDeleteEvents(t *testing.T) {
	t.Run("coverage/history.delete.events/dotnet-client-to-go-server", func(t *testing.T) {
		assertPeerDeletesGoEvents(t, dotnetEventClient)
	})
}

// startDotnetEventServer starts the dotnet server, gated on its fixture
// s=History.Events (history-events) and, with update, its writable history
// and s=History.ResetEvents (history-events-update).
func startDotnetEventServer(t *testing.T, update bool) *serverHandle {
	t.Helper()
	requireServerFeature(t, dotnetEnv, defaultDotnetImage, "history-events")
	if update {
		requireServerFeature(t, dotnetEnv, defaultDotnetImage, "history-events-update")
	}
	return startDotnetServer(t)
}

func TestDotnetServer_HistoryReadEvents(t *testing.T) {
	t.Run("coverage/history.read.events/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetEventServer(t, false)
		assertGoReadsPeerEvents(t, h.endpoint, ua.StatusGoodNoData)
	})
}

func TestDotnetServer_HistoryReadEventsContinuation(t *testing.T) {
	t.Run("coverage/history.read.events.continuation/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetEventServer(t, false)
		assertGoContinuesPeerEvents(t, h.endpoint, true)
	})
}

func TestDotnetServer_HistoryReadEventsFilter(t *testing.T) {
	t.Run("coverage/history.read.events.filter/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetEventServer(t, false)
		assertGoFiltersPeerEvents(t, h.endpoint, true)
	})
}

func TestDotnetServer_HistoryUpdateEvents(t *testing.T) {
	t.Run("coverage/history.update.events/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetEventServer(t, true)
		assertGoUpdatesPeerEvents(t, h.endpoint)
	})
}

func TestDotnetServer_HistoryDeleteEvents(t *testing.T) {
	t.Run("coverage/history.delete.events/go-client-to-dotnet-server", func(t *testing.T) {
		h := startDotnetEventServer(t, true)
		assertGoDeletesPeerEvents(t, h.endpoint, ua.StatusBadNoEntryExists)
	})
}
