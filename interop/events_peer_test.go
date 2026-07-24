//go:build interop

// SPDX-License-Identifier: MIT

// Peer event subscription tests (O→S / M→S).
// COVERAGE.md: events / event.subscription

package interop

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func emitPeerEvent(t *testing.T, srv *server.Server, source *ua.NodeID) {
	t.Helper()
	evt := &server.BaseEvent{
		EventID:    []byte("peer-event"),
		EventType:  ua.NewNumericNodeID(0, id.BaseEventType),
		SourceNode: source,
		SourceName: "Events.Source",
		Time:       time.Now().UTC(),
		Message:    ua.NewLocalizedText("peer-event"),
		Severity:   500,
	}
	if err := srv.EmitBaseEvent(source, evt); err != nil {
		t.Logf("EmitBaseEvent: %v", err)
	}
}

func TestGoServer_Open62541Client_EventSubscribe(t *testing.T) {
	t.Run("coverage/event.subscription/open62541-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "OPEN62541_IMAGE", defaultOpen62541Image, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		_, nsIdx := findNSFromServer(t, srv)
		source := ua.NewStringNodeID(nsIdx, "Events.Source")
		node := "nsu=" + interopNamespaceURI + ";s=Events.Source"
		go func() {
			time.Sleep(1500 * time.Millisecond)
			emitPeerEvent(t, srv, source)
		}()
		result := runOpen62541ClientResult(t, endpoint, "event-subscribe",
			"--node", node,
			"--events", "1",
			"--timeout-ms", "8000",
		)
		if !result.Success {
			t.Fatalf("event-subscribe failed: %+v", result)
		}
	})
}

func TestGoServer_MiloClient_EventSubscribe(t *testing.T) {
	t.Run("coverage/event.subscription/milo-to-go-server", func(t *testing.T) {
		requireAdapterOp(t, "MILO_IMAGE", defaultMiloImage, "event-subscribe")
		endpoint, srv := startGoServerWithEvents(t)
		_, nsIdx := findNSFromServer(t, srv)
		source := ua.NewStringNodeID(nsIdx, "Events.Source")
		node := "nsu=" + interopNamespaceURI + ";s=Events.Source"
		go func() {
			time.Sleep(1500 * time.Millisecond)
			emitPeerEvent(t, srv, source)
		}()
		result := runMiloClientResult(t, endpoint, "event-subscribe",
			"--node", node,
			"--events", "1",
			"--timeout-ms", "8000",
		)
		if !result.Success {
			t.Fatalf("event-subscribe failed: %+v", result)
		}
	})
}
