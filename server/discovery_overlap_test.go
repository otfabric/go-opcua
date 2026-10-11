// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// logTrigger is a log handler that calls a function, once, when a record with
// a given text is logged. It lets a test act at a precise point of the code
// under test.
type logTrigger struct {
	text string
	fn   func()
	done atomic.Bool
}

func (h *logTrigger) Enabled(context.Context, slog.Level) bool { return true }
func (h *logTrigger) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *logTrigger) WithGroup(string) slog.Handler            { return h }
func (h *logTrigger) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.text) {
		// Not a sync.Once: fn logs the same text from another goroutine and
		// must not wait for itself.
		if h.done.CompareAndSwap(false, true) {
			h.fn()
		}
	}
	return nil
}

// TestMulticast_OverlappingRegistrationsStayAnnounced pins down two
// registrations of the same server that overlap: the second one arrives while
// the first is being announced with mDNS. The first then found that it was no
// longer the current registration and withdrew "its" announcement, which was
// the announcement of the second: the server stayed registered, but its mDNS
// records were gone, and because a renewal that changes nothing is not
// announced again they never came back. The expiry of a registration that
// races with its renewal had the same effect.
func TestMulticast_OverlappingRegistrationsStayAnnounced(t *testing.T) {
	link := mdns.NewMemNetwork()
	seen := browseLink(t, link)

	rs := regServer("urn:test:press")
	rs.ServerNames = []*ua.LocalizedText{ua.NewLocalizedText("Press")}
	// The address is skipped with a log message before the host name is
	// announced: that is where the second registration comes in.
	rs.DiscoveryURLs = []string{"opc.tcp://192.0.2.7:4841", "opc.tcp://press7:4841"}

	var (
		s      *Server
		second = make(chan ua.StatusCode, 1)
	)
	trigger := &logTrigger{text: "its discovery URL has no host name", fn: func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			status, _ := s.disc.register(nil, rs, nil)
			second <- status
		}()
		// The second registration either overtakes the first here, or it
		// waits for it: then there is nothing to wait for.
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
	}}
	s = multicastServer(t, link, WithMulticastDiscovery(MulticastHostname("lds-host")), SetLogger(slog.New(trigger)))

	status, _ := s.disc.register(nil, rs, nil)
	require.Equal(t, ua.StatusOK, status)
	select {
	case status := <-second:
		require.Equal(t, ua.StatusOK, status)
	case <-time.After(wait):
		t.Fatal("the second registration did not return")
	}

	// The server is registered, has its row and is announced.
	require.Equal(t, []string{"urn:test:press"}, registeredURIs(s))
	require.Equal(t, []string{"Test LDS-lds-host", "Press-press7"}, onNetworkNames(s))
	require.Eventually(t, func() bool { _, ok := seen()["Press-press7"]; return ok }, wait, 5*time.Millisecond)

	// A renewal changes nothing about that.
	status, _ = s.disc.register(nil, rs, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, []string{"Test LDS-lds-host", "Press-press7"}, onNetworkNames(s))
	require.True(t, s.disc.node.Unregister("Press-press7", opcuaServiceType),
		"the mDNS responder does not announce the registered server")
}

// TestMulticast_NoServersOnNetworkAfterStop pins down the ServerOnNetwork
// table of a server that was closed: it kept the table of the moment it
// stopped, although ServersOnNetwork is documented to be empty unless the
// server is running.
func TestMulticast_NoServersOnNetworkAfterStop(t *testing.T) {
	link := mdns.NewMemNetwork()
	s := multicastServer(t, link, WithMulticastDiscovery(MulticastHostname("lds-host")))
	status, _ := s.disc.register(nil, regServer("urn:test:press"), nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, []string{"Test LDS-lds-host", "Press-press7"}, onNetworkNames(s))

	s.disc.stop()
	require.Empty(t, s.ServersOnNetwork())
}
