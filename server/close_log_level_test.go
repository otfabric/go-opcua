// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// recordHandler keeps the level and message of every record logged.
type recordHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.recs = append(h.recs, r.Clone())
	h.mu.Unlock()
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordHandler) records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]slog.Record(nil), h.recs...)
}

func (h *recordHandler) has(level slog.Level, msg string) bool {
	for _, r := range h.records() {
		if r.Level == level && r.Message == msg {
			return true
		}
	}
	return false
}

// TestServer_NormalCloseNotWarned closes a client the normal way
// (CloseSession, CloseSecureChannel, then the connection) and then the
// server: neither is logged at Warn or above.
func TestServer_NormalCloseNotWarned(t *testing.T) {
	t.Parallel()
	h := &recordHandler{}
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.SetLogger(slog.New(h)),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := testutil.NewTestClient(t, srv.Endpoints()[0].EndpointURL)
	require.NoError(t, c.Close(ctx))
	require.Eventually(t, func() bool { return h.has(slog.LevelInfo, "secure channel closed") },
		5*time.Second, 10*time.Millisecond, "the close of the channel is logged at Info")
	require.NoError(t, srv.Close())

	for _, r := range h.records() {
		require.Less(t, r.Level, slog.LevelWarn, "%s %s", r.Level, r.Message)
	}
}
