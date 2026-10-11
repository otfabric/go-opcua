// SPDX-License-Identifier: MIT

package server

import (
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// The AuthenticationToken is the only thing that ties a request to a session,
// so it must not be guessable: an opaque NodeId carrying 256 random bits.
func TestNewSession_AuthenticationTokenIsUnguessable(t *testing.T) {
	sb := newSessionBroker(slog.New(slog.DiscardHandler))

	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		s := sb.NewSession()
		tok := s.AuthTokenID
		require.Equal(t, ua.NodeIDTypeByteString, tok.Type(), "token must be opaque, not a small number")
		raw, err := base64.StdEncoding.DecodeString(tok.StringID())
		require.NoError(t, err)
		require.Len(t, raw, 32)
		require.False(t, seen[tok.String()], "token issued twice")
		seen[tok.String()] = true
		require.Same(t, s, sb.Session(tok), "the token must find its session")
	}
}
