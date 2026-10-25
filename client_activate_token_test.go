// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestActivateSession_DoesNotChangeTheConfiguredToken activates sessions of
// one client with a username identity, also concurrently, the way the
// application (DetachSession / ActivateSession) and the client's own
// reconnect do.
//
// Regression (the race needs -race): ActivateSession wrote the protected
// password into the configured identity token, which all sessions of a
// client share. Two activations at once raced on it, and one could send the
// password as it was protected for the other session.
func TestActivateSession_DoesNotChangeTheConfiguredToken(t *testing.T) {
	t.Parallel()
	_, url := testutil.NewTestServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == "alice" && pass == "wonderland" {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)
	var ep *ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityMode == ua.MessageSecurityModeNone {
			ep = e
		}
	}
	require.NotNil(t, ep)

	connect := func() *opcua.Client {
		c, err := opcua.NewClient(url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
			opcua.AuthUsername("alice", "wonderland"),
			opcua.AutoReconnect(false),
			opcua.DialTimeout(30*time.Second),
			opcua.RequestTimeout(30*time.Second),
		)
		require.NoError(t, err)
		require.NoError(t, c.Connect(ctx))
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}

	c := connect()
	tok, ok := c.TestingConfiguredUserToken().(*ua.UserNameIdentityToken)
	require.True(t, ok)
	require.Equal(t, "alice", tok.UserName)
	require.Empty(t, tok.Password, "the configured token does not carry what was sent for one session")
	require.Empty(t, tok.EncryptionAlgorithm)

	// Several sessions of the client, activated at once.
	var sessions []*opcua.Session
	for i := 0; i < 4; i++ {
		s, err := c.CreateSession(ctx, c.TestingSessionConfig())
		require.NoError(t, err)
		sessions = append(sessions, s)
	}
	var wg sync.WaitGroup
	errs := make([]error, len(sessions))
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = c.ActivateSession(ctx, sessions[i])
		}()
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "activation %d", i)
	}
	require.Empty(t, tok.Password)
}
