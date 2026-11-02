// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// A rejected ActivateSession leaves the session as it was (Part 4 §5.6.3):
// a session of alice that tries bob's name with a wrong password is still
// alice's, and is not taken for one of bob's, e.g. by TransferSubscriptions.
func TestSessionService_ActivateSession_RejectedKeepsIdentity(t *testing.T) {
	srv := newTestServer()
	srv.cfg.usernameValidator = func(user, pass string) error {
		if (user == "alice" && pass == "a") || (user == "bob" && pass == "b") {
			return nil
		}
		return ua.StatusBadUserAccessDenied
	}
	svc := &SessionService{srv: srv}
	sc := scNone()
	ctx := context.Background()

	newSession := func() *ua.NodeID {
		resp, err := svc.CreateSession(ctx, sc, &ua.CreateSessionRequest{
			RequestHeader:           reqHeader(),
			EndpointURL:             "opc.tcp://localhost:4840",
			RequestedSessionTimeout: 5000,
			ClientNonce:             []byte("n"),
		}, 1)
		require.NoError(t, err)
		return resp.(*ua.CreateSessionResponse).AuthenticationToken
	}
	activate := func(token *ua.NodeID, user, pass string) error {
		_, err := svc.ActivateSession(ctx, sc, &ua.ActivateSessionRequest{
			RequestHeader:   &ua.RequestHeader{RequestHandle: 2, AuthenticationToken: token},
			ClientSignature: &ua.SignatureData{},
			UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
				UserName: user,
				Password: []byte(pass),
			}),
		}, 2)
		return err
	}

	aliceTok, bobTok := newSession(), newSession()
	require.NoError(t, activate(aliceTok, "alice", "a"))
	require.NoError(t, activate(bobTok, "bob", "b"))
	alice, bob := srv.sb.Session(aliceTok), srv.sb.Session(bobTok)
	roles := alice.handle().Roles()

	require.ErrorIs(t, activate(aliceTok, "bob", "wrong"), ua.StatusBadUserAccessDenied)
	tok, ok := alice.handle().Identity().(*ua.UserNameIdentityToken)
	require.True(t, ok)
	require.Equal(t, "alice", tok.UserName)
	require.Equal(t, roles, alice.handle().Roles())
	require.False(t, sameUser(bob, alice), "bob's subscriptions do not move to alice")

	// An accepted identity is taken.
	require.NoError(t, activate(aliceTok, "bob", "b"))
	require.True(t, sameUser(bob, alice))
}
