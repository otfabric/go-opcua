// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// TestSessionBoundToSecureChannel checks that a session is served only on
// the SecureChannel it is associated with and that ActivateSession moves it
// to a new channel (Part 4 §5.7.3).
func TestSessionBoundToSecureChannel(t *testing.T) {
	srv := newTestServer()
	srv.cfg.usernameValidator = func(user, pass string) error {
		if pass == "secret" {
			return nil
		}
		return ua.StatusBadUserAccessDenied
	}
	offerTokens(srv, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, ua.UserTokenTypeUserName)
	svc := &SessionService{srv: srv}
	ctx := context.Background()

	scA := scNone()
	create, err := svc.CreateSession(ctx, scA, &ua.CreateSessionRequest{
		RequestHeader:           reqHeader(),
		EndpointURL:             "opc.tcp://localhost:4840",
		RequestedSessionTimeout: 5000,
		ClientNonce:             []byte("n"),
	}, 1)
	require.NoError(t, err)
	token := create.(*ua.CreateSessionResponse).AuthenticationToken

	activate := func(sc *uasc.SecureChannel, user string) error {
		_, err := svc.ActivateSession(ctx, sc, &ua.ActivateSessionRequest{
			RequestHeader:   &ua.RequestHeader{AuthenticationToken: token},
			ClientSignature: &ua.SignatureData{},
			UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
				UserName: user,
				Password: []byte("secret"),
			}),
		}, 2)
		return err
	}
	read := func(sc *uasc.SecureChannel) ua.StatusCode {
		_, st := srv.checkSession(sc, &ua.ReadRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: token}})
		return st
	}

	// The first ActivateSession has to come over the channel of CreateSession.
	require.ErrorIs(t, activate(scNone(), "alice"), ua.StatusBadSecureChannelIDInvalid)
	require.NoError(t, activate(scA, "alice"))

	// Another channel cannot use the session.
	scB := scNone()
	require.Equal(t, ua.StatusOK, read(scA))
	require.Equal(t, ua.StatusBadSecureChannelIDInvalid, read(scB))
	_, err = svc.CloseSession(ctx, scB, &ua.CloseSessionRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: token}}, 3)
	require.ErrorIs(t, err, ua.StatusBadSecureChannelIDInvalid)

	// A channel with other security cannot take the session over.
	scSigned := uasc.NewCryptoChannel(&uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		SecurityMode:      ua.MessageSecurityModeSign,
	})
	require.ErrorIs(t, activate(scSigned, "alice"), ua.StatusBadSecureChannelIDInvalid)

	// Nor can another user.
	require.ErrorIs(t, activate(scB, "mallory"), ua.StatusBadIdentityChangeNotSupported)
	require.Equal(t, ua.StatusOK, read(scA))

	// The same user moves the session to the new channel; the old one is
	// rejected from then on.
	require.NoError(t, activate(scB, "alice"))
	require.Equal(t, ua.StatusOK, read(scB))
	require.Equal(t, ua.StatusBadSecureChannelIDInvalid, read(scA))

	// The user may change on the channel of the session.
	require.NoError(t, activate(scB, "bob"))

	_, err = svc.CloseSession(ctx, scB, &ua.CloseSessionRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: token}}, 4)
	require.NoError(t, err)
}
