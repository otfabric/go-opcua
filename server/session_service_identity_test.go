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
	offerTokens(srv, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, ua.UserTokenTypeUserName)
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

// ActivateSession accepts only the user token types an endpoint of the
// channel offers (Part 4 §5.6.3): a server that offers user names does not
// let in an anonymous client, nor one that sends no token, which counts as
// anonymous.
func TestSessionService_ActivateSession_TokenTypeOffered(t *testing.T) {
	srv := newTestServer()
	srv.cfg.usernameValidator = func(user, pass string) error { return nil }
	// User names over a secured channel only; anonymous over None only.
	offerTokens(srv, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, ua.UserTokenTypeUserName)
	offerTokens(srv, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, ua.UserTokenTypeAnonymous)
	svc := &SessionService{srv: srv}
	sc := scNone()
	ctx := context.Background()

	resp, err := svc.CreateSession(ctx, sc, &ua.CreateSessionRequest{
		RequestHeader:           reqHeader(),
		EndpointURL:             "opc.tcp://localhost:4840",
		RequestedSessionTimeout: 5000,
		ClientNonce:             []byte("n"),
	}, 1)
	require.NoError(t, err)
	token := resp.(*ua.CreateSessionResponse).AuthenticationToken
	activate := func(tok *ua.ExtensionObject) error {
		_, err := svc.ActivateSession(ctx, sc, &ua.ActivateSessionRequest{
			RequestHeader:     &ua.RequestHeader{RequestHandle: 2, AuthenticationToken: token},
			ClientSignature:   &ua.SignatureData{},
			UserIdentityToken: tok,
		}, 2)
		return err
	}

	require.ErrorIs(t, activate(ua.NewExtensionObject(&ua.UserNameIdentityToken{UserName: "alice", Password: []byte("a")})),
		ua.StatusBadIdentityTokenRejected, "no endpoint of the None channel offers user names")
	require.NoError(t, activate(ua.NewExtensionObject(&ua.AnonymousIdentityToken{})))
	require.NoError(t, activate(nil), "no token is an anonymous one")
	require.NoError(t, activate(ua.NewExtensionObject(nil)), "nor is an empty one")
	require.ErrorIs(t, activate(ua.NewExtensionObject(&ua.ReadRequest{})), ua.StatusBadIdentityTokenInvalid)

	_, ok := srv.sb.Session(token).handle().Identity().(*ua.AnonymousIdentityToken)
	require.True(t, ok)

	// The other way round: anonymous is refused where only user names are offered.
	srv.endpoints = nil
	offerTokens(srv, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, ua.UserTokenTypeUserName)
	require.ErrorIs(t, activate(ua.NewExtensionObject(&ua.AnonymousIdentityToken{})), ua.StatusBadIdentityTokenRejected)
	require.ErrorIs(t, activate(nil), ua.StatusBadIdentityTokenRejected)
	require.NoError(t, activate(ua.NewExtensionObject(&ua.UserNameIdentityToken{UserName: "alice", Password: []byte("a")})))
}

// The virtual channels of opc.https are matched with the endpoints of
// opc.https, the real channels with the others.
func TestTokenOffered_Transport(t *testing.T) {
	srv := newTestServer()
	srv.endpoints = []*ua.EndpointDescription{{
		SecurityPolicyURI:   ua.SecurityPolicyURINone,
		SecurityMode:        ua.MessageSecurityModeNone,
		TransportProfileURI: ua.TransportProfileHTTPS,
		UserIdentityTokens:  []*ua.UserTokenPolicy{{TokenType: ua.UserTokenTypeUserName}},
	}}
	require.False(t, srv.tokenOffered(scNone(), ua.UserTokenTypeUserName), "an opc.tcp channel")
	require.False(t, srv.tokenOffered(nil, ua.UserTokenTypeUserName))

	vsc := scNone()
	srv.hs = &httpsServer{vc: &virtualChannels{channels: map[string]*virtualChannel{ua.SecurityPolicyURINone: {sc: vsc}}}}
	require.True(t, srv.isVirtualChannel(vsc))
	require.True(t, srv.tokenOffered(vsc, ua.UserTokenTypeUserName))
	require.False(t, srv.tokenOffered(vsc, ua.UserTokenTypeAnonymous))
	require.False(t, srv.isVirtualChannel(scNone()))
	require.False(t, srv.isVirtualChannel(nil))
}
