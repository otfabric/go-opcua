// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scNone() *uasc.SecureChannel {
	return uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeNone,
		SecurityPolicyURI: ua.SecurityPolicyURINone,
	})
}

func TestSessionService_CreateSession_TimeoutClamping(t *testing.T) {
	srv := newTestServer()
	srv.endpoints = []*ua.EndpointDescription{{
		EndpointURL: "opc.tcp://localhost:4840/",
	}}
	svc := &SessionService{srv: srv}
	sc := scNone()

	cases := []struct {
		name string
		req  float64
		want float64
	}{
		{"below min", 1, float64(sessionTimeoutDefault / time.Millisecond)},
		{"above max", float64(sessionTimeoutMax/time.Millisecond) + 1, float64(sessionTimeoutDefault / time.Millisecond)},
		{"in range", 5000, 5000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &ua.CreateSessionRequest{
				RequestHeader:           reqHeader(),
				EndpointURL:             "opc.tcp://localhost:4840",
				RequestedSessionTimeout: tc.req,
				ClientNonce:             []byte("client-nonce"),
				ClientCertificate:       nil,
			}
			resp, err := svc.CreateSession(context.Background(), sc, req, 1)
			require.NoError(t, err)
			cs := resp.(*ua.CreateSessionResponse)
			assert.Equal(t, tc.want, cs.RevisedSessionTimeout)
			assert.NotEmpty(t, cs.ServerNonce)
			require.Len(t, cs.ServerEndpoints, 1)
		})
	}
}

func TestSessionService_CreateSession_ClientCertRejected(t *testing.T) {
	srv := newTestServer()
	srv.cfg.clientCertificateValidator = func([]byte) error {
		return errors.New("untrusted")
	}
	svc := &SessionService{srv: srv}
	req := &ua.CreateSessionRequest{
		RequestHeader:           reqHeader(),
		EndpointURL:             "opc.tcp://localhost:4840",
		RequestedSessionTimeout: 5000,
		ClientCertificate:       []byte("cert"),
		ClientNonce:             []byte("n"),
	}
	_, err := svc.CreateSession(context.Background(), scNone(), req, 1)
	require.EqualError(t, err, "untrusted")
}

func TestSessionService_ActivateSession_UnknownAndUsername(t *testing.T) {
	srv := newTestServer()
	accepted := false
	srv.cfg.usernameValidator = func(user, pass string) error {
		if user == "alice" && pass == "secret" {
			accepted = true
			return nil
		}
		return ua.StatusBadUserAccessDenied
	}
	svc := &SessionService{srv: srv}
	sc := scNone()

	_, err := svc.ActivateSession(context.Background(), sc, &ua.ActivateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       1,
			AuthenticationToken: ua.NewNumericNodeID(0, 99999),
		},
		ClientSignature: &ua.SignatureData{},
	}, 1)
	require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)

	createResp, err := svc.CreateSession(context.Background(), sc, &ua.CreateSessionRequest{
		RequestHeader:           reqHeader(),
		EndpointURL:             "opc.tcp://localhost:4840",
		RequestedSessionTimeout: 5000,
		ClientNonce:             []byte("n"),
	}, 1)
	require.NoError(t, err)
	cs := createResp.(*ua.CreateSessionResponse)

	_, err = svc.ActivateSession(context.Background(), sc, &ua.ActivateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       2,
			AuthenticationToken: cs.AuthenticationToken,
		},
		ClientSignature: &ua.SignatureData{},
		UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
			UserName: "bob",
			Password: []byte("nope"),
		}),
	}, 2)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	resp, err := svc.ActivateSession(context.Background(), sc, &ua.ActivateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       3,
			AuthenticationToken: cs.AuthenticationToken,
		},
		ClientSignature: &ua.SignatureData{},
		UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
			UserName: "alice",
			Password: []byte("secret"),
		}),
	}, 3)
	require.NoError(t, err)
	assert.True(t, accepted)
	assert.NotEmpty(t, resp.(*ua.ActivateSessionResponse).ServerNonce)
}

func TestSessionService_CloseSession_ReleasesHistoryCP(t *testing.T) {
	srv := newTestServer()
	released := 0
	srv.historyCPs = newHistoryCPRegistry(func([]byte) { released++ })
	svc := &SessionService{srv: srv}
	sc := scNone()

	// sessionBroker.Close is currently tolerant of unknown tokens (returns nil).
	_, err := svc.CloseSession(context.Background(), sc, &ua.CloseSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       1,
			AuthenticationToken: ua.NewNumericNodeID(0, 1),
		},
	}, 1)
	require.NoError(t, err)

	createResp, err := svc.CreateSession(context.Background(), sc, &ua.CreateSessionRequest{
		RequestHeader:           reqHeader(),
		EndpointURL:             "opc.tcp://localhost:4840",
		RequestedSessionTimeout: 5000,
		ClientNonce:             []byte("n"),
	}, 1)
	require.NoError(t, err)
	token := createResp.(*ua.CreateSessionResponse).AuthenticationToken
	outer := srv.historyCPs.bind(token.String(), []byte("inner"))

	_, err = svc.CloseSession(context.Background(), sc, &ua.CloseSessionRequest{
		RequestHeader: &ua.RequestHeader{
			RequestHandle:       2,
			AuthenticationToken: token,
		},
		DeleteSubscriptions: true,
	}, 2)
	require.NoError(t, err)
	assert.Equal(t, 1, released)
	_, st := srv.historyCPs.resolve(token.String(), outer)
	assert.Equal(t, ua.StatusBadContinuationPointInvalid, st)
}

func TestSessionService_validateX509UserToken(t *testing.T) {
	srv := newTestServer()
	svc := &SessionService{srv: srv}
	sc := scNone()
	sess := srv.sb.NewSession()
	sess.serverNonce = []byte("server-nonce")

	err := svc.validateX509UserToken(sc, sess, &ua.ActivateSessionRequest{}, &ua.X509IdentityToken{})
	require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)

	err = svc.validateX509UserToken(sc, sess, &ua.ActivateSessionRequest{}, &ua.X509IdentityToken{
		CertificateData: []byte("not-der"),
	})
	require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)

	key, der := testUserCert(t)
	_ = key
	err = svc.validateX509UserToken(sc, sess, &ua.ActivateSessionRequest{}, &ua.X509IdentityToken{
		CertificateData: der,
	})
	require.ErrorIs(t, err, ua.StatusBadIdentityTokenRejected)

	srv.cfg.x509UserValidator = func([]byte) error { return nil }
	err = svc.validateX509UserToken(sc, sess, &ua.ActivateSessionRequest{}, &ua.X509IdentityToken{
		CertificateData: der,
	})
	require.NoError(t, err)

	srv.cfg.x509UserValidator = func([]byte) error { return errors.New("nope") }
	err = svc.validateX509UserToken(sc, sess, &ua.ActivateSessionRequest{}, &ua.X509IdentityToken{
		CertificateData: der,
	})
	require.ErrorIs(t, err, ua.StatusBadIdentityTokenRejected)
}

func TestSessionService_validateX509UserToken_Signature(t *testing.T) {
	srv := newTestServer()
	svc := &SessionService{srv: srv}
	serverKey, serverCert := testUserCert(t)
	srv.cfg.certificate = serverCert
	srv.cfg.x509UserValidator = func([]byte) error { return nil }

	userKey, userCert := testUserCert(t)
	nonce := []byte("server-nonce-0123456789abcdef")
	sess := srv.sb.NewSession()
	sess.serverNonce = nonce

	policy := ua.SecurityPolicyURIBasic256Sha256
	srv.endpoints = []*ua.EndpointDescription{{
		EndpointURL: "opc.tcp://localhost:4840",
		UserIdentityTokens: []*ua.UserTokenPolicy{{
			PolicyID:          "x509",
			TokenType:         ua.UserTokenTypeCertificate,
			SecurityPolicyURI: policy,
		}},
	}}

	sc := uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: policy,
		LocalKey:          serverKey,
		Certificate:       serverCert,
	})

	enc, err := uapolicy.Asymmetric(policy, userKey, &serverKey.PublicKey)
	require.NoError(t, err)
	sig, err := enc.Signature(append(serverCert, nonce...))
	require.NoError(t, err)

	tok := &ua.X509IdentityToken{
		PolicyID:        "x509",
		CertificateData: userCert,
	}
	req := &ua.ActivateSessionRequest{
		UserTokenSignature: &ua.SignatureData{Signature: sig, Algorithm: enc.SignatureURI()},
	}

	require.NoError(t, svc.validateX509UserToken(sc, sess, req, tok))

	// Tampered signature must fail.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	req.UserTokenSignature.Signature = bad
	err = svc.validateX509UserToken(sc, sess, req, tok)
	require.ErrorIs(t, err, ua.StatusBadUserSignatureInvalid)

	// Fall back to channel policy when PolicyID is empty.
	tok.PolicyID = ""
	req.UserTokenSignature.Signature = sig
	require.NoError(t, svc.validateX509UserToken(sc, sess, req, tok))

	// Unknown PolicyID keeps the channel policy (still valid).
	tok.PolicyID = "missing"
	require.NoError(t, svc.validateX509UserToken(sc, sess, req, tok))

	// Unsupported token policy URI fails asymmetric setup.
	srv.endpoints[0].UserIdentityTokens[0].PolicyID = "bad-policy"
	srv.endpoints[0].UserIdentityTokens[0].SecurityPolicyURI = "http://example/unsupported"
	tok.PolicyID = "bad-policy"
	err = svc.validateX509UserToken(sc, sess, req, tok)
	require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)

	// SecurityPolicy#None skips signature verification.
	scNonePol := uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeNone,
		SecurityPolicyURI: ua.SecurityPolicyURINone,
	})
	tok.PolicyID = ""
	req.UserTokenSignature.Signature = []byte("ignored")
	require.NoError(t, svc.validateX509UserToken(scNonePol, sess, req, tok))

	// Non-RSA user cert fails public-key extraction during signature verify.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ec-user"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ecDER, err := x509.CreateCertificate(rand.Reader, ecTmpl, ecTmpl, &ecKey.PublicKey, ecKey)
	require.NoError(t, err)
	tok.CertificateData = ecDER
	tok.PolicyID = "x509"
	srv.endpoints[0].UserIdentityTokens[0].PolicyID = "x509"
	srv.endpoints[0].UserIdentityTokens[0].SecurityPolicyURI = policy
	req.UserTokenSignature.Signature = sig
	err = svc.validateX509UserToken(sc, sess, req, tok)
	require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)
}

func testUserCert(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "user"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}
