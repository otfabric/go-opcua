// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestECC_Username covers username/password identity over the ECC policies.
// There is no asymmetric encryption: the password travels in an
// EccEncryptedSecret made with the ephemeral key the server handed out in
// CreateSession, and the server has to verify and decrypt it.
func TestECC_Username(t *testing.T) {
	f, url := mixedServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(userValidator),
	)
	ctx := context.Background()

	for _, pol := range eccPolicies {
		for _, mode := range secureModes {
			t.Run(shortPolicy(pol.uri)+"/"+mode.String(), func(t *testing.T) {
				ep := endpointFor(t, url, pol.uri, mode)

				c := newClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeUserName),
					opcua.AuthUsername("alice", "wonderland"))...)
				dv, err := c.ReadValue(ctx, f.Int32)
				require.NoError(t, err)
				require.Equal(t, int32(42), dv.Value.Value())

				_, err = dialClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeUserName),
					opcua.AuthUsername("alice", "wrong"))...)
				require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
			})
		}
	}
}

// TestECC_UsernameReactivation activates the same session repeatedly, as a
// client does when it moves the session to a new SecureChannel. An ephemeral
// key is good for one activation; each response has to bring the next key.
func TestECC_UsernameReactivation(t *testing.T) {
	var mu sync.Mutex
	var passwords []string
	f, url := mixedServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			mu.Lock()
			passwords = append(passwords, pass)
			mu.Unlock()
			return userValidator(user, pass)
		}),
	)
	ctx := context.Background()
	ep := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt)

	c := newClient(t, url, append(eccClientOpts(t, ep, curveP256, ua.UserTokenTypeUserName),
		opcua.AuthUsername("alice", "wonderland"))...)

	for i := 0; i < 3; i++ {
		require.NoError(t, c.ActivateSession(ctx, c.Session()), "activation %d", i+2)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"wonderland", "wonderland", "wonderland", "wonderland"}, passwords,
		"the server decrypted the password of every activation")
}

// TestECC_IssuedToken verifies that the data of an issued token is protected
// like a password on an ECC channel and reaches the role mapper as issued.
func TestECC_IssuedToken(t *testing.T) {
	var mu sync.Mutex
	var tokens []ua.IdentityToken
	_, url := mixedServer(t,
		server.EnableAuthMode(ua.UserTokenTypeIssuedToken),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			mu.Lock()
			tokens = append(tokens, tok)
			mu.Unlock()
			return server.DefaultRoleMapper(tok)
		}),
	)

	for _, pol := range eccPolicies {
		t.Run(shortPolicy(pol.uri), func(t *testing.T) {
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			jwt := []byte("opaque-jwt-" + shortPolicy(pol.uri))
			c := newClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeIssuedToken),
				opcua.AuthIssuedToken(jwt))...)

			mu.Lock()
			require.NotEmpty(t, tokens)
			tok, ok := tokens[len(tokens)-1].(*ua.IssuedIdentityToken)
			mu.Unlock()
			require.True(t, ok)
			require.Equal(t, jwt, tok.TokenData, "the role mapper sees the token the issuer created")
			require.Equal(t, strings.ToLower("issuedtoken_"+shortPolicy(pol.uri)), tok.PolicyID)

			// The token is encrypted anew for every activation; the
			// configured token data is not overwritten by the first one.
			require.NoError(t, c.ActivateSession(context.Background(), c.Session()))
			mu.Lock()
			tok, ok = tokens[len(tokens)-1].(*ua.IssuedIdentityToken)
			mu.Unlock()
			require.True(t, ok)
			require.Equal(t, jwt, tok.TokenData)
		})
	}
}

// TestECC_X509UserToken covers X.509 user identity tokens with an ECC user
// certificate: the user token signature is an ECDSA signature.
func TestECC_X509UserToken(t *testing.T) {
	p := pki(t)
	ecc := p.ecc
	ctx := context.Background()

	// A user certificate per curve: ECC_nistP384 permits P-384 keys only.
	users := map[string]*eccIdentity{curveP256: ecc.user, curveP384: ecc.client[curveP384]}

	var mu sync.Mutex
	var seen [][]byte
	f, url := mixedServer(t,
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.WithX509UserValidator(func(der []byte) error {
			mu.Lock()
			seen = append(seen, der)
			mu.Unlock()
			for _, user := range users {
				if string(der) == string(user.cert) {
					return nil
				}
			}
			return ua.StatusBadIdentityTokenRejected
		}),
	)

	for _, pol := range eccPolicies {
		t.Run("Accepted/"+shortPolicy(pol.uri), func(t *testing.T) {
			user := users[pol.curve]
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			c := newClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeCertificate),
				opcua.AuthCertificate(user.cert),
				opcua.AuthPrivateKeySigner(user.key),
			)...)
			dv, err := c.ReadValue(ctx, f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())
		})
	}

	mu.Lock()
	require.Len(t, seen, len(eccPolicies), "validator must have been consulted once per session")
	mu.Unlock()

	ep := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt)
	base := func() []opcua.Option { return eccClientOpts(t, ep, curveP256, ua.UserTokenTypeCertificate) }

	t.Run("RejectedByValidator", func(t *testing.T) {
		_, err := dialClient(t, url, append(base(),
			opcua.AuthCertificate(ecc.stranger.cert),
			opcua.AuthPrivateKeySigner(ecc.stranger.key),
		)...)
		require.ErrorIs(t, err, ua.StatusBadIdentityTokenRejected)
	})

	t.Run("WrongPrivateKey", func(t *testing.T) {
		// A trusted certificate presented without its private key: the user
		// token signature cannot verify.
		_, err := dialClient(t, url, append(base(),
			opcua.AuthCertificate(ecc.user.cert),
			opcua.AuthPrivateKeySigner(ecc.stranger.key),
		)...)
		require.ErrorIs(t, err, ua.StatusBadUserSignatureInvalid)
	})

	t.Run("RejectedCurve", func(t *testing.T) {
		// ECC_nistP384 permits P-384 keys only; the server refuses a P-256
		// user certificate there even though its signature is well formed.
		ep384 := endpointFor(t, url, ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSignAndEncrypt)
		_, err := dialClient(t, url, append(eccClientOpts(t, ep384, curveP384, ua.UserTokenTypeCertificate),
			opcua.AuthCertificate(ecc.user.cert),
			opcua.AuthPrivateKeySigner(ecc.user.key),
		)...)
		require.Error(t, err)
	})

	t.Run("RSAUserCertificateOnECCChannel", func(t *testing.T) {
		// An RSA key cannot produce the ECDSA signature the policy asks for.
		_, err := dialClient(t, url, append(base(),
			opcua.AuthCertificate(p.userCert),
			opcua.AuthPrivateKey(p.userKey),
		)...)
		require.Error(t, err)
	})
}
