// SPDX-License-Identifier: MIT

package eccext

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// The ECC policies whose certificates crypto/x509 cannot handle:
// ECC_brainpoolP256r1, ECC_brainpoolP384r1 (ECDSA on the Brainpool curves)
// and ECC_curve448 (Ed448). They get a server of their own, with an RSA
// certificate for the RSA endpoints and one certificate per curve.

// extPolicies lists them with the curve of the certificates the tests use.
var extPolicies = []struct {
	uri   string
	curve string
}{
	{ua.SecurityPolicyURIECCBrainpoolP256r1, curveBrainpoolP256r1},
	{ua.SecurityPolicyURIECCBrainpoolP384r1, curveBrainpoolP384r1},
	{ua.SecurityPolicyURIECCCurve448, curveEd448},
}

// extServerOpts returns the options of a server with every RSA endpoint and
// the endpoints of extPolicies in both modes.
func extServerOpts(t *testing.T, extra ...server.Option) []server.Option {
	t.Helper()
	ecc := pki(t).ecc
	opts := secureServerOpts(t)
	for _, pol := range extPolicies {
		id := ecc.server[pol.curve]
		opts = append(opts, server.ApplicationIdentity(id.cert, id.key))
		for _, mode := range secureModes {
			opts = append(opts, server.EnableSecurity(pol.uri, mode))
		}
	}
	return append(opts, extra...)
}

func extServer(t *testing.T, extra ...server.Option) (*testutil.Fixture, string) {
	t.Helper()
	srv, url := newServer(t, extServerOpts(t, extra...)...)
	return testutil.AddFixture(t, srv), url
}

// extClientOpts returns the client options for a validated connection to ep
// with the client certificate on curve.
func extClientOpts(t *testing.T, ep *ua.EndpointDescription, curve string, auth ua.UserTokenType) []opcua.Option {
	t.Helper()
	ecc := pki(t).ecc
	return []opcua.Option{
		opcua.SecurityFromEndpoint(ep, auth),
		opcua.Certificate(ecc.client[curve].cert),
		opcua.PrivateKeySigner(ecc.client[curve].key),
		opcua.TrustedCertificates(ecc.server[curveBrainpoolP256r1].x509, ecc.server[curveBrainpoolP384r1].x509, ecc.server[curveEd448].x509),
	}
}

var extMatrixValue atomic.Int32

// TestECCExt_PolicyModeMatrix connects with each policy in both modes and
// runs reads, writes, a multi-chunk read, a method call, a subscription and
// a SecureChannel renewal over the channel.
func TestECCExt_PolicyModeMatrix(t *testing.T) {
	f, url := extServer(t)
	ctx := context.Background()
	ecc := pki(t).ecc

	for _, pol := range extPolicies {
		for _, mode := range secureModes {
			t.Run(shortPolicy(pol.uri)+"/"+mode.String(), func(t *testing.T) {
				ep := endpointFor(t, url, pol.uri, mode)
				require.Equal(t, ecc.server[pol.curve].cert, ep.ServerCertificate, "the endpoint advertises the certificate of its curve")
				require.Equal(t, uapolicy.SecurityLevel(pol.uri, mode), ep.SecurityLevel)

				c := newClient(t, url, extClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous)...)
				require.Equal(t, pol.uri, c.SecurityPolicy())
				require.Equal(t, mode, c.SecurityMode())

				want := "ext-" + shortPolicy(pol.uri) + "-" + mode.String()
				st, err := c.WriteNodeValue(ctx, f.String, want)
				require.NoError(t, err)
				require.Equal(t, ua.StatusOK, st)
				dv, err := c.ReadValue(ctx, f.String)
				require.NoError(t, err)
				require.Equal(t, want, dv.Value.Value())

				// Several secured chunks in both directions.
				ids := make([]*ua.NodeID, 600)
				for i := range ids {
					ids[i] = f.Int32Array
				}
				dvs, err := c.ReadValues(ctx, ids...)
				require.NoError(t, err)
				require.Len(t, dvs, len(ids))
				for _, dv := range dvs {
					require.Equal(t, []int32{1, 2, 3, 4, 5}, dv.Value.Value())
				}

				res, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(9))
				require.NoError(t, err)
				require.Equal(t, ua.StatusOK, res.StatusCode)
				require.Equal(t, int32(81), res.OutputArguments[0].Value())

				sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Writable).Start(ctx)
				require.NoError(t, err)
				t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
				nextDataChanges(t, ch)

				// A renewal negotiates new ephemeral keys; the channel and
				// the subscription carry on.
				for range 2 {
					require.NoError(t, c.SecureChannel().Renew(ctx))
				}
				changed := 7000 + extMatrixValue.Add(1)
				writeInt32(t, c, f.Writable, changed)
				awaitInt32Change(t, ch, changed)
				dv, err = c.ReadValue(ctx, f.String)
				require.NoError(t, err)
				require.Equal(t, want, dv.Value.Value())
			})
		}
	}
}

// TestECCExt_Endpoints checks what the server advertises and that the client
// picks the endpoint by its certificate.
func TestECCExt_Endpoints(t *testing.T) {
	_, url := extServer(t)
	eps, err := opcua.GetEndpoints(context.Background(), url)
	require.NoError(t, err)
	require.Len(t, eps, 1+2*(len(securePolicies)+len(extPolicies)))

	ecc := pki(t).ecc
	for _, pol := range extPolicies {
		ep, err := opcua.SelectEndpoint(eps, pol.uri, ua.MessageSecurityModeSignAndEncrypt, ecc.client[pol.curve].cert)
		require.NoError(t, err, pol.uri)
		require.Equal(t, pol.uri, ep.SecurityPolicyURI)
		for _, tok := range ep.UserIdentityTokens {
			if tok.TokenType == ua.UserTokenTypeUserName {
				require.Contains(t, []string{"", pol.uri}, tok.SecurityPolicyURI)
			}
		}
	}
}

// TestECCExt_UserTokens covers the user identity tokens over each policy:
// passwords and issued tokens in an EccEncryptedSecret, X.509 user
// certificates with keys of the policy's curve.
func TestECCExt_UserTokens(t *testing.T) {
	p := pki(t)
	ecc := p.ecc
	ctx := context.Background()

	var mu sync.Mutex
	var tokens []ua.IdentityToken
	var passwords []string
	f, url := extServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.EnableAuthMode(ua.UserTokenTypeIssuedToken),
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.WithUsernameValidator(func(user, pass string) error {
			mu.Lock()
			passwords = append(passwords, pass)
			mu.Unlock()
			return userValidator(user, pass)
		}),
		server.WithIssuedTokenValidator(func(tok *ua.IssuedIdentityToken) error {
			if bytes.HasPrefix(tok.TokenData, []byte("opaque-jwt")) {
				return nil
			}
			return ua.StatusBadIdentityTokenRejected
		}),
		server.WithX509UserValidator(func(der []byte) error {
			for _, pol := range extPolicies {
				if bytes.Equal(der, ecc.users[pol.curve].cert) {
					return nil
				}
			}
			return ua.StatusBadIdentityTokenRejected
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			mu.Lock()
			tokens = append(tokens, tok)
			mu.Unlock()
			return server.DefaultRoleMapper(tok)
		}),
	)
	lastToken := func() ua.IdentityToken {
		mu.Lock()
		defer mu.Unlock()
		require.NotEmpty(t, tokens)
		return tokens[len(tokens)-1]
	}
	read := func(t *testing.T, c *opcua.Client) {
		t.Helper()
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	}

	for _, pol := range extPolicies {
		t.Run(shortPolicy(pol.uri), func(t *testing.T) {
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			opts := func(auth ua.UserTokenType, extra ...opcua.Option) []opcua.Option {
				return append(extClientOpts(t, ep, pol.curve, auth), extra...)
			}

			t.Run("Username", func(t *testing.T) {
				for _, mode := range secureModes {
					mep := endpointFor(t, url, pol.uri, mode)
					mu.Lock()
					passwords = nil
					mu.Unlock()
					c := newClient(t, url, append(extClientOpts(t, mep, pol.curve, ua.UserTokenTypeUserName),
						opcua.AuthUsername("alice", "wonderland"))...)
					read(t, c)
					// Every activation needs the next ephemeral key of the
					// server and seals the password anew.
					for range 2 {
						require.NoError(t, c.ActivateSession(ctx, c.Session()), mode)
						read(t, c)
					}
					mu.Lock()
					require.Equal(t, []string{"wonderland", "wonderland", "wonderland"}, passwords, "the server decrypted every activation")
					mu.Unlock()
				}
				_, err := dialClient(t, url, opts(ua.UserTokenTypeUserName, opcua.AuthUsername("alice", "wrong"))...)
				require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
			})

			t.Run("IssuedToken", func(t *testing.T) {
				jwt := []byte("opaque-jwt-" + shortPolicy(pol.uri))
				c := newClient(t, url, opts(ua.UserTokenTypeIssuedToken, opcua.AuthIssuedToken(jwt))...)
				read(t, c)
				tok, ok := lastToken().(*ua.IssuedIdentityToken)
				require.True(t, ok)
				require.Equal(t, jwt, tok.TokenData)
				require.Equal(t, strings.ToLower("issuedtoken_"+shortPolicy(pol.uri)), tok.PolicyID)
			})

			t.Run("X509", func(t *testing.T) {
				user := ecc.users[pol.curve]
				c := newClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(user.cert), opcua.AuthPrivateKeySigner(user.key))...)
				read(t, c)
				tok, ok := lastToken().(*ua.X509IdentityToken)
				require.True(t, ok)
				require.Equal(t, user.cert, tok.CertificateData)
				require.NoError(t, c.ActivateSession(ctx, c.Session()))
				read(t, c)

				// The certificate without its private key.
				_, err := dialClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(user.cert), opcua.AuthPrivateKeySigner(ecc.client[pol.curve].key))...)
				require.ErrorIs(t, err, ua.StatusBadUserSignatureInvalid)

				// A user certificate of another key type: the client cannot
				// even make the signature.
				for _, other := range extPolicies {
					if other.curve == pol.curve || (pol.curve == curveBrainpoolP256r1 && other.curve == curveBrainpoolP384r1) {
						continue // a P384r1 key also serves ECC_brainpoolP256r1
					}
					wrong := ecc.users[other.curve]
					_, err = dialClient(t, url, opts(ua.UserTokenTypeCertificate,
						opcua.AuthCertificate(wrong.cert), opcua.AuthPrivateKeySigner(wrong.key))...)
					require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, other.curve)
				}
				_, err = dialClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(p.userCert), opcua.AuthPrivateKey(p.userKey))...)
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

				// Not trusted by the server.
				stranger := ecc.client[pol.curve]
				_, err = dialClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(stranger.cert), opcua.AuthPrivateKeySigner(stranger.key))...)
				require.ErrorIs(t, err, ua.StatusBadIdentityTokenRejected)
			})
		})
	}
}

// TestECCExt_CertificateTrust covers the trust decisions on both sides for
// Brainpool and Ed448 certificates.
func TestECCExt_CertificateTrust(t *testing.T) {
	ecc := pki(t).ecc
	ctx := context.Background()

	t.Run("UntrustedServerCertificate", func(t *testing.T) {
		_, url := extServer(t)
		for _, pol := range extPolicies {
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			_, err := dialClient(t, url,
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(ecc.client[pol.curve].cert),
				opcua.PrivateKeySigner(ecc.client[pol.curve].key),
				opcua.TrustedCertificates(ecc.client[pol.curve].x509),
			)
			require.ErrorContains(t, err, "server certificate validation failed", pol.uri)
		}
	})

	t.Run("ClientTrustList", func(t *testing.T) {
		var anchors [][]byte
		for _, pol := range extPolicies {
			anchors = append(anchors, ecc.cas[pol.curve].cert)
		}
		f, url := extServer(t, server.WithClientCertificateTrustList(anchors...))
		for _, pol := range extPolicies {
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			issued := ecc.issuedByCA[pol.curve]
			c := newClient(t, url,
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(issued.cert),
				opcua.PrivateKeySigner(issued.key),
				opcua.TrustedCertificates(ecc.server[pol.curve].x509),
			)
			dv, err := c.ReadValue(ctx, f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())

			// A self-signed certificate is not issued by a trusted CA.
			_, err = dialClient(t, url, extClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous)...)
			require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted, pol.uri)
		}
	})

	t.Run("ServerChainIssuedByTrustedCA", func(t *testing.T) {
		// A server whose certificate is issued by a CA the client trusts.
		for _, pol := range extPolicies {
			issued := ecc.issuedByCA[pol.curve] // carries the client URI: also the server's here
			srv, url := newServer(t,
				server.ApplicationIdentity(issued.cert, issued.key),
				server.EnableSecurity(pol.uri, ua.MessageSecurityModeSign),
			)
			f := testutil.AddFixture(t, srv)
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSign)
			c := newClient(t, url,
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(ecc.client[pol.curve].cert),
				opcua.PrivateKeySigner(ecc.client[pol.curve].key),
				opcua.TrustedCertificates(ecc.cas[pol.curve].x509),
			)
			dv, err := c.ReadValue(ctx, f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())
		}
	})
}

// TestECCExt_WrongCertificateKey: an application instance certificate whose
// key does not fit the selected policy is refused before anything is sent.
func TestECCExt_WrongCertificateKey(t *testing.T) {
	_, url := extServer(t)
	ecc := pki(t).ecc
	for _, pol := range extPolicies {
		ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
		for _, other := range []string{curveP256, curveEd25519, curveEd448, curveBrainpoolP256r1} {
			if other == pol.curve {
				continue
			}
			_, err := dialClient(t, url,
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(ecc.client[other].cert),
				opcua.PrivateKeySigner(ecc.client[other].key),
				opcua.TrustedCertificates(ecc.server[pol.curve].x509),
			)
			require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, "%s with a %s certificate", pol.uri, other)
		}
	}
}
