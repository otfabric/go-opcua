// SPDX-License-Identifier: MIT

package conformance

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// securePolicies lists every non-None security policy the library supports.
var securePolicies = []string{
	ua.SecurityPolicyURIBasic128Rsa15,
	ua.SecurityPolicyURIBasic256,
	ua.SecurityPolicyURIBasic256Sha256,
	ua.SecurityPolicyURIAes128Sha256RsaOaep,
	ua.SecurityPolicyURIAes256Sha256RsaPss,
}

var secureModes = []ua.MessageSecurityMode{
	ua.MessageSecurityModeSign,
	ua.MessageSecurityModeSignAndEncrypt,
}

// secureServerOpts returns server options enabling the server certificate and
// every policy x mode combination, plus any extra options.
func secureServerOpts(t *testing.T, extra ...server.Option) []server.Option {
	t.Helper()
	p := pki(t)
	opts := []server.Option{
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
	}
	for _, pol := range securePolicies {
		for _, mode := range secureModes {
			opts = append(opts, server.EnableSecurity(pol, mode))
		}
	}
	return append(opts, extra...)
}

// secureServer starts a server with the fixture and all secure endpoints.
func secureServer(t *testing.T, extra ...server.Option) (*testutil.Fixture, string) {
	t.Helper()
	srv, url := newServer(t, secureServerOpts(t, extra...)...)
	f := testutil.AddFixture(t, srv)
	return f, url
}

// secureClientOpts returns the client options for a fully validated secure
// connection to ep using the shared client application certificate.
func secureClientOpts(t *testing.T, ep *ua.EndpointDescription, auth ua.UserTokenType) []opcua.Option {
	t.Helper()
	p := pki(t)
	return []opcua.Option{
		opcua.SecurityFromEndpoint(ep, auth),
		opcua.Certificate(p.ClientCert),
		opcua.PrivateKey(p.ClientKey),
		opcua.TrustedCertificates(p.ServerCertX509),
	}
}

func shortPolicy(uri string) string {
	return strings.TrimPrefix(uri, "http://opcfoundation.org/UA/SecurityPolicy#")
}

// TestSecurity_PolicyModeMatrix connects with every supported security policy
// in both Sign and SignAndEncrypt mode and performs signed/encrypted reads,
// writes, a multi-chunk read and a method call over the channel.
func TestSecurity_PolicyModeMatrix(t *testing.T) {
	f, url := secureServer(t)
	ctx := context.Background()

	for _, pol := range securePolicies {
		for _, mode := range secureModes {
			t.Run(shortPolicy(pol)+"/"+mode.String(), func(t *testing.T) {
				ep := endpointFor(t, url, pol, mode)
				require.NotEmpty(t, ep.ServerCertificate)
				require.Equal(t, serverAppURI, ep.Server.ApplicationURI)

				c := newClient(t, url, secureClientOpts(t, ep, ua.UserTokenTypeAnonymous)...)
				require.Equal(t, pol, c.SecurityPolicy())
				require.Equal(t, mode, c.SecurityMode())

				// Each subtest writes a distinct value so a stale read cannot pass.
				want := "secure-" + shortPolicy(pol) + "-" + mode.String()
				st, err := c.WriteNodeValue(ctx, f.String, want)
				require.NoError(t, err)
				require.Equal(t, ua.StatusOK, st)

				dv, err := c.ReadValue(ctx, f.String)
				require.NoError(t, err)
				require.Equal(t, want, dv.Value.Value())

				// A request large enough to span several secured chunks in both
				// directions.
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

				res, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(12))
				require.NoError(t, err)
				require.Equal(t, ua.StatusOK, res.StatusCode)
				require.Equal(t, int32(144), res.OutputArguments[0].Value())
			})
		}
	}
}

// TestSecurity_SubscriptionOverEncryptedChannel checks the asynchronous
// Publish path over a SignAndEncrypt channel.
func TestSecurity_SubscriptionOverEncryptedChannel(t *testing.T) {
	f, url := secureServer(t)
	ctx := context.Background()
	ep := endpointFor(t, url, ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt)
	c := newClient(t, url, secureClientOpts(t, ep, ua.UserTokenTypeAnonymous)...)

	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })

	awaitValue(t, ch, 0, int32(42))
	writeInt32(t, c, f.Int32, 4711)
	awaitValue(t, ch, 0, int32(4711))
}

// TestSecurity_EndpointsAdvertised verifies GetEndpoints lists exactly the
// configured policy/mode combinations with consistent security levels.
func TestSecurity_EndpointsAdvertised(t *testing.T) {
	_, url := secureServer(t)
	eps, err := opcua.GetEndpoints(context.Background(), url)
	require.NoError(t, err)

	type key struct {
		pol  string
		mode ua.MessageSecurityMode
	}
	seen := map[key]*ua.EndpointDescription{}
	for _, ep := range eps {
		k := key{ep.SecurityPolicyURI, ep.SecurityMode}
		require.NotContains(t, seen, k, "duplicate endpoint")
		seen[k] = ep
	}
	require.Len(t, seen, 1+len(securePolicies)*len(secureModes))
	require.Contains(t, seen, key{ua.SecurityPolicyURINone, ua.MessageSecurityModeNone})
	for _, pol := range securePolicies {
		sign := seen[key{pol, ua.MessageSecurityModeSign}]
		enc := seen[key{pol, ua.MessageSecurityModeSignAndEncrypt}]
		require.NotNil(t, sign)
		require.NotNil(t, enc)
		require.Equal(t, pki(t).ServerCert, sign.ServerCertificate)
		require.Greater(t, enc.SecurityLevel, sign.SecurityLevel,
			"SignAndEncrypt must rank above Sign for %s", pol)
		require.Greater(t, sign.SecurityLevel, seen[key{ua.SecurityPolicyURINone, ua.MessageSecurityModeNone}].SecurityLevel)
	}
}

// TestSecurity_ServerCertificateTrust covers the client-side validation of the
// server application certificate.
func TestSecurity_ServerCertificateTrust(t *testing.T) {
	f, url := secureServer(t)
	p := pki(t)
	ctx := context.Background()
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)

	base := func() []opcua.Option {
		return []opcua.Option{
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.Certificate(p.ClientCert),
			opcua.PrivateKey(p.ClientKey),
		}
	}

	t.Run("UntrustedRejected", func(t *testing.T) {
		_, err := dialClient(t, url, base()...)
		require.Error(t, err)
		require.Contains(t, err.Error(), "server certificate validation failed")
	})

	t.Run("WrongTrustAnchorRejected", func(t *testing.T) {
		stranger, err := x509.ParseCertificate(p.StrangerCert)
		require.NoError(t, err)
		_, err = dialClient(t, url, append(base(), opcua.TrustedCertificates(stranger))...)
		require.Error(t, err)
		require.Contains(t, err.Error(), "server certificate validation failed")
	})

	t.Run("TrustedCertificatesAccepted", func(t *testing.T) {
		c := newClient(t, url, append(base(), opcua.TrustedCertificates(p.ServerCertX509))...)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("InsecureSkipVerifyAccepted", func(t *testing.T) {
		c := newClient(t, url, append(base(), opcua.InsecureSkipVerify())...)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("ApplicationURIMismatchRejected", func(t *testing.T) {
		// The endpoint claims a different ApplicationURI than the one bound
		// into the certificate's URI SAN: trusted CA, wrong application.
		forged := *ep
		app := *ep.Server
		app.ApplicationURI = "urn:someone:else"
		forged.Server = &app
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(&forged, ua.UserTokenTypeAnonymous),
			opcua.Certificate(p.ClientCert),
			opcua.PrivateKey(p.ClientKey),
			opcua.TrustedCertificates(p.ServerCertX509),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not contain the server ApplicationURI")
	})

	t.Run("ExplicitOptionsWithoutEndpoint", func(t *testing.T) {
		// The same connection configured piecemeal instead of through
		// SecurityFromEndpoint.
		c := newClient(t, url,
			opcua.SecurityPolicy("Basic256Sha256"),
			opcua.SecurityModeString("SignAndEncrypt"),
			opcua.RemoteCertificate(p.ServerCert),
			opcua.Certificate(p.ClientCert),
			opcua.PrivateKey(p.ClientKey),
			opcua.TrustedCertificates(p.ServerCertX509),
		)
		require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, c.SecurityPolicy())
		require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, c.SecurityMode())
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})
}

// TestSecurity_ClientCertificateTrustList covers the server-side validation of
// the client application certificate.
func TestSecurity_ClientCertificateTrustList(t *testing.T) {
	p := pki(t)
	f, url := secureServer(t, server.WithClientCertificateTrustList(p.CACert))
	ctx := context.Background()
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)

	t.Run("IssuedByTrustedCAAccepted", func(t *testing.T) {
		c := newClient(t, url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.Certificate(p.IssuedCert),
			opcua.PrivateKey(p.IssuedKey),
			opcua.TrustedCertificates(p.ServerCertX509),
		)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("SelfSignedRejected", func(t *testing.T) {
		_, err := dialClient(t, url, secureClientOpts(t, ep, ua.UserTokenTypeAnonymous)...)
		require.Error(t, err)
		require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)
	})

	t.Run("UnsecuredChannelUnaffected", func(t *testing.T) {
		// The trust list governs application certificates; a None channel
		// presents none and stays reachable.
		c := newClient(t, url)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})
}

// TestSecurity_EmptyTrustListRejectsAll verifies that a server configured with
// an empty client trust list accepts no client certificate at all.
func TestSecurity_EmptyTrustListRejectsAll(t *testing.T) {
	p := pki(t)
	_, url := secureServer(t, server.WithClientCertificateTrustList())
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign)

	for name, creds := range map[string]struct {
		cert []byte
		key  *rsa.PrivateKey
	}{
		"SelfSigned": {p.ClientCert, p.ClientKey},
		"CAIssued":   {p.IssuedCert, p.IssuedKey},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := dialClient(t, url,
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(creds.cert),
				opcua.PrivateKey(creds.key),
				opcua.TrustedCertificates(p.ServerCertX509),
			)
			require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)
		})
	}
}

// userValidator accepts exactly alice/wonderland.
func userValidator(user, pass string) error {
	if user == "alice" && pass == "wonderland" {
		return nil
	}
	return ua.StatusBadUserAccessDenied
}

// TestSecurity_UsernameOnNone covers username/password identity over an
// unsecured channel, which the server only advertises with AllowUsernameOnNone.
func TestSecurity_UsernameOnNone(t *testing.T) {
	ctx := context.Background()

	t.Run("NotAdvertisedByDefault", func(t *testing.T) {
		_, url := newServer(t,
			server.EnableAuthMode(ua.UserTokenTypeUserName),
			server.WithUsernameValidator(userValidator),
		)
		ep := endpointFor(t, url, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
		for _, tok := range ep.UserIdentityTokens {
			require.NotEqual(t, ua.UserTokenTypeUserName, tok.TokenType,
				"UserName must not be offered on None without AllowUsernameOnNone")
		}
	})

	srv, url := newServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(userValidator),
	)
	f := testutil.AddFixture(t, srv)
	ep := endpointFor(t, url, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)

	t.Run("Advertised", func(t *testing.T) {
		var types []ua.UserTokenType
		for _, tok := range ep.UserIdentityTokens {
			types = append(types, tok.TokenType)
			require.NotEmpty(t, tok.PolicyID)
		}
		require.ElementsMatch(t, []ua.UserTokenType{ua.UserTokenTypeAnonymous, ua.UserTokenTypeUserName}, types)
	})

	t.Run("ValidCredentials", func(t *testing.T) {
		c := newClient(t, url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
			opcua.AuthUsername("alice", "wonderland"),
		)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("WrongPassword", func(t *testing.T) {
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
			opcua.AuthUsername("alice", "queen-of-hearts"),
		)
		require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	})

	t.Run("UnknownUser", func(t *testing.T) {
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
			opcua.AuthUsername("mallory", "wonderland"),
		)
		require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	})

	t.Run("PolicyIDViaAuthPolicyID", func(t *testing.T) {
		// Without SecurityFromEndpoint: the policy id is supplied explicitly,
		// before the token exists (deferred application).
		var policyID string
		for _, tok := range ep.UserIdentityTokens {
			if tok.TokenType == ua.UserTokenTypeUserName {
				policyID = tok.PolicyID
			}
		}
		c := newClient(t, url,
			opcua.AuthPolicyID(policyID),
			opcua.AuthUsername("alice", "wonderland"),
		)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})
}

// TestSecurity_UsernameEncrypted covers username/password identity on secured
// channels, where the client encrypts the password with the server certificate
// and the server has to decrypt it before validating.
func TestSecurity_UsernameEncrypted(t *testing.T) {
	f, url := secureServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(userValidator),
	)
	ctx := context.Background()

	for _, pol := range securePolicies {
		for _, mode := range secureModes {
			t.Run(shortPolicy(pol)+"/"+mode.String(), func(t *testing.T) {
				ep := endpointFor(t, url, pol, mode)

				c := newClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeUserName),
					opcua.AuthUsername("alice", "wonderland"))...)
				dv, err := c.ReadValue(ctx, f.Int32)
				require.NoError(t, err)
				require.Equal(t, int32(42), dv.Value.Value())

				_, err = dialClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeUserName),
					opcua.AuthUsername("alice", "wrong"))...)
				require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
			})
		}
	}
}

// TestSecurity_X509UserToken covers X.509 user identity tokens: proof of
// possession through the user token signature and the server's validator.
func TestSecurity_X509UserToken(t *testing.T) {
	p := pki(t)
	ctx := context.Background()

	var mu sync.Mutex
	var seen [][]byte
	validator := func(der []byte) error {
		mu.Lock()
		seen = append(seen, der)
		mu.Unlock()
		if string(der) == string(p.UserCert) {
			return nil
		}
		return ua.StatusBadIdentityTokenRejected
	}

	f, url := secureServer(t,
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.WithX509UserValidator(validator),
	)

	for _, pol := range securePolicies {
		t.Run("Accepted/"+shortPolicy(pol), func(t *testing.T) {
			ep := endpointFor(t, url, pol, ua.MessageSecurityModeSignAndEncrypt)
			c := newClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeCertificate),
				opcua.AuthCertificate(p.UserCert),
				opcua.AuthPrivateKey(p.UserKey),
			)...)
			dv, err := c.ReadValue(ctx, f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())
		})
	}

	mu.Lock()
	require.NotEmpty(t, seen, "validator must have been consulted")
	for _, der := range seen {
		require.Equal(t, p.UserCert, der)
	}
	mu.Unlock()

	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)

	t.Run("RejectedByValidator", func(t *testing.T) {
		_, err := dialClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeCertificate),
			opcua.AuthCertificate(p.StrangerCert),
			opcua.AuthPrivateKey(p.StrangerKey),
		)...)
		require.ErrorIs(t, err, ua.StatusBadIdentityTokenRejected)
	})

	t.Run("WrongPrivateKey", func(t *testing.T) {
		// A trusted certificate presented without its private key: the user
		// token signature cannot verify.
		_, err := dialClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeCertificate),
			opcua.AuthCertificate(p.UserCert),
			opcua.AuthPrivateKey(p.StrangerKey),
		)...)
		require.ErrorIs(t, err, ua.StatusBadUserSignatureInvalid)
	})

	t.Run("GarbageCertificate", func(t *testing.T) {
		_, err := dialClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeCertificate),
			opcua.AuthCertificate([]byte("not a certificate")),
			opcua.AuthPrivateKey(p.UserKey),
		)...)
		require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)
	})
}

// TestSecurity_X509UserTokenWithoutValidator verifies the server refuses X.509
// user tokens when no validator has been configured.
func TestSecurity_X509UserTokenWithoutValidator(t *testing.T) {
	p := pki(t)
	_, url := secureServer(t, server.EnableAuthMode(ua.UserTokenTypeCertificate))
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)

	_, err := dialClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeCertificate),
		opcua.AuthCertificate(p.UserCert),
		opcua.AuthPrivateKey(p.UserKey),
	)...)
	require.ErrorIs(t, err, ua.StatusBadIdentityTokenRejected)
}

// TestSecurity_IdentityReachesRoleMapper verifies each identity token type
// arrives intact at the server's RoleMapper hook.
func TestSecurity_IdentityReachesRoleMapper(t *testing.T) {
	var mu sync.Mutex
	var tokens []ua.IdentityToken
	mapper := func(tok ua.IdentityToken) []*ua.NodeID {
		mu.Lock()
		tokens = append(tokens, tok)
		mu.Unlock()
		return server.DefaultRoleMapper(tok)
	}
	last := func() ua.IdentityToken {
		mu.Lock()
		defer mu.Unlock()
		require.NotEmpty(t, tokens)
		return tokens[len(tokens)-1]
	}

	_, url := newServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.EnableAuthMode(ua.UserTokenTypeIssuedToken),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == "bob" && pass == "builder" {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithIssuedTokenValidator(func(tok *ua.IssuedIdentityToken) error {
			if bytes.HasPrefix(tok.TokenData, []byte("opaque-jwt")) {
				return nil
			}
			return ua.StatusBadIdentityTokenRejected
		}),
		server.AllowUsernameOnNone(),
		server.WithRoleMapper(mapper),
	)
	ep := endpointFor(t, url, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)

	t.Run("Anonymous", func(t *testing.T) {
		newClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous())
		tok, ok := last().(*ua.AnonymousIdentityToken)
		require.True(t, ok, "got %T", last())
		require.Equal(t, "anonymous_none", tok.PolicyID)
	})

	t.Run("AnonymousPolicyDiscovered", func(t *testing.T) {
		// No SecurityFromEndpoint: the client picks the anonymous policy id
		// from the CreateSession response.
		newClient(t, url)
		tok, ok := last().(*ua.AnonymousIdentityToken)
		require.True(t, ok, "got %T", last())
		require.Equal(t, "anonymous_none", tok.PolicyID)
	})

	t.Run("UserName", func(t *testing.T) {
		newClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("bob", "builder"))
		tok, ok := last().(*ua.UserNameIdentityToken)
		require.True(t, ok, "got %T", last())
		require.Equal(t, "bob", tok.UserName)
		require.Equal(t, "builder", string(tok.Password))
		require.Equal(t, "username_none", tok.PolicyID)
	})

	t.Run("IssuedToken", func(t *testing.T) {
		newClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeIssuedToken), opcua.AuthIssuedToken([]byte("opaque-jwt")))
		tok, ok := last().(*ua.IssuedIdentityToken)
		require.True(t, ok, "got %T", last())
		require.Equal(t, []byte("opaque-jwt"), tok.TokenData)
		require.Equal(t, "issuedtoken_none", tok.PolicyID)
	})

	t.Run("UserNameRejected", func(t *testing.T) {
		c, err := opcua.NewClient(url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("bob", "wrong"), opcua.AutoReconnect(false))
		require.NoError(t, err)
		require.ErrorIs(t, c.Connect(context.Background()), ua.StatusBadUserAccessDenied)
	})

	t.Run("IssuedTokenRejected", func(t *testing.T) {
		c, err := opcua.NewClient(url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeIssuedToken), opcua.AuthIssuedToken([]byte("forged")), opcua.AutoReconnect(false))
		require.NoError(t, err)
		require.ErrorIs(t, c.Connect(context.Background()), ua.StatusBadIdentityTokenRejected)
	})
}

// TestSecurity_AccessRestrictions verifies the per-node AccessRestrictions
// attribute is enforced against the security mode of the channel.
func TestSecurity_AccessRestrictions(t *testing.T) {
	srv, url := newServer(t, secureServerOpts(t)...)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	restrict := func(name string, r ua.AccessRestrictionType) *ua.NodeID {
		n := f.NS.AddNewVariableStringNode(name, int32(7))
		require.NoError(t, n.SetAttribute(ua.AttributeIDAccessRestrictions, server.DataValueFromValue(uint16(r))))
		f.NS.Objects().AddRef(n, server.RefTypeIDHasComponent, true)
		return n.ID()
	}
	signOnly := restrict("NeedsSigning", ua.AccessRestrictionTypeSigningRequired)
	encOnly := restrict("NeedsEncryption", ua.AccessRestrictionTypeEncryptionRequired)
	browseHidden := restrict("NeedsEncryptionToBrowse",
		ua.AccessRestrictionTypeEncryptionRequired|ua.AccessRestrictionTypeApplyRestrictionsToBrowse)

	clients := map[ua.MessageSecurityMode]*opcua.Client{
		ua.MessageSecurityModeNone: newClient(t, url),
	}
	for _, mode := range secureModes {
		ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, mode)
		clients[mode] = newClient(t, url, secureClientOpts(t, ep, ua.UserTokenTypeAnonymous)...)
	}

	denied := ua.StatusBadSecurityModeInsufficient
	cases := []struct {
		node *ua.NodeID
		want map[ua.MessageSecurityMode]ua.StatusCode
	}{
		{signOnly, map[ua.MessageSecurityMode]ua.StatusCode{
			ua.MessageSecurityModeNone: denied, ua.MessageSecurityModeSign: ua.StatusOK, ua.MessageSecurityModeSignAndEncrypt: ua.StatusOK}},
		{encOnly, map[ua.MessageSecurityMode]ua.StatusCode{
			ua.MessageSecurityModeNone: denied, ua.MessageSecurityModeSign: denied, ua.MessageSecurityModeSignAndEncrypt: ua.StatusOK}},
	}
	for _, tc := range cases {
		for mode, want := range tc.want {
			t.Run(tc.node.StringID()+"/"+mode.String(), func(t *testing.T) {
				c := clients[mode]
				dv, err := c.ReadValue(ctx, tc.node)
				require.NoError(t, err)
				require.Equal(t, want, dv.Status)
				if want == ua.StatusOK {
					require.Equal(t, int32(7), dv.Value.Value())
				} else {
					require.Nil(t, dv.Value.Value(), "a denied read must not leak the value")
				}

				st, err := c.WriteNodeValue(ctx, tc.node, int32(7))
				require.NoError(t, err)
				require.Equal(t, want, st)

				// Browse is not restricted unless ApplyRestrictionsToBrowse is set.
				refs, err := c.BrowseAll(ctx, tc.node)
				require.NoError(t, err)
				require.Empty(t, refs)
			})
		}
	}

	t.Run("ApplyRestrictionsToBrowse", func(t *testing.T) {
		for mode, c := range clients {
			resp, err := c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
				NodeID:          browseHidden,
				BrowseDirection: ua.BrowseDirectionBoth,
				ResultMask:      uint32(ua.BrowseResultMaskAll),
			}}})
			require.NoError(t, err)
			want := denied
			if mode == ua.MessageSecurityModeSignAndEncrypt {
				want = ua.StatusOK
			}
			require.Equal(t, want, resp.Results[0].StatusCode, "mode %s", mode)
		}
	})
}

// TestSecurity_OnlyEnabledSecurityAccepted verifies the server refuses
// sessions over a secure channel whose policy or mode it did not enable, so a
// client cannot downgrade below what the operator configured.
func TestSecurity_OnlyEnabledSecurityAccepted(t *testing.T) {
	p := pki(t)
	// Deliberately no None endpoint: only Basic256Sha256 / SignAndEncrypt.
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	url := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
	f := testutil.AddFixture(t, srv)

	secure := func(policy string, mode ua.MessageSecurityMode) []opcua.Option {
		return []opcua.Option{
			opcua.SecurityPolicy(policy),
			opcua.SecurityMode(mode),
			opcua.RemoteCertificate(p.ServerCert),
			opcua.Certificate(p.ClientCert),
			opcua.PrivateKey(p.ClientKey),
			opcua.TrustedCertificates(p.ServerCertX509),
		}
	}

	t.Run("EnabledCombinationAccepted", func(t *testing.T) {
		c := newClient(t, url, secure(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)...)
		dv, err := c.ReadValue(context.Background(), f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("NoneRejected", func(t *testing.T) {
		_, err := dialClient(t, url)
		require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)
	})

	t.Run("OtherPolicyRejected", func(t *testing.T) {
		_, err := dialClient(t, url, secure(ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt)...)
		require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)
	})

	t.Run("WeakerModeRejected", func(t *testing.T) {
		_, err := dialClient(t, url, secure(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign)...)
		require.ErrorIs(t, err, ua.StatusBadSecurityModeRejected)
	})

	t.Run("DiscoveryStillPossibleOverNone", func(t *testing.T) {
		// GetEndpoints needs no session and must stay reachable so clients can
		// find out which security they have to use.
		eps, err := opcua.GetEndpoints(context.Background(), url)
		require.NoError(t, err)
		require.Len(t, eps, 1)
		require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, eps[0].SecurityPolicyURI)
		require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, eps[0].SecurityMode)
	})
}

// TestSecurity_NoValidatorRejects: an auth mode without its validator is
// advertised, but every token of that type is rejected, and the server says
// so when it is created.
func TestSecurity_NoValidatorRejects(t *testing.T) {
	var logBuf bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logBuf.Write(p)
	}), nil))
	_, url := newServer(t,
		server.SetLogger(logger),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.EnableAuthMode(ua.UserTokenTypeIssuedToken),
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.AllowUsernameOnNone(),
	)
	logMu.Lock()
	logged := logBuf.String()
	logMu.Unlock()
	for _, opt := range []string{"WithUsernameValidator", "WithIssuedTokenValidator", "WithX509UserValidator"} {
		require.Contains(t, logged, opt, "New warns about the mode without its validator")
	}

	ep := endpointFor(t, url, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
	for _, tc := range []struct {
		name string
		opts []opcua.Option
		want ua.StatusCode
	}{
		{"UserName", []opcua.Option{opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("anyone", "anything")}, ua.StatusBadUserAccessDenied},
		{"IssuedToken", []opcua.Option{opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeIssuedToken), opcua.AuthIssuedToken([]byte("any-token"))}, ua.StatusBadIdentityTokenRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := opcua.NewClient(url, append(tc.opts, opcua.AutoReconnect(false))...)
			require.NoError(t, err)
			require.ErrorIs(t, c.Connect(context.Background()), tc.want)
		})
	}
	// Anonymous login is unaffected.
	newClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous())
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
