// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// The ECC security policies of OPC UA 1.05.07 with authenticated encryption:
// ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly and ECC_curve25519. The
// messages of an open channel have no padding and a 16 byte tag instead of an
// HMAC; the two nistP256 policies bind the session to the channel.

// aeadExtraOpts are the options that add the AEAD endpoints and the Ed25519
// certificate to a server built from mixedServerOpts.
func aeadExtraOpts(t *testing.T) []server.Option {
	t.Helper()
	ed := pki(t).ecc.server[curveEd25519]
	opts := []server.Option{server.ApplicationIdentity(ed.cert, ed.key)}
	for _, pol := range aeadPolicies {
		for _, mode := range secureModes {
			opts = append(opts, server.EnableSecurity(pol.uri, mode))
		}
	}
	return opts
}

// proxiedAEADServer starts a server with all endpoints behind a wire proxy.
func proxiedAEADServer(t *testing.T, hook func(dir string, msg []byte) []byte, extra ...server.Option) (*testutil.Fixture, string) {
	t.Helper()
	return proxiedECCServer(t, hook, append(aeadExtraOpts(t), extra...)...)
}

// TestAEAD_PolicyModeMatrix connects with every ECC security policy with
// authenticated encryption in both Sign and SignAndEncrypt mode and performs
// reads, writes, a multi-chunk read, a method call and a subscription over the
// channel.
func TestAEAD_PolicyModeMatrix(t *testing.T) {
	f, url := aeadServer(t)
	ctx := context.Background()

	for _, pol := range aeadPolicies {
		for _, mode := range secureModes {
			t.Run(shortPolicy(pol.uri)+"/"+mode.String(), func(t *testing.T) {
				ep := endpointFor(t, url, pol.uri, mode)
				require.Equal(t, pki(t).ecc.server[pol.curve].cert, ep.ServerCertificate,
					"the endpoint advertises the certificate of its key type")
				require.Equal(t, uapolicy.SecurityLevel(pol.uri, mode), ep.SecurityLevel)

				c := newClient(t, url, eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous)...)
				require.Equal(t, pol.uri, c.SecurityPolicy())
				require.Equal(t, mode, c.SecurityMode())
				require.Equal(t, uapolicy.SecureChannelEnhancements(pol.uri), len(c.SecureChannel().ChannelThumbprint()) > 0,
					"a ChannelThumbprint exactly where the policy has SecureChannelEnhancements")

				want := "aead-" + shortPolicy(pol.uri) + "-" + mode.String()
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

				sub, ch, err := c.NewSubscription().
					Interval(fastInterval).
					Monitor(f.Writable).
					Start(ctx)
				require.NoError(t, err)
				t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
				nextDataChanges(t, ch) // initial value
				changed := 4242 + eccMatrixValue.Add(1)
				writeInt32(t, c, f.Writable, changed)
				awaitInt32Change(t, ch, changed)
			})
		}
	}
}

// TestAEAD_Identities covers the user identities over the AEAD policies: a
// password and an issued token travel in an EccEncryptedSecret sealed with
// the cipher of the policy, an X.509 user token is signed with the user's key
// (over channel bound data for the nistP256 policies, with Ed25519 for
// ECC_curve25519).
func TestAEAD_Identities(t *testing.T) {
	p := pki(t)
	ecc := p.ecc
	ctx := context.Background()

	// A user certificate per key type.
	users := map[string]*eccIdentity{curveP256: ecc.user, curveEd25519: ecc.edUser}

	var mu sync.Mutex
	var tokens []ua.IdentityToken
	f, url := aeadServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.EnableAuthMode(ua.UserTokenTypeIssuedToken),
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.WithUsernameValidator(userValidator),
		server.WithIssuedTokenValidator(func(tok *ua.IssuedIdentityToken) error {
			if bytes.HasPrefix(tok.TokenData, []byte("opaque-jwt")) {
				return nil
			}
			return ua.StatusBadIdentityTokenRejected
		}),
		server.WithX509UserValidator(func(der []byte) error {
			for _, user := range users {
				if bytes.Equal(der, user.cert) {
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

	for _, pol := range aeadPolicies {
		t.Run(shortPolicy(pol.uri), func(t *testing.T) {
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			opts := func(auth ua.UserTokenType, extra ...opcua.Option) []opcua.Option {
				return append(eccClientOpts(t, ep, pol.curve, auth), extra...)
			}

			t.Run("Username", func(t *testing.T) {
				for _, mode := range secureModes {
					mep := endpointFor(t, url, pol.uri, mode)
					c := newClient(t, url, append(eccClientOpts(t, mep, pol.curve, ua.UserTokenTypeUserName),
						opcua.AuthUsername("alice", "wonderland"))...)
					read(t, c)
					// Every activation needs a new ephemeral key of the
					// server and seals the password anew.
					require.NoError(t, c.ActivateSession(ctx, c.Session()), mode)
					read(t, c)
				}
				_, err := dialClient(t, url, opts(ua.UserTokenTypeUserName, opcua.AuthUsername("alice", "wrong"))...)
				require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
			})

			t.Run("IssuedToken", func(t *testing.T) {
				jwt := []byte("opaque-jwt-" + shortPolicy(pol.uri))
				c := newClient(t, url, opts(ua.UserTokenTypeIssuedToken, opcua.AuthIssuedToken(jwt))...)
				tok, ok := lastToken().(*ua.IssuedIdentityToken)
				require.True(t, ok)
				require.Equal(t, jwt, tok.TokenData, "the role mapper sees the token the issuer created")
				require.Equal(t, strings.ToLower("issuedtoken_"+shortPolicy(pol.uri)), tok.PolicyID)
				require.NoError(t, c.ActivateSession(ctx, c.Session()))
				tok, ok = lastToken().(*ua.IssuedIdentityToken)
				require.True(t, ok)
				require.Equal(t, jwt, tok.TokenData)
			})

			t.Run("X509", func(t *testing.T) {
				user := users[pol.curve]
				c := newClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(user.cert), opcua.AuthPrivateKeySigner(user.key))...)
				read(t, c)
				tok, ok := lastToken().(*ua.X509IdentityToken)
				require.True(t, ok)
				require.Equal(t, user.cert, tok.CertificateData)
				// Activated again: the signature covers the nonce the server
				// issued last.
				require.NoError(t, c.ActivateSession(ctx, c.Session()))
				read(t, c)

				// A trusted certificate without its private key.
				other := ecc.stranger.key
				if pol.curve == curveEd25519 {
					other = ecc.client[curveEd25519].key
				}
				_, err := dialClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(user.cert), opcua.AuthPrivateKeySigner(other))...)
				require.ErrorIs(t, err, ua.StatusBadUserSignatureInvalid)

				// A user certificate of the key type of another policy: the
				// client cannot even make the signature.
				wrong := users[curveEd25519]
				if pol.curve == curveEd25519 {
					wrong = users[curveP256]
				}
				_, err = dialClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(wrong.cert), opcua.AuthPrivateKeySigner(wrong.key))...)
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
				_, err = dialClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(p.UserCert), opcua.AuthPrivateKey(p.UserKey))...)
				require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)

				// Not trusted by the server.
				stranger := ecc.stranger
				if pol.curve == curveEd25519 {
					stranger = ecc.client[curveEd25519]
				}
				_, err = dialClient(t, url, opts(ua.UserTokenTypeCertificate,
					opcua.AuthCertificate(stranger.cert), opcua.AuthPrivateKeySigner(stranger.key))...)
				require.ErrorIs(t, err, ua.StatusBadIdentityTokenRejected)
			})
		})
	}
}

// testAEADRenewalUnderTraffic (run by TestTokenRenewal) renews an AEAD SecureChannel on a 2 s lifetime
// while reads, writes and a subscription keep running. Every renewal issues a
// SecurityToken with new keys and a new TokenId, which the nonces depend on;
// the nistP256 policies chain the keys of each token to the previous ones.
func testAEADRenewalUnderTraffic(t *testing.T) {
	for _, pol := range aeadPolicies {
		t.Run(shortPolicy(pol.uri), func(t *testing.T) {
			var mu sync.Mutex
			var opens int         // OpenSecureChannel responses on the secured channel
			var tokenIDs []uint32 // token id of every server MSG chunk
			var prefixes [][]byte // start of the protected part of every server MSG chunk
			marker := []byte(pol.uri + "\x00")[:len(pol.uri)]
			f, url := proxiedAEADServer(t, func(dir string, msg []byte) []byte {
				mu.Lock()
				defer mu.Unlock()
				switch string(msg[:3]) {
				case "OPN":
					// The URI is followed by the length of the certificate;
					// make sure a longer URI with the same start does not match.
					if i := bytes.Index(msg, marker); i < 0 || msg[i+len(marker)] == '_' {
						break
					}
					if dir == "s2c" {
						opens++
					}
				case "MSG":
					if dir == "s2c" && len(msg) >= 32 && opens > 0 {
						tokenIDs = append(tokenIDs, binary.LittleEndian.Uint32(msg[12:16]))
						prefixes = append(prefixes, append([]byte(nil), msg[16:32]...))
					}
				}
				return msg
			})

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)

			// A 2 s lifetime makes the client renew every 1.5 s.
			c := newClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous),
				opcua.Lifetime(2*time.Second))...)
			thumbprint := c.SecureChannel().ChannelThumbprint()

			sub, notifyCh, err := c.NewSubscription().
				Interval(50 * time.Millisecond).
				Monitor(f.Writable).
				Start(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

			count := func() int {
				mu.Lock()
				defer mu.Unlock()
				return opens
			}
			deadline := time.Now().Add(30 * time.Second)
			var written int32
			for count() < 4 { // issue + 3 renewals
				require.True(t, time.Now().Before(deadline), "only %d OpenSecureChannel responses within 30s", count())
				written++
				writeInt32(t, c, f.Writable, written)
				dv, err := c.ReadValue(ctx, f.Writable)
				require.NoError(t, err)
				require.Equal(t, written, dv.Value.Value())
				time.Sleep(20 * time.Millisecond)
			}
			awaitInt32Change(t, notifyCh, written)

			// The ChannelThumbprint belongs to the channel, not to a token.
			require.Equal(t, thumbprint, c.SecureChannel().ChannelThumbprint())

			mu.Lock()
			defer mu.Unlock()
			var order []uint32
			used := map[uint32]bool{}
			for _, id := range tokenIDs {
				if len(order) > 0 && order[len(order)-1] == id {
					continue
				}
				require.False(t, used[id], "server went back to SecurityToken %d (sequence %v)", id, order)
				used[id] = true
				order = append(order, id)
			}
			require.GreaterOrEqual(t, len(order), 3, "distinct SecurityTokens across 3 renewals: %v", order)

			// Encrypted sequence headers never repeat: the sequence numbers
			// differ, and so do key and nonce.
			seen := map[string]bool{}
			for _, p := range prefixes {
				require.False(t, seen[string(p)], "two chunks start with the same ciphertext")
				seen[string(p)] = true
			}
		})
	}
}

// TestAEAD_TamperedAndReplayedChunks changes and repeats chunks on the wire.
func TestAEAD_TamperedAndReplayedChunks(t *testing.T) {
	for _, pol := range aeadPolicies {
		for _, mode := range secureModes {
			name := shortPolicy(pol.uri) + "/" + mode.String()

			t.Run("TamperedTag/"+name, func(t *testing.T) {
				var mu sync.Mutex
				armed, done := false, false
				f, url := proxiedAEADServer(t, func(dir string, msg []byte) []byte {
					mu.Lock()
					defer mu.Unlock()
					if armed && !done && dir == "s2c" && string(msg[:3]) == "MSG" {
						done = true
						msg[len(msg)-1] ^= 0x01 // the last byte of the tag
					}
					return msg
				})
				ep := endpointFor(t, url, pol.uri, mode)
				c := newClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous),
					opcua.AutoReconnect(false))...)
				dv, err := c.ReadValue(context.Background(), f.Int32)
				require.NoError(t, err)
				require.Equal(t, int32(42), dv.Value.Value())

				mu.Lock()
				armed = true
				mu.Unlock()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_, err = c.ReadValue(ctx, f.Int32)
				require.Error(t, err, "a response with a broken tag must not be delivered")
			})

			t.Run("ReplayedRequest/"+name, func(t *testing.T) {
				// The proxy sends one request chunk twice. The server must
				// answer it once and refuse the copy: its nonce belongs to a
				// position in the stream that has passed.
				var mu sync.Mutex
				armed, replayed := false, false
				responses := 0
				f, url := proxiedAEADServer(t, func(dir string, msg []byte) []byte {
					mu.Lock()
					defer mu.Unlock()
					if !armed {
						return msg
					}
					if dir == "s2c" {
						if string(msg[:3]) == "MSG" {
							responses++
						}
						return msg
					}
					if !replayed && string(msg[:3]) == "MSG" {
						replayed = true
						return append(append([]byte(nil), msg...), msg...)
					}
					return msg
				})
				ep := endpointFor(t, url, pol.uri, mode)
				c := newClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous),
					opcua.AutoReconnect(false))...)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_, err := c.ReadValue(ctx, f.Int32)
				require.NoError(t, err)

				mu.Lock()
				armed = true
				mu.Unlock()
				// The server may still answer the original (it need not: the
				// copy arrives right behind it and ends the channel) ...
				_, _ = c.ReadValue(ctx, f.Int32)
				// ... but the copy is never served: the channel is closed.
				eventually(t, func() bool {
					_, err := c.ReadValue(ctx, f.Int32)
					return err != nil
				}, "the server kept the channel open after a replayed chunk")
				mu.Lock()
				defer mu.Unlock()
				require.True(t, replayed)
				require.LessOrEqual(t, responses, 1, "at most one response: the replayed request was not executed")
			})
		}
	}

	// The OpenSecureChannel messages are signed, and for the nistP256
	// policies the response signature also covers the request signature.
	for _, pol := range aeadPolicies {
		for _, tt := range []struct {
			name    string
			dir     string
			fromEnd int
		}{
			{"RequestSignature", "c2s", 1},
			{"RequestNonce", "c2s", 64 + 20},
			{"ResponseSignature", "s2c", 1},
			{"ResponseNonce", "s2c", 64 + 10},
		} {
			t.Run("OpenSecureChannel"+tt.name+"/"+shortPolicy(pol.uri), func(t *testing.T) {
				marker := []byte(pol.uri)
				var once sync.Once
				_, url := proxiedAEADServer(t, func(dir string, msg []byte) []byte {
					if dir == tt.dir && string(msg[:3]) == "OPN" && bytes.Contains(msg, marker) {
						once.Do(func() { msg[len(msg)-tt.fromEnd] ^= 0x01 })
					}
					return msg
				})
				ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
				_, err := dialClient(t, url, eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous)...)
				require.Error(t, err, "a channel must not open on a forged OpenSecureChannel message")
			})
		}
	}
}

// TestAEAD_SessionMovesToNewChannel breaks the connection of a client with a
// user name identity. The client opens a new SecureChannel and activates its
// session on it: with a ClientSignature bound to the new ChannelThumbprint
// and a password sealed for the ephemeral key of the last activation.
func TestAEAD_SessionMovesToNewChannel(t *testing.T) {
	for _, pol := range aeadPolicies {
		t.Run(shortPolicy(pol.uri), func(t *testing.T) {
			var mu sync.Mutex
			armed, done := false, false
			issues := 0
			marker := []byte(pol.uri)
			f, url := proxiedAEADServer(t, func(dir string, msg []byte) []byte {
				mu.Lock()
				defer mu.Unlock()
				if dir == "c2s" && string(msg[:3]) == "OPN" && bytes.Contains(msg, marker) {
					issues++
				}
				if armed && !done && dir == "s2c" && string(msg[:3]) == "MSG" {
					done = true
					msg[len(msg)-1] ^= 0x01
				}
				return msg
			},
				server.EnableAuthMode(ua.UserTokenTypeUserName),
				server.WithUsernameValidator(userValidator),
			)
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			states := &stateRecorder{}
			c := newClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeUserName),
				opcua.AuthUsername("alice", "wonderland"),
				opcua.ReconnectInterval(50*time.Millisecond),
				opcua.WithConnStateHandler(states.Record),
				opcua.AutoReconnect(true),
			)...)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			dv, err := c.ReadValue(ctx, f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())
			first := c.SecureChannel().ChannelThumbprint()
			session := c.Session().SessionID()

			mu.Lock()
			armed = true
			mu.Unlock()
			// The damaged response takes the channel down; the client
			// recovers on a new one.
			_, _ = c.ReadValue(ctx, f.Int32)
			eventually(t, func() bool {
				if !states.SeenAfter(opcua.Reconnecting, opcua.Connected) {
					return false
				}
				dv, err := c.ReadValue(ctx, f.Int32)
				return err == nil && dv.Value.Value() == int32(42)
			}, "the client did not recover on a new SecureChannel")

			mu.Lock()
			require.GreaterOrEqual(t, issues, 2, "a second SecureChannel was opened")
			mu.Unlock()
			if uapolicy.SecureChannelEnhancements(pol.uri) {
				second := c.SecureChannel().ChannelThumbprint()
				require.NotEmpty(t, second)
				require.NotEqual(t, first, second, "the new channel has a ChannelThumbprint of its own")
			}
			require.Equal(t, session.String(), c.Session().SessionID().String(), "the session moved to the new channel")
		})
	}
}

// TestAEAD_CertificatesAndPolicies covers which certificate goes with which
// policy on both sides, endpoint selection and the refusal of what a server
// does not offer.
func TestAEAD_CertificatesAndPolicies(t *testing.T) {
	p := pki(t)
	ecc := p.ecc
	_, url := aeadServer(t)
	ctx := context.Background()

	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)
	require.Len(t, eps, 1+2*(len(securePolicies)+len(eccPolicies)+len(aeadPolicies)))

	gcmEP := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256AesGcm, ua.MessageSecurityModeSignAndEncrypt)
	chachaEP := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256ChaChaPoly, ua.MessageSecurityModeSignAndEncrypt)
	edEP := endpointFor(t, url, ua.SecurityPolicyURIECCCurve25519, ua.MessageSecurityModeSignAndEncrypt)
	trust := opcua.TrustedCertificates(p.ServerCertX509, ecc.server[curveP256].x509, ecc.server[curveEd25519].x509)

	t.Run("EndpointSelection", func(t *testing.T) {
		// The best endpoint of the server needs an Ed25519 certificate.
		best, err := ua.SelectEndpoint(append([]*ua.EndpointDescription{}, eps...), "", ua.MessageSecurityModeInvalid)
		require.NoError(t, err)
		require.Equal(t, ua.SecurityPolicyURIECCCurve25519, best.SecurityPolicyURI)
		require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, best.SecurityMode)

		for name, tt := range map[string]struct {
			cert   []byte
			policy string
		}{
			"rsa":     {p.ClientCert, ua.SecurityPolicyURIAes256Sha256RsaPss},
			"p256":    {ecc.client[curveP256].cert, ua.SecurityPolicyURIECCNistP256ChaChaPoly},
			"p384":    {ecc.client[curveP384].cert, ua.SecurityPolicyURIECCNistP256ChaChaPoly},
			"ed25519": {ecc.client[curveEd25519].cert, ua.SecurityPolicyURIECCCurve25519},
		} {
			ep, err := opcua.SelectEndpoint(eps, "", ua.MessageSecurityModeInvalid, tt.cert)
			require.NoError(t, err, name)
			require.Equal(t, tt.policy, ep.SecurityPolicyURI, name)
			require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, ep.SecurityMode, name)
		}

		ep, err := opcua.SelectEndpoint(eps, "ECC_nistP256_AesGcm", ua.MessageSecurityModeSign, ecc.client[curveP256].cert)
		require.NoError(t, err)
		require.Equal(t, ua.SecurityPolicyURIECCNistP256AesGcm, ep.SecurityPolicyURI)
		require.Equal(t, ua.MessageSecurityModeSign, ep.SecurityMode)

		// What the certificate cannot be used with is not offered.
		_, err = opcua.SelectEndpoint(eps, "ECC_curve25519", ua.MessageSecurityModeInvalid, ecc.client[curveP256].cert)
		require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)
		_, err = opcua.SelectEndpoint(eps, "ECC_nistP256_AesGcm", ua.MessageSecurityModeInvalid, ecc.client[curveEd25519].cert)
		require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)
		_, err = opcua.SelectEndpoint(eps, "ECC_nistP256_ChaChaPoly", ua.MessageSecurityModeInvalid, p.ClientCert)
		require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)

		// Equal levels: the ranking of the library decides.
		tied := []*ua.EndpointDescription{
			{SecurityPolicyURI: ua.SecurityPolicyURIECCNistP256, SecurityMode: ua.MessageSecurityModeSignAndEncrypt, SecurityLevel: 10},
			{SecurityPolicyURI: ua.SecurityPolicyURIECCNistP256AesGcm, SecurityMode: ua.MessageSecurityModeSignAndEncrypt, SecurityLevel: 10},
			{SecurityPolicyURI: ua.SecurityPolicyURIECCNistP256ChaChaPoly, SecurityMode: ua.MessageSecurityModeSign, SecurityLevel: 10},
			{SecurityPolicyURI: ua.SecurityPolicyURIECCNistP384, SecurityMode: ua.MessageSecurityModeSignAndEncrypt, SecurityLevel: 10},
		}
		for i := 0; i < len(tied); i++ {
			tied = append(tied[1:], tied[0])
			ep, err := opcua.SelectEndpoint(tied, "", ua.MessageSecurityModeInvalid, ecc.client[curveP384].cert)
			require.NoError(t, err)
			require.Equal(t, ua.SecurityPolicyURIECCNistP256ChaChaPoly, ep.SecurityPolicyURI)
		}
		// The level the server advertises still comes first.
		tied[0].SecurityLevel = 11
		ep, err = opcua.SelectEndpoint(tied, "", ua.MessageSecurityModeInvalid, ecc.client[curveP384].cert)
		require.NoError(t, err)
		require.Equal(t, tied[0].SecurityPolicyURI, ep.SecurityPolicyURI)
	})

	t.Run("P384CertificateOnTheNistP256Policies", func(t *testing.T) {
		c := newClient(t, url, eccClientOpts(t, gcmEP, curveP384, ua.UserTokenTypeAnonymous)...)
		require.Equal(t, ua.SecurityPolicyURIECCNistP256AesGcm, c.SecurityPolicy())
	})

	t.Run("WrongKeyTypeForThePolicy", func(t *testing.T) {
		for name, opts := range map[string][]opcua.Option{
			"ed25519 certificate on AesGcm":   eccClientOpts(t, gcmEP, curveEd25519, ua.UserTokenTypeAnonymous),
			"ed25519 certificate on ChaCha":   eccClientOpts(t, chachaEP, curveEd25519, ua.UserTokenTypeAnonymous),
			"p256 certificate on curve25519":  eccClientOpts(t, edEP, curveP256, ua.UserTokenTypeAnonymous),
			"p384 certificate on curve25519":  eccClientOpts(t, edEP, curveP384, ua.UserTokenTypeAnonymous),
			"rsa certificate on AesGcm":       {opcua.SecurityFromEndpoint(gcmEP, ua.UserTokenTypeAnonymous), opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey), trust},
			"rsa certificate on curve25519":   {opcua.SecurityFromEndpoint(edEP, ua.UserTokenTypeAnonymous), opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey), trust},
			"ed25519 certificate on RSA":      {opcua.SecurityFromEndpoint(endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt), ua.UserTokenTypeAnonymous), opcua.Certificate(ecc.client[curveEd25519].cert), opcua.PrivateKeySigner(ecc.client[curveEd25519].key), trust},
			"ed25519 certificate on nistP256": eccClientOpts(t, endpointFor(t, url, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt), curveEd25519, ua.UserTokenTypeAnonymous),
		} {
			_, err := dialClient(t, url, opts...)
			require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig, name)
		}

		// The server certificate of another policy.
		_, err := dialClient(t, url,
			opcua.SecurityPolicy(ua.SecurityPolicyURIECCCurve25519),
			opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
			opcua.RemoteCertificate(ecc.server[curveP256].cert),
			opcua.Certificate(ecc.client[curveEd25519].cert),
			opcua.PrivateKeySigner(ecc.client[curveEd25519].key),
			trust,
		)
		require.Error(t, err)

		// A key that does not belong to the certificate: the server cannot
		// verify the OpenSecureChannel request.
		_, err = dialClient(t, url,
			opcua.SecurityFromEndpoint(edEP, ua.UserTokenTypeAnonymous),
			opcua.Certificate(ecc.client[curveEd25519].cert),
			opcua.PrivateKeySigner(ecc.edUser.key),
			trust,
		)
		require.Error(t, err)
	})

	t.Run("UntrustedCertificates", func(t *testing.T) {
		// The client trusts some other certificate, not the server's.
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(edEP, ua.UserTokenTypeAnonymous),
			opcua.Certificate(ecc.client[curveEd25519].cert),
			opcua.PrivateKeySigner(ecc.client[curveEd25519].key),
			opcua.TrustedCertificates(ecc.stranger.x509),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "server certificate validation failed")

		// A server with a trust list turns self-signed clients away at
		// OpenSecureChannel, whatever the policy.
		_, strict := aeadServer(t, server.WithClientCertificateTrustList(ecc.caCert))
		for _, pol := range aeadPolicies {
			ep := endpointFor(t, strict, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			_, err := dialClient(t, strict, eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous)...)
			require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted, pol.uri)
		}
		// One that the CA issued is welcome.
		ep := endpointFor(t, strict, ua.SecurityPolicyURIECCNistP256ChaChaPoly, ua.MessageSecurityModeSignAndEncrypt)
		c := newClient(t, strict,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.Certificate(ecc.issued.cert),
			opcua.PrivateKeySigner(ecc.issued.key),
			trust,
		)
		require.Equal(t, ua.SecurityPolicyURIECCNistP256ChaChaPoly, c.SecurityPolicy())
	})

	t.Run("ServerConfiguration", func(t *testing.T) {
		// ECC_curve25519 needs an Ed25519 certificate, the nistP256
		// policies an ECDSA one.
		for name, opts := range map[string][]server.Option{
			"curve25519 with a P-256 certificate": {
				server.ApplicationIdentity(ecc.server[curveP256].cert, ecc.server[curveP256].key),
				server.EnableSecurity(ua.SecurityPolicyURIECCCurve25519, ua.MessageSecurityModeSignAndEncrypt),
			},
			"AesGcm with an Ed25519 certificate": {
				server.ApplicationIdentity(ecc.server[curveEd25519].cert, ecc.server[curveEd25519].key),
				server.EnableSecurity(ua.SecurityPolicyURIECCNistP256AesGcm, ua.MessageSecurityModeSignAndEncrypt),
			},
			"ChaChaPoly with an RSA certificate": {
				server.Certificate(p.ServerCert), server.PrivateKey(p.ServerKey),
				server.EnableSecurity(ua.SecurityPolicyURIECCNistP256ChaChaPoly, ua.MessageSecurityModeSign),
			},
		} {
			srv, err := server.New(append([]server.Option{server.InsecureNoSecurity()}, append([]server.Option{server.EndPoint("localhost", 0), server.EnableAuthMode(ua.UserTokenTypeAnonymous)}, opts...)...)...)
			require.NoError(t, err, name)
			err = srv.Start(ctx)
			require.Error(t, err, name)
			require.Contains(t, err.Error(), "ECC application instance certificate", name)
			_ = srv.Close()
		}
	})

	t.Run("OnlyEnabledPoliciesAccepted", func(t *testing.T) {
		// The server offers ECC_nistP256_AesGcm in SignAndEncrypt mode only.
		// Its certificate could serve other policies too, but the operator
		// did not enable them: a client cannot pick another policy or mode.
		id := ecc.server[curveP256]
		srv, err := server.New(
			server.EndPoint("localhost", 0),
			server.ApplicationIdentity(id.cert, id.key),
			server.EnableSecurity(ua.SecurityPolicyURIECCNistP256AesGcm, ua.MessageSecurityModeSignAndEncrypt),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		)
		require.NoError(t, err)
		require.NoError(t, srv.Start(ctx))
		t.Cleanup(func() { _ = srv.Close() })
		only := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())

		secure := func(policy string, mode ua.MessageSecurityMode) []opcua.Option {
			return []opcua.Option{
				opcua.SecurityPolicy(policy),
				opcua.SecurityMode(mode),
				opcua.RemoteCertificate(id.cert),
				opcua.Certificate(ecc.client[curveP256].cert),
				opcua.PrivateKeySigner(ecc.client[curveP256].key),
				opcua.TrustedCertificates(id.x509),
			}
		}
		_, err = dialClient(t, only, secure(ua.SecurityPolicyURIECCNistP256AesGcm, ua.MessageSecurityModeSignAndEncrypt)...)
		require.NoError(t, err)
		for _, policy := range []string{ua.SecurityPolicyURIECCNistP256ChaChaPoly, ua.SecurityPolicyURIECCNistP256} {
			_, err = dialClient(t, only, secure(policy, ua.MessageSecurityModeSignAndEncrypt)...)
			require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected, policy)
		}
		_, err = dialClient(t, only, secure(ua.SecurityPolicyURIECCNistP256AesGcm, ua.MessageSecurityModeSign)...)
		require.ErrorIs(t, err, ua.StatusBadSecurityModeRejected)
	})

	t.Run("AllFamiliesSideBySide", func(t *testing.T) {
		// One server, a client per family of policies, all at once.
		f, url := aeadServer(t)
		rsaEP := endpointFor(t, url, ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt)
		cbcEP := endpointFor(t, url, ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSignAndEncrypt)
		clients := []*opcua.Client{
			newClient(t, url, secureClientOpts(t, rsaEP, ua.UserTokenTypeAnonymous)...),
			newClient(t, url, eccClientOpts(t, cbcEP, curveP384, ua.UserTokenTypeAnonymous)...),
		}
		for _, pol := range aeadPolicies {
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			clients = append(clients, newClient(t, url, eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous)...))
		}
		for i, c := range clients {
			writeInt32(t, c, f.Writable, int32(500+i))
			for _, other := range clients {
				dv, err := other.ReadValue(ctx, f.Writable)
				require.NoError(t, err)
				require.Equal(t, int32(500+i), dv.Value.Value())
			}
		}
	})
}

// TestAEAD_ReverseConnect opens AEAD channels over connections the server
// initiated. Nothing about the security of a channel depends on who opened
// the socket.
func TestAEAD_ReverseConnect(t *testing.T) {
	l, clientURL := reverseListener(t, nil)
	srv, url := newServer(t, aeadServerOpts(t, server.WithReverseConnect(clientURL, fastReverseRetry))...)
	f := testutil.AddFixture(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	reverse := opcua.ReverseConnectListener(l, opcua.ReverseServerURI(serverAppURI))
	eps, err := opcua.GetEndpoints(ctx, url, reverse, opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(30*time.Second))
	require.NoError(t, err)

	for _, pol := range aeadPolicies {
		t.Run(shortPolicy(pol.uri), func(t *testing.T) {
			var ep *ua.EndpointDescription
			for _, e := range eps {
				if e.SecurityPolicyURI == pol.uri && e.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
					ep = e
				}
			}
			require.NotNil(t, ep, "endpoint advertised")

			c := newClient(t, url, append(eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous), reverse)...)
			require.Equal(t, pol.uri, c.SecurityPolicy())

			want := "reverse-" + shortPolicy(pol.uri)
			st, err := c.WriteNodeValue(ctx, f.String, want)
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, st)
			dv, err := c.ReadValue(ctx, f.String)
			require.NoError(t, err)
			require.Equal(t, want, dv.Value.Value())

			sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
			require.NoError(t, err)
			awaitValue(t, ch, 0, int32(42))
			require.NoError(t, sub.Cancel(ctx))
			require.NoError(t, c.Close(ctx))
		})
	}
}

// TestAEAD_DiscoveryRegistration registers servers with a Local Discovery
// Server over the AEAD policies. A registering server uses the endpoint of
// the discovery server that its own certificate fits, and that certificate.
func TestAEAD_DiscoveryRegistration(t *testing.T) {
	ecc := pki(t).ecc
	lds, ldsURL := newServer(t, aeadServerOpts(t, server.WithLocalDiscoveryServer())...)
	registeredHere := func() []string {
		var out []string
		for _, rs := range lds.RegisteredServers() {
			out = append(out, rs.ServerURI)
		}
		return out
	}

	for _, tt := range []struct {
		name     string
		identity *eccIdentity
		uri      string
		extra    []server.RegistrationOption
		policy   string
	}{
		// The best endpoint of the discovery server needs an Ed25519
		// certificate; a server with a P-256 certificate takes the best one
		// it can use.
		{"P-256 certificate", ecc.client[curveP256], clientAppURI, nil, ua.SecurityPolicyURIECCNistP256ChaChaPoly},
		{"Ed25519 certificate", ecc.edUser, "urn:otfabric:conformance:user", nil, ua.SecurityPolicyURIECCCurve25519},
		{"pinned policy", ecc.issued, clientAppURI,
			[]server.RegistrationOption{server.RegisterSecurity("ECC_nistP256_AesGcm", ua.MessageSecurityModeSignAndEncrypt)},
			ua.SecurityPolicyURIECCNistP256AesGcm},
	} {
		// One after the other: two of the registrants share an application URI.
		var log conformkit.RegistrationLog
		opts := append([]server.RegistrationOption{
			server.RegisterEventHandler(log.Handle),
			server.RegisterRequestTimeout(30 * time.Second),
		}, tt.extra...)
		a, _ := newServer(t,
			server.ApplicationIdentity(tt.identity.cert, tt.identity.key),
			server.WithDiscoveryRegistration(ldsURL, opts...),
		)
		eventually(t, func() bool { return log.Count(conformkit.Registered) > 0 }, tt.name+": registers with the LDS")
		ev := log.Snapshot()[0]
		require.Equal(t, tt.policy, ev.SecurityPolicyURI, tt.name)
		require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, ev.SecurityMode, tt.name)
		require.Contains(t, registeredHere(), tt.uri, tt.name)
		require.NoError(t, a.Close())
		require.NotContains(t, registeredHere(), tt.uri, tt.name)
	}

	// A server whose certificate fits no secured endpoint of the discovery
	// server cannot register over a secured channel.
	only, onlyURL := newServer(t,
		server.ApplicationIdentity(ecc.server[curveEd25519].cert, ecc.server[curveEd25519].key),
		server.EnableSecurity(ua.SecurityPolicyURIECCCurve25519, ua.MessageSecurityModeSignAndEncrypt),
		server.WithLocalDiscoveryServer(),
	)
	var log conformkit.RegistrationLog
	a, _ := newServer(t,
		server.ApplicationIdentity(ecc.client[curveP256].cert, ecc.client[curveP256].key),
		server.WithDiscoveryRegistration(onlyURL,
			server.RegisterEventHandler(log.Handle),
			server.RegisterBackoff(10*time.Millisecond, 50*time.Millisecond),
		),
	)
	eventually(t, func() bool {
		return log.Count(func(e server.RegistrationEvent) bool { return e.Err != nil }) > 0
	}, "the registration fails")
	require.ErrorIs(t, log.Snapshot()[0].Err, ua.StatusBadSecurityModeRejected)
	require.Empty(t, only.RegisteredServers())
	require.NoError(t, a.Close())
}
