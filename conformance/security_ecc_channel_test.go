// SPDX-License-Identifier: MIT

package conformance

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// wireProxy sits between a client and the server and shows every UACP message
// to a hook, which may record or change it. The OpenSecureChannel messages of
// the ECC policies are signed but not encrypted, so the proxy can read them.
type wireProxy struct {
	ln      net.Listener
	mu      sync.Mutex
	backend string

	// hook is called for every message with its direction ("c2s" or "s2c")
	// and returns the bytes to forward.
	hook func(dir string, msg []byte) []byte
}

func startWireProxy(t *testing.T, hook func(dir string, msg []byte) []byte) *wireProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	p := &wireProxy{ln: ln, hook: hook}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			backend := p.backend
			p.mu.Unlock()
			srv, err := net.DialTimeout("tcp", backend, 5*time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			pipe := func(dir string, from, to net.Conn) {
				defer func() { _ = from.Close(); _ = to.Close() }()
				hdr := make([]byte, 8)
				for {
					if _, err := io.ReadFull(from, hdr); err != nil {
						return
					}
					size := binary.LittleEndian.Uint32(hdr[4:])
					if size < 8 || size > 1<<24 {
						return
					}
					msg := make([]byte, size)
					copy(msg, hdr)
					if _, err := io.ReadFull(from, msg[8:]); err != nil {
						return
					}
					if _, err := to.Write(p.hook(dir, msg)); err != nil {
						return
					}
				}
			}
			go pipe("c2s", client, srv)
			go pipe("s2c", srv, client)
		}
	}()
	return p
}

func (p *wireProxy) port() int { return p.ln.Addr().(*net.TCPAddr).Port }

// proxiedECCServer starts a server behind a wire proxy. The server advertises
// the proxy's port (it validates the endpoint URL of the Hello message).
func proxiedECCServer(t *testing.T, hook func(dir string, msg []byte) []byte, extra ...server.Option) (*testutil.Fixture, string) {
	t.Helper()
	parallel(t)
	proxy := startWireProxy(t, hook)
	opts := append([]server.Option{
		server.EndPoint("localhost", proxy.port()),
		server.ListenOn("localhost:0"),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}, mixedServerOpts(t, extra...)...)
	srv, err := server.New(opts...)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	proxy.mu.Lock()
	proxy.backend = fmt.Sprintf("localhost:%d", srv.Port())
	proxy.mu.Unlock()
	return testutil.AddFixture(t, srv), fmt.Sprintf("opc.tcp://localhost:%d", proxy.port())
}

// testECCRenewalUnderTraffic (run by TestTokenRenewal) renews an ECC SecureChannel every second while
// reads, writes and a subscription keep running. Every renewal negotiates
// fresh ephemeral keys on both sides and issues a new SecurityToken.
func testECCRenewalUnderTraffic(t *testing.T) {
	for _, pol := range eccPolicies {
		t.Run(shortPolicy(pol.uri), func(t *testing.T) {
			var mu sync.Mutex
			var requests, responses [][]byte // OpenSecureChannel messages on the secured channel
			var tokenIDs []uint32            // token id of every server MSG chunk
			marker := []byte(pol.uri)
			f, url := proxiedECCServer(t, func(dir string, msg []byte) []byte {
				mu.Lock()
				defer mu.Unlock()
				switch string(msg[:3]) {
				case "OPN":
					if !bytes.Contains(msg, marker) {
						break // the discovery channel
					}
					if dir == "c2s" {
						requests = append(requests, append([]byte(nil), msg...))
					} else {
						responses = append(responses, append([]byte(nil), msg...))
					}
				case "MSG":
					if dir == "s2c" && len(msg) >= 16 {
						tokenIDs = append(tokenIDs, binary.LittleEndian.Uint32(msg[12:16]))
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

			sub, notifyCh, err := c.NewSubscription().
				Interval(50 * time.Millisecond).
				Monitor(f.Writable).
				Start(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

			opens := func() int {
				mu.Lock()
				defer mu.Unlock()
				return len(responses)
			}

			deadline := time.Now().Add(30 * time.Second)
			var written int32
			for opens() < 4 { // issue + 3 renewals
				require.True(t, time.Now().Before(deadline), "only %d OpenSecureChannel responses within 30s", opens())
				written++
				writeInt32(t, c, f.Writable, written)
				dv, err := c.ReadValue(ctx, f.Writable)
				require.NoError(t, err)
				require.Equal(t, written, dv.Value.Value())
				time.Sleep(20 * time.Millisecond)
			}
			awaitInt32Change(t, notifyCh, written)

			mu.Lock()
			defer mu.Unlock()

			// The messages are signed, not encrypted: the policy URI and the
			// certificates are readable, and nothing is padded to an RSA block.
			n := uapolicy.Thumbprint(pki(t).ecc.server[pol.curve].cert)
			for _, req := range requests {
				require.Contains(t, string(req), pol.uri)
				require.True(t, bytes.Contains(req, n), "request names the server certificate by thumbprint")
			}

			// Every exchange carries a different nonce in each direction: the
			// ephemeral keys are never reused. The signature covers the nonce,
			// so equal keys would show as equal messages only by accident;
			// compare the nonces themselves, which follow the fixed header.
			seen := map[string]bool{}
			for _, msg := range append(append([][]byte{}, requests...), responses...) {
				key := string(msg[len(msg)-200:]) // nonce and signature
				require.False(t, seen[key], "an OpenSecureChannel message was repeated")
				seen[key] = true
			}

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
		})
	}
}

// TestECC_TamperedMessagesRejected flips one bit in a signed message on the
// wire and expects the receiver to refuse it.
func TestECC_TamperedMessagesRejected(t *testing.T) {
	marker := []byte(ua.SecurityPolicyURIECCNistP256)
	connect := func(t *testing.T, url string, mode ua.MessageSecurityMode) (*opcua.Client, error) {
		ep := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256, mode)
		return dialClient(t, url, eccClientOpts(t, ep, curveP256, ua.UserTokenTypeAnonymous)...)
	}

	for _, tt := range []struct {
		name string
		dir  string
		// offset from the end of the message of the byte to change
		fromEnd int
	}{
		{"RequestSignature", "c2s", 1},
		{"RequestNonce", "c2s", 64 + 20}, // inside the client's ephemeral public key
		{"ResponseSignature", "s2c", 1},
		{"ResponseNonce", "s2c", 64 + 20},
	} {
		t.Run("OpenSecureChannel"+tt.name, func(t *testing.T) {
			var once sync.Once
			_, url := proxiedECCServer(t, func(dir string, msg []byte) []byte {
				if dir == tt.dir && string(msg[:3]) == "OPN" && bytes.Contains(msg, marker) {
					once.Do(func() { msg[len(msg)-tt.fromEnd] ^= 0x01 })
				}
				return msg
			})
			_, err := connect(t, url, ua.MessageSecurityModeSignAndEncrypt)
			require.Error(t, err, "a channel must not open on a forged OpenSecureChannel message")
		})
	}

	t.Run("SignedServiceMessage", func(t *testing.T) {
		// In Sign mode the service messages are readable. Change one byte of
		// the first response after the session is up.
		var mu sync.Mutex
		armed, done := false, false
		f, url := proxiedECCServer(t, func(dir string, msg []byte) []byte {
			mu.Lock()
			defer mu.Unlock()
			if armed && !done && dir == "s2c" && string(msg[:3]) == "MSG" {
				done = true
				msg[len(msg)-40] ^= 0x01 // in the body, before the 32 byte HMAC
			}
			return msg
		})
		c, err := connect(t, url, ua.MessageSecurityModeSign)
		require.NoError(t, err)
		dv, err := c.ReadValue(context.Background(), f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())

		mu.Lock()
		armed = true
		mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = c.ReadValue(ctx, f.Int32)
		require.Error(t, err, "a response with a broken signature must not be delivered")
	})
}

// TestECC_MixedServer runs RSA and ECC clients against one server that has a
// certificate per key type.
func TestECC_MixedServer(t *testing.T) {
	p := pki(t)
	ecc := p.ecc
	f, url := mixedServer(t)
	ctx := context.Background()

	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)

	t.Run("EndpointsAdvertiseTheCertificateOfTheirPolicy", func(t *testing.T) {
		levels := map[string]uint8{}
		for _, ep := range eps {
			switch ep.SecurityPolicyURI {
			case ua.SecurityPolicyURINone:
				require.Equal(t, p.serverCert, ep.ServerCertificate)
			case ua.SecurityPolicyURIECCNistP256:
				require.Equal(t, ecc.server[curveP256].cert, ep.ServerCertificate)
			case ua.SecurityPolicyURIECCNistP384:
				require.Equal(t, ecc.server[curveP384].cert, ep.ServerCertificate)
			default:
				require.Equal(t, p.serverCert, ep.ServerCertificate, ep.SecurityPolicyURI)
			}
			require.Equal(t, serverAppURI, ep.Server.ApplicationURI)
			require.Equal(t, uapolicy.SecurityLevel(ep.SecurityPolicyURI, ep.SecurityMode), ep.SecurityLevel)
			if ep.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
				levels[ep.SecurityPolicyURI] = ep.SecurityLevel
			}
		}
		require.Len(t, eps, 1+2*(len(securePolicies)+len(eccPolicies)))
		// ECC ranks above RSA, and the stronger curve above the weaker.
		require.Greater(t, levels[ua.SecurityPolicyURIECCNistP256], levels[ua.SecurityPolicyURIAes256Sha256RsaPss])
		require.Greater(t, levels[ua.SecurityPolicyURIECCNistP384], levels[ua.SecurityPolicyURIECCNistP256])
	})

	t.Run("EndpointSelectionFollowsTheClientCertificate", func(t *testing.T) {
		// The best endpoint of the server needs a P-384 certificate.
		best, err := ua.SelectEndpoint(append([]*ua.EndpointDescription{}, eps...), "", ua.MessageSecurityModeInvalid)
		require.NoError(t, err)
		require.Equal(t, ua.SecurityPolicyURIECCNistP384, best.SecurityPolicyURI)

		for name, tt := range map[string]struct {
			cert   []byte
			policy string
			mode   ua.MessageSecurityMode
		}{
			"rsa":   {p.clientCert, ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt},
			"p256":  {ecc.client[curveP256].cert, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt},
			"p384":  {ecc.client[curveP384].cert, ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSignAndEncrypt},
			"nocrt": {nil, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone},
		} {
			ep, err := opcua.SelectEndpoint(eps, "", ua.MessageSecurityModeInvalid, tt.cert)
			require.NoError(t, err, name)
			require.Equal(t, tt.policy, ep.SecurityPolicyURI, name)
			require.Equal(t, tt.mode, ep.SecurityMode, name)
		}

		// A policy and mode can still be asked for.
		ep, err := opcua.SelectEndpoint(eps, "ECC_nistP256", ua.MessageSecurityModeSign, ecc.client[curveP384].cert)
		require.NoError(t, err)
		require.Equal(t, ua.SecurityPolicyURIECCNistP256, ep.SecurityPolicyURI)
		require.Equal(t, ua.MessageSecurityModeSign, ep.SecurityMode)

		// What the certificate cannot be used with is not offered.
		_, err = opcua.SelectEndpoint(eps, "ECC_nistP384", ua.MessageSecurityModeInvalid, ecc.client[curveP256].cert)
		require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)
		_, err = opcua.SelectEndpoint(eps, "Basic256Sha256", ua.MessageSecurityModeInvalid, ecc.client[curveP256].cert)
		require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)
		_, err = opcua.SelectEndpoint(nil, "", ua.MessageSecurityModeInvalid, nil)
		require.ErrorIs(t, err, errors.ErrNoEndpoints)
		_, err = opcua.SelectEndpoint([]*ua.EndpointDescription{{SecurityPolicyURI: "urn:unknown"}, nil}, "", ua.MessageSecurityModeInvalid, p.clientCert)
		require.ErrorIs(t, err, errors.ErrNoMatchingEndpoint)
	})

	t.Run("RSAAndECCClientsSideBySide", func(t *testing.T) {
		rsaEP, err := opcua.SelectEndpoint(eps, "", ua.MessageSecurityModeInvalid, p.clientCert)
		require.NoError(t, err)
		rsaClient := newClient(t, url, secureClientOpts(t, rsaEP, ua.UserTokenTypeAnonymous)...)

		eccEP, err := opcua.SelectEndpoint(eps, "", ua.MessageSecurityModeInvalid, ecc.client[curveP256].cert)
		require.NoError(t, err)
		eccClient := newClient(t, url, eccClientOpts(t, eccEP, curveP256, ua.UserTokenTypeAnonymous)...)

		// A P-384 certificate is permitted with ECC_nistP256 as well.
		p256EP := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt)
		p384Client := newClient(t, url, eccClientOpts(t, p256EP, curveP384, ua.UserTokenTypeAnonymous)...)

		for i, c := range []*opcua.Client{rsaClient, eccClient, p384Client} {
			writeInt32(t, c, f.Writable, int32(100+i))
			for _, other := range []*opcua.Client{rsaClient, eccClient, p384Client} {
				dv, err := other.ReadValue(ctx, f.Writable)
				require.NoError(t, err)
				require.Equal(t, int32(100+i), dv.Value.Value())
			}
		}
	})
}

// TestECC_CertificateAndPolicyMismatch covers the wrong key for the policy on
// either side.
func TestECC_CertificateAndPolicyMismatch(t *testing.T) {
	p := pki(t)
	ecc := p.ecc
	_, url := mixedServer(t)

	p256EP := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt)
	p384EP := endpointFor(t, url, ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSignAndEncrypt)
	rsaEP := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	trust := opcua.TrustedCertificates(p.serverCertX509, ecc.server[curveP256].x509, ecc.server[curveP384].x509)

	t.Run("P256CertificateOnP384Policy", func(t *testing.T) {
		_, err := dialClient(t, url, eccClientOpts(t, p384EP, curveP256, ua.UserTokenTypeAnonymous)...)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	})

	t.Run("RSACertificateOnECCPolicy", func(t *testing.T) {
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(p256EP, ua.UserTokenTypeAnonymous),
			opcua.Certificate(p.clientCert),
			opcua.PrivateKey(p.clientKey),
			trust,
		)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	})

	t.Run("ECCCertificateOnRSAPolicy", func(t *testing.T) {
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(rsaEP, ua.UserTokenTypeAnonymous),
			opcua.Certificate(ecc.client[curveP256].cert),
			opcua.PrivateKeySigner(ecc.client[curveP256].key),
			trust,
		)
		require.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
	})

	t.Run("KeyOfAnotherCertificate", func(t *testing.T) {
		// The certificate is fine, but the key that signs is not its key:
		// the server cannot verify the OpenSecureChannel request.
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(p256EP, ua.UserTokenTypeAnonymous),
			opcua.Certificate(ecc.client[curveP256].cert),
			opcua.PrivateKeySigner(ecc.stranger.key),
			trust,
		)
		require.Error(t, err)
	})

	t.Run("ServerCertificateOfAnotherPolicy", func(t *testing.T) {
		// A client that is told the P-384 certificate belongs to the P-256
		// endpoint talks to a server that signs with its P-256 key.
		_, err := dialClient(t, url,
			opcua.SecurityPolicy(ua.SecurityPolicyURIECCNistP256),
			opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
			opcua.RemoteCertificate(ecc.server[curveP384].cert),
			opcua.Certificate(ecc.client[curveP256].cert),
			opcua.PrivateKeySigner(ecc.client[curveP256].key),
			trust,
		)
		require.Error(t, err)
	})
}

// TestECC_CertificateTrust covers certificate validation on both sides with
// ECC certificates.
func TestECC_CertificateTrust(t *testing.T) {
	ecc := pki(t).ecc
	ctx := context.Background()

	t.Run("UntrustedServerCertificate", func(t *testing.T) {
		_, url := mixedServer(t)
		ep := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt)
		// The client trusts some other certificate, not the server's.
		_, err := dialClient(t, url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.Certificate(ecc.client[curveP256].cert),
			opcua.PrivateKeySigner(ecc.client[curveP256].key),
			opcua.TrustedCertificates(ecc.stranger.x509),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "server certificate validation failed")
	})

	t.Run("ClientTrustList", func(t *testing.T) {
		f, url := mixedServer(t, server.WithClientCertificateTrustList(ecc.caCert))
		ep := endpointFor(t, url, ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt)
		trust := opcua.TrustedCertificates(ecc.server[curveP256].x509)

		c := newClient(t, url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.Certificate(ecc.issued.cert),
			opcua.PrivateKeySigner(ecc.issued.key),
			trust,
		)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())

		// A self-signed ECC certificate is not issued by the trusted CA.
		_, err = dialClient(t, url, eccClientOpts(t, ep, curveP256, ua.UserTokenTypeAnonymous)...)
		require.ErrorIs(t, err, ua.StatusBadCertificateUntrusted)
	})
}

// TestECC_ServerConfiguration covers the server side of the certificate setup.
func TestECC_ServerConfiguration(t *testing.T) {
	parallel(t) // every server of this test listens on an OS-assigned port
	p := pki(t)
	ecc := p.ecc

	t.Run("ECCPolicyNeedsAnECCCertificate", func(t *testing.T) {
		srv, err := server.New(
			server.EndPoint("localhost", 0),
			server.Certificate(p.serverCert),
			server.PrivateKey(p.serverKey),
			server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		)
		require.NoError(t, err)
		err = srv.Start(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "ECC application instance certificate")
		_ = srv.Close()
	})

	t.Run("P256CertificateDoesNotServeP384", func(t *testing.T) {
		srv, err := server.New(
			server.EndPoint("localhost", 0),
			server.ApplicationIdentity(ecc.server[curveP256].cert, ecc.server[curveP256].key),
			server.EnableSecurity(ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSign),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		)
		require.NoError(t, err)
		require.Error(t, srv.Start(context.Background()))
		_ = srv.Close()
	})

	t.Run("KeyMustBelongToTheCertificate", func(t *testing.T) {
		_, err := server.New(
			server.EndPoint("localhost", 0),
			server.ApplicationIdentity(ecc.server[curveP256].cert, ecc.stranger.key),
		)
		require.Error(t, err)
		_, err = server.New(
			server.EndPoint("localhost", 0),
			server.ApplicationIdentity([]byte("not a certificate"), ecc.stranger.key),
		)
		require.Error(t, err)
	})

	t.Run("ECCOnlyServer", func(t *testing.T) {
		// No RSA certificate at all: the P-384 certificate serves both ECC
		// policies and is the certificate of the unsecured endpoint.
		id := ecc.server[curveP384]
		srv, url := newServer(t,
			server.ApplicationIdentity(id.cert, id.key),
			server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
			server.EnableSecurity(ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSignAndEncrypt),
		)
		f := testutil.AddFixture(t, srv)

		eps, err := opcua.GetEndpoints(context.Background(), url)
		require.NoError(t, err)
		require.Len(t, eps, 3)
		for _, ep := range eps {
			require.Equal(t, id.cert, ep.ServerCertificate)
			require.Equal(t, serverAppURI, ep.Server.ApplicationURI)
		}

		for _, pol := range eccPolicies {
			ep := endpointFor(t, url, pol.uri, ua.MessageSecurityModeSignAndEncrypt)
			c := newClient(t, url, eccClientOpts(t, ep, pol.curve, ua.UserTokenTypeAnonymous)...)
			dv, err := c.ReadValue(context.Background(), f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())
		}

		// An RSA policy is neither enabled nor possible.
		_, err = dialClient(t, url,
			opcua.SecurityPolicy(ua.SecurityPolicyURIBasic256Sha256),
			opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
			opcua.RemoteCertificate(p.serverCert),
			opcua.Certificate(p.clientCert),
			opcua.PrivateKey(p.clientKey),
			opcua.TrustedCertificates(p.serverCertX509),
		)
		require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)
	})

	t.Run("OnlyEnabledECCSecurityAccepted", func(t *testing.T) {
		// The server offers ECC_nistP384 only. It has a certificate that
		// could serve ECC_nistP256 too, but the operator did not enable it:
		// a client cannot talk the server down to the weaker policy or mode.
		id := ecc.server[curveP384]
		srv, err := server.New(
			server.EndPoint("localhost", 0),
			server.ApplicationIdentity(id.cert, id.key),
			server.EnableSecurity(ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSignAndEncrypt),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		)
		require.NoError(t, err)
		require.NoError(t, srv.Start(context.Background()))
		t.Cleanup(func() { _ = srv.Close() })
		url := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())

		secure := func(policy string, mode ua.MessageSecurityMode) []opcua.Option {
			return []opcua.Option{
				opcua.SecurityPolicy(policy),
				opcua.SecurityMode(mode),
				opcua.RemoteCertificate(id.cert),
				opcua.Certificate(ecc.client[curveP384].cert),
				opcua.PrivateKeySigner(ecc.client[curveP384].key),
				opcua.TrustedCertificates(id.x509),
			}
		}
		_, err = dialClient(t, url, secure(ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSignAndEncrypt)...)
		require.NoError(t, err)
		_, err = dialClient(t, url, secure(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt)...)
		require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)
		_, err = dialClient(t, url, secure(ua.SecurityPolicyURIECCNistP384, ua.MessageSecurityModeSign)...)
		require.ErrorIs(t, err, ua.StatusBadSecurityModeRejected)
		_, err = dialClient(t, url)
		require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)
	})
}
