// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

func testECCIdentity(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	u, _ := url.Parse("urn:otfabric:server:test")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "server ecc test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}

// eccSessionFixture is a session service with the server end of an ECC
// SecureChannel, and the keys of the client at the other end.
type eccSessionFixture struct {
	t          *testing.T
	policy     string
	svc        *SessionService
	sc         *uasc.SecureChannel
	clientKey  *ecdsa.PrivateKey
	clientCert []byte
	serverKey  *ecdsa.PrivateKey
	serverCert []byte
	client     *uasc.SecureChannel // the client's view, for its crypto helpers
	passwords  []string
	tokens     []ua.IdentityToken
}

func newECCSessionFixture(t *testing.T) *eccSessionFixture {
	t.Helper()
	f := &eccSessionFixture{t: t, policy: ua.SecurityPolicyURIECCNistP256}
	f.clientKey, f.clientCert = testECCIdentity(t, elliptic.P256())
	f.serverKey, f.serverCert = testECCIdentity(t, elliptic.P256())

	srv := newTestServer()
	srv.cfg.certificate = f.serverCert
	srv.cfg.identities = []applicationIdentity{{certificate: f.serverCert, key: f.serverKey}}
	srv.cfg.usernameValidator = func(user, pass string) error {
		f.passwords = append(f.passwords, pass)
		if user == "alice" && pass == "wonderland" {
			return nil
		}
		return ua.StatusBadUserAccessDenied
	}
	srv.cfg.issuedTokenValidator = func(tok *ua.IssuedIdentityToken) error {
		if string(tok.TokenData) == "jwt" { // the decrypted token
			return nil
		}
		return ua.StatusBadIdentityTokenRejected
	}
	srv.cfg.roleMapper = func(tok ua.IdentityToken) []*ua.NodeID {
		f.tokens = append(f.tokens, tok)
		return DefaultRoleMapper(tok)
	}
	f.svc = &SessionService{srv: srv}
	f.sc = uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: f.policy,
		Certificate:       f.serverCert,
		LocalPrivateKey:   f.serverKey,
		RemoteCertificate: f.clientCert,
	})
	f.client = uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: f.policy,
		Certificate:       f.clientCert,
		LocalPrivateKey:   f.clientKey,
		RemoteCertificate: f.serverCert,
	})
	return f
}

// create runs CreateSession, optionally asking for an ephemeral key.
func (f *eccSessionFixture) create(ecdhPolicy string) (*ua.CreateSessionResponse, error) {
	hdr := reqHeader()
	if ecdhPolicy != "" {
		hdr.AdditionalHeader = uasc.NewECDHPolicyHeader(ecdhPolicy)
	}
	resp, err := f.svc.CreateSession(context.Background(), f.sc, &ua.CreateSessionRequest{
		RequestHeader:           hdr,
		EndpointURL:             "opc.tcp://localhost:4840",
		RequestedSessionTimeout: 5000,
		ClientNonce:             []byte("0123456789abcdef0123456789abcdef"),
		ClientCertificate:       f.clientCert,
	}, 1)
	if err != nil {
		return nil, err
	}
	return resp.(*ua.CreateSessionResponse), nil
}

// ephemeralKey returns the verified ephemeral key of a response header, or
// nil if it carries none.
func (f *eccSessionFixture) ephemeralKey(hdr *ua.ResponseHeader) []byte {
	f.t.Helper()
	key, err := uasc.ECDHKeyFromHeader(hdr.AdditionalHeader)
	require.NoError(f.t, err)
	if key == nil {
		return nil
	}
	uri, ok := uasc.ECDHPolicyFromHeader(hdr.AdditionalHeader)
	require.True(f.t, ok)
	require.Equal(f.t, f.policy, uri)
	require.NoError(f.t, f.client.VerifyEphemeralKeySignature("", f.serverCert, key.PublicKey, key.Signature))
	return key.PublicKey
}

// activate runs ActivateSession with the token. nonce is the server nonce the
// client signature is made over.
func (f *eccSessionFixture) activate(auth *ua.NodeID, nonce []byte, token any, ecdhPolicy string) (*ua.ActivateSessionResponse, error) {
	f.t.Helper()
	sig, alg, err := f.client.NewSessionSignature(f.serverCert, nonce)
	require.NoError(f.t, err)
	hdr := &ua.RequestHeader{RequestHandle: 2, AuthenticationToken: auth}
	if ecdhPolicy != "" {
		hdr.AdditionalHeader = uasc.NewECDHPolicyHeader(ecdhPolicy)
	}
	resp, err := f.svc.ActivateSession(context.Background(), f.sc, &ua.ActivateSessionRequest{
		RequestHeader:     hdr,
		ClientSignature:   &ua.SignatureData{Signature: sig, Algorithm: alg},
		UserIdentityToken: ua.NewExtensionObject(token),
	}, 2)
	if err != nil {
		return nil, err
	}
	return resp.(*ua.ActivateSessionResponse), nil
}

func (f *eccSessionFixture) username(password string, key, nonce []byte) *ua.UserNameIdentityToken {
	f.t.Helper()
	secret, err := f.client.EncryptUserSecret("", []byte(password), key, nonce)
	require.NoError(f.t, err)
	return &ua.UserNameIdentityToken{UserName: "alice", Password: secret}
}

func TestSessionService_ECC_EphemeralKeyLifecycle(t *testing.T) {
	f := newECCSessionFixture(t)

	// CreateSession hands out a signed key, asked for or not.
	cs, err := f.create("")
	require.NoError(t, err)
	require.Equal(t, f.serverCert, cs.ServerCertificate)
	require.NoError(t, f.client.VerifySessionSignature(f.serverCert, []byte("0123456789abcdef0123456789abcdef"), cs.ServerSignature.Signature))
	key1 := f.ephemeralKey(cs.ResponseHeader)
	require.Len(t, key1, 64)

	asked, err := f.create(f.policy)
	require.NoError(t, err)
	require.Len(t, f.ephemeralKey(asked.ResponseHeader), 64)

	// First activation: the password is encrypted for key1. The client does
	// not ask for a new key, but the old one is spent: a new one comes back.
	as, err := f.activate(cs.AuthenticationToken, cs.ServerNonce, f.username("wonderland", key1, cs.ServerNonce), "")
	require.NoError(t, err)
	require.Equal(t, []string{"wonderland"}, f.passwords)
	key2 := f.ephemeralKey(as.ResponseHeader)
	require.Len(t, key2, 64)
	require.NotEqual(t, key1, key2)

	// The role mapper got the clear text token.
	tok, ok := f.tokens[len(f.tokens)-1].(*ua.UserNameIdentityToken)
	require.True(t, ok)
	require.Equal(t, "wonderland", string(tok.Password))
	require.Empty(t, tok.EncryptionAlgorithm)

	// An anonymous activation does not use the key: without a request the
	// server keeps it and returns nothing.
	as2, err := f.activate(cs.AuthenticationToken, as.ServerNonce, &ua.AnonymousIdentityToken{}, "")
	require.NoError(t, err)
	require.Nil(t, f.ephemeralKey(as2.ResponseHeader))

	// key2 is therefore still good, and this time the client asks for the next.
	as3, err := f.activate(cs.AuthenticationToken, as2.ServerNonce, f.username("wonderland", key2, as2.ServerNonce), f.policy)
	require.NoError(t, err)
	key3 := f.ephemeralKey(as3.ResponseHeader)
	require.Len(t, key3, 64)
	require.NotEqual(t, key2, key3)

	// A wrong password is refused after decryption, and spends the key.
	_, err = f.activate(cs.AuthenticationToken, as3.ServerNonce, f.username("guess", key3, as3.ServerNonce), "")
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, err = f.activate(cs.AuthenticationToken, as3.ServerNonce, f.username("wonderland", key3, as3.ServerNonce), "")
	require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid, "no second secret for the same ephemeral key")
}

func TestSessionService_ECC_SecretRejections(t *testing.T) {
	t.Run("replay of an earlier activation", func(t *testing.T) {
		f := newECCSessionFixture(t)
		cs, err := f.create(f.policy)
		require.NoError(t, err)
		key := f.ephemeralKey(cs.ResponseHeader)
		token := f.username("wonderland", key, cs.ServerNonce)
		recorded := append([]byte(nil), token.Password...) // what an eavesdropper keeps

		as, err := f.activate(cs.AuthenticationToken, cs.ServerNonce, token, f.policy)
		require.NoError(t, err)

		// The recorded token again: made for the previous key and nonce.
		replay := &ua.UserNameIdentityToken{UserName: "alice", Password: recorded}
		_, err = f.activate(cs.AuthenticationToken, as.ServerNonce, replay, "")
		require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)
		require.Equal(t, []string{"wonderland"}, f.passwords, "the validator never saw the replayed secret")
	})

	t.Run("stale nonce", func(t *testing.T) {
		f := newECCSessionFixture(t)
		cs, err := f.create(f.policy)
		require.NoError(t, err)
		key := f.ephemeralKey(cs.ResponseHeader)
		_, err = f.activate(cs.AuthenticationToken, cs.ServerNonce, f.username("wonderland", key, []byte("not the nonce of this session....")), "")
		require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)
		require.Empty(t, f.passwords)
	})

	t.Run("clear text password", func(t *testing.T) {
		// On an ECC channel a password is an EccEncryptedSecret or nothing:
		// an empty EncryptionAlgorithm does not make clear text acceptable.
		f := newECCSessionFixture(t)
		cs, err := f.create(f.policy)
		require.NoError(t, err)
		_, err = f.activate(cs.AuthenticationToken, cs.ServerNonce, &ua.UserNameIdentityToken{UserName: "alice", Password: []byte("wonderland")}, "")
		require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)
		require.Empty(t, f.passwords)
	})

	t.Run("signed by another application", func(t *testing.T) {
		f := newECCSessionFixture(t)
		cs, err := f.create(f.policy)
		require.NoError(t, err)
		key := f.ephemeralKey(cs.ResponseHeader)

		otherKey, otherCert := testECCIdentity(t, elliptic.P256())
		other := uasc.NewCryptoChannel(&uasc.Config{SecurityPolicyURI: f.policy, Certificate: otherCert, LocalPrivateKey: otherKey})
		secret, err := other.EncryptUserSecret("", []byte("wonderland"), key, cs.ServerNonce)
		require.NoError(t, err)
		_, err = f.activate(cs.AuthenticationToken, cs.ServerNonce, &ua.UserNameIdentityToken{UserName: "alice", Password: secret}, "")
		require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)
		require.Empty(t, f.passwords)
	})

	t.Run("issued token", func(t *testing.T) {
		f := newECCSessionFixture(t)
		cs, err := f.create(f.policy)
		require.NoError(t, err)
		key := f.ephemeralKey(cs.ResponseHeader)

		data, err := f.client.EncryptUserSecret("", []byte("jwt"), key, cs.ServerNonce)
		require.NoError(t, err)
		as, err := f.activate(cs.AuthenticationToken, cs.ServerNonce, &ua.IssuedIdentityToken{TokenData: data}, f.policy)
		require.NoError(t, err)
		tok, ok := f.tokens[len(f.tokens)-1].(*ua.IssuedIdentityToken)
		require.True(t, ok)
		require.Equal(t, "jwt", string(tok.TokenData))

		// Clear text token data is refused.
		_, err = f.activate(cs.AuthenticationToken, as.ServerNonce, &ua.IssuedIdentityToken{TokenData: []byte("jwt")}, "")
		require.ErrorIs(t, err, ua.StatusBadIdentityTokenInvalid)
	})
}

func TestSessionService_ECC_EphemeralKeyRequests(t *testing.T) {
	f := newECCSessionFixture(t)

	// A key can only be had for the policy of the channel.
	for _, uri := range []string{
		ua.SecurityPolicyURIECCNistP384,
		ua.SecurityPolicyURIBasic256Sha256,
		ua.SecurityPolicyURINone,
		"http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519",
		"not a policy",
	} {
		_, err := f.create(uri)
		require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected, uri)
	}

	cs, err := f.create(f.policy)
	require.NoError(t, err)
	_, err = f.activate(cs.AuthenticationToken, cs.ServerNonce, &ua.AnonymousIdentityToken{}, ua.SecurityPolicyURIBasic256Sha256)
	require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)

	// No channel, no key (and no panic).
	hdr := responseHeader(1, ua.StatusOK)
	require.Equal(t, ua.StatusOK, f.svc.issueEphemeralKey(nil, &session{}, reqHeader(), hdr, true))
	require.Equal(t, ua.SecurityPolicyURINone, f.svc.userTokenPolicy(nil))
	_, st := f.svc.decryptEccSecret(nil, &session{}, nil, nil)
	require.Equal(t, ua.StatusBadIdentityTokenInvalid, st)

	// An RSA or unsecured channel never hands out a key unasked, and refuses
	// to hand one out when asked.
	none := scNone()
	require.Equal(t, ua.StatusOK, f.svc.issueEphemeralKey(none, &session{}, reqHeader(), hdr, true))
	asked := reqHeader()
	asked.AdditionalHeader = uasc.NewECDHPolicyHeader(f.policy)
	require.Equal(t, ua.StatusBadSecurityPolicyRejected, f.svc.issueEphemeralKey(none, &session{}, asked, hdr, true))

	// A channel whose key cannot sign for the policy.
	keyless := uasc.NewCryptoChannel(&uasc.Config{SecurityPolicyURI: f.policy, SecurityMode: ua.MessageSecurityModeSign})
	require.Equal(t, ua.StatusBadInternalError, f.svc.issueEphemeralKey(keyless, &session{}, reqHeader(), hdr, true))
	require.Equal(t, f.serverCert, f.svc.serverCertificate(keyless), "falls back to the server's default certificate")
}

func TestServerConfig_ApplicationIdentities(t *testing.T) {
	rsaKey, rsaCert := testUserCert(t)
	p256Key, p256Cert := testECCIdentity(t, elliptic.P256())
	p384Key, p384Cert := testECCIdentity(t, elliptic.P384())

	apply := func(opts ...Option) *serverConfig {
		cfg := &serverConfig{}
		for _, opt := range opts {
			require.NoError(t, opt(cfg))
		}
		return cfg
	}
	identity := func(cfg *serverConfig, uri string) ([]byte, crypto.Signer) {
		cert, key, ok := cfg.identityFor(uri)
		require.True(t, ok, uri)
		return cert, key
	}

	t.Run("rsa and ecc", func(t *testing.T) {
		cfg := apply(
			Certificate(rsaCert), PrivateKey(rsaKey),
			ApplicationIdentity(p256Cert, p256Key),
			ApplicationIdentity(p384Cert, p384Key),
		)
		cert, key := identity(cfg, ua.SecurityPolicyURIBasic256Sha256)
		require.Equal(t, rsaCert, cert)
		require.Equal(t, crypto.Signer(rsaKey), key)

		cert, key = identity(cfg, ua.SecurityPolicyURIECCNistP256)
		require.Equal(t, p256Cert, cert)
		require.Equal(t, crypto.Signer(p256Key), key)

		cert, key = identity(cfg, ua.SecurityPolicyURIECCNistP384)
		require.Equal(t, p384Cert, cert)
		require.Equal(t, crypto.Signer(p384Key), key)

		cert, _ = identity(cfg, ua.SecurityPolicyURINone)
		require.Equal(t, rsaCert, cert)

		require.Equal(t, p384Cert, cfg.certificateFor(ua.SecurityPolicyURIECCNistP384))
		require.Equal(t, rsaCert, cfg.certificateFor("urn:unknown"), "an unknown policy falls back to the default certificate")
	})

	t.Run("ecc only", func(t *testing.T) {
		cfg := apply(ApplicationIdentity(p384Cert, p384Key))
		require.Equal(t, p384Cert, cfg.certificate, "the first identity is the default certificate")
		require.Equal(t, "urn:otfabric:server:test", cfg.applicationURI)
		require.Nil(t, cfg.privateKey)

		// P-384 serves both ECC policies; nothing serves RSA.
		cert, _ := identity(cfg, ua.SecurityPolicyURIECCNistP256)
		require.Equal(t, p384Cert, cert)
		_, _, ok := cfg.identityFor(ua.SecurityPolicyURIBasic256Sha256)
		require.False(t, ok)
		cert, key, ok := cfg.identityFor(ua.SecurityPolicyURINone)
		require.True(t, ok)
		require.Equal(t, p384Cert, cert)
		require.Nil(t, key, "no typed nil for an unset RSA key")
	})

	t.Run("rsa through ApplicationIdentity", func(t *testing.T) {
		cfg := apply(ApplicationIdentity(rsaCert, rsaKey))
		require.Equal(t, rsaKey, cfg.privateKey)
		cert, key := identity(cfg, ua.SecurityPolicyURIAes256Sha256RsaPss)
		require.Equal(t, rsaCert, cert)
		require.Equal(t, crypto.Signer(rsaKey), key)
	})

	t.Run("invalid", func(t *testing.T) {
		cfg := &serverConfig{}
		require.Error(t, ApplicationIdentity([]byte("junk"), p256Key)(cfg))
		require.Error(t, ApplicationIdentity(p256Cert, p384Key)(cfg))
		require.Error(t, ApplicationIdentity(p256Cert, nil)(cfg))
		require.Empty(t, cfg.identities)
	})

	t.Run("localIdentity", func(t *testing.T) {
		cfg := apply(Certificate(rsaCert), PrivateKey(rsaKey), ApplicationIdentity(p256Cert, p256Key))

		// Without EnableSecurity nothing is restricted.
		cert, key, err := cfg.localIdentity(ua.SecurityPolicyURIECCNistP256)
		require.NoError(t, err)
		require.Equal(t, p256Cert, cert)
		require.Equal(t, crypto.Signer(p256Key), key)

		// No certificate for the policy.
		_, _, err = cfg.localIdentity(ua.SecurityPolicyURIECCNistP384)
		require.Error(t, err)

		// With EnableSecurity only the enabled policies get a certificate.
		require.NoError(t, EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSign)(cfg))
		_, _, err = cfg.localIdentity(ua.SecurityPolicyURIECCNistP256)
		require.NoError(t, err)
		_, _, err = cfg.localIdentity(ua.SecurityPolicyURIBasic256Sha256)
		require.Error(t, err, "not enabled, although the RSA certificate could serve it")
	})
}

func TestSessionService_decryptUserPassword_RSAIdentity(t *testing.T) {
	// The RSA path picks the server key through the identity table too.
	rsaKey, rsaCert := testUserCert(t)
	srv := newTestServer()
	srv.cfg.certificate = rsaCert
	srv.cfg.privateKey = rsaKey
	svc := &SessionService{srv: srv}
	sc := uasc.NewCryptoChannel(&uasc.Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
	})
	nonce := []byte("0123456789abcdef0123456789abcdef")
	enc, alg, err := sc.EncryptUserPassword("", "pw", rsaCert, nonce)
	require.NoError(t, err)

	got, st := svc.decryptUserPassword(sc, &session{}, &ua.UserNameIdentityToken{Password: enc, EncryptionAlgorithm: alg}, nonce)
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, "pw", string(got))

	// A server without a key for the policy cannot decrypt.
	srv.cfg.privateKey = nil
	_, st = svc.decryptUserPassword(sc, &session{}, &ua.UserNameIdentityToken{Password: enc, EncryptionAlgorithm: alg}, nonce)
	require.Equal(t, ua.StatusBadIdentityTokenInvalid, st)
}
