// SPDX-License-Identifier: MIT

package opcua

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	goerrors "github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

func eccTestCert(t *testing.T, curve elliptic.Curve, usage x509.KeyUsage) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ecc config test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}

func TestPrivateKeySigner(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	eccKey, _ := eccTestCert(t, elliptic.P256(), x509.KeyUsageDigitalSignature)

	t.Run("ecc", func(t *testing.T) {
		cfg, err := ApplyConfig(PrivateKeySigner(eccKey))
		require.NoError(t, err)
		require.Nil(t, cfg.sechan.LocalKey)
		require.Equal(t, crypto.Signer(eccKey), cfg.sechan.LocalPrivateKey)
	})

	t.Run("rsa keeps using the RSA field", func(t *testing.T) {
		cfg, err := ApplyConfig(PrivateKeySigner(rsaKey))
		require.NoError(t, err)
		require.Equal(t, rsaKey, cfg.sechan.LocalKey)
		require.Nil(t, cfg.sechan.LocalPrivateKey)
	})

	t.Run("the last key wins", func(t *testing.T) {
		cfg, err := ApplyConfig(PrivateKeySigner(eccKey), PrivateKey(rsaKey))
		require.NoError(t, err)
		require.Equal(t, rsaKey, cfg.sechan.LocalKey)
		require.Nil(t, cfg.sechan.LocalPrivateKey)

		cfg, err = ApplyConfig(PrivateKey(rsaKey), PrivateKeySigner(eccKey))
		require.NoError(t, err)
		require.Nil(t, cfg.sechan.LocalKey)
		require.Equal(t, crypto.Signer(eccKey), cfg.sechan.LocalPrivateKey)

		cfg, err = ApplyConfig(PrivateKeySigner(eccKey), PrivateKeySigner(nil))
		require.NoError(t, err)
		require.Nil(t, cfg.sechan.LocalKey)
		require.Nil(t, cfg.sechan.LocalPrivateKey)
	})

	t.Run("auth key", func(t *testing.T) {
		cfg, err := ApplyConfig(AuthPrivateKeySigner(eccKey))
		require.NoError(t, err)
		require.Nil(t, cfg.sechan.UserKey)
		require.Equal(t, crypto.Signer(eccKey), cfg.sechan.UserPrivateKey)

		cfg, err = ApplyConfig(AuthPrivateKeySigner(eccKey), AuthPrivateKeySigner(rsaKey))
		require.NoError(t, err)
		require.Equal(t, rsaKey, cfg.sechan.UserKey)
		require.Nil(t, cfg.sechan.UserPrivateKey)

		cfg, err = ApplyConfig(AuthPrivateKeySigner(eccKey), AuthPrivateKey(rsaKey))
		require.NoError(t, err)
		require.Equal(t, rsaKey, cfg.sechan.UserKey)
		require.Nil(t, cfg.sechan.UserPrivateKey)

		cfg, err = ApplyConfig(AuthPrivateKeySigner(eccKey), AuthPrivateKeySigner(nil))
		require.NoError(t, err)
		require.Nil(t, cfg.sechan.UserKey)
		require.Nil(t, cfg.sechan.UserPrivateKey)
	})
}

func TestPrivateKeyFile_ECC(t *testing.T) {
	key, _ := eccTestCert(t, elliptic.P384(), x509.KeyUsageDigitalSignature)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"pkcs8.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		"pkcs8.der": pkcs8,
		"sec1.pem":  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		"sec1.der":  sec1,
	} {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))

		cfg, err := ApplyConfig(PrivateKeyFile(path))
		require.NoError(t, err, name)
		require.Nil(t, cfg.sechan.LocalKey, name)
		require.True(t, key.Equal(cfg.sechan.LocalPrivateKey), name)
	}

	// An RSA key file still ends up where RSA keys always went.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	path := filepath.Join(dir, "rsa.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), 0o600))
	cfg, err := ApplyConfig(PrivateKeyFile(path))
	require.NoError(t, err)
	require.True(t, rsaKey.Equal(cfg.sechan.LocalKey))
	require.Nil(t, cfg.sechan.LocalPrivateKey)

	_, err = ApplyConfig(PrivateKeyFile(filepath.Join(dir, "missing.pem")))
	require.ErrorIs(t, err, goerrors.ErrInvalidPrivateKey)
}

// An ECC certificate has no keyEncipherment usage: nothing is ever encrypted
// with its key. That must not disqualify it for SignAndEncrypt.
func TestValidateServerCertificate_ECCKeyUsage(t *testing.T) {
	trust := func(der []byte) *Config {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		c := newConfig()
		c.certValidator.trustedCerts = x509.NewCertPool()
		c.certValidator.trustedCerts.AddCert(cert)
		c.certValidator.trustedCertsList = []*x509.Certificate{cert}
		return c
	}

	_, signOnly := eccTestCert(t, elliptic.P256(), x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment)
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		require.NoError(t, trust(signOnly).validateServerCertificate(signOnly, mode), mode.String())
	}

	// digitalSignature is still required.
	_, agreementOnly := eccTestCert(t, elliptic.P256(), x509.KeyUsageKeyAgreement)
	err := trust(agreementOnly).validateServerCertificate(agreementOnly, ua.MessageSecurityModeSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key usage 0x10 does not include required bits 0x1")
}

func TestECDHPolicyFor(t *testing.T) {
	channel := func(uri string) *uasc.SecureChannel {
		return uasc.NewCryptoChannel(&uasc.Config{SecurityPolicyURI: uri})
	}
	ecc, rsaPolicy := ua.SecurityPolicyURIECCNistP256, ua.SecurityPolicyURIBasic256Sha256

	for name, tt := range map[string]struct {
		channel string
		token   ua.IdentityToken
		policy  string // AuthPolicyURI
		want    string
	}{
		"username inherits the channel policy":  {ecc, &ua.UserNameIdentityToken{}, "", ecc},
		"issued token inherits":                 {ecc, &ua.IssuedIdentityToken{}, "", ecc},
		"explicit token policy":                 {rsaPolicy, &ua.UserNameIdentityToken{}, ua.SecurityPolicyURIECCNistP384, ua.SecurityPolicyURIECCNistP384},
		"token policy None on an ecc channel":   {ecc, &ua.UserNameIdentityToken{}, ua.SecurityPolicyURINone, ""},
		"rsa token policy on an ecc channel":    {ecc, &ua.UserNameIdentityToken{}, rsaPolicy, ""},
		"rsa channel":                           {rsaPolicy, &ua.UserNameIdentityToken{}, "", ""},
		"anonymous has no secret":               {ecc, &ua.AnonymousIdentityToken{}, "", ""},
		"x509 token is signed, not encrypted":   {ecc, &ua.X509IdentityToken{}, "", ""},
		"no token yet":                          {ecc, nil, "", ""},
		"unsecured channel, default token":      {ua.SecurityPolicyURINone, &ua.UserNameIdentityToken{}, "", ""},
		"unsecured channel, ecc token security": {ua.SecurityPolicyURINone, &ua.IssuedIdentityToken{}, ecc, ecc},
	} {
		got := ecdhPolicyFor(channel(tt.channel), &uasc.SessionConfig{UserIdentityToken: tt.token, AuthPolicyURI: tt.policy})
		require.Equal(t, tt.want, got, name)
	}
}

func TestServerEphemeralKey(t *testing.T) {
	const uri = ua.SecurityPolicyURIECCNistP256
	serverKey, serverCert := eccTestCert(t, elliptic.P256(), x509.KeyUsageDigitalSignature)
	server := uasc.NewCryptoChannel(&uasc.Config{SecurityPolicyURI: uri, LocalPrivateKey: serverKey, Certificate: serverCert})
	client := uasc.NewCryptoChannel(&uasc.Config{SecurityPolicyURI: uri})

	public := []byte("stand-in for an ephemeral public key")
	sig, err := server.NewEphemeralKeySignature("", public)
	require.NoError(t, err)
	header := func(policy string, key *ua.EphemeralKeyType) *ua.ResponseHeader {
		return &ua.ResponseHeader{AdditionalHeader: uasc.NewECDHKeyHeader(policy, key)}
	}

	got, err := serverEphemeralKey(client, uri, header(uri, &ua.EphemeralKeyType{PublicKey: public, Signature: sig}), serverCert)
	require.NoError(t, err)
	require.Equal(t, public, got)

	// Nothing there.
	got, err = serverEphemeralKey(client, uri, nil, serverCert)
	require.NoError(t, err)
	require.Nil(t, got)
	got, err = serverEphemeralKey(client, uri, &ua.ResponseHeader{AdditionalHeader: ua.NewExtensionObject(nil)}, serverCert)
	require.NoError(t, err)
	require.Nil(t, got)

	// A key for another policy than the one asked for.
	_, err = serverEphemeralKey(client, uri, header(ua.SecurityPolicyURIECCNistP384, &ua.EphemeralKeyType{PublicKey: public, Signature: sig}), serverCert)
	require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)

	// A key that the server did not sign: unsigned, signed for another key,
	// or signed by someone else.
	_, err = serverEphemeralKey(client, uri, header(uri, &ua.EphemeralKeyType{PublicKey: public}), serverCert)
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
	_, err = serverEphemeralKey(client, uri, header(uri, &ua.EphemeralKeyType{PublicKey: []byte("another key"), Signature: sig}), serverCert)
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
	_, otherCert := eccTestCert(t, elliptic.P256(), x509.KeyUsageDigitalSignature)
	_, err = serverEphemeralKey(client, uri, header(uri, &ua.EphemeralKeyType{PublicKey: public, Signature: sig}), otherCert)
	require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)

	// The server reports that it could not create a key.
	failed := &ua.ResponseHeader{AdditionalHeader: ua.NewExtensionObject(&ua.AdditionalParametersType{
		Parameters: []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "ECDHKey"}, Value: ua.MustVariant(ua.StatusBadSecurityPolicyRejected)}},
	})}
	_, err = serverEphemeralKey(client, uri, failed, serverCert)
	require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected)

	// A key is used once.
	s := &Session{serverEphemeralKey: public}
	require.Equal(t, public, s.takeServerEphemeralKey())
	require.Nil(t, s.takeServerEphemeralKey())
}
