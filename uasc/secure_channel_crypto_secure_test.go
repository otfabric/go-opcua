// SPDX-License-Identifier: MIT

package uasc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

func testRSACert(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "go-opcua-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}

func TestSecureChannelCrypto_SessionSignatureRoundTrip(t *testing.T) {
	localKey, localCert := testRSACert(t)
	remoteKey, remoteCert := testRSACert(t)
	nonce := []byte("session-nonce-0123456789abcdef")

	local := &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		LocalKey:          localKey,
		Certificate:       localCert,
	}}
	remote := &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		LocalKey:          remoteKey,
		Certificate:       remoteCert,
	}}

	sig, alg, err := local.NewSessionSignature(remoteCert, nonce)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	require.NotEmpty(t, alg)
	require.NoError(t, remote.VerifySessionSignature(localCert, nonce, sig))

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	require.Error(t, remote.VerifySessionSignature(localCert, nonce, tampered))
}

func TestSecureChannelCrypto_InvalidCertErrors(t *testing.T) {
	key, cert := testRSACert(t)
	sc := &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeSign,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		LocalKey:          key,
		UserKey:           key,
		Certificate:       cert,
	}}
	bad := []byte("not-a-certificate")
	_, _, err := sc.NewSessionSignature(bad, []byte("n"))
	require.Error(t, err)
	require.Error(t, sc.VerifySessionSignature(bad, []byte("n"), []byte("sig")))
	_, _, err = sc.EncryptUserPassword(ua.SecurityPolicyURIBasic256Sha256, "pw", bad, []byte("n"))
	require.Error(t, err)
	_, _, err = sc.NewUserTokenSignature(ua.SecurityPolicyURIBasic256Sha256, bad, []byte("n"))
	require.Error(t, err)
}

func TestSecureChannelCrypto_EncryptUserPassword_RoundTrip(t *testing.T) {
	localKey, localCert := testRSACert(t)
	remoteKey, remoteCert := testRSACert(t)
	nonce := []byte("user-nonce")

	sc := &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		LocalKey:          localKey,
		Certificate:       localCert,
	}}

	cipher, alg, err := sc.EncryptUserPassword("", "s3cret", remoteCert, nonce)
	require.NoError(t, err)
	require.NotEmpty(t, cipher)
	require.NotEmpty(t, alg)

	enc, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, remoteKey, &localKey.PublicKey)
	require.NoError(t, err)
	plain, err := enc.Decrypt(cipher)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(plain), 4)
	n := binary.LittleEndian.Uint32(plain[:4])
	require.Equal(t, uint32(len("s3cret")+len(nonce)), n)
	require.Equal(t, append([]byte("s3cret"), nonce...), plain[4:])
}

func TestSecureChannelCrypto_NewUserTokenSignature(t *testing.T) {
	userKey, userCert := testRSACert(t)
	_, peerCert := testRSACert(t)
	nonce := []byte("tok-nonce")

	sc := &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		UserKey:           userKey,
		Certificate:       userCert,
	}}

	sig, alg, err := sc.NewUserTokenSignature("", peerCert, nonce)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	require.NotEmpty(t, alg)

	// Verify with peer-side asymmetric VerifySignature over cert||nonce.
	enc, err := uapolicy.Asymmetric(ua.SecurityPolicyURIBasic256Sha256, nil, &userKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, enc.VerifySignature(append(peerCert, nonce...), sig))
}
