// SPDX-License-Identifier: MIT

package uasc

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// chainPKI is an application with a CA-issued certificate, sent as the
// chain leaf | CA (Part 6 §6.2.3), and a peer with a self-signed one.
type chainPKI struct {
	pki   *testpki.PKI
	leaf  []byte
	chain []byte
}

func newChainPKI(t *testing.T) *chainPKI {
	t.Helper()
	pki, err := testpki.Get()
	require.NoError(t, err)
	return &chainPKI{
		pki:   pki,
		leaf:  pki.IssuedCert,
		chain: joinBytes(pki.IssuedCert, pki.CACert),
	}
}

// chained is the channel of the application with the chain, configured with
// certificate (the leaf or the chain); peer is the other end.
func (p *chainPKI) channels(certificate []byte) (chained, peer *SecureChannel) {
	chained = &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		LocalKey:          p.pki.IssuedKey,
		Certificate:       certificate,
		RemoteCertificate: p.pki.ClientCert,
	}}
	peer = &SecureChannel{cfg: &Config{
		SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		LocalKey:          p.pki.ClientKey,
		UserKey:           p.pki.UserKey,
		Certificate:       p.pki.ClientCert,
		RemoteCertificate: certificate,
	}}
	return chained, peer
}

// verifies reports whether the signature of key holder cert verifies over data.
func verifies(t *testing.T, cert, data, signature []byte) bool {
	t.Helper()
	key, err := uapolicy.CertificatePublicKey(cert)
	require.NoError(t, err)
	enc, err := uapolicy.AsymmetricKeys(ua.SecurityPolicyURIBasic256Sha256, nil, key)
	require.NoError(t, err)
	return enc.VerifySignature(data, signature) == nil
}

// signs returns the signature of the key of the chain's leaf over data.
func (p *chainPKI) signs(t *testing.T, data []byte) []byte {
	t.Helper()
	enc, err := uapolicy.AsymmetricKeys(ua.SecurityPolicyURIBasic256Sha256, p.pki.IssuedKey, nil)
	require.NoError(t, err)
	sig, err := enc.Signature(data)
	require.NoError(t, err)
	return sig
}

func TestLeafDER(t *testing.T) {
	p := newChainPKI(t)
	require.Equal(t, p.leaf, leafDER(p.chain))
	require.Equal(t, p.leaf, leafDER(p.leaf))
	require.Equal(t, []byte("junk"), leafDER([]byte("junk")), "a blob that does not parse is used as is")
	require.Nil(t, leafDER(nil))
}

// Part 4 §6.1.8: without SecureChannelEnhancements the signatures are made
// over the leaf certificate of a chain.
func TestSessionSignature_SignsLeafOfChain(t *testing.T) {
	p := newChainPKI(t)
	_, peer := p.channels(p.chain)
	nonce := []byte("server-nonce-0123456789abcdef012")

	t.Run("ClientSignature", func(t *testing.T) {
		sig, alg, err := peer.NewActivateSessionSignature(p.chain, nonce, nil)
		require.NoError(t, err)
		require.NotEmpty(t, alg)
		require.True(t, verifies(t, p.pki.ClientCert, joinBytes(p.leaf, nonce), sig))
		require.False(t, verifies(t, p.pki.ClientCert, joinBytes(p.chain, nonce), sig))
	})

	t.Run("UserTokenSignature", func(t *testing.T) {
		sig, _, err := peer.NewSessionUserTokenSignature("", p.chain, nonce, nil)
		require.NoError(t, err)
		require.True(t, verifies(t, p.pki.UserCert, joinBytes(p.leaf, nonce), sig))
		require.False(t, verifies(t, p.pki.UserCert, joinBytes(p.chain, nonce), sig))
	})

	t.Run("ServerSignature", func(t *testing.T) {
		// The server is the peer here, the client sent the chain.
		clientNonce := []byte("client-nonce-0123456789abcdef012")
		sig, _, err := peer.NewCreateSessionSignature(p.chain, clientNonce, nonce)
		require.NoError(t, err)
		require.True(t, verifies(t, p.pki.ClientCert, joinBytes(p.leaf, clientNonce), sig))
		require.False(t, verifies(t, p.pki.ClientCert, joinBytes(p.chain, clientNonce), sig))
	})
}

// Part 4 §6.1.8: the verifier calculates with the leaf first and then with
// the entire chain, so signatures of stacks that sign either are accepted.
func TestSessionSignature_VerifiesLeafAndChain(t *testing.T) {
	p := newChainPKI(t)
	nonce := []byte("nonce-0123456789abcdef0123456789")
	other := []byte("other-0123456789abcdef0123456789")

	for name, certificate := range map[string][]byte{"configured chain": p.chain, "configured leaf": p.leaf} {
		t.Run(name, func(t *testing.T) {
			chained, peer := p.channels(certificate)

			// The peer signs what this application sent (its configured
			// certificate) with its own key; this application verifies.
			for _, data := range [][]byte{p.leaf, certificate} {
				enc, err := uapolicy.AsymmetricKeys(ua.SecurityPolicyURIBasic256Sha256, p.pki.ClientKey, nil)
				require.NoError(t, err)
				sig, err := enc.Signature(joinBytes(data, nonce))
				require.NoError(t, err)
				require.NoError(t, chained.VerifySessionSignature(p.pki.ClientCert, nonce, sig))
				require.NoError(t, chained.VerifyActivateSessionSignature(p.pki.ClientCert, nonce, nil, sig))
				require.NoError(t, chained.VerifyCreateSessionSignature(p.pki.ClientCert, nonce, nil, sig))
				require.Error(t, chained.VerifySessionSignature(p.pki.ClientCert, other, sig))

				user, err := uapolicy.AsymmetricKeys(ua.SecurityPolicyURIBasic256Sha256, p.pki.UserKey, nil)
				require.NoError(t, err)
				usig, err := user.Signature(joinBytes(data, nonce))
				require.NoError(t, err)
				require.NoError(t, chained.VerifySessionUserTokenSignature("", p.pki.UserCert, certificate, nonce, nil, usig))
				require.Error(t, chained.VerifySessionUserTokenSignature("", p.pki.UserCert, certificate, other, nil, usig))
				require.Error(t, chained.VerifySessionUserTokenSignature("", p.pki.ClientCert, certificate, nonce, nil, usig), "signed by another key")
			}

			// The peer verifies what the chained application signs over its
			// certificate, sent as a chain.
			sig, _, err := chained.NewSessionSignature(p.pki.ClientCert, nonce)
			require.NoError(t, err)
			require.NoError(t, peer.VerifySessionSignature(certificate, nonce, sig))
			require.NoError(t, peer.VerifySessionSignature(p.chain, nonce, sig), "the chain carries the signing key in its leaf")
			require.NoError(t, peer.VerifySessionSignature(p.leaf, nonce, sig))
			require.Error(t, peer.VerifySessionSignature(p.pki.CACert, nonce, sig), "the key of the CA did not sign")
		})
	}

	t.Run("a chain signature of the wrong data", func(t *testing.T) {
		chained, _ := p.channels(p.chain)
		sig := func(data []byte) []byte {
			enc, err := uapolicy.AsymmetricKeys(ua.SecurityPolicyURIBasic256Sha256, p.pki.ClientKey, nil)
			require.NoError(t, err)
			s, err := enc.Signature(data)
			require.NoError(t, err)
			return s
		}
		require.Error(t, chained.VerifySessionSignature(p.pki.ClientCert, nonce, sig(joinBytes(p.pki.CACert, nonce))))
		require.Error(t, chained.VerifySessionSignature(p.pki.ClientCert, nonce, sig(joinBytes(p.chain, other))))
	})
}

func TestVerifyLegacySignature(t *testing.T) {
	p := newChainPKI(t)
	nonce := []byte("n")
	enc, err := verifier(ua.SecurityPolicyURIBasic256Sha256, p.leaf)
	require.NoError(t, err)

	require.NoError(t, verifyLegacySignature(enc, p.chain, nonce, p.signs(t, joinBytes(p.leaf, nonce))))
	require.NoError(t, verifyLegacySignature(enc, p.chain, nonce, p.signs(t, joinBytes(p.chain, nonce))))
	require.NoError(t, verifyLegacySignature(enc, p.leaf, nonce, p.signs(t, joinBytes(p.leaf, nonce))))
	// A single certificate is not tried twice, and a chain signature does
	// not fit a leaf that was sent alone.
	require.Error(t, verifyLegacySignature(enc, p.leaf, nonce, p.signs(t, joinBytes(p.chain, nonce))))
	// Data that does not parse is verified as is.
	require.NoError(t, verifyLegacySignature(enc, []byte("junk"), nonce, p.signs(t, []byte("junkn"))))

	_, err = verifier(ua.SecurityPolicyURIBasic256Sha256, []byte("junk"))
	require.Error(t, err)
}
