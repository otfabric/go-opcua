package uapolicy

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// signOnlyKey is the signing key of Part 6 §6.8.1 for a Sign-only channel of
// a policy without authenticated encryption, computed independently of
// deriveKeys: L is the signing key length alone (Step 1), and it is the first
// field of the salt.
func signOnlyKey(t *testing.T, secret []byte, label string, first, second []byte, sigLen int) []byte {
	t.Helper()
	salt := binary.LittleEndian.AppendUint16(nil, uint16(sigLen))
	salt = append(salt, label...)
	salt = append(salt, first...)
	salt = append(salt, second...)
	k, err := hkdf.Key(sha256.New, secret, salt, string(salt), sigLen)
	require.NoError(t, err)
	return k
}

func TestECCKeyDerivation_SignOnly(t *testing.T) {
	p := eccPolicies[ua.SecurityPolicyURIECCNistP256]
	secret := unhex(t, rfc5903girx)
	client, server := unhex(t, rfc5903gi), unhex(t, rfc5903gr)

	ck, err := p.channelKeys(secret, eccLabelClient, client, server, true)
	require.NoError(t, err)
	require.Equal(t, signOnlyKey(t, secret, eccLabelClient, client, server, 32), ck.signing)
	require.Equal(t, make([]byte, 16), ck.encryption, "the encrypting key is not derived")
	require.Equal(t, make([]byte, AESBlockSize), ck.iv, "the IV is not derived")
	// L is part of the salt: the key differs from the SignAndEncrypt one.
	require.NotEqual(t, unhex(t, katP256ClientKeys)[:32], ck.signing)

	sk, err := p.channelKeys(secret, eccLabelServer, server, client, true)
	require.NoError(t, err)
	require.Equal(t, signOnlyKey(t, secret, eccLabelServer, server, client, 32), sk.signing)
}

// The policies with authenticated encryption derive the same keys in both
// modes (L always covers the encrypting key and IV).
func TestECCKeyDerivation_SignOnlyAEADUnchanged(t *testing.T) {
	secret := unhex(t, rfc5903girx)
	client, server := unhex(t, rfc5903gi), unhex(t, rfc5903gr)
	for _, uri := range []string{ua.SecurityPolicyURIECCNistP256AesGcm, ua.SecurityPolicyURIECCNistP256ChaChaPoly, ua.SecurityPolicyURIECCCurve25519, ua.SecurityPolicyURIECCCurve448} {
		p := eccPolicies[uri]
		full, err := p.channelKeys(secret, eccLabelClient, client, server, false)
		require.NoError(t, err, uri)
		sign, err := p.channelKeys(secret, eccLabelClient, client, server, true)
		require.NoError(t, err, uri)
		require.Equal(t, full, sign, uri)
	}
}

func TestKeyExchange_SetSecurityMode(t *testing.T) {
	for _, uri := range []string{ua.SecurityPolicyURIECCNistP256, ua.SecurityPolicyURIECCNistP384, ua.SecurityPolicyURIECCBrainpoolP256r1, ua.SecurityPolicyURIECCBrainpoolP384r1} {
		t.Run(uri, func(t *testing.T) {
			pair := func(clientMode, serverMode ua.MessageSecurityMode) (c, s *EncryptionAlgorithm) {
				t.Helper()
				ckx, err := NewKeyExchange(uri, RoleClient)
				require.NoError(t, err)
				skx, err := NewKeyExchange(uri, RoleServer)
				require.NoError(t, err)
				ckx.SetSecurityMode(clientMode)
				skx.SetSecurityMode(serverMode)
				c, err = ckx.Symmetric(skx.Nonce())
				require.NoError(t, err)
				s, err = skx.Symmetric(ckx.Nonce())
				require.NoError(t, err)
				return c, s
			}
			msg := []byte("a message to sign")
			for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeInvalid} {
				c, s := pair(mode, mode)
				sig, err := c.Signature(msg)
				require.NoError(t, err)
				require.NoError(t, s.VerifySignature(msg, sig), "both sides in %v", mode)
			}
			// Sign against the legacy derivation (no mode): other signing keys.
			c, s := pair(ua.MessageSecurityModeSign, ua.MessageSecurityModeInvalid)
			sig, err := c.Signature(msg)
			require.NoError(t, err)
			require.Error(t, s.VerifySignature(msg, sig))
		})
	}
}
