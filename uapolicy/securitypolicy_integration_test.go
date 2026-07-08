// SPDX-License-Identifier: MIT

package uapolicy

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAsymmetricLookup_AllPolicies verifies that Asymmetric() returns valid
// EncryptionAlgorithms for every registered security policy URI.
func TestAsymmetricLookup_AllPolicies(t *testing.T) {
	localKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	remoteKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, uri := range SupportedPolicies() {
		t.Run(uri, func(t *testing.T) {
			algo, err := Asymmetric(uri, localKey, &remoteKey.PublicKey)
			require.NoError(t, err)
			require.NotNil(t, algo)

			if uri == ua.SecurityPolicyURINone {
				assert.Equal(t, 0, algo.NonceLength())
			} else {
				assert.Greater(t, algo.NonceLength(), 0)
				assert.Greater(t, algo.SignatureLength(), 0)
			}
		})
	}
}

// TestSymmetricLookup_AllPolicies verifies that Symmetric() returns valid
// EncryptionAlgorithms for every registered security policy URI.
func TestSymmetricLookup_AllPolicies(t *testing.T) {
	localKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	remoteKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, uri := range SupportedPolicies() {
		t.Run(uri, func(t *testing.T) {
			// Get nonce length from asymmetric first.
			asym, err := Asymmetric(uri, localKey, &remoteKey.PublicKey)
			require.NoError(t, err)

			nl := asym.NonceLength()
			var localNonce, remoteNonce []byte
			if nl > 0 {
				localNonce = make([]byte, nl)
				remoteNonce = make([]byte, nl)
				_, err = rand.Read(localNonce)
				require.NoError(t, err)
				_, err = rand.Read(remoteNonce)
				require.NoError(t, err)
			}

			sym, err := Symmetric(uri, localNonce, remoteNonce)
			require.NoError(t, err)
			require.NotNil(t, sym)
		})
	}
}

// TestAsymmetric_UnsupportedPolicy verifies the error for an unknown URI.
func TestAsymmetric_UnsupportedPolicy(t *testing.T) {
	_, err := Asymmetric("http://bogus/policy", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy)
}

// TestSymmetric_UnsupportedPolicy verifies the error for an unknown URI.
func TestSymmetric_UnsupportedPolicy(t *testing.T) {
	_, err := Symmetric("http://bogus/policy", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.ErrUnsupportedSecurityPolicy)
}

// TestSymmetric_NilNonces verifies that non-None policies require nonces.
func TestSymmetric_NilNonces(t *testing.T) {
	for _, uri := range SupportedPolicies() {
		if uri == ua.SecurityPolicyURINone {
			continue
		}
		t.Run(uri, func(t *testing.T) {
			_, err := Symmetric(uri, nil, nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, errors.ErrInvalidSecurityConfig)
		})
	}
}

// TestSymmetric_NonePolicy_NilNonces verifies None policy works with nil nonces.
func TestSymmetric_NonePolicy_NilNonces(t *testing.T) {
	algo, err := Symmetric(ua.SecurityPolicyURINone, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, algo)
}

// TestAsymmetricNonceCrossValidation verifies that the asymmetric nonce length
// is consistent with symmetric nonce requirements for each policy.
func TestAsymmetricNonceCrossValidation(t *testing.T) {
	localKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	remoteKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, uri := range SupportedPolicies() {
		if uri == ua.SecurityPolicyURINone {
			continue
		}
		t.Run(uri, func(t *testing.T) {
			asym, err := Asymmetric(uri, localKey, &remoteKey.PublicKey)
			require.NoError(t, err)

			nonce, err := asym.MakeNonce()
			require.NoError(t, err)
			assert.Equal(t, asym.NonceLength(), len(nonce))

			// Symmetric should succeed with a properly-sized nonce.
			remoteNonce := make([]byte, asym.NonceLength())
			_, err = rand.Read(remoteNonce)
			require.NoError(t, err)

			sym, err := Symmetric(uri, nonce, remoteNonce)
			require.NoError(t, err)
			require.NotNil(t, sym)
		})
	}
}

// TestSecurityLevel verifies SecurityLevel returns expected rankings.
func TestSecurityLevel(t *testing.T) {
	tests := []struct {
		policy string
		mode   ua.MessageSecurityMode
		want   uint8
	}{
		{ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 1},
		{ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, 32},
		{ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 33},
		{ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt, 53},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			got := SecurityLevel(tt.policy, tt.mode)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestSymmetricRoundTrip_AllPolicies does a full encrypt→decrypt and sign→verify
// roundtrip for every security policy using symmetric keys.
func TestSymmetricRoundTrip_AllPolicies(t *testing.T) {
	localKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	remoteKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	payload := make([]byte, 512)
	_, err = rand.Read(payload)
	require.NoError(t, err)

	for _, uri := range SupportedPolicies() {
		t.Run(uri, func(t *testing.T) {
			asym, err := Asymmetric(uri, localKey, &remoteKey.PublicKey)
			require.NoError(t, err)

			nl := asym.NonceLength()
			var localNonce, remoteNonce []byte
			if nl > 0 {
				localNonce = make([]byte, nl)
				remoteNonce = make([]byte, nl)
				_, err = rand.Read(localNonce)
				require.NoError(t, err)
				_, err = rand.Read(remoteNonce)
				require.NoError(t, err)
			}

			localSym, err := Symmetric(uri, localNonce, remoteNonce)
			require.NoError(t, err)

			remoteSym, err := Symmetric(uri, remoteNonce, localNonce)
			require.NoError(t, err)

			// Pad the plaintext to block size.
			plaintext := make([]byte, len(payload))
			copy(plaintext, payload)

			bs := localSym.BlockSize()
			if bs > 0 {
				padSize := len(plaintext) % bs
				if padSize > 0 {
					padSize = bs - padSize
					plaintext = append(plaintext, make([]byte, padSize)...)
				}
			}

			// Encrypt with local, decrypt with remote.
			ciphertext, err := localSym.Encrypt(plaintext)
			require.NoError(t, err)

			decrypted, err := remoteSym.Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)

			// Sign with local, verify with remote.
			sig, err := localSym.Signature(plaintext)
			require.NoError(t, err)

			err = remoteSym.VerifySignature(plaintext, sig)
			require.NoError(t, err)
		})
	}
}
