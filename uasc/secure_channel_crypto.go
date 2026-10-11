// SPDX-License-Identifier: MIT

package uasc

import (
	"crypto"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-opcua/errors"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// NewSessionSignature issues a new signature for the client to send on the next ActivateSessionRequest.
func (s *SecureChannel) NewSessionSignature(cert, nonce []byte) ([]byte, string, error) {
	if s.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return nil, "", nil
	}

	// The peer's certificate is part of the signed data; it has to be one.
	if _, err := uapolicy.CertificatePublicKey(cert); err != nil {
		return nil, "", err
	}

	// Only the local key is needed to sign.
	enc, err := uapolicy.AsymmetricKeys(s.cfg.SecurityPolicyURI, s.cfg.localKey(), nil)
	if err != nil {
		return nil, "", err
	}

	sig, err := enc.Signature(append(append([]byte(nil), cert...), nonce...))
	if err != nil {
		return nil, "", err
	}
	sigAlg := enc.SignatureURI()

	return sig, sigAlg, nil
}

// VerifySessionSignature checks the integrity of a Create/Activate Session response's signature.
func (s *SecureChannel) VerifySessionSignature(cert, nonce, signature []byte) error {
	if s.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return nil
	}

	remoteKey, err := uapolicy.CertificatePublicKey(cert)
	if err != nil {
		return err
	}

	enc, err := uapolicy.AsymmetricKeys(s.cfg.SecurityPolicyURI, nil, remoteKey)
	if err != nil {
		return err
	}
	err = enc.VerifySignature(append(append([]byte(nil), s.cfg.Certificate...), nonce...), signature)
	if err != nil {
		return err
	}

	return nil
}

// EncryptUserPassword issues a new signature for the client to send in ActivateSessionRequest.
func (s *SecureChannel) EncryptUserPassword(policyURI, password string, cert, nonce []byte) ([]byte, string, error) {
	// If the User ID Token's policy was null, then default to the secure channel's policy
	if policyURI == "" {
		policyURI = s.cfg.SecurityPolicyURI
	}

	if policyURI == ua.SecurityPolicyURINone {
		return []byte(password), "", nil
	}

	if uapolicy.IsECC(policyURI) {
		return nil, "", fmt.Errorf("%w: %s protects secrets with an EccEncryptedSecret, use EncryptUserSecret", errors.ErrInvalidSecurityConfig, policyURI)
	}

	remoteKey, err := uapolicy.CertificatePublicKey(cert)
	if err != nil {
		return nil, "", err
	}

	enc, err := uapolicy.AsymmetricKeys(policyURI, nil, remoteKey)
	if err != nil {
		return nil, "", err
	}

	l := len(password) + len(nonce)
	secret := make([]byte, 4)
	binary.LittleEndian.PutUint32(secret, uint32(l))
	secret = append(secret, []byte(password)...)
	secret = append(secret, nonce...)
	pass, err := enc.Encrypt(secret)
	if err != nil {
		return nil, "", err
	}
	passAlg := enc.EncryptionURI()

	return pass, passAlg, nil
}

// NewUserTokenSignature issues a new signature for the client to send in ActivateSessionRequest
// The security policy for the SecureChannel is used if policyURI value is null or empty
// https://reference.opcfoundation.org/Core/Part4/v104/docs/7.37
func (s *SecureChannel) NewUserTokenSignature(policyURI string, cert, nonce []byte) ([]byte, string, error) {
	if policyURI == "" {
		policyURI = s.cfg.SecurityPolicyURI
	}

	if policyURI == ua.SecurityPolicyURINone {
		return nil, "", nil
	}

	if _, err := uapolicy.CertificatePublicKey(cert); err != nil {
		return nil, "", err
	}

	// Only the user's key is needed to sign.
	enc, err := uapolicy.AsymmetricKeys(policyURI, s.cfg.userKey(), nil)
	if err != nil {
		return nil, "", err
	}

	sig, err := enc.Signature(append(append([]byte(nil), cert...), nonce...))
	if err != nil {
		return nil, "", err
	}
	sigAlg := enc.SignatureURI()

	return sig, sigAlg, nil
}

// LocalCertificate returns the application instance certificate this side of
// the channel uses. On a server with certificates of several key types it is
// the one selected for the security policy of the channel.
func (s *SecureChannel) LocalCertificate() []byte {
	return s.cfg.Certificate
}

// userTokenPolicy returns the security policy that protects a user identity
// token: the one of its UserTokenPolicy, or the policy of the channel if the
// token policy does not name one.
func (s *SecureChannel) userTokenPolicy(policyURI string) string {
	if policyURI == "" {
		return s.cfg.SecurityPolicyURI
	}
	return policyURI
}

// UserTokenPolicyIsECC reports whether the secrets of a user identity token
// with the given token security policy ("" selects the policy of the channel)
// are protected with an EccEncryptedSecret and an ephemeral key exchange.
func (s *SecureChannel) UserTokenPolicyIsECC(policyURI string) bool {
	return uapolicy.IsECC(s.userTokenPolicy(policyURI))
}

// EncryptUserSecret protects the secret of a user identity token (a password
// or the data of an issued token) for an ECC security policy. The result is
// an EccEncryptedSecret (Part 4 §7.41.2.3): encrypted with a key agreed with
// the ephemeral public key the server handed out and signed with the client's
// application instance key.
//
// nonce is the last session nonce received from the server.
func (s *SecureChannel) EncryptUserSecret(policyURI string, secret, serverEphemeralKey, nonce []byte) ([]byte, error) {
	policyURI = s.userTokenPolicy(policyURI)
	if len(serverEphemeralKey) == 0 {
		return nil, fmt.Errorf("%w: the server did not provide an ephemeral key for %s", errors.ErrInvalidSecurityConfig, policyURI)
	}
	return uapolicy.EncryptSecret(policyURI, s.cfg.localKey(), s.cfg.Certificate, serverEphemeralKey, nonce, secret, s.timeNow())
}

// NewEphemeralKeySignature signs an ephemeral public key with the local
// application instance key, as a server does for the EphemeralKeyType it
// returns from CreateSession and ActivateSession (Part 6 §6.8.2).
func (s *SecureChannel) NewEphemeralKeySignature(policyURI string, publicKey []byte) ([]byte, error) {
	enc, err := uapolicy.AsymmetricKeys(s.userTokenPolicy(policyURI), s.cfg.localKey(), nil)
	if err != nil {
		return nil, err
	}
	return enc.Signature(publicKey)
}

// VerifyEphemeralKeySignature checks that an ephemeral public key was signed
// by the owner of the certificate.
func (s *SecureChannel) VerifyEphemeralKeySignature(policyURI string, certificate, publicKey, signature []byte) error {
	key, err := uapolicy.CertificatePublicKey(certificate)
	if err != nil {
		return err
	}
	enc, err := uapolicy.AsymmetricKeys(s.userTokenPolicy(policyURI), nil, key)
	if err != nil {
		return err
	}
	return enc.VerifySignature(publicKey, signature)
}

// DecryptUserSecret verifies and decrypts an EccEncryptedSecret a client
// created for the ephemeral key. The secret must be signed with the key of
// signerCertificate, the client's application instance certificate, and be
// bound to nonce, the session nonce the server issued last.
func DecryptUserSecret(key *uapolicy.EphemeralKey, data, signerCertificate, nonce []byte) ([]byte, error) {
	signer, err := uapolicy.CertificatePublicKey(signerCertificate)
	if err != nil {
		return nil, err
	}
	secret, err := key.DecryptSecret(data, func(certificate []byte) (crypto.PublicKey, error) {
		// The secret names its signing certificate. It has to be the one
		// the client authenticated the session with; a secret signed by
		// anyone else is of no value.
		if len(certificate) > 0 && subtle.ConstantTimeCompare(uapolicy.Thumbprint(certificate), uapolicy.Thumbprint(signerCertificate)) != 1 {
			return nil, fmt.Errorf("%w: encrypted secret is signed with a different certificate", errors.ErrSignatureValidationFailed)
		}
		return signer, nil
	})
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(secret.Nonce, nonce) != 1 {
		return nil, fmt.Errorf("%w: encrypted secret is bound to a different nonce", errors.ErrSignatureValidationFailed)
	}
	return secret.Secret, nil
}
