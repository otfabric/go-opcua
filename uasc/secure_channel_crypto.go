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

	sig, err := enc.Signature(legacySignedData(cert, nonce))
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

	enc, err := verifier(s.cfg.SecurityPolicyURI, cert)
	if err != nil {
		return err
	}
	return verifyLegacySignature(enc, s.cfg.Certificate, nonce, signature)
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

	sig, err := enc.Signature(legacySignedData(cert, nonce))
	if err != nil {
		return nil, "", err
	}
	sigAlg := enc.SignatureURI()

	return sig, sigAlg, nil
}

// Session signatures without SecureChannelEnhancements (Part 4 §6.1.8,
// Table 102) are calculated over a certificate followed by a nonce:
//
//	ServerSignature     ClientCertificate | ClientNonce
//	ClientSignature     ServerCertificate | ServerNonce
//	UserTokenSignature  ServerCertificate | ServerNonce
//
// The certificate parameter of CreateSession may be a chain: the application
// instance certificate followed by its issuers (Part 6 §6.2.3). Part 4
// §6.1.8 (1.05.07) allows the legacy method to use the entire chain and
// says that, for backward compatibility, the calculation is first done with
// the leaf certificate. Stacks differ: open62541 and asyncua sign and verify
// the leaf only, UA-.NETStandard verifies with the leaf and then the chain.
// Signatures are therefore made over the leaf, which every stack accepts,
// and verified with the leaf first and then the certificate as sent.

// leafDER returns the DER encoding of the leaf certificate of cert, a single
// certificate or a chain. A blob that does not parse is returned unchanged.
func leafDER(cert []byte) []byte {
	if leaf, err := uapolicy.LeafCertificate(cert); err == nil {
		return leaf.Raw
	}
	return cert
}

// legacySignedData returns the data a session signature without
// SecureChannelEnhancements is made over: the leaf of cert followed by nonce.
func legacySignedData(cert, nonce []byte) []byte {
	return joinBytes(leafDER(cert), nonce)
}

// verifyLegacySignature checks a session signature without
// SecureChannelEnhancements over cert followed by nonce: first with the leaf
// of cert, then, if cert is a chain, with the chain as sent. The error is the
// one of the leaf.
func verifyLegacySignature(enc *uapolicy.EncryptionAlgorithm, cert, nonce, signature []byte) error {
	leaf := leafDER(cert)
	err := enc.VerifySignature(joinBytes(leaf, nonce), signature)
	if err == nil || len(leaf) == len(cert) {
		return err
	}
	if enc.VerifySignature(joinBytes(cert, nonce), signature) == nil {
		return nil
	}
	return err
}

// LocalCertificate returns the application instance certificate this side of
// the channel uses. On a server with certificates of several key types it is
// the one selected for the security policy of the channel.
func (s *SecureChannel) LocalCertificate() []byte {
	return s.cfg.Certificate
}

// LocalPrivateKey returns the private key of LocalCertificate, or nil if
// there is none.
func (s *SecureChannel) LocalPrivateKey() crypto.PrivateKey {
	return s.cfg.localKey()
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
