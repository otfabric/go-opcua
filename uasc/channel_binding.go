// SPDX-License-Identifier: MIT

package uasc

import (
	"fmt"
	"sync"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// SecureChannelEnhancements of OPC UA 1.05.07.
//
// Security policies with this property (ECC_nistP256_AesGcm and
// ECC_nistP256_ChaChaPoly) tie a Session to the SecureChannel it runs on:
//
//   - ChannelThumbprint (Part 6 §6.7.5). The signature of the first
//     OpenSecureChannel response is calculated over the response followed by
//     the signature of the request. That signature is the ChannelThumbprint:
//     a value both applications have, that depends on both their keys and on
//     both ephemeral keys, and that nobody in the middle can reproduce. It is
//     kept for the life of the channel; renewals are signed the plain way.
//
//   - Key chaining (Part 6 §6.8.1): see uapolicy.KeyExchange.SymmetricChained.
//
//   - Channel bound signatures (Part 4 §6.1.8). The signatures of
//     CreateSession and ActivateSession cover the ChannelThumbprint and
//     hashes of the certificates instead of a certificate and a nonce:
//
//     ServerSignature     ChannelThumbprint | ClientNonce | H(ServerChannelCert) |
//     H(ClientChannelCert) | ServerNonce
//     ClientSignature     ChannelThumbprint | ServerNonce | H(ServerCert) |
//     H(ServerChannelCert) | H(ClientChannelCert) | ClientNonce
//     UserTokenSignature  ChannelThumbprint | ServerNonce | H(ServerCert) |
//     H(ServerChannelCert) | H(ClientCert) | H(ClientChannelCert) | ClientNonce
//
//     ClientNonce is the nonce of the CreateSession request, ServerNonce the
//     one the server issued last and H the SHA-256 hash of the DER encoded
//     leaf certificate. A signature that was made for one channel is
//     worthless on another one.
//
// channelBinding holds the ChannelThumbprint of a channel while it is being
// established and afterwards.
type channelBinding struct {
	mu sync.Mutex

	// requestSignature is the signature of the first OpenSecureChannel
	// request, from the moment it was sent (client) or verified (server) until
	// the response has been dealt with.
	requestSignature []byte

	// thumbprint is the signature of the first OpenSecureChannel response.
	thumbprint []byte
}

// pending reports whether the channel still has to establish its
// ChannelThumbprint. The mutex must be held.
//
// The security mode is not consulted: a server learns it from the body of the
// first request, after it has verified the signature of that request.
func (b *channelBinding) pending(s *SecureChannel) bool {
	return b.thumbprint == nil && uapolicy.SecureChannelEnhancements(s.cfg.SecurityPolicyURI)
}

func joinBytes(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

// signedData returns the data the signature of an outgoing OpenSecureChannel
// message is calculated over: message, or for the response that establishes
// the ChannelThumbprint the message followed by the signature of the request.
func (b *channelBinding) signedData(s *SecureChannel, message []byte) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.kind == server && b.pending(s) && b.requestSignature != nil {
		return joinBytes(message, b.requestSignature)
	}
	return message
}

// sent records the signature of an outgoing OpenSecureChannel message.
func (b *channelBinding) sent(s *SecureChannel, signature []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.pending(s) {
		return
	}
	if s.kind == server {
		if b.requestSignature != nil {
			b.thumbprint = append([]byte{}, signature...)
			b.requestSignature = nil
		}
		return
	}
	b.requestSignature = append([]byte{}, signature...)
}

// verifiedData is the counterpart of signedData for an incoming
// OpenSecureChannel message.
func (b *channelBinding) verifiedData(s *SecureChannel, message []byte) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.kind == client && b.pending(s) && b.requestSignature != nil {
		return joinBytes(message, b.requestSignature)
	}
	return message
}

// received records the signature of an incoming OpenSecureChannel message
// after it has been verified.
func (b *channelBinding) received(s *SecureChannel, signature []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.pending(s) {
		return
	}
	if s.kind == client {
		if b.requestSignature != nil {
			b.thumbprint = append([]byte{}, signature...)
			b.requestSignature = nil
		}
		return
	}
	b.requestSignature = append([]byte{}, signature...)
}

// ChannelThumbprint returns the ChannelThumbprint of a SecureChannel whose
// security policy has SecureChannelEnhancements: the signature of the first
// OpenSecureChannel response. It is nil for every other channel and until the
// channel is open. The value identifies the channel to its two applications;
// it is not a secret.
func (s *SecureChannel) ChannelThumbprint() []byte {
	s.binding.mu.Lock()
	defer s.binding.mu.Unlock()
	return append([]byte(nil), s.binding.thumbprint...)
}

// channelBound reports whether the session signatures of the channel are
// bound to it.
func (s *SecureChannel) channelBound() bool {
	return s.cfg.SecurityMode != ua.MessageSecurityModeNone &&
		uapolicy.SecureChannelEnhancements(s.cfg.SecurityPolicyURI)
}

// boundSignatureData assembles the data of a channel bound signature:
//
//	ChannelThumbprint | first | H(certificates[0]) | ... | last
func (s *SecureChannel) boundSignatureData(first []byte, certificates [][]byte, last []byte) ([]byte, error) {
	thumbprint := s.ChannelThumbprint()
	if len(thumbprint) == 0 {
		return nil, fmt.Errorf("%w: the SecureChannel has no ChannelThumbprint", errors.ErrInvalidState)
	}
	data := append(thumbprint, first...)
	for _, c := range certificates {
		h, err := uapolicy.CertificateHash(s.cfg.SecurityPolicyURI, c)
		if err != nil {
			return nil, err
		}
		data = append(data, h...)
	}
	return append(data, last...), nil
}

// NewCreateSessionSignature creates the ServerSignature of a CreateSession
// response (Part 4 §5.7.2, §6.1.8).
//
// clientCertificate and clientNonce come from the request, serverNonce is the
// nonce of the response. On a channel with SecureChannelEnhancements the
// signature is bound to the channel; otherwise it covers the client
// certificate and the client nonce.
func (s *SecureChannel) NewCreateSessionSignature(clientCertificate, clientNonce, serverNonce []byte) ([]byte, string, error) {
	if !s.channelBound() {
		return s.NewSessionSignature(clientCertificate, clientNonce)
	}
	data, err := s.boundSignatureData(clientNonce, [][]byte{s.cfg.Certificate, s.RemoteCertificate()}, serverNonce)
	if err != nil {
		return nil, "", err
	}
	return s.signWith(s.cfg.SecurityPolicyURI, s.cfg.localKey(), data)
}

// VerifyCreateSessionSignature checks the ServerSignature of a CreateSession
// response. serverCertificate, serverNonce and signature come from the
// response, clientNonce is the nonce of the request.
func (s *SecureChannel) VerifyCreateSessionSignature(serverCertificate, clientNonce, serverNonce, signature []byte) error {
	if !s.channelBound() {
		return s.VerifySessionSignature(serverCertificate, clientNonce, signature)
	}
	data, err := s.boundSignatureData(clientNonce, [][]byte{s.RemoteCertificate(), s.cfg.Certificate}, serverNonce)
	if err != nil {
		return err
	}
	return s.verifyWith(s.cfg.SecurityPolicyURI, serverCertificate, data, signature)
}

// NewActivateSessionSignature creates the ClientSignature of an
// ActivateSession request (Part 4 §5.7.3, §6.1.8).
//
// serverCertificate is the certificate of the CreateSession response,
// serverNonce the nonce the server issued last and clientNonce the nonce of
// the CreateSession request.
func (s *SecureChannel) NewActivateSessionSignature(serverCertificate, serverNonce, clientNonce []byte) ([]byte, string, error) {
	if !s.channelBound() {
		return s.NewSessionSignature(serverCertificate, serverNonce)
	}
	data, err := s.boundSignatureData(serverNonce, [][]byte{serverCertificate, s.RemoteCertificate(), s.cfg.Certificate}, clientNonce)
	if err != nil {
		return nil, "", err
	}
	return s.signWith(s.cfg.SecurityPolicyURI, s.cfg.localKey(), data)
}

// VerifyActivateSessionSignature checks the ClientSignature of an
// ActivateSession request. clientCertificate is the certificate the Session
// was created with.
func (s *SecureChannel) VerifyActivateSessionSignature(clientCertificate, serverNonce, clientNonce, signature []byte) error {
	if !s.channelBound() {
		return s.VerifySessionSignature(clientCertificate, serverNonce, signature)
	}
	local := s.cfg.Certificate
	data, err := s.boundSignatureData(serverNonce, [][]byte{local, local, s.RemoteCertificate()}, clientNonce)
	if err != nil {
		return err
	}
	return s.verifyWith(s.cfg.SecurityPolicyURI, clientCertificate, data, signature)
}

// userTokenBound reports whether the signature of an X509IdentityToken with
// the given token security policy is bound to the channel: both the policy of
// the channel and the one of the token must have SecureChannelEnhancements.
func (s *SecureChannel) userTokenBound(policyURI string) bool {
	return s.channelBound() && uapolicy.SecureChannelEnhancements(s.userTokenPolicy(policyURI))
}

func (s *SecureChannel) boundUserTokenData(serverCertificate, serverChannelCertificate, clientChannelCertificate, serverNonce, clientNonce []byte) ([]byte, error) {
	return s.boundSignatureData(serverNonce, [][]byte{
		serverCertificate, serverChannelCertificate,
		// The client's application instance certificate and the certificate
		// of its channel are the same one.
		clientChannelCertificate, clientChannelCertificate,
	}, clientNonce)
}

// NewSessionUserTokenSignature creates the UserTokenSignature of an
// ActivateSession request for an X509IdentityToken, with the private key of
// the user certificate (Part 4 §6.1.8).
//
// policyURI is the security policy of the UserTokenPolicy ("" selects the
// policy of the channel). The other arguments are those of
// NewActivateSessionSignature.
func (s *SecureChannel) NewSessionUserTokenSignature(policyURI string, serverCertificate, serverNonce, clientNonce []byte) ([]byte, string, error) {
	if !s.userTokenBound(policyURI) {
		return s.NewUserTokenSignature(policyURI, serverCertificate, serverNonce)
	}
	data, err := s.boundUserTokenData(serverCertificate, s.RemoteCertificate(), s.cfg.Certificate, serverNonce, clientNonce)
	if err != nil {
		return nil, "", err
	}
	return s.signWith(s.userTokenPolicy(policyURI), s.cfg.userKey(), data)
}

// VerifySessionUserTokenSignature checks the UserTokenSignature of an
// ActivateSession request against the certificate of the X509IdentityToken.
// serverCertificate is the application instance certificate the server
// returned from CreateSession.
func (s *SecureChannel) VerifySessionUserTokenSignature(policyURI string, userCertificate, serverCertificate, serverNonce, clientNonce, signature []byte) error {
	policyURI = s.userTokenPolicy(policyURI)
	if s.userTokenBound(policyURI) {
		data, err := s.boundUserTokenData(serverCertificate, s.cfg.Certificate, s.RemoteCertificate(), serverNonce, clientNonce)
		if err != nil {
			return err
		}
		return s.verifyWith(policyURI, userCertificate, data, signature)
	}
	enc, err := verifier(policyURI, userCertificate)
	if err != nil {
		return err
	}
	return verifyLegacySignature(enc, serverCertificate, serverNonce, signature)
}

func (s *SecureChannel) signWith(policyURI string, key any, data []byte) ([]byte, string, error) {
	enc, err := uapolicy.AsymmetricKeys(policyURI, key, nil)
	if err != nil {
		return nil, "", err
	}
	sig, err := enc.Signature(data)
	if err != nil {
		return nil, "", err
	}
	return sig, enc.SignatureURI(), nil
}

func (s *SecureChannel) verifyWith(policyURI string, certificate, data, signature []byte) error {
	enc, err := verifier(policyURI, certificate)
	if err != nil {
		return err
	}
	return enc.VerifySignature(data, signature)
}

// verifier returns the algorithms of the security policy that verify
// signatures made with the key of certificate (its leaf, if it is a chain).
func verifier(policyURI string, certificate []byte) (*uapolicy.EncryptionAlgorithm, error) {
	key, err := uapolicy.CertificatePublicKey(certificate)
	if err != nil {
		return nil, err
	}
	return uapolicy.AsymmetricKeys(policyURI, nil, key)
}
