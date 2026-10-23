// SPDX-License-Identifier: MIT

package uadp

import (
	"bytes"
	"fmt"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// The security header (Part 14 Table 146 in 1.05):
//
//	SecurityFlags      Byte    bit 0 signed, 1 encrypted, 2 footer, 3 force key reset
//	SecurityTokenId    UInt32
//	NonceLength        Byte
//	MessageNonce       Byte[NonceLength]
//	SecurityFooterSize UInt16  only if the footer bit is set
//
// The encrypted range is everything after the security header up to the end of
// the SecurityFooter, the signed range is everything before the signature,
// starting with the UADPFlags. The signature is the last SignatureLength bytes
// of the message.

// encodeSecurity holds what Encode needs to secure one message.
type encodeSecurity struct {
	encrypt bool
	policy  security.Policy
	keys    *security.Keys
	nonce   []byte
}

func secError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrSecurityChecksFailed}, args...)...)
}

func newEncodeSecurity(opts *EncodeOptions) (*encodeSecurity, error) {
	switch opts.SecurityMode {
	case ua.MessageSecurityModeInvalid, ua.MessageSecurityModeNone:
		return nil, nil
	case ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt:
	default:
		return nil, secError("security mode %d", opts.SecurityMode)
	}
	if opts.Keys == nil {
		return nil, secError("security mode %v without keys", opts.SecurityMode)
	}
	p := opts.Keys.Policy()
	if p == nil {
		return nil, secError("KeySource without policy")
	}
	k, err := opts.Keys.CurrentKeys()
	if err != nil {
		return nil, fmt.Errorf("pubsub/uadp: current keys: %w", err)
	}
	if k == nil {
		return nil, secError("no current keys")
	}
	nonce, err := p.NewMessageNonce(opts.NonceSequence)
	if err != nil {
		return nil, secError("message nonce: %v", err)
	}
	encrypt := opts.SecurityMode == ua.MessageSecurityModeSignAndEncrypt
	if len(nonce) > MaxNonceLength || (encrypt && len(nonce) == 0) {
		return nil, secError("message nonce of %d bytes", len(nonce))
	}
	return &encodeSecurity{encrypt: encrypt, policy: p, keys: k, nonce: nonce}, nil
}

func (s *encodeSecurity) writeHeader(b *ua.Buffer) {
	flags := byte(secSigned)
	if s.encrypt {
		flags |= secEncrypted
	}
	b.WriteUint8(flags)
	b.WriteUint32(s.keys.TokenID)
	b.WriteUint8(uint8(len(s.nonce)))
	b.Write(s.nonce)
}

// protect encrypts msg[payloadStart:] if required and appends the signature
// over msg.
func (s *encodeSecurity) protect(msg []byte, payloadStart int) ([]byte, error) {
	if s.encrypt {
		if err := s.policy.Encrypt(s.keys, s.nonce, msg[payloadStart:]); err != nil {
			return nil, secError("encrypt: %v", err)
		}
	}
	sig, err := s.policy.Sign(s.keys, msg)
	if err != nil {
		return nil, secError("sign: %v", err)
	}
	if len(sig) != s.policy.SignatureLength() {
		return nil, secError("signature of %d bytes, the policy announces %d", len(sig), s.policy.SignatureLength())
	}
	return append(msg, sig...), nil
}

// decodeSecurityHeader reads the security header and checks it as open62541
// does (validateSecurityHeader): no unknown flags, no encryption without
// signature and nonce, no footer or key reset that is not authenticated.
func decodeSecurityHeader(b *ua.Buffer) (*message.SecurityHeader, error) {
	flags := b.ReadUint8()
	h := &message.SecurityHeader{
		Signed:          flags&secSigned != 0,
		Encrypted:       flags&secEncrypted != 0,
		ForceKeyReset:   flags&secForceKeyReset != 0,
		SecurityTokenID: b.ReadUint32(),
	}
	n := int(b.ReadUint8())
	if b.Error() != nil {
		return nil, malformed("truncated security header")
	}
	switch {
	case flags&^secKnown != 0:
		return nil, secError("unknown security flags 0x%02x", flags)
	case n > MaxNonceLength:
		return nil, secError("message nonce of %d bytes", n)
	case h.Encrypted && !h.Signed:
		return nil, secError("encrypted message without signature")
	case h.Encrypted && n == 0:
		return nil, secError("encrypted message without nonce")
	case (flags&secFooter != 0 || h.ForceKeyReset) && !h.Signed:
		return nil, secError("security footer or key reset of an unsigned message")
	}
	if n > 0 {
		h.MessageNonce = bytes.Clone(b.ReadN(n))
	}
	if flags&secFooter != 0 {
		h.FooterSize = b.ReadUint16()
	}
	if b.Error() != nil {
		return nil, malformed("truncated security header")
	}
	return h, nil
}

func modeOf(h *message.SecurityHeader) ua.MessageSecurityMode {
	switch {
	case h == nil || !h.Signed:
		return ua.MessageSecurityModeNone
	case h.Encrypted:
		return ua.MessageSecurityModeSignAndEncrypt
	default:
		return ua.MessageSecurityModeSign
	}
}

// unprotect checks the security of a message against what the receiver
// requires, verifies the signature and decrypts. It returns the bytes after
// the security header (payload and footer), without the signature, decrypted
// in place.
func (d *decoder) unprotect(nm *message.NetworkMessage, hdrEnd int) ([]byte, error) {
	required := ua.MessageSecurityModeNone
	var ks security.KeySource
	if d.opts.Security != nil {
		mode, src, err := d.opts.Security(nm)
		if err != nil {
			return nil, err
		}
		ks = src
		if mode > required {
			required = mode
		}
	}
	got := modeOf(nm.Security)
	if got < required {
		return nil, fmt.Errorf("%w: message security %v, required %v", ErrSecurityMode, got, required)
	}
	if got == ua.MessageSecurityModeNone {
		return d.b[hdrEnd:], nil
	}
	if ks == nil || ks.Policy() == nil {
		return nil, fmt.Errorf("%w: message security %v, no keys to verify it", ErrSecurityMode, got)
	}
	p := ks.Policy()
	h := nm.Security
	keys, err := ks.KeysForToken(h.SecurityTokenID)
	if err != nil {
		return nil, fmt.Errorf("pubsub/uadp: security token %d: %w", h.SecurityTokenID, err)
	}
	if keys == nil {
		return nil, fmt.Errorf("pubsub/uadp: security token %d: %w", h.SecurityTokenID, security.ErrNoKeys)
	}

	sigLen := p.SignatureLength()
	if sigLen < 0 || len(d.b)-hdrEnd < sigLen {
		return nil, secError("message too short for its signature")
	}
	end := len(d.b) - sigLen
	if err := p.Verify(keys, d.b[:end], d.b[end:]); err != nil {
		return nil, secError("signature: %v", err)
	}
	body := d.b[hdrEnd:end]
	if got == ua.MessageSecurityModeSignAndEncrypt {
		if len(h.MessageNonce) != p.MessageNonceLength() {
			return nil, secError("message nonce of %d bytes, the policy needs %d", len(h.MessageNonce), p.MessageNonceLength())
		}
		if err := p.Decrypt(keys, h.MessageNonce, body); err != nil {
			return nil, secError("decrypt: %v", err)
		}
	}
	return body, nil
}
