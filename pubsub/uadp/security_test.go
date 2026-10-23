// SPDX-License-Identifier: MIT

package uadp

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// The encrypted NetworkMessage of open62541 v1.5.9,
// tests/pubsub/check_pubsub_decryption.c (MSG_HEADER, MSG_PAYLOAD_ENC,
// MSG_PAYLOAD_DEC, MSG_SIG, MSG_SIG_INVALID, MSG_HEADER_NO_SEC): PublisherId
// UInt16 2234, WriterGroupId 100, DataSetWriterId 62541, SignAndEncrypt with
// token 1, all-zero keys and the MessageNonce b02d012e 01000000 (four random
// bytes and the sequence number 1).
const (
	o6Header      = "f111ba08016400014df4030100000008b02d012e01000000"
	o6HeaderNoSec = "f101ba08016400014df4"
	o6PayloadEnc  = "1c26767c41d1b02e506daece57546ce9c958279e1b6be3e28c0f775648"
	o6PayloadDec  = "e1101054c2949f3ad701b4205f69841e5f6901000d7657c2949F3ad701"
	o6Sig         = "31eb5d01b947a70cee7f82d4c77924811b06e7e1c93d1e7f03dd2125fc48fc5a"
	o6SigInvalid  = "5e08a9ff14b83ea2247792eeffc757c85ac99c0ffa79e4fbe5629783dc77b403"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func requireSecurity(mode ua.MessageSecurityMode, ks security.KeySource) func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
	return func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
		return mode, ks, nil
	}
}

// o6Message is the decoded content of the open62541 vector.
func o6Message(t testing.TB) *message.NetworkMessage {
	t.Helper()
	plain := unhex(t, o6HeaderNoSec+o6PayloadDec)
	nm, err := Decode(plain, nil)
	require.NoError(t, err)
	return nm
}

func TestOpen62541DecryptionVector(t *testing.T) {
	p := testPolicy{nonceRandom: [4]byte{0xb0, 0x2d, 0x01, 0x2e}}
	ks := zeroKeys(p)
	enc := unhex(t, o6Header+o6PayloadEnc+o6Sig)
	orig := append([]byte(nil), enc...)

	nm, err := Decode(enc, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, ks)})
	require.NoError(t, err)
	require.Equal(t, orig, enc, "Decode must not modify its input")

	require.Equal(t, message.NewPublisherID(message.PublisherIDUInt16, 2234), nm.PublisherID)
	require.Equal(t, uint16(100), nm.GroupHeader.WriterGroupID)
	require.Equal(t, &message.SecurityHeader{
		Signed: true, Encrypted: true, SecurityTokenID: 1,
		MessageNonce: unhex(t, "b02d012e01000000"),
	}, nm.Security)
	require.Len(t, nm.Messages, 1)
	m := nm.Messages[0]
	require.Equal(t, uint16(62541), m.DataSetWriterID)
	require.True(t, m.Valid)
	require.Equal(t, message.FieldEncodingVariant, m.FieldEncoding)
	require.Equal(t, ua.UADPDataSetMessageContentMaskTimestamp|ua.UADPDataSetMessageContentMaskMajorVersion|
		ua.UADPDataSetMessageContentMaskMinorVersion, m.UADPMask)
	require.Len(t, m.Fields, 1)
	require.Equal(t, ua.TypeIDDateTime, m.Fields[0].Value.Value.Type())

	// The plaintext of the vector decodes to the same DataSetMessages.
	plain := o6Message(t)
	require.Equal(t, plain.Messages, nm.Messages)

	// Encoding the message again with the same nonce reproduces the
	// vector byte for byte: same flags, same encrypted range, same
	// signed range.
	nm.Security = nil
	out, err := Encode(nm, &EncodeOptions{SecurityMode: ua.MessageSecurityModeSignAndEncrypt, Keys: ks, NonceSequence: 1})
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(orig), hex.EncodeToString(out))

	// And the plaintext message encodes to the plaintext vector.
	out, err = Encode(plain, nil)
	require.NoError(t, err)
	require.Equal(t, unhex(t, o6HeaderNoSec+o6PayloadDec), out)
}

func TestOpen62541InvalidSignature(t *testing.T) {
	ks := zeroKeys(testPolicy{})
	enc := unhex(t, o6Header+o6PayloadEnc+o6SigInvalid)
	_, err := Decode(enc, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, ks)})
	require.ErrorIs(t, err, ErrSecurityChecksFailed)

	// open62541 ShortSignedNetworkMessage: the header alone.
	_, err = Decode(unhex(t, o6Header), &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, ks)})
	require.ErrorIs(t, err, ErrSecurityChecksFailed)
}

func TestSecurityModeChecks(t *testing.T) {
	ks := zeroKeys(testPolicy{})
	enc := unhex(t, o6Header+o6PayloadEnc+o6Sig)
	plain := unhex(t, o6HeaderNoSec+o6PayloadDec)

	// open62541 InvalidSecurityModeRejectedSig: an unsecured message to a
	// reader that requires encryption.
	_, err := Decode(plain, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, ks)})
	require.ErrorIs(t, err, ErrSecurityMode)
	_, err = Decode(plain, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSign, ks)})
	require.ErrorIs(t, err, ErrSecurityMode)

	// open62541 InvalidSecurityModeInsufficientSig: a secured message to a
	// reader without keys.
	_, err = Decode(enc, nil)
	require.ErrorIs(t, err, ErrSecurityMode)
	_, err = Decode(enc, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeNone, nil)})
	require.ErrorIs(t, err, ErrSecurityMode)

	// A stronger message than required is verified and accepted when the
	// keys are known.
	_, err = Decode(enc, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSign, ks)})
	require.NoError(t, err)
	_, err = Decode(enc, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeNone, ks)})
	require.NoError(t, err)

	// A signed message is weaker than SignAndEncrypt.
	nm := o6Message(t)
	signed, err := Encode(nm, &EncodeOptions{SecurityMode: ua.MessageSecurityModeSign, Keys: ks, NonceSequence: 7})
	require.NoError(t, err)
	_, err = Decode(signed, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, ks)})
	require.ErrorIs(t, err, ErrSecurityMode)
	got, err := Decode(signed, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSign, ks)})
	require.NoError(t, err)
	require.Equal(t, nm.Messages, got.Messages)
	require.True(t, got.Security.Signed)
	require.False(t, got.Security.Encrypted)

	// The signature covers the header: flipping a header bit fails.
	signed[3] ^= 1
	_, err = Decode(signed, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSign, ks)})
	require.ErrorIs(t, err, ErrSecurityChecksFailed)

	// Unknown token.
	other := zeroKeys(testPolicy{})
	other.keys.TokenID = 2
	_, err = Decode(enc, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, other)})
	require.ErrorIs(t, err, security.ErrNoKeys)

	// A KeySource that returns nil keys.
	_, err = Decode(enc, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, nilKeys{testPolicy{}})})
	require.ErrorIs(t, err, security.ErrNoKeys)

	// Errors of the Security callback are returned.
	boom := errors.New("boom")
	_, err = Decode(enc, &DecodeOptions{Security: func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
		return 0, nil, boom
	}})
	require.ErrorIs(t, err, boom)
}

type nilKeys struct{ p security.Policy }

func (k nilKeys) Policy() security.Policy                    { return k.p }
func (nilKeys) CurrentKeys() (*security.Keys, error)         { return nil, nil }
func (nilKeys) KeysForToken(uint32) (*security.Keys, error) { return nil, nil }

// failingPolicy fails in the operation named by fail.
type failingPolicy struct {
	testPolicy
	fail   string
	sigLen   int
	nonce    []byte
	nonceLen int
}

func (p failingPolicy) MessageNonceLength() int {
	if p.nonceLen != 0 {
		return p.nonceLen
	}
	return p.testPolicy.MessageNonceLength()
}

func (p failingPolicy) NewMessageNonce(seq uint32) ([]byte, error) {
	if p.fail == "nonce" {
		return nil, errors.New("no entropy")
	}
	if p.nonce != nil {
		return p.nonce, nil
	}
	return p.testPolicy.NewMessageNonce(seq)
}

func (p failingPolicy) Sign(k *security.Keys, data []byte) ([]byte, error) {
	if p.fail == "sign" {
		return nil, errors.New("sign failed")
	}
	sig, err := p.testPolicy.Sign(k, data)
	if p.sigLen != 0 {
		sig = sig[:p.sigLen]
	}
	return sig, err
}

func (p failingPolicy) Encrypt(k *security.Keys, nonce, data []byte) error {
	if p.fail == "encrypt" {
		return errors.New("encrypt failed")
	}
	return p.testPolicy.Encrypt(k, nonce, data)
}

func (p failingPolicy) Decrypt(k *security.Keys, nonce, data []byte) error {
	if p.fail == "decrypt" {
		return errors.New("decrypt failed")
	}
	return p.testPolicy.Decrypt(k, nonce, data)
}

func TestEncodeSecurityErrors(t *testing.T) {
	nm := o6Message(t)
	enc := func(mode ua.MessageSecurityMode, ks security.KeySource) error {
		_, err := Encode(nm, &EncodeOptions{SecurityMode: mode, Keys: ks})
		return err
	}
	require.ErrorIs(t, enc(ua.MessageSecurityMode(9), nil), ErrSecurityChecksFailed)
	require.ErrorIs(t, enc(ua.MessageSecurityModeSign, nil), ErrSecurityChecksFailed)
	require.ErrorIs(t, enc(ua.MessageSecurityModeSign, &testKeys{}), ErrSecurityChecksFailed)
	boom := errors.New("boom")
	require.ErrorIs(t, enc(ua.MessageSecurityModeSign, &testKeys{policy: testPolicy{}, err: boom}), boom)
	require.ErrorIs(t, enc(ua.MessageSecurityModeSign, nilKeys{testPolicy{}}), ErrSecurityChecksFailed)

	keys := zeroKeys(testPolicy{}).keys
	for _, tc := range []struct {
		mode ua.MessageSecurityMode
		p    failingPolicy
	}{
		{ua.MessageSecurityModeSign, failingPolicy{fail: "nonce"}},
		{ua.MessageSecurityModeSign, failingPolicy{fail: "sign"}},
		{ua.MessageSecurityModeSign, failingPolicy{sigLen: 16}},
		{ua.MessageSecurityModeSignAndEncrypt, failingPolicy{fail: "encrypt"}},
		{ua.MessageSecurityModeSignAndEncrypt, failingPolicy{nonce: []byte{}}},
		{ua.MessageSecurityModeSign, failingPolicy{nonce: make([]byte, MaxNonceLength+1)}},
	} {
		require.ErrorIs(t, enc(tc.mode, &testKeys{policy: tc.p, keys: keys}), ErrSecurityChecksFailed, "%+v", tc.p)
	}

	// Decrypt failures and nonces of the wrong length.
	ks := zeroKeys(testPolicy{})
	msg, err := Encode(nm, &EncodeOptions{SecurityMode: ua.MessageSecurityModeSignAndEncrypt, Keys: ks})
	require.NoError(t, err)
	_, err = Decode(msg, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt,
		&testKeys{policy: failingPolicy{fail: "decrypt"}, keys: ks.keys})})
	require.ErrorIs(t, err, ErrSecurityChecksFailed)

	longNonce := &testKeys{policy: failingPolicy{nonceLen: 12}, keys: ks.keys}
	_, err = Decode(msg, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSignAndEncrypt, longNonce)})
	require.ErrorIs(t, err, ErrSecurityChecksFailed)
}

// open62541 UA_PubSub_Decode_RejectsInvalidSecurityFlags
// (check_pubsub_encoding.c, assertSecurityHeaderRejected).
func TestSecurityHeaderRejected(t *testing.T) {
	for _, tc := range []struct{ flags, nonceLen byte }{
		{0x10, 0}, // reserved flag
		{0x02, 1}, // encrypt without sign
		{0x03, 0}, // encrypt without nonce
		{0x04, 0}, // unauthenticated footer
		{0x08, 0}, // unauthenticated key reset
		{0x01, MaxNonceLength + 1},
	} {
		raw := []byte{0x81, 0x10, tc.flags, 0x01, 0x00, 0x00, 0x00, tc.nonceLen}
		raw = append(raw, make([]byte, int(tc.nonceLen))...)
		raw = append(raw, 0x01, 0x00)
		_, err := Decode(raw, nil)
		require.ErrorIs(t, err, ErrSecurityChecksFailed, "flags %02x", tc.flags)
	}
	// Truncated security headers.
	for _, raw := range [][]byte{{0x81, 0x10}, {0x81, 0x10, 0x01, 0x01}, {0x81, 0x10, 0x01, 0, 0, 0, 0, 8, 1}, {0x81, 0x10, 0x05, 0, 0, 0, 0, 0, 1}} {
		_, err := Decode(raw, nil)
		require.ErrorIs(t, err, ErrMalformed, "% x", raw)
	}
}

// A signed message with a security footer and the force-key-reset flag (as
// open62541 UA_PubSub_EnDecode_SecurityHeaderAndFooter): the footer is part of
// the signed range and not of the payload.
func TestSecurityFooter(t *testing.T) {
	ks := zeroKeys(testPolicy{})
	ks.keys.TokenID = 42
	plain := unhex(t, o6HeaderNoSec+o6PayloadDec)
	// Turn on security in ExtendedFlags1 and insert the security header:
	// signed, footer, force key reset; token 42; no nonce; footer of 4.
	msg := append([]byte{plain[0], plain[1] | ext1Security}, plain[2:10]...)
	msg = append(msg, 0x0d, 42, 0, 0, 0, 0, 4, 0)
	msg = append(msg, plain[10:]...)
	msg = append(msg, 0x10, 0x20, 0x30, 0x40)
	sig, _ := testPolicy{}.Sign(ks.keys, msg)
	msg = append(msg, sig...)

	nm, err := Decode(msg, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSign, ks)})
	require.NoError(t, err)
	require.Equal(t, &message.SecurityHeader{Signed: true, ForceKeyReset: true, SecurityTokenID: 42, FooterSize: 4}, nm.Security)
	require.Equal(t, o6Message(t).Messages, nm.Messages)

	// A footer larger than what follows the header.
	msg2 := append([]byte(nil), msg[:len(msg)-32]...)
	msg2[16] = 0xff
	sig, _ = testPolicy{}.Sign(ks.keys, msg2)
	msg2 = append(msg2, sig...)
	_, err = Decode(msg2, &DecodeOptions{Security: requireSecurity(ua.MessageSecurityModeSign, ks)})
	require.ErrorIs(t, err, ErrMalformed)
}

// Accept sees the header before the security is checked.
func TestAccept(t *testing.T) {
	enc := unhex(t, o6Header+o6PayloadEnc+o6Sig)
	var seen *message.NetworkMessage
	_, err := Decode(enc, &DecodeOptions{Accept: func(h *message.NetworkMessage) bool {
		seen = h
		return false
	}})
	require.ErrorIs(t, err, ErrFiltered)
	require.Equal(t, uint16(62541), seen.Messages[0].DataSetWriterID)
	require.Equal(t, uint32(1), seen.Security.SecurityTokenID)
}
