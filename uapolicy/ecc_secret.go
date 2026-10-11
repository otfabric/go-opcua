// SPDX-License-Identifier: MIT

package uapolicy

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// EccEncryptedSecret (Part 4 §7.41.2.3 "EncryptedSecret format", Part 6
// §6.8.3).
//
// With an ECC security policy the secret of a UserIdentityToken (the password
// of a UserNameIdentityToken, the token data of an IssuedIdentityToken) cannot
// be encrypted with the receiver's certificate. The receiver hands out an
// ephemeral public key instead (EphemeralKeyType in the AdditionalHeader of
// the CreateSession and ActivateSession responses). The sender creates an
// ephemeral key of its own, derives an encryption key from the key agreement
// and signs the result with its application instance key:
//
//	TypeId            NodeId      i=17546 (EccEncryptedSecret)
//	EncodingMask      Byte        1
//	Length            UInt32      number of bytes that follow
//	SecurityPolicyUri String
//	Certificate       ByteString  signing certificate of the sender
//	SigningTime       DateTime
//	KeyDataLength     UInt16      length of the two fields that follow
//	SenderPublicKey   ByteString  ephemeral key of the sender
//	ReceiverPublicKey ByteString  ephemeral key of the receiver
//	-- encrypted ------------------------------------------------------
//	Nonce             ByteString  the receiver's last session nonce
//	Secret            ByteString
//	Padding           Byte[*]     every byte is the low byte of PaddingSize
//	PaddingSize       UInt16
//	-- end of encrypted data ------------------------------------------
//	Tag               Byte[16]    policies with authenticated encryption only
//	Signature         Byte[*]     over everything above
//
// The encryption key and initialization vector are derived with
//
//	Salt = L | "opcua-secret" | SenderPublicKey | ReceiverPublicKey
//	EncryptingKey | InitializationVector = HKDF(shared secret, Salt, Info = Salt, L)
//
// The policies with authenticated encryption (AES-GCM, ChaCha20-Poly1305)
// seal the payload with the derived key and the IV as it is derived. The
// additional authenticated data is everything in front of the payload, from
// the TypeId to the ReceiverPublicKey, and the tag follows the ciphertext.
// The payload is padded to a multiple of 16 bytes all the same. This is the
// construction of open62541 v1.5.9.

const eccSecretPrefixLength = 4 + 1 + 4 // TypeId (four byte NodeId), EncodingMask, Length

// Secret is the content of a decrypted EccEncryptedSecret.
type Secret struct {
	// Nonce is the nonce the sender bound the secret to: the last session
	// nonce it received. The receiver must compare it with the nonce it
	// issued; DecryptSecret does not know it.
	Nonce []byte

	// Secret is the protected value.
	Secret []byte

	// Certificate is the signing certificate named in the secret.
	Certificate []byte

	// SigningTime is when the sender created the secret.
	SigningTime time.Time
}

// EncryptSecret creates an EccEncryptedSecret for the ECC security policy.
//
// receiverPublicKey is the ephemeral public key the receiver handed out,
// nonce the receiver's last session nonce and secret the value to protect.
// The result is signed with signingKey, the private key of signingCertificate
// (the sender's application instance certificate).
func EncryptSecret(uri string, signingKey crypto.PrivateKey, signingCertificate, receiverPublicKey, nonce, secret []byte, signingTime time.Time) ([]byte, error) {
	p, ok := eccPolicies[uri]
	if !ok {
		return nil, fmt.Errorf("%w: %s is not an ECC policy", errors.ErrUnsupportedSecurityPolicy, uri)
	}
	if isNilKey(signingKey) {
		return nil, fmt.Errorf("%w: %s needs a private key to sign the secret", errors.ErrInvalidSecurityConfig, uri)
	}
	signer, signatureLength, err := p.signature.signer(signingKey)
	if err != nil {
		return nil, err
	}

	sender, err := NewEphemeralKey(uri)
	if err != nil {
		return nil, err
	}
	key, iv, err := p.secretKeys(sender, sender.public, receiverPublicKey, receiverPublicKey)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	// The payload is padded to the cipher block size. If the secret together
	// with the padding is shorter than a block another block is added, so the
	// length of a short secret cannot be read off the message.
	const block = AESBlockSize
	payloadLength := 4 + len(nonce) + 4 + len(secret) + 2
	padding := 0
	if r := payloadLength % block; r != 0 {
		padding = block - r
	}
	if padding+len(secret) < block {
		padding += block
	}
	payloadLength += padding

	keyDataLength := 4 + len(sender.public) + 4 + len(receiverPublicKey)

	buf := ua.NewBuffer(nil)
	buf.WriteStruct(ua.NewFourByteNodeID(0, id.EccEncryptedSecret))
	buf.WriteUint8(1)
	lengthPos := buf.Len()
	buf.WriteUint32(0) // patched below
	buf.WriteString(uri)
	buf.WriteByteString(signingCertificate)
	buf.WriteTime(signingTime)
	buf.WriteUint16(uint16(keyDataLength))
	buf.WriteByteString(sender.public)
	buf.WriteByteString(receiverPublicKey)
	headerLength := buf.Len()

	buf.WriteByteString(nonce)
	buf.WriteByteString(secret)
	buf.Write(bytes.Repeat([]byte{byte(padding)}, padding))
	buf.WriteUint16(uint16(padding))
	if err := buf.Error(); err != nil {
		return nil, err
	}

	out := buf.Bytes()
	if len(out) != headerLength+payloadLength {
		return nil, fmt.Errorf("%w: encrypted secret: inconsistent length", errors.ErrInvalidState)
	}
	binary.LittleEndian.PutUint32(out[lengthPos:], uint32(len(out)-eccSecretPrefixLength+p.symmetric.secretOverhead()+signatureLength))

	encrypted, err := p.symmetric.sealSecret(key, iv, out[:headerLength], out[headerLength:])
	clear(out[headerLength:])
	if err != nil {
		return nil, err
	}
	out = append(out[:headerLength], encrypted...)

	signature, err := signer.Signature(out)
	if err != nil {
		return nil, err
	}
	if len(signature) != signatureLength {
		return nil, fmt.Errorf("%w: encrypted secret: unexpected signature length", errors.ErrInvalidState)
	}
	return append(out, signature...), nil
}

// secretKeys derives the encryption key and initialization vector of an
// EccEncryptedSecret. local is the ephemeral key of the caller and
// remotePublicKey the one of the other side.
func (p *eccPolicy) secretKeys(local *EphemeralKey, senderPublicKey, receiverPublicKey, remotePublicKey []byte) (key, iv []byte, err error) {
	if local == nil || local.policy != p {
		return nil, nil, fmt.Errorf("%w: ephemeral key does not belong to %s", errors.ErrInvalidSecurityConfig, p.uri)
	}
	shared, err := local.key.sharedSecret(remotePublicKey)
	if err != nil {
		return nil, nil, err
	}
	defer clear(shared)

	keyLength := p.symmetric.encryptingKeyLength()
	okm, err := p.deriveKeys(shared, eccLabelSecret, senderPublicKey, receiverPublicKey, keyLength+p.symmetric.ivLength())
	if err != nil {
		return nil, nil, err
	}
	return okm[:keyLength], okm[keyLength:], nil
}

// DecryptSecret verifies and decrypts an EccEncryptedSecret that was created
// for this ephemeral key.
//
// signerKey is called with the signing certificate named in the secret and
// returns the public key to verify the signature with. That is where the
// caller decides whether the certificate is acceptable: a Server requires the
// application instance certificate of the Session's Client. The signature is
// verified before anything is decrypted.
//
// The caller must still compare Secret.Nonce with the nonce it issued, and
// must not accept a second secret for the same ephemeral key.
func (k *EphemeralKey) DecryptSecret(data []byte, signerKey func(certificate []byte) (crypto.PublicKey, error)) (*Secret, error) {
	p := k.policy
	invalid := func(what string) error {
		return fmt.Errorf("%w: encrypted secret: %s", errors.ErrInvalidCiphertext, what)
	}

	buf := ua.NewBuffer(data)
	typeID := new(ua.NodeID)
	buf.ReadStruct(typeID)
	mask := buf.ReadUint8()
	length := buf.ReadUint32()
	if buf.Error() != nil {
		return nil, invalid("truncated header")
	}
	if typeID.Namespace() != 0 || typeID.Type() == ua.NodeIDTypeString || typeID.IntID() != id.EccEncryptedSecret || mask != 1 {
		return nil, invalid("not an EccEncryptedSecret")
	}
	// Length counts the bytes that follow the Length field. The secret is the
	// whole ByteString: nothing may follow it.
	if uint64(buf.Pos())+uint64(length) != uint64(len(data)) {
		return nil, invalid("inconsistent length")
	}

	policyURI := buf.ReadString()
	certificate := buf.ReadBytes()
	signingTime := buf.ReadTime()
	keyDataLength := int(buf.ReadUint16())
	if buf.Error() != nil {
		return nil, invalid("truncated header")
	}
	if policyURI != p.uri {
		return nil, fmt.Errorf("%w: encrypted secret: policy %q does not match %q", errors.ErrInvalidSecurityConfig, policyURI, p.uri)
	}

	// Authenticate before parsing or decrypting anything else.
	if signerKey == nil {
		return nil, fmt.Errorf("%w: encrypted secret: no signing key", errors.ErrInvalidSecurityConfig)
	}
	pub, err := signerKey(certificate)
	if err != nil {
		return nil, err
	}
	if isNilKey(pub) {
		return nil, errors.ErrSignatureValidationFailed
	}
	verifier, signatureLength, err := p.signature.verifier(pub)
	if err != nil {
		return nil, err
	}
	if len(data)-buf.Pos() < keyDataLength+signatureLength {
		return nil, invalid("truncated")
	}
	signed, signature := data[:len(data)-signatureLength], data[len(data)-signatureLength:]
	if err := verifier.Verify(signed, signature); err != nil {
		return nil, err
	}

	keyDataStart := buf.Pos()
	senderPublicKey := buf.ReadBytes()
	receiverPublicKey := buf.ReadBytes()
	if buf.Error() != nil || buf.Pos()-keyDataStart != keyDataLength {
		return nil, invalid("inconsistent key data")
	}
	// The secret must have been made for this ephemeral key and no other.
	if !bytes.Equal(receiverPublicKey, k.public) {
		return nil, invalid("not encrypted for this ephemeral key")
	}

	header, payload := signed[:buf.Pos()], signed[buf.Pos():]
	if len(payload) == 0 {
		return nil, invalid("no payload")
	}
	key, iv, err := p.secretKeys(k, senderPublicKey, receiverPublicKey, senderPublicKey)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	plain, err := p.symmetric.openSecret(key, iv, header, payload)
	if err != nil {
		return nil, err
	}

	body := ua.NewBuffer(plain)
	nonce := buf2bytes(body)
	secret := buf2bytes(body)
	if body.Error() != nil || len(plain)-body.Pos() < 2 {
		clear(plain)
		return nil, invalid("malformed payload")
	}
	padding := plain[body.Pos() : len(plain)-2]
	paddingSize := binary.LittleEndian.Uint16(plain[len(plain)-2:])
	// Constant time: the padding is derived from secret data.
	want := bytes.Repeat([]byte{byte(paddingSize)}, len(padding))
	if int(paddingSize) != len(padding) || subtle.ConstantTimeCompare(padding, want) != 1 {
		clear(plain)
		return nil, invalid("invalid padding")
	}

	return &Secret{
		Nonce:       nonce,
		Secret:      secret,
		Certificate: certificate,
		SigningTime: signingTime,
	}, nil
}

// buf2bytes reads a ByteString and returns a copy that does not alias the
// buffer; a null ByteString is returned as an empty one.
func buf2bytes(b *ua.Buffer) []byte {
	return append([]byte{}, b.ReadBytes()...)
}
