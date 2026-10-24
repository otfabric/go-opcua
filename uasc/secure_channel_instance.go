// SPDX-License-Identifier: MIT

package uasc

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

type instanceState int

const (
	channelOpening instanceState = iota
	channelActive
)

type channelInstance struct {
	sync.Mutex
	sc              *SecureChannel
	state           instanceState
	createdAt       time.Time
	revisedLifetime time.Duration
	secureChannelID uint32
	securityTokenID uint32
	sequenceNumber  uint32
	algo            *uapolicy.EncryptionAlgorithm

	// zeroBasedSeq selects the sequence number rules of the security
	// policies without LegacySequenceNumbers (ECC): the first number is 0 and
	// the numbers wrap to 0 after UInt32.MaxValue (Part 6 §6.7.2.4).
	// seqStarted records that the first number has been handed out.
	zeroBasedSeq bool
	seqStarted   bool
	maxBodySize  uint32

	// expiry retires the token; expired is set once a client token has
	// outlived its grace period. Both are guarded by
	// SecureChannel.instancesMu.
	expiry  *time.Timer
	expired bool

	bytesSent uint64 // atomic.Load/Store - needs to be aligned for 32bit systems
	// bytesReceived    uint64
	messagesSent uint32 // atomic.Load/Store
	// messagesReceived uint32
}

func newChannelInstance(sc *SecureChannel) *channelInstance {
	return &channelInstance{
		sc:    sc,
		state: channelOpening,
	}
}

func (c *channelInstance) nextSequenceNumber() uint32 {
	// lock must be held
	if c.zeroBasedSeq {
		if !c.seqStarted {
			c.seqStarted = true
			c.sequenceNumber = 0
			return 0
		}
		c.sequenceNumber++ // wraps to 0 after UInt32.MaxValue
		return c.sequenceNumber
	}

	c.sequenceNumber++
	if c.sequenceNumber > math.MaxUint32-1023 {
		c.sequenceNumber = 1
	}

	return c.sequenceNumber
}

func (c *channelInstance) newRequestMessage(req ua.Request, reqID uint32, authToken *ua.NodeID, timeout time.Duration) (*Message, error) {
	typeID := ua.ServiceTypeID(req)
	if typeID == 0 {
		return nil, fmt.Errorf("%w: %T", errors.ErrUnknownService, req)
	}
	if authToken == nil {
		authToken = ua.NewTwoByteNodeID(0)
	}

	reqHdr := &ua.RequestHeader{
		AuthenticationToken: authToken,
		Timestamp:           c.sc.timeNow(),
		RequestHandle:       reqID, // client-assigned; reusing reqID for simple correlation
	}

	// The header is created here, but the caller may have set fields of it
	// that belong to the request rather than to the channel: the
	// ReturnDiagnostics mask and the AuditEntryId (Part 4 §7.33), and the
	// AdditionalHeader CreateSession and ActivateSession use to ask for the
	// ephemeral key of an ECC security policy.
	if prev := req.Header(); prev != nil {
		reqHdr.ReturnDiagnostics = prev.ReturnDiagnostics
		reqHdr.AuditEntryID = prev.AuditEntryID
		reqHdr.AdditionalHeader = prev.AdditionalHeader
	}

	if timeout > 0 && timeout < c.sc.cfg.RequestTimeout {
		timeout = c.sc.cfg.RequestTimeout
	}
	reqHdr.TimeoutHint = uint32(timeout / time.Millisecond)
	req.SetHeader(reqHdr)

	// encode the message
	return c.newMessage(req, typeID, reqID), nil
}

func (c *channelInstance) newMessage(srv interface{}, typeID uint16, requestID uint32) *Message {
	sequenceNumber := c.nextSequenceNumber()
	c.sc.cfg.Logger.Debug("got sequence number", "sequence_number", sequenceNumber)

	switch typeID {
	case id.OpenSecureChannelRequestEncodingDefaultBinary, id.OpenSecureChannelResponseEncodingDefaultBinary:
		// Do not send the thumbprint for security mode None
		// even if we have a certificate.
		//
		// See https://github.com/otfabric/go-opcua/issues/259
		thumbprint := c.sc.cfg.Thumbprint
		if c.sc.cfg.SecurityMode == ua.MessageSecurityModeNone {
			thumbprint = nil
		}

		return &Message{
			MessageHeader: &MessageHeader{
				Header:                   NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, c.secureChannelID),
				AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(c.sc.cfg.SecurityPolicyURI, c.sc.cfg.Certificate, thumbprint),
				SequenceHeader:           NewSequenceHeader(sequenceNumber, requestID),
			},
			TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
			Service: srv,
		}

	case id.CloseSecureChannelRequestEncodingDefaultBinary, id.CloseSecureChannelResponseEncodingDefaultBinary:
		return &Message{
			MessageHeader: &MessageHeader{
				Header:                  NewHeader(MessageTypeCloseSecureChannel, ChunkTypeFinal, c.secureChannelID),
				SymmetricSecurityHeader: NewSymmetricSecurityHeader(c.securityTokenID),
				SequenceHeader:          NewSequenceHeader(sequenceNumber, requestID),
			},
			TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
			Service: srv,
		}

	default:
		return &Message{
			MessageHeader: &MessageHeader{
				Header:                  NewHeader(MessageTypeMessage, ChunkTypeFinal, c.secureChannelID),
				SymmetricSecurityHeader: NewSymmetricSecurityHeader(c.securityTokenID),
				SequenceHeader:          NewSequenceHeader(sequenceNumber, requestID),
			},
			TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
			Service: srv,
		}
	}
}

func (c *channelInstance) SetMaximumBodySize(chunkSize int) {
	sequenceHeaderSize := 8
	headerSize := 12
	symmetricAlgorithmHeader := 4

	// What follows the headers is encrypted in whole cipher blocks, so only
	// as many blocks as fit the chunk can be used. They hold the sequence
	// header, the body, the padding and the signature. signAndEncrypt pads
	// with at least one byte besides the padding size (two size bytes for
	// keys above 2048 bits), so reserve those: a body that left room for the
	// padding size only would be padded by a whole block and the chunk would
	// no longer fit the send buffer of the connection.
	//
	// The formula used before (from node-opcua) took the signature and one
	// padding byte off before rounding down to whole blocks. Whenever the
	// signature length is a multiple of the block size, which it is for all
	// policies, that leaves the padding out of the calculation: with a send
	// buffer of 65535 bytes every full chunk was 65536 bytes long.
	padding := 2
	if c.algo.RemoteSignatureLength() > 256 {
		padding = 3
	}
	blocks := (chunkSize - headerSize - symmetricAlgorithmHeader) / c.algo.BlockSize()
	maxBodySize := c.algo.PlaintextBlockSize()*blocks - sequenceHeaderSize - c.algo.SignatureLength() - padding
	if maxBodySize < 0 {
		maxBodySize = 0
	}
	c.maxBodySize = uint32(maxBodySize)
}

// signAndEncrypt encrypts the message bytes stored in b and returns the
// data signed and encrypted per the security policy information from the
// secure channel.
func (c *channelInstance) signAndEncrypt(m *Message, b []byte) ([]byte, error) {
	// Nothing to do
	if c.sc.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return b, nil
	}

	isAsymmetric := m.AsymmetricSecurityHeader != nil

	var headerLength int

	if isAsymmetric {
		headerLength = 12 + m.AsymmetricSecurityHeader.Len()
	} else {
		headerLength = 12 + m.SymmetricSecurityHeader.Len()
	}

	// Authenticated encryption has a chunk layout of its own.
	if !isAsymmetric && c.algo.AEAD() {
		return c.sealChunk(m, b, headerLength)
	}

	// OpenSecureChannel messages are encrypted whatever the security mode,
	// unless the policy has no asymmetric encryption (ECC): then they are
	// signed only and carry no padding.
	encrypted := c.sc.cfg.SecurityMode == ua.MessageSecurityModeSignAndEncrypt || isAsymmetric
	if isAsymmetric && c.algo.SignOnly() {
		encrypted = false
	}

	var encryptedLength int
	if encrypted {
		plaintextBlockSize := c.algo.PlaintextBlockSize()
		extraPadding := c.algo.RemoteSignatureLength() > 256
		paddingBytes := 1
		if extraPadding {
			paddingBytes = 2
		}
		paddingLength := plaintextBlockSize - ((len(b[headerLength:]) + c.algo.SignatureLength() + paddingBytes) % plaintextBlockSize)

		for i := 0; i <= paddingLength; i++ {
			b = append(b, byte(paddingLength))
		}
		if extraPadding {
			b = append(b, byte(paddingLength>>8))
		}
		encryptedLength = ((len(b[headerLength:]) + c.algo.SignatureLength()) / plaintextBlockSize) * c.algo.BlockSize()
	} else { // MessageSecurityModeSign
		encryptedLength = len(b[headerLength:]) + c.algo.SignatureLength()
	}

	// Fix header size to account for signing / encryption
	binary.LittleEndian.PutUint32(b[4:], uint32(headerLength+encryptedLength))
	m.MessageSize = uint32(headerLength + encryptedLength)

	signed := b
	if isAsymmetric {
		signed = c.sc.binding.signedData(c.sc, b)
	}
	signature, err := c.algo.Signature(signed)
	if err != nil {
		return nil, ua.StatusBadSecurityChecksFailed
	}
	if isAsymmetric {
		c.sc.binding.sent(c.sc, signature)
	}

	b = append(b, signature...)
	p := b[headerLength:]
	if encrypted {
		p, err = c.algo.Encrypt(p)
		if err != nil {
			return nil, ua.StatusBadSecurityChecksFailed
		}
	}
	return append(b[:headerLength], p...), nil
}

func (c *channelInstance) verifyAndDecrypt(m *MessageChunk, r []byte) ([]byte, error) {
	// OPC UA Part 6 §6.7.4: OPN messages (isAsymmetric) are always encrypted and
	// signed even in Sign mode, to protect the client nonce. The SecurityMode field
	// starts as None on the server until the first OPN is fully processed, so we
	// cannot use SecurityMode alone for the early-return decision.
	//
	// Use the algo instead: nil means no algo configured (None pre-OPN),
	// remoteSignatureLength == 0 means the None security policy is active.
	// Both cases require no crypto.
	if c.algo == nil || (c.algo.RemoteSignatureLength() == 0 && !c.algo.SignOnly()) {
		return m.Data, nil
	}

	isAsymmetric := m.AsymmetricSecurityHeader != nil

	// See signAndEncrypt: ECC OpenSecureChannel messages are signed only.
	encrypted := c.sc.cfg.SecurityMode == ua.MessageSecurityModeSignAndEncrypt || isAsymmetric
	if isAsymmetric && c.algo.SignOnly() {
		encrypted = false
	}

	headerLength := 12

	if isAsymmetric {
		headerLength += m.AsymmetricSecurityHeader.Len()
	} else {
		headerLength += m.SymmetricSecurityHeader.Len()
	}

	if !isAsymmetric && c.algo.AEAD() {
		return c.openChunk(m, r, headerLength)
	}

	b := make([]byte, len(r))
	copy(b, r)

	if encrypted {
		p, err := c.algo.Decrypt(b[headerLength:])
		if err != nil {
			return nil, ua.StatusBadSecurityChecksFailed
		}
		b = append(b[:headerLength], p...)
	}

	// A signature is required. Without a key to verify it with there is
	// nothing to trust, and a chunk too short to hold one is malformed.
	sigLen := c.algo.RemoteSignatureLength()
	if sigLen == 0 || len(b) < headerLength+sigLen {
		return nil, ua.StatusBadSecurityChecksFailed
	}

	signature := b[len(b)-sigLen:]
	messageToVerify := b[:len(b)-sigLen]

	verified := messageToVerify
	if isAsymmetric {
		verified = c.sc.binding.verifiedData(c.sc, messageToVerify)
	}
	if err := c.algo.VerifySignature(verified, signature); err != nil {
		return nil, ua.StatusBadSecurityChecksFailed
	}
	if isAsymmetric {
		c.sc.binding.received(c.sc, signature)
	}

	var paddingLength int
	if encrypted {
		paddingLength = int(messageToVerify[len(messageToVerify)-1])
		if c.algo.SignatureLength() > 256 {
			paddingLength <<= 8
			paddingLength += int(messageToVerify[len(messageToVerify)-2])
			paddingLength += 1
		}
		paddingLength += 1
	}

	b = messageToVerify[headerLength : len(messageToVerify)-paddingLength]

	return b, nil
}

// sealChunk secures a symmetric chunk of a security policy with authenticated
// encryption (Part 6 §6.7.2): no padding, and a tag in place of the signature.
// The nonce is made from the TokenId and the sequence number of the chunk
// sent before this one; see uapolicy.EncryptionAlgorithm.SealChunk.
func (c *channelInstance) sealChunk(m *Message, b []byte, headerLength int) ([]byte, error) {
	if len(b) < headerLength+8 {
		return nil, ua.StatusBadSecurityChecksFailed
	}
	size := uint32(len(b) + c.algo.SignatureLength())
	binary.LittleEndian.PutUint32(b[4:], size)
	m.MessageSize = size

	tokenID := binary.LittleEndian.Uint32(b[headerLength-4:])
	// Sequence numbers of these policies are contiguous and wrap at
	// UInt32.MaxValue, so the previous number is always one less.
	lastSequenceNumber := binary.LittleEndian.Uint32(b[headerLength:]) - 1

	encrypt := c.sc.cfg.SecurityMode == ua.MessageSecurityModeSignAndEncrypt
	out, err := c.algo.SealChunk(b, headerLength, tokenID, lastSequenceNumber, encrypt)
	if err != nil {
		c.sc.cfg.Logger.Warn("cannot secure message chunk", "error", err)
		return nil, ua.StatusBadSecurityChecksFailed
	}
	return out, nil
}

// openChunk is the reverse of sealChunk. The nonce needs the sequence number
// of the chunk received before this one, which the channel keeps: the number
// of the chunk itself is encrypted.
func (c *channelInstance) openChunk(m *MessageChunk, r []byte, headerLength int) ([]byte, error) {
	encrypted := c.sc.cfg.SecurityMode == ua.MessageSecurityModeSignAndEncrypt
	out, err := c.algo.OpenChunk(r, headerLength, m.TokenID, c.sc.lastReceivedSequenceNumber.Load(), encrypted)
	if err != nil {
		return nil, ua.StatusBadSecurityChecksFailed
	}
	return out[headerLength:], nil
}
