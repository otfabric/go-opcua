// SPDX-License-Identifier: MIT

// Package uadp implements the UADP message mapping of OPC UA PubSub
// (Part 14 §7.2.2 in 1.04, §7.2.4 in 1.05): the binary encoding of
// NetworkMessages and DataSetMessages, including the message security of the
// security header.
//
// # Wire layout
//
// A NetworkMessage is laid out as
//
//	UADPFlags | ExtendedFlags1 | ExtendedFlags2 | PublisherId | DataSetClassId
//	GroupHeader | PayloadHeader | Timestamp | PicoSeconds | PromotedFields
//	SecurityHeader | Payload | SecurityFooter | Signature
//
// Which optional parts are present follows [message.NetworkMessage.UADPMask]
// and [message.DataSetMessage.UADPMask] on encode; Decode reports what it found
// in the same masks. ExtendedFlags1 and ExtendedFlags2 are only written when
// one of their bits is needed, exactly as open62541 does.
//
// # Security
//
// With SecurityMode Sign the signature covers the whole message from the
// UADPFlags up to and including the SecurityFooter. With SignAndEncrypt the
// Payload and the SecurityFooter are encrypted first (in place, AES-CTR keeps
// the length) with the MessageNonce of the security header, and the signature
// is then computed over the encrypted message. This is the layout of open62541
// (src/pubsub/ua_pubsub_writergroup.c, encryptAndSign; readergroup.c,
// verifyAndDecryptNetworkMessage). The codec is independent of the policy: it
// only calls the [security.Policy] methods.
//
// # Chunks
//
// Chunked NetworkMessages (ExtendedFlags2 bit 0) are not supported: open62541
// 1.5.9 neither sends nor accepts them. Decode rejects them with
// [ErrUnsupported].
package uadp

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// Errors returned by Encode and Decode. They are wrapped with details; test
// with errors.Is.
var (
	// ErrFiltered is returned by Decode when the Accept callback rejected
	// the message after its header was decoded.
	ErrFiltered = errors.New("pubsub/uadp: message filtered")
	// ErrMalformed is returned for a message that does not follow the
	// UADP encoding, and by Encode for a NetworkMessage that cannot be
	// encoded.
	ErrMalformed = errors.New("pubsub/uadp: malformed message")
	// ErrUnsupported is returned for valid UADP features this package does
	// not implement (chunked messages, discovery messages other than
	// DataSetMetaData announcements).
	ErrUnsupported = errors.New("pubsub/uadp: unsupported")
	// ErrSecurityMode is returned by Decode when the security of a message
	// is weaker than required, or when a secured message arrives and no
	// keys are available to verify it.
	ErrSecurityMode = errors.New("pubsub/uadp: security mode rejected")
	// ErrSecurityChecksFailed is returned by Decode for an invalid security
	// header, a bad signature or a failed decryption, and by Encode when
	// signing or encryption fails.
	ErrSecurityChecksFailed = errors.New("pubsub/uadp: security checks failed")
	// ErrNoMetaData is returned by Decode for a RawData DataSetMessage
	// whose DataSetMetaData the MetaData callback does not supply: RawData
	// fields carry no type information.
	ErrNoMetaData = errors.New("pubsub/uadp: RawData needs the DataSetMetaData")
)

// Limits of the decoder. Every count and length read from the wire is
// bounded by them and by the bytes that are actually left.
const (
	// MaxNonceLength is the largest MessageNonce accepted (open62541:
	// UA_NETWORKMESSAGE_MAX_NONCE_LENGTH).
	MaxNonceLength = 16
	// maxMessages is the largest number of DataSetMessages of one
	// NetworkMessage: the count is a Byte.
	maxMessages = 0xff
)

// EncodeOptions control Encode.
type EncodeOptions struct {
	// SecurityMode is None (or Invalid) for an unsecured message, Sign or
	// SignAndEncrypt. Keys must be set for the latter two.
	SecurityMode ua.MessageSecurityMode
	Keys         security.KeySource
	// NonceSequence is the sender's message counter used to build unique
	// MessageNonces; the caller increments it for every secured message.
	NonceSequence uint32
	// MetaData supplies the DataSetMetaData of RawData DataSetMessages:
	// the MaxStringLength padding of String and ByteString fields, the
	// number of array dimensions and their upper bounds. Without it,
	// RawData fields are written as their values are typed and sized.
	MetaData message.MetaDataLookup
}

// DecodeOptions control Decode.
type DecodeOptions struct {
	// Accept, if set, is called with the decoded NetworkMessage header
	// (publisher id, group header, payload header, security header)
	// before the payload is verified, decrypted and decoded. Returning
	// false stops decoding with ErrFiltered. The DataSetMessages of the
	// header carry only their DataSetWriterID.
	Accept func(header *message.NetworkMessage) bool
	// Security returns the security mode the receiver requires for a
	// message and the keys to verify and decrypt it. It is called after
	// Accept. Nil, or a nil KeySource, accepts only unsecured messages.
	Security func(header *message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error)
	// MetaData supplies the DataSetMetaData needed to decode RawData
	// fields and to name fields. Without a PayloadHeader the
	// DataSetWriterId is unknown and passed as 0.
	MetaData message.MetaDataLookup
}

// Encode encodes a NetworkMessage.
//
// A NetworkMessage of type NetworkMessageDataSet needs at least one
// DataSetMessage, and the PayloadHeader when it has more than one. A
// NetworkMessage of type NetworkMessageDiscoveryResponse carries
// nm.Discovery; only DataSetMetaData announcements are supported, and the
// PayloadHeader bit of the mask is ignored for them. The WriterGroupId,
// GroupVersion, NetworkMessageNumber and SequenceNumber bits only take effect
// together with the GroupHeader bit. nm.Security is ignored: the security
// header follows from opts. Encode does not modify nm.
//
// For a secured message the caller increments opts.NonceSequence for every
// message; MessageNonces must never repeat for the same keys, since AES-CTR
// with a repeated counter block reveals the plaintext.
func Encode(nm *message.NetworkMessage, opts *EncodeOptions) ([]byte, error) {
	if nm == nil {
		return nil, fmt.Errorf("%w: nil NetworkMessage", ErrMalformed)
	}
	if opts == nil {
		opts = &EncodeOptions{}
	}
	sec, err := newEncodeSecurity(opts)
	if err != nil {
		return nil, err
	}
	e := &encoder{nm: nm, opts: opts, sec: sec}
	return e.encode()
}

// Decode decodes a NetworkMessage. It never modifies b; the returned message
// does not reference b.
func Decode(b []byte, opts *DecodeOptions) (*message.NetworkMessage, error) {
	if opts == nil {
		opts = &DecodeOptions{}
	}
	d := &decoder{b: bytes.Clone(b), opts: opts}
	return d.decode()
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformed}, args...)...)
}

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnsupported}, args...)...)
}
