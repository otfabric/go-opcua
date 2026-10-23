// SPDX-License-Identifier: MIT

// Package uadp implements the UADP message mapping of OPC UA PubSub
// (Part 14 §7.2.2): the binary encoding of NetworkMessages and
// DataSetMessages, including the message security of the security header.
package uadp

import (
	"errors"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

// ErrFiltered is returned by Decode when the Accept callback rejected the
// message after its header was decoded.
var ErrFiltered = errors.New("pubsub/uadp: message filtered")

// EncodeOptions control Encode.
type EncodeOptions struct {
	// SecurityMode is None (or Invalid) for an unsecured message, Sign or
	// SignAndEncrypt. Keys must be set for the latter two.
	SecurityMode ua.MessageSecurityMode
	Keys         security.KeySource
	// NonceSequence is the sender's message counter used to build unique
	// MessageNonces; the caller increments it for every secured message.
	NonceSequence uint32
}

// DecodeOptions control Decode.
type DecodeOptions struct {
	// Accept, if set, is called with the decoded NetworkMessage header
	// (publisher id, group header, payload header, security header)
	// before the payload is verified, decrypted and decoded. Returning
	// false stops decoding with ErrFiltered.
	Accept func(header *message.NetworkMessage) bool
	// Security returns the security mode the receiver requires for a
	// message and the keys to verify and decrypt it. It is called after
	// Accept. Nil, or a nil KeySource, accepts only unsecured messages.
	Security func(header *message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error)
	// MetaData supplies the DataSetMetaData needed to decode RawData
	// fields and to name fields.
	MetaData message.MetaDataLookup
}

// Encode encodes a NetworkMessage.
func Encode(nm *message.NetworkMessage, opts *EncodeOptions) ([]byte, error) {
	return nil, errors.New("pubsub/uadp: not implemented")
}

// Decode decodes a NetworkMessage.
func Decode(b []byte, opts *DecodeOptions) (*message.NetworkMessage, error) {
	return nil, errors.New("pubsub/uadp: not implemented")
}
