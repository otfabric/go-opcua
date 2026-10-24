// SPDX-License-Identifier: MIT

package pubsub

import (
	"bytes"
	"errors"
	"strings"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
)

// encoding is a message mapping.
type encoding uint8

const (
	encUADP encoding = iota
	encJSON
)

func (e encoding) String() string {
	if e == encJSON {
		return "JSON"
	}
	return "UADP"
}

// codec is the message mapping as the runtime uses it. The UADP and JSON
// implementations call package uadp and package jsonmsg; the options of the
// UADP codec carry the security and filter hooks for both (JSON has no
// message security).
type codec interface {
	// Encode encodes a NetworkMessage: data or, for UADP, a discovery
	// announcement of DataSetMetaData.
	Encode(nm *message.NetworkMessage, opts *uadp.EncodeOptions) ([]byte, error)
	// Decode decodes a NetworkMessage. It returns uadp.ErrFiltered if
	// opts.Accept rejected the message.
	Decode(b []byte, opts *decodeOptions) (*message.NetworkMessage, error)
	// EncodeChunks encodes a NetworkMessage of one DataSetMessage (or an
	// announcement) as UADP chunks of at most maxSize bytes;
	// DecodeReassembled decodes the message reassembled from the chunks
	// of header. The JSON mapping has no chunks.
	EncodeChunks(nm *message.NetworkMessage, opts *uadp.EncodeOptions, maxSize int) ([][]byte, error)
	DecodeReassembled(header *message.NetworkMessage, payload []byte, opts *decodeOptions) (*message.NetworkMessage, error)
	// EncodeMetaData and DecodeMetaData handle the "ua-metadata" messages
	// of the JSON mapping.
	EncodeMetaData(m *jsonmsg.MetaDataMessage) ([]byte, error)
	DecodeMetaData(b []byte, opts *decodeOptions) (*jsonmsg.MetaDataMessage, error)
}

// decodeOptions are the options of the UADP decoder plus the fallbacks the
// JSON decoder uses for messages without DataSetWriterId or PublisherId.
type decodeOptions struct {
	uadp.DecodeOptions
	DataSetWriterID uint16
	PublisherID     *message.PublisherID
}

func (o *decodeOptions) json() *jsonmsg.DecodeOptions {
	if o == nil {
		return &jsonmsg.DecodeOptions{}
	}
	return &jsonmsg.DecodeOptions{MetaData: o.MetaData, DataSetWriterID: o.DataSetWriterID, PublisherID: o.PublisherID}
}

var errNoJSONMetaData = errors.New("pubsub: the UADP mapping announces DataSetMetaData with discovery messages")

type uadpCodec struct{}

func (uadpCodec) Encode(nm *message.NetworkMessage, opts *uadp.EncodeOptions) ([]byte, error) {
	return uadp.Encode(nm, opts)
}

func (uadpCodec) Decode(b []byte, opts *decodeOptions) (*message.NetworkMessage, error) {
	if opts == nil {
		return uadp.Decode(b, nil)
	}
	return uadp.Decode(b, &opts.DecodeOptions)
}

func (uadpCodec) EncodeChunks(nm *message.NetworkMessage, opts *uadp.EncodeOptions, maxSize int) ([][]byte, error) {
	return uadp.EncodeChunks(nm, opts, maxSize)
}

func (uadpCodec) DecodeReassembled(header *message.NetworkMessage, payload []byte, opts *decodeOptions) (*message.NetworkMessage, error) {
	if opts == nil {
		return uadp.DecodeReassembled(header, payload, nil)
	}
	return uadp.DecodeReassembled(header, payload, &opts.DecodeOptions)
}

func (uadpCodec) EncodeMetaData(*jsonmsg.MetaDataMessage) ([]byte, error) {
	return nil, errNoJSONMetaData
}

func (uadpCodec) DecodeMetaData([]byte, *decodeOptions) (*jsonmsg.MetaDataMessage, error) {
	return nil, errNoJSONMetaData
}

type jsonCodec struct{}

func (jsonCodec) Encode(nm *message.NetworkMessage, _ *uadp.EncodeOptions) ([]byte, error) {
	return jsonmsg.Encode(nm, &jsonmsg.EncodeOptions{})
}

func (jsonCodec) Decode(b []byte, opts *decodeOptions) (*message.NetworkMessage, error) {
	nm, err := jsonmsg.Decode(b, opts.json())
	if err != nil {
		return nil, err
	}
	if opts != nil && opts.Accept != nil && !opts.Accept(nm) {
		return nil, uadp.ErrFiltered
	}
	return nm, nil
}

var errNoJSONChunks = errors.New("pubsub: the JSON mapping has no chunks")

func (jsonCodec) EncodeChunks(*message.NetworkMessage, *uadp.EncodeOptions, int) ([][]byte, error) {
	return nil, errNoJSONChunks
}

func (jsonCodec) DecodeReassembled(*message.NetworkMessage, []byte, *decodeOptions) (*message.NetworkMessage, error) {
	return nil, errNoJSONChunks
}

func (jsonCodec) EncodeMetaData(m *jsonmsg.MetaDataMessage) ([]byte, error) {
	return jsonmsg.EncodeMetaData(m, &jsonmsg.EncodeOptions{})
}

func (jsonCodec) DecodeMetaData(b []byte, opts *decodeOptions) (*jsonmsg.MetaDataMessage, error) {
	return jsonmsg.DecodeMetaData(b, opts.json())
}

// defaultCodecs returns the codecs of the message mappings.
func defaultCodecs(e encoding) codec {
	if e == encJSON {
		return jsonCodec{}
	}
	return uadpCodec{}
}

// messageEncoding returns the encoding of a received message: the one its
// MQTT 5.0 Content Type names (Part 14 §7.3.4.9), else what the payload
// looks like.
func messageEncoding(m *transport.Message) (encoding, error) {
	switch ct, _, _ := strings.Cut(m.ContentType, ";"); strings.ToLower(strings.TrimSpace(ct)) {
	case transport.ContentTypeJSON:
		return encJSON, nil
	case transport.ContentTypeUADP:
		return encUADP, nil
	}
	return payloadEncoding(m.Payload), nil
}

// contentType is the MIME type of the NetworkMessages of an encoding.
func (e encoding) contentType() string {
	if e == encJSON {
		return transport.ContentTypeJSON
	}
	return transport.ContentTypeUADP
}

// payloadEncoding guesses the mapping of a received payload: JSON messages
// are objects or arrays, a UADP NetworkMessage starts with its version and
// flags byte.
func payloadEncoding(b []byte) encoding {
	b = bytes.TrimLeft(b, " \t\r\n")
	if len(b) > 0 && (b[0] == '{' || b[0] == '[') {
		return encJSON
	}
	return encUADP
}

// isJSONMetaData reports whether a JSON payload is a "ua-metadata" message.
func isJSONMetaData(b []byte) bool {
	if len(b) > 512 {
		b = b[:512]
	}
	return bytes.Contains(b, []byte(`"ua-metadata"`))
}
