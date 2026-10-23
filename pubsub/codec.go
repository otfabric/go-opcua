// SPDX-License-Identifier: MIT

package pubsub

import (
	"bytes"
	"errors"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
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
	Decode(b []byte, opts *uadp.DecodeOptions) (*message.NetworkMessage, error)
	// EncodeMetaData and DecodeMetaData handle the "ua-metadata" messages
	// of the JSON mapping.
	EncodeMetaData(m *jsonmsg.MetaDataMessage) ([]byte, error)
	DecodeMetaData(b []byte, opts *uadp.DecodeOptions) (*jsonmsg.MetaDataMessage, error)
}

var errNoJSONMetaData = errors.New("pubsub: the UADP mapping announces DataSetMetaData with discovery messages")

type uadpCodec struct{}

func (uadpCodec) Encode(nm *message.NetworkMessage, opts *uadp.EncodeOptions) ([]byte, error) {
	return uadp.Encode(nm, opts)
}

func (uadpCodec) Decode(b []byte, opts *uadp.DecodeOptions) (*message.NetworkMessage, error) {
	return uadp.Decode(b, opts)
}

func (uadpCodec) EncodeMetaData(*jsonmsg.MetaDataMessage) ([]byte, error) {
	return nil, errNoJSONMetaData
}

func (uadpCodec) DecodeMetaData([]byte, *uadp.DecodeOptions) (*jsonmsg.MetaDataMessage, error) {
	return nil, errNoJSONMetaData
}

type jsonCodec struct{}

func (jsonCodec) Encode(nm *message.NetworkMessage, _ *uadp.EncodeOptions) ([]byte, error) {
	return jsonmsg.Encode(nm, &jsonmsg.EncodeOptions{})
}

func (jsonCodec) Decode(b []byte, opts *uadp.DecodeOptions) (*message.NetworkMessage, error) {
	var md message.MetaDataLookup
	if opts != nil {
		md = opts.MetaData
	}
	nm, err := jsonmsg.Decode(b, &jsonmsg.DecodeOptions{MetaData: md})
	if err != nil {
		return nil, err
	}
	if opts != nil && opts.Accept != nil && !opts.Accept(nm) {
		return nil, uadp.ErrFiltered
	}
	return nm, nil
}

func (jsonCodec) EncodeMetaData(m *jsonmsg.MetaDataMessage) ([]byte, error) {
	return jsonmsg.EncodeMetaData(m, &jsonmsg.EncodeOptions{})
}

func (jsonCodec) DecodeMetaData(b []byte, opts *uadp.DecodeOptions) (*jsonmsg.MetaDataMessage, error) {
	var md message.MetaDataLookup
	if opts != nil {
		md = opts.MetaData
	}
	return jsonmsg.DecodeMetaData(b, &jsonmsg.DecodeOptions{MetaData: md})
}

// defaultCodecs returns the codecs of the message mappings.
func defaultCodecs(e encoding) codec {
	if e == encJSON {
		return jsonCodec{}
	}
	return uadpCodec{}
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
