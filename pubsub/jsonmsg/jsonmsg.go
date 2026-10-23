// SPDX-License-Identifier: MIT

// Package jsonmsg implements the JSON message mapping of OPC UA PubSub
// (Part 14 §7.2.5): NetworkMessages and DataSetMessages ("ua-data") and
// DataSetMetaData messages ("ua-metadata") in JSON.
package jsonmsg

import (
	"errors"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// EncodeOptions control Encode.
type EncodeOptions struct {
	// NamespaceArray, if set, makes NodeIds in values use namespace URIs.
	NamespaceArray []string
}

// DecodeOptions control Decode.
type DecodeOptions struct {
	// MetaData supplies the DataSetMetaData of a writer, needed to order
	// fields and to type RawData fields.
	MetaData       message.MetaDataLookup
	NamespaceArray []string
}

// Encode encodes a NetworkMessage of type NetworkMessageDataSet as a
// "ua-data" JSON message.
func Encode(nm *message.NetworkMessage, opts *EncodeOptions) ([]byte, error) {
	return nil, errors.New("pubsub/jsonmsg: not implemented")
}

// Decode decodes a "ua-data" JSON NetworkMessage (or a single
// DataSetMessage when the publisher omitted the network message header).
func Decode(b []byte, opts *DecodeOptions) (*message.NetworkMessage, error) {
	return nil, errors.New("pubsub/jsonmsg: not implemented")
}

// MetaDataMessage is a "ua-metadata" message.
type MetaDataMessage struct {
	MessageID       string
	PublisherID     message.PublisherID
	DataSetWriterID uint16
	WriterGroupName string
	MetaData        *ua.DataSetMetaDataType
	Timestamp       time.Time
}

// EncodeMetaData encodes a "ua-metadata" message.
func EncodeMetaData(m *MetaDataMessage, opts *EncodeOptions) ([]byte, error) {
	return nil, errors.New("pubsub/jsonmsg: not implemented")
}

// DecodeMetaData decodes a "ua-metadata" message.
func DecodeMetaData(b []byte, opts *DecodeOptions) (*MetaDataMessage, error) {
	return nil, errors.New("pubsub/jsonmsg: not implemented")
}
