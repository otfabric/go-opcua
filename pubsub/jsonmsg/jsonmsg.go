// SPDX-License-Identifier: MIT

// Package jsonmsg implements the JSON message mapping of OPC UA PubSub
// (Part 14 §7.2.5): NetworkMessages and DataSetMessages ("ua-data"),
// DataSetMetaData messages ("ua-metadata"), status messages ("ua-status")
// and the messages of PubSub Actions ("ua-action-request",
// "ua-action-response", "ua-action-metadata", "ua-action-responder").
//
// # Wire shapes
//
// A NetworkMessage with the NetworkMessageHeader bit of its
// [ua.JSONNetworkMessageContentMask] is an object
//
//	{"MessageId":"..","MessageType":"ua-data","PublisherId":"..",
//	 "WriterGroupName":"..","DataSetClassId":"..","Messages":[..]}
//
// whose Messages member is an array of DataSetMessages, or a single
// DataSetMessage object with the SingleDataSetMessage bit. Without the
// NetworkMessageHeader bit the message is just the content of Messages. A
// DataSetMessage with the DataSetMessageHeader bit is an object
//
//	{"DataSetWriterId":1,"DataSetWriterName":"..","PublisherId":"..",
//	 "WriterGroupName":"..","SequenceNumber":1,"MetaDataVersion":{..},
//	 "MinorVersion":1,"Timestamp":"..","Status":{..},
//	 "MessageType":"ua-keyframe","Payload":{"Field":..}}
//
// with the members its [ua.JSONDataSetMessageContentMask] selects; without
// the bit it is the Payload object alone.
//
// The fields of the Payload are written as the [ua.DataSetFieldContentMask]
// of the DataSetMessage asks: as a Variant ({"UaType":7,"Value":27}) when no
// bit is set, as a DataValue ({"UaType":7,"Value":27,"Status":..,
// "SourceTimestamp":..}) when one of the StatusCode, timestamp or picoseconds
// bits is set, and as the bare value (27) with the RawData bit. The values
// use the Compact JSON encoding of OPC UA 1.05.04 (see [ua.EncodeJSON]),
// or the Verbose encoding when the FieldEncoding2 bit of the DataSetMessage
// content mask is set.
//
// # Actions
//
// A NetworkMessage with [message.NetworkMessage.Action] set is a message of
// PubSub Actions (Part 14 §7.2.5.6 in 1.05), always an object with header,
//
//	{"MessageId":"..","MessageType":"ua-action-request","PublisherId":"..",
//	 "Timestamp":"..","ResponseAddress":"..","CorrelationData":"..",
//	 "RequestorId":"..","TimeoutHint":1500,"Messages":[..]}
//
// whose PublisherId is the one of the Responder, and whose Messages are
// ActionRequest or ActionResponse DataSetMessages with header,
//
//	{"DataSetWriterId":1,"ActionTargetId":2,"DataSetWriterName":"..",
//	 "WriterGroupName":"..","MetaDataVersion":{..},"Timestamp":"..",
//	 "Status":{..},"MessageType":"ua-action-response","RequestId":7,
//	 "ActionState":2,"Payload":{"Out":..}}
//
// DataSetWriterId, ActionTargetId, RequestId, ActionState and Payload are
// always written, Status in responses; the other DataSetMessage members
// follow the JSONMask of the DataSetMessage. The fields of the Payload are
// Variants, or bare values with the RawData bit of the FieldContentMask
// (DataValue fields are not allowed, §7.2.5.6.2). The ActionState is the
// number of the Compact encoding; Decode also accepts the Verbose form
// ("Executing_1") and the bare name.
//
// # PublisherId
//
// Part 14 (1.05) encodes the PublisherId as a JSON string whatever its type,
// and so does open62541. Encode writes numeric PublisherIds as strings
// ("65535") unless [EncodeOptions.NumericPublisherID] is set. Decode accepts
// a string or a number; a string of decimal digits is decoded as a UInt64
// PublisherId (as open62541 does), any other string as a String PublisherId.
// Compare decoded PublisherIds with the configured one by their String form.
//
// # Interoperability with open62541 1.5
//
// open62541 always writes the network message header with MessageId (null
// when it has none), MessageType and PublisherId (as a string), always writes
// Messages as an array and always writes DataSetWriterId and MessageType
// "ua-keyframe" in its DataSetMessages, whatever the content masks say.
// It reads only key frames, and it rejects a SequenceNumber or a Status above
// 65535 because it keeps both in 16 bits. Decode accepts everything it writes
// (including the null MessageId and Status as a bare number).
package jsonmsg

import (
	"errors"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// Message types of the JSON mapping (Part 14 §7.2.5).
const (
	MessageTypeData        = "ua-data"
	MessageTypeMetaData    = "ua-metadata"
	MessageTypeStatus      = "ua-status"
	MessageTypeApplication = "ua-application"
	MessageTypeEndpoints   = "ua-endpoints"
	MessageTypeConnection  = "ua-connection"

	// The NetworkMessages of PubSub Actions (Part 14 §7.2.5.6 in 1.05);
	// their DataSetMessages carry the same MessageType.
	MessageTypeActionRequest  = "ua-action-request"
	MessageTypeActionResponse = "ua-action-response"
	// The discovery messages of PubSub Actions (§7.2.5.5.7, §7.2.5.5.8).
	MessageTypeActionMetaData  = "ua-action-metadata"
	MessageTypeActionResponder = "ua-action-responder"

	MessageTypeKeyFrame   = "ua-keyframe"
	MessageTypeDeltaFrame = "ua-deltaframe"
	MessageTypeEvent      = "ua-event"
	MessageTypeKeepAlive  = "ua-keepalive"
)

// Default limits of the decoder.
const (
	// DefaultMaxMessageSize is the largest message Decode accepts.
	DefaultMaxMessageSize = 16 << 20
	// DefaultMaxDataSetMessages is the largest number of DataSetMessages in
	// one NetworkMessage.
	DefaultMaxDataSetMessages = 4096
	// DefaultMaxFields is the largest number of fields of one
	// DataSetMessage.
	DefaultMaxFields = 65535
)

// ErrDecode is wrapped by all errors about malformed input.
var ErrDecode = errors.New("pubsub/jsonmsg: malformed message")

// UnsupportedMessageTypeError is returned for a well-formed message of a
// type this package does not decode (ua-application, ua-endpoints,
// ua-connection, ...), or of a type the called function does not
// handle (a "ua-metadata" message passed to Decode).
type UnsupportedMessageTypeError struct {
	MessageType string
}

func (e *UnsupportedMessageTypeError) Error() string {
	return fmt.Sprintf("pubsub/jsonmsg: unsupported message type %q", e.MessageType)
}

// EncodeOptions control the encoders.
type EncodeOptions struct {
	// NamespaceArray, if set, makes NodeIds in values use namespace URIs.
	NamespaceArray []string
	// MetaData, if set, supplies the field names of fields whose Name is
	// empty (by their Index).
	MetaData message.MetaDataLookup
	// NumericPublisherID writes numeric PublisherIds as JSON numbers, as
	// some 1.04 implementations expect, instead of the strings of Part 14
	// 1.05 that open62541 writes and expects.
	NumericPublisherID bool
}

// DecodeOptions control the decoders.
type DecodeOptions struct {
	// MetaData supplies the DataSetMetaData of a writer, needed to order
	// fields and to type RawData fields.
	MetaData       message.MetaDataLookup
	NamespaceArray []string

	// DataSetWriterID is used for DataSetMessages that carry no
	// DataSetWriterId (the subscriber knows the writer from the topic).
	DataSetWriterID uint16
	// PublisherID is used for messages that carry no PublisherId.
	PublisherID *message.PublisherID

	// Limits; zero selects the defaults.
	MaxMessageSize     int
	MaxDataSetMessages int
	MaxFields          int
}

func (o *DecodeOptions) maxMessageSize() int {
	if o != nil && o.MaxMessageSize > 0 {
		return o.MaxMessageSize
	}
	return DefaultMaxMessageSize
}

func (o *DecodeOptions) maxDataSetMessages() int {
	if o != nil && o.MaxDataSetMessages > 0 {
		return o.MaxDataSetMessages
	}
	return DefaultMaxDataSetMessages
}

func (o *DecodeOptions) maxFields() int {
	if o != nil && o.MaxFields > 0 {
		return o.MaxFields
	}
	return DefaultMaxFields
}

func (o *DecodeOptions) codecOptions() []ua.CodecOption {
	if o == nil || o.NamespaceArray == nil {
		return nil
	}
	return []ua.CodecOption{ua.WithNamespaceArray(o.NamespaceArray)}
}

// MetaDataMessage is a "ua-metadata" message (Part 14 §7.2.5.5.2).
type MetaDataMessage struct {
	// MessageID is generated by EncodeMetaData when empty.
	MessageID         string
	PublisherID       message.PublisherID
	DataSetWriterID   uint16
	WriterGroupName   string
	DataSetWriterName string
	// Timestamp is omitted when zero.
	Timestamp time.Time
	MetaData  *ua.DataSetMetaDataType
}

// ActionMetaDataMessage is a "ua-action-metadata" message (Part 14
// §7.2.5.5.7 in 1.05): the ActionMetaData of an Action writer of a
// Responder.
type ActionMetaDataMessage struct {
	// MessageID is generated by EncodeActionMetaData when empty.
	MessageID         string
	PublisherID       message.PublisherID
	DataSetWriterID   uint16
	DataSetWriterName string
	Timestamp         time.Time
	ActionTargets     []*ua.ActionTargetDataType
	Request           *ua.DataSetMetaDataType
	Response          *ua.DataSetMetaDataType
	// ActionMethods, if set, are the Methods of the targets, one per
	// target in the same order.
	ActionMethods []*ua.ActionMethodDataType
}

// ActionResponderMessage is a "ua-action-responder" message (Part 14
// §7.2.5.5.8 in 1.05): the PubSubConnection of a Responder with only its
// Action writer groups and writers.
type ActionResponderMessage struct {
	// MessageID is generated by EncodeActionResponder when empty.
	MessageID   string
	PublisherID message.PublisherID
	Timestamp   time.Time
	Connection  *ua.PubSubConnectionDataType
}

// StatusMessage is a "ua-status" message (Part 14 §7.2.5.5.6): the state of a
// publisher.
type StatusMessage struct {
	// MessageID is generated by EncodeStatus when empty.
	MessageID   string
	PublisherID message.PublisherID
	// Timestamp is omitted when zero.
	Timestamp time.Time
	IsCyclic  bool
	Status    ua.PubSubState
	// NextReportTime is omitted when zero.
	NextReportTime time.Time
}
