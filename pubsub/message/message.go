// SPDX-License-Identifier: MIT

// Package message is the encoding-independent model of OPC UA PubSub messages
// (Part 14 §7.2): NetworkMessages that carry DataSetMessages, and the
// DataSetMetaData that describes them.
//
// The model is shared by the UADP message mapping (package
// [github.com/otfabric/go-opcua/pubsub/uadp]) and the JSON message mapping
// (package [github.com/otfabric/go-opcua/pubsub/jsonmsg]). Which optional
// header fields a message carries is expressed with the content masks of
// Part 14 (ua.UADPNetworkMessageContentMask, ua.JSONDataSetMessageContentMask,
// ...): an encoder writes the fields its mask selects, a decoder sets the mask
// to the fields it found. The masks of one mapping are ignored by the other.
package message

import (
	"fmt"
	"strconv"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// PublisherIDType is the data type of a PublisherId (Part 14 §7.2.2.2.2,
// ExtendedFlags1 bits 0-2).
type PublisherIDType uint8

const (
	PublisherIDByte   PublisherIDType = 0
	PublisherIDUInt16 PublisherIDType = 1
	PublisherIDUInt32 PublisherIDType = 2
	PublisherIDUInt64 PublisherIDType = 3
	PublisherIDString PublisherIDType = 4
)

func (t PublisherIDType) String() string {
	switch t {
	case PublisherIDByte:
		return "Byte"
	case PublisherIDUInt16:
		return "UInt16"
	case PublisherIDUInt32:
		return "UInt32"
	case PublisherIDUInt64:
		return "UInt64"
	case PublisherIDString:
		return "String"
	}
	return "PublisherIDType(" + strconv.Itoa(int(t)) + ")"
}

// PublisherID identifies the publisher of a NetworkMessage. The zero value is
// the Byte 0.
type PublisherID struct {
	Type PublisherIDType
	// Num is the value of a numeric PublisherId.
	Num uint64
	// Str is the value of a String PublisherId.
	Str string
}

// NewPublisherID returns a numeric PublisherId of the given type.
func NewPublisherID(t PublisherIDType, v uint64) PublisherID {
	return PublisherID{Type: t, Num: v}
}

// StringPublisherID returns a String PublisherId.
func StringPublisherID(s string) PublisherID {
	return PublisherID{Type: PublisherIDString, Str: s}
}

// PublisherIDFromVariant converts the PublisherId of a PubSubConnection
// (a Variant of Byte, UInt16, UInt32, UInt64 or String) to a PublisherID.
func PublisherIDFromVariant(v *ua.Variant) (PublisherID, error) {
	if v == nil || v.Value() == nil {
		return PublisherID{}, fmt.Errorf("pubsub: empty PublisherId")
	}
	switch x := v.Value().(type) {
	case byte:
		return NewPublisherID(PublisherIDByte, uint64(x)), nil
	case uint16:
		return NewPublisherID(PublisherIDUInt16, uint64(x)), nil
	case uint32:
		return NewPublisherID(PublisherIDUInt32, uint64(x)), nil
	case uint64:
		return NewPublisherID(PublisherIDUInt64, x), nil
	case string:
		return StringPublisherID(x), nil
	}
	return PublisherID{}, fmt.Errorf("pubsub: PublisherId of type %T is not allowed", v.Value())
}

// Variant returns the PublisherId as a Variant of its type.
func (p PublisherID) Variant() *ua.Variant {
	switch p.Type {
	case PublisherIDByte:
		return ua.MustVariant(byte(p.Num))
	case PublisherIDUInt16:
		return ua.MustVariant(uint16(p.Num))
	case PublisherIDUInt32:
		return ua.MustVariant(uint32(p.Num))
	case PublisherIDUInt64:
		return ua.MustVariant(p.Num)
	default:
		return ua.MustVariant(p.Str)
	}
}

// String returns the value of the PublisherId (a number or the string).
func (p PublisherID) String() string {
	if p.Type == PublisherIDString {
		return p.Str
	}
	return strconv.FormatUint(p.Num, 10)
}

// Equal reports whether two PublisherIds have the same type and value.
func (p PublisherID) Equal(o PublisherID) bool {
	if p.Type != o.Type {
		return false
	}
	if p.Type == PublisherIDString {
		return p.Str == o.Str
	}
	return p.Num == o.Num
}

// NetworkMessageType is the content of a UADP NetworkMessage
// (ExtendedFlags2 bits 2-4).
type NetworkMessageType uint8

const (
	// NetworkMessageDataSet carries DataSetMessages.
	NetworkMessageDataSet NetworkMessageType = 0
	// NetworkMessageDiscoveryRequest is a discovery probe.
	NetworkMessageDiscoveryRequest NetworkMessageType = 1
	// NetworkMessageDiscoveryResponse is a discovery announcement, for
	// example of DataSetMetaData.
	NetworkMessageDiscoveryResponse NetworkMessageType = 2
)

// GroupHeader is the UADP group header (Part 14 §7.2.2.2.3). Which of its
// fields are present follows the UADP network message content mask.
type GroupHeader struct {
	WriterGroupID        uint16
	GroupVersion         uint32 // VersionTime
	NetworkMessageNumber uint16
	SequenceNumber       uint16
}

// SecurityHeader is the UADP security header (Part 14 §7.2.2.2.6) of a
// received message. Encoders derive it from the security settings and ignore
// this field.
type SecurityHeader struct {
	Signed          bool
	Encrypted       bool
	ForceKeyReset   bool
	SecurityTokenID uint32
	MessageNonce    []byte
	FooterSize      uint16
}

// NetworkMessage is a PubSub NetworkMessage: the unit sent over a transport.
type NetworkMessage struct {
	Type NetworkMessageType

	// UADPMask selects (encode) or reports (decode) the optional UADP
	// header fields.
	UADPMask ua.UADPNetworkMessageContentMask
	// JSONMask selects or reports the optional JSON header fields.
	JSONMask ua.JSONNetworkMessageContentMask

	PublisherID    PublisherID
	DataSetClassID *ua.GUID
	GroupHeader    GroupHeader
	Timestamp      time.Time
	PicoSeconds    uint16
	PromotedFields []*ua.Variant

	// Security is the security header of a received UADP message, nil if
	// the message was not secured.
	Security *SecurityHeader

	// JSON mapping only.
	MessageID       string
	WriterGroupName string
	ReplyTo         string

	// Messages are the DataSetMessages of a NetworkMessage of type
	// NetworkMessageDataSet, in the order of the payload header.
	Messages []*DataSetMessage

	// Discovery holds the body of a discovery NetworkMessage.
	Discovery *Discovery
}

// FieldEncoding is the encoding of the fields of a UADP DataSetMessage
// (DataSetFlags1 bits 1-2).
type FieldEncoding uint8

const (
	FieldEncodingVariant   FieldEncoding = 0
	FieldEncodingRawData   FieldEncoding = 1
	FieldEncodingDataValue FieldEncoding = 2
)

func (e FieldEncoding) String() string {
	switch e {
	case FieldEncodingVariant:
		return "Variant"
	case FieldEncodingRawData:
		return "RawData"
	case FieldEncodingDataValue:
		return "DataValue"
	}
	return "FieldEncoding(" + strconv.Itoa(int(e)) + ")"
}

// DataSetMessageType is the kind of a DataSetMessage (UADP DataSetFlags2
// bits 0-3; JSON "MessageType").
type DataSetMessageType uint8

const (
	DataSetMessageKeyFrame   DataSetMessageType = 0
	DataSetMessageDeltaFrame DataSetMessageType = 1
	DataSetMessageEvent      DataSetMessageType = 2
	DataSetMessageKeepAlive  DataSetMessageType = 3
)

func (t DataSetMessageType) String() string {
	switch t {
	case DataSetMessageKeyFrame:
		return "KeyFrame"
	case DataSetMessageDeltaFrame:
		return "DeltaFrame"
	case DataSetMessageEvent:
		return "Event"
	case DataSetMessageKeepAlive:
		return "KeepAlive"
	}
	return "DataSetMessageType(" + strconv.Itoa(int(t)) + ")"
}

// Field is one field of a DataSetMessage.
type Field struct {
	// Index is the position of the field in the DataSet (its
	// DataSetMetaData). Key frames and events carry all fields in order;
	// delta frames carry the changed ones with their index.
	Index uint16
	// Name is the field name. The JSON mapping identifies fields by name;
	// for UADP it is filled from the DataSetMetaData when available.
	Name string
	// Value is the value with its status and timestamps. With the Variant
	// and RawData encodings only Value.Value is transported.
	Value *ua.DataValue
}

// DataSetMessage is one DataSetMessage of a NetworkMessage.
type DataSetMessage struct {
	// DataSetWriterID identifies the writer. For UADP it comes from the
	// payload header of the NetworkMessage.
	DataSetWriterID uint16

	Type DataSetMessageType
	// Valid is false for a DataSetMessage the writer marked invalid.
	Valid bool

	// UADPMask selects or reports the optional UADP DataSetMessage header
	// fields; FieldEncoding is the UADP field encoding.
	UADPMask      ua.UADPDataSetMessageContentMask
	FieldEncoding FieldEncoding
	// JSONMask selects or reports the optional JSON DataSetMessage fields;
	// FieldContentMask selects the JSON field encoding (Variant, DataValue
	// or RawData) and the DataValue fields that are sent.
	JSONMask         ua.JSONDataSetMessageContentMask
	FieldContentMask ua.DataSetFieldContentMask

	SequenceNumber  uint32 // UADP transports the low 16 bits
	Timestamp       time.Time
	PicoSeconds     uint16
	Status          ua.StatusCode // UADP transports the high 16 bits
	MetaDataVersion ua.ConfigurationVersionDataType

	// JSON mapping only.
	DataSetWriterName string
	PublisherID       *PublisherID
	WriterGroupName   string

	Fields []*Field
}

// DiscoveryType is the kind of a UADP discovery NetworkMessage.
type DiscoveryType uint8

const (
	DiscoveryPublisherEndpoints  DiscoveryType = 1
	DiscoveryDataSetMetaData     DiscoveryType = 2
	DiscoveryDataSetWriterConfig DiscoveryType = 3
)

// Discovery is the body of a discovery NetworkMessage (Part 14 §7.2.2.4).
type Discovery struct {
	Type DiscoveryType
	// SequenceNumber of the announcement.
	SequenceNumber uint16
	// DataSetWriterID and MetaData for a DataSetMetaData announcement.
	DataSetWriterID uint16
	MetaData        *ua.DataSetMetaDataType
	StatusCode      ua.StatusCode
}

// MetaDataLookup returns the DataSetMetaData a decoder needs for messages of a
// writer: RawData fields have no type information on the wire, and field names
// are not part of UADP. It returns nil if the writer is unknown.
type MetaDataLookup func(publisherID PublisherID, writerGroupID, dataSetWriterID uint16) *ua.DataSetMetaDataType
