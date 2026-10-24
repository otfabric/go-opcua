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

	// Discovery holds the body of a discovery announcement (a
	// NetworkMessage of type NetworkMessageDiscoveryResponse).
	Discovery *Discovery
	// Request holds the body of a discovery probe (a NetworkMessage of
	// type NetworkMessageDiscoveryRequest).
	Request *DiscoveryRequest

	// Action is the action header of an ActionRequest or ActionResponse
	// NetworkMessage (Part 14 §7.2.4.4.2 Table 154 in 1.05; the header of
	// the JSON action NetworkMessage, §7.2.5.6.1), nil for any other
	// message. Its Messages are then of type DataSetMessageActionRequest
	// or DataSetMessageActionResponse, as Action.Type says.
	Action *ActionHeader

	// Chunk is set for one chunk of a chunked UADP NetworkMessage
	// (Part 14 §7.2.4.4.4 in 1.05). Its NetworkMessage carries the headers
	// of the chunk; the DataSetMessage or the discovery announcement it is
	// a piece of is decoded once all chunks are reassembled.
	Chunk *Chunk
}

// Chunk is the chunk payload of a chunked UADP NetworkMessage (Part 14
// Table 159 in 1.05): a piece of one DataSetMessage or of one discovery
// announcement. All chunks of a message except the last one have the same
// size.
type Chunk struct {
	// MessageSequenceNumber identifies the chunked message among the
	// messages of its writer: the sequence number of the DataSetMessage, or
	// of the discovery announcement.
	MessageSequenceNumber uint16
	// ChunkOffset is the position of Data in the complete message.
	ChunkOffset uint32
	// TotalSize is the size of the complete message in bytes.
	TotalSize uint32
	// Data is the piece of the message.
	Data []byte
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
	// DataSetMessageActionRequest and DataSetMessageActionResponse are the
	// DataSetMessages of PubSub Actions (Part 14 §7.2.4.5.9 and
	// §7.2.4.5.10 in 1.05; UADP DataSetFlags2 type 0101 and 0110).
	DataSetMessageActionRequest  DataSetMessageType = 5
	DataSetMessageActionResponse DataSetMessageType = 6
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
	case DataSetMessageActionRequest:
		return "ActionRequest"
	case DataSetMessageActionResponse:
		return "ActionResponse"
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

	// ActionTargetID, RequestID and ActionState of an ActionRequest or
	// ActionResponse DataSetMessage (Part 14 Tables 166 and 167 in 1.05).
	// The Status of a response is Status.
	ActionTargetID uint16
	RequestID      uint16
	ActionState    ua.ActionState

	Fields []*Field
}

// ActionMessageType tells an ActionRequest from an ActionResponse
// NetworkMessage (UADP ActionFlags bit 0; JSON "ua-action-request" and
// "ua-action-response").
type ActionMessageType uint8

const (
	ActionRequest  ActionMessageType = 1
	ActionResponse ActionMessageType = 2
)

func (t ActionMessageType) String() string {
	switch t {
	case ActionRequest:
		return "ActionRequest"
	case ActionResponse:
		return "ActionResponse"
	}
	return "ActionMessageType(" + strconv.Itoa(int(t)) + ")"
}

// ActionHeader is the action header of a PubSub Action NetworkMessage
// (Part 14 Table 154 in 1.05, the ActionHeader of UADP; Table 195, the
// header of the JSON action NetworkMessage). The PublisherId of the
// NetworkMessage is the one of the Responder, in requests and responses.
//
// The optional members are written when they are set: ResponseAddress when
// not empty (requests only), CorrelationData when not nil, RequestorID when
// not nil, TimeoutHint when positive (requests only). A decoder leaves the
// members the message does not carry at their zero value.
type ActionHeader struct {
	Type ActionMessageType
	// ResponseAddress is where the Responder sends the responses; empty
	// selects the default of the transport mapping.
	ResponseAddress string
	// CorrelationData is chosen by the Requestor and returned unchanged in
	// the responses.
	CorrelationData []byte
	// RequestorID is the PublisherId of the Requestor.
	RequestorID *PublisherID
	// TimeoutHint (Duration, milliseconds) is how long the Requestor waits
	// for the response; the Responder stops processing after it. It is
	// mandatory in requests.
	TimeoutHint float64
}

// DiscoveryType is the AnnouncementType of a UADP discovery announcement
// (Part 14 Table 168 in 1.05).
type DiscoveryType uint8

const (
	DiscoveryPublisherEndpoints  DiscoveryType = 1
	DiscoveryDataSetMetaData     DiscoveryType = 2
	DiscoveryDataSetWriterConfig DiscoveryType = 3
	DiscoveryPubSubConnection    DiscoveryType = 4
	// DiscoveryApplicationInformation announces the ApplicationDescription
	// or the status of the publisher, see [ApplicationInformation].
	DiscoveryApplicationInformation DiscoveryType = 5
)

func (t DiscoveryType) String() string {
	switch t {
	case DiscoveryPublisherEndpoints:
		return "PublisherEndpoints"
	case DiscoveryDataSetMetaData:
		return "DataSetMetaData"
	case DiscoveryDataSetWriterConfig:
		return "DataSetWriterConfiguration"
	case DiscoveryPubSubConnection:
		return "PubSubConnection"
	case DiscoveryApplicationInformation:
		return "ApplicationInformation"
	}
	return "DiscoveryType(" + strconv.Itoa(int(t)) + ")"
}

// DiscoveryLayout is the byte layout of a UADP discovery message. The
// encoder writes the layout it is given; the decoder recognises both and
// reports the one it found.
type DiscoveryLayout uint8

const (
	// DiscoveryLayoutSpec is the layout of Part 14 §7.2.4.6 in 1.05: a
	// probe starts with its ProbeType and the InformationType, the
	// structures of an announcement are encoded as they are.
	DiscoveryLayoutSpec DiscoveryLayout = 0
	// DiscoveryLayoutDotNet is the layout of the OPC Foundation .NET stack
	// 2.x (Opc.Ua.PubSub UadpDiscoveryCoder): a probe has a single type
	// byte (the InformationType, no ProbeType) followed by the
	// DataSetWriterIds, every structure of an announcement is preceded by
	// its length as a UInt32, the PubSubConnection announcement carries
	// one PubSubConnectionDataType and a StatusCode, and the types
	// PubSubConnection and ApplicationInformation are numbered 5 and 4.
	DiscoveryLayoutDotNet DiscoveryLayout = 1
)

// Discovery is the body of a discovery announcement (Part 14 §7.2.4.6 in
// 1.05). Which fields are used follows Type.
type Discovery struct {
	Type DiscoveryType
	// SequenceNumber of the announcement; it increases by one for every
	// announcement of a PublisherId.
	SequenceNumber uint16

	// DataSetWriterID and MetaData of a DataSetMetaData announcement.
	DataSetWriterID uint16
	MetaData        *ua.DataSetMetaDataType
	// StatusCode of a DataSetMetaData, PublisherEndpoints or (in the .NET
	// layout) PubSubConnection announcement.
	StatusCode ua.StatusCode

	// Endpoints of a PublisherEndpoints announcement.
	Endpoints []*ua.EndpointDescription

	// DataSetWriterIDs, WriterGroup and StatusCodes (one per writer id) of
	// a DataSetWriter configuration announcement. WriterGroup holds only
	// the DataSetWriters of DataSetWriterIDs.
	DataSetWriterIDs []uint16
	WriterGroup      *ua.WriterGroupDataType
	StatusCodes      []ua.StatusCode

	// Connections of a PubSubConnection announcement.
	Connections []*ua.PubSubConnectionDataType

	// Application of an ApplicationInformation announcement.
	Application *ApplicationInformation

	// Layout is the byte layout the announcement is (to be) encoded in.
	Layout DiscoveryLayout
}

// ApplicationInformationType selects the content of an ApplicationInformation
// announcement (Part 14 Table 169 in 1.05).
type ApplicationInformationType uint16

const (
	ApplicationInformationDescription ApplicationInformationType = 1
	ApplicationInformationStatus      ApplicationInformationType = 2
)

// ApplicationInformation is the body of an ApplicationInformation
// announcement: the ApplicationDescription with the capabilities of the
// publisher (Table 171), or its status (Table 173).
type ApplicationInformation struct {
	Type ApplicationInformationType

	Description  *ua.ApplicationDescription
	Capabilities []string

	IsCyclic       bool
	Status         ua.PubSubState
	NextReportTime time.Time
	Timestamp      time.Time
}

// ProbeType is the kind of a UADP discovery probe (Part 14 Table 178 in 1.05).
type ProbeType uint8

const (
	// ProbePublisherInformation asks the publishers for the information
	// of the InformationType.
	ProbePublisherInformation ProbeType = 1
	// ProbeFindApplications asks all applications for their
	// ApplicationInformation; it has no further fields.
	ProbeFindApplications ProbeType = 2
)

// InformationType is what a publisher information probe asks for (Part 14
// Table 179 in 1.05).
type InformationType uint8

const (
	InformationPublisherEndpoints  InformationType = 1
	InformationDataSetMetaData     InformationType = 2
	InformationDataSetWriterConfig InformationType = 3
	InformationWriterGroupConfig   InformationType = 4
	InformationPubSubConnections   InformationType = 5
)

func (t InformationType) String() string {
	switch t {
	case InformationPublisherEndpoints:
		return "PublisherEndpoints"
	case InformationDataSetMetaData:
		return "DataSetMetaData"
	case InformationDataSetWriterConfig:
		return "DataSetWriterConfiguration"
	case InformationWriterGroupConfig:
		return "WriterGroupConfiguration"
	case InformationPubSubConnections:
		return "PubSubConnections"
	}
	return "InformationType(" + strconv.Itoa(int(t)) + ")"
}

// DiscoveryRequest is the body of a discovery probe (Part 14 §7.2.4.6.12 in
// 1.05). Which fields are used follows InformationType.
type DiscoveryRequest struct {
	ProbeType       ProbeType
	InformationType InformationType
	// DataSetWriterIDs of a DataSetMetaData or DataSetWriter configuration
	// probe (Table 180). Empty asks for all writers.
	DataSetWriterIDs []uint16
	// WriterGroupID and IncludeDataSetWriters of a WriterGroup
	// configuration probe (Table 181).
	WriterGroupID         uint16
	IncludeDataSetWriters bool
	// TransportProfileURIs and IncludeWriterGroups (with
	// IncludeDataSetWriters) of a PubSubConnections probe (Table 182).
	TransportProfileURIs []string
	IncludeWriterGroups  bool

	// Layout is the byte layout the probe is (to be) encoded in.
	Layout DiscoveryLayout
}

// MetaDataLookup returns the DataSetMetaData a decoder needs for messages of a
// writer: RawData fields have no type information on the wire, and field names
// are not part of UADP. It returns nil if the writer is unknown.
type MetaDataLookup func(publisherID PublisherID, writerGroupID, dataSetWriterID uint16) *ua.DataSetMetaDataType
