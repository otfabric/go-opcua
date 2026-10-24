// SPDX-License-Identifier: MIT

package uadp

import (
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// UADPVersion is the only version of the UADP encoding.
const UADPVersion = 1

// UADPFlags (Part 14 Table 141 in 1.05).
const (
	flagsVersionMask   = 0x0f
	flagsPublisherID   = 0x10
	flagsGroupHeader   = 0x20
	flagsPayloadHeader = 0x40
	flagsExtended1     = 0x80
)

// ExtendedFlags1.
const (
	ext1PublisherIDTypeMask = 0x07
	ext1DataSetClassID      = 0x08
	ext1Security            = 0x10
	ext1Timestamp           = 0x20
	ext1PicoSeconds         = 0x40
	ext1Extended2           = 0x80
)

// ExtendedFlags2.
const (
	ext2Chunk          = 0x01
	ext2PromotedFields = 0x02
	ext2TypeMask       = 0x1c
	ext2TypeShift      = 2
	// ext2Action announces the ActionHeader of an ActionRequest or
	// ActionResponse NetworkMessage (Part 14 Table 154 in 1.05).
	ext2Action = 0x20
)

// ActionFlags of the ActionHeader (Part 14 Table 154 in 1.05).
const (
	actRequest         = 0x01
	actResponseAddress = 0x02
	actCorrelationData = 0x04
	actRequestorID     = 0x08
	actTimeoutHint     = 0x10
	actKnown           = 0x1f
)

// SecurityFlags of the security header.
const (
	secSigned        = 0x01
	secEncrypted     = 0x02
	secFooter        = 0x04
	secForceKeyReset = 0x08
	secKnown         = 0x0f
)

// DataSetFlags1 and DataSetFlags2.
const (
	dsf1Valid         = 0x01
	dsf1EncodingMask  = 0x06
	dsf1EncodingShift = 1
	dsf1Flags2        = 0x80

	dsf2TypeMask = 0x0f
)

// The optional fields of the group header and of the DataSetMessage header
// are tables: a content mask bit, the flag bit that announces the field on the
// wire, and its codec, in wire order.

type groupField struct {
	mask ua.UADPNetworkMessageContentMask
	flag byte
	enc  func(b *ua.Buffer, g *message.GroupHeader)
	dec  func(b *ua.Buffer, g *message.GroupHeader)
}

var groupFields = []groupField{
	{ua.UADPNetworkMessageContentMaskWriterGroupID, 0x01,
		func(b *ua.Buffer, g *message.GroupHeader) { b.WriteUint16(g.WriterGroupID) },
		func(b *ua.Buffer, g *message.GroupHeader) { g.WriterGroupID = b.ReadUint16() }},
	{ua.UADPNetworkMessageContentMaskGroupVersion, 0x02,
		func(b *ua.Buffer, g *message.GroupHeader) { b.WriteUint32(g.GroupVersion) },
		func(b *ua.Buffer, g *message.GroupHeader) { g.GroupVersion = b.ReadUint32() }},
	{ua.UADPNetworkMessageContentMaskNetworkMessageNumber, 0x04,
		func(b *ua.Buffer, g *message.GroupHeader) { b.WriteUint16(g.NetworkMessageNumber) },
		func(b *ua.Buffer, g *message.GroupHeader) { g.NetworkMessageNumber = b.ReadUint16() }},
	{ua.UADPNetworkMessageContentMaskSequenceNumber, 0x08,
		func(b *ua.Buffer, g *message.GroupHeader) { b.WriteUint16(g.SequenceNumber) },
		func(b *ua.Buffer, g *message.GroupHeader) { g.SequenceNumber = b.ReadUint16() }},
}

type dsmField struct {
	mask   ua.UADPDataSetMessageContentMask
	flags2 bool // the flag is in DataSetFlags2, not DataSetFlags1
	flag   byte
	enc    func(b *ua.Buffer, m *message.DataSetMessage)
	dec    func(b *ua.Buffer, m *message.DataSetMessage)
}

var dsmFields = []dsmField{
	{ua.UADPDataSetMessageContentMaskSequenceNumber, false, 0x08,
		func(b *ua.Buffer, m *message.DataSetMessage) { b.WriteUint16(uint16(m.SequenceNumber)) },
		func(b *ua.Buffer, m *message.DataSetMessage) { m.SequenceNumber = uint32(b.ReadUint16()) }},
	{ua.UADPDataSetMessageContentMaskTimestamp, true, 0x10,
		func(b *ua.Buffer, m *message.DataSetMessage) { b.WriteTime(m.Timestamp) },
		func(b *ua.Buffer, m *message.DataSetMessage) { m.Timestamp = b.ReadTime() }},
	{ua.UADPDataSetMessageContentMaskPicoSeconds, true, 0x20,
		func(b *ua.Buffer, m *message.DataSetMessage) { b.WriteUint16(m.PicoSeconds) },
		func(b *ua.Buffer, m *message.DataSetMessage) { m.PicoSeconds = b.ReadUint16() }},
	// The Status is the high 16 bits of the StatusCode (severity and
	// sub-code).
	{ua.UADPDataSetMessageContentMaskStatus, false, 0x10,
		func(b *ua.Buffer, m *message.DataSetMessage) { b.WriteUint16(uint16(uint32(m.Status) >> 16)) },
		func(b *ua.Buffer, m *message.DataSetMessage) { m.Status = ua.StatusCode(uint32(b.ReadUint16()) << 16) }},
	{ua.UADPDataSetMessageContentMaskMajorVersion, false, 0x20,
		func(b *ua.Buffer, m *message.DataSetMessage) { b.WriteUint32(m.MetaDataVersion.MajorVersion) },
		func(b *ua.Buffer, m *message.DataSetMessage) { m.MetaDataVersion.MajorVersion = b.ReadUint32() }},
	{ua.UADPDataSetMessageContentMaskMinorVersion, false, 0x40,
		func(b *ua.Buffer, m *message.DataSetMessage) { b.WriteUint32(m.MetaDataVersion.MinorVersion) },
		func(b *ua.Buffer, m *message.DataSetMessage) { m.MetaDataVersion.MinorVersion = b.ReadUint32() }},
}
