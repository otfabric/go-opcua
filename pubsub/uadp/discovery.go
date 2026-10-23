// SPDX-License-Identifier: MIT

package uadp

import (
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// A discovery response (Part 14 §7.2.4.6 in 1.05) follows the headers in
// place of the payload:
//
//	ResponseType    Byte                 2 = DataSetMetaData
//	SequenceNumber  UInt16
//	DataSetWriterId UInt16               the DataSetMetaData announcement
//	MetaData        DataSetMetaDataType
//	StatusCode      StatusCode
//
// It has no PayloadHeader. This is the layout of the OPC Foundation .NET stack
// (UadpNetworkMessage, EncodeDiscoveryResponse); open62541 1.5.9 does not
// implement discovery messages.

func encodeDiscovery(b *ua.Buffer, d *message.Discovery) error {
	if d.Type != message.DiscoveryDataSetMetaData {
		return unsupported("discovery response type %d", d.Type)
	}
	if d.MetaData == nil {
		return malformed("DataSetMetaData announcement without DataSetMetaData")
	}
	b.WriteUint8(uint8(d.Type))
	b.WriteUint16(d.SequenceNumber)
	b.WriteUint16(d.DataSetWriterID)
	b.WriteStruct(d.MetaData)
	b.WriteUint32(uint32(d.StatusCode))
	return nil
}

func decodeDiscovery(data []byte) (*message.Discovery, error) {
	b := ua.NewBuffer(data)
	d := &message.Discovery{Type: message.DiscoveryType(b.ReadUint8())}
	if b.Error() != nil {
		return nil, malformed("empty discovery response")
	}
	if d.Type != message.DiscoveryDataSetMetaData {
		return nil, unsupported("discovery response type %d", d.Type)
	}
	d.SequenceNumber = b.ReadUint16()
	d.DataSetWriterID = b.ReadUint16()
	d.MetaData = new(ua.DataSetMetaDataType)
	b.ReadStruct(d.MetaData)
	d.StatusCode = ua.StatusCode(b.ReadUint32())
	if b.Error() != nil {
		return nil, malformed("DataSetMetaData announcement: %v", b.Error())
	}
	return d, nil
}
