// SPDX-License-Identifier: MIT

package uadp

import (
	"math"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// Discovery messages (Part 14 §7.2.4.6 in 1.05) follow the headers in place
// of the payload; they have no PayloadHeader. A discovery announcement
// (NetworkMessage type 2) starts with the announcement header (Table 168)
//
//	AnnouncementType Byte    message.DiscoveryType
//	SequenceNumber   UInt16
//
// followed by the body of its type:
//
//	1 PublisherEndpoints  Endpoints EndpointDescription[], StatusCode
//	2 DataSetMetaData     DataSetWriterId UInt16, MetaData DataSetMetaDataType, StatusCode
//	3 DataSetWriter conf. DataSetWriterIds UInt16[], WriterGroupDataType, StatusCodes StatusCode[]
//	4 PubSubConnection    PubSubConnections PubSubConnectionDataType[]
//	5 ApplicationInfo.    ApplicationInformationType UInt16, then
//	                        1: ApplicationDescription, Capabilities String[]
//	                        2: IsCyclic Boolean, Status PubSubState,
//	                           NextReportTime UtcTime, Timestamp UtcTime
//
// The ActionResponder (6) and ActionMetaData (7) announcements of PubSub
// Actions are not supported. A discovery probe (NetworkMessage type 1) is
// (Tables 178 to 182)
//
//	ProbeType Byte  1 = publisher information, 2 = FindApplications (no fields)
//	InformationType Byte, then
//	  1 PublisherEndpoints   -
//	  2 DataSetMetaData      DataSetWriterIds UInt16[]
//	  3 DataSetWriter conf.  DataSetWriterIds UInt16[]
//	  4 WriterGroup conf.    WriterGroupId UInt16, IncludeDataSetWriters Boolean
//	  5 PubSubConnections    TransportProfileUris String[], IncludeWriterGroups Boolean,
//	                         IncludeDataSetWriters Boolean
//
// The OPC Foundation .NET stack deviates (message.DiscoveryLayoutDotNet).
// In 1.5 (Libraries/Opc.Ua.PubSub, UadpNetworkMessage EncodeDiscoveryRequest)
// and 2.x (src/Opc.Ua.PubSub, UadpDiscoveryCoder EncodeRequest) a probe is a
// single type byte, the InformationType without the ProbeType, followed by
// the DataSetWriterIds as a UInt32 count and UInt16 values, whatever the type
// (6 is a .NET probe with a filter, not supported here). Its announcements
// in 2.x (UadpDiscoveryWire.WriteEncodeable) precede every structure with its
// length as a UInt32, number PubSubConnection 5 and ApplicationInformation 4
// (also in its probes), send a single PubSubConnectionDataType followed by a
// StatusCode, and write the status times only if IsCyclic. The 1.5
// announcements follow the spec layout. Decode recognises both layouts (the
// one that consumes the message exactly, the spec layout if both do) and
// reports it in Layout; open62541 1.5.9 does not implement discovery messages.

func encodeDiscovery(b *ua.Buffer, d *message.Discovery) error {
	dotnet := d.Layout == message.DiscoveryLayoutDotNet
	t := byte(d.Type)
	if dotnet {
		t = dotnetAnnouncementType(d.Type)
	}
	b.WriteUint8(t)
	b.WriteUint16(d.SequenceNumber)
	switch d.Type {
	case message.DiscoveryPublisherEndpoints:
		if dotnet {
			b.WriteUint32(uint32(len(d.Endpoints)))
			for _, ep := range d.Endpoints {
				writePrefixed(b, nonNil(ep))
			}
		} else {
			b.WriteStruct(nonNilSlice(d.Endpoints))
		}
		b.WriteUint32(uint32(d.StatusCode))
	case message.DiscoveryDataSetMetaData:
		if d.MetaData == nil {
			return malformed("DataSetMetaData announcement without DataSetMetaData")
		}
		b.WriteUint16(d.DataSetWriterID)
		writeStruct(b, d.MetaData, dotnet)
		b.WriteUint32(uint32(d.StatusCode))
	case message.DiscoveryDataSetWriterConfig:
		if d.WriterGroup == nil {
			return malformed("DataSetWriter configuration announcement without WriterGroup")
		}
		if len(d.StatusCodes) != len(d.DataSetWriterIDs) {
			return malformed("%d StatusCodes for %d DataSetWriterIds", len(d.StatusCodes), len(d.DataSetWriterIDs))
		}
		writeUint16Array(b, d.DataSetWriterIDs)
		writeStruct(b, d.WriterGroup, dotnet)
		b.WriteUint32(uint32(len(d.StatusCodes)))
		for _, sc := range d.StatusCodes {
			b.WriteUint32(uint32(sc))
		}
	case message.DiscoveryPubSubConnection:
		if dotnet {
			if len(d.Connections) != 1 {
				return unsupported("the .NET layout carries one PubSubConnection, not %d", len(d.Connections))
			}
			writePrefixed(b, nonNil(d.Connections[0]))
			b.WriteUint32(uint32(d.StatusCode))
		} else {
			b.WriteStruct(nonNilSlice(d.Connections))
		}
	case message.DiscoveryApplicationInformation:
		return encodeApplicationInformation(b, d.Application, dotnet)
	default:
		return unsupported("discovery announcement type %d", d.Type)
	}
	return nil
}

func encodeApplicationInformation(b *ua.Buffer, a *message.ApplicationInformation, dotnet bool) error {
	if a == nil {
		return malformed("ApplicationInformation announcement without content")
	}
	b.WriteUint16(uint16(a.Type))
	switch a.Type {
	case message.ApplicationInformationDescription:
		writeStruct(b, nonNil(a.Description), dotnet)
		writeStringArray(b, a.Capabilities)
	case message.ApplicationInformationStatus:
		if dotnet {
			// .NET: IsCyclic as a Byte, the times only if cyclic.
			b.WriteBool(a.IsCyclic)
			b.WriteUint32(uint32(a.Status))
			if a.IsCyclic {
				b.WriteTime(a.NextReportTime)
				b.WriteTime(a.Timestamp)
			}
			return nil
		}
		b.WriteBool(a.IsCyclic)
		b.WriteUint32(uint32(a.Status))
		b.WriteTime(a.NextReportTime)
		b.WriteTime(a.Timestamp)
	default:
		return unsupported("ApplicationInformationType %d", a.Type)
	}
	return nil
}

func decodeDiscovery(data []byte) (*message.Discovery, error) {
	if len(data) < 3 {
		return nil, malformed("discovery announcement of %d bytes", len(data))
	}
	t, seq, body := data[0], uint16(data[1])|uint16(data[2])<<8, data[3:]
	// The spec layout first; the .NET one if the spec layout does not fit.
	var errSpec error
	if d, err := decodeAnnouncement(message.DiscoveryType(t), body, false); err == nil {
		d.SequenceNumber = seq
		return d, nil
	} else {
		errSpec = err
	}
	if dt, ok := fromDotnetAnnouncementType(t); ok {
		if d, err := decodeAnnouncement(dt, body, true); err == nil {
			d.SequenceNumber = seq
			d.Layout = message.DiscoveryLayoutDotNet
			return d, nil
		}
	}
	return nil, errSpec
}

// decodeAnnouncement decodes the body of an announcement in one layout. The
// body must be consumed exactly.
func decodeAnnouncement(t message.DiscoveryType, body []byte, dotnet bool) (*message.Discovery, error) {
	b := ua.NewBuffer(body)
	d := &message.Discovery{Type: t}
	switch t {
	case message.DiscoveryPublisherEndpoints:
		if dotnet {
			n := readCount(b, 4)
			for range n {
				ep := new(ua.EndpointDescription)
				readPrefixed(b, ep)
				d.Endpoints = append(d.Endpoints, ep)
			}
		} else {
			b.ReadStruct(&d.Endpoints)
		}
		d.StatusCode = ua.StatusCode(b.ReadUint32())
	case message.DiscoveryDataSetMetaData:
		d.DataSetWriterID = b.ReadUint16()
		d.MetaData = new(ua.DataSetMetaDataType)
		readStruct(b, d.MetaData, dotnet)
		d.StatusCode = ua.StatusCode(b.ReadUint32())
	case message.DiscoveryDataSetWriterConfig:
		d.DataSetWriterIDs = readUint16Array(b)
		d.WriterGroup = new(ua.WriterGroupDataType)
		readStruct(b, d.WriterGroup, dotnet)
		n := readCount(b, 4)
		if b.Error() == nil && n != len(d.DataSetWriterIDs) {
			return nil, malformed("%d StatusCodes for %d DataSetWriterIds", n, len(d.DataSetWriterIDs))
		}
		for range n {
			d.StatusCodes = append(d.StatusCodes, ua.StatusCode(b.ReadUint32()))
		}
	case message.DiscoveryPubSubConnection:
		if dotnet {
			c := new(ua.PubSubConnectionDataType)
			readPrefixed(b, c)
			d.Connections = []*ua.PubSubConnectionDataType{c}
			d.StatusCode = ua.StatusCode(b.ReadUint32())
		} else {
			b.ReadStruct(&d.Connections)
		}
	case message.DiscoveryApplicationInformation:
		a, err := decodeApplicationInformation(b, dotnet)
		if err != nil {
			return nil, err
		}
		d.Application = a
	default:
		return nil, unsupported("discovery announcement type %d", t)
	}
	if b.Error() != nil {
		return nil, malformed("%v announcement: %v", t, b.Error())
	}
	if b.Len() != 0 {
		return nil, malformed("%v announcement: %d bytes left", t, b.Len())
	}
	return d, nil
}

func decodeApplicationInformation(b *ua.Buffer, dotnet bool) (*message.ApplicationInformation, error) {
	a := &message.ApplicationInformation{Type: message.ApplicationInformationType(b.ReadUint16())}
	switch a.Type {
	case message.ApplicationInformationDescription:
		a.Description = new(ua.ApplicationDescription)
		readStruct(b, a.Description, dotnet)
		a.Capabilities = readStringArray(b)
	case message.ApplicationInformationStatus:
		a.IsCyclic = b.ReadBool()
		a.Status = ua.PubSubState(b.ReadUint32())
		if !dotnet || a.IsCyclic {
			a.NextReportTime = b.ReadTime()
			a.Timestamp = b.ReadTime()
		}
	default:
		if b.Error() != nil {
			return nil, malformed("truncated ApplicationInformation announcement")
		}
		return nil, unsupported("ApplicationInformationType %d", a.Type)
	}
	return a, nil
}

// The .NET 2.x numbering of the AnnouncementType (UadpDiscoveryType):
// ApplicationInformation 4 and PubSubConnection 5, the spec has them the
// other way round.
func dotnetAnnouncementType(t message.DiscoveryType) byte {
	switch t {
	case message.DiscoveryPubSubConnection:
		return 5
	case message.DiscoveryApplicationInformation:
		return 4
	default:
		return byte(t)
	}
}

func fromDotnetAnnouncementType(t byte) (message.DiscoveryType, bool) {
	switch t {
	case 1, 2, 3:
		return message.DiscoveryType(t), true
	case 4:
		return message.DiscoveryApplicationInformation, true
	case 5:
		return message.DiscoveryPubSubConnection, true
	}
	return 0, false
}

func encodeDiscoveryRequest(b *ua.Buffer, r *message.DiscoveryRequest) error {
	if r.Layout == message.DiscoveryLayoutDotNet {
		return encodeDotnetRequest(b, r)
	}
	switch r.ProbeType {
	case message.ProbeFindApplications:
		b.WriteUint8(uint8(r.ProbeType))
		return nil
	case message.ProbePublisherInformation:
	default:
		return unsupported("discovery probe type %d", r.ProbeType)
	}
	b.WriteUint8(uint8(r.ProbeType))
	b.WriteUint8(uint8(r.InformationType))
	switch r.InformationType {
	case message.InformationPublisherEndpoints:
	case message.InformationDataSetMetaData, message.InformationDataSetWriterConfig:
		writeUint16Array(b, r.DataSetWriterIDs)
	case message.InformationWriterGroupConfig:
		b.WriteUint16(r.WriterGroupID)
		b.WriteBool(r.IncludeDataSetWriters)
	case message.InformationPubSubConnections:
		writeStringArray(b, r.TransportProfileURIs)
		b.WriteBool(r.IncludeWriterGroups)
		b.WriteBool(r.IncludeDataSetWriters)
	default:
		return unsupported("discovery InformationType %d", r.InformationType)
	}
	return nil
}

// encodeDotnetRequest writes a probe as the .NET stack does: its
// UadpDiscoveryType and the DataSetWriterIds.
func encodeDotnetRequest(b *ua.Buffer, r *message.DiscoveryRequest) error {
	var t byte
	switch {
	case r.ProbeType == message.ProbeFindApplications:
		t = 4 // UadpDiscoveryType.ApplicationInformation
	case r.ProbeType != message.ProbePublisherInformation:
		return unsupported("discovery probe type %d", r.ProbeType)
	case r.InformationType == message.InformationPubSubConnections:
		if len(r.TransportProfileURIs) > 0 || r.IncludeWriterGroups || r.IncludeDataSetWriters {
			return unsupported("PubSubConnections probe settings in the .NET layout")
		}
		t = 5 // UadpDiscoveryType.PubSubConnection
	case r.InformationType >= message.InformationPublisherEndpoints && r.InformationType <= message.InformationDataSetWriterConfig:
		t = byte(r.InformationType)
	default:
		return unsupported("discovery InformationType %v in the .NET layout", r.InformationType)
	}
	b.WriteUint8(t)
	b.WriteUint32(uint32(len(r.DataSetWriterIDs)))
	for _, id := range r.DataSetWriterIDs {
		b.WriteUint16(id)
	}
	return nil
}

func decodeDiscoveryRequest(data []byte) (*message.DiscoveryRequest, error) {
	r, errSpec := decodeSpecRequest(data)
	if errSpec == nil {
		return r, nil
	}
	if r, err := decodeDotnetRequest(data); err == nil {
		return r, nil
	}
	return nil, errSpec
}

func decodeSpecRequest(data []byte) (*message.DiscoveryRequest, error) {
	b := ua.NewBuffer(data)
	r := &message.DiscoveryRequest{ProbeType: message.ProbeType(b.ReadUint8())}
	switch r.ProbeType {
	case message.ProbeFindApplications:
	case message.ProbePublisherInformation:
		r.InformationType = message.InformationType(b.ReadUint8())
		switch r.InformationType {
		case message.InformationPublisherEndpoints:
		case message.InformationDataSetMetaData, message.InformationDataSetWriterConfig:
			r.DataSetWriterIDs = readUint16Array(b)
		case message.InformationWriterGroupConfig:
			r.WriterGroupID = b.ReadUint16()
			r.IncludeDataSetWriters = b.ReadBool()
		case message.InformationPubSubConnections:
			r.TransportProfileURIs = readStringArray(b)
			r.IncludeWriterGroups = b.ReadBool()
			r.IncludeDataSetWriters = b.ReadBool()
		default:
			if b.Error() != nil {
				return nil, malformed("truncated discovery probe")
			}
			return nil, unsupported("discovery InformationType %d", r.InformationType)
		}
	default:
		if b.Error() != nil {
			return nil, malformed("empty discovery probe")
		}
		return nil, unsupported("discovery probe type %d", r.ProbeType)
	}
	if b.Error() != nil {
		return nil, malformed("discovery probe: %v", b.Error())
	}
	if b.Len() != 0 {
		return nil, malformed("discovery probe: %d bytes left", b.Len())
	}
	return r, nil
}

func decodeDotnetRequest(data []byte) (*message.DiscoveryRequest, error) {
	b := ua.NewBuffer(data)
	r := &message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, Layout: message.DiscoveryLayoutDotNet}
	switch t := b.ReadUint8(); t {
	case 1, 2, 3:
		r.InformationType = message.InformationType(t)
	case 4:
		r.ProbeType = message.ProbeFindApplications
	case 5:
		r.InformationType = message.InformationPubSubConnections
	default:
		return nil, unsupported(".NET discovery probe type %d", t)
	}
	r.DataSetWriterIDs = readUint16Array(b)
	if b.Error() != nil {
		return nil, malformed(".NET discovery probe: %v", b.Error())
	}
	if b.Len() != 0 {
		return nil, malformed(".NET discovery probe: %d bytes left", b.Len())
	}
	return r, nil
}

// readCount reads an Int32 array count (-1, a null array, is 0) and checks it
// against the bytes left, every element taking at least minSize bytes.
func readCount(b *ua.Buffer, minSize int) int {
	n := int32(b.ReadUint32())
	if b.Error() != nil || n == -1 {
		return 0
	}
	if n < 0 || int(n) > b.Len()/minSize {
		// Make the buffer fail: the rest cannot be decoded.
		b.ReadN(math.MaxInt32)
		return 0
	}
	return int(n)
}

func readUint16Array(b *ua.Buffer) []uint16 {
	n := readCount(b, 2)
	if n == 0 {
		return nil
	}
	out := make([]uint16, n)
	for i := range out {
		out[i] = b.ReadUint16()
	}
	return out
}

func writeUint16Array(b *ua.Buffer, ids []uint16) {
	b.WriteUint32(uint32(len(ids)))
	for _, id := range ids {
		b.WriteUint16(id)
	}
}

func readStringArray(b *ua.Buffer) []string {
	n := readCount(b, 4)
	var out []string
	for range n {
		out = append(out, b.ReadString())
	}
	return out
}

func writeStringArray(b *ua.Buffer, s []string) {
	b.WriteUint32(uint32(len(s)))
	for _, v := range s {
		b.WriteString(v)
	}
}

// writeStruct writes a structure, preceded by its length in the .NET layout.
func writeStruct(b *ua.Buffer, v any, dotnet bool) {
	if dotnet {
		writePrefixed(b, v)
		return
	}
	b.WriteStruct(v)
}

func readStruct(b *ua.Buffer, v any, dotnet bool) {
	if dotnet {
		readPrefixed(b, v)
		return
	}
	b.ReadStruct(v)
}

// writePrefixed writes a structure preceded by its length as a UInt32
// (.NET 2.x UadpDiscoveryWire.WriteEncodeable).
func writePrefixed(b *ua.Buffer, v any) {
	s := ua.NewBuffer(nil)
	s.WriteStruct(v)
	if s.Error() != nil {
		b.WriteStruct(v) // reports the error
		return
	}
	b.WriteUint32(uint32(s.Len()))
	b.Write(s.Bytes())
}

// readPrefixed reads a structure preceded by its length; the structure must
// fill it exactly.
func readPrefixed(b *ua.Buffer, v any) {
	n := b.ReadUint32()
	if b.Error() != nil {
		return
	}
	if int64(n) > int64(b.Len()) {
		b.ReadN(math.MaxInt32)
		return
	}
	s := ua.NewBuffer(b.ReadN(int(n)))
	s.ReadStruct(v)
	if s.Error() != nil || s.Len() != 0 {
		b.ReadN(math.MaxInt32)
	}
}

// nonNil returns a zero value for a nil structure, which the binary encoder
// cannot write.
func nonNil[T any](v *T) *T {
	if v == nil {
		return new(T)
	}
	return v
}

// nonNilSlice replaces nil elements of an array of structures.
func nonNilSlice[T any](s []*T) []*T {
	out := make([]*T, len(s))
	for i, v := range s {
		out[i] = nonNil(v)
	}
	return out
}
