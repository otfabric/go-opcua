// SPDX-License-Identifier: MIT

package uadp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

func discoveryNM(d *message.Discovery) *message.NetworkMessage {
	return &message.NetworkMessage{
		Type:        message.NetworkMessageDiscoveryResponse,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDByte, 1),
		Discovery:   d,
	}
}

func probeNM(r *message.DiscoveryRequest) *message.NetworkMessage {
	return &message.NetworkMessage{
		Type:        message.NetworkMessageDiscoveryRequest,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: message.NewPublisherID(message.PublisherIDByte, 1),
		Request:     r,
	}
}

func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, err := ua.Encode(v)
	require.NoError(t, err)
	return b
}

func prefixed(t *testing.T, v any) []byte {
	b := encoded(t, v)
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(b))), b...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestDiscoveryGoldenDotNet checks the .NET 2.x layout of a DataSetMetaData
// announcement and of a probe (UadpDiscoveryCoder: WriteCommonHeader,
// WriteMetaData with the UInt32 length of WriteEncodeable, EncodeRequest),
// and the spec layout of the same probe.
func TestDiscoveryGoldenDotNet(t *testing.T) {
	md := &ua.DataSetMetaDataType{Name: "DS", ConfigurationVersion: &ua.ConfigurationVersionDataType{MajorVersion: 1}}
	d := &message.Discovery{Type: message.DiscoveryDataSetMetaData, SequenceNumber: 5, DataSetWriterID: 10, MetaData: md, Layout: message.DiscoveryLayoutDotNet}
	want := cat(h(t, "91 80 08 01 02 0500 0a00"), prefixed(t, md), h(t, "00000000"))
	got, err := Encode(discoveryNM(d), nil)
	require.NoError(t, err)
	require.Equal(t, want, got)
	dec, err := Decode(got, nil)
	require.NoError(t, err)
	require.Equal(t, message.DiscoveryLayoutDotNet, dec.Discovery.Layout)
	require.Equal(t, "DS", dec.Discovery.MetaData.Name)
	require.Equal(t, uint16(10), dec.Discovery.DataSetWriterID)

	r := &message.DiscoveryRequest{ProbeType: message.ProbePublisherInformation, InformationType: message.InformationDataSetMetaData, DataSetWriterIDs: []uint16{10, 11}}
	got, err = Encode(probeNM(r), nil)
	require.NoError(t, err)
	require.Equal(t, h(t, "91 80 04 01 01 02 02000000 0a00 0b00"), got)
	dr, err := Decode(got, nil)
	require.NoError(t, err)
	require.Equal(t, r, dr.Request)
	require.Equal(t, message.NetworkMessageDiscoveryRequest, dr.Type)

	r.Layout = message.DiscoveryLayoutDotNet
	got, err = Encode(probeNM(r), nil)
	require.NoError(t, err)
	require.Equal(t, h(t, "91 80 04 01 02 02000000 0a00 0b00"), got)
	dr, err = Decode(got, nil)
	require.NoError(t, err)
	require.Equal(t, r, dr.Request)
}

func TestDiscoveryAnnouncements(t *testing.T) {
	ep := &ua.EndpointDescription{EndpointURL: "opc.tcp://host:4840", SecurityMode: ua.MessageSecurityModeNone, SecurityPolicyURI: "http://opcfoundation.org/UA/SecurityPolicy#None"}
	wg := &ua.WriterGroupDataType{Name: "wg", WriterGroupID: 7, PublishingInterval: 100, DataSetWriters: []*ua.DataSetWriterDataType{{Name: "w", DataSetWriterID: 3}}}
	conn := &ua.PubSubConnectionDataType{Name: "c", TransportProfileURI: "uri", WriterGroups: []*ua.WriterGroupDataType{wg}}
	app := &ua.ApplicationDescription{ApplicationURI: "urn:app", ApplicationName: &ua.LocalizedText{Text: "app", EncodingMask: ua.LocalizedTextText}}
	tm := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		name string
		d    *message.Discovery
		// body of the spec layout after the announcement header
		spec []byte
	}{
		{"endpoints", &message.Discovery{Type: message.DiscoveryPublisherEndpoints, Endpoints: []*ua.EndpointDescription{ep}, StatusCode: ua.StatusBadNotSupported},
			cat(encoded(t, []*ua.EndpointDescription{ep}), h(t, "00003d80"))},
		{"no endpoints", &message.Discovery{Type: message.DiscoveryPublisherEndpoints, Endpoints: []*ua.EndpointDescription{}}, h(t, "00000000 00000000")},
		{"metadata", &message.Discovery{Type: message.DiscoveryDataSetMetaData, DataSetWriterID: 3, MetaData: &ua.DataSetMetaDataType{Name: "x"}},
			cat(h(t, "0300"), encoded(t, &ua.DataSetMetaDataType{Name: "x"}), h(t, "00000000"))},
		{"writer config", &message.Discovery{Type: message.DiscoveryDataSetWriterConfig, DataSetWriterIDs: []uint16{3}, WriterGroup: wg, StatusCodes: []ua.StatusCode{ua.StatusOK}},
			cat(h(t, "01000000 0300"), encoded(t, wg), h(t, "01000000 00000000"))},
		{"connection", &message.Discovery{Type: message.DiscoveryPubSubConnection, Connections: []*ua.PubSubConnectionDataType{conn}},
			encoded(t, []*ua.PubSubConnectionDataType{conn})},
		{"application", &message.Discovery{Type: message.DiscoveryApplicationInformation, Application: &message.ApplicationInformation{
			Type: message.ApplicationInformationDescription, Description: app, Capabilities: []string{"cap"}}},
			cat(h(t, "0100"), encoded(t, app), h(t, "01000000 03000000 636170"))},
		{"status", &message.Discovery{Type: message.DiscoveryApplicationInformation, Application: &message.ApplicationInformation{
			Type: message.ApplicationInformationStatus, IsCyclic: true, Status: ua.PubSubStateOperational, NextReportTime: tm, Timestamp: tm}},
			cat(h(t, "0200 01 02000000"), encoded(t, tm), encoded(t, tm))},
		{"status not cyclic", &message.Discovery{Type: message.DiscoveryApplicationInformation, Application: &message.ApplicationInformation{
			Type: message.ApplicationInformationStatus, Status: ua.PubSubStateError}},
			h(t, "0200 00 03000000 0000000000000000 0000000000000000")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.d.SequenceNumber = 0x1234
			for _, layout := range []message.DiscoveryLayout{message.DiscoveryLayoutSpec, message.DiscoveryLayoutDotNet} {
				d := *tc.d
				d.Layout = layout
				b, err := Encode(discoveryNM(&d), nil)
				if layout == message.DiscoveryLayoutDotNet && d.Type == message.DiscoveryPubSubConnection {
					// The .NET layout carries one connection and a
					// StatusCode.
					require.NoError(t, err)
					require.Equal(t, cat(h(t, "91 80 08 01 05 3412"), prefixed(t, conn), h(t, "00000000")), b)
				}
				require.NoError(t, err)
				if layout == message.DiscoveryLayoutSpec {
					require.Equal(t, cat(h(t, "91 80 08 01"), []byte{byte(d.Type), 0x34, 0x12}, tc.spec), b)
				}
				dec, err := Decode(b, nil)
				require.NoError(t, err)
				got := dec.Discovery
				if tc.name == "no endpoints" {
					// The same bytes in both layouts.
					require.Equal(t, message.DiscoveryLayoutSpec, got.Layout)
				} else {
					require.Equal(t, layout, got.Layout, "layout detected")
				}
				require.Equal(t, d.Type, got.Type)
				require.Equal(t, d.SequenceNumber, got.SequenceNumber)
				require.Equal(t, d.StatusCode, got.StatusCode)
				require.Equal(t, d.DataSetWriterID, got.DataSetWriterID)
				require.Len(t, got.Endpoints, len(d.Endpoints))
				require.Equal(t, d.DataSetWriterIDs, got.DataSetWriterIDs)
				require.Equal(t, d.StatusCodes, got.StatusCodes)
				if d.MetaData != nil {
					require.Equal(t, d.MetaData.Name, got.MetaData.Name)
				}
				if d.WriterGroup != nil {
					require.Equal(t, "w", got.WriterGroup.DataSetWriters[0].Name)
				}
				if d.Connections != nil {
					require.Equal(t, "wg", got.Connections[0].WriterGroups[0].Name)
				}
				if a := d.Application; a != nil {
					require.Equal(t, a.Type, got.Application.Type)
					require.Equal(t, a.Capabilities, got.Application.Capabilities)
					require.Equal(t, a.Status, got.Application.Status)
					require.Equal(t, a.IsCyclic, got.Application.IsCyclic)
					require.True(t, a.NextReportTime.Equal(got.Application.NextReportTime))
				}
			}
		})
	}
}

func TestDiscoveryDotNetNumbering(t *testing.T) {
	// The .NET layout numbers ApplicationInformation 4.
	d := &message.Discovery{Type: message.DiscoveryApplicationInformation, Layout: message.DiscoveryLayoutDotNet,
		Application: &message.ApplicationInformation{Type: message.ApplicationInformationStatus, Status: ua.PubSubStateOperational}}
	b, err := Encode(discoveryNM(d), nil)
	require.NoError(t, err)
	require.Equal(t, h(t, "91 80 08 01 04 0000 0200 00 02000000"), b)
	dec, err := Decode(b, nil)
	require.NoError(t, err)
	require.Equal(t, message.DiscoveryApplicationInformation, dec.Discovery.Type)
	require.Equal(t, message.DiscoveryLayoutDotNet, dec.Discovery.Layout)
}

func TestDiscoveryProbes(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *message.DiscoveryRequest
		spec string
		net  string // "" if the .NET layout cannot express it
	}{
		{"endpoints", &message.DiscoveryRequest{ProbeType: 1, InformationType: message.InformationPublisherEndpoints}, "01 01", "01 00000000"},
		{"metadata", &message.DiscoveryRequest{ProbeType: 1, InformationType: message.InformationDataSetMetaData, DataSetWriterIDs: []uint16{1}}, "01 02 01000000 0100", "02 01000000 0100"},
		{"all metadata", &message.DiscoveryRequest{ProbeType: 1, InformationType: message.InformationDataSetMetaData}, "01 02 00000000", "02 00000000"},
		{"writer config", &message.DiscoveryRequest{ProbeType: 1, InformationType: message.InformationDataSetWriterConfig, DataSetWriterIDs: []uint16{1, 2}}, "01 03 02000000 0100 0200", "03 02000000 0100 0200"},
		{"writer group", &message.DiscoveryRequest{ProbeType: 1, InformationType: message.InformationWriterGroupConfig, WriterGroupID: 9, IncludeDataSetWriters: true}, "01 04 0900 01", ""},
		{"connections", &message.DiscoveryRequest{ProbeType: 1, InformationType: message.InformationPubSubConnections, TransportProfileURIs: []string{"u"}, IncludeWriterGroups: true}, "01 05 01000000 01000000 75 01 00", ""},
		{"all connections", &message.DiscoveryRequest{ProbeType: 1, InformationType: message.InformationPubSubConnections}, "01 05 00000000 00 00", "05 00000000"},
		{"find applications", &message.DiscoveryRequest{ProbeType: message.ProbeFindApplications}, "02", "04 00000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Encode(probeNM(tc.r), nil)
			require.NoError(t, err)
			require.Equal(t, cat(h(t, "91 80 04 01"), h(t, tc.spec)), b)
			dec, err := Decode(b, nil)
			require.NoError(t, err)
			require.Equal(t, tc.r, dec.Request)

			r := *tc.r
			r.Layout = message.DiscoveryLayoutDotNet
			b, err = Encode(probeNM(&r), nil)
			if tc.net == "" {
				require.ErrorIs(t, err, ErrUnsupported)
				return
			}
			require.NoError(t, err)
			require.Equal(t, cat(h(t, "91 80 04 01"), h(t, tc.net)), b)
			dec, err = Decode(b, nil)
			require.NoError(t, err)
			want := r
			want.TransportProfileURIs, want.IncludeWriterGroups = nil, false
			if want.ProbeType == message.ProbeFindApplications {
				want.InformationType = 0
			}
			require.Equal(t, &want, dec.Request)
		})
	}
	_, err := Encode(probeNM(&message.DiscoveryRequest{ProbeType: 3}), nil)
	require.ErrorIs(t, err, ErrUnsupported)
	_, err = Encode(probeNM(&message.DiscoveryRequest{ProbeType: 3, Layout: message.DiscoveryLayoutDotNet}), nil)
	require.ErrorIs(t, err, ErrUnsupported)
	_, err = Encode(probeNM(&message.DiscoveryRequest{ProbeType: 1, InformationType: 9}), nil)
	require.ErrorIs(t, err, ErrUnsupported)
}

// TestDiscoveryActionAnnouncements: the ActionResponder (Table 176) and
// ActionMetaData (Table 177) announcements, in the spec layout only.
func TestDiscoveryActionAnnouncements(t *testing.T) {
	wg := &ua.WriterGroupDataType{Name: "Actions", WriterGroupID: 10, DataSetWriters: []*ua.DataSetWriterDataType{{Name: "Calc", DataSetWriterID: 100}}}
	conn := &ua.PubSubConnectionDataType{Name: "Responder", TransportProfileURI: "uri", WriterGroups: []*ua.WriterGroupDataType{wg}}
	targets := []*ua.ActionTargetDataType{{ActionTargetID: 1, Name: "Add", Description: &ua.LocalizedText{}}, {ActionTargetID: 2, Name: "Sub", Description: &ua.LocalizedText{}}}
	version := &ua.ConfigurationVersionDataType{MajorVersion: 5, MinorVersion: 6}
	req := &ua.DataSetMetaDataType{Name: "Calc", ConfigurationVersion: version, Fields: []*ua.FieldMetaData{{Name: "A"}, {Name: "B"}}}
	resp := &ua.DataSetMetaDataType{Name: "Calc", ConfigurationVersion: version, Fields: []*ua.FieldMetaData{{Name: "Sum"}}}
	methods := []*ua.ActionMethodDataType{
		{ObjectID: ua.NewStringNodeID(1, "Calc"), MethodID: ua.NewStringNodeID(1, "Add")},
		{ObjectID: ua.NewStringNodeID(1, "Calc"), MethodID: ua.NewStringNodeID(1, "Sub")},
	}
	for _, tc := range []struct {
		name string
		d    *message.Discovery
		body []byte
	}{
		{"responder", &message.Discovery{Type: message.DiscoveryActionResponder, Connections: []*ua.PubSubConnectionDataType{conn}},
			encoded(t, []*ua.PubSubConnectionDataType{conn})},
		{"metadata", &message.Discovery{Type: message.DiscoveryActionMetaData, DataSetWriterID: 100, ActionTargets: targets, RequestMetaData: req, MetaData: resp},
			cat(h(t, "6400"), encoded(t, targets), encoded(t, req), encoded(t, resp), h(t, "00000000"))},
		{"metadata with methods", &message.Discovery{Type: message.DiscoveryActionMetaData, DataSetWriterID: 100, ActionTargets: targets, RequestMetaData: req, MetaData: resp, ActionMethods: methods},
			cat(h(t, "6400"), encoded(t, targets), encoded(t, req), encoded(t, resp), encoded(t, methods))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.d.SequenceNumber = 0x1234
			b, err := Encode(discoveryNM(tc.d), nil)
			require.NoError(t, err)
			require.Equal(t, cat(h(t, "91 80 08 01"), []byte{byte(tc.d.Type), 0x34, 0x12}, tc.body), b)
			dec, err := Decode(b, nil)
			require.NoError(t, err)
			got := dec.Discovery
			require.Equal(t, message.DiscoveryLayoutSpec, got.Layout)
			require.Equal(t, tc.d.Type, got.Type)
			require.Equal(t, uint16(0x1234), got.SequenceNumber)
			if tc.d.Type == message.DiscoveryActionResponder {
				require.Equal(t, "Calc", got.Connections[0].WriterGroups[0].DataSetWriters[0].Name)
				return
			}
			require.Equal(t, uint16(100), got.DataSetWriterID)
			require.Equal(t, targets, got.ActionTargets)
			require.Equal(t, req.Fields[1].Name, got.RequestMetaData.Fields[1].Name)
			require.Equal(t, version, got.MetaData.ConfigurationVersion)
			require.Equal(t, "Sum", got.MetaData.Fields[0].Name)
			if tc.d.ActionMethods != nil {
				require.Equal(t, methods, got.ActionMethods)
			} else {
				require.Empty(t, got.ActionMethods)
			}
		})
	}

	for _, d := range []*message.Discovery{
		{Type: message.DiscoveryActionMetaData, MetaData: resp},
		{Type: message.DiscoveryActionMetaData, RequestMetaData: req},
		{Type: message.DiscoveryActionMetaData, RequestMetaData: req, MetaData: resp, ActionTargets: targets, ActionMethods: methods[:1]},
	} {
		_, err := Encode(discoveryNM(d), nil)
		require.ErrorIs(t, err, ErrMalformed, "%+v", d)
	}
	for _, typ := range []message.DiscoveryType{message.DiscoveryActionResponder, message.DiscoveryActionMetaData} {
		_, err := Encode(discoveryNM(&message.Discovery{Type: typ, RequestMetaData: req, MetaData: resp, Layout: message.DiscoveryLayoutDotNet}), nil)
		require.ErrorIs(t, err, ErrUnsupported, "%v", typ)
	}
	// ActionMethods that do not match the targets.
	b := cat(h(t, "91 80 08 01 07 0000 6400"), encoded(t, targets), encoded(t, req), encoded(t, resp), encoded(t, methods[:1]))
	_, err := Decode(b, nil)
	require.ErrorIs(t, err, ErrMalformed)
}

func TestDiscoveryMalformed(t *testing.T) {
	for _, tc := range []struct {
		name, hex string
		err       error
	}{
		{"short announcement", "91 80 08 01 02 00", ErrMalformed},
		{"truncated endpoints", "91 80 08 01 01 0000 01000000", ErrMalformed},
		{"endpoint count beyond the message", "91 80 08 01 01 0000 ffffff7f 00000000", ErrMalformed},
		{"negative count", "91 80 08 01 03 0000 feffffff", ErrMalformed},
		{"status count mismatch", "91 80 08 01 03 0000 00000000" + hexOf(t, &ua.WriterGroupDataType{}) + "01000000 00000000", ErrMalformed},
		{"trailing bytes", "91 80 08 01 01 0000 00000000 00000000 00", ErrMalformed},
		{"application type", "91 80 08 01 05 0000 0300", ErrUnsupported},
		{"truncated application type", "91 80 08 01 05 0000 03", ErrMalformed},
		{"unknown announcement", "91 80 08 01 08 0000", ErrUnsupported},
		{"truncated action metadata", "91 80 08 01 07 0000 0100", ErrMalformed},
		{".NET action metadata", "91 80 08 01 07 0000", ErrMalformed},
		{"prefix beyond the message", "91 80 08 01 02 0000 0100 ffffff00", ErrMalformed},
		{"empty probe", "91 80 04 01", ErrMalformed},
		{"unknown probe", "91 80 04 01 03", ErrUnsupported},
		{"truncated probe", "91 80 04 01 01", ErrMalformed},
		{"unknown information", "91 80 04 01 01 09", ErrUnsupported},
		{"probe trailing bytes", "91 80 04 01 01 01 00", ErrMalformed},
		{".NET probe with filter", "91 80 04 01 06 00000000", ErrUnsupported},
		{"truncated .NET probe", "91 80 04 01 06 0100", ErrUnsupported},
		{"truncated ids", "91 80 04 01 01 02 02000000 0100", ErrMalformed},
	} {
		_, err := Decode(h(t, tc.hex), nil)
		require.ErrorIs(t, err, tc.err, tc.name)
	}
	// A prefixed structure that does not fill its length.
	md := encoded(t, &ua.DataSetMetaDataType{})
	b := cat(h(t, "91 80 08 01 02 0000 0100"), binary.LittleEndian.AppendUint32(nil, uint32(len(md)+1)), md, []byte{0}, h(t, "00000000"))
	_, err := Decode(b, nil)
	require.ErrorIs(t, err, ErrMalformed)

	for _, d := range []*message.Discovery{
		{Type: message.DiscoveryDataSetWriterConfig},
		{Type: message.DiscoveryDataSetWriterConfig, WriterGroup: &ua.WriterGroupDataType{}, DataSetWriterIDs: []uint16{1}},
		{Type: message.DiscoveryApplicationInformation},
	} {
		_, err := Encode(discoveryNM(d), nil)
		require.ErrorIs(t, err, ErrMalformed, "%+v", d)
	}
	for _, d := range []*message.Discovery{
		{Type: message.DiscoveryApplicationInformation, Application: &message.ApplicationInformation{Type: 7}},
		{Type: message.DiscoveryPubSubConnection, Layout: message.DiscoveryLayoutDotNet},
	} {
		_, err := Encode(discoveryNM(d), nil)
		require.ErrorIs(t, err, ErrUnsupported, "%+v", d)
	}
	// Nil structures are written as empty ones.
	b, err = Encode(discoveryNM(&message.Discovery{Type: message.DiscoveryPublisherEndpoints, Endpoints: []*ua.EndpointDescription{nil}}), nil)
	require.NoError(t, err)
	dec, err := Decode(b, nil)
	require.NoError(t, err)
	require.Len(t, dec.Discovery.Endpoints, 1)
	b, err = Encode(discoveryNM(&message.Discovery{Type: message.DiscoveryPublisherEndpoints, Endpoints: []*ua.EndpointDescription{nil}, Layout: message.DiscoveryLayoutDotNet}), nil)
	require.NoError(t, err)
	dec, err = Decode(b, nil)
	require.NoError(t, err)
	require.Len(t, dec.Discovery.Endpoints, 1)
	require.Equal(t, message.DiscoveryLayoutDotNet, dec.Discovery.Layout)
}

func hexOf(t *testing.T, v any) string {
	const digits = "0123456789abcdef"
	var out []byte
	for _, c := range encoded(t, v) {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
