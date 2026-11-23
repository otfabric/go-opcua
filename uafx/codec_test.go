// SPDX-License-Identifier: MIT

package uafx

import (
	"errors"
	"reflect"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

const testData = 7 // the index of the UAFX Data namespace in the tests

func fullRequest() *EstablishConnectionsRequest {
	return &EstablishConnectionsRequest{
		CommandMask: AllFxCommands,
		AssetVerifications: []*AssetVerification{{
			AssetToVerify:              ua.NewNumericNodeID(9, 1100),
			VerificationMode:           AssetIdentityAndCompatibility,
			ExpectedVerificationResult: AssetVerificationMatch,
			ExpectedVerificationVariables: []*ua.KeyValuePair{
				{Key: &ua.QualifiedName{NamespaceIndex: 4, Name: "SerialNumber"}, Value: ua.MustVariant("SN-1")},
			},
			ExpectedAdditionalVerificationVariables: []*NodeIDValuePair{
				{Key: &NodeIDArray{Node: ua.NewNumericNodeID(9, 1108), ArrayIndex: []uint32{1, 2}}, Value: ua.MustVariant(int32(3))},
			},
		}},
		ConnectionEndpointConfigurations: []*ConnectionEndpointConfiguration{
			{
				FunctionalEntityNode: ua.NewNumericNodeID(9, 1200),
				ConnectionEndpoint: &ConnectionEndpointDefinition{Parameter: &PubSubConnectionEndpointParameter{
					Name:                     "ToLine",
					ConnectionEndpointTypeID: ua.NewNumericNodeID(8, 1005),
					InputVariableIDs:         []*ua.NodeID{ua.NewNumericNodeID(9, 1)},
					OutputVariableIDs:        []*ua.NodeID{ua.NewNumericNodeID(9, 2), ua.NewStringNodeID(9, "out")},
					CleanupTimeout:           -1,
					RelatedEndpoint: &RelatedEndpoint{
						Address:                "opc.tcp://peer:4840",
						ConnectionEndpointPath: []*ua.PortableQualifiedName{{NamespaceURI: "urn:peer", Name: "Line"}},
						ConnectionEndpointName: "ToController",
					},
					Mode: PubSubPublisherSubscriber,
				}},
				ExpectedVerificationVariables: []*NodeIDValuePair{{Key: &NodeIDArray{Node: ua.NewNumericNodeID(9, 5)}, Value: ua.MustVariant(true)}},
				ControlGroups:                 []*ua.NodeID{ua.NewNumericNodeID(9, 6)},
				ConfigurationData:             []*NodeIDValuePair{{Key: &NodeIDArray{Node: ua.NewNumericNodeID(9, 7)}, Value: ua.MustVariant(1.5)}},
				CommunicationLinks: &PubSubCommunicationLinkConfiguration{
					DataSetReaderRef:                 &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceReader, ElementIndex: 0, ConnectionIndex: 0, GroupIndex: 1},
					ExpectedSubscribedDataSetVersion: &ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 2},
					DataSetWriterRef:                 &ua.PubSubConfigurationRefDataType{ConfigurationMask: ua.PubSubConfigurationRefMaskReferenceWriter},
					ExpectedPublishedDataSetVersion:  &ua.ConfigurationVersionDataType{},
				},
			},
			{
				FunctionalEntityNode: ua.NewNumericNodeID(9, 1200),
				ConnectionEndpoint:   &ConnectionEndpointDefinition{Node: ua.NewNumericNodeID(9, 1300)},
			},
		},
		ReserveCommunicationIDs: []*PubSubReserveCommunicationIDs{{TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp", NumReqWriterGroupIDs: 1, NumReqDataSetWriterIDs: 2, RequestTransportSpecificInfo: true}},
		CommunicationConfigurations: []*PubSubCommunicationConfiguration{{
			PubSubConfiguration: &ua.PubSubConfiguration2DataType{
				Connections: []*ua.PubSubConnectionDataType{{Name: "C", Enabled: true, PublisherID: ua.MustVariant(uint16(7)), TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"}},
			},
			RequireCompleteUpdate:   true,
			ConfigurationReferences: []*ua.PubSubConfigurationRefDataType{{ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | ua.PubSubConfigurationRefMaskReferenceConnection}},
		}},
	}
}

func fullResult() *EstablishConnectionsResult {
	return &EstablishConnectionsResult{
		AssetVerificationResults: []*AssetVerificationResultData{{VerificationStatus: ua.StatusOK, VerificationResult: AssetVerificationMatch, VerificationVariablesErrors: []ua.StatusCode{ua.StatusOK}}},
		ConnectionEndpointConfigurationResults: []*ConnectionEndpointConfigurationResult{{
			ConnectionEndpointID:      ua.NewNumericNodeID(9, 5000),
			ConnectionEndpointResult:  ua.StatusOK,
			VerificationResult:        FunctionalEntityVerificationMatch,
			EstablishControlResult:    []ua.StatusCode{ua.StatusBadNodeIDUnknown},
			EnableCommunicationResult: ua.StatusBadNothingToDo,
		}},
		ReserveCommunicationIDsResults: []*PubSubReserveCommunicationIDsResult{{
			DefaultPublisherID: ua.MustVariant(uint64(42)), WriterGroupIDs: []uint16{0x8000}, DataSetWriterIDs: []uint16{0x8000, 0x8001},
			TransportSpecificInfo: ua.MustVariant(uint16(4840)),
		}},
		CommunicationConfigurationResults: []*PubSubCommunicationConfigurationResult{{
			Result: ua.StatusOK, ChangesApplied: true, ReferenceResults: []ua.StatusCode{ua.StatusOK},
			ConfigurationValues:  []*ua.PubSubConfigurationValueDataType{{ConfigurationElement: &ua.PubSubConfigurationRefDataType{}, Name: "C", Identifier: ua.MustVariant(uint16(1))}},
			ConfigurationObjects: []*ua.NodeID{ua.NewNumericNodeID(1, 77)},
		}},
	}
}

// wire sends args through the binary encoding as a Call does.
func wire(t *testing.T, args []*ua.Variant) []*ua.Variant {
	t.Helper()
	out := make([]*ua.Variant, len(args))
	for i, a := range args {
		b, err := a.Encode()
		if err != nil {
			t.Fatal(err)
		}
		out[i] = new(ua.Variant)
		if _, err := out[i].Decode(b); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestEstablishConnectionsRequestRoundTrip(t *testing.T) {
	want := fullRequest()
	args, err := EncodeEstablishConnectionsRequest(want, testData)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEstablishConnectionsRequest(wire(t, args), testData)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundTrip(t, want), got) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	// Another Data namespace index does not decode.
	if _, err := DecodeEstablishConnectionsRequest(wire(t, args), testData+1); !errors.Is(err, ErrCodec) {
		t.Errorf("another namespace: %v", err)
	}
}

// roundTrip returns v as the reflective decoder rebuilds it: empty slices
// and nil pointers as Decode leaves them.
func roundTrip[T any](t *testing.T, v *T) *T {
	t.Helper()
	switch x := any(v).(type) {
	case *EstablishConnectionsRequest:
		args, err := EncodeEstablishConnectionsRequest(x, testData)
		if err != nil {
			t.Fatal(err)
		}
		r, err := DecodeEstablishConnectionsRequest(wire(t, args), testData)
		if err != nil {
			t.Fatal(err)
		}
		args2, err := EncodeEstablishConnectionsRequest(r, testData)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := DecodeEstablishConnectionsRequest(wire(t, args2), testData)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(r, r2) {
			t.Fatalf("not stable:\n%+v\n%+v", r, r2)
		}
		return any(r).(*T)
	}
	return v
}

func TestEstablishConnectionsRequestFields(t *testing.T) {
	want := fullRequest()
	args, err := EncodeEstablishConnectionsRequest(want, testData)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEstablishConnectionsRequest(wire(t, args), testData)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommandMask != AllFxCommands || len(got.ConnectionEndpointConfigurations) != 2 {
		t.Fatalf("%+v", got)
	}
	p := got.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter
	if p == nil || p.Name != "ToLine" || p.Mode != PubSubPublisherSubscriber || p.CleanupTimeout != -1 ||
		p.RelatedEndpoint.ConnectionEndpointPath[0].Name != "Line" || len(p.OutputVariableIDs) != 2 {
		t.Errorf("parameter: %+v", p)
	}
	if n := got.ConnectionEndpointConfigurations[1].ConnectionEndpoint.Node; n == nil || n.IntID() != 1300 {
		t.Errorf("node arm: %v", n)
	}
	if l := got.ConnectionEndpointConfigurations[1].CommunicationLinks; l != nil {
		t.Errorf("CommunicationLinks of the second: %+v", l)
	}
	l := got.ConnectionEndpointConfigurations[0].CommunicationLinks
	if l == nil || l.ExpectedSubscribedDataSetVersion.MinorVersion != 2 || l.DataSetReaderRef.GroupIndex != 1 {
		t.Errorf("links: %+v", l)
	}
	r := got.ReserveCommunicationIDs[0]
	if r.NumReqDataSetWriterIDs != 2 || !r.RequestTransportSpecificInfo {
		t.Errorf("reserve: %+v", r)
	}
	if c := got.CommunicationConfigurations[0]; !c.RequireCompleteUpdate || c.PubSubConfiguration.Connections[0].Name != "C" {
		t.Errorf("communication: %+v", c)
	}
}

func TestEstablishConnectionsResultRoundTrip(t *testing.T) {
	want := fullResult()
	out, err := EncodeEstablishConnectionsResult(want, testData)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEstablishConnectionsResult(wire(t, out), testData)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID.IntID() != 5000 ||
		got.ConnectionEndpointConfigurationResults[0].EstablishControlResult[0] != ua.StatusBadNodeIDUnknown ||
		got.ReserveCommunicationIDsResults[0].TransportSpecificInfo.Value() != uint16(4840) ||
		got.CommunicationConfigurationResults[0].ConfigurationObjects[0].IntID() != 77 ||
		got.AssetVerificationResults[0].VerificationResult != AssetVerificationMatch {
		t.Errorf("%+v", got)
	}
}

func TestReserveV1(t *testing.T) {
	c := codec{testData}
	eo, err := c.eo(fxdataid.PubSubReserveCommunicationIDsDataTypeEncodingDefaultBinary, &reserveV1{TransportProfileURI: "u", NumReqWriterGroupIDs: 3})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.decodeReserve(eo)
	if err != nil || v.NumReqWriterGroupIDs != 3 || v.RequestTransportSpecificInfo {
		t.Errorf("%+v %v", v, err)
	}
	eo, err = c.eo(fxdataid.PubSubReserveCommunicationIDsResultDataTypeEncodingDefaultBinary, &reserveResultV1{WriterGroupIDs: []uint16{9}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.decodeReserveResult(eo)
	if err != nil || res.WriterGroupIDs[0] != 9 || res.TransportSpecificInfo != nil {
		t.Errorf("%+v %v", res, err)
	}
}

func TestCodecErrors(t *testing.T) {
	c := codec{testData}
	good, err := EncodeEstablishConnectionsRequest(fullRequest(), testData)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(i int, v *ua.Variant) []*ua.Variant {
		out := append([]*ua.Variant(nil), good...)
		out[i] = v
		return out
	}
	other, _ := codec{testData}.eo(fxdataid.AssetVerificationDataTypeEncodingDefaultBinary, &AssetVerification{})
	trunc := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(testData, fxdataid.ConnectionEndpointConfigurationDataTypeEncodingDefaultBinary), Value: []byte{1, 2}}
	badSwitch, _ := c.eo(fxdataid.ConnectionEndpointConfigurationDataTypeEncodingDefaultBinary, &struct {
		F *ua.NodeID
		S uint32
	}{ua.NewTwoByteNodeID(0), 3})
	nullParam, _ := c.eo(fxdataid.ConnectionEndpointConfigurationDataTypeEncodingDefaultBinary, &endpointConfigurationWire{
		ConnectionEndpoint: &definitionWire{Switch: 1, Parameter: nullEO()}, CommunicationLinks: nullEO(),
	})
	wrongParam, _ := c.eo(fxdataid.ConnectionEndpointConfigurationDataTypeEncodingDefaultBinary, &endpointConfigurationWire{
		ConnectionEndpoint: &definitionWire{Switch: 1, Parameter: other}, CommunicationLinks: nullEO(),
	})
	wrongLinks, _ := c.eo(fxdataid.ConnectionEndpointConfigurationDataTypeEncodingDefaultBinary, &endpointConfigurationWire{
		ConnectionEndpoint: &definitionWire{}, CommunicationLinks: other,
	})
	xml := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectXML, TypeID: ua.NewNumericExpandedNodeID(testData, 1), Value: new(ua.XMLElement)}
	uri := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: &ua.ExpandedNodeID{NodeID: ua.NewNumericNodeID(0, 1), NamespaceURI: "u"}, Value: []byte{}}
	decoded := &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, TypeID: ua.NewNumericExpandedNodeID(testData, 1), Value: 1}
	for name, args := range map[string][]*ua.Variant{
		"count":          good[:4],
		"mask type":      mk(0, ua.MustVariant(int32(1))),
		"not an array":   mk(1, ua.MustVariant("x")),
		"wrong encoding": mk(1, ua.MustVariant([]*ua.ExtensionObject{trunc})),
		"truncated":      mk(2, ua.MustVariant([]*ua.ExtensionObject{trunc})),
		"switch":         mk(2, ua.MustVariant([]*ua.ExtensionObject{badSwitch})),
		"null parameter": mk(2, ua.MustVariant([]*ua.ExtensionObject{nullParam})),
		"parameter type": mk(2, ua.MustVariant([]*ua.ExtensionObject{wrongParam})),
		"links type":     mk(2, ua.MustVariant([]*ua.ExtensionObject{wrongLinks})),
		"xml":            mk(3, ua.MustVariant([]*ua.ExtensionObject{xml})),
		"uri":            mk(3, ua.MustVariant([]*ua.ExtensionObject{uri})),
	} {
		if _, err := DecodeEstablishConnectionsRequest(wire(t, args), testData); !errors.Is(err, ErrCodec) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := c.body(decoded); !errors.Is(err, ErrCodec) {
		t.Errorf("decoded: %v", err)
	}
	if _, _, err := c.body(&ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary}); !errors.Is(err, ErrCodec) {
		t.Errorf("no type: %v", err)
	}
	if _, err := DecodeEstablishConnectionsResult(good[:3], testData); !errors.Is(err, ErrCodec) {
		t.Errorf("result count: %v", err)
	}
	for i := range 4 {
		out := []*ua.Variant{nil, nil, nil, nil}
		out[i] = ua.MustVariant([]*ua.ExtensionObject{trunc})
		if _, err := DecodeEstablishConnectionsResult(out, testData); !errors.Is(err, ErrCodec) {
			t.Errorf("result %d: %v", i, err)
		}
	}
	if _, err := EncodeEstablishConnectionsRequest(&EstablishConnectionsRequest{AssetVerifications: []*AssetVerification{nil}}, testData); !errors.Is(err, ErrCodec) {
		t.Errorf("nil element: %v", err)
	}
	both := &EstablishConnectionsRequest{ConnectionEndpointConfigurations: []*ConnectionEndpointConfiguration{{ConnectionEndpoint: &ConnectionEndpointDefinition{Parameter: &PubSubConnectionEndpointParameter{}, Node: ua.NewTwoByteNodeID(1)}}}}
	if _, err := EncodeEstablishConnectionsRequest(both, testData); !errors.Is(err, ErrCodec) {
		t.Errorf("both arms: %v", err)
	}
	if _, err := (&definitionWire{Switch: 9}).Encode(); !errors.Is(err, ErrCodec) {
		t.Errorf("switch 9: %v", err)
	}
}

func TestCommandMask(t *testing.T) {
	m := EnableCommunicationCmd | VerifyAssetCmd | ReserveCommunicationIDsCmd | CreateConnectionEndpointCmd
	want := []FxCommandMask{VerifyAssetCmd, ReserveCommunicationIDsCmd, CreateConnectionEndpointCmd, EnableCommunicationCmd}
	if got := m.Order(); !reflect.DeepEqual(got, want) {
		t.Errorf("Order: %v", got)
	}
	if s := (VerifyAssetCmd | 1<<12).String(); s != "VerifyAsset|0x1000" {
		t.Errorf("String: %s", s)
	}
	if !PubSubPublisherSubscriber.Publishes() || !PubSubPublisherSubscriber.Subscribes() || PubSubPublisher.Subscribes() || PubSubSubscriber.Publishes() {
		t.Error("mode")
	}
	p := &PubSubConnectionEndpointParameter{CleanupTimeout: -1}
	if _, ok := p.CleanupTimeoutDuration(); ok {
		t.Error("negative")
	}
	p.CleanupTimeout = 1500
	if d, ok := p.CleanupTimeoutDuration(); !ok || d.Milliseconds() != 1500 {
		t.Errorf("%v %v", d, ok)
	}
}
