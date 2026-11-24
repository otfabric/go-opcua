// SPDX-License-Identifier: MIT

package fxcm

import (
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
)

func ptr[T any](v T) *T { return &v }

// vendorNS is the namespace index of the vendor model in the Namespaces of
// the servers of the fixture; acNS that of the UAFX AC namespace.
const (
	vendorNS = 1
	acNS     = 2
)

var serverNamespaces = []string{uaNamespace, "urn:vendor:model", fxacid.NamespaceURI}

// path is an IdentifierBrowsePath of one element in the vendor namespace.
func path(names ...string) *uafx.NodeIdentifier {
	rp := &ua.RelativePath{}
	for _, n := range names {
		rp.Elements = append(rp.Elements, &ua.RelativePathElement{
			ReferenceTypeID: ua.NewNumericNodeID(0, 47), // HasComponent
			IncludeSubtypes: true,
			TargetName:      &ua.QualifiedName{NamespaceIndex: vendorNS, Name: n},
		})
	}
	return &uafx.NodeIdentifier{IdentifierBrowsePath: rp}
}

func urlAddress(u string) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: u})
}

// validConf is a set with two servers, two AutomationComponents, one
// multicast flow with one SubscriberConfiguration and two Connections from
// AC1 to AC2 and back... the second publishes on its own unicast flow.
func validConf() *uafx.ConnectionConfigurationSetConf {
	server := func(name, addr string) *uafx.ServerAddressConf {
		return &uafx.ServerAddressConf{
			BrowseName:            name,
			Address:               addr,
			SecurityMode:          ua.MessageSecurityModeSignAndEncrypt,
			SecurityModeSelection: []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt},
			ServerURI:             "urn:" + name,
			Namespaces:            serverNamespaces,
		}
	}
	pubsub := ua.NewNumericNodeID(acNS, fxacid.PubSubConnectionEndpointType)
	return &uafx.ConnectionConfigurationSetConf{
		BrowseName:                       "Line1",
		ConnectionConfigurationSetFolder: []string{"Plant", "Hall"},
		RollbackOnError:                  true,
		ServerAddresses:                  []*uafx.ServerAddressConf{server("PLC1", "opc.tcp://plc1:4840"), server("PLC2", "opc.tcp://plc2:4840")},
		AutomationComponentConfigurations: []*uafx.AutomationComponentConfigurationConf{
			{BrowseName: "AC1", AutomationComponentNode: path("AC1"), ServerAddressIndex: 0},
			{
				BrowseName: "AC2", AutomationComponentNode: path("AC2"), ServerAddressIndex: 1,
				AutomationComponentNodeSelection: []*uafx.NodeIdentifier{path("AC2"), path("AC2b")},
				AssetVerification: []*uafx.AssetVerificationConf{{
					AssetToVerify:                 path("Drive"),
					ExpectedVerificationVariables: []*uafx.NodeIdentifierValuePair{{Key: path("Serial"), Value: ua.MustVariant("42")}},
				}},
			},
		},
		CommunicationFlows: []uafx.CommunicationFlowConfigurationConf{
			&uafx.PubSubCommunicationFlowConfigurationConf{
				BrowseName:                  "Flow1",
				Address:                     &uafx.AddressSelection{Address: urlAddress("opc.udp://239.0.0.1:4840")},
				PublishingInterval:          ptr(10.0),
				PublishingIntervalSelection: []float64{10, 20},
				SubscriberConfigurations:    []*uafx.SubscriberConfigurationConf{{BrowseName: "Sub1", MessageReceiveTimeout: 100}},
			},
			&uafx.PubSubCommunicationFlowConfigurationConf{
				BrowseName:               "Flow2",
				Address:                  &uafx.AddressSelection{Address: urlAddress("opc.udp://10.0.0.1:4840")},
				SubscriberConfigurations: []*uafx.SubscriberConfigurationConf{{BrowseName: "Sub1", MessageReceiveTimeout: 100}},
			},
		},
		Connections: []*uafx.ConnectionConfigurationConf{
			{
				BrowseName: "C1",
				Endpoint1: &uafx.ConnectionEndpointConfigurationConf{
					FunctionalEntityNode: path("AC1", "FE1"), Name: "ToAC2", NameSelection: []string{"ToAC2"},
					ConnectionEndpointTypeID: pubsub, OutputVariableIDs: []*uafx.NodeIdentifier{path("Out1")},
					AutomationComponentIndex: 0, OutboundFlowIndex: ptr[int32](0),
					PreconfiguredPublishedDataSet: ptr("PDS1"),
				},
				Endpoint2: &uafx.ConnectionEndpointConfigurationConf{
					FunctionalEntityNode: path("AC2", "FE2"), Name: "FromAC1",
					ConnectionEndpointTypeID: pubsub, InputVariableIDs: []*uafx.NodeIdentifier{path("In1")},
					AutomationComponentIndex: 1, InboundFlowIndex: []int32{0, 0},
					ControlGroups:     []*uafx.NodeIdentifier{{Node: ua.NewStringNodeID(vendorNS, "CG1")}},
					ConfigurationData: []*uafx.NodeIdentifierValuePair{{Key: path("Gain"), Value: ua.MustVariant(1.5)}},
				},
			},
			{
				BrowseName: "C2",
				Endpoint1: &uafx.ConnectionEndpointConfigurationConf{
					FunctionalEntityNode: path("AC2", "FE2"), Name: "ToAC1",
					ConnectionEndpointTypeID: pubsub, OutputVariableIDs: []*uafx.NodeIdentifier{{Alias: ptr("Out2")}},
					AutomationComponentIndex: 1, OutboundFlowIndex: ptr[int32](1),
				},
				Endpoint2: &uafx.ConnectionEndpointConfigurationConf{
					FunctionalEntityNode: path("AC1", "FE1"), Name: "FromAC2",
					ConnectionEndpointTypeID: pubsub, InputVariableIDs: []*uafx.NodeIdentifier{path("In2")},
					AutomationComponentIndex: 0, InboundFlowIndex: []int32{1, 0}, OutboundFlowIndex: ptr[int32](-1),
				},
			},
		},
	}
}
