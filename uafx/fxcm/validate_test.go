// SPDX-License-Identifier: MIT

package fxcm

import (
	"errors"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
)

type conf = uafx.ConnectionConfigurationSetConf

// TestValidate changes the valid fixture in one way per case and checks
// the finding: its Path and a part of its Clause.
func TestValidate(t *testing.T) {
	ep := func(c *conf, i, n int) *uafx.ConnectionEndpointConfigurationConf {
		if n == 1 {
			return c.Connections[i].Endpoint1
		}
		return c.Connections[i].Endpoint2
	}
	for _, tc := range []struct {
		name   string
		mutate func(c *conf)
		path   string
		clause string
	}{
		// The set.
		{"no BrowseName", func(c *conf) { c.BrowseName = "" }, "BrowseName", libInterp},
		{"empty Folder", func(c *conf) { c.ConnectionConfigurationSetFolder[1] = "" }, "ConnectionConfigurationSetFolder[1]", libInterp},
		{"no Connections", func(c *conf) { c.Connections = nil }, "Connections", "§6.8.2 Table 89"},
		{"no flows", func(c *conf) { c.CommunicationFlows = nil }, "CommunicationFlows", "§6.8.2 Table 89"},
		{"no ServerAddresses", func(c *conf) { c.ServerAddresses = nil }, "ServerAddresses", "§6.8.2 Table 89"},
		{"no ACs", func(c *conf) { c.AutomationComponentConfigurations = nil }, "AutomationComponentConfigurations", "§6.8.2 Table 89"},

		// ServerAddresses.
		{"null server", func(c *conf) { c.ServerAddresses[1] = nil }, "ServerAddresses[1].Address", "§9.2"},
		{"server without name", func(c *conf) { c.ServerAddresses[1].BrowseName = "" }, "ServerAddresses[1].BrowseName", libInterp},
		{"server name twice", func(c *conf) { c.ServerAddresses[1].BrowseName = "PLC1" }, "ServerAddresses[1].BrowseName", "siblings"},
		{"no Address", func(c *conf) { c.ServerAddresses[0].Address = "" }, "ServerAddresses[0].Address", "§9.2"},
		{"SecurityMode Invalid", func(c *conf) {
			c.ServerAddresses[0].SecurityMode = ua.MessageSecurityModeInvalid
			c.ServerAddresses[0].SecurityModeSelection = nil
		}, "ServerAddresses[0].SecurityMode", "§9.2"},
		{"SecurityMode 9", func(c *conf) {
			c.ServerAddresses[0].SecurityMode = 9
			c.ServerAddresses[0].SecurityModeModify = ptr(true)
		}, "ServerAddresses[0].SecurityMode", "§9.2"},
		{"SecurityMode not selectable", func(c *conf) { c.ServerAddresses[0].SecurityMode = ua.MessageSecurityModeNone }, "ServerAddresses[0].SecurityMode", "F.1.2.3"},
		{"Namespaces[0] not UA", func(c *conf) { c.ServerAddresses[0].Namespaces = []string{"urn:x"} }, "ServerAddresses[0].Namespaces[0]", "F.1.2.2"},
		{"empty NamespaceUri", func(c *conf) { c.ServerAddresses[0].Namespaces = []string{uaNamespace, ""} }, "ServerAddresses[0].Namespaces[1]", "F.1.2.2"},
		{"Address not selectable", func(c *conf) { c.ServerAddresses[0].AddressSelection = []string{"opc.tcp://other:4840"} }, "ServerAddresses[0].Address", "F.1.2.3"},
		{"SecurityPolicyUri not selectable", func(c *conf) { c.ServerAddresses[0].SecurityPolicyURISelection = []string{"x"} }, "ServerAddresses[0].SecurityPolicyUri", "F.1.2.3"},
		{"ServerUri not selectable", func(c *conf) { c.ServerAddresses[0].ServerURISelection = []string{"x"} }, "ServerAddresses[0].ServerUri", "F.1.2.3"},

		// AutomationComponentConfigurations.
		{"null AC", func(c *conf) { c.AutomationComponentConfigurations[1] = nil }, "AutomationComponentConfigurations[1].AutomationComponentNode", "§6.14"},
		{"AC name twice", func(c *conf) { c.AutomationComponentConfigurations[1].BrowseName = "AC1" }, "AutomationComponentConfigurations[1].BrowseName", "siblings"},
		{"AC without server", func(c *conf) { c.AutomationComponentConfigurations[0].ServerAddressIndex = -1 }, "AutomationComponentConfigurations[0].ServerAddressIndex", "Table 90"},
		{"AC server out of range", func(c *conf) { c.AutomationComponentConfigurations[0].ServerAddressIndex = 2 }, "AutomationComponentConfigurations[0].ServerAddressIndex", "F.1.2.1"},
		{"AC node absent", func(c *conf) { c.AutomationComponentConfigurations[0].AutomationComponentNode = nil }, "AutomationComponentConfigurations[0].AutomationComponentNode", "§6.14"},
		{"AC node null union", func(c *conf) { c.AutomationComponentConfigurations[0].AutomationComponentNode = &uafx.NodeIdentifier{} }, "AutomationComponentConfigurations[0].AutomationComponentNode", "§6.14"},
		{"AC node not selectable", func(c *conf) { c.AutomationComponentConfigurations[1].AutomationComponentNode = path("AC3") }, "AutomationComponentConfigurations[1].AutomationComponentNode", "F.1.2.3"},
		{"AC node namespace", func(c *conf) {
			c.AutomationComponentConfigurations[0].AutomationComponentNode.IdentifierBrowsePath.Elements[0].TargetName.NamespaceIndex = 9
		}, "AutomationComponentConfigurations[0].AutomationComponentNode.IdentifierBrowsePath[0].TargetName", "F.1.2.2"},
		{"null AssetVerification", func(c *conf) { c.AutomationComponentConfigurations[1].AssetVerification[0] = nil }, "AutomationComponentConfigurations[1].AssetVerification[0].AssetToVerify", "§6.15"},
		{"no AssetToVerify", func(c *conf) { c.AutomationComponentConfigurations[1].AssetVerification[0].AssetToVerify = nil }, "AutomationComponentConfigurations[1].AssetVerification[0].AssetToVerify", "§6.15"},
		{"null verification pair", func(c *conf) {
			c.AutomationComponentConfigurations[1].AssetVerification[0].ExpectedVerificationVariables[0] = nil
		}, "AutomationComponentConfigurations[1].AssetVerification[0].ExpectedVerificationVariables[0].Key", "§6.15"},
		{"verification pair without key", func(c *conf) {
			c.AutomationComponentConfigurations[1].AssetVerification[0].ExpectedAdditionalVerificationVariables = []*uafx.NodeIdentifierValuePair{{}}
		}, "AutomationComponentConfigurations[1].AssetVerification[0].ExpectedAdditionalVerificationVariables[0].Key", "§6.15"},

		// CommunicationFlows.
		{"null flow", func(c *conf) { c.CommunicationFlows[1] = nil }, "CommunicationFlows[1]", "§6.13"},
		{"flow name twice", func(c *conf) { pubsubFlow(c, 1).BrowseName = "Flow1" }, "CommunicationFlows[1].BrowseName", "siblings"},
		{"null subscriber", func(c *conf) {
			pubsubFlow(c, 0).SubscriberConfigurations = append(pubsubFlow(c, 0).SubscriberConfigurations, nil)
		}, "CommunicationFlows[0].SubscriberConfigurations[1].BrowseName", libInterp},
		{"subscriber name twice", func(c *conf) {
			pubsubFlow(c, 0).SubscriberConfigurations = append(pubsubFlow(c, 0).SubscriberConfigurations, &uafx.SubscriberConfigurationConf{BrowseName: "Sub1"})
		}, "CommunicationFlows[0].SubscriberConfigurations[1].BrowseName", "siblings"},
		{"no Address anywhere", func(c *conf) { pubsubFlow(c, 0).Address = nil }, "CommunicationFlows[0].SubscriberConfigurations[0].Address", "§6.13.3"},
		{"null Address anywhere", func(c *conf) {
			pubsubFlow(c, 0).Address = &uafx.AddressSelection{}
			pubsubFlow(c, 0).SubscriberConfigurations[0].Address = &uafx.AddressSelection{Address: &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectEmpty, TypeID: ua.NewTwoByteExpandedNodeID(0)}}
		}, "CommunicationFlows[0].SubscriberConfigurations[0].Address", "§6.13.3"},
		{"ReceiveQos without Qos", func(c *conf) {
			pubsubFlow(c, 0).SubscriberConfigurations[0].ReceiveQos = &uafx.ReceiveQosSelection{}
		}, "CommunicationFlows[0].SubscriberConfigurations[0].ReceiveQos", "§6.13.3"},
		{"TransportProfileUri not selectable", func(c *conf) {
			pubsubFlow(c, 0).TransportProfileURI = ptr("a")
			pubsubFlow(c, 0).TransportProfileURISelection = []string{"b"}
		}, "CommunicationFlows[0].TransportProfileUri", "F.1.2.3"},
		{"PublishingInterval not selectable", func(c *conf) { pubsubFlow(c, 0).PublishingInterval = ptr(30.0) }, "CommunicationFlows[0].PublishingInterval", "F.1.2.3"},
		{"Qos not selectable", func(c *conf) {
			pubsubFlow(c, 0).Qos = &uafx.CommunicationFlowQos{QosCategory: "a"}
			pubsubFlow(c, 0).QosSelection = []*uafx.CommunicationFlowQos{{QosCategory: "b"}}
		}, "CommunicationFlows[0].Qos", "F.1.2.3"},
		{"flow Address not selectable", func(c *conf) {
			pubsubFlow(c, 0).Address.AddressSelection = []*ua.ExtensionObject{urlAddress("opc.udp://239.0.0.2:4840")}
		}, "CommunicationFlows[0].Address", "F.1.2.3"},
		{"subscriber Address not selectable", func(c *conf) {
			pubsubFlow(c, 0).SubscriberConfigurations[0].Address = &uafx.AddressSelection{
				Address:          urlAddress("opc.udp://239.0.0.1:4841"),
				AddressSelection: []*ua.ExtensionObject{urlAddress("opc.udp://239.0.0.1:4842")},
			}
		}, "CommunicationFlows[0].SubscriberConfigurations[0].Address", "F.1.2.3"},
		{"MessageReceiveTimeout not selectable", func(c *conf) {
			pubsubFlow(c, 0).SubscriberConfigurations[0].MessageReceiveTimeoutSelection = []float64{1}
		}, "CommunicationFlows[0].SubscriberConfigurations[0].MessageReceiveTimeout", "F.1.2.3"},
		{"two publishers", func(c *conf) { ep(c, 1, 1).OutboundFlowIndex = ptr[int32](0) }, "CommunicationFlows[0]", "§6.13.3"},
		{"unicast with two SubscriberConfigurations", func(c *conf) {
			pubsubFlow(c, 1).SubscriberConfigurations = append(pubsubFlow(c, 1).SubscriberConfigurations, &uafx.SubscriberConfigurationConf{BrowseName: "Sub2"})
		}, "CommunicationFlows[1].SubscriberConfigurations", "§6.13.3"},
		{"unicast with two subscribers", func(c *conf) { ep(c, 0, 2).InboundFlowIndex = []int32{1, 0} }, "CommunicationFlows[1]", "§6.13.3"},

		// Connections.
		{"null Connection", func(c *conf) { c.Connections[1] = nil }, "Connections[1].BrowseName", libInterp},
		{"Connection without name", func(c *conf) { c.Connections[1].BrowseName = "" }, "Connections[1].BrowseName", libInterp},
		{"Connection name twice", func(c *conf) { c.Connections[1].BrowseName = "C1" }, "Connections[1].BrowseName", "§6.8.2"},
		{"no Endpoint1", func(c *conf) { c.Connections[1].Endpoint1 = nil }, "Connections[1].Endpoint1.FunctionalEntityNode", "§6.11"},
		{"AC index negative", func(c *conf) { ep(c, 0, 1).AutomationComponentIndex = -1 }, "Connections[0].Endpoint1.AutomationComponentIndex", "Table 90"},
		{"AC index out of range", func(c *conf) { ep(c, 0, 1).AutomationComponentIndex = 2 }, "Connections[0].Endpoint1.AutomationComponentIndex", "F.1.2.1"},
		{"no FunctionalEntityNode", func(c *conf) { ep(c, 0, 1).FunctionalEntityNode = nil }, "Connections[0].Endpoint1.FunctionalEntityNode", "§6.11"},
		{"empty Alias", func(c *conf) { ep(c, 0, 1).FunctionalEntityNode = &uafx.NodeIdentifier{Alias: ptr("")} }, "Connections[0].Endpoint1.FunctionalEntityNode.Alias", "§6.11"},
		{"empty RelativePath", func(c *conf) {
			ep(c, 0, 1).FunctionalEntityNode = &uafx.NodeIdentifier{IdentifierBrowsePath: &ua.RelativePath{}}
		}, "Connections[0].Endpoint1.FunctionalEntityNode.IdentifierBrowsePath", "§6.11"},
		{"RelativePath element without TargetName", func(c *conf) {
			ep(c, 0, 1).FunctionalEntityNode.IdentifierBrowsePath.Elements[1].TargetName = nil
		}, "Connections[0].Endpoint1.FunctionalEntityNode.IdentifierBrowsePath[1]", "F.1.15"},
		{"ReferenceTypeId namespace", func(c *conf) {
			ep(c, 0, 1).FunctionalEntityNode.IdentifierBrowsePath.Elements[0].ReferenceTypeID = ua.NewNumericNodeID(5, 1)
		}, "Connections[0].Endpoint1.FunctionalEntityNode.IdentifierBrowsePath[0].ReferenceTypeId", "F.1.2.2"},
		{"Node namespace", func(c *conf) { ep(c, 0, 2).ControlGroups[0].Node = ua.NewStringNodeID(3, "CG1") }, "Connections[0].Endpoint2.ControlGroups[0].Node", "F.1.2.2"},
		{"FunctionalEntityNode not selectable", func(c *conf) {
			ep(c, 0, 1).FunctionalEntityNodeSelection = []*uafx.NodeIdentifier{path("AC1", "FE9")}
		}, "Connections[0].Endpoint1.FunctionalEntityNode", "F.1.2.3"},
		{"no Name", func(c *conf) {
			ep(c, 0, 1).Name = ""
			ep(c, 0, 1).NameModify = ptr(true)
		}, "Connections[0].Endpoint1.Name", "§6.12"},
		{"Name not selectable", func(c *conf) { ep(c, 0, 1).Name = "Other" }, "Connections[0].Endpoint1.Name", "F.1.2.3"},
		{"no type", func(c *conf) { ep(c, 0, 1).ConnectionEndpointTypeID = nil }, "Connections[0].Endpoint1.ConnectionEndpointTypeId", "§6.12"},
		{"type namespace", func(c *conf) { ep(c, 0, 2).ConnectionEndpointTypeID = ua.NewNumericNodeID(7, 1) }, "Connections[0].Endpoint2.ConnectionEndpointTypeId", "F.1.2.2"},
		{"no variables", func(c *conf) { ep(c, 0, 1).OutputVariableIDs = []*uafx.NodeIdentifier{} }, "Connections[0].Endpoint1", "§6.12"},
		{"bad input variable", func(c *conf) { ep(c, 0, 2).InputVariableIDs[0] = nil }, "Connections[0].Endpoint2.InputVariableIds[0]", "§6.12"},
		{"bad output variable", func(c *conf) { ep(c, 0, 1).OutputVariableIDs[0] = &uafx.NodeIdentifier{} }, "Connections[0].Endpoint1.OutputVariableIds[0]", "§6.12"},
		{"preconfigured DataSet, base type", func(c *conf) {
			ep(c, 0, 1).ConnectionEndpointTypeID = ua.NewNumericNodeID(acNS, fxacid.ConnectionEndpointType)
		}, "Connections[0].Endpoint1.ConnectionEndpointTypeId", "§6.12"},
		{"preconfigured DataSet, OPC UA type", func(c *conf) {
			ep(c, 0, 1).ConnectionEndpointTypeID = ua.NewNumericNodeID(0, 58)
		}, "Connections[0].Endpoint1.ConnectionEndpointTypeId", "§6.12"},
		{"preconfigured DataSet, string type", func(c *conf) {
			ep(c, 0, 2).PreconfiguredSubscribedDataSet = ptr("SDS")
			ep(c, 0, 2).ConnectionEndpointTypeID = ua.NewStringNodeID(acNS, "PubSubConnectionEndpointType")
		}, "Connections[0].Endpoint2.ConnectionEndpointTypeId", "§6.12"},
		{"bad ControlGroup", func(c *conf) { ep(c, 0, 2).ControlGroups[0] = nil }, "Connections[0].Endpoint2.ControlGroups[0]", "§6.11"},
		{"null ConfigurationData", func(c *conf) { ep(c, 0, 2).ConfigurationData[0] = nil }, "Connections[0].Endpoint2.ConfigurationData[0].Key", "§6.11"},
		{"bad ExpectedVerificationVariables", func(c *conf) {
			ep(c, 0, 2).ExpectedVerificationVariables = []*uafx.NodeIdentifierValuePair{{Key: &uafx.NodeIdentifier{}}}
		}, "Connections[0].Endpoint2.ExpectedVerificationVariables[0].Key", "§6.11"},
		{"OutboundFlowIndex out of range", func(c *conf) { ep(c, 0, 1).OutboundFlowIndex = ptr[int32](2) }, "Connections[0].Endpoint1.OutboundFlowIndex", "F.1.2.1"},
		{"InboundFlowIndex one element", func(c *conf) { ep(c, 0, 2).InboundFlowIndex = []int32{0} }, "Connections[0].Endpoint2.InboundFlowIndex", "Table F.5"},
		{"InboundFlowIndex subscriber without flow", func(c *conf) { ep(c, 0, 2).InboundFlowIndex = []int32{-1, 0} }, "Connections[0].Endpoint2.InboundFlowIndex", "F.1.2.1"},
		{"InboundFlowIndex flow out of range", func(c *conf) { ep(c, 0, 2).InboundFlowIndex = []int32{2, 0} }, "Connections[0].Endpoint2.InboundFlowIndex[0]", "F.1.2.1"},
		{"InboundFlowIndex subscriber out of range", func(c *conf) { ep(c, 0, 2).InboundFlowIndex = []int32{0, 1} }, "Connections[0].Endpoint2.InboundFlowIndex[1]", "§6.13.3"},
		{"InboundFlowIndex subscriber negative", func(c *conf) { ep(c, 0, 2).InboundFlowIndex = []int32{0, -1} }, "Connections[0].Endpoint2.InboundFlowIndex[1]", "§6.13.3"},
		{"Name twice in a FunctionalEntity", func(c *conf) { ep(c, 1, 2).Name = "ToAC2" }, "Connections[1].Endpoint2.Name", "§6.12"},

		// SecurityKeyServer.
		{"SKS without Address", func(c *conf) { c.SecurityKeyServer = &uafx.SecurityKeyServerAddressConf{ServerURI: "urn:sks"} }, "SecurityKeyServer.Address", "§9.3"},
		{"SKS Address not selectable", func(c *conf) {
			c.SecurityKeyServer = &uafx.SecurityKeyServerAddressConf{Address: "opc.tcp://sks", AddressSelection: []string{"opc.tcp://other"}}
		}, "SecurityKeyServer.Address", "F.1.2.3"},
		{"SKS SecurityPolicyUri not selectable", func(c *conf) {
			c.SecurityKeyServer = &uafx.SecurityKeyServerAddressConf{Address: "opc.tcp://sks", SecurityPolicyURISelection: []string{"x"}}
		}, "SecurityKeyServer.SecurityPolicyUri", "F.1.2.3"},
		{"SKS ServerUri not selectable", func(c *conf) {
			c.SecurityKeyServer = &uafx.SecurityKeyServerAddressConf{Address: "opc.tcp://sks", ServerURISelection: []string{"x"}}
		}, "SecurityKeyServer.ServerUri", "F.1.2.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConf()
			tc.mutate(c)
			_, err := NewConfig(c)
			var ce *ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("err %v, want a ConfigError", err)
			}
			if !errors.Is(err, ErrConfig) || !errors.Is(err, ua.StatusBadConfigurationError) || ce.FxError() != uafx.FxErrorConnectionConfigurationSetInvalid {
				t.Errorf("chain of %v", err)
			}
			for _, f := range ce.Findings {
				if f.Path == tc.path && strings.Contains(f.Clause, tc.clause) {
					return
				}
			}
			t.Errorf("no finding %s (%s) in %v", tc.path, tc.clause, ce.Findings)
		})
	}
}

// TestValidateAccepts changes the valid fixture in ways that stay valid.
func TestValidateAccepts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(c *conf)
	}{
		{"no Folder", func(c *conf) { c.ConnectionConfigurationSetFolder = nil }},
		{"Namespaces without OPC UA", func(c *conf) {
			for _, s := range c.ServerAddresses {
				s.Namespaces = nil
			}
			for _, cn := range c.Connections {
				for _, e := range []*uafx.ConnectionEndpointConfigurationConf{cn.Endpoint1, cn.Endpoint2} {
					e.ConnectionEndpointTypeID = ua.NewStringNodeID(0, "vendor-type-in-ns0-never-checked-for-InputOnly")
				}
			}
			c.Connections[0].Endpoint1.PreconfiguredPublishedDataSet = nil
			for _, ac := range c.AutomationComponentConfigurations {
				ac.AutomationComponentNode = &uafx.NodeIdentifier{Alias: ptr(ac.BrowseName)}
				ac.AutomationComponentNodeSelection = nil
				ac.AssetVerification = nil
			}
			for _, cn := range c.Connections {
				for _, e := range []*uafx.ConnectionEndpointConfigurationConf{cn.Endpoint1, cn.Endpoint2} {
					e.FunctionalEntityNode = &uafx.NodeIdentifier{Alias: ptr(cn.BrowseName + e.Name)}
					e.InputVariableIDs, e.OutputVariableIDs = nil, []*uafx.NodeIdentifier{{Alias: ptr("v")}}
					e.ControlGroups, e.ConfigurationData = nil, nil
				}
			}
		}},
		{"vendor endpoint type with a preconfigured DataSet", func(c *conf) {
			c.Connections[0].Endpoint1.ConnectionEndpointTypeID = ua.NewNumericNodeID(vendorNS, 5000)
		}},
		{"Modify TRUE allows any value", func(c *conf) {
			c.Connections[0].Endpoint1.Name, c.Connections[0].Endpoint1.NameModify = "Other", ptr(true)
			pubsubFlow(c, 0).PublishingInterval, pubsubFlow(c, 0).PublishingIntervalModify = ptr(30.0), ptr(true)
		}},
		{"current value among the Selection", func(c *conf) {
			pubsubFlow(c, 0).Address.AddressSelection = []*ua.ExtensionObject{urlAddress("opc.udp://239.0.0.9:4840"), urlAddress("opc.udp://239.0.0.1:4840")}
			pubsubFlow(c, 0).Qos = &uafx.CommunicationFlowQos{QosCategory: "a"}
			pubsubFlow(c, 0).QosSelection = []*uafx.CommunicationFlowQos{{QosCategory: "a"}}
			pubsubFlow(c, 0).SubscriberConfigurations[0].ReceiveQos = &uafx.ReceiveQosSelection{}
		}},
		{"subscriber Address without flow Address", func(c *conf) {
			pubsubFlow(c, 0).Address = nil
			pubsubFlow(c, 0).SubscriberConfigurations[0].Address = &uafx.AddressSelection{Address: urlAddress("opc.udp://239.0.0.1:4840")}
		}},
		{"multicast flow with two subscribers", func(c *conf) {
			pubsubFlow(c, 0).SubscriberConfigurations = append(pubsubFlow(c, 0).SubscriberConfigurations, &uafx.SubscriberConfigurationConf{BrowseName: "Sub2"})
			c.Connections = append(c.Connections, &uafx.ConnectionConfigurationConf{
				BrowseName: "C3",
				Endpoint1: &uafx.ConnectionEndpointConfigurationConf{
					FunctionalEntityNode: path("AC1", "FE3"), Name: "FromAC1",
					ConnectionEndpointTypeID: ua.NewNumericNodeID(acNS, fxacid.PubSubConnectionEndpointType),
					InputVariableIDs:         []*uafx.NodeIdentifier{path("In3")},
					AutomationComponentIndex: 0, InboundFlowIndex: []int32{0, 1},
				},
			})
		}},
		{"flow of a host name", func(c *conf) {
			pubsubFlow(c, 1).Address.Address = urlAddress("opc.udp://plc:4840")
			pubsubFlow(c, 1).SubscriberConfigurations = append(pubsubFlow(c, 1).SubscriberConfigurations, &uafx.SubscriberConfigurationConf{BrowseName: "Sub2"})
		}},
		{"no inbound flow", func(c *conf) { c.Connections[1].Endpoint2.InboundFlowIndex = []int32{-1, -1} }},
		{"same Name in another FunctionalEntity", func(c *conf) { c.Connections[1].Endpoint2.Name = "FromAC1" }},
		{"SKS", func(c *conf) {
			c.SecurityKeyServer = &uafx.SecurityKeyServerAddressConf{Address: "opc.tcp://sks", AddressSelection: []string{"opc.tcp://sks"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConf()
			tc.mutate(c)
			if _, err := NewConfig(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNullSKS(t *testing.T) {
	if !nullSKS(nil) || !nullSKS(&uafx.SecurityKeyServerAddressConf{}) || nullSKS(&uafx.SecurityKeyServerAddressConf{UsePushModel: true}) {
		t.Error("nullSKS")
	}
}

func TestMaybePubSubEndpoint(t *testing.T) {
	ns := namespaceScope(serverNamespaces)
	for _, tc := range []struct {
		id   *ua.NodeID
		want bool
	}{
		{nil, true},
		{ua.NewNumericNodeID(acNS, fxacid.PubSubConnectionEndpointType), true},
		{ua.NewNumericNodeID(acNS, fxacid.ConnectionEndpointType), false},
		{ua.NewGUIDNodeID(acNS, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"), false},
		{ua.NewNumericNodeID(0, 58), false},
		{ua.NewNumericNodeID(vendorNS, 1005), true},
		{ua.NewNumericNodeID(9, 1005), true},
	} {
		if got := maybePubSubEndpoint(tc.id, ns); got != tc.want {
			t.Errorf("%v: %v", tc.id, got)
		}
	}
}

func TestSameStructureNil(t *testing.T) {
	if sameStructure[*uafx.NodeIdentifier](nil, path("a")) || sameStructure(path("a"), (*uafx.NodeIdentifier)(nil)) {
		t.Error("a nil structure is the same as another")
	}
}
