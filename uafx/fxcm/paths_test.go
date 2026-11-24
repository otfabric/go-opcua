// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// capabilitiesNodeSet gives Ctl ComponentCapabilities with
// MaxConnectionsPerCall 1 and CommandBundleRequired (Part 81 §6.2.6).
const capabilitiesNodeSet = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>urn:go-opcua:fxserver:connections</Uri>
    <Uri>http://opcfoundation.org/UA/FX/Data/</Uri>
    <Uri>http://opcfoundation.org/UA/FX/AC/</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
    <Alias Alias="HasProperty">i=46</Alias>
    <Alias Alias="HasComponent">i=47</Alias>
  </Aliases>
  <UAObject NodeId="ns=1;i=1090" BrowseName="3:ComponentCapabilities">
    <DisplayName>ComponentCapabilities</DisplayName>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=58</Reference>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=1000</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=1091" BrowseName="3:MaxConnectionsPerCall" DataType="i=7">
    <DisplayName>MaxConnectionsPerCall</DisplayName>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=1090</Reference>
    </References>
    <Value><UInt32 xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">1</UInt32></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=1092" BrowseName="3:CommandBundleRequired" DataType="i=1">
    <DisplayName>CommandBundleRequired</DisplayName>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=1090</Reference>
    </References>
    <Value><Boolean xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">true</Boolean></Value>
  </UAVariable>
</UANodeSet>`

// The namespace indexes of the Namespaces of the ServerAddresses of
// pathsConf: another order than the servers have, so that every index is
// mapped (F.1.2.2).
const (
	pAC   = 1
	pData = 2
	pTest = 3
)

// bp is an IdentifierBrowsePath of HierarchicalReferences through names of
// the namespaces of pathsConf ("t:" test, "a:" AC).
func bp(names ...string) *uafx.NodeIdentifier {
	rp := &ua.RelativePath{}
	for _, n := range names {
		ns := uint16(pTest)
		if n[:2] == "a:" {
			ns = pAC
		}
		rp.Elements = append(rp.Elements, &ua.RelativePathElement{
			ReferenceTypeID: ua.NewNumericNodeID(0, 33), IncludeSubtypes: true,
			TargetName: &ua.QualifiedName{NamespaceIndex: ns, Name: n[2:]},
		})
	}
	return &uafx.NodeIdentifier{IdentifierBrowsePath: rp}
}

func pathsLinks(t *testing.T, writer, reader *ua.PubSubConfigurationRefDataType) *ua.ExtensionObject {
	t.Helper()
	eo, err := uafx.EncodeStructure(&uafx.PubSubCommunicationLinkConfiguration{DataSetReaderRef: reader, DataSetWriterRef: writer},
		uafx.NamespaceIndexes{Data: pData, AC: pAC})
	require.NoError(t, err)
	return eo
}

func linkRef(kind ua.PubSubConfigurationRefMask, conn uint16) *ua.PubSubConfigurationRefDataType {
	return &ua.PubSubConfigurationRefDataType{ConfigurationMask: kind, ConnectionIndex: conn}
}

// pathsModel is e2eModel in the namespaces of pathsConf. With axisOut the
// AC publishes Actual on a third PubSubConnection to axisOut, with axisIn
// it reads into AxisIn from a third PubSubConnection on axisIn.
func pathsModel(out, in, axisOut, axisIn string) *uafx.PubSubCommunicationModelConfiguration {
	m := e2eModel(out, in)
	cfg := m.PubSubConfiguration
	retarget := func(n *ua.NodeID) *ua.NodeID { return ua.NewNumericNodeID(pTest, n.IntID()) }
	items := cfg.PublishedDataSets[0].DataSetSource.Value.(*ua.PublishedDataItemsDataType)
	items.PublishedData[0].PublishedVariable = retarget(items.PublishedData[0].PublishedVariable)
	tv := cfg.Connections[1].ReaderGroups[0].DataSetReaders[0].SubscribedDataSet.Value.(*ua.TargetVariablesDataType)
	tv.TargetVariables[0].TargetNodeID = retarget(tv.TargetVariables[0].TargetNodeID)
	add := func(mask ua.PubSubConfigurationRefMask) {
		if mask&(ua.PubSubConfigurationRefMaskReferenceConnection|ua.PubSubConfigurationRefMaskReferenceReaderGroup) != 0 {
			mask |= ua.PubSubConfigurationRefMaskElementMatch
		}
		m.ConfigurationReferences = append(m.ConfigurationReferences, &ua.PubSubConfigurationRefDataType{
			ConfigurationMask: ua.PubSubConfigurationRefMaskElementAdd | mask, ConnectionIndex: 2,
		})
	}
	switch {
	case axisOut != "":
		w := pubsub.DataSetWriter("W2", 0, "PDS")
		cfg.Connections = append(cfg.Connections, pubsub.AttachWriterGroups(pubsub.UDPConnection("Pub2", axisOut, nil), pubsub.WriterGroup("", 0, 10*time.Millisecond, w)))
		add(ua.PubSubConfigurationRefMaskReferenceConnection)
		add(ua.PubSubConfigurationRefMaskReferenceWriterGroup)
		add(ua.PubSubConfigurationRefMaskReferenceWriter)
	case axisIn != "":
		md := pubsub.MetaData("m", pubsub.Field{Name: "x", Type: ua.TypeIDDouble})
		r := pubsub.SetTargetVariables(pubsub.DataSetReader("R2", nil, 0, 0, md), pubsub.Target(ua.NewNumericNodeID(pTest, fxtest.ConnAxisIn)))
		cfg.Connections = append(cfg.Connections, pubsub.AttachReaderGroups(pubsub.UDPConnection("Sub2", axisIn, nil), pubsub.ReaderGroup("RG2", r)))
		add(ua.PubSubConfigurationRefMaskReferenceConnection)
		add(ua.PubSubConfigurationRefMaskReferenceReaderGroup)
		add(ua.PubSubConfigurationRefMaskReferenceReader)
	}
	return m
}

// pathsConf is e2eConf with BrowsePaths from FxRoot and the
// FunctionalEntity, an AssetVerification, the verification of Motion, and
// a second Connection from Motion of a to Axis of b on its own flow.
func pathsConf(t *testing.T, a, b *ac) *uafx.ConnectionConfigurationSetConf {
	t.Helper()
	ab := fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))
	ba := fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))
	ax := fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))
	server := func(x *ac) *uafx.ServerAddressConf {
		return &uafx.ServerAddressConf{
			BrowseName: x.uri, Address: x.url, SecurityMode: ua.MessageSecurityModeNone, ServerURI: x.uri,
			Namespaces: []string{uaNamespace, fxacid.NamespaceURI, fxdataid.NamespaceURI, fxtest.ConnNS},
		}
	}
	motion := bp("t:Ctl", "a:FunctionalEntities", "t:Motion")
	endpoint := func(acIdx, out, in int32, name string) *uafx.ConnectionEndpointConfigurationConf {
		return &uafx.ConnectionEndpointConfigurationConf{
			FunctionalEntityNode:          motion,
			Name:                          name,
			ConnectionEndpointTypeID:      ua.NewNumericNodeID(pAC, fxacid.PubSubConnectionEndpointType),
			InputVariableIDs:              []*uafx.NodeIdentifier{bp("a:InputData", "t:Setpoint")},
			OutputVariableIDs:             []*uafx.NodeIdentifier{bp("a:OutputData", "t:Actual")},
			CleanupTimeout:                -1,
			CommunicationLinks:            pathsLinks(t, linkRef(ua.PubSubConfigurationRefMaskReferenceWriter, 0), linkRef(ua.PubSubConfigurationRefMaskReferenceReader, 1)),
			ExpectedVerificationVariables: []*uafx.NodeIdentifierValuePair{{Key: bp("a:ConfigurationData", "t:Fixed"), Value: ua.MustVariant(7.0)}},
			ConfigurationData:             []*uafx.NodeIdentifierValuePair{{Key: bp("a:ConfigurationData", "t:Gain"), Value: ua.MustVariant(3.5)}},
			AutomationComponentIndex:      acIdx,
			OutboundFlowIndex:             &out,
			InboundFlowIndex:              []int32{in, 0},
		}
	}
	return &uafx.ConnectionConfigurationSetConf{
		BrowseName:      "Paths",
		RollbackOnError: true,
		ServerAddresses: []*uafx.ServerAddressConf{server(a), server(b)},
		AutomationComponentConfigurations: []*uafx.AutomationComponentConfigurationConf{
			{
				BrowseName: "A", AutomationComponentNode: bp("t:Ctl"), ServerAddressIndex: 0, CommunicationModelConfig: pathsModel(ab, ba, ax, ""),
				AssetVerification: []*uafx.AssetVerificationConf{{
					AssetToVerify: bp("a:Assets", "t:Pump"), ExpectedVerificationResult: uafx.AssetVerificationMatch,
					// A Key is a BrowseName: the TargetName of a one-element
					// path, else the BrowseName of the node it resolves to.
					ExpectedVerificationVariables: []*uafx.NodeIdentifierValuePair{
						{Key: bp("t:SerialNumber"), Value: ua.MustVariant("S1")},
						{Key: &uafx.NodeIdentifier{Node: ua.NewNumericNodeID(pTest, 1010)}, Value: ua.MustVariant("Pump")},
					},
				}},
			},
			{BrowseName: "B", AutomationComponentNode: bp("t:Ctl"), ServerAddressIndex: 1, CommunicationModelConfig: pathsModel(ba, ab, "", ax)},
		},
		CommunicationFlows: []uafx.CommunicationFlowConfigurationConf{
			&uafx.PubSubCommunicationFlowConfigurationConf{
				BrowseName: "AB", Address: &uafx.AddressSelection{Address: urlAddress(ab)},
				SubscriberConfigurations: []*uafx.SubscriberConfigurationConf{{BrowseName: "S", MessageReceiveTimeout: 1000}},
			},
			&uafx.PubSubCommunicationFlowConfigurationConf{
				BrowseName: "BA", Address: &uafx.AddressSelection{Address: urlAddress(ba)},
				SubscriberConfigurations: []*uafx.SubscriberConfigurationConf{{BrowseName: "S", MessageReceiveTimeout: 1000}},
			},
			&uafx.PubSubCommunicationFlowConfigurationConf{
				BrowseName: "AX", Address: &uafx.AddressSelection{Address: urlAddress(ax)},
				SubscriberConfigurations: []*uafx.SubscriberConfigurationConf{{BrowseName: "S", MessageReceiveTimeout: 1000}},
			},
		},
		Connections: []*uafx.ConnectionConfigurationConf{
			{BrowseName: "Motion", Endpoint1: endpoint(0, 0, 1, "ToB"), Endpoint2: endpoint(1, 1, 0, "ToA")},
			{
				BrowseName: "Axis",
				Endpoint1: &uafx.ConnectionEndpointConfigurationConf{
					FunctionalEntityNode:     motion,
					Name:                     "ToAxis",
					ConnectionEndpointTypeID: ua.NewNumericNodeID(pAC, fxacid.PubSubConnectionEndpointType),
					OutputVariableIDs:        []*uafx.NodeIdentifier{bp("a:OutputData", "t:Actual")},
					CleanupTimeout:           -1,
					CommunicationLinks:       pathsLinks(t, linkRef(ua.PubSubConfigurationRefMaskReferenceWriter, 2), nil),
					AutomationComponentIndex: 0,
					OutboundFlowIndex:        ptr[int32](2),
				},
				Endpoint2: &uafx.ConnectionEndpointConfigurationConf{
					FunctionalEntityNode:     bp("t:Ctl", "a:FunctionalEntities", "t:Motion", "t:Axis"),
					Name:                     "FromA",
					ConnectionEndpointTypeID: ua.NewNumericNodeID(pAC, fxacid.PubSubConnectionEndpointType),
					InputVariableIDs:         []*uafx.NodeIdentifier{bp("a:InputData", "t:AxisIn")},
					CleanupTimeout:           -1,
					CommunicationLinks:       pathsLinks(t, nil, linkRef(ua.PubSubConfigurationRefMaskReferenceReader, 2)),
					AutomationComponentIndex: 1,
					InboundFlowIndex:         []int32{2, 0},
				},
			},
		},
	}
}

// TestEstablishPaths: the identifiers of a set are BrowsePaths in its own
// namespace indexes (EC-8, F.1.2.2); the asset and the FunctionalEntity
// are verified; b takes one endpoint per call and wants bundles (§6.2.6),
// so its two endpoints are configured in two calls (EC-5), the second
// inside the PubSubConnections the first added.
func TestEstablishPaths(t *testing.T) {
	t.Parallel()
	var (
		mu   sync.Mutex
		keys []*ua.QualifiedName
	)
	verifier := func(_ context.Context, _ *ua.NodeID, _ uafx.AssetVerificationMode, vars []*ua.KeyValuePair, _ []*uafx.NodeIDValuePair) (uafx.AssetVerificationResult, []ua.StatusCode, []ua.StatusCode, ua.StatusCode) {
		mu.Lock()
		defer mu.Unlock()
		for _, v := range vars {
			keys = append(keys, v.Key)
		}
		return uafx.AssetVerificationMatch, nil, nil, ua.StatusOK
	}
	a := newAC(t, "a", fxserver.ConnectionOptions{AssetVerifier: verifier})
	b := newACWith(t, "b", fxserver.ConnectionOptions{MaxConnectionsPerCall: 1, CommandBundleRequired: true}, capabilitiesNodeSet)
	require.NoError(t, fxtest.SetValue(b.srv, b.id(fxtest.ConnActual), 17.0))
	events := &eventLog{}
	m := newManager(t, Options{Observer: events, Logger: slog.New(slog.DiscardHandler)})
	cfg, err := m.Add(pathsConf(t, a, b))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, StateReady, res.State, "%+v", res.Failures)
	assert.Len(t, res.Created, 4)
	mu.Lock()
	assert.Equal(t, []*ua.QualifiedName{{NamespaceIndex: a.test, Name: "SerialNumber"}, {NamespaceIndex: a.test, Name: "Pump"}}, keys)
	mu.Unlock()
	assert.ElementsMatch(t, []string{"ToB", "ToAxis"}, a.endpoints())
	assert.ElementsMatch(t, []string{"ToA", "FromA"}, b.endpoints())
	assert.Equal(t, 3.5, b.value(t, fxtest.ConnGain))
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnSetpoint) == 42.5 }, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return b.value(t, fxtest.ConnAxisIn) == 42.5 }, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return a.value(t, fxtest.ConnSetpoint) == 17.0 }, 10*time.Second, 10*time.Millisecond)
	calls := map[string]int{}
	for _, e := range events.of(EventCall) {
		calls[e.Address]++
	}
	// a: reserve, configure; b: reserve, two configure calls.
	assert.Equal(t, 2, calls[a.url])
	assert.Equal(t, 3, calls[b.url])

	// A wrong verification value fails the FunctionalEntity (§6.2.4.3.3).
	conf := pathsConf(t, a, b)
	conf.BrowseName = "Wrong"
	conf.Connections = conf.Connections[:1]
	conf.Connections[0].Endpoint1.Name, conf.Connections[0].Endpoint2.Name = "W1", "W2"
	conf.Connections[0].Endpoint1.ExpectedVerificationVariables[0].Value = ua.MustVariant(8.0)
	cfg2, err := m.Add(conf)
	require.NoError(t, err)
	res = process(t, m, uafx.ActionEstablishConnectionsDisabled, cfg2.Key())
	require.Equal(t, StateError, res.State)
	// b, bundled, subscribes to a and is configured after it
	// (configureWaves): a's failure stops the run before b's call (EC-10).
	assert.Equal(t, []Failure{{FxError: uafx.FxErrorVerifyFunctionalEntityError, Status: ua.StatusBadNoMatch}}, res.Failures)
	assert.ElementsMatch(t, []string{"ToA", "FromA"}, b.endpoints())
}
