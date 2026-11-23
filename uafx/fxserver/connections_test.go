// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// The NodeIds of fxtest.ConnectionsNodeSet.
const (
	ctlID      = fxtest.ConnCtl
	ctlHealth  = fxtest.ConnCtlHealth
	pumpID     = fxtest.ConnPump
	motionID   = fxtest.ConnMotion
	motionOH   = fxtest.ConnMotionOH
	setpointID = fxtest.ConnSetpoint
	limitID    = fxtest.ConnLimit
	actualID   = fxtest.ConnActual
	gainID     = fxtest.ConnGain
	fixedID    = fxtest.ConnFixed
	tableID    = fxtest.ConnTable
	groupID    = fxtest.ConnGroup
	notGroupID = fxtest.ConnNotAGroup
	axisID     = fxtest.ConnAxis
	axisInID   = fxtest.ConnAxisIn
	presetID   = fxtest.ConnPreset
	peerID     = fxtest.ConnPeer
	remoteID   = fxtest.ConnRemote
)

// fx is a server with the connection Methods and a client connected to it.
type fx struct {
	srv   *server.Server
	c     *opcua.Client
	conns *fxserver.Connections
	ns    fxserver.Namespaces
	test  uint16 // index of connNS
	udp   string // a free opc.udp URL on the loopback
}

func (f *fx) id(n uint32) *ua.NodeID { return ua.NewNumericNodeID(f.test, n) }

func newFX(t *testing.T, opts fxserver.ConnectionOptions, srvOpts ...server.Option) *fx {
	t.Helper()
	srv := newServer(t, append([]server.Option{server.WithPubSub(nil)}, srvOpts...)...)
	ns, test, err := fxtest.PrepareConnections(srv)
	require.NoError(t, err)
	f := &fx{srv: srv, ns: ns, test: test, udp: fmt.Sprintf("opc.udp://127.0.0.1:%d", testport.UDP(t))}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Interval == 0 {
		opts.Interval = 10 * time.Millisecond
	}
	f.conns, err = fxserver.EnableConnections(srv, ns, opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.conns.Close() })
	f.c = start(t, srv)
	return f
}

func setValue(t *testing.T, srv *server.Server, n *ua.NodeID, v any) {
	t.Helper()
	node := srv.Node(n)
	require.NotNil(t, node, n)
	require.NoError(t, node.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(v)))
}

// isNull reports whether n is nil or the null NodeId, which a nil NodeId
// becomes on the wire.
func isNull(n *ua.NodeID) bool {
	return n == nil || n.Namespace() == 0 && n.IntID() == 0 && n.StringID() == ""
}

func sameNode(a, b *ua.NodeID) bool { return a != nil && b != nil && a.String() == b.String() }

func (f *fx) value(t *testing.T, n uint32) any {
	t.Helper()
	dv := f.srv.Node(f.id(n)).Value()
	require.NotNil(t, dv)
	return dv.Value.Value()
}

// The PubSub configuration of a loopback connection of Motion: the writer
// publishes Actual, the reader writes what it receives to Setpoint.
const (
	pubConn, subConn = "Pub", "Sub"
	wgName, rgName   = "WG", "RG"
	writerName       = "W"
	readerName       = "R"
	pdsName          = "PDS"
)

var md = pubsub.MetaData("m", pubsub.Field{Name: "x", Type: ua.TypeIDDouble})

func (f *fx) pubsubConfig(version uint32) *ua.PubSubConfiguration2DataType {
	pds := pubsub.PublishedDataItems(pdsName, pubsub.Var("x", f.id(actualID), ua.TypeIDDouble))
	pds.DataSetMetaData.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: version, MinorVersion: version}
	w := pubsub.DataSetWriter(writerName, 11, pdsName)
	w.Enabled = false
	wg := pubsub.WriterGroup(wgName, 10, 10*time.Millisecond, w)
	m := *md
	m.ConfigurationVersion = &ua.ConfigurationVersionDataType{MajorVersion: version, MinorVersion: version}
	r := pubsub.SetTargetVariables(pubsub.DataSetReader(readerName, uint16(77), 10, 11, &m), pubsub.Target(f.id(setpointID)))
	r.Enabled = false
	return &ua.PubSubConfiguration2DataType{
		PublishedDataSets: []*ua.PublishedDataSetDataType{pds},
		Connections: []*ua.PubSubConnectionDataType{
			pubsub.AttachWriterGroups(pubsub.UDPConnection(pubConn, f.udp, uint16(77)), wg),
			pubsub.AttachReaderGroups(pubsub.UDPConnection(subConn, f.udp, nil), pubsub.ReaderGroup(rgName, r)),
		},
		Enabled: true,
	}
}

func ref(mask ua.PubSubConfigurationRefMask, conn, group, elem uint16) *ua.PubSubConfigurationRefDataType {
	return &ua.PubSubConfigurationRefDataType{ConfigurationMask: mask, ConnectionIndex: conn, GroupIndex: group, ElementIndex: elem}
}

const (
	refAdd    = ua.PubSubConfigurationRefMaskElementAdd
	refConn   = ua.PubSubConfigurationRefMaskReferenceConnection
	refPDS    = ua.PubSubConfigurationRefMaskReferencePubDataset
	refWG     = ua.PubSubConfigurationRefMaskReferenceWriterGroup
	refRG     = ua.PubSubConfigurationRefMaskReferenceReaderGroup
	refWriter = ua.PubSubConfigurationRefMaskReferenceWriter
	refReader = ua.PubSubConfigurationRefMaskReferenceReader
)

// addAll are the references that add all of pubsubConfig.
var addAll = []*ua.PubSubConfigurationRefDataType{
	ref(refAdd|refPDS, 0, 0, 0),
	ref(refAdd|refConn, 0, 0, 0), ref(refAdd|refConn, 1, 0, 0),
	ref(refAdd|refWG, 0, 0, 0), ref(refAdd|refRG, 1, 0, 0),
	ref(refAdd|refWriter, 0, 0, 0), ref(refAdd|refReader, 1, 0, 0),
}

// endpointParam is a PublisherSubscriber endpoint of Motion.
func (f *fx) endpointParam(name string) *uafx.PubSubConnectionEndpointParameter {
	return &uafx.PubSubConnectionEndpointParameter{
		Name:                     name,
		ConnectionEndpointTypeID: ua.NewNumericNodeID(f.ns.AC, fxacid.PubSubConnectionEndpointType),
		InputVariableIDs:         []*ua.NodeID{f.id(setpointID)},
		OutputVariableIDs:        []*ua.NodeID{f.id(actualID)},
		CleanupTimeout:           -1,
		RelatedEndpoint:          &uafx.RelatedEndpoint{Address: "opc.tcp://peer:4840", ConnectionEndpointName: "FromMotion"},
		Mode:                     uafx.PubSubPublisherSubscriber,
	}
}

// fullRequest establishes a PublisherSubscriber endpoint name of Motion
// with all commands but VerifyAsset and the control commands.
func (f *fx) fullRequest(name string) *uafx.EstablishConnectionsRequest {
	return &uafx.EstablishConnectionsRequest{
		CommandMask: uafx.VerifyFunctionalEntityCmd | uafx.CreateConnectionEndpointCmd | uafx.SetConfigurationDataCmd |
			uafx.SetCommunicationConfigurationCmd | uafx.EnableCommunicationCmd | uafx.ReserveCommunicationIDsCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
			FunctionalEntityNode:          f.id(motionID),
			ConnectionEndpoint:            &uafx.ConnectionEndpointDefinition{Parameter: f.endpointParam(name)},
			ExpectedVerificationVariables: []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: f.id(fixedID)}, Value: ua.MustVariant(7.0)}},
			ConfigurationData:             []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: f.id(gainID)}, Value: ua.MustVariant(2.5)}},
			CommunicationLinks: &uafx.PubSubCommunicationLinkConfiguration{
				DataSetReaderRef: ref(refReader, 1, 0, 0),
				DataSetWriterRef: ref(refWriter, 0, 0, 0),
			},
		}},
		ReserveCommunicationIDs: []*uafx.PubSubReserveCommunicationIDs{{
			TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp", NumReqWriterGroupIDs: 1, NumReqDataSetWriterIDs: 1, RequestTransportSpecificInfo: true,
		}},
		CommunicationConfigurations: []*uafx.PubSubCommunicationConfiguration{{
			PubSubConfiguration: f.pubsubConfig(0), ConfigurationReferences: addAll,
		}},
	}
}

func (f *fx) establish(t *testing.T, req *uafx.EstablishConnectionsRequest) *uafx.EstablishConnectionsResult {
	t.Helper()
	res, err := uafx.EstablishConnections(context.Background(), f.c, f.id(ctlID), req)
	require.NoError(t, err)
	return res
}

// TestConnectionsLifecycle is the acceptance test of Release B: a client
// establishes a non-persistent connection of a FunctionalEntity, data flows
// over PubSub, the Status and health follow, and CloseConnections disables
// and removes what the call created.
func TestConnectionsLifecycle(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	ctx := context.Background()

	res := f.establish(t, f.fullRequest("ToPeer"))
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	er := res.ConnectionEndpointConfigurationResults[0]
	require.Equal(t, ua.StatusOK, er.ConnectionEndpointResult)
	require.Equal(t, uafx.FunctionalEntityVerificationMatch, er.VerificationResult)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, er.ConfigurationDataResult)
	require.Equal(t, ua.StatusOK, er.CommunicationLinksResult)
	require.Equal(t, ua.StatusOK, er.EnableCommunicationResult)
	require.NotNil(t, er.ConnectionEndpointID)
	require.Equal(t, 2.5, f.value(t, gainID))
	require.Equal(t, ua.StatusOK, res.ReserveCommunicationIDsResults[0].Result)
	require.Equal(t, uint16(4840), res.ReserveCommunicationIDsResults[0].TransportSpecificInfo.Value())
	require.True(t, res.CommunicationConfigurationResults[0].ChangesApplied)

	// Data flows from Actual to Setpoint; the endpoint becomes Operational.
	ep := er.ConnectionEndpointID
	require.Eventually(t, func() bool { return f.value(t, setpointID) == 42.5 }, 5*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool {
		st, ok := f.conns.Status(ep)
		return ok && st == uafx.ConnectionEndpointOperational
	}, 5*time.Second, 5*time.Millisecond)

	// Close with Remove: the endpoint and the reader and writer go.
	sc, results, err := uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{ep}, true)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
	require.Nil(t, f.srv.Node(ep))
	rt := f.srv.PubSub()
	sub, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
	require.True(t, ok, "the connections stay")
	rg, ok := rt.Lookup(pubsub.KindReaderGroup, sub, rgName)
	require.True(t, ok, "the groups stay")
	_, ok = rt.Lookup(pubsub.KindDataSetReader, rg, readerName)
	require.False(t, ok, "the reader the call configured goes")
}
