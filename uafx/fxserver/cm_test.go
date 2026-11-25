// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// offlineDialer reaches no server: every run of the Manager fails.
type offlineDialer struct{}

func (offlineDialer) Dial(context.Context, fxcm.ServerAddress) (fxcm.Session, error) {
	return nil, errors.New("offline")
}

func ptrOf[T any](v T) *T { return &v }

// cmConf is a set with two ACs, one multicast flow and one Connection.
func cmConf(name string) *uafx.ConnectionConfigurationSetConf {
	srv := func(n, addr string) *uafx.ServerAddressConf {
		return &uafx.ServerAddressConf{BrowseName: n, Address: addr, SecurityMode: ua.MessageSecurityModeNone,
			SecurityModeSelection: []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSign},
			ServerURI:             "urn:" + n, Namespaces: []string{"http://opcfoundation.org/UA/", "urn:test:plc", fxacid.NamespaceURI}}
	}
	path := func(names ...string) *uafx.NodeIdentifier {
		rp := &ua.RelativePath{}
		for _, n := range names {
			rp.Elements = append(rp.Elements, &ua.RelativePathElement{
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true,
				TargetName: &ua.QualifiedName{NamespaceIndex: 1, Name: n}})
		}
		return &uafx.NodeIdentifier{IdentifierBrowsePath: rp}
	}
	pubsub := ua.NewNumericNodeID(2, fxacid.PubSubConnectionEndpointType)
	return &uafx.ConnectionConfigurationSetConf{
		BrowseName: name, ConnectionConfigurationSetFolder: []string{"Plant"},
		ServerAddresses: []*uafx.ServerAddressConf{srv("PLC1", "opc.tcp://127.0.0.1:1"), srv("PLC2", "opc.tcp://127.0.0.1:2")},
		AutomationComponentConfigurations: []*uafx.AutomationComponentConfigurationConf{
			{BrowseName: "AC1", AutomationComponentNode: path("AC1"), ServerAddressIndex: 0},
			{BrowseName: "AC2", AutomationComponentNode: path("AC2"), ServerAddressIndex: 1,
				AutomationComponentNodeSelection: []*uafx.NodeIdentifier{path("AC2"), path("AC2b")}},
		},
		CommunicationFlows: []uafx.CommunicationFlowConfigurationConf{
			&uafx.PubSubCommunicationFlowConfigurationConf{
				BrowseName:                  "Flow1",
				Address:                     &uafx.AddressSelection{Address: ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "opc.udp://239.0.0.1:4840"})},
				PublishingInterval:          ptrOf(10.0),
				PublishingIntervalSelection: []float64{10, 20},
				SecurityMode:                ptrOf(ua.MessageSecurityModeNone),
				SubscriberConfigurations:    []*uafx.SubscriberConfigurationConf{{BrowseName: "Sub1", MessageReceiveTimeout: 100, MessageReceiveTimeoutModify: ptrOf(true)}},
			},
		},
		Connections: []*uafx.ConnectionConfigurationConf{{
			BrowseName: "C1",
			Endpoint1: &uafx.ConnectionEndpointConfigurationConf{
				FunctionalEntityNode: path("AC1", "FE1"), Name: "ToAC2", NameSelection: []string{"ToAC2", "Out"},
				ConnectionEndpointTypeID: pubsub, OutputVariableIDs: []*uafx.NodeIdentifier{path("Out1")},
				AutomationComponentIndex: 0, OutboundFlowIndex: ptrOf[int32](0),
			},
			Endpoint2: &uafx.ConnectionEndpointConfigurationConf{
				FunctionalEntityNode: path("AC2", "FE2"), Name: "FromAC1",
				ConnectionEndpointTypeID: pubsub, InputVariableIDs: []*uafx.NodeIdentifier{path("In1")},
				AutomationComponentIndex: 1, InboundFlowIndex: []int32{0, 0},
			},
		}},
	}
}

type cmFX struct {
	srv     *server.Server
	ns      fxserver.Namespaces
	m       *fxcm.Manager
	cm      *fxserver.ConnectionManager
	c       *opcua.Client
	noAdmin *atomic.Bool
	set     *ua.NodeID
}

func newCMFX(t *testing.T, opts fxserver.ConnectionManagerOptions, srvOpts ...server.Option) *cmFX {
	t.Helper()
	noAdmin := &atomic.Bool{}
	roles := func(tok ua.IdentityToken) []*ua.NodeID {
		out := server.DefaultRoleMapper(tok)
		if !noAdmin.Load() {
			out = append(out, fxserver.ConfigureAdmin())
		}
		return out
	}
	srv := newServer(t, append([]server.Option{server.WithRoleMapper(roles)}, srvOpts...)...)
	ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
	require.NoError(t, err)
	m, err := fxcm.New(fxcm.Options{Dialer: offlineDialer{}, ApplicationURI: "urn:test:cm", Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })
	_, err = m.Add(cmConf("Line1"))
	require.NoError(t, err)
	opts.Manager = m
	opts.Logger = slog.New(slog.DiscardHandler)
	cm, err := fxserver.EnableConnectionManager(srv, ns, opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cm.Close() })
	f := &cmFX{srv: srv, ns: ns, m: m, cm: cm, noAdmin: noAdmin}
	f.c = start(t, srv)
	f.set, _ = cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
	require.NotNil(t, f.set)
	return f
}

func (f *cmFX) client(t *testing.T, uri string, admin bool) *opcua.Client {
	t.Helper()
	ctx := context.Background()
	if !admin {
		f.noAdmin.Store(true)
		defer f.noAdmin.Store(false)
	}
	c, err := opcua.NewClient(fmt.Sprintf("opc.tcp://localhost:%d", f.srv.Port()), opcua.InsecureNoSecurity(), opcua.ApplicationURI(uri))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(ctx) })
	return c
}

// node is a node of the set Line1 by the suffix of its NodeId.
func (f *cmFX) node(suffix string) *ua.NodeID {
	return ua.NewStringNodeID(f.ns.CM, f.set.StringID()+suffix)
}

func (f *cmFX) read(t *testing.T, c *opcua.Client, n *ua.NodeID) *ua.DataValue {
	t.Helper()
	res, err := c.Read(context.Background(), &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: n, AttributeID: ua.AttributeIDValue}}})
	require.NoError(t, err)
	require.Len(t, res.Results, 1)
	return res.Results[0]
}

func (f *cmFX) value(t *testing.T, suffix string) any {
	t.Helper()
	dv := f.read(t, f.c, f.node(suffix))
	require.Equal(t, ua.StatusOK, dv.Status, suffix)
	return dv.Value.Value()
}

func (f *cmFX) write(t *testing.T, c *opcua.Client, n *ua.NodeID, v any) ua.StatusCode {
	t.Helper()
	res, err := c.Write(context.Background(), &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID: n, AttributeID: ua.AttributeIDValue,
		Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
	}}})
	require.NoError(t, err)
	return res.Results[0]
}

func (f *cmFX) edit(t *testing.T, c *opcua.Client, a uafx.FxEdit, sets ...*ua.NodeID) (ua.StatusCode, []ua.StatusCode) {
	t.Helper()
	sc, rs, err := uafx.EditConnectionConfigurationSets(context.Background(), c, a, sets)
	require.NoError(t, err)
	return sc, rs
}

func (f *cmFX) lockCall(t *testing.T, c *opcua.Client, name string) (int32, ua.StatusCode) {
	t.Helper()
	res, err := c.Call(context.Background(), &ua.CallMethodRequest{ObjectID: f.node(".Lock"), MethodID: f.node(".Lock." + name),
		InputArguments: lockArgs(name)})
	require.NoError(t, err)
	if res.StatusCode != ua.StatusOK {
		return 0, res.StatusCode
	}
	require.Len(t, res.OutputArguments, 1)
	return res.OutputArguments[0].Value().(int32), res.StatusCode
}

func lockArgs(name string) []*ua.Variant {
	if name == "InitLock" {
		return []*ua.Variant{ua.MustVariant("")}
	}
	return nil
}

// TestConnectionManagerNodes: the set is exposed below its Folder, Ready,
// Version 1, Edit FALSE and locked to the ConnectionManager (§6.8.2,
// F.1.3), with its SelectionLists (§6.8.1) and the members of the
// ConnectionManager (§6.7.2, §6.7.6).
func TestConnectionManagerNodes(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true})
	assert.Equal(t, "Ready", f.value(t, ".CurrentState").(*ua.LocalizedText).Text)
	assert.Equal(t, uint32(fxcmid.ConnectionConfigurationSetStateMachineTypeReady), f.value(t, ".CurrentState.Id").(*ua.NodeID).IntID())
	assert.Equal(t, uint32(1), f.value(t, ".Version"))
	assert.Equal(t, false, f.value(t, ".Edit"))
	assert.Equal(t, false, f.value(t, ".RollbackOnError"))
	assert.Equal(t, true, f.value(t, ".Lock.Locked"))
	assert.Equal(t, "CM", f.value(t, ".Lock.LockingUser"))
	cmID := ua.NewNumericNodeID(f.ns.CM, fxcmid.FxRootConnectionManager)
	assert.Equal(t, cmID.String(), f.value(t, ".Lock.LockingClient"))
	assert.Equal(t, 10.0, f.value(t, ".Flow[Flow1].PublishingInterval"))
	assert.Equal(t, []float64{10, 20}, f.value(t, ".Flow[Flow1].PublishingInterval.Selections"))
	assert.Equal(t, true, f.value(t, ".Flow[Flow1].PublishingInterval.RestrictToList"))
	assert.Equal(t, false, f.value(t, ".Flow[Flow1].Sub[Sub1].MessageReceiveTimeout.RestrictToList"))
	assert.Equal(t, int32(ua.MessageSecurityModeNone), f.value(t, ".Flow[Flow1].SecurityMode"))
	assert.Equal(t, "ToAC2", f.value(t, ".Conn[C1].Endpoint1.ConnectionEndpoint.Name"))
	assert.Equal(t, []float64{0}, f.value(t, ".Conn[C1].Endpoint1.ConnectionEndpoint.CleanupTimeout.Selections"))
	assert.Equal(t, ua.StatusGood, f.value(t, ".Conn[C1].ProcessingResult"))
	assert.Len(t, f.value(t, ".ConnectionsDiagnostics"), 1)
	// A client without the UAFX types reads Bad_DataTypeIdUnknown with
	// the body kept: read the value in the server.
	fe, ok := f.srv.Node(f.node(".Conn[C1].Endpoint1.FunctionalEntityNode")).Value().Value.Value().(*ua.ExtensionObject)
	require.True(t, ok)
	s, err := uafx.DecodeStructure(fe, uafx.NamespaceIndexes{Data: f.ns.Data, AC: f.ns.AC, CM: f.ns.CM})
	require.NoError(t, err)
	pn := s.(*uafx.PortableNodeIdentifier)
	require.NotNil(t, pn.IdentifierBrowsePath)
	assert.Equal(t, "urn:test:plc", pn.IdentifierBrowsePath.Elements[0].TargetName.NamespaceURI)
	assert.Equal(t, "FE1", pn.IdentifierBrowsePath.Elements[1].TargetName.Name)
	assert.Equal(t, "opc.tcp://127.0.0.1:1", f.value(t, ".ServerAddress[PLC1].Address"))

	// The ConnectionManager members.
	cmVal := func(sid string) any {
		dv := f.read(t, f.c, ua.NewStringNodeID(f.ns.CM, sid))
		require.Equal(t, ua.StatusOK, dv.Status, sid)
		return dv.Value.Value()
	}
	assert.Equal(t, false, cmVal("cm.AggregatedCurrentState"))
	assert.Equal(t, uint32(0), cmVal("cm.Diagnostics.EstablishCallCount"))
	assert.Equal(t, uint32(fxcm.DefaultMaxConnectionConfigurationSets), cmVal("cm.Capabilities.MaxConnectionConfigurationSets"))
	assert.Equal(t, false, cmVal("cm.Capabilities.MonitorsAllConnectionEndpoints"))

	// Browse: the set in its Folder, the Table 90 References.
	refs := browse(t, f.c, ua.NewStringNodeID(f.ns.CM, "cm.folder:Plant"), id.Organizes)
	require.Len(t, refs, 1)
	assert.Equal(t, "Line1", refs[0].BrowseName.Name)
	out := browse(t, f.c, f.node(".Conn[C1].Endpoint1"), 0)
	var outbound bool
	for _, r := range out {
		outbound = outbound || r.BrowseName.Name == "Flow1"
	}
	assert.True(t, outbound, "ToOutboundFlow")
	assert.NotEmpty(t, browse(t, f.c, f.node(".ServerAddress[PLC2]"), 0))
}

func browse(t *testing.T, c *opcua.Client, n *ua.NodeID, refType uint32) []*ua.ReferenceDescription {
	t.Helper()
	rt := ua.NewNumericNodeID(0, id.References)
	if refType != 0 {
		rt = ua.NewNumericNodeID(0, refType)
	}
	res, err := c.Browse(context.Background(), &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: n, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: rt, IncludeSubtypes: true,
		ResultMask: uint32(ua.BrowseResultMaskAll)}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
	return res.Results[0].References
}

// TestConnectionManagerEdit follows §6.7.4 through the Method: StartEditing
// gives the Lock to the session, writes follow RestrictToList, CommitUpdates
// makes Version 2 and gives the Lock back; another client is refused.
func TestConnectionManagerEdit(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true}, server.WithAuditing(true))
	other := f.client(t, "urn:test:other", true)
	pi := f.node(".Flow[Flow1].PublishingInterval")

	// Outside edit the set is locked to the ConnectionManager.
	assert.Equal(t, ua.StatusBadLocked, f.write(t, f.c, pi, 20.0))
	sc, rs := f.edit(t, f.c, uafx.CommitUpdates, f.set)
	assert.Equal(t, ua.StatusGood, sc, "Commit outside edit is ignored")
	assert.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)

	sc, rs = f.edit(t, f.c, uafx.StartEditing, f.set)
	require.Equal(t, ua.StatusGood, sc)
	require.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)
	assert.Equal(t, true, f.value(t, ".Edit"))
	assert.NotEqual(t, "CM", f.value(t, ".Lock.LockingUser"))
	assert.Greater(t, f.value(t, ".Lock.RemainingLockTime").(float64), 0.0)
	sc, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	assert.Equal(t, ua.StatusGood, sc, "StartEditing again by the owner")

	// Another client: InvalidState, its writes Locked.
	sc, rs = f.edit(t, other, uafx.StartEditing, f.set)
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadInvalidState}, rs)
	assert.Equal(t, ua.StatusBadLocked, f.write(t, other, pi, 20.0))
	_, rs = f.edit(t, other, uafx.CommitUpdates, f.set)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadInvalidState}, rs)

	// The owner: RestrictToList.
	assert.Equal(t, ua.StatusBadOutOfRange, f.write(t, f.c, pi, 30.0))
	assert.Equal(t, ua.StatusBadTypeMismatch, f.write(t, f.c, pi, "x"))
	require.Equal(t, ua.StatusOK, f.write(t, f.c, pi, 20.0))
	assert.Equal(t, 20.0, f.value(t, ".Flow[Flow1].PublishingInterval"))
	require.Equal(t, ua.StatusOK, f.write(t, f.c, f.node(".Flow[Flow1].Sub[Sub1].MessageReceiveTimeout"), 333.0), "Modify TRUE")
	require.Equal(t, ua.StatusOK, f.write(t, f.c, f.node(".Conn[C1].Endpoint1.ConnectionEndpoint.Name"), "Out"))
	assert.Equal(t, ua.StatusBadNotWritable, f.write(t, f.c, f.node(".Conn[C1].Endpoint1.ConnectionEndpoint.CleanupTimeout"), 5.0))
	require.Equal(t, ua.StatusOK, f.write(t, f.c, f.node(".ServerAddress[PLC1].SecurityMode"), int32(ua.MessageSecurityModeSign)))
	assert.Equal(t, uint32(1), f.value(t, ".Version"), "not committed yet")

	sc, rs = f.edit(t, f.c, uafx.CommitUpdates, f.set)
	require.Equal(t, ua.StatusGood, sc, "%v", rs)
	assert.Equal(t, uint32(2), f.value(t, ".Version"))
	assert.Equal(t, false, f.value(t, ".Edit"))
	assert.Equal(t, "CM", f.value(t, ".Lock.LockingUser"))
	cfg, _ := f.m.Config(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
	got := cfg.Conf()
	assert.Equal(t, 20.0, *got.CommunicationFlows[0].(*uafx.PubSubCommunicationFlowConfigurationConf).PublishingInterval)
	assert.Equal(t, "Out", got.Connections[0].Endpoint1.Name)
	assert.Equal(t, ua.MessageSecurityModeSign, got.ServerAddresses[0].SecurityMode)

	// Discard drops the edit.
	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	require.Equal(t, ua.StatusOK, f.write(t, f.c, pi, 10.0))
	sc, _ = f.edit(t, f.c, uafx.DiscardUpdates, f.set)
	require.Equal(t, ua.StatusGood, sc)
	assert.Equal(t, 20.0, f.value(t, ".Flow[Flow1].PublishingInterval"))
	assert.Equal(t, uint32(2), f.value(t, ".Version"))

	// Arguments.
	sc, rs = f.edit(t, f.c, uafx.StartEditing, ua.NewStringNodeID(f.ns.CM, "nope"), ua.NewNumericNodeID(0, id.Server), ua.NewTwoByteNodeID(0))
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadNodeIDUnknown, ua.StatusBadInvalidArgument, ua.StatusBadNodeIDInvalid}, rs)
	_, _, err := uafx.EditConnectionConfigurationSets(context.Background(), f.c, 7, []*ua.NodeID{f.set})
	assert.ErrorIs(t, err, ua.StatusBadInvalidArgument)
}

// TestConnectionManagerAccess: without ConfigureAdmin the calls are
// Bad_UserAccessDenied (Tables 81, 82, 85, 86); a CMAuthorizer decides
// instead when given.
func TestConnectionManagerAccess(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true})
	plain := f.client(t, "urn:test:plain", false)
	_, _, err := uafx.EditConnectionConfigurationSets(context.Background(), plain, uafx.StartEditing, []*ua.NodeID{f.set})
	assert.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, _, err = uafx.ProcessConnectionConfigurationSets(context.Background(), plain, uafx.ActionEnableConnections, []*ua.NodeID{f.set})
	assert.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	// Writes too.
	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	assert.Equal(t, ua.StatusBadUserAccessDenied, f.write(t, plain, f.node(".Flow[Flow1].PublishingInterval"), 20.0))

	var seen []fxserver.CMOperation
	g := newCMFX(t, fxserver.ConnectionManagerOptions{Authorizer: func(_ context.Context, r fxserver.CMRequest) ua.StatusCode {
		seen = append(seen, r.Operation)
		return ua.StatusBadUserAccessDenied
	}})
	_, _, err = uafx.EditConnectionConfigurationSets(context.Background(), g.c, uafx.StartEditing, []*ua.NodeID{g.set})
	assert.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	assert.Equal(t, []fxserver.CMOperation{fxserver.CMEdit}, seen)
	assert.Equal(t, "Edit", fxserver.CMEdit.String())
	assert.Equal(t, "CMOperation(99)", fxserver.CMOperation(99).String())

	// Not Editable: Bad_InvalidState.
	h := newCMFX(t, fxserver.ConnectionManagerOptions{})
	_, rs := h.edit(t, h.c, uafx.StartEditing, h.set)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadInvalidState}, rs)
}

// TestConnectionManagerProcess: Process starts a run and returns; the set
// goes to Error as no server is reachable, with the events of §8.7 and §8.9
// and AggregatedCurrentState TRUE (§6.7.2).
func TestConnectionManagerProcess(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true})
	events := watchEvents(t, f.c, ua.NewNumericNodeID(f.ns.CM, fxcmid.FxRootConnectionManager),
		"EventType", "SourceNode", "ConnectionConfigurationSetNode", "Name", "Action")

	_, _, err := uafx.ProcessConnectionConfigurationSets(context.Background(), f.c, 99, []*ua.NodeID{f.set})
	assert.ErrorIs(t, err, ua.StatusBadNotSupported)

	sc, rs, err := uafx.ProcessConnectionConfigurationSets(context.Background(), f.c, uafx.ActionEstablishConnections,
		[]*ua.NodeID{f.set, ua.NewStringNodeID(f.ns.CM, "nope")})
	require.NoError(t, err)
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Equal(t, ua.StatusGood, rs[0])
	assert.Equal(t, ua.StatusBadNodeIDUnknown, rs[1])

	started := nextEvent(t, events, ua.NewNumericNodeID(f.ns.CM, fxcmid.ConnectionConfigurationSetProcessingStartedEventType))
	assert.Equal(t, f.set.String(), started[2].Value().(*ua.NodeID).String())
	assert.Equal(t, "Line1", started[3].Value())
	assert.Equal(t, int32(uafx.ActionEstablishConnections), started[4].Value())
	nextEvent(t, events, ua.NewNumericNodeID(f.ns.CM, fxcmid.ConnectionConfigurationSetProcessingFailedEventType))
	require.Eventually(t, func() bool {
		return f.read(t, f.c, f.node(".CurrentState")).Value.Value().(*ua.LocalizedText).Text == "Error"
	}, 10*time.Second, 10*time.Millisecond)
	assert.Equal(t, uint32(fxcmid.ConnectionConfigurationSetStateMachineTypeProcessingToError), f.value(t, ".LastTransition.Id").(*ua.NodeID).IntID())
	assert.Equal(t, true, f.read(t, f.c, ua.NewStringNodeID(f.ns.CM, "cm.AggregatedCurrentState")).Value.Value())
	assert.NotEqual(t, ua.StatusGood, f.value(t, ".Conn[C1].ProcessingResult"))
}

// TestConnectionManagerLock: the Lock of a set in edit (§6.7.4, OPC
// 10000-100 §7): InitLock is refused, RenewLock and ExitLock are the
// owner's, BreakLock the authorized client's; an expired Lock or the end of
// the session discards the edit.
func TestConnectionManagerLock(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true, MaxInactiveLockTime: time.Minute})
	other := f.client(t, "urn:test:other", true)
	plain := f.client(t, "urn:test:plain", false)
	st, _ := f.lockCall(t, f.c, "InitLock")
	assert.Equal(t, int32(-1), st)
	st, _ = f.lockCall(t, f.c, "RenewLock")
	assert.Equal(t, int32(-1), st, "not in edit")
	st, _ = f.lockCall(t, f.c, "BreakLock")
	assert.Equal(t, int32(-1), st, "the Lock of the ConnectionManager")

	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	st, _ = f.lockCall(t, f.c, "RenewLock")
	assert.Equal(t, int32(0), st)
	st, _ = f.lockCall(t, other, "RenewLock")
	assert.Equal(t, int32(-1), st)
	st, _ = f.lockCall(t, other, "ExitLock")
	assert.Equal(t, int32(-1), st)
	_, sc := f.lockCall(t, plain, "BreakLock")
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	st, _ = f.lockCall(t, f.c, "ExitLock")
	assert.Equal(t, int32(0), st)
	assert.Equal(t, false, f.value(t, ".Edit"))

	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	st, _ = f.lockCall(t, other, "BreakLock")
	assert.Equal(t, int32(0), st)
	assert.Equal(t, false, f.value(t, ".Edit"))

	// Expiry.
	// The clock is read by the loop of the ConnectionManager too.
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	fxserver.SetCMClock(f.cm, func() time.Time { return time.Unix(0, now.Load()) })
	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	now.Add(int64(30 * time.Second))
	fxserver.TickCMLocks(f.cm)
	assert.Equal(t, true, f.value(t, ".Edit"))
	now.Add(int64(31 * time.Second))
	fxserver.TickCMLocks(f.cm)
	assert.Equal(t, false, f.value(t, ".Edit"))

	// Expiry between two ticks: a write and a commit after the deadline
	// find the Lock gone, without waiting for the loop.
	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	now.Add(int64(61 * time.Second))
	assert.Equal(t, ua.StatusBadLocked, f.write(t, f.c, f.node(".Flow[Flow1].PublishingInterval"), 20.0))
	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	now.Add(int64(61 * time.Second))
	_, rs := f.edit(t, f.c, uafx.CommitUpdates, f.set)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadInvalidState}, rs)
	assert.Equal(t, false, f.value(t, ".Edit"))
	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	now.Add(int64(61 * time.Second))
	st, _ = f.lockCall(t, f.c, "RenewLock")
	assert.Equal(t, int32(-1), st, "an expired Lock is not renewed")

	// The end of the session.
	c := f.client(t, "urn:test:gone", true)
	_, _ = f.edit(t, c, uafx.StartEditing, f.set)
	assert.Equal(t, true, f.value(t, ".Edit"))
	require.NoError(t, c.Close(context.Background()))
	require.Eventually(t, func() bool {
		return f.read(t, f.c, f.node(".Edit")).Value.Value() == false
	}, 10*time.Second, 10*time.Millisecond)
	fxserver.CMSessionEnded(f.cm, nil)
}

// TestConnectionManagerFile: ConnectionManagerConfiguration (F.3): read
// the sets, write a file and apply it with CloseAndUpdate.
func TestConnectionManagerFile(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{File: true})
	file := ua.NewStringNodeID(f.ns.CM, "cm.File")
	m := func(name string) *ua.NodeID { return ua.NewStringNodeID(f.ns.CM, "cm.File."+name) }
	call := func(c *opcua.Client, name string, args ...any) ([]*ua.Variant, ua.StatusCode) {
		t.Helper()
		in := make([]*ua.Variant, len(args))
		for i, a := range args {
			in[i] = ua.MustVariant(a)
		}
		res, err := c.Call(context.Background(), &ua.CallMethodRequest{ObjectID: file, MethodID: m(name), InputArguments: in})
		require.NoError(t, err)
		return res.OutputArguments, res.StatusCode
	}
	_, sc := call(f.c, "Open", uint8(0x02))
	assert.Equal(t, ua.StatusBadInvalidArgument, sc, "F.3.2: Read or Write+EraseExisting only")

	out, sc := call(f.c, "Open", uint8(0x01))
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)
	_, sc = call(f.c, "Open", uint8(0x06))
	assert.Equal(t, ua.StatusBadInvalidState, sc, "no writer beside a reader")
	var data []byte
	for {
		out, sc = call(f.c, "Read", h, int32(64))
		require.Equal(t, ua.StatusOK, sc)
		b, _ := out[0].Value().([]byte)
		if len(b) == 0 {
			break
		}
		data = append(data, b...)
	}
	out, sc = call(f.c, "GetPosition", h)
	require.Equal(t, ua.StatusOK, sc)
	assert.Equal(t, uint64(len(data)), out[0].Value())
	_, sc = call(f.c, "SetPosition", h, uint64(0))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = call(f.c, "Close", h)
	require.Equal(t, ua.StatusOK, sc)
	sets, err := fxcm.DecodeFile(data)
	require.NoError(t, err)
	require.Len(t, sets, 1)
	assert.Equal(t, "Line1", sets[0].BrowseName)

	// Write two sets: add Line2, replace Line1.
	body, err := fxcm.EncodeFile([]*uafx.ConnectionConfigurationSetConf{cmConf("Line2"), cmConf("Line1")})
	require.NoError(t, err)
	out, sc = call(f.c, "Open", uint8(0x06))
	require.Equal(t, ua.StatusOK, sc)
	h = out[0].Value().(uint32)
	_, sc = call(f.c, "Read", h, int32(1))
	assert.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = call(f.c, "Write", h, body)
	require.Equal(t, ua.StatusOK, sc)
	// Operations is an array of Byte (Table F.39).
	ops := ua.ByteArray{byte(uafx.ElementAdd), byte(uafx.ElementReplace)}
	out, sc = call(f.c, "CloseAndUpdate", h, true, ops)
	require.Equal(t, ua.StatusOK, sc)
	assert.Equal(t, true, out[0].Value())
	assert.Equal(t, []ua.StatusCode{ua.StatusGood, ua.StatusGood}, out[1].Value())
	objs := out[2].Value().([]*ua.NodeID)
	n2, ok := f.cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line2"})
	require.True(t, ok)
	assert.Equal(t, n2.String(), objs[0].String())
	assert.Equal(t, f.set.String(), objs[1].String(), "a replaced set keeps its NodeId")
	_, sc = call(f.c, "Close", h)
	assert.Equal(t, ua.StatusBadInvalidArgument, sc, "CloseAndUpdate closed the handle")

	// An empty file, a mismatch of operations, a reader handle.
	empty, err := fxcm.EncodeFile(nil)
	require.NoError(t, err)
	out, _ = call(f.c, "Open", uint8(0x06))
	h = out[0].Value().(uint32)
	_, _ = call(f.c, "Write", h, empty)
	_, sc = call(f.c, "CloseAndUpdate", h, false, []byte{})
	assert.Equal(t, ua.StatusBadNothingToDo, sc)
	out, _ = call(f.c, "Open", uint8(0x06))
	h = out[0].Value().(uint32)
	_, _ = call(f.c, "Write", h, body)
	_, sc = call(f.c, "CloseAndUpdate", h, false, []byte{1})
	assert.Equal(t, ua.StatusBadInvalidArgument, sc)
	out, _ = call(f.c, "Open", uint8(0x01))
	h = out[0].Value().(uint32)
	_, sc = call(f.c, "CloseAndUpdate", h, false, []byte{1})
	assert.Equal(t, ua.StatusBadInvalidState, sc)
	_, sc = call(f.c, "Write", h, []byte{1})
	assert.Equal(t, ua.StatusBadInvalidState, sc)

	_, sc = call(f.c, "Close", h)
	require.Equal(t, ua.StatusOK, sc)

	// RequireCompleteUpdate FALSE: one of two applied is ChangesApplied
	// TRUE (F.3.3 Table F.39).
	partial, err := fxcm.EncodeFile([]*uafx.ConnectionConfigurationSetConf{cmConf("Line3"), cmConf("Line2")})
	require.NoError(t, err)
	out, _ = call(f.c, "Open", uint8(0x06))
	h = out[0].Value().(uint32)
	_, _ = call(f.c, "Write", h, partial)
	out, sc = call(f.c, "CloseAndUpdate", h, false, []byte{byte(uafx.ElementAdd), byte(uafx.ElementAdd)})
	require.Equal(t, ua.StatusOK, sc)
	assert.Equal(t, true, out[0].Value(), "one set applied")
	rs := out[1].Value().([]ua.StatusCode)
	assert.Equal(t, ua.StatusGood, rs[0])
	assert.NotEqual(t, ua.StatusGood, rs[1], "Line2 exists")

	// The handles of a session end with it (OPC 10000-20 §4.2.1): its
	// writer no longer blocks another.
	gone := f.client(t, "urn:test:gone", true)
	out, sc = call(gone, "Open", uint8(0x06))
	require.Equal(t, ua.StatusOK, sc)
	_, sc = call(f.c, "Open", uint8(0x06))
	assert.Equal(t, ua.StatusBadInvalidState, sc)
	require.NoError(t, gone.Close(context.Background()))
	require.Eventually(t, func() bool {
		out, sc = call(f.c, "Open", uint8(0x06))
		return sc == ua.StatusOK
	}, 10*time.Second, 10*time.Millisecond)
	_, sc = call(f.c, "Close", out[0].Value().(uint32))
	require.Equal(t, ua.StatusOK, sc)

	// Writing needs ConfigureAdmin.
	plain := f.client(t, "urn:test:plain", false)
	_, sc = call(plain, "Open", uint8(0x06))
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
}

// TestConnectionManagerFollowsManager: sets added, replaced and removed
// through the Go API appear and go; a commit that changes the structure
// rebuilds the nodes.
func TestConnectionManagerFollowsManager(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true})
	_, err := f.m.Add(cmConf("Line3"))
	require.NoError(t, err)
	f.cm.Flush()
	k3 := fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line3"}
	n3, ok := f.cm.SetNode(k3)
	require.True(t, ok)
	e, err := f.m.StartEdit(k3, "go")
	require.NoError(t, err)
	// A flow Variable goes: the structure changes, the nodes are rebuilt.
	e.Conf().CommunicationFlows[0].(*uafx.PubSubCommunicationFlowConfigurationConf).SecurityMode = nil
	e.Conf().Connections[0].Endpoint1.Name = "Out"
	_, _, err = f.m.CommitEdit(k3, "go")
	require.NoError(t, err)
	f.cm.Flush()
	dv := f.read(t, f.c, ua.NewStringNodeID(f.ns.CM, n3.StringID()+".Conn[C1].Endpoint1.ConnectionEndpoint.Name"))
	require.Equal(t, ua.StatusOK, dv.Status)
	assert.Equal(t, "Out", dv.Value.Value())
	assert.Equal(t, ua.StatusBadNodeIDUnknown, f.read(t, f.c, ua.NewStringNodeID(f.ns.CM, n3.StringID()+".Flow[Flow1].SecurityMode")).Status)
	n3b, _ := f.cm.SetNode(k3)
	assert.Equal(t, n3.String(), n3b.String(), "the NodeId stays")
	require.NoError(t, f.m.Remove(context.Background(), k3))
	f.cm.Flush()
	_, ok = f.cm.SetNode(k3)
	assert.False(t, ok)
	assert.Equal(t, ua.StatusBadNodeIDUnknown, f.read(t, f.c, n3).Status)
	require.NoError(t, f.cm.Close())
	require.NoError(t, f.cm.Close())
	_, _, err = uafx.EditConnectionConfigurationSets(context.Background(), f.c, uafx.StartEditing, []*ua.NodeID{f.set})
	assert.ErrorIs(t, err, ua.StatusBadShutdown)
}

// TestConnectionManagerNodeIDs: the names in the String NodeIds are
// escaped, so a set "Line1.Version" is not the Version of Line1 and a
// Folder "a/b" is not the Folders a and b.
func TestConnectionManagerNodeIDs(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{})
	dotted := cmConf("Line1.Version")
	_, err := f.m.Add(dotted)
	require.NoError(t, err)
	slash := cmConf("S")
	slash.ConnectionConfigurationSetFolder = []string{"a/b"}
	_, err = f.m.Add(slash)
	require.NoError(t, err)
	nested := cmConf("S")
	nested.ConnectionConfigurationSetFolder = []string{"a", "b"}
	_, err = f.m.Add(nested)
	require.NoError(t, err)
	f.cm.Flush()

	n1, ok := f.cm.SetNode(fxcm.KeyOf(dotted))
	require.True(t, ok)
	assert.NotEqual(t, f.node(".Version").String(), n1.String())
	assert.Equal(t, uint32(1), f.value(t, ".Version"), "Line1's Version is still a Variable")
	n2, ok := f.cm.SetNode(fxcm.KeyOf(slash))
	require.True(t, ok)
	n3, ok := f.cm.SetNode(fxcm.KeyOf(nested))
	require.True(t, ok)
	assert.NotEqual(t, n2.String(), n3.String())
	for _, n := range []*ua.NodeID{n1, n2, n3} {
		dv := f.read(t, f.c, n)
		assert.Equal(t, ua.StatusBadAttributeIDInvalid, dv.Status, "%v is an Object", n)
	}
}

// TestConnectionManagerFlowIndex: a Replace that moves an endpoint from
// flow 0 to flow 1 moves its ToOutboundFlow and ToInboundFlow References;
// the set keeps its NodeId.
func TestConnectionManagerFlowIndex(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{})
	two := func(out, in int32) *uafx.ConnectionConfigurationSetConf {
		conf := cmConf("Line1")
		second := *conf.CommunicationFlows[0].(*uafx.PubSubCommunicationFlowConfigurationConf)
		second.BrowseName = "Flow2"
		conf.CommunicationFlows = append(conf.CommunicationFlows, &second)
		conf.Connections[0].Endpoint1.OutboundFlowIndex = ptrOf(out)
		conf.Connections[0].Endpoint2.InboundFlowIndex = []int32{in, 0}
		return conf
	}
	target := func(endpoint string, ref uint32) string {
		t.Helper()
		var out []string
		for _, r := range browse(t, f.c, f.node(".Conn[C1]."+endpoint), 0) {
			if r.ReferenceTypeID.Equal(ua.NewNumericNodeID(f.ns.CM, ref)) {
				out = append(out, r.NodeID.NodeID.String())
			}
		}
		require.Len(t, out, 1, endpoint)
		return out[0]
	}
	_, err := f.m.Replace(context.Background(), two(0, 0))
	require.NoError(t, err)
	f.cm.Flush()
	assert.Equal(t, f.node(".Flow[Flow1]").String(), target("Endpoint1", fxcmid.ToOutboundFlow))
	assert.Equal(t, f.node(".Flow[Flow1]").String(), target("Endpoint2", fxcmid.ToInboundFlow))

	// Only the outbound index changes (the shape once had only whether it
	// was set), then the inbound one.
	_, err = f.m.Replace(context.Background(), two(1, 0))
	require.NoError(t, err)
	f.cm.Flush()
	assert.Equal(t, f.node(".Flow[Flow2]").String(), target("Endpoint1", fxcmid.ToOutboundFlow))
	assert.Equal(t, f.node(".Flow[Flow1]").String(), target("Endpoint2", fxcmid.ToInboundFlow))
	_, err = f.m.Replace(context.Background(), two(1, 1))
	require.NoError(t, err)
	f.cm.Flush()
	n, ok := f.cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
	require.True(t, ok)
	assert.Equal(t, f.set.String(), n.String(), "the set keeps its NodeId")
	assert.Equal(t, f.node(".Flow[Flow2]").String(), target("Endpoint1", fxcmid.ToOutboundFlow))
	assert.Equal(t, f.node(".Flow[Flow2]").String(), target("Endpoint2", fxcmid.ToInboundFlow))
}

// TestConnectionManagerAudit: with auditing, a call of a Method reports an
// AuditUpdateMethodResultEventType event and a write of a set an
// AuditUpdateConnectionConfigurationSetEventType event (§6.7.4, §8.5).
func TestConnectionManagerAudit(t *testing.T) {
	t.Parallel()
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true}, server.WithAuditing(true))
	events := watchEvents(t, f.c, ua.NewNumericNodeID(0, id.Server), "EventType", "SourceNode", "Status")
	_, _ = f.edit(t, f.c, uafx.StartEditing, f.set)
	call := nextEvent(t, events, ua.NewNumericNodeID(f.ns.Data, fxdataid.AuditUpdateMethodResultEventType))
	assert.Equal(t, ua.NewNumericNodeID(f.ns.CM, fxcmid.FxRootConnectionManager).String(), call[1].Value().(*ua.NodeID).String())
	assert.Equal(t, true, call[2].Value())
	pi := f.node(".Flow[Flow1].PublishingInterval")
	require.Equal(t, ua.StatusOK, f.write(t, f.c, pi, 20.0))
	w := nextEvent(t, events, ua.NewNumericNodeID(f.ns.CM, fxcmid.AuditUpdateConnectionConfigurationSetEventType))
	assert.Equal(t, pi.String(), w[1].Value().(*ua.NodeID).String())
	assert.Equal(t, true, w[2].Value())

	// A call refused before it reaches a set is audited too (§6.7.4).
	_, _, err := uafx.EditConnectionConfigurationSets(context.Background(), f.c, 99, []*ua.NodeID{f.set})
	require.Error(t, err)
	call = nextEvent(t, events, ua.NewNumericNodeID(f.ns.Data, fxdataid.AuditUpdateMethodResultEventType))
	assert.Equal(t, false, call[2].Value())
	_, _, err = uafx.ProcessConnectionConfigurationSets(context.Background(), f.c, 99, []*ua.NodeID{f.set})
	require.Error(t, err)
	call = nextEvent(t, events, ua.NewNumericNodeID(f.ns.Data, fxdataid.AuditUpdateMethodResultEventType))
	assert.Equal(t, false, call[2].Value())
}

// TestEnableConnectionManagerErrors: the model and the Manager are needed.
func TestEnableConnectionManagerErrors(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	_, err := fxserver.EnableConnectionManager(srv, fxserver.Namespaces{}, fxserver.ConnectionManagerOptions{})
	assert.ErrorIs(t, err, fxserver.ErrConnectionManager)
	ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
	require.NoError(t, err)
	_, err = fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{})
	assert.ErrorIs(t, err, fxserver.ErrConnectionManager)

	// A second ConnectionManager on the server finds its nodes taken.
	f := newCMFX(t, fxserver.ConnectionManagerOptions{Editable: true})
	_, err = fxserver.EnableConnectionManager(f.srv, f.ns, fxserver.ConnectionManagerOptions{Manager: f.m})
	require.ErrorIs(t, err, fxserver.ErrConnectionManager)
	_, ok := f.cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
	assert.True(t, ok, "the failed second one leaves the first one's nodes")

	// Without the DI namespace a set has no Lock: it is not exposed.
	srv2 := newServer(t)
	ns2, err := fxserver.AddModel(srv2, fxserver.ModelCM)
	require.NoError(t, err)
	ns2.DI = 0
	cm, err := fxserver.EnableConnectionManager(srv2, ns2, fxserver.ConnectionManagerOptions{Manager: f.m, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = cm.Close() })
	_, ok = cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
	assert.False(t, ok)

	for o, s := range map[fxserver.CMOperation]string{fxserver.CMEdit: "Edit", fxserver.CMProcess: "Process", fxserver.CMWrite: "Write",
		fxserver.CMFileWrite: "FileWrite", fxserver.CMBreakLock: "BreakLock", 99: "CMOperation(99)"} {
		assert.Equal(t, s, o.String())
	}
}

// watchEvents subscribes to the events of n with the fields paths.
func watchEvents(t *testing.T, c *opcua.Client, n *ua.NodeID, paths ...string) <-chan []*ua.Variant {
	t.Helper()
	b := ua.NewEventFilter().SelectPaths(paths...)
	sub, ch, err := c.NewSubscription().Interval(20*time.Millisecond).MonitorEvents(b.Build(), n).Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	out := make(chan []*ua.Variant, 64)
	done, exited := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(done); <-exited })
	go func() {
		defer close(exited)
		for {
			var msg *opcua.PublishNotificationData
			select {
			case msg = <-ch:
			case <-done:
				return
			}
			if msg == nil {
				return
			}
			if enl, ok := msg.Value.(*ua.EventNotificationList); ok {
				for _, e := range enl.Events {
					select {
					case out <- e.EventFields:
					default:
					}
				}
			}
		}
	}()
	return out
}

func nextEvent(t *testing.T, ch <-chan []*ua.Variant, typ *ua.NodeID) []*ua.Variant {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-ch:
			if n, ok := e[0].Value().(*ua.NodeID); ok && n.String() == typ.String() {
				return e
			}
		case <-deadline:
			t.Fatalf("no event %v", typ)
		}
	}
}
