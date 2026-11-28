// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// callStatus returns the Bad status of a failed EstablishConnections call.
func (f *fx) callStatus(t *testing.T, req *uafx.EstablishConnectionsRequest) ua.StatusCode {
	t.Helper()
	_, err := uafx.EstablishConnections(context.Background(), f.c, f.id(ctlID), req)
	require.ErrorIs(t, err, uafx.ErrCall)
	var sc ua.StatusCode
	require.True(t, errors.As(err, &sc), "%v", err)
	return sc
}

func node(f *fx, n uint32) *uafx.ConnectionEndpointDefinition {
	return &uafx.ConnectionEndpointDefinition{Node: f.id(n)}
}

// TestEstablishArguments: arguments that do not match the commands fail the
// call (Part 81 Table 8, Table 9).
func TestEstablishArguments(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{MaxConnectionsPerCall: 2})
	full := func(mod func(r *uafx.EstablishConnectionsRequest)) *uafx.EstablishConnectionsRequest {
		r := f.fullRequest("X")
		mod(r)
		return r
	}
	e0 := func(r *uafx.EstablishConnectionsRequest) *uafx.ConnectionEndpointConfiguration {
		return r.ConnectionEndpointConfigurations[0]
	}
	for name, req := range map[string]*uafx.EstablishConnectionsRequest{
		"no command":      {},
		"unknown command": {CommandMask: 1 << 9},
		"asset no list":   {CommandMask: uafx.VerifyAssetCmd},
		"asset list alone": full(func(r *uafx.EstablishConnectionsRequest) {
			r.AssetVerifications = []*uafx.AssetVerification{{AssetToVerify: f.id(pumpID)}}
		}),
		"reserve no list": full(func(r *uafx.EstablishConnectionsRequest) { r.ReserveCommunicationIDs = nil }),
		"reserve alone": full(func(r *uafx.EstablishConnectionsRequest) {
			r.CommandMask &^= uafx.ReserveCommunicationIDsCmd
		}),
		"endpoint list alone": {CommandMask: uafx.ReserveCommunicationIDsCmd, ReserveCommunicationIDs: []*uafx.PubSubReserveCommunicationIDs{{}},
			ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{FunctionalEntityNode: f.id(motionID)}}},
		"no endpoint list": full(func(r *uafx.EstablishConnectionsRequest) { r.ConnectionEndpointConfigurations = nil }),
		"two comm configs": full(func(r *uafx.EstablishConnectionsRequest) {
			r.CommunicationConfigurations = append(r.CommunicationConfigurations, r.CommunicationConfigurations[0])
		}),
		"comm config alone": full(func(r *uafx.EstablishConnectionsRequest) {
			r.CommandMask &^= uafx.SetCommunicationConfigurationCmd
			e0(r).CommunicationLinks = nil
		}),
		"no verify values":   full(func(r *uafx.EstablishConnectionsRequest) { e0(r).ExpectedVerificationVariables = nil }),
		"verify values only": full(func(r *uafx.EstablishConnectionsRequest) { r.CommandMask &^= uafx.VerifyFunctionalEntityCmd }),
		"no config data":     full(func(r *uafx.EstablishConnectionsRequest) { e0(r).ConfigurationData = nil }),
		"config data only":   full(func(r *uafx.EstablishConnectionsRequest) { r.CommandMask &^= uafx.SetConfigurationDataCmd }),
		"no links":           full(func(r *uafx.EstablishConnectionsRequest) { e0(r).CommunicationLinks = nil }),
		"control no groups":  full(func(r *uafx.EstablishConnectionsRequest) { r.CommandMask |= uafx.EstablishControlCmd }),
		"groups no control":  full(func(r *uafx.EstablishConnectionsRequest) { e0(r).ControlGroups = []*ua.NodeID{f.id(groupID)} }),
		"create no param":    full(func(r *uafx.EstablishConnectionsRequest) { e0(r).ConnectionEndpoint = node(f, presetID) }),
		"param no create": full(func(r *uafx.EstablishConnectionsRequest) {
			r.CommandMask &^= uafx.CreateConnectionEndpointCmd
		}),
		"null endpoint": full(func(r *uafx.EstablishConnectionsRequest) { e0(r).ConnectionEndpoint = nil }),
		"null endpoint, verify only": {CommandMask: uafx.VerifyFunctionalEntityCmd, ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
			FunctionalEntityNode: f.id(motionID), ExpectedVerificationVariables: []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: f.id(gainID)}}}}}},
	} {
		assert.Equal(t, ua.StatusBadInvalidArgument, f.callStatus(t, req), name)
	}
	r := f.fullRequest("X")
	r.ConnectionEndpointConfigurations = append(r.ConnectionEndpointConfigurations, r.ConnectionEndpointConfigurations[0], r.ConnectionEndpointConfigurations[0])
	assert.Equal(t, ua.StatusBadTooManyOperations, f.callStatus(t, r))

	// A null endpoint with a create elsewhere, only verification for it.
	ok := &uafx.EstablishConnectionsRequest{CommandMask: uafx.VerifyFunctionalEntityCmd | uafx.CreateConnectionEndpointCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{
			{FunctionalEntityNode: f.id(motionID), ExpectedVerificationVariables: []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: f.id(fixedID)}, Value: ua.MustVariant(7.0)}}},
			{FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Parameter: f.endpointParam("Y")}},
		}}
	res := f.establish(t, ok)
	require.Equal(t, ua.StatusOK, res.Status)
	assert.Equal(t, uafx.FunctionalEntityVerificationMatch, res.ConnectionEndpointConfigurationResults[0].VerificationResult)
	assert.Equal(t, ua.StatusGoodNoData, res.ConnectionEndpointConfigurationResults[1].VerificationStatus)
	assert.Equal(t, ua.StatusOK, res.ConnectionEndpointConfigurationResults[1].ConnectionEndpointResult)
}

// TestEstablishBundle: an AutomationComponent with CommandBundleRequired
// takes the bundled commands only with CreateConnectionEndpointCmd and
// SetCommunicationConfigurationCmd (Part 81 §6.2.4.3.1).
func TestEstablishBundle(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{CommandBundleRequired: true})
	r := f.fullRequest("B")
	r.CommandMask &^= uafx.SetCommunicationConfigurationCmd | uafx.EnableCommunicationCmd
	r.CommunicationConfigurations, r.ConnectionEndpointConfigurations[0].CommunicationLinks = nil, nil
	assert.Equal(t, ua.StatusBadInvalidArgument, f.callStatus(t, r))
	res := f.establish(t, f.fullRequest("B"))
	assert.Equal(t, ua.StatusOK, res.Status)
	// Verification alone is not bundled.
	res = f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.VerifyFunctionalEntityCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: node(f, presetID),
			ExpectedVerificationVariables: []*uafx.NodeIDValuePair{{Key: &uafx.NodeIDArray{Node: f.id(fixedID)}, Value: ua.MustVariant(7.0)}}}}})
	assert.Equal(t, ua.StatusOK, res.Status)
}

// pubsubIDs returns the names of the readers and writers of the runtime.
func pubsubIDs(f *fx) map[string]bool {
	out := map[string]bool{}
	for _, c := range f.srv.PubSub().Components() {
		out[c.Kind.String()+"/"+c.Name] = true
	}
	return out
}

// TestEstablishAbort: a command that fails aborts the call: it returns
// Uncertain, the commands after it Bad_NothingToDo, and the server undoes
// what Part 81 Table 21 says: the endpoint, the PubSub configuration and
// the links go, the ConfigurationData and the reserved ids stay.
func TestEstablishAbort(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	before := pubsubIDs(f)
	endpoints := len(f.conns.Endpoints())

	t.Run("links", func(t *testing.T) {
		r := f.fullRequest("A1")
		r.ConnectionEndpointConfigurations[0].CommunicationLinks.DataSetReaderRef = ref(refReader, 1, 0, 5)
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status)
		er := res.ConnectionEndpointConfigurationResults[0]
		assert.Equal(t, ua.StatusOK, er.ConnectionEndpointResult)
		assert.True(t, isNull(er.ConnectionEndpointID), "the endpoint is removed")
		assert.Equal(t, []ua.StatusCode{ua.StatusOK}, er.ConfigurationDataResult)
		assert.Equal(t, ua.StatusBadNotFound, er.CommunicationLinksResult)
		assert.Equal(t, ua.StatusBadNothingToDo, er.EnableCommunicationResult)
		assert.Equal(t, ua.StatusBadNothingToDo, res.CommunicationConfigurationResults[0].Result)
		assert.Equal(t, ua.StatusOK, res.ReserveCommunicationIDsResults[0].Result)
		assert.Equal(t, 2.5, f.value(t, gainID), "ConfigurationData is not rolled back")
		assert.Equal(t, before, pubsubIDs(f))
		assert.Len(t, f.conns.Endpoints(), endpoints)
	})
	t.Run("version", func(t *testing.T) {
		r := f.fullRequest("A2")
		r.ConnectionEndpointConfigurations[0].CommunicationLinks.ExpectedSubscribedDataSetVersion = &ua.ConfigurationVersionDataType{MajorVersion: 9}
		r.CommunicationConfigurations[0].PubSubConfiguration = f.pubsubConfig(3)
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status)
		assert.Equal(t, ua.StatusBadConfigurationError, res.ConnectionEndpointConfigurationResults[0].CommunicationLinksResult)
		assert.Equal(t, ua.StatusOK, res.CommunicationConfigurationResults[0].Result, "the configuration was applied, then reverted")
		assert.Equal(t, before, pubsubIDs(f), "the PubSub configuration of the call is reverted")
		assert.Len(t, f.conns.Endpoints(), endpoints)
	})
	t.Run("variables", func(t *testing.T) {
		r := f.fullRequest("A3")
		p := r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter
		p.InputVariableIDs = []*ua.NodeID{f.id(limitID)} // the reader writes Setpoint
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status)
		assert.Equal(t, ua.StatusBadNoMatch, res.ConnectionEndpointConfigurationResults[0].CommunicationLinksResult)
		assert.Equal(t, before, pubsubIDs(f))
	})
	t.Run("mode", func(t *testing.T) {
		r := f.fullRequest("A4")
		r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.Mode = uafx.PubSubPublisher
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status)
		assert.Equal(t, ua.StatusBadNoMatch, res.ConnectionEndpointConfigurationResults[0].CommunicationLinksResult)
	})
	t.Run("mask", func(t *testing.T) {
		r := f.fullRequest("A5")
		r.ConnectionEndpointConfigurations[0].CommunicationLinks.DataSetReaderRef = ref(refReader|refAdd, 1, 0, 0)
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status)
		assert.Equal(t, ua.StatusBadInvalidArgument, res.ConnectionEndpointConfigurationResults[0].CommunicationLinksResult)
	})
	t.Run("pubsub", func(t *testing.T) {
		r := f.fullRequest("A6")
		r.CommunicationConfigurations[0].ConfigurationReferences = []*ua.PubSubConfigurationRefDataType{ref(refAdd|refWriter, 0, 0, 0)}
		res := f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status)
		assert.NotEqual(t, ua.StatusOK, res.CommunicationConfigurationResults[0].Result)
		assert.Equal(t, before, pubsubIDs(f))
		assert.Len(t, f.conns.Endpoints(), endpoints)
	})
	t.Run("enable", func(t *testing.T) {
		// The first connection takes Setpoint; a second one that writes it
		// cannot be enabled (Part 81 Table 17) and is rolled back.
		res := f.establish(t, f.fullRequest("First"))
		require.Equal(t, ua.StatusOK, res.Status)
		mid := pubsubIDs(f)
		r := f.fullRequest("Second")
		cfg := f.pubsubConfig(0)
		for i, c := range cfg.Connections {
			c.Name += "2"
			c.Address = cfg.Connections[i].Address
		}
		cfg.PublishedDataSets[0].Name = "PDS2"
		cfg.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetName = "PDS2"
		r.CommunicationConfigurations[0].PubSubConfiguration = cfg
		res = f.establish(t, r)
		require.Equal(t, ua.StatusUncertain, res.Status)
		er := res.ConnectionEndpointConfigurationResults[0]
		assert.Equal(t, ua.StatusOK, er.CommunicationLinksResult)
		assert.Equal(t, ua.StatusBadRequestNotAllowed, er.EnableCommunicationResult)
		assert.Equal(t, mid, pubsubIDs(f), "the configuration of the second call is reverted")
		assert.Len(t, f.conns.Endpoints(), endpoints+1)
	})
}

// TestEstablishControlGroups: the codes of the control commands for
// ControlGroups that cannot be controlled: no groups is nothing to do, an
// unknown or invalid one its Table 13 code, a ControlGroup without Locks
// Bad_InvalidState, and any of these aborts the call. The ControlAuthorizer
// allows all: these come after authorization (TestControlGroupMethods).
func TestEstablishControlGroups(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{ControlAuthorizer: func(context.Context, fxserver.ControlRequest) ua.StatusCode {
		return ua.StatusOK
	}})
	for name, tc := range map[string]struct {
		groups []*ua.NodeID
		want   ua.StatusCode
	}{
		"no Locks":     {[]*ua.NodeID{f.id(groupID)}, ua.StatusBadInvalidState},
		"unknown":      {[]*ua.NodeID{f.id(9999)}, ua.StatusBadNodeIDUnknown},
		"other FE":     {[]*ua.NodeID{f.id(remoteID)}, ua.StatusBadNodeIDUnknown},
		"null":         {[]*ua.NodeID{ua.NewNumericNodeID(0, 0)}, ua.StatusBadNodeIDInvalid},
		"not a group":  {[]*ua.NodeID{f.id(notGroupID)}, ua.StatusBadInvalidArgument},
		"group folder": {[]*ua.NodeID{f.id(groupID - 1)}, ua.StatusBadInvalidArgument},
	} {
		for _, cmd := range []uafx.FxCommandMask{uafx.EstablishControlCmd, uafx.ReassignControlCmd} {
			r := f.fullRequest("C")
			r.CommandMask |= cmd
			e := r.ConnectionEndpointConfigurations[0]
			e.ControlGroups = tc.groups
			// A second element without groups: nothing to do for it.
			r.ConnectionEndpointConfigurations = append(r.ConnectionEndpointConfigurations, &uafx.ConnectionEndpointConfiguration{
				FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: node(f, presetID)})
			res := f.establish(t, r)
			require.Equal(t, ua.StatusUncertain, res.Status, name)
			er := res.ConnectionEndpointConfigurationResults[0]
			got := er.EstablishControlResult
			if cmd == uafx.ReassignControlCmd {
				got = er.ReassignControlResult
				assert.Equal(t, []ua.StatusCode{ua.StatusOK}, er.ConfigurationDataResult, name)
			}
			assert.Equal(t, []ua.StatusCode{tc.want}, got, name)
			assert.True(t, isNull(er.ConnectionEndpointID), name)
			assert.Equal(t, ua.StatusBadNothingToDo, er.CommunicationLinksResult, name)
			other := res.ConnectionEndpointConfigurationResults[1]
			assert.Nil(t, other.EstablishControlResult, name)
			assert.Nil(t, other.ReassignControlResult, name)
		}
	}
	assert.Len(t, f.conns.Endpoints(), 1, "only Preset")
}

// TestEstablishCreate: the ConnectionEndpointResult codes of Part 81 Table
// 12.
func TestEstablishCreate(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{MaxConnections: 3})
	create := func(fe uint32, mod func(p *uafx.PubSubConnectionEndpointParameter)) *uafx.ConnectionEndpointConfigurationResult {
		p := f.endpointParam("N")
		if mod != nil {
			mod(p)
		}
		res := f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.CreateConnectionEndpointCmd,
			ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
				FunctionalEntityNode: f.id(fe), ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Parameter: p}}}})
		return res.ConnectionEndpointConfigurationResults[0]
	}
	acType := func(n uint32) *ua.NodeID { return ua.NewNumericNodeID(f.ns.AC, n) }
	for name, tc := range map[string]struct {
		fe   uint32
		mod  func(p *uafx.PubSubConnectionEndpointParameter)
		want ua.StatusCode
	}{
		"persistent": {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.IsPersistent = true }, ua.StatusBadNotSupported},
		"base type": {motionID, func(p *uafx.PubSubConnectionEndpointParameter) {
			p.ConnectionEndpointTypeID = acType(fxacid.ConnectionEndpointType)
		}, ua.StatusBadInvalidArgument},
		"not a type": {motionID, func(p *uafx.PubSubConnectionEndpointParameter) {
			p.ConnectionEndpointTypeID = acType(fxacid.FunctionalEntityType)
		}, ua.StatusBadInvalidArgument},
		"no type":         {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.ConnectionEndpointTypeID = nil }, ua.StatusBadInvalidArgument},
		"no variables":    {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.InputVariableIDs, p.OutputVariableIDs = nil, nil }, ua.StatusBadInvalidArgument},
		"input not input": {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.InputVariableIDs = []*ua.NodeID{f.id(actualID)} }, ua.StatusBadInvalidArgument},
		"output not out":  {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.OutputVariableIDs = []*ua.NodeID{f.id(gainID)} }, ua.StatusBadInvalidArgument},
		"nil input":       {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.InputVariableIDs = []*ua.NodeID{nil} }, ua.StatusBadInvalidArgument},
		"no related":      {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.RelatedEndpoint = &uafx.RelatedEndpoint{} }, ua.StatusBadInvalidArgument},
		"no name":         {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.Name = "" }, ua.StatusBadInvalidArgument},
		"bad mode":        {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.Mode = 0 }, ua.StatusBadInvalidArgument},
		"duplicate":       {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.Name = "Preset" }, ua.StatusBadBrowseNameDuplicated},
		"preset unknown":  {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.IsPreconfigured = true }, ua.StatusBadInvalidArgument},
		"preset mismatch": {motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.IsPreconfigured, p.Name = true, "Preset" }, ua.StatusBadInvalidArgument},
	} {
		er := create(tc.fe, tc.mod)
		assert.Equal(t, tc.want, er.ConnectionEndpointResult, name)
		assert.True(t, isNull(er.ConnectionEndpointID), name)
	}
	for name, tc := range map[string]struct {
		fe   *ua.NodeID
		want ua.StatusCode
	}{
		"FE unknown": {f.id(9999), ua.StatusBadNodeIDUnknown},
		"FE null":    {ua.NewNumericNodeID(0, 0), ua.StatusBadNodeIDInvalid},
		"FE other":   {f.id(remoteID), ua.StatusBadInvalidArgument},
		"not a FE":   {f.id(gainID), ua.StatusBadInvalidArgument},
	} {
		res := f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.CreateConnectionEndpointCmd,
			ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
				FunctionalEntityNode: tc.fe, ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Parameter: f.endpointParam("N")}}}})
		assert.Equal(t, ua.StatusUncertain, res.Status, name)
		er := res.ConnectionEndpointConfigurationResults[0]
		assert.Equal(t, tc.want, er.FunctionalEntityNodeResult, name)
		assert.Equal(t, ua.StatusBadNothingToDo, er.ConnectionEndpointResult, name)
	}

	// A SubFunctionalEntity's input is the FunctionalEntity's; a
	// Subscriber endpoint created on the sub-entity itself.
	er := create(motionID, func(p *uafx.PubSubConnectionEndpointParameter) {
		p.Name, p.InputVariableIDs, p.OutputVariableIDs, p.Mode = "Sub", []*ua.NodeID{f.id(axisInID)}, nil, uafx.PubSubSubscriber
	})
	require.Equal(t, ua.StatusOK, er.ConnectionEndpointResult)
	er = create(axisID, func(p *uafx.PubSubConnectionEndpointParameter) {
		p.Name, p.InputVariableIDs, p.OutputVariableIDs, p.Mode = "OnAxis", []*ua.NodeID{f.id(axisInID)}, nil, uafx.PubSubSubscriber
	})
	require.Equal(t, ua.StatusOK, er.ConnectionEndpointResult)
	axisCE := f.srv.Node(er.ConnectionEndpointID)
	require.NotNil(t, axisCE, "the Axis got a ConnectionEndpoints folder")
	assert.Equal(t, ua.StatusBadResourceUnavailable, create(motionID, func(p *uafx.PubSubConnectionEndpointParameter) { p.Name = "Third" }).ConnectionEndpointResult)

	// The created endpoint's members (Part 81 §6.6.2, §6.6.3).
	ctx := context.Background()
	got := map[string]any{}
	refs, err := f.c.Node(er.ConnectionEndpointID).References(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassVariable, true)
	require.NoError(t, err)
	for _, r := range refs {
		require.Equal(t, f.ns.AC, r.BrowseName.NamespaceIndex, r.BrowseName.Name)
		if r.BrowseName.Name == "RelatedEndpoint" {
			got[r.BrowseName.Name] = f.srv.Node(r.NodeID.NodeID).Value().Value.Value()
			continue
		}
		v, err := f.c.Node(r.NodeID.NodeID).Value(ctx)
		require.NoError(t, err)
		got[r.BrowseName.Name] = v.Value()
	}
	assert.Equal(t, int32(uafx.ConnectionEndpointInitial), got["Status"])
	assert.Equal(t, false, got["IsPersistent"])
	assert.Equal(t, -1.0, got["CleanupTimeout"])
	assert.Equal(t, int32(uafx.PubSubSubscriber), got["Mode"])
	assert.Equal(t, []*ua.NodeID{f.id(axisInID)}, got["InputVariables"])
	assert.Equal(t, []*ua.NodeID{}, got["OutputVariables"])
	assert.Contains(t, got, "RelatedEndpoint")
	assert.NotEmpty(t, got["ConnectionManagerApplicationUri"], "the ApplicationUri of the caller")
	typ, err := f.c.Node(er.ConnectionEndpointID).References(ctx, id.HasTypeDefinition, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, typ, 1)
	assert.True(t, sameNode(acType(fxacid.PubSubConnectionEndpointType), typ[0].NodeID.NodeID))
}

// TestEstablishPreconfigured: a preconfigured endpoint is used, not created
// (Part 81 §6.2.4.3.5): it takes the RelatedEndpoint and CleanupTimeout of
// the call, cannot be used twice, and stays after CloseConnections with
// Remove; the reader the call configured for it goes.
func TestEstablishPreconfigured(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	ctx := context.Background()
	preset := func() *uafx.EstablishConnectionsRequest {
		r := f.fullRequest("Preset")
		p := r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter
		p.IsPreconfigured, p.Mode, p.OutputVariableIDs, p.CleanupTimeout = true, uafx.PubSubSubscriber, nil, 5000
		r.ConnectionEndpointConfigurations[0].CommunicationLinks.DataSetWriterRef = nil
		// The writer is not the endpoint's: it publishes from the start.
		r.CommunicationConfigurations[0].PubSubConfiguration.Connections[0].WriterGroups[0].DataSetWriters[0].Enabled = true
		return r
	}
	res := f.establish(t, preset())
	require.Equal(t, ua.StatusOK, res.Status)
	er := res.ConnectionEndpointConfigurationResults[0]
	require.True(t, sameNode(f.id(presetID), er.ConnectionEndpointID), "%v", er.ConnectionEndpointID)
	require.Eventually(t, func() bool { return f.value(t, setpointID) == 42.5 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, 5000.0, f.value(t, presetID+3))

	// In use: a second use fails (Table 12) and leaves it as it is.
	again := f.establish(t, preset())
	require.Equal(t, ua.StatusUncertain, again.Status)
	assert.Equal(t, ua.StatusBadInvalidState, again.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult)
	st, _ := f.conns.Status(f.id(presetID))
	assert.Equal(t, uafx.ConnectionEndpointOperational, st)

	sc, results, err := uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{f.id(presetID)}, true)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
	require.NotNil(t, f.srv.Node(f.id(presetID)), "a preconfigured endpoint stays")
	ids := pubsubIDs(f)
	assert.False(t, ids["DataSetReader/"+readerName], "the reader of the call goes")
	assert.True(t, ids["DataSetWriter/"+writerName], "the writer no endpoint referenced stays")
	require.Eventually(t, func() bool {
		st, _ := f.conns.Status(f.id(presetID))
		return st == uafx.ConnectionEndpointInitial
	}, 5*time.Second, 5*time.Millisecond)
	assert.Empty(t, f.targets(t, f.id(presetID), fxacid.ToDataSetReader), "the reference to the removed reader goes")

	// No longer in use: it can be used again.
	res = f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.CreateConnectionEndpointCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{FunctionalEntityNode: f.id(motionID),
			ConnectionEndpoint: preset().ConnectionEndpointConfigurations[0].ConnectionEndpoint}}})
	require.Equal(t, ua.StatusOK, res.Status)
	assert.True(t, sameNode(f.id(presetID), res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID))

	// A rollback restores what the call changed on it.
	sc, _, err = uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{f.id(presetID)}, true)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc)
	r := preset()
	r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = 9
	r.ConnectionEndpointConfigurations[0].ControlGroups = []*ua.NodeID{f.id(groupID)}
	r.CommandMask |= uafx.EstablishControlCmd
	res = f.establish(t, r)
	require.Equal(t, ua.StatusUncertain, res.Status)
	assert.Equal(t, 5000.0, f.value(t, presetID+3), "CleanupTimeout restored")
	assert.Nil(t, val(f.srv.Node(f.id(presetID+4)).Value().Value), "RelatedEndpoint restored")
	assert.NotNil(t, f.srv.Node(f.id(presetID)), "a preconfigured endpoint is not deleted by a rollback")
}

func val(v *ua.Variant) any {
	if v == nil {
		return nil
	}
	return v.Value()
}

// targets returns the targets of the forward references of the AC type
// refType of n, browsed by the client.
func (f *fx) targets(t *testing.T, n *ua.NodeID, refType uint32) []*ua.NodeID {
	t.Helper()
	res, err := f.c.Browse(context.Background(), &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: n, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: ua.NewNumericNodeID(f.ns.AC, refType),
		IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)}}})
	require.NoError(t, err)
	require.Len(t, res.Results, 1)
	require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
	var out []*ua.NodeID
	for _, r := range res.Results[0].References {
		out = append(out, r.NodeID.NodeID)
	}
	return out
}

// TestCloseConnections: CloseConnections disables what no other endpoint
// references, leaves the parents alone, and returns a result per element
// (Part 81 §6.2.5).
func TestCloseConnections(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	ctx := context.Background()
	// Two endpoints of one call share the writer: Pub publishes and
	// subscribes, Pub2 only publishes.
	r := f.fullRequest("Pub")
	p2 := f.endpointParam("Pub2")
	p2.Mode, p2.InputVariableIDs = uafx.PubSubPublisher, nil
	r.ConnectionEndpointConfigurations = append(r.ConnectionEndpointConfigurations, &uafx.ConnectionEndpointConfiguration{
		FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Parameter: p2},
		CommunicationLinks: &uafx.PubSubCommunicationLinkConfiguration{DataSetWriterRef: ref(refWriter, 0, 0, 0)},
	})
	res := f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status)
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	ep2 := res.ConnectionEndpointConfigurationResults[1].ConnectionEndpointID

	rt := f.srv.PubSub()
	lookup := func(kind pubsub.ComponentKind, conn, group, name string) pubsub.ComponentID {
		c, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, conn)
		require.True(t, ok)
		gk := pubsub.KindWriterGroup
		if kind == pubsub.KindDataSetReader {
			gk = pubsub.KindReaderGroup
		}
		g, ok := rt.Lookup(gk, c, group)
		require.True(t, ok)
		x, ok := rt.Lookup(kind, g, name)
		require.True(t, ok, name)
		return x
	}
	enabled := func(cid pubsub.ComponentID) bool {
		info, err := rt.Component(cid)
		require.NoError(t, err)
		return info.Enabled
	}
	w, rd := lookup(pubsub.KindDataSetWriter, pubConn, wgName, writerName), lookup(pubsub.KindDataSetReader, subConn, rgName, readerName)

	// Without Remove: the shared writer stays enabled, the reader is
	// disabled, the groups are untouched, the endpoint stays (Ready).
	sc, results, err := uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{ep}, false)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
	assert.True(t, enabled(w), "shared")
	assert.False(t, enabled(rd))
	c, _ := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
	assert.True(t, enabled(c), "parents stay")
	require.NotNil(t, f.srv.Node(ep))
	require.Eventually(t, func() bool { st, _ := f.conns.Status(ep); return st == uafx.ConnectionEndpointReady }, 5*time.Second, 5*time.Millisecond)

	// With Remove: the reader goes, the shared writer stays while Pub2
	// references it, and goes with Pub2.
	sc, results, err = uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{ep}, true)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
	ids := pubsubIDs(f)
	assert.False(t, ids["DataSetReader/"+readerName])
	assert.True(t, ids["DataSetWriter/"+writerName], "Pub2 references it")
	assert.True(t, enabled(w))
	assert.Nil(t, f.srv.Node(ep))
	sc, results, err = uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{ep2}, true)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, sc)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)
	assert.False(t, pubsubIDs(f)["DataSetWriter/"+writerName])
	assert.Nil(t, f.srv.Node(ep2))
	// The call added the groups and connections (ElementAdd): they go
	// once empty (§6.2.5.2).
	assert.False(t, pubsubIDs(f)["WriterGroup/"+wgName], "an emptied group the call added goes")

	// Element errors (Table 24).
	sc, results, err = uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{
		f.id(9999), ua.NewNumericNodeID(0, 0), f.id(gainID), ep, f.id(presetID),
	}, false)
	require.NoError(t, err)
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadNodeIDUnknown, ua.StatusBadNodeIDInvalid, ua.StatusBadInvalidArgument, ua.StatusBadNodeIDUnknown, ua.StatusOK}, results)
	sc, results, err = uafx.CloseConnections(ctx, f.c, f.id(peerID), []*ua.NodeID{f.id(presetID)}, false)
	require.NoError(t, err)
	assert.Equal(t, ua.StatusUncertain, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadNodeIDUnknown}, results, "an endpoint of another AutomationComponent")
	sc, results, err = uafx.CloseConnections(ctx, f.c, f.id(ctlID), nil, true)
	require.NoError(t, err)
	assert.Equal(t, ua.StatusOK, sc)
	assert.Empty(t, results)
}

// TestCleanupTimeout: the CleanupTimeout starts when the Status leaves
// Operational, not before (Part 81 §6.6.2); on expiry the endpoint is
// closed as with Remove; CloseConnections disables it.
func TestCleanupTimeout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	writer := func(f *fx) pubsub.ComponentID {
		rt := f.srv.PubSub()
		c, _ := rt.Lookup(pubsub.KindConnection, pubsub.Root, pubConn)
		wg, _ := rt.Lookup(pubsub.KindWriterGroup, c, wgName)
		w, ok := rt.Lookup(pubsub.KindDataSetWriter, wg, writerName)
		require.True(t, ok)
		return w
	}
	operational := func(t *testing.T, f *fx, timeout float64) *ua.NodeID {
		r := f.fullRequest("Live")
		r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = timeout
		res := f.establish(t, r)
		require.Equal(t, ua.StatusOK, res.Status)
		ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
		require.Eventually(t, func() bool { st, _ := f.conns.Status(ep); return st == uafx.ConnectionEndpointOperational }, 5*time.Second, 5*time.Millisecond)
		return ep
	}

	t.Run("never operational", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		r := f.fullRequest("Idle")
		r.CommandMask &^= uafx.EnableCommunicationCmd
		r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = 0
		res := f.establish(t, r)
		require.Equal(t, ua.StatusOK, res.Status)
		idle := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
		time.Sleep(100 * time.Millisecond)
		st, ok := f.conns.Status(idle)
		require.True(t, ok, "an endpoint that was never Operational is not cleaned up")
		assert.Equal(t, uafx.ConnectionEndpointReady, st)
	})
	t.Run("expires", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{}, server.WithAuditing(true))
		ep := operational(t, f, 200)
		require.NoError(t, f.srv.PubSub().Disable(writer(f)))
		left := time.Now()
		require.Eventually(t, func() bool { _, ok := f.conns.Status(ep); return !ok }, 5*time.Second, 5*time.Millisecond)
		assert.GreaterOrEqual(t, time.Since(left), 150*time.Millisecond, "not before the timeout")
		assert.Nil(t, f.srv.Node(ep))
		assert.False(t, pubsubIDs(f)["DataSetWriter/"+writerName], "closed as with Remove")
	})
	t.Run("reset", func(t *testing.T) {
		t.Parallel()
		f := newFX(t, fxserver.ConnectionOptions{})
		ep := operational(t, f, 400)
		rt, w := f.srv.PubSub(), writer(f)
		require.NoError(t, rt.Disable(w))
		require.Eventually(t, func() bool { st, _ := f.conns.Status(ep); return st != uafx.ConnectionEndpointOperational }, 5*time.Second, 5*time.Millisecond)
		require.NoError(t, rt.Enable(w))
		require.Eventually(t, func() bool { st, _ := f.conns.Status(ep); return st == uafx.ConnectionEndpointOperational }, 5*time.Second, 5*time.Millisecond)
		time.Sleep(600 * time.Millisecond)
		_, ok := f.conns.Status(ep)
		assert.True(t, ok, "the timeout was reset")

		// CloseConnections without Remove disables the processing.
		_, _, err := uafx.CloseConnections(ctx, f.c, f.id(ctlID), []*ua.NodeID{ep}, false)
		require.NoError(t, err)
		time.Sleep(600 * time.Millisecond)
		_, ok = f.conns.Status(ep)
		assert.True(t, ok, "no cleanup after CloseConnections")
	})
}

// TestConnectionHealth: the CommHealth of the ConnectionEndpoints folder,
// the lower 16 bits of the OperationalHealth of the FunctionalEntity and
// the AggregatedOperationalHealth follow the Status of the endpoints (Part
// 81 §6.4.8, §10.34, §9.1.2).
func TestConnectionHealth(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	opHealth := func() uint32 { v, _ := f.value(t, motionOH).(uint32); return v }
	aggregated := func() uint32 {
		eo, ok := f.value(t, ctlHealth).(*ua.ExtensionObject)
		require.True(t, ok)
		b, _ := eo.Value.([]byte)
		require.Len(t, b, 6)
		return uint32(b[2]) | uint32(b[3])<<8 | uint32(b[4])<<16 | uint32(b[5])<<24
	}
	// Preset references nothing: Initial.
	require.Eventually(t, func() bool { return opHealth() == 0x10000|1 }, 5*time.Second, 5*time.Millisecond, "the vendor bits stay")
	assert.Equal(t, uint32(0x10000|1), aggregated())

	res := f.establish(t, f.fullRequest("H"))
	require.Equal(t, ua.StatusOK, res.Status)
	_, _, err := uafx.CloseConnections(context.Background(), f.c, f.id(ctlID), []*ua.NodeID{f.id(presetID)}, true)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return opHealth()&0xffff == 1 }, 5*time.Second, 5*time.Millisecond, "Preset is still Initial")

	setValue(t, f.srv, f.id(motionOH), uint32(0x20000|1))
	// The AggregatedOperationalHealth ORs that of every FunctionalEntity:
	// the endpoints of H go Initial, PreOperational, Operational while
	// their data starts to flow, so the CommHealth bits of their
	// FunctionalEntity clear only once they are Operational.
	require.Eventually(t, func() bool {
		f.conns.RefreshHealth()
		return aggregated() == 0x20000|1
	}, 5*time.Second, 5*time.Millisecond, "the vendor bits of Motion and the Initial Preset only")
}

// TestEstablishVerify: VerifyAssetCmd and VerifyFunctionalEntityCmd
// (Part 81 §6.2.4.3.2, §6.2.4.3.3; Tables 10, 44, 45).
func TestEstablishVerify(t *testing.T) {
	t.Parallel()
	var calls int
	verifier := func(_ context.Context, asset *ua.NodeID, mode uafx.AssetVerificationMode, _ []*ua.KeyValuePair, _ []*uafx.NodeIDValuePair) (uafx.AssetVerificationResult, []ua.StatusCode, []ua.StatusCode, ua.StatusCode) {
		calls++
		if mode == uafx.AssetIdentity {
			return uafx.AssetVerificationMismatch, nil, nil, ua.StatusUncertain
		}
		return uafx.AssetVerificationMatch, nil, nil, ua.StatusOK
	}
	f := newFX(t, fxserver.ConnectionOptions{AssetVerifier: verifier})
	asset := func(n *ua.NodeID, mode uafx.AssetVerificationMode) *uafx.EstablishConnectionsResult {
		return f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.VerifyAssetCmd,
			AssetVerifications: []*uafx.AssetVerification{{AssetToVerify: n, VerificationMode: mode, ExpectedVerificationResult: uafx.AssetVerificationMatch}}})
	}
	res := asset(f.id(pumpID), uafx.AssetCompatibility)
	assert.Equal(t, ua.StatusOK, res.Status)
	assert.Equal(t, uafx.AssetVerificationMatch, res.AssetVerificationResults[0].VerificationResult)
	res = asset(f.id(pumpID), uafx.AssetIdentity)
	assert.Equal(t, ua.StatusUncertain, res.Status)
	for n, want := range map[*ua.NodeID]ua.StatusCode{
		f.id(9999): ua.StatusBadNodeIDUnknown, ua.NewNumericNodeID(0, 0): ua.StatusBadNodeIDInvalid, f.id(gainID): ua.StatusBadInvalidArgument,
	} {
		res = asset(n, uafx.AssetCompatibility)
		assert.Equal(t, ua.StatusUncertain, res.Status)
		assert.Equal(t, want, res.AssetVerificationResults[0].VerificationStatus, n.String())
	}
	assert.Equal(t, 2, calls)
	g := newFX(t, fxserver.ConnectionOptions{})
	res, err := uafx.EstablishConnections(context.Background(), g.c, g.id(ctlID), &uafx.EstablishConnectionsRequest{CommandMask: uafx.VerifyAssetCmd,
		AssetVerifications: []*uafx.AssetVerification{{AssetToVerify: g.id(pumpID)}}})
	require.NoError(t, err)
	assert.Equal(t, ua.StatusBadNotSupported, res.AssetVerificationResults[0].VerificationStatus)

	verify := func(pairs ...*uafx.NodeIDValuePair) *uafx.ConnectionEndpointConfigurationResult {
		res := f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.VerifyFunctionalEntityCmd | uafx.EnableCommunicationCmd,
			ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{FunctionalEntityNode: f.id(motionID),
				ConnectionEndpoint: node(f, presetID), ExpectedVerificationVariables: pairs}}})
		return res.ConnectionEndpointConfigurationResults[0]
	}
	pair := func(n uint32, v any, idx ...uint32) *uafx.NodeIDValuePair {
		var vv *ua.Variant
		if v != nil {
			vv = ua.MustVariant(v)
		}
		return &uafx.NodeIDValuePair{Key: &uafx.NodeIDArray{Node: f.id(n), ArrayIndex: idx}, Value: vv}
	}
	er := verify(pair(gainID, 1.0), pair(tableID, 2.0, 1), pair(motionID, nil), pair(gainID, nil))
	assert.Equal(t, uafx.FunctionalEntityVerificationMatch, er.VerificationResult)
	assert.Equal(t, ua.StatusOK, er.VerificationStatus)
	assert.Equal(t, ua.StatusBadInvalidState, er.EnableCommunicationResult, "Preset has no reader")

	er = verify(pair(gainID, 2.0), pair(gainID, int32(1)), pair(9999, 1.0), pair(tableID, 1.0, 7), pair(tableID, 1.0, 0, 0), pair(motionID, 1.0))
	assert.Equal(t, uafx.FunctionalEntityVerificationMismatch, er.VerificationResult)
	assert.Equal(t, ua.StatusUncertain, er.VerificationStatus)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadOutOfRange, ua.StatusBadTypeMismatch, ua.StatusBadNodeIDUnknown, ua.StatusBadOutOfRange, ua.StatusBadOutOfRange, ua.StatusBadOutOfRange}, er.VerificationVariablesErrors)
	assert.Equal(t, ua.StatusBadNothingToDo, er.EnableCommunicationResult)
}

// TestEstablishConfigurationData: SetConfigurationDataCmd writes with the
// rights of the caller (Part 81 Table 14).
func TestEstablishConfigurationData(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	set := func(pairs ...*uafx.NodeIDValuePair) []ua.StatusCode {
		res := f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.SetConfigurationDataCmd,
			ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{FunctionalEntityNode: f.id(motionID),
				ConnectionEndpoint: node(f, presetID), ConfigurationData: pairs}}})
		return res.ConnectionEndpointConfigurationResults[0].ConfigurationDataResult
	}
	pair := func(n uint32, v any, idx ...uint32) *uafx.NodeIDValuePair {
		return &uafx.NodeIDValuePair{Key: &uafx.NodeIDArray{Node: f.id(n), ArrayIndex: idx}, Value: ua.MustVariant(v)}
	}
	assert.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, set(pair(gainID, 3.0), pair(tableID, 9.0, 2)))
	assert.Equal(t, 3.0, f.value(t, gainID))
	assert.Equal(t, []float64{1, 2, 9}, f.value(t, tableID))
	for name, tc := range map[string]struct {
		p    *uafx.NodeIDValuePair
		want ua.StatusCode
	}{
		"read only":  {pair(fixedID, 1.0), ua.StatusBadUserAccessDenied},
		"not config": {pair(setpointID, 1.0), ua.StatusBadInvalidArgument},
		"unknown":    {pair(9999, 1.0), ua.StatusBadNodeIDUnknown},
		"null":       {&uafx.NodeIDValuePair{Key: &uafx.NodeIDArray{Node: ua.NewNumericNodeID(0, 0)}}, ua.StatusBadNodeIDInvalid},
		"no key":     {&uafx.NodeIDValuePair{}, ua.StatusBadNodeIDInvalid},
		"type":       {pair(gainID, int32(1)), ua.StatusBadTypeMismatch},
		"elem type":  {pair(tableID, int32(1), 0), ua.StatusBadTypeMismatch},
		"index":      {pair(tableID, 1.0, 9), ua.StatusBadInvalidArgument},
	} {
		assert.Equal(t, []ua.StatusCode{tc.want, ua.StatusBadNothingToDo}, set(tc.p, pair(gainID, 4.0)), name)
	}
	assert.Equal(t, 3.0, f.value(t, gainID))

	// The node of the endpoint must be one of the FunctionalEntity.
	res := f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.SetConfigurationDataCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{
			{FunctionalEntityNode: f.id(axisID), ConnectionEndpoint: node(f, presetID), ConfigurationData: []*uafx.NodeIDValuePair{pair(gainID, 1.0)}},
		}})
	assert.Equal(t, ua.StatusBadNodeIDUnknown, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult)
	for n, want := range map[*ua.NodeID]ua.StatusCode{f.id(9999): ua.StatusBadNodeIDUnknown, ua.NewNumericNodeID(0, 0): ua.StatusBadNodeIDInvalid, f.id(gainID): ua.StatusBadInvalidArgument} {
		res := f.establish(t, &uafx.EstablishConnectionsRequest{CommandMask: uafx.SetConfigurationDataCmd,
			ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{
				{FunctionalEntityNode: f.id(motionID), ConnectionEndpoint: &uafx.ConnectionEndpointDefinition{Node: n}, ConfigurationData: []*uafx.NodeIDValuePair{pair(gainID, 1.0)}},
			}})
		assert.Equal(t, want, res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointResult, n.String())
	}
}

// denyCloseAndUpdate denies the CloseAndUpdate Method of PubSub.
type denyCloseAndUpdate struct{ server.DefaultAccessController }

func (denyCloseAndUpdate) CheckCall(_ context.Context, _ *server.Session, m *ua.NodeID) ua.StatusCode {
	if m.Equal(ua.NewNumericNodeID(0, id.PublishSubscribePubSubConfigurationCloseAndUpdate)) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

// TestEstablishAccess: SetCommunicationConfigurationCmd has no more rights
// than its caller: a session that may not call CloseAndUpdate cannot
// configure PubSub through EstablishConnections, and the call aborts.
func TestEstablishAccess(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{}, server.WithAccessController(denyCloseAndUpdate{}))
	before := pubsubIDs(f)
	res := f.establish(t, f.fullRequest("D"))
	require.Equal(t, ua.StatusUncertain, res.Status)
	assert.Equal(t, ua.StatusBadUserAccessDenied, res.CommunicationConfigurationResults[0].Result)
	assert.Equal(t, before, pubsubIDs(f))
	assert.Len(t, f.conns.Endpoints(), 1)
}

// TestEnableConnectionsErrors: EnableConnections needs the AC model, PubSub
// and an AutomationComponent with the Methods.
func TestEnableConnectionsErrors(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	ns, err := fxserver.AddModel(srv, fxserver.ModelAC)
	require.NoError(t, err)
	_, err = fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{})
	require.ErrorIs(t, err, fxserver.ErrConnections, "no PubSub")
	_, err = fxserver.EnableConnections(srv, fxserver.Namespaces{}, fxserver.ConnectionOptions{})
	require.ErrorIs(t, err, fxserver.ErrConnections, "no model")

	srv = newServer(t, server.WithPubSub(nil))
	ns, err = fxserver.AddModel(srv, fxserver.ModelAC)
	require.NoError(t, err)
	_, err = fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{})
	require.ErrorIs(t, err, fxserver.ErrConnections, "no AutomationComponent")
}

// fxAudit is an audit event of the connection Methods.
type fxAudit struct {
	typ     *ua.NodeID
	source  *ua.NodeID
	status  bool
	code    ua.StatusCode
	outputs int
	removed string
}

// watchAudit subscribes the client of f to the audit events of the Server
// object.
func watchAudit(t *testing.T, f *fx) <-chan fxAudit {
	t.Helper()
	b := ua.NewEventFilter().SelectPaths("EventType", "SourceNode", "Status", "StatusCodeId", "OutputArguments", "RemovedEndpoint")
	b.Where(&ua.ContentFilterElement{
		FilterOperator: ua.FilterOperatorOfType,
		FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(ua.NewNumericNodeID(0, id.AuditEventType))})},
	})
	sub, ch, err := f.c.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(b.Build(), ua.NewNumericNodeID(0, id.Server)).Start(context.Background())
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = sub.Cancel(context.Background()) })
	out := make(chan fxAudit, 64)
	done, exited := make(chan struct{}), make(chan struct{})
	cleanup.Register(t, func() { close(done); <-exited })
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
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok {
				continue
			}
			for _, e := range enl.Events {
				fl := e.EventFields
				a := fxAudit{}
				a.typ, _ = fl[0].Value().(*ua.NodeID)
				a.source, _ = fl[1].Value().(*ua.NodeID)
				a.status, _ = fl[2].Value().(bool)
				a.code, _ = fl[3].Value().(ua.StatusCode)
				if vs, ok := fl[4].Value().([]*ua.Variant); ok {
					a.outputs = len(vs)
				}
				a.removed, _ = fl[5].Value().(string)
				select {
				case out <- a:
				default:
				}
			}
		}
	}()
	return out
}

func nextFXAudit(t *testing.T, ch <-chan fxAudit, typ *ua.NodeID) fxAudit {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case a := <-ch:
			if sameNode(a.typ, typ) {
				return a
			}
		case <-deadline:
			t.Fatalf("no audit event %v", typ)
		}
	}
}

// TestConnectionsAudit: with auditing, every call of EstablishConnections
// and CloseConnections reports an AuditUpdateMethodResultEventType event
// from the AutomationComponent, and an expired CleanupTimeout an
// AuditConnectionCleanupEventType event from the FunctionalEntity (Part 81
// §6.2.4.1, §6.2.5.1, §6.6.2, §8.3, §8.4).
func TestConnectionsAudit(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{}, server.WithAuditing(true))
	ch := watchAudit(t, f)
	methodResult := ua.NewNumericNodeID(f.ns.Data, fxdataid.AuditUpdateMethodResultEventType)

	r := f.fullRequest("Audited")
	r.ConnectionEndpointConfigurations[0].ConnectionEndpoint.Parameter.CleanupTimeout = 0
	res := f.establish(t, r)
	require.Equal(t, ua.StatusOK, res.Status)
	a := nextFXAudit(t, ch, methodResult)
	assert.True(t, sameNode(f.id(ctlID), a.source))
	assert.True(t, a.status)
	assert.Equal(t, ua.StatusOK, a.code)
	assert.Equal(t, 4, a.outputs)

	assert.Equal(t, ua.StatusBadInvalidArgument, f.callStatus(t, &uafx.EstablishConnectionsRequest{}))
	a = nextFXAudit(t, ch, methodResult)
	assert.False(t, a.status)
	assert.Equal(t, ua.StatusBadInvalidArgument, a.code)

	sc, _, err := uafx.CloseConnections(context.Background(), f.c, f.id(ctlID), []*ua.NodeID{f.id(9999)}, false)
	require.NoError(t, err)
	require.Equal(t, ua.StatusUncertain, sc)
	a = nextFXAudit(t, ch, methodResult)
	assert.True(t, a.status)
	assert.Equal(t, ua.StatusUncertain, a.code)
	assert.Equal(t, 1, a.outputs)

	// Operational, then not: a CleanupTimeout of 0 cleans up at once.
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	require.Eventually(t, func() bool { st, _ := f.conns.Status(ep); return st == uafx.ConnectionEndpointOperational }, 5*time.Second, 5*time.Millisecond)
	rt := f.srv.PubSub()
	c, _ := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
	require.NoError(t, rt.Disable(c))
	a = nextFXAudit(t, ch, ua.NewNumericNodeID(f.ns.AC, fxacid.AuditConnectionCleanupEventType))
	assert.True(t, sameNode(f.id(motionID), a.source))
	assert.Equal(t, "Audited", a.removed)
	assert.Nil(t, f.srv.Node(ep))
	assert.False(t, pubsubIDs(f)["Connection/"+subConn], "the cleanup removes the emptied connection the call added (§6.2.5.2)")
}

// TestEstablishAbortLate: an abort after part of the call has run undoes
// it: an element enabled before the failing one is disabled again with the
// configuration of the call, and a failed ReserveIds stops the call before
// anything is created.
func TestEstablishAbortLate(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	before := pubsubIDs(f)

	// Two endpoints that subscribe Setpoint: the second cannot be enabled
	// once the first is (Part 81 Table 17).
	r := f.fullRequest("One")
	two := *r.ConnectionEndpointConfigurations[0]
	two.ConnectionEndpoint = &uafx.ConnectionEndpointDefinition{Parameter: f.endpointParam("Two")}
	two.ConfigurationData, two.ExpectedVerificationVariables = nil, nil
	r.ConnectionEndpointConfigurations = append(r.ConnectionEndpointConfigurations, &two)
	res := f.establish(t, r)
	require.Equal(t, ua.StatusUncertain, res.Status)
	assert.Equal(t, ua.StatusOK, res.ConnectionEndpointConfigurationResults[0].EnableCommunicationResult)
	assert.Equal(t, ua.StatusBadRequestNotAllowed, res.ConnectionEndpointConfigurationResults[1].EnableCommunicationResult)
	assert.Equal(t, before, pubsubIDs(f))
	assert.Len(t, f.conns.Endpoints(), 1)
	assert.True(t, isNull(res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID))

	// ReserveIds fails (Part 81 Table 18), here for a caller the
	// PubSubAuthorizer denies it: nothing after it runs.
	g := newFX(t, fxserver.ConnectionOptions{}, server.WithPubSubAuthorizer(func(_ context.Context, _ *server.MethodCaller, m string) ua.StatusCode {
		if m == "ReserveIds" {
			return ua.StatusBadUserAccessDenied
		}
		return ua.StatusOK
	}))
	res = g.establish(t, g.fullRequest("Three"))
	require.Equal(t, ua.StatusUncertain, res.Status)
	assert.Equal(t, ua.StatusBadUserAccessDenied, res.ReserveCommunicationIDsResults[0].Result)
	er := res.ConnectionEndpointConfigurationResults[0]
	assert.Equal(t, uafx.FunctionalEntityVerificationMatch, er.VerificationResult, "verification ran before")
	assert.Equal(t, ua.StatusBadNothingToDo, er.ConnectionEndpointResult)
	assert.Equal(t, []ua.StatusCode{ua.StatusBadNothingToDo}, er.ConfigurationDataResult)
	assert.Equal(t, 1.0, g.value(t, gainID))
	assert.Len(t, g.conns.Endpoints(), 1)
}

// TestEstablishAssignedNames: CommunicationLinks refer to a group and
// elements added with a null Name by the Names the server assigns (Part 81
// §6.16.3).
func TestEstablishAssignedNames(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	req := f.fullRequest("Named")
	cfg := req.CommunicationConfigurations[0].PubSubConfiguration
	cfg.Connections[0].WriterGroups[0].Name = ""
	cfg.Connections[0].WriterGroups[0].DataSetWriters[0].Name = ""
	cfg.Connections[1].ReaderGroups[0].Name = ""
	cfg.Connections[1].ReaderGroups[0].DataSetReaders[0].Name = ""
	res := f.establish(t, req)
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	er := res.ConnectionEndpointConfigurationResults[0]
	assert.Equal(t, ua.StatusOK, er.CommunicationLinksResult)
	names := map[string]bool{}
	for _, v := range res.CommunicationConfigurationResults[0].ConfigurationValues {
		names[v.Name] = true
	}
	assert.True(t, names["WriterGroup1"] && names["DataSetWriter1"] && names["DataSetReader1"], "%v", names)
	require.Eventually(t, func() bool { return f.value(t, setpointID) == 42.5 }, 5*time.Second, 5*time.Millisecond)
}

// TestEstablishModifyKeepsOwnership: a later call that modifies the
// DataSetReader of an endpoint (SetCommunicationConfigurationCmd on the
// endpoint's Node with ElementModify, as a ConnectionManager adapts a
// subscriber to a PublisherId, Part 81 §6.16.3) keeps it the endpoint's
// own, so CloseConnections with Remove still removes it (§6.2.5.2), though
// the runtime gives the modified reader a new node.
func TestEstablishModifyKeepsOwnership(t *testing.T) {
	t.Parallel()
	f := newFX(t, fxserver.ConnectionOptions{})
	res := f.establish(t, f.fullRequest("Mod"))
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	ep := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
	before := f.lookup(t, pubsub.KindDataSetReader, subConn, rgName, readerName)

	cfg := f.pubsubConfig(0)
	cfg.Connections[1].ReaderGroups[0].DataSetReaders[0].PublisherID = ua.MustVariant(uint16(78))
	modify := &uafx.EstablishConnectionsRequest{
		CommandMask: uafx.SetCommunicationConfigurationCmd,
		ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{{
			FunctionalEntityNode: f.id(motionID),
			ConnectionEndpoint:   &uafx.ConnectionEndpointDefinition{Node: ep},
			CommunicationLinks: &uafx.PubSubCommunicationLinkConfiguration{
				DataSetReaderRef: ref(refReader, 1, 0, 0),
				DataSetWriterRef: ref(refWriter, 0, 0, 0),
			},
		}},
		CommunicationConfigurations: []*uafx.PubSubCommunicationConfiguration{{
			PubSubConfiguration: cfg, RequireCompleteUpdate: true,
			ConfigurationReferences: []*ua.PubSubConfigurationRefDataType{ref(ua.PubSubConfigurationRefMaskElementModify|refReader, 1, 0, 0)},
		}},
	}
	res = f.establish(t, modify)
	require.Equal(t, ua.StatusOK, res.Status, "%+v", res.ConnectionEndpointConfigurationResults[0])
	after := f.lookup(t, pubsub.KindDataSetReader, subConn, rgName, readerName)
	dr, err := f.srv.PubSub().DataSetReaderConfig(after)
	require.NoError(t, err)
	assert.Equal(t, ua.MustVariant(uint16(78)), dr.PublisherID)
	assert.NotEqual(t, before, after, "the runtime replaces the reader")

	sc, results := f.close(t, true, ep)
	require.Equal(t, ua.StatusOK, sc, "%v", results)
	rt := f.srv.PubSub()
	_, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, subConn)
	assert.False(t, ok, "the modified reader is removed with its endpoint, and its emptied group and connection")
	_, err = rt.Component(after)
	assert.Error(t, err)
}
