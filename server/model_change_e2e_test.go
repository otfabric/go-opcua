// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// changeClient is a client subscribed to the ModelChangeEvents and
// SemanticChangeEvents of the Server Object.
type changeClient struct {
	t      *testing.T
	c      *opcua.Client
	ctx    context.Context
	notify chan *opcua.PublishNotificationData
	sub    *opcua.Subscription
}

func newChangeClient(t *testing.T, srv *server.Server) *changeClient {
	t.Helper()
	c := testutil.NewTestClient(t, srv.Endpoints()[0].EndpointURL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	cc := &changeClient{t: t, c: c, ctx: ctx, notify: make(chan *opcua.PublishNotificationData, 64)}
	sub, _, err := c.NewSubscription().Interval(20 * time.Millisecond).NotifyChannel(cc.notify).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	cc.sub = sub
	filter := ua.NewEventFilter().Select("EventType", "Changes", "SourceNode").Build()
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle: 1, Filter: ua.NewExtensionObject(filter), QueueSize: 100, DiscardOldest: true,
		},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
	return cc
}

// event waits for the next event of the Server Object and returns its
// EventType and Changes.
func (cc *changeClient) event() (uint32, []*ua.ExtensionObject) {
	cc.t.Helper()
	for {
		select {
		case msg := <-cc.notify:
			require.NoError(cc.t, msg.Error)
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || len(enl.Events) == 0 {
				continue
			}
			require.Len(cc.t, enl.Events, 1)
			f := enl.Events[0].EventFields
			require.True(cc.t, ua.NewNumericNodeID(0, id.Server).Equal(f[2].Value().(*ua.NodeID)))
			eos, _ := f[1].Value().([]*ua.ExtensionObject)
			return f[0].Value().(*ua.NodeID).IntID(), eos
		case <-cc.ctx.Done():
			cc.t.Fatal("timeout waiting for an event")
		}
	}
}

// modelChanges waits for a GeneralModelChangeEvent and returns its changes
// by Affected NodeId.
func (cc *changeClient) modelChanges() map[string]ua.ModelChangeStructureVerbMask {
	cc.t.Helper()
	typ, eos := cc.event()
	require.Equal(cc.t, uint32(id.GeneralModelChangeEventType), typ)
	m := map[string]ua.ModelChangeStructureVerbMask{}
	for _, eo := range eos {
		c, ok := eo.Value.(*ua.ModelChangeStructureDataType)
		require.True(cc.t, ok, "%T", eo.Value)
		m[c.Affected.String()] = ua.ModelChangeStructureVerbMask(c.Verb)
	}
	return m
}

// read reads the Value of nid.
func (cc *changeClient) read(nid *ua.NodeID) *ua.DataValue {
	cc.t.Helper()
	resp, err := cc.c.Read(cc.ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: nid, AttributeID: ua.AttributeIDValue}}})
	require.NoError(cc.t, err)
	return resp.Results[0]
}

// TestModelChangeEventsOverTheWire: each Node Management service changes
// the NodeVersion of the nodes it changes and reports them in one
// GeneralModelChangeEvent that a subscribed client receives (Part 3 §9.32,
// Part 5 §6.4.32, §12.16).
func TestModelChangeEventsOverTheWire(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableNodeManagement(),
		server.WithNodeVersionOnAddNodes(true))
	require.NoError(t, err)
	ns := server.NewNodeNameSpace(srv, "urn:e2e:model-change")
	folder := server.NewFolderNode(ua.NewStringNodeID(ns.ID(), "Folder"), "Folder")
	ns.AddNode(folder)
	ns.Objects().AddRef(folder, id.Organizes, true)
	folderVersion := ns.AddNodeVersion(folder).ID()
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	cc := newChangeClient(t, srv)
	version := func(nid *ua.NodeID) string {
		t.Helper()
		dv := cc.read(nid)
		require.Equal(t, ua.StatusOK, dv.Status)
		return dv.Value.Value().(string)
	}
	require.Equal(t, "0", version(folderVersion))

	// AddNodes.
	added := ua.NewStringNodeID(ns.ID(), "Added")
	ar, err := cc.c.AddNodes(cc.ctx, &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{{
		ParentNodeID:       ua.NewExpandedNodeID(folder.ID(), "", 0),
		ReferenceTypeID:    ua.NewNumericNodeID(0, id.Organizes),
		RequestedNewNodeID: ua.NewExpandedNodeID(added, "", 0),
		BrowseName:         &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "Added"},
		NodeClass:          ua.NodeClassObject,
		TypeDefinition:     ua.NewExpandedNodeID(ua.NewNumericNodeID(0, id.FolderType), "", 0),
	}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, ar.Results[0].StatusCode)
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		added.String():       ua.ModelChangeStructureVerbMaskNodeAdded | ua.ModelChangeStructureVerbMaskReferenceAdded,
		folder.ID().String(): ua.ModelChangeStructureVerbMaskReferenceAdded,
	}, cc.modelChanges())
	require.Equal(t, "1", version(folderVersion))
	// The node has its NodeVersion Property.
	br, err := cc.c.Browse(cc.ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: added, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: ua.NewNumericNodeID(0, id.HasProperty),
		IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	require.NoError(t, err)
	require.Len(t, br.Results[0].References, 1)
	require.Equal(t, "NodeVersion", br.Results[0].References[0].BrowseName.Name)
	addedVersion := br.Results[0].References[0].NodeID.NodeID
	require.Equal(t, "0", version(addedVersion))

	// AddReferences: both ends.
	hasComponent := ua.NewNumericNodeID(0, id.HasComponent)
	rr, err := cc.c.AddReferences(cc.ctx, &ua.AddReferencesRequest{ReferencesToAdd: []*ua.AddReferencesItem{{
		SourceNodeID: folder.ID(), ReferenceTypeID: hasComponent, IsForward: true,
		TargetNodeID: ua.NewExpandedNodeID(added, "", 0), TargetNodeClass: ua.NodeClassObject,
	}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, rr.Results[0])
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		added.String():       ua.ModelChangeStructureVerbMaskReferenceAdded,
		folder.ID().String(): ua.ModelChangeStructureVerbMaskReferenceAdded,
	}, cc.modelChanges())
	require.Equal(t, "2", version(folderVersion))
	require.Equal(t, "1", version(addedVersion))

	// DeleteReferences, both directions.
	dr, err := cc.c.DeleteReferences(cc.ctx, &ua.DeleteReferencesRequest{ReferencesToDelete: []*ua.DeleteReferencesItem{{
		SourceNodeID: folder.ID(), ReferenceTypeID: hasComponent, IsForward: true,
		TargetNodeID: ua.NewExpandedNodeID(added, "", 0), DeleteBidirectional: true,
	}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dr.Results[0])
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		added.String():       ua.ModelChangeStructureVerbMaskReferenceDeleted,
		folder.ID().String(): ua.ModelChangeStructureVerbMaskReferenceDeleted,
	}, cc.modelChanges())
	require.Equal(t, "3", version(folderVersion))
	require.Equal(t, "2", version(addedVersion))

	// DeleteNodes: the node and the source of its references.
	dn, err := cc.c.DeleteNodes(cc.ctx, &ua.DeleteNodesRequest{NodesToDelete: []*ua.DeleteNodesItem{{
		NodeID: added, DeleteTargetReferences: true,
	}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, dn.Results[0])
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		added.String():       ua.ModelChangeStructureVerbMaskNodeDeleted,
		folder.ID().String(): ua.ModelChangeStructureVerbMaskReferenceDeleted,
	}, cc.modelChanges())
	require.Equal(t, "4", version(folderVersion))
	require.Equal(t, ua.StatusBadNodeIDUnknown, cc.read(addedVersion).Status, "the NodeVersion went with its node")

	// A refused request changes nothing and reports nothing: the next
	// event is that of the Go API change below.
	dn, err = cc.c.DeleteNodes(cc.ctx, &ua.DeleteNodesRequest{NodesToDelete: []*ua.DeleteNodesItem{{NodeID: added}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNodeIDUnknown, dn.Results[0])
	require.True(t, folder.RemoveRef(ua.NewExpandedNodeID(ns.Objects().ID(), "", 0), ua.NewNumericNodeID(0, id.Organizes), false))
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		folder.ID().String(): ua.ModelChangeStructureVerbMaskReferenceDeleted,
	}, cc.modelChanges())
	require.Equal(t, "5", version(folderVersion))
}

// TestSemanticChangeOverTheWire: a change of a Property with the
// SemanticChange bit is reported in a SemanticChangeEvent, and the next data
// change Notification of the Variable carries the SemanticsChanged bit
// (Part 3 §5.6.2, §9.33; Part 4 §7.38.1).
func TestSemanticChangeOverTheWire(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	ns := server.NewNodeNameSpace(srv, "urn:e2e:semantic")
	level := ns.AddNewVariableStringNode("Level", 1.5)
	ns.Objects().AddRef(level, id.HasComponent, true)
	eu := server.NewVariableNode(ua.NewStringNodeID(ns.ID(), "Level.EURange"), "EURange", "0..10 m")
	require.NoError(t, eu.SetAttribute(ua.AttributeIDAccessLevel, server.DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite|ua.AccessLevelTypeSemanticChange))))
	ns.AddNode(eu)
	level.AddRef(eu, id.HasProperty, true)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	cc := newChangeClient(t, srv)

	res, err := cc.sub.Monitor(cc.ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:       &ua.ReadValueID{NodeID: level.ID(), AttributeID: ua.AttributeIDValue},
		MonitoringMode:      ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{ClientHandle: 2, QueueSize: 1},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)
	value := func() *ua.DataValue {
		t.Helper()
		for {
			select {
			case msg := <-cc.notify:
				require.NoError(t, msg.Error)
				if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok && len(dcn.MonitoredItems) > 0 {
					return dcn.MonitoredItems[len(dcn.MonitoredItems)-1].Value
				}
			case <-cc.ctx.Done():
				t.Fatal("timeout waiting for a data change")
			}
		}
	}
	require.Zero(t, value().Status&(1<<14), "the initial value")

	// A client writes the Property.
	wr, err := cc.c.Write(cc.ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID: eu.ID(), AttributeID: ua.AttributeIDValue,
		Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant("0..10 km")},
	}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, wr.Results[0])
	typ, eos := cc.event()
	require.Equal(t, uint32(id.SemanticChangeEventType), typ)
	require.Len(t, eos, 1)
	sc, ok := eos[0].Value.(*ua.SemanticChangeStructureDataType)
	require.True(t, ok, "%T", eos[0].Value)
	require.True(t, level.ID().Equal(sc.Affected))

	require.Equal(t, ua.StatusOK, ns.SetAttribute(level.ID(), ua.AttributeIDValue, server.DataValueFromValue(2.5)))
	dv := value()
	require.Equal(t, 2.5, dv.Value.Value())
	require.Equal(t, ua.StatusCode(1<<14), dv.Status&(1<<14), "SemanticsChanged")
	require.Equal(t, ua.StatusOK, ns.SetAttribute(level.ID(), ua.AttributeIDValue, server.DataValueFromValue(3.5)))
	require.Zero(t, value().Status&(1<<14), "once")
}

// TestModelChangeRestoreOverTheWire: WithModelChangeEvents(false) restores
// the old behaviour: no event, no NodeVersion change.
func TestModelChangeRestoreOverTheWire(t *testing.T) {
	t.Parallel()
	srv, err := server.New(server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableNodeManagement(),
		server.WithNodeVersionOnAddNodes(true),
		server.WithModelChangeEvents(false))
	require.NoError(t, err)
	ns := server.NewNodeNameSpace(srv, "urn:e2e:restore")
	folder := server.NewFolderNode(ua.NewStringNodeID(ns.ID(), "Folder"), "Folder")
	ns.AddNode(folder)
	folderVersion := ns.AddNodeVersion(folder).ID()
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	cc := newChangeClient(t, srv)

	added := ua.NewStringNodeID(ns.ID(), "Added")
	ar, err := cc.c.AddNodes(cc.ctx, &ua.AddNodesRequest{NodesToAdd: []*ua.AddNodesItem{{
		ParentNodeID:       ua.NewExpandedNodeID(folder.ID(), "", 0),
		ReferenceTypeID:    ua.NewNumericNodeID(0, id.Organizes),
		RequestedNewNodeID: ua.NewExpandedNodeID(added, "", 0),
		BrowseName:         &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "Added"},
		NodeClass:          ua.NodeClassObject,
		TypeDefinition:     ua.NewExpandedNodeID(ua.NewNumericNodeID(0, id.FolderType), "", 0),
	}}})
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, ar.Results[0].StatusCode)
	require.Equal(t, "0", cc.read(folderVersion).Value.Value())
	// Nothing arrives within a few publishing intervals.
	select {
	case msg := <-cc.notify:
		if enl, ok := msg.Value.(*ua.EventNotificationList); ok {
			require.Empty(t, enl.Events)
		}
	case <-time.After(300 * time.Millisecond):
	}
}
