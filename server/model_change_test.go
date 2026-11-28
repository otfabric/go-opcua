// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// changeRecorder is an event item on the Server Object that selects the
// EventType and the Changes of the events.
type changeRecorder struct {
	sub  *Subscription
	item *MonitoredItem
}

func recordChanges(t *testing.T, s *Server) *changeRecorder {
	t.Helper()
	sub := &Subscription{EventNotifyChannel: make(chan *ua.EventFieldList), shutdown: make(chan struct{})}
	item := &MonitoredItem{ID: 77, Sub: sub, isEvent: true, evQueueSize: 100, Mode: ua.MonitoringModeReporting,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor:       &ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDEventNotifier},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1},
		}}
	s.eventItems.register(item.ID, &EventMonitoredItem{SelectClauses: []*ua.SimpleAttributeOperand{
		{BrowsePath: []*ua.QualifiedName{{Name: "EventType"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "Changes"}}},
		{BrowsePath: []*ua.QualifiedName{{Name: "SourceName"}}},
	}})
	key := ua.NewNumericNodeID(0, id.Server).String()
	s.MonitoredItemService.Mu.Lock()
	s.MonitoredItemService.Nodes[key] = append(s.MonitoredItemService.Nodes[key], item)
	s.MonitoredItemService.Mu.Unlock()
	return &changeRecorder{sub: sub, item: item}
}

// recorded is an event the recorder saw.
type recorded struct {
	eventType uint32
	changes   []*ua.ModelChangeStructureDataType
	semantic  []*ua.SemanticChangeStructureDataType
}

// take returns the events recorded since the last call.
func (r *changeRecorder) take(t *testing.T) []recorded {
	t.Helper()
	r.sub.evMu.Lock()
	defer r.sub.evMu.Unlock()
	var out []recorded
	for _, q := range r.item.events {
		f := q.ef.EventFields
		require.Len(t, f, 3)
		require.Equal(t, "Server", f[2].Value())
		ev := recorded{eventType: f[0].Value().(*ua.NodeID).IntID()}
		if eos, ok := f[1].Value().([]*ua.ExtensionObject); ok {
			for _, eo := range eos {
				switch c := eo.Value.(type) {
				case *ua.ModelChangeStructureDataType:
					ev.changes = append(ev.changes, c)
				case *ua.SemanticChangeStructureDataType:
					ev.semantic = append(ev.semantic, c)
				}
			}
		}
		out = append(out, ev)
	}
	r.item.events = nil
	return out
}

// verbsOf maps the Affected NodeIds of the changes to their verbs.
func verbsOf(changes []*ua.ModelChangeStructureDataType) map[string]ua.ModelChangeStructureVerbMask {
	m := map[string]ua.ModelChangeStructureVerbMask{}
	for _, c := range changes {
		m[c.Affected.String()] = ua.ModelChangeStructureVerbMask(c.Verb)
	}
	return m
}

// nodeVersion returns the NodeVersion of n, "" without one.
func nodeVersion(t *testing.T, s *Server, n *Node) string {
	t.Helper()
	vid := n.nodeVersionID()
	if vid == nil {
		return ""
	}
	p := s.Node(vid)
	require.NotNil(t, p)
	return p.Value().Value.Value().(string)
}

func newModelChangeServer(t *testing.T, opts ...Option) (*Server, *NodeNameSpace) {
	t.Helper()
	s := newTestServer()
	for _, o := range opts {
		require.NoError(t, o(s.cfg))
	}
	return s, NewNodeNameSpace(s, "urn:test:model-change")
}

func TestModelChangeGoAPI(t *testing.T) {
	s, ns := newModelChangeServer(t)
	rec := recordChanges(t, s)
	a := NewFolderNode(ua.NewStringNodeID(ns.ID(), "A"), "A")
	b := NewFolderNode(ua.NewStringNodeID(ns.ID(), "B"), "B")
	plain := NewFolderNode(ua.NewStringNodeID(ns.ID(), "Plain"), "Plain")
	ns.AddNode(plain)
	require.Empty(t, rec.take(t), "a node without NodeVersion is not reported")

	ns.AddNode(a)
	ns.AddNode(b)
	vp := ns.AddNodeVersion(a)
	require.Same(t, vp, ns.AddNodeVersion(a), "AddNodeVersion of a node that has one")
	ns.AddNodeVersion(b)
	require.Empty(t, rec.take(t), "creating the NodeVersion is not reported")
	require.Equal(t, "0", nodeVersion(t, s, a))
	tdef := s.Node(ua.NewNumericNodeID(0, id.PropertyType))
	require.True(t, hasReference(vp, tdef.ID(), id.HasTypeDefinition, true))

	// AddRef: both ends.
	a.AddRef(b, id.Organizes, true)
	evs := rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, uint32(id.GeneralModelChangeEventType), evs[0].eventType)
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		a.ID().String(): ua.ModelChangeStructureVerbMaskReferenceAdded,
		b.ID().String(): ua.ModelChangeStructureVerbMaskReferenceAdded,
	}, verbsOf(evs[0].changes))
	require.Equal(t, "1", nodeVersion(t, s, a))
	require.Equal(t, "1", nodeVersion(t, s, b))

	// A reference both ends hold already is not added, not reported.
	a.AddRef(b, id.Organizes, true)
	require.Empty(t, rec.take(t))

	// AddReference to a node without NodeVersion: only a is reported.
	a.AddReference(plain, ua.NewNumericNodeID(0, id.HasComponent), true)
	evs = rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{a.ID().String(): ua.ModelChangeStructureVerbMaskReferenceAdded}, verbsOf(evs[0].changes))
	require.Equal(t, "2", nodeVersion(t, s, a))

	// RemoveRef.
	require.True(t, a.RemoveRef(ua.NewExpandedNodeID(b.ID(), "", 0), ua.NewNumericNodeID(0, id.Organizes), true))
	evs = rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		a.ID().String(): ua.ModelChangeStructureVerbMaskReferenceDeleted,
		b.ID().String(): ua.ModelChangeStructureVerbMaskReferenceDeleted,
	}, verbsOf(evs[0].changes))
	require.False(t, a.RemoveRef(ua.NewExpandedNodeID(b.ID(), "", 0), ua.NewNumericNodeID(0, id.Organizes), true))
	require.Empty(t, rec.take(t))

	// AddObject and AddVariable report the reference of the parent.
	obj := a.AddObject(NewFolderNode(ua.NewStringNodeID(ns.ID(), "Obj"), "Obj"))
	require.NotNil(t, obj)
	a.AddVariable(NewVariableNode(ua.NewStringNodeID(ns.ID(), "Var"), "Var", int32(1)))
	evs = rec.take(t)
	require.Len(t, evs, 2)
	require.Equal(t, "5", nodeVersion(t, s, a))

	// DeleteNode: the node and the targets that lose a reference.
	b.AddRef(a, id.HasComponent, true)
	rec.take(t)
	require.Equal(t, ua.StatusGood, ns.DeleteNode(b.ID()))
	evs = rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		b.ID().String(): ua.ModelChangeStructureVerbMaskNodeDeleted,
		a.ID().String(): ua.ModelChangeStructureVerbMaskReferenceDeleted,
	}, verbsOf(evs[0].changes))
	require.Equal(t, ua.StatusBadNodeIDUnknown, ns.DeleteNode(b.ID()))

	// A node added with a NodeVersion is reported as added, with the
	// NodeVersion it has.
	c := NewFolderNode(ua.NewStringNodeID(ns.ID(), "C"), "C")
	ns.AddNodeVersion(c)
	ns.AddNode(c)
	evs = rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{c.ID().String(): ua.ModelChangeStructureVerbMaskNodeAdded}, verbsOf(evs[0].changes))
	require.Nil(t, evs[0].changes[0].AffectedType, "a folder without type definition")
	require.Equal(t, "0", nodeVersion(t, s, c))
}

func TestModelChangeAttributes(t *testing.T) {
	s, ns := newModelChangeServer(t)
	rec := recordChanges(t, s)
	v := ns.AddNewVariableStringNode("v", int32(1))
	ft := s.Node(ua.NewNumericNodeID(0, id.BaseDataVariableType))
	v.AddRef(ft, id.HasTypeDefinition, true)
	ns.AddNodeVersion(v)
	rec.take(t)

	require.NoError(t, v.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Double))))
	evs := rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, uint32(id.GeneralModelChangeEventType), evs[0].eventType)
	require.Len(t, evs[0].changes, 1)
	require.Equal(t, uint8(ua.ModelChangeStructureVerbMaskDataTypeChanged), evs[0].changes[0].Verb)
	require.True(t, evs[0].changes[0].AffectedType.Equal(ft.ID()))
	require.Equal(t, "1", nodeVersion(t, s, v))

	// The same DataType again changes nothing.
	require.NoError(t, v.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Double))))
	require.Empty(t, rec.take(t))

	// ValueRank and ArrayDimensions: a BaseModelChangeEvent.
	require.NoError(t, v.SetAttribute(ua.AttributeIDValueRank, DataValueFromValue(int32(1))))
	require.NoError(t, v.SetAttribute(ua.AttributeIDArrayDimensions, DataValueFromValue([]uint32{3})))
	evs = rec.take(t)
	require.Len(t, evs, 2)
	for _, ev := range evs {
		require.Equal(t, uint32(id.BaseModelChangeEventType), ev.eventType)
		require.Empty(t, ev.changes)
	}
	require.Equal(t, "3", nodeVersion(t, s, v))

	// Other attributes, and the DataType of an Object, are not model changes.
	require.NoError(t, v.SetAttribute(ua.AttributeIDDescription, DataValueFromValue(ua.NewLocalizedText("d"))))
	o := NewFolderNode(ua.NewStringNodeID(ns.ID(), "o"), "o")
	ns.AddNode(o)
	ns.AddNodeVersion(o)
	require.NoError(t, o.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Double))))
	require.Empty(t, rec.take(t))

	// A NodeVersion that is not a number starts again at 1.
	p := s.Node(v.nodeVersionID())
	p.SetValueFunc(func() *ua.DataValue { return DataValueFromValue("v7") })
	require.NoError(t, v.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Float))))
	require.Equal(t, "1", nodeVersion(t, s, v))
	// A NodeVersion Property that is gone is not changed; the change is
	// reported.
	_ = ns.DeleteNode(p.ID())
	rec.take(t)
	require.NoError(t, v.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Int16))))
	require.Len(t, rec.take(t), 1)
}

func TestModelChangeDisabled(t *testing.T) {
	s, ns := newModelChangeServer(t, WithModelChangeEvents(false))
	rec := recordChanges(t, s)
	a := NewFolderNode(ua.NewStringNodeID(ns.ID(), "A"), "A")
	ns.AddNode(a)
	ns.AddNodeVersion(a)
	b := ns.AddNewVariableStringNode("b", int32(1))
	a.AddRef(b, id.Organizes, true)
	a.RemoveRef(ua.NewExpandedNodeID(b.ID(), "", 0), ua.NewNumericNodeID(0, id.Organizes), true)
	require.NoError(t, b.SetAttribute(ua.AttributeIDDataType, DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Double))))
	_ = ns.DeleteNode(a.ID())
	require.Empty(t, rec.take(t))
	require.Equal(t, "0", nodeVersion(t, s, a), "NodeVersion is not maintained")

	// SemanticChange is off too.
	eu := semanticProperty(t, ns, b, "EngineeringUnits", "m")
	require.NoError(t, eu.SetAttribute(ua.AttributeIDValue, DataValueFromValue("km")))
	require.Empty(t, rec.take(t))
}

// semanticProperty adds to owner a Property name with the SemanticChange
// bit and the value v.
func semanticProperty(t *testing.T, ns *NodeNameSpace, owner *Node, name string, v any) *Node {
	t.Helper()
	p := NewVariableNode(ua.NewStringNodeID(ns.ID(), owner.ID().StringID()+"."+name), name, v)
	require.NoError(t, p.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeSemanticChange))))
	ns.AddNode(p)
	owner.AddRef(p, id.HasProperty, true)
	return p
}

func TestSemanticChange(t *testing.T) {
	s, ns := newModelChangeServer(t)
	rec := recordChanges(t, s)
	v := ns.AddNewVariableStringNode("level", 1.5)
	vt := s.Node(ua.NewNumericNodeID(0, id.BaseDataVariableType))
	v.AddRef(vt, id.HasTypeDefinition, true)
	eu := semanticProperty(t, ns, v, "EngineeringUnits", "m")
	plain := NewVariableNode(ua.NewStringNodeID(ns.ID(), "level.Icon"), "Icon", "x")
	ns.AddNode(plain)
	v.AddRef(plain, id.HasProperty, true)
	orphan := NewVariableNode(ua.NewStringNodeID(ns.ID(), "orphan"), "orphan", "a")
	require.NoError(t, orphan.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(uint32(ua.AccessLevelTypeSemanticChange))))
	ns.AddNode(orphan)
	rec.take(t)

	// A data item of the Value of v.
	item := &MonitoredItem{ID: 5, queueSize: 2, discardOldest: true, Mode: ua.MonitoringModeReporting,
		Req: &ua.MonitoredItemCreateRequest{ItemToMonitor: &ua.ReadValueID{NodeID: v.ID(), AttributeID: ua.AttributeIDValue}}}
	ev := &MonitoredItem{ID: 6, isEvent: true, Req: &ua.MonitoredItemCreateRequest{ItemToMonitor: &ua.ReadValueID{NodeID: v.ID(), AttributeID: ua.AttributeIDEventNotifier}}}
	s.MonitoredItemService.Mu.Lock()
	s.MonitoredItemService.Nodes[v.ID().String()] = []*MonitoredItem{item, ev, nil}
	s.MonitoredItemService.Mu.Unlock()

	require.NoError(t, eu.SetAttribute(ua.AttributeIDValue, DataValueFromValue("km")))
	evs := rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, uint32(id.SemanticChangeEventType), evs[0].eventType)
	require.Len(t, evs[0].semantic, 1)
	require.True(t, evs[0].semantic[0].Affected.Equal(v.ID()))
	require.True(t, evs[0].semantic[0].AffectedType.Equal(vt.ID()))
	require.False(t, ev.semanticsPending)

	// The next notification of the item carries SemanticsChanged, once.
	s.MonitoredItemService.Mu.Lock()
	n1 := &ua.MonitoredItemNotification{Value: &ua.DataValue{}}
	n2 := &ua.MonitoredItemNotification{Value: &ua.DataValue{}}
	item.enqueue(n1)
	item.enqueue(n2)
	s.MonitoredItemService.Mu.Unlock()
	require.Equal(t, statusSemanticsChanged, n1.Value.Status)
	require.NotZero(t, n1.Value.EncodingMask&ua.DataValueStatusCode)
	require.Zero(t, n2.Value.Status)

	// The same value again, a Property without the bit, and a node that is
	// no Property: nothing.
	require.NoError(t, eu.SetAttribute(ua.AttributeIDValue, DataValueFromValue("km")))
	require.NoError(t, plain.SetAttribute(ua.AttributeIDValue, DataValueFromValue("y")))
	require.NoError(t, orphan.SetAttribute(ua.AttributeIDValue, DataValueFromValue("b")))
	require.Empty(t, rec.take(t))
	require.Equal(t, "", nodeVersion(t, s, v), "no NodeVersion change (Part 3 §9.33.2)")
}

// The SemanticsChanged bit of a notification the queue drops moves to the
// next one (Part 4 §7.38.1).
func TestSemanticsChangedOverflow(t *testing.T) {
	mark := func(item *MonitoredItem) {
		item.semanticsPending = true
	}
	carries := func(n *ua.MonitoredItemNotification) bool {
		return n.Value.Status&statusSemanticsChanged != 0
	}
	newN := func() *ua.MonitoredItemNotification { return &ua.MonitoredItemNotification{Value: &ua.DataValue{}} }

	// QueueSize 1: the newer sample replaces the marked one.
	one := &MonitoredItem{queueSize: 1}
	mark(one)
	a, b := newN(), newN()
	one.enqueue(a)
	one.enqueue(b)
	require.True(t, carries(b))

	// DiscardOldest: the oldest goes, the next oldest takes the bit.
	old := &MonitoredItem{queueSize: 2, discardOldest: true}
	mark(old)
	a, b, c := newN(), newN(), newN()
	old.enqueue(a)
	old.enqueue(b)
	old.enqueue(c)
	require.Same(t, b, old.queue[0])
	require.True(t, carries(b))
	require.False(t, carries(c))

	// DiscardNewest: the newest is replaced by the one that arrives.
	newest := &MonitoredItem{queueSize: 2}
	a, b, c = newN(), newN(), newN()
	newest.enqueue(a)
	mark(newest)
	newest.enqueue(b)
	newest.enqueue(c)
	require.Same(t, c, newest.queue[1])
	require.True(t, carries(c))

	// Nothing to move.
	dropSemantics(nil, a)
	dropSemantics(newN(), nil)
	(&MonitoredItem{semanticsPending: true}).markSemantics(&ua.MonitoredItemNotification{})
}

func TestModelChangeNodeManagementBatch(t *testing.T) {
	s, ns := newModelChangeServer(t, EnableNodeManagement(), WithNodeVersionOnAddNodes(true))
	rec := recordChanges(t, s)
	parent := NewFolderNode(ua.NewStringNodeID(ns.ID(), "P"), "P")
	ns.AddNode(parent)
	ns.AddNodeVersion(parent)
	svc := &NodeManagementService{srv: s}
	ctx := context.Background()

	add := func(name string) *ua.AddNodesItem {
		return &ua.AddNodesItem{
			ParentNodeID:       ua.NewExpandedNodeID(parent.ID(), "", 0),
			ReferenceTypeID:    ua.NewNumericNodeID(0, id.Organizes),
			RequestedNewNodeID: ua.NewExpandedNodeID(ua.NewStringNodeID(ns.ID(), name), "", 0),
			BrowseName:         &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: name},
			NodeClass:          ua.NodeClassObject,
		}
	}
	r, err := svc.AddNodes(ctx, nil, &ua.AddNodesRequest{RequestHeader: reqHeader(), NodesToAdd: []*ua.AddNodesItem{add("x"), add("y"), nil}}, 1)
	require.NoError(t, err)
	res := r.(*ua.AddNodesResponse).Results
	require.Equal(t, ua.StatusGood, res[0].StatusCode)
	require.Equal(t, ua.StatusGood, res[1].StatusCode)
	evs := rec.take(t)
	require.Len(t, evs, 1, "one event for the request")
	x, y := s.Node(res[0].AddedNodeID), s.Node(res[1].AddedNodeID)
	added := ua.ModelChangeStructureVerbMaskNodeAdded | ua.ModelChangeStructureVerbMaskReferenceAdded
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		x.ID().String():      added,
		y.ID().String():      added,
		parent.ID().String(): ua.ModelChangeStructureVerbMaskReferenceAdded,
	}, verbsOf(evs[0].changes))
	require.Equal(t, "1", nodeVersion(t, s, parent), "once for the request")
	require.Equal(t, "0", nodeVersion(t, s, x))
	vid := x.nodeVersionID()

	// DeleteNodes deletes the NodeVersion Property with its node.
	r, err = svc.DeleteNodes(ctx, nil, &ua.DeleteNodesRequest{RequestHeader: reqHeader(), NodesToDelete: []*ua.DeleteNodesItem{
		{NodeID: x.ID(), DeleteTargetReferences: true},
	}}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, r.(*ua.DeleteNodesResponse).Results[0])
	require.Nil(t, s.Node(vid))
	evs = rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{
		x.ID().String():      ua.ModelChangeStructureVerbMaskNodeDeleted,
		parent.ID().String(): ua.ModelChangeStructureVerbMaskReferenceDeleted,
	}, verbsOf(evs[0].changes))

	// A request that changes nothing reports nothing.
	_, err = svc.DeleteNodes(ctx, nil, &ua.DeleteNodesRequest{RequestHeader: reqHeader(), NodesToDelete: []*ua.DeleteNodesItem{{NodeID: x.ID()}}}, 1)
	require.NoError(t, err)
	_, err = svc.AddReferences(ctx, nil, &ua.AddReferencesRequest{RequestHeader: reqHeader(), ReferencesToAdd: []*ua.AddReferencesItem{{
		SourceNodeID: parent.ID(), ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes), IsForward: true,
		TargetNodeID: ua.NewExpandedNodeID(y.ID(), "", 0),
	}}}, 1)
	require.NoError(t, err)
	require.Empty(t, rec.take(t))
}

// Without WithNodeVersionOnAddNodes the nodes AddNodes adds have no
// NodeVersion: only a parent with one is reported.
func TestModelChangeAddNodesWithoutNodeVersion(t *testing.T) {
	s, ns := newModelChangeServer(t, EnableNodeManagement())
	rec := recordChanges(t, s)
	parent := NewFolderNode(ua.NewStringNodeID(ns.ID(), "P"), "P")
	ns.AddNode(parent)
	ns.AddNodeVersion(parent)
	svc := &NodeManagementService{srv: s}
	r, err := svc.AddNodes(context.Background(), nil, &ua.AddNodesRequest{RequestHeader: reqHeader(), NodesToAdd: []*ua.AddNodesItem{{
		ParentNodeID:       ua.NewExpandedNodeID(parent.ID(), "", 0),
		ReferenceTypeID:    ua.NewNumericNodeID(0, id.Organizes),
		RequestedNewNodeID: ua.NewExpandedNodeID(ua.NewStringNodeID(ns.ID(), "x"), "", 0),
		BrowseName:         &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "x"},
		NodeClass:          ua.NodeClassObject,
	}}}, 1)
	require.NoError(t, err)
	x := s.Node(r.(*ua.AddNodesResponse).Results[0].AddedNodeID)
	require.Nil(t, x.nodeVersionID())
	evs := rec.take(t)
	require.Len(t, evs, 1)
	require.Equal(t, map[string]ua.ModelChangeStructureVerbMask{parent.ID().String(): ua.ModelChangeStructureVerbMaskReferenceAdded}, verbsOf(evs[0].changes))
}

// An import brings the NodeVersion of the NodeSet and reports nothing.
func TestModelChangeImportReportsNothing(t *testing.T) {
	s, _ := newModelChangeServer(t)
	rec := recordChanges(t, s)
	doc := []byte(`<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <Aliases><Alias Alias="Organizes">i=35</Alias><Alias Alias="HasProperty">i=46</Alias><Alias Alias="HasComponent">i=47</Alias><Alias Alias="HasTypeDefinition">i=40</Alias></Aliases>
  <NamespaceUris><Uri>urn:test:model-change</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;i=1" BrowseName="1:Obj">
    <DisplayName>Obj</DisplayName>
    <References>
      <Reference ReferenceType="Organizes" IsForward="false">i=85</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=2</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=2" BrowseName="NodeVersion" DataType="i=12" ParentNodeId="ns=1;i=1">
    <DisplayName>NodeVersion</DisplayName>
    <Value><String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">7</String></Value>
  </UAVariable>
</UANodeSet>`)
	require.NoError(t, s.ImportNodeSetXML(doc))
	require.Empty(t, rec.take(t))
	obj := s.Node(ua.NewNumericNodeID(1, 1))
	require.NotNil(t, obj)
	require.Equal(t, "7", nodeVersion(t, s, obj))
	// From then on its changes are reported.
	obj.AddRef(s.Node(ua.NewNumericNodeID(0, id.FolderType)), id.HasTypeDefinition, true)
	evs := rec.take(t)
	require.Len(t, evs, 1)
	require.True(t, evs[0].changes[0].AffectedType.Equal(ua.NewNumericNodeID(0, id.FolderType)))
	require.Equal(t, "8", nodeVersion(t, s, obj))
}

// Concurrent updates of one node each get their own NodeVersion.
func TestModelChangeConcurrent(t *testing.T) {
	s, ns := newModelChangeServer(t)
	a := NewFolderNode(ua.NewStringNodeID(ns.ID(), "A"), "A")
	ns.AddNode(a)
	ns.AddNodeVersion(a)
	const workers, each = 8, 20
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				n := NewFolderNode(ua.NewNumericNodeID(ns.ID(), uint32(10000+w*each+i)), "n")
				ns.AddNode(n)
				ns.AddNodeVersion(n)
				a.AddRef(n, id.Organizes, true)
			}
		}(w)
	}
	wg.Wait()
	require.Equal(t, "160", nodeVersion(t, s, a))
}

func TestNodeVersionHelpers(t *testing.T) {
	var nilNode *Node
	require.Nil(t, nilNode.server())
	(*modelChanges)(nil).noteStructure(nil)
	(*modelChanges)(nil).flush()
	var nilSrv *Server
	require.Nil(t, nilSrv.modelChanges())
	nilSrv.semanticChange(nil)
	require.False(t, hasAccessBit(nil, ua.AccessLevelTypeSemanticChange))
	require.False(t, hasAccessBit(DataValueFromValue("x"), ua.AccessLevelTypeSemanticChange))
	require.True(t, sameValue(nil, &ua.DataValue{}))
	s := newTestServer()
	// A NodeVersion that is gone is not changed.
	s.bumpNodeVersion(ua.NewStringNodeID(0, "missing"))
	// The reference to the NodeVersion of a node.
	ref := &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasProperty), IsForward: true,
		BrowseName: &ua.QualifiedName{Name: nodeVersionName}, NodeID: ua.NewExpandedNodeID(ua.NewStringNodeID(1, "v"), "", 0),
	}
	require.True(t, isNodeVersionRef(ref))
	ref.BrowseName = &ua.QualifiedName{NamespaceIndex: 1, Name: nodeVersionName}
	require.False(t, isNodeVersionRef(ref))
}

// The guards of the model change code: namespaces that are no
// NodeNameSpace and Properties with other references.
func TestModelChangeGuards(t *testing.T) {
	s, ns := newModelChangeServer(t, EnableNodeManagement(), WithNodeVersionOnAddNodes(true))
	rec := recordChanges(t, s)
	svc := &NodeManagementService{srv: s}
	ctx := context.Background()

	// AddNodes and DeleteNodes in a MapNamespace: its nodes have no
	// NodeVersion, nothing is reported.
	mns := NewMapNamespace(s, "urn:test:map")
	mid := ua.NewStringNodeID(mns.ID(), "m")
	r, err := svc.AddNodes(ctx, nil, &ua.AddNodesRequest{RequestHeader: reqHeader(), NodesToAdd: []*ua.AddNodesItem{{
		RequestedNewNodeID: ua.NewExpandedNodeID(mid, "", 0),
		BrowseName:         &ua.QualifiedName{NamespaceIndex: mns.ID(), Name: "m"},
		NodeClass:          ua.NodeClassObject,
	}}}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusGood, r.(*ua.AddNodesResponse).Results[0].StatusCode)
	d, err := svc.DeleteNodes(ctx, nil, &ua.DeleteNodesRequest{RequestHeader: reqHeader(), NodesToDelete: []*ua.DeleteNodesItem{{NodeID: mid}}}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNodeIDUnknown, d.(*ua.DeleteNodesResponse).Results[0])
	require.Empty(t, rec.take(t))

	// The owner of a Property is the source of its inverse HasProperty
	// Reference, whatever other References it has.
	owner := NewFolderNode(ua.NewStringNodeID(ns.ID(), "Owner"), "Owner")
	ns.AddNode(owner)
	p := NewVariableNode(ua.NewStringNodeID(ns.ID(), "Owner.P"), "P", int32(1))
	ns.AddNode(p)
	p.AddRef(owner, id.Organizes, true)
	require.Nil(t, p.propertyOwner())
	owner.AddRef(p, id.HasProperty, true)
	require.Same(t, owner, p.propertyOwner())

	// The AffectedType of a node that is no Object or Variable is null.
	require.Nil(t, affectedType(s.Node(ua.NewNumericNodeID(0, id.FolderType))))
}
