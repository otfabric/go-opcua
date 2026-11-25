// SPDX-License-Identifier: MIT

package fxserver

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// The projection of the sets of the Manager (§6.8.2 Table 89): one
// ConnectionConfigurationSetType Object per set, below
// ConnectionConfigurationSets or the Folders its
// ConnectionConfigurationSetFolder names, with string NodeIds derived from
// the path of the set, so that a set keeps its NodeIds over commits and
// replacements. The values are computed under ConnectionManager.mu and
// read without a lock.

// cmSet is the projection of one set.
type cmSet struct {
	key    fxcm.SetKey
	id     *ua.NodeID
	parent *ua.NodeID // the Folder of the set
	nodes  []*ua.NodeID
	vars   []*cmVar
	byID   map[string]*cmVar
	shape  string
	lock   *setLock

	// The edit started by EditConnectionConfigurationSets, nil when the
	// set is not in edit through the Method.
	edit       *fxcm.Edit
	owner      fxcm.LockOwner
	lockClient string
	lockUser   string
	deadline   time.Time
}

// cmVar is a Variable of a set whose value is derived from the set.
type cmVar struct {
	id  *ua.NodeID
	get func(v *cmView) any
	cur atomic.Pointer[ua.DataValue]
	enc []byte
	// write applies a client's write to the working copy of the set in
	// edit (§6.8.1); nil for a Variable that is not writable.
	write func(conf *uafx.ConnectionConfigurationSetConf, v *ua.Variant) ua.StatusCode
	// set is the set of the Variable; name its BrowseName.
	set  *cmSet
	name string
}

// cmView is what a value is derived from.
type cmView struct {
	conf *uafx.ConnectionConfigurationSetConf
	st   fxcm.Status
	set  *cmSet
	c    *ConnectionManager
}

func (v *cmVar) value() *ua.DataValue {
	if dv := v.cur.Load(); dv != nil {
		return dv
	}
	return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadWaitingForInitialData}
}

// --- nodes ------------------------------------------------------------------

// nodeBuilder adds nodes in the CM namespace and records them in list.
type nodeBuilder struct {
	c    *ConnectionManager
	list *[]*ua.NodeID
}

func (c *ConnectionManager) builder(list *[]*ua.NodeID) *nodeBuilder {
	return &nodeBuilder{c: c, list: list}
}

func dt0(i uint32) *ua.NodeID { return ua.NewNumericNodeID(0, i) }

func (b *nodeBuilder) add(n *server.Node, typ *ua.NodeID) error {
	ns, err := b.c.srv.Namespace(int(n.ID().Namespace()))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConnectionManager, err)
	}
	if old := b.c.srv.Node(n.ID()); old != nil {
		return fmt.Errorf("%w: the node %v exists", ErrConnectionManager, n.ID())
	}
	ns.AddNode(n)
	*b.list = append(*b.list, n.ID())
	if typ != nil {
		if t := b.c.srv.Node(typ); t != nil {
			n.AddReference(t, ua.NewNumericNodeID(0, id.HasTypeDefinition), true)
		}
	}
	return nil
}

// object adds an Object of the type typ.
func (b *nodeBuilder) object(sid string, bn *ua.QualifiedName, typ *ua.NodeID) (*server.Node, error) {
	n := server.NewFolderNode(ua.NewStringNodeID(b.c.ns.CM, sid), bn.Name)
	if err := setAttrs(n, map[ua.AttributeID]any{ua.AttributeIDBrowseName: bn}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectionManager, err)
	}
	return n, b.add(n, typ)
}

// variable adds a BaseDataVariable whose value get returns on each read.
func (b *nodeBuilder) variable(parent *ua.NodeID, sid string, bn *ua.QualifiedName, dt *ua.NodeID, rank int32, get func() any) (*server.Node, error) {
	return b.variableOf(sid, bn, dt, rank, dt0(id.BaseDataVariableType), false,
		server.ValueFunc(func() *ua.DataValue { return server.DataValueFromValue(get()) }))
}

func (b *nodeBuilder) variableOf(sid string, bn *ua.QualifiedName, dt *ua.NodeID, rank int32, typ *ua.NodeID, writable bool, val server.ValueFunc) (*server.Node, error) {
	n := server.NewVariableNode(ua.NewStringNodeID(b.c.ns.CM, sid), bn.Name, val)
	access := byte(ua.AccessLevelTypeCurrentRead)
	if writable {
		access |= byte(ua.AccessLevelTypeCurrentWrite)
	}
	attrs := map[ua.AttributeID]any{
		ua.AttributeIDBrowseName:      bn,
		ua.AttributeIDDataType:        ua.NewExpandedNodeID(dt, "", 0),
		ua.AttributeIDValueRank:       rank,
		ua.AttributeIDAccessLevel:     access,
		ua.AttributeIDUserAccessLevel: access,
	}
	if rank == 1 {
		attrs[ua.AttributeIDArrayDimensions] = []uint32{0}
	}
	if err := setAttrs(n, attrs); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectionManager, err)
	}
	return n, b.add(n, typ)
}

// --- the sets ---------------------------------------------------------------

// idEscaper escapes the characters the String NodeIds of the sets use as
// separators, so that no two names give the same NodeId: a set "A.Version"
// is not the Version of a set "A", a Folder "a/b" not the Folders a and b.
var idEscaper = strings.NewReplacer("%", "%25", "/", "%2F", ".", "%2E", "[", "%5B", "]", "%5D")

// idPart is a name as a part of a String NodeId of the ConnectionManager.
func idPart(name string) string { return idEscaper.Replace(name) }

// idPath is the escaped names of path joined with "/".
func idPath(path []string) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = idPart(p)
	}
	return strings.Join(parts, "/")
}

// setNodeID is the NodeId of the Object of a set.
func (c *ConnectionManager) setNodeID(k fxcm.SetKey) string {
	return "cm.set:" + idPath(append(append([]string{}, k.Folder...), k.Name))
}

// syncSetLocked brings the projection of key up to date with the Manager:
// it adds, rebuilds, updates or removes it. c.mu is held.
func (c *ConnectionManager) syncSetLocked(k fxcm.SetKey) {
	cfg, ok := c.m.Config(k)
	s := c.sets[k.String()]
	if !ok {
		if s != nil {
			c.dropSetLocked(s)
		}
		return
	}
	st, _ := c.m.Status(k)
	if !st.Editing && s != nil && s.edit != nil {
		s.edit, s.owner = nil, ""
	}
	conf := cfg.Conf()
	if s != nil && s.edit != nil {
		conf = s.edit.Conf()
	}
	shape := shapeOf(conf)
	if s == nil || s.shape != shape {
		var keep *cmSet
		if s != nil {
			keep = s
			c.dropSetLocked(s)
		}
		ns, err := c.buildSetLocked(k, conf, shape)
		if err != nil {
			c.log.Warn("uafx: ConnectionConfigurationSet not exposed", "set", k.String(), "err", err)
			return
		}
		if keep != nil {
			ns.edit, ns.owner, ns.lockClient, ns.lockUser, ns.deadline = keep.edit, keep.owner, keep.lockClient, keep.lockUser, keep.deadline
		}
		s = ns
	}
	c.refreshSetLocked(s, &cmView{conf: conf, st: st, set: s, c: c})
}

// refreshSetLocked recomputes the values of s and notifies the changed ones.
func (c *ConnectionManager) refreshSetLocked(s *cmSet, v *cmView) {
	for _, x := range s.vars {
		val := x.get(v)
		dv := server.DataValueFromValue(val)
		enc, err := ua.Encode(dv.Value)
		if err == nil && x.enc != nil && bytes.Equal(enc, x.enc) {
			continue
		}
		x.enc = enc
		dv.SourceTimestamp = time.Now()
		dv.EncodingMask |= ua.DataValueSourceTimestamp
		x.cur.Store(dv)
		c.srv.ChangeNotification(x.id)
	}
}

// shapeOf is the structure of a set: what decides which nodes and
// References it has.
func shapeOf(conf *uafx.ConnectionConfigurationSetConf) string {
	// Names are quoted, so that no Name can look like a delimiter; the
	// indexes are the ones the References follow (ToOutboundFlow,
	// ToInboundFlow, ToConnectionEndpointConfiguration), -1 when the
	// builder adds no Reference.
	nflows := len(conf.CommunicationFlows)
	flow := func(i int32) int32 {
		if i < 0 || int(i) >= nflows {
			return -1
		}
		return i
	}
	var b strings.Builder
	for _, s := range conf.ServerAddresses {
		fmt.Fprintf(&b, "S%q;", s.BrowseName)
	}
	for _, a := range conf.AutomationComponentConfigurations {
		fmt.Fprintf(&b, "A%q/%d;", a.BrowseName, a.ServerAddressIndex)
	}
	for _, f := range conf.CommunicationFlows {
		p, ok := f.(*uafx.PubSubCommunicationFlowConfigurationConf)
		if !ok {
			b.WriteString("F?;")
			continue
		}
		fmt.Fprintf(&b, "F%q/%t%t%t%t%t%t", p.BrowseName, p.Address != nil, p.TransportProfileURI != nil,
			p.HeaderLayoutURI != nil, p.PublishingInterval != nil, p.SecurityMode != nil, p.SecurityGroupID != nil)
		for _, sc := range p.SubscriberConfigurations {
			fmt.Fprintf(&b, "/%q%t", sc.BrowseName, sc.Address != nil)
		}
		b.WriteString(";")
	}
	for _, cn := range conf.Connections {
		fmt.Fprintf(&b, "C%q", cn.BrowseName)
		for _, e := range []*uafx.ConnectionEndpointConfigurationConf{cn.Endpoint1, cn.Endpoint2} {
			if e == nil {
				b.WriteString("/-")
				continue
			}
			out, in := int32(-1), int32(-1)
			if e.OutboundFlowIndex != nil {
				out = flow(*e.OutboundFlowIndex)
			}
			if len(e.InboundFlowIndex) > 0 {
				in = flow(e.InboundFlowIndex[0])
			}
			fmt.Fprintf(&b, "/%d,%d,%d", e.AutomationComponentIndex, out, in)
		}
		b.WriteString(";")
	}
	return b.String()
}

// folderLocked returns the Folder of a set, creating the sub-Folders its
// ConnectionConfigurationSetFolder names (F.3.3.2: ElementAdd creates
// missing Folders).
func (c *ConnectionManager) folderLocked(path []string) (*ua.NodeID, error) {
	parent := c.folder
	for i := range path {
		k := idPath(path[:i+1])
		if f, ok := c.folders[k]; ok {
			parent = f
			continue
		}
		b := c.builder(&c.nodes)
		f, err := b.object("cm.folder:"+k, qn(c.ns.CM, path[i]), dt0(id.FolderType))
		if err != nil {
			return nil, err
		}
		c.srv.Node(parent).AddRef(f, server.RefTypeIDOrganizes, true)
		c.srv.ChangeNotification(parent)
		c.folders[k] = f.ID()
		parent = f.ID()
	}
	return parent, nil
}

func (c *ConnectionManager) dropSetLocked(s *cmSet) {
	if p := c.srv.Node(s.parent); p != nil {
		p.RemoveRef(ua.NewExpandedNodeID(s.id, "", 0), dt0(id.HasComponent), true)
		p.RemoveRef(ua.NewExpandedNodeID(s.id, "", 0), dt0(id.Organizes), true)
	}
	for i := len(s.nodes) - 1; i >= 0; i-- {
		c.deleteNode(s.nodes[i])
	}
	delete(c.sets, s.key.String())
	delete(c.byNode, s.id.String())
	c.srv.ChangeNotification(s.parent)
}

// ref adds a forward Reference of type t from a to b.
func (c *ConnectionManager) ref(a, b *server.Node, t uint32, ns uint16) {
	a.AddReference(b, ua.NewNumericNodeID(ns, t), true)
}

func (c *ConnectionManager) buildSetLocked(k fxcm.SetKey, conf *uafx.ConnectionConfigurationSetConf, shape string) (*cmSet, error) {
	parent, err := c.folderLocked(k.Folder)
	if err != nil {
		return nil, err
	}
	sid := c.setNodeID(k)
	s := &cmSet{key: k, parent: parent, shape: shape, byID: map[string]*cmVar{}}
	b := c.builder(&s.nodes)
	cmNS := c.ns.CM
	obj, err := b.object(sid, qn(cmNS, k.Name), ua.NewNumericNodeID(cmNS, fxcmid.ConnectionConfigurationSetType))
	if err != nil {
		return nil, err
	}
	s.id = obj.ID()
	ok := false
	defer func() {
		if !ok {
			for i := len(s.nodes) - 1; i >= 0; i-- {
				c.deleteNode(s.nodes[i])
			}
		}
	}()
	pb := &projector{c: c, b: b, s: s}

	// The state machine (§6.9.2).
	sm, err := b.object(sid+".StateMachine", qn(cmNS, "ConnectionConfigurationSetStateMachine"), ua.NewNumericNodeID(cmNS, fxcmid.ConnectionConfigurationSetStateMachineType))
	if err != nil {
		return nil, err
	}
	obj.AddRef(sm, server.RefTypeIDHasComponent, true)
	cur, err := pb.v(sm, sid+".CurrentState", qn(0, "CurrentState"), dt0(id.LocalizedText), -1, dt0(id.FiniteStateVariableType), false,
		func(v *cmView) any { return ua.NewLocalizedText(v.st.State.String()) })
	if err != nil {
		return nil, err
	}
	if _, err := pb.p(cur, sid+".CurrentState.Id", qn(0, "Id"), dt0(id.NodeID), -1,
		func(v *cmView) any { return ua.NewNumericNodeID(cmNS, v.st.State.ID()) }); err != nil {
		return nil, err
	}
	last, err := pb.v(sm, sid+".LastTransition", qn(0, "LastTransition"), dt0(id.LocalizedText), -1, dt0(id.FiniteTransitionVariableType), false,
		func(v *cmView) any { return ua.NewLocalizedText(v.st.Transition.String()) })
	if err != nil {
		return nil, err
	}
	if _, err := pb.p(last, sid+".LastTransition.Id", qn(0, "Id"), dt0(id.NodeID), -1, func(v *cmView) any {
		if t := v.st.Transition; t != 0 {
			return ua.NewNumericNodeID(cmNS, t.ID())
		}
		return ua.NewTwoByteNodeID(0)
	}); err != nil {
		return nil, err
	}

	// The Lock (§6.8.2, OPC 10000-100 §7).
	if err := c.buildLock(pb, obj, sid); err != nil {
		return nil, err
	}

	if _, err := pb.p(obj, sid+".RollbackOnError", qn(cmNS, "RollbackOnError"), dt0(id.Boolean), -1,
		func(v *cmView) any { return v.conf.RollbackOnError }); err != nil {
		return nil, err
	}
	if c.opts.Editable {
		if _, err := pb.p(obj, sid+".Edit", qn(cmNS, "Edit"), dt0(id.Boolean), -1,
			func(v *cmView) any { return v.st.Editing }); err != nil {
			return nil, err
		}
	}
	if _, err := pb.v(obj, sid+".Version", qn(cmNS, "Version"), dt0(id.UInt32), -1, dt0(id.BaseDataVariableType), false,
		func(v *cmView) any { return v.st.Version }); err != nil {
		return nil, err
	}
	if _, err := pb.v(obj, sid+".ConnectionsDiagnostics", qn(cmNS, "ConnectionsDiagnostics"), ua.NewNumericNodeID(cmNS, fxcmid.ConnectionDiagnosticsDataType), 1, dt0(id.BaseDataVariableType), false,
		func(v *cmView) any { return c.diagnostics(v.st.Diagnostics) }); err != nil {
		return nil, err
	}

	servers, err := pb.servers(obj, sid, conf)
	if err != nil {
		return nil, err
	}
	acs, err := pb.acs(obj, sid, conf, servers)
	if err != nil {
		return nil, err
	}
	flows, err := pb.flows(obj, sid, conf)
	if err != nil {
		return nil, err
	}
	if err := pb.connections(obj, sid, conf, acs, flows); err != nil {
		return nil, err
	}

	var rt server.RefType = server.RefTypeIDHasComponent
	if len(k.Folder) > 0 {
		rt = server.RefTypeIDOrganizes
	}
	c.srv.Node(parent).AddRef(obj, rt, true)
	c.srv.ChangeNotification(parent)
	c.sets[k.String()] = s
	c.byNode[s.id.String()] = s
	ok = true
	return s, nil
}

// diagnostics encodes ConnectionsDiagnostics (§6.8.2).
func (c *ConnectionManager) diagnostics(ds []*uafx.ConnectionDiagnostics) []*ua.ExtensionObject {
	out := make([]*ua.ExtensionObject, 0, len(ds))
	for _, d := range ds {
		eo, err := uafx.EncodeStructure(d, c.idx())
		if err != nil {
			continue
		}
		out = append(out, eo)
	}
	return out
}

func (c *ConnectionManager) idx() uafx.NamespaceIndexes {
	return uafx.NamespaceIndexes{Data: c.ns.Data, AC: c.ns.AC, CM: c.ns.CM}
}

// projector builds the members of one set.
type projector struct {
	c *ConnectionManager
	b *nodeBuilder
	s *cmSet
}

// v adds a Variable component of parent whose value get derives.
func (p *projector) v(parent *server.Node, sid string, bn *ua.QualifiedName, dt *ua.NodeID, rank int32, typ *ua.NodeID, writable bool, get func(*cmView) any) (*cmVar, error) {
	x := &cmVar{get: get, set: p.s, name: bn.Name}
	n, err := p.b.variableOf(sid, bn, dt, rank, typ, writable, x.value)
	if err != nil {
		return nil, err
	}
	x.id = n.ID()
	parent.AddRef(n, server.RefTypeIDHasComponent, true)
	p.s.vars = append(p.s.vars, x)
	p.s.byID[x.id.String()] = x
	return x, nil
}

// p adds a Property of the node of parent.
func (p *projector) p(parent any, sid string, bn *ua.QualifiedName, dt *ua.NodeID, rank int32, get func(*cmView) any) (*cmVar, error) {
	var pn *server.Node
	switch x := parent.(type) {
	case *server.Node:
		pn = x
	case *cmVar:
		pn = p.c.srv.Node(x.id)
	}
	x := &cmVar{get: get, set: p.s, name: bn.Name}
	n, err := p.b.variableOf(sid, bn, dt, rank, dt0(id.PropertyType), false, x.value)
	if err != nil {
		return nil, err
	}
	x.id = n.ID()
	pn.AddReference(n, dt0(id.HasProperty), true)
	p.s.vars = append(p.s.vars, x)
	p.s.byID[x.id.String()] = x
	return x, nil
}

// sel adds a SelectionListType Variable (OPC 10000-5 §7.18, Part 81
// §6.8.1, F.1.2.3): its value, the Selections Property and RestrictToList,
// TRUE unless the <Var>Modify field is TRUE. write is nil for a Variable
// that is not writable.
func (p *projector) sel(parent *server.Node, sid, name string, dt *ua.NodeID, s selection) (*cmVar, error) {
	x, err := p.v(parent, sid+"."+name, qn(p.c.ns.CM, name), dt, -1, dt0(id.SelectionListType), s.write != nil, func(v *cmView) any {
		val, _, _ := s.get(v.conf)
		return val
	})
	if err != nil {
		return nil, err
	}
	x.write = s.write
	if s.write != nil {
		p.c.srv.Node(x.id).SetValueWriter(p.c.writer(x))
	}
	if _, err := p.p(x, sid+"."+name+".Selections", qn(0, "Selections"), dt0(id.BaseDataType), 1, func(v *cmView) any {
		_, sels, _ := s.get(v.conf)
		return sels
	}); err != nil {
		return nil, err
	}
	if _, err := p.p(x, sid+"."+name+".RestrictToList", qn(0, "RestrictToList"), dt0(id.Boolean), -1, func(v *cmView) any {
		_, _, modify := s.get(v.conf)
		return !modify
	}); err != nil {
		return nil, err
	}
	return x, nil
}

// --- ServerAddresses and AutomationComponentConfigurations ------------------

func (p *projector) servers(obj *server.Node, sid string, conf *uafx.ConnectionConfigurationSetConf) ([]*server.Node, error) {
	cmNS := p.c.ns.CM
	var out []*server.Node
	for i, sa := range conf.ServerAddresses {
		i := i
		at := func(c *uafx.ConnectionConfigurationSetConf) *uafx.ServerAddressConf {
			if i < len(c.ServerAddresses) {
				return c.ServerAddresses[i]
			}
			return &uafx.ServerAddressConf{}
		}
		ssid := fmt.Sprintf("%s.ServerAddress[%s]", sid, idPart(sa.BrowseName))
		x, err := p.v(obj, ssid, qn(cmNS, sa.BrowseName), ua.NewNumericNodeID(cmNS, fxcmid.ServerAddressDataType), -1,
			ua.NewNumericNodeID(cmNS, fxcmid.ServerAddressType), false, func(*cmView) any { return nil })
		if err != nil {
			return nil, err
		}
		n := p.c.srv.Node(x.id)
		obj.RemoveRef(ua.NewExpandedNodeID(x.id, "", 0), dt0(id.HasComponent), true)
		p.c.ref(obj, n, fxcmid.HasServerAddress, cmNS)
		out = append(out, n)
		for _, f := range []struct {
			name string
			dt   uint32
			s    selection
		}{
			{"Address", id.String, strSel(func(c *uafx.ConnectionConfigurationSetConf) (*string, []string, *bool) {
				s := at(c)
				return &s.Address, s.AddressSelection, s.AddressModify
			})},
			{"SecurityMode", id.MessageSecurityMode, modeSel(func(c *uafx.ConnectionConfigurationSetConf) (*ua.MessageSecurityMode, []ua.MessageSecurityMode, *bool) {
				s := at(c)
				return &s.SecurityMode, s.SecurityModeSelection, s.SecurityModeModify
			})},
			{"SecurityPolicyUri", id.String, strSel(func(c *uafx.ConnectionConfigurationSetConf) (*string, []string, *bool) {
				s := at(c)
				return &s.SecurityPolicyURI, s.SecurityPolicyURISelection, s.SecurityPolicyURIModify
			})},
			{"ServerUri", id.String, strSel(func(c *uafx.ConnectionConfigurationSetConf) (*string, []string, *bool) {
				s := at(c)
				return &s.ServerURI, s.ServerURISelection, s.ServerURIModify
			})},
		} {
			if _, err := p.sel(n, ssid, f.name, dt0(f.dt), f.s); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func (p *projector) acs(obj *server.Node, sid string, conf *uafx.ConnectionConfigurationSetConf, servers []*server.Node) ([]*server.Node, error) {
	cmNS := p.c.ns.CM
	var out []*server.Node
	for i, a := range conf.AutomationComponentConfigurations {
		i := i
		at := func(c *uafx.ConnectionConfigurationSetConf) *uafx.AutomationComponentConfigurationConf {
			if i < len(c.AutomationComponentConfigurations) {
				return c.AutomationComponentConfigurations[i]
			}
			return &uafx.AutomationComponentConfigurationConf{}
		}
		asid := fmt.Sprintf("%s.AC[%s]", sid, idPart(a.BrowseName))
		n, err := p.b.object(asid, qn(cmNS, a.BrowseName), ua.NewNumericNodeID(cmNS, fxcmid.AutomationComponentConfigurationType))
		if err != nil {
			return nil, err
		}
		p.c.ref(obj, n, fxcmid.HasAutomationComponentConfiguration, cmNS)
		if si := int(a.ServerAddressIndex); si >= 0 && si < len(servers) {
			p.c.ref(servers[si], n, fxcmid.ToAutomationComponentConfiguration, cmNS)
		}
		if _, err := p.sel(n, asid, "AutomationComponentNode", ua.NewNumericNodeID(cmNS, fxcmid.PortableNodeIdentifier),
			p.identSel(func(c *uafx.ConnectionConfigurationSetConf) (**uafx.NodeIdentifier, []*uafx.NodeIdentifier, *bool, []string) {
				a := at(c)
				var ns []string
				if si := int(a.ServerAddressIndex); si >= 0 && si < len(c.ServerAddresses) {
					ns = c.ServerAddresses[si].Namespaces
				}
				return &a.AutomationComponentNode, a.AutomationComponentNodeSelection, &a.AutomationComponentNodeModify, ns
			})); err != nil {
			return nil, err
		}
		x, err := p.v(n, asid+".CommandBundleRequired", qn(cmNS, "CommandBundleRequired"), dt0(id.Boolean), -1, dt0(id.BaseDataVariableType), false,
			func(v *cmView) any { return at(v.conf).CommandBundleRequired })
		if err != nil {
			return nil, err
		}
		n.RemoveRef(ua.NewExpandedNodeID(x.id, "", 0), dt0(id.HasComponent), true)
		p.c.ref(n, p.c.srv.Node(x.id), fxcmid.HasCharacteristic, cmNS)
		out = append(out, n)
	}
	return out, nil
}

// --- CommunicationFlows -----------------------------------------------------

func (p *projector) flows(obj *server.Node, sid string, conf *uafx.ConnectionConfigurationSetConf) ([]*server.Node, error) {
	cmNS := p.c.ns.CM
	var out []*server.Node
	for i, f := range conf.CommunicationFlows {
		ps, ok := f.(*uafx.PubSubCommunicationFlowConfigurationConf)
		if !ok {
			out = append(out, nil)
			continue
		}
		i := i
		at := func(c *uafx.ConnectionConfigurationSetConf) *uafx.PubSubCommunicationFlowConfigurationConf {
			if i < len(c.CommunicationFlows) {
				if f, ok := c.CommunicationFlows[i].(*uafx.PubSubCommunicationFlowConfigurationConf); ok {
					return f
				}
			}
			return &uafx.PubSubCommunicationFlowConfigurationConf{}
		}
		fsid := fmt.Sprintf("%s.Flow[%s]", sid, idPart(ps.BrowseName))
		n, err := p.b.object(fsid, qn(cmNS, ps.BrowseName), ua.NewNumericNodeID(cmNS, fxcmid.PubSubCommunicationFlowConfigurationType))
		if err != nil {
			return nil, err
		}
		p.c.ref(obj, n, fxcmid.HasCommunicationFlowConfiguration, cmNS)
		out = append(out, n)
		type member struct {
			name    string
			dt      *ua.NodeID
			present bool
			s       selection
		}
		members := []member{
			{"Address", dt0(id.NetworkAddressDataType), ps.Address != nil, addrSel(func(c *uafx.ConnectionConfigurationSetConf) *uafx.AddressSelection { return at(c).Address })},
			{"TransportProfileUri", dt0(id.String), ps.TransportProfileURI != nil, optStrSel(func(c *uafx.ConnectionConfigurationSetConf) (**string, []string, *bool) {
				f := at(c)
				return &f.TransportProfileURI, f.TransportProfileURISelection, f.TransportProfileURIModify
			})},
			{"HeaderLayoutUri", dt0(id.String), ps.HeaderLayoutURI != nil, optStrSel(func(c *uafx.ConnectionConfigurationSetConf) (**string, []string, *bool) {
				f := at(c)
				return &f.HeaderLayoutURI, f.HeaderLayoutURISelection, f.HeaderLayoutURIModify
			})},
			{"PublishingInterval", dt0(id.Duration), ps.PublishingInterval != nil, optFloatSel(func(c *uafx.ConnectionConfigurationSetConf) (**float64, []float64, *bool) {
				f := at(c)
				return &f.PublishingInterval, f.PublishingIntervalSelection, f.PublishingIntervalModify
			})},
			{"SecurityMode", dt0(id.MessageSecurityMode), ps.SecurityMode != nil, optModeSel(func(c *uafx.ConnectionConfigurationSetConf) (**ua.MessageSecurityMode, []ua.MessageSecurityMode, *bool) {
				f := at(c)
				return &f.SecurityMode, f.SecurityModeSelection, f.SecurityModeModify
			})},
			{"SecurityGroupId", dt0(id.String), ps.SecurityGroupID != nil, optStrSel(func(c *uafx.ConnectionConfigurationSetConf) (**string, []string, *bool) {
				f := at(c)
				return &f.SecurityGroupID, f.SecurityGroupIDSelection, f.SecurityGroupIDModify
			})},
		}
		for _, m := range members {
			if !m.present {
				continue
			}
			if _, err := p.sel(n, fsid, m.name, m.dt, m.s); err != nil {
				return nil, err
			}
		}
		for j, sc := range ps.SubscriberConfigurations {
			j := j
			sat := func(c *uafx.ConnectionConfigurationSetConf) *uafx.SubscriberConfigurationConf {
				if f := at(c); j < len(f.SubscriberConfigurations) {
					return f.SubscriberConfigurations[j]
				}
				return &uafx.SubscriberConfigurationConf{}
			}
			ssid := fmt.Sprintf("%s.Sub[%s]", fsid, idPart(sc.BrowseName))
			sn, err := p.b.object(ssid, qn(cmNS, sc.BrowseName), ua.NewNumericNodeID(cmNS, fxcmid.SubscriberConfigurationType))
			if err != nil {
				return nil, err
			}
			n.AddRef(sn, server.RefTypeIDHasComponent, true)
			if sc.Address != nil {
				if _, err := p.sel(sn, ssid, "Address", dt0(id.NetworkAddressDataType),
					addrSel(func(c *uafx.ConnectionConfigurationSetConf) *uafx.AddressSelection { return sat(c).Address })); err != nil {
					return nil, err
				}
			}
			if _, err := p.sel(sn, ssid, "MessageReceiveTimeout", dt0(id.Duration), floatSel(func(c *uafx.ConnectionConfigurationSetConf) (*float64, []float64, *bool) {
				s := sat(c)
				return &s.MessageReceiveTimeout, s.MessageReceiveTimeoutSelection, s.MessageReceiveTimeoutModify
			})); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// --- Connections ------------------------------------------------------------

func (p *projector) connections(obj *server.Node, sid string, conf *uafx.ConnectionConfigurationSetConf, acs, flows []*server.Node) error {
	cmNS := p.c.ns.CM
	for i, cn := range conf.Connections {
		i := i
		csid := fmt.Sprintf("%s.Conn[%s]", sid, idPart(cn.BrowseName))
		n, err := p.b.object(csid, qn(cmNS, cn.BrowseName), ua.NewNumericNodeID(cmNS, fxcmid.ConnectionConfigurationType))
		if err != nil {
			return err
		}
		p.c.ref(obj, n, fxcmid.HasConnectionConfiguration, cmNS)
		// ProcessingResult (CS-22, library interpretation): Good when the
		// Connection has no error, else the first bad status of its
		// endpoints.
		if _, err := p.p(n, csid+".ProcessingResult", qn(cmNS, "ProcessingResult"), dt0(id.StatusCode), -1, func(v *cmView) any {
			if i < len(v.st.Diagnostics) {
				d := v.st.Diagnostics[i]
				for _, s := range []ua.StatusCode{d.Endpoint1Status, d.Endpoint2Status} {
					if s.Uint32()&0x80000000 != 0 {
						return s
					}
				}
				if d.LastActivity&uafx.LastActivityError != 0 {
					return ua.StatusBad
				}
			}
			return ua.StatusGood
		}); err != nil {
			return err
		}
		for num, e := range []*uafx.ConnectionEndpointConfigurationConf{cn.Endpoint1, cn.Endpoint2} {
			if e == nil {
				continue
			}
			num := num + 1
			ep := func(c *uafx.ConnectionConfigurationSetConf) *uafx.ConnectionEndpointConfigurationConf {
				if i < len(c.Connections) {
					cn := c.Connections[i]
					if num == 1 && cn.Endpoint1 != nil {
						return cn.Endpoint1
					}
					if num == 2 && cn.Endpoint2 != nil {
						return cn.Endpoint2
					}
				}
				return &uafx.ConnectionEndpointConfigurationConf{}
			}
			if err := p.endpoint(n, csid, num, e, ep, acs, flows); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *projector) endpoint(conn *server.Node, csid string, num int, e *uafx.ConnectionEndpointConfigurationConf,
	ep func(*uafx.ConnectionConfigurationSetConf) *uafx.ConnectionEndpointConfigurationConf, acs, flows []*server.Node) error {
	cmNS := p.c.ns.CM
	name := fmt.Sprintf("Endpoint%d", num)
	esid := csid + "." + name
	n, err := p.b.object(esid, qn(cmNS, name), ua.NewNumericNodeID(cmNS, fxcmid.ConnectionEndpointConfigurationType))
	if err != nil {
		return err
	}
	conn.AddRef(n, server.RefTypeIDHasComponent, true)
	if ai := int(e.AutomationComponentIndex); ai >= 0 && ai < len(acs) {
		p.c.ref(acs[ai], n, fxcmid.ToConnectionEndpointConfiguration, cmNS)
	}
	if o := e.OutboundFlowIndex; o != nil && *o >= 0 && int(*o) < len(flows) && flows[*o] != nil {
		p.c.ref(n, flows[*o], fxcmid.ToOutboundFlow, cmNS)
	}
	if in := e.InboundFlowIndex; len(in) > 0 && in[0] >= 0 && int(in[0]) < len(flows) && flows[in[0]] != nil {
		p.c.ref(n, flows[in[0]], fxcmid.ToInboundFlow, cmNS)
	}
	if _, err := p.sel(n, esid, "FunctionalEntityNode", ua.NewNumericNodeID(cmNS, fxcmid.PortableNodeIdentifier),
		p.identSel(func(c *uafx.ConnectionConfigurationSetConf) (**uafx.NodeIdentifier, []*uafx.NodeIdentifier, *bool, []string) {
			e := ep(c)
			return &e.FunctionalEntityNode, e.FunctionalEntityNodeSelection, e.FunctionalEntityNodeModify, namespacesOf(c, e.AutomationComponentIndex)
		})); err != nil {
		return err
	}
	psid := esid + ".ConnectionEndpoint"
	pn, err := p.b.object(psid, qn(cmNS, "ConnectionEndpoint"), ua.NewNumericNodeID(cmNS, fxcmid.ConnectionEndpointParameterType))
	if err != nil {
		return err
	}
	n.AddRef(pn, server.RefTypeIDHasComponent, true)
	if _, err := p.sel(pn, psid, "Name", dt0(id.String), strSel(func(c *uafx.ConnectionConfigurationSetConf) (*string, []string, *bool) {
		e := ep(c)
		return &e.Name, e.NameSelection, e.NameModify
	})); err != nil {
		return err
	}
	// CleanupTimeout and IsPersistent have no Selection in the set
	// (Table F.12): fixed values (§6.8.1).
	if _, err := p.sel(pn, psid, "CleanupTimeout", dt0(id.Duration), fixedSel(func(c *uafx.ConnectionConfigurationSetConf) float64 {
		return ep(c).CleanupTimeout
	}, asFloat)); err != nil {
		return err
	}
	if _, err := p.sel(pn, psid, "IsPersistent", dt0(id.Boolean), fixedSel(func(c *uafx.ConnectionConfigurationSetConf) bool {
		return ep(c).IsPersistent
	}, asBool)); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		dt   uint32
		get  func(*uafx.ConnectionEndpointConfigurationConf) any
	}{
		{"IsPreconfigured", id.Boolean, func(e *uafx.ConnectionEndpointConfigurationConf) any { return e.IsPreconfigured }},
		{"ConnectionEndpointTypeId", id.NodeID, func(e *uafx.ConnectionEndpointConfigurationConf) any {
			if e.ConnectionEndpointTypeID == nil {
				return ua.NewTwoByteNodeID(0)
			}
			return e.ConnectionEndpointTypeID
		}},
	} {
		get := f.get
		if _, err := p.v(pn, psid+"."+f.name, qn(cmNS, f.name), dt0(f.dt), -1, dt0(id.BaseDataVariableType), false,
			func(v *cmView) any { return get(ep(v.conf)) }); err != nil {
			return err
		}
	}
	return nil
}
