// SPDX-License-Identifier: MIT

package server

import (
	"reflect"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// The diagnostics nodes: the ServerDiagnostics object of the standard node
// set (i=2274) gets its values, and every session a SessionDiagnosticsObject
// (Part 5 §6.3.5) below SessionsDiagnosticsSummary (i=3706).

// bind gives the ServerDiagnostics variables of namespace 0 their values. It
// replaces the nodes by copies of this server (see ownNode).
func (d *serverDiagnostics) bind() {
	s := d.s
	set := func(nid uint32, val ValueFunc, access byte) *Node {
		n := s.ownNode(nid)
		if n == nil {
			return nil
		}
		n.mu.Lock()
		n.val = val
		n.attr[ua.AttributeIDAccessLevel] = DataValueFromValue(access)
		n.attr[ua.AttributeIDUserAccessLevel] = DataValueFromValue(access)
		n.mu.Unlock()
		return n
	}
	ro := byte(ua.AccessLevelTypeCurrentRead)
	array := func(f func() []*ua.ExtensionObject) ValueFunc {
		return func() *ua.DataValue { return DataValueFromValue(f()) }
	}

	summary := func() any { return d.summary() }
	if n := set(id.ServerServerDiagnosticsServerDiagnosticsSummary, structValue(summary), ro); n != nil {
		for _, c := range componentsOf(s, n) {
			set(c.ID().IntID(), fieldValue(summary, c.BrowseName().Name), ro)
		}
	}
	set(id.ServerServerDiagnosticsSamplingIntervalDiagnosticsArray, array(d.samplingIntervalDiagnosticsArray), ro)
	set(id.ServerServerDiagnosticsSubscriptionDiagnosticsArray, array(func() []*ua.ExtensionObject { return d.subscriptionDiagnosticsArray(nil) }), ro)
	set(id.ServerServerDiagnosticsSessionsDiagnosticsSummarySessionDiagnosticsArray, array(d.sessionDiagnosticsArray), ro)
	set(id.ServerServerDiagnosticsSessionsDiagnosticsSummarySessionSecurityDiagnosticsArray, array(d.sessionSecurityDiagnosticsArray), ro)
	set(id.ServerServerDiagnosticsEnabledFlag, func() *ua.DataValue { return DataValueFromValue(d.enabled.Load()) },
		byte(ua.AccessLevelTypeCurrentRead|ua.AccessLevelTypeCurrentWrite))
	d.summaryObj = s.ownNode(id.ServerServerDiagnosticsSessionsDiagnosticsSummary)
}

// componentsOf returns the variables a node has a forward HasComponent or
// HasProperty reference to.
func componentsOf(s *Server, n *Node) []*Node {
	var out []*Node
	for _, r := range n.refsSnapshot() {
		if r == nil || !r.IsForward || r.ReferenceTypeID == nil || r.NodeID == nil || r.NodeID.NodeID == nil {
			continue
		}
		if rt := r.ReferenceTypeID.IntID(); rt != id.HasComponent && rt != id.HasProperty {
			continue
		}
		if c := s.Node(r.NodeID.NodeID); c != nil && c.NodeClass() == ua.NodeClassVariable {
			out = append(out, c)
		}
	}
	return out
}

// structValue returns the value function of a variable whose value is the
// structure f returns.
func structValue(f func() any) ValueFunc {
	return func() *ua.DataValue {
		v := f()
		if v == nil || reflect.ValueOf(v).IsNil() {
			return badValue(ua.StatusBadNodeIDUnknown)
		}
		return DataValueFromValue(ua.NewExtensionObject(v))
	}
}

// fieldValue returns the value function of the component variable of a
// structured variable (Part 5 §7: the components of ServerDiagnosticsSummary,
// SessionDiagnostics, SessionSecurityDiagnostics): the field of the
// structure f returns whose name is the BrowseName of the variable.
func fieldValue(f func() any, name string) ValueFunc {
	return func() *ua.DataValue {
		v := f()
		if v == nil {
			return badValue(ua.StatusBadNodeIDUnknown)
		}
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Pointer {
			if rv.IsNil() {
				return badValue(ua.StatusBadNodeIDUnknown)
			}
			rv = rv.Elem()
		}
		fv := rv.FieldByNameFunc(func(n string) bool { return strings.EqualFold(n, name) })
		if !fv.IsValid() {
			return badValue(ua.StatusBadNotReadable)
		}
		return DataValueFromValue(variantValue(fv.Interface()))
	}
}

// variantValue converts a field of a diagnostics structure to the value of
// its variable.
func variantValue(v any) any {
	switch x := v.(type) {
	case *ua.ServiceCounterDataType:
		if x == nil {
			x = &ua.ServiceCounterDataType{}
		}
		return ua.NewExtensionObject(x)
	case *ua.ApplicationDescription:
		if x == nil {
			x = &ua.ApplicationDescription{ApplicationName: &ua.LocalizedText{}}
		}
		return ua.NewExtensionObject(x)
	case ua.MessageSecurityMode:
		return int32(x)
	case *ua.NodeID:
		if x == nil {
			return ua.NewTwoByteNodeID(0)
		}
		return x
	}
	return v
}

// sessionNodes are the nodes of the diagnostics object of a session.
type sessionNodes struct {
	obj  *Node
	name string
	ids  []*ua.NodeID
}

// addSession creates the diagnostics object of a session.
func (d *serverDiagnostics) addSession(sess *session) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addSessionLocked(sess)
}

// addSessionLocked creates the diagnostics object of a session that the
// session broker keeps, if diagnostics are enabled and it has none.
func (d *serverDiagnostics) addSessionLocked(sess *session) {
	if !d.enabled.Load() || d.summaryObj == nil || d.sessions[sess] != nil {
		return
	}
	// A session that is gone (closed, timed out) must not get an object:
	// sessionRemoved, which would delete it, has already run.
	if !d.s.sb.has(sess) {
		return
	}
	ns := d.namespaceLocked()
	if sess.ID == nil || sess.ID.Namespace() != ns.ID() || sess.ID.Type() != ua.NodeIDTypeGUID {
		return
	}
	guid := sess.ID.StringID()
	sn := &sessionNodes{}

	sess.diag.mu.Lock()
	name := sess.diag.name
	sess.diag.mu.Unlock()
	if name == "" {
		name = "Session"
	}
	if d.nameUsedLocked(name) {
		name += " " + guid
	}
	sn.name = name

	obj := NewNode(sess.ID, Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(&ua.QualifiedName{NamespaceIndex: ns.ID(), Name: name}),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	ns.AddNode(obj)
	d.typeDef(obj, id.SessionDiagnosticsObjectType)
	sn.obj = obj
	sn.ids = append(sn.ids, obj.ID())

	diagOf := func() any {
		if !d.s.sb.has(sess) {
			return (*ua.SessionDiagnosticsDataType)(nil)
		}
		return d.sessionDiagnostics(sess, d.subscriptionsBySession()[sess])
	}
	securityOf := func() any {
		if !d.s.sb.has(sess) {
			return (*ua.SessionSecurityDiagnosticsDataType)(nil)
		}
		return d.sessionSecurityDiagnostics(sess)
	}
	sdNode := d.variable(sn, ns, obj, id.HasComponent, guid+".SessionDiagnostics", "SessionDiagnostics",
		ua.NewNumericExpandedNodeID(0, id.SessionDiagnosticsDataType), -1, id.SessionDiagnosticsVariableType, structValue(diagOf))
	d.components(sn, ns, sdNode, guid+".SessionDiagnostics", id.SessionDiagnosticsObjectTypeSessionDiagnostics, diagOf)
	secNode := d.variable(sn, ns, obj, id.HasComponent, guid+".SessionSecurityDiagnostics", "SessionSecurityDiagnostics",
		ua.NewNumericExpandedNodeID(0, id.SessionSecurityDiagnosticsDataType), -1, id.SessionSecurityDiagnosticsType, structValue(securityOf))
	d.components(sn, ns, secNode, guid+".SessionSecurityDiagnostics", id.SessionDiagnosticsObjectTypeSessionSecurityDiagnostics, securityOf)
	d.variable(sn, ns, obj, id.HasComponent, guid+".SubscriptionDiagnosticsArray", "SubscriptionDiagnosticsArray",
		ua.NewNumericExpandedNodeID(0, id.SubscriptionDiagnosticsDataType), 1, id.SubscriptionDiagnosticsArrayType,
		func() *ua.DataValue { return DataValueFromValue(d.subscriptionDiagnosticsArray(sess)) })
	d.variable(sn, ns, obj, id.HasProperty, guid+".CurrentRoleIds", "CurrentRoleIds",
		ua.NewNumericExpandedNodeID(0, id.NodeID), 1, id.PropertyType,
		func() *ua.DataValue {
			sess.diag.mu.Lock()
			roles := append([]*ua.NodeID{}, sess.diag.roles...)
			sess.diag.mu.Unlock()
			return DataValueFromValue(roles)
		})

	linkChild(d.summaryObj, obj, id.HasComponent)
	d.sessions[sess] = sn
}

// nameUsedLocked reports whether the object of another session has the
// BrowseName name.
func (d *serverDiagnostics) nameUsedLocked(name string) bool {
	for _, sn := range d.sessions {
		if sn.name == name {
			return true
		}
	}
	return false
}

// components creates the component variables of a structured variable from
// the InstanceDeclarations of its type (decl, e.g. i=2030 for
// SessionDiagnostics).
func (d *serverDiagnostics) components(sn *sessionNodes, ns *NodeNameSpace, parent *Node, prefix string, decl uint32, f func() any) {
	dn := d.s.Node(ua.NewNumericNodeID(0, decl))
	if dn == nil {
		return
	}
	for _, c := range componentsOf(d.s, dn) {
		name := c.BrowseName().Name
		dt := ua.NewNumericExpandedNodeID(0, id.BaseDataType)
		if a, err := c.Attribute(ua.AttributeIDDataType); err == nil && a.Value != nil && a.Value.Value != nil {
			if e, ok := a.Value.Value.Value().(*ua.ExpandedNodeID); ok {
				dt = e
			}
		}
		rank := int32(-1)
		if a, err := c.Attribute(ua.AttributeIDValueRank); err == nil && a.Value != nil && a.Value.Value != nil {
			if r, ok := a.Value.Value.Value().(int32); ok {
				rank = r
			}
		}
		d.variable(sn, ns, parent, id.HasComponent, prefix+"."+name, name, dt, rank, id.BaseDataVariableType, fieldValue(f, name))
	}
}

// variable creates a read-only variable of a session diagnostics object.
func (d *serverDiagnostics) variable(sn *sessionNodes, ns *NodeNameSpace, parent *Node, refType uint32, sid, name string,
	dataType *ua.ExpandedNodeID, valueRank int32, typeDef uint32, val ValueFunc) *Node {
	n := NewNode(ua.NewStringNodeID(ns.ID(), sid), Attributes{
		ua.AttributeIDNodeClass:               DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:              DataValueFromValue(&ua.QualifiedName{Name: name}),
		ua.AttributeIDDisplayName:             DataValueFromValue(attrs.DisplayName(name, "")),
		ua.AttributeIDDescription:             DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:                DataValueFromValue(dataType),
		ua.AttributeIDValueRank:               DataValueFromValue(valueRank),
		ua.AttributeIDAccessLevel:             DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDUserAccessLevel:         DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead)),
		ua.AttributeIDMinimumSamplingInterval: DataValueFromValue(float64(0)),
		ua.AttributeIDHistorizing:             DataValueFromValue(false),
	}, nil, val)
	ns.AddNode(n)
	d.typeDef(n, typeDef)
	linkChild(parent, n, refType)
	sn.ids = append(sn.ids, n.ID())
	return n
}

func (d *serverDiagnostics) typeDef(n *Node, t uint32) {
	if tn := d.s.Node(ua.NewNumericNodeID(0, t)); tn != nil {
		n.AddRef(tn, RefType(id.HasTypeDefinition), true)
	}
}

// dropNodesLocked deletes the diagnostics object of a session.
func (d *serverDiagnostics) dropNodesLocked(sn *sessionNodes) {
	if d.summaryObj != nil && sn.obj != nil {
		d.summaryObj.RemoveRef(ua.NewExpandedNodeID(sn.obj.ID(), "", 0), ua.NewNumericNodeID(0, id.HasComponent), true)
	}
	if d.ns == nil {
		return
	}
	for _, nid := range sn.ids {
		_ = d.ns.DeleteNode(nid)
	}
}

// sessionObjectCount returns the number of session diagnostics objects (for
// tests).
func (d *serverDiagnostics) sessionObjectCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sessions)
}

// diagnosticsOwner returns the GUID of the session a node of the
// diagnostics namespace belongs to: the SessionId of the object, or the
// prefix of the string NodeId of its variables.
func diagnosticsOwner(nid *ua.NodeID) string {
	switch nid.Type() {
	case ua.NodeIDTypeGUID:
		return strings.ToLower(nid.StringID())
	case ua.NodeIDTypeString:
		s := nid.StringID()
		if i := strings.IndexByte(s, '.'); i >= 0 {
			s = s[:i]
		}
		return strings.ToLower(s)
	default:
		return ""
	}
}

// lastContact is when a session was last used.
func lastContact(sess *session) time.Time {
	return monoEpoch.Add(time.Duration(sess.lastActivity.Load()))
}
