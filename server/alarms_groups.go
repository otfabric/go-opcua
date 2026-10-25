// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// Alarm groups (Part 9 §5.8, AlarmGroupType and AlarmSuppressionGroupType).
//
// An AlarmGroup (AlarmGroupType) groups alarms with AlarmGroupMember
// references; GetGroupMemberships of an alarm lists the groups it belongs
// to. An AlarmSuppressionGroup (AlarmSuppressionGroupType) references its
// alarms with AlarmSuppressionGroupMember, and they reference it with
// HasAlarmSuppressionGroup: while the group suppresses
// ([AlarmGroup.SetSuppressing], or [AlarmGroup.Evaluate] of its
// DigitalVariables), its alarms are suppressed. A change of the group sets
// the SuppressedState of each member to whether any of its suppression
// groups suppresses; the Suppress and Unsuppress methods change it in
// between (Part 9: the last change wins).

// AlarmGroupConfig describes an alarm group for [Server.AddAlarmGroup].
type AlarmGroupConfig struct {
	// NodeID is the NodeId of the group. Default: a new numeric NodeId in
	// Namespace.
	NodeID *ua.NodeID
	// Namespace receives the node. Default: the namespace of NodeID.
	Namespace *NodeNameSpace
	// Name is the BrowseName. Required.
	Name string
	// Parent organizes the group. Default: the Objects folder.
	Parent *ua.NodeID
	// Suppression makes the group an AlarmSuppressionGroup.
	Suppression bool
	// DigitalVariables are the Boolean variables of an
	// AlarmSuppressionGroup: [AlarmGroup.Evaluate] makes the group suppress
	// while any of them is true.
	DigitalVariables []*ua.NodeID
}

// AlarmGroup is an alarm group in the address space.
type AlarmGroup struct {
	srv         *Server
	id          *ua.NodeID
	name        string
	ns          *NodeNameSpace
	node        *Node
	parent      *Node
	suppression bool
	digital     []*ua.NodeID

	// members and suppressing are guarded by alarmManager.mu.
	members     []*Condition
	suppressing bool
	removed     bool

	// fmu guards the following; it is a leaf lock, taken with the lock
	// of a condition held. memberSet mirrors members for the alarm
	// metrics of the group; firstOut are the alarms with this group as
	// their FirstInGroup, activeOut those of them that are active and
	// first the first-out alarm.
	fmu       sync.Mutex
	memberSet map[*Condition]bool
	firstOut  []*Condition
	activeOut map[*Condition]bool
	first     *Condition
}

// setMember records c in (or out of) memberSet.
func (g *AlarmGroup) setMember(c *Condition, in bool) {
	g.fmu.Lock()
	defer g.fmu.Unlock()
	if g.memberSet == nil {
		g.memberSet = map[*Condition]bool{}
	}
	if in {
		g.memberSet[c] = true
	} else {
		delete(g.memberSet, c)
	}
}

// hasMember reports whether c is a member of the group.
func (g *AlarmGroup) hasMember(c *Condition) bool {
	g.fmu.Lock()
	defer g.fmu.Unlock()
	return g.memberSet[c]
}

// groupState are the alarm groups of a server.
type groupState struct {
	groups map[string]*AlarmGroup // guarded by alarmManager.mu
	// evalMu serializes the changes of suppression groups and their effect
	// on the members. It is never taken with a condition lock held.
	evalMu sync.Mutex
}

// AddAlarmGroup creates an AlarmGroupType (or, with Suppression,
// AlarmSuppressionGroupType) object.
func (s *Server) AddAlarmGroup(cfg AlarmGroupConfig) (*AlarmGroup, error) {
	if cfg.Name == "" {
		return nil, errors.New("server: AddAlarmGroup: Name is required")
	}
	ns := cfg.Namespace
	if ns == nil && cfg.NodeID != nil && cfg.NodeID.Namespace() != 0 {
		if x, err := s.Namespace(int(cfg.NodeID.Namespace())); err == nil {
			ns, _ = x.(*NodeNameSpace)
		}
	}
	if ns == nil {
		return nil, errors.New("server: AddAlarmGroup: Namespace is required")
	}
	if len(cfg.DigitalVariables) > 0 && !cfg.Suppression {
		return nil, errors.New("server: AddAlarmGroup: DigitalVariables need Suppression")
	}
	var digital []*Node
	for _, v := range cfg.DigitalVariables {
		n := s.Node(v)
		if n == nil || n.NodeClass() != ua.NodeClassVariable {
			return nil, fmt.Errorf("server: AddAlarmGroup: %v is not a variable", v)
		}
		digital = append(digital, n)
	}
	parentID := cfg.Parent
	if parentID == nil {
		parentID = ua.NewNumericNodeID(0, id.ObjectsFolder)
	}
	parent := s.Node(parentID)
	if parent == nil {
		return nil, fmt.Errorf("server: AddAlarmGroup: parent %v not found", parentID)
	}
	if parentID.Namespace() == 0 {
		parent = s.ownNode(parentID.IntID())
	}
	gid := cfg.NodeID
	if gid == nil {
		gid = ua.NewNumericNodeID(ns.ID(), ns.GetNextNodeID())
	}
	if s.Node(gid) != nil {
		return nil, fmt.Errorf("server: AddAlarmGroup: node %v exists", gid)
	}
	typ := uint32(id.AlarmGroupType)
	if cfg.Suppression {
		typ = id.AlarmSuppressionGroupType
	}
	g := &AlarmGroup{srv: s, id: gid, name: cfg.Name, ns: ns, parent: parent, suppression: cfg.Suppression, digital: slices.Clone(cfg.DigitalVariables)}

	s.alarms.mu.Lock()
	if _, dup := s.alarms.groups.groups[gid.String()]; dup {
		s.alarms.mu.Unlock()
		return nil, fmt.Errorf("server: AddAlarmGroup: group %v exists", gid)
	}
	s.alarms.groups.groups[gid.String()] = g
	s.alarms.mu.Unlock()

	g.node = NewNode(gid, Attributes{
		ua.AttributeIDNodeClass:     DataValueFromValue(uint32(ua.NodeClassObject)),
		ua.AttributeIDBrowseName:    DataValueFromValue(&ua.QualifiedName{NamespaceIndex: ns.ID(), Name: cfg.Name}),
		ua.AttributeIDDisplayName:   DataValueFromValue(attrs.DisplayName(cfg.Name, "")),
		ua.AttributeIDDescription:   DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDEventNotifier: DataValueFromValue(byte(0)),
	}, nil, nil)
	ns.AddNode(g.node)
	if tn := s.Node(ua.NewNumericNodeID(0, typ)); tn != nil {
		g.node.AddRef(tn, RefType(id.HasTypeDefinition), true)
	}
	linkChild(parent, g.node, id.Organizes)
	for _, n := range digital {
		linkChild(g.node, n, id.AlarmSuppressionGroupMember)
	}
	return g, nil
}

// AlarmGroup returns the alarm group with the given NodeId.
func (s *Server) AlarmGroup(groupID *ua.NodeID) (*AlarmGroup, bool) {
	if groupID == nil {
		return nil, false
	}
	s.alarms.mu.Lock()
	defer s.alarms.mu.Unlock()
	g, ok := s.alarms.groups.groups[groupID.String()]
	return g, ok
}

// RemoveAlarmGroup deletes an alarm group. A suppressing group stops
// suppressing first.
func (s *Server) RemoveAlarmGroup(groupID *ua.NodeID) error {
	g, ok := s.AlarmGroup(groupID)
	if !ok {
		return fmt.Errorf("server: alarm group %v not found", groupID)
	}
	if g.suppression {
		_ = g.SetSuppressing(false)
	}
	s.alarms.groups.evalMu.Lock()
	defer s.alarms.groups.evalMu.Unlock()
	s.alarms.mu.Lock()
	members := g.members
	g.members, g.removed = nil, true
	delete(s.alarms.groups.groups, groupID.String())
	s.alarms.mu.Unlock()
	for _, c := range members {
		g.setMember(c, false)
		g.unlink(c)
	}
	target := ua.NewExpandedNodeID(g.id, "", 0)
	g.parent.RemoveRef(target, ua.NewNumericNodeID(0, id.Organizes), true)
	for _, v := range g.digital {
		if n := s.Node(v); n != nil {
			n.RemoveRef(target, ua.NewNumericNodeID(0, id.AlarmSuppressionGroupMember), false)
		}
	}
	_ = g.ns.DeleteNode(g.id)
	return nil
}

// NodeID returns the NodeId of the group.
func (g *AlarmGroup) NodeID() *ua.NodeID { return g.id }

// Name returns the BrowseName of the group.
func (g *AlarmGroup) Name() string { return g.name }

// IsSuppressionGroup reports whether the group is an AlarmSuppressionGroup.
func (g *AlarmGroup) IsSuppressionGroup() bool { return g.suppression }

// memberRef is the reference from the group to its members.
func (g *AlarmGroup) memberRef() uint32 {
	if g.suppression {
		return id.AlarmSuppressionGroupMember
	}
	return id.AlarmGroupMember
}

// AddMember adds an alarm to the group. A member of a suppression group must
// be a Suppressible alarm; it takes the group's suppression at once if the
// group suppresses.
func (g *AlarmGroup) AddMember(c *Condition) error {
	if c == nil || c.srv != g.srv {
		return errors.New("server: AlarmGroup.AddMember: condition of another server")
	}
	if !c.isAlarm {
		return ErrConditionNotAlarm
	}
	if g.suppression && !c.cfg.Suppressible {
		return ErrConditionUnsupport
	}
	s := g.srv
	s.alarms.groups.evalMu.Lock()
	defer s.alarms.groups.evalMu.Unlock()
	s.alarms.mu.Lock()
	if g.removed {
		s.alarms.mu.Unlock()
		return fmt.Errorf("server: alarm group %v removed", g.id)
	}
	if _, ok := s.alarms.conds[c.id.String()]; !ok {
		s.alarms.mu.Unlock()
		return ErrConditionRemoved
	}
	if slices.Contains(g.members, c) {
		s.alarms.mu.Unlock()
		return nil
	}
	g.members = append(g.members, c)
	suppressing := g.suppressing
	s.alarms.mu.Unlock()
	g.setMember(c, true)

	if cn := s.Node(c.id); cn != nil {
		linkChild(g.node, cn, g.memberRef())
		if g.suppression {
			cn.AddRef(g.node, RefType(id.HasAlarmSuppressionGroup), true)
			g.node.AddRef(cn, RefType(id.HasAlarmSuppressionGroup), false)
		}
	}
	if suppressing {
		s.applyGroupSuppression([]*Condition{c})
	}
	return nil
}

// RemoveMember removes an alarm from the group; the alarm takes the
// suppression of its other suppression groups.
func (g *AlarmGroup) RemoveMember(c *Condition) error {
	s := g.srv
	s.alarms.groups.evalMu.Lock()
	defer s.alarms.groups.evalMu.Unlock()
	s.alarms.mu.Lock()
	i := slices.Index(g.members, c)
	if i < 0 {
		s.alarms.mu.Unlock()
		return fmt.Errorf("server: %v is not a member of alarm group %v", c.NodeID(), g.id)
	}
	g.members = slices.Delete(g.members, i, i+1)
	suppressing := g.suppressing
	s.alarms.mu.Unlock()
	g.setMember(c, false)
	g.unlink(c)
	if suppressing {
		s.applyGroupSuppression([]*Condition{c})
	}
	return nil
}

// unlink removes the references between the group and an alarm.
func (g *AlarmGroup) unlink(c *Condition) {
	cn := g.srv.Node(c.id)
	if cn == nil {
		return
	}
	ct := ua.NewExpandedNodeID(c.id, "", 0)
	gt := ua.NewExpandedNodeID(g.id, "", 0)
	g.node.RemoveRef(ct, ua.NewNumericNodeID(0, g.memberRef()), true)
	cn.RemoveRef(gt, ua.NewNumericNodeID(0, g.memberRef()), false)
	if g.suppression {
		cn.RemoveRef(gt, ua.NewNumericNodeID(0, id.HasAlarmSuppressionGroup), true)
		g.node.RemoveRef(ct, ua.NewNumericNodeID(0, id.HasAlarmSuppressionGroup), false)
	}
}

// Members returns the ConditionIds of the members of the group.
func (g *AlarmGroup) Members() []*ua.NodeID {
	g.srv.alarms.mu.Lock()
	defer g.srv.alarms.mu.Unlock()
	out := make([]*ua.NodeID, len(g.members))
	for i, c := range g.members {
		out[i] = c.id
	}
	return out
}

// Suppressing reports whether a suppression group suppresses its alarms.
func (g *AlarmGroup) Suppressing() bool {
	g.srv.alarms.mu.Lock()
	defer g.srv.alarms.mu.Unlock()
	return g.suppressing
}

// SetSuppressing makes a suppression group suppress its alarms or stop
// suppressing them.
func (g *AlarmGroup) SetSuppressing(on bool) error {
	if !g.suppression {
		return ErrConditionUnsupport
	}
	s := g.srv
	s.alarms.groups.evalMu.Lock()
	defer s.alarms.groups.evalMu.Unlock()
	s.alarms.mu.Lock()
	if g.removed {
		s.alarms.mu.Unlock()
		return fmt.Errorf("server: alarm group %v removed", g.id)
	}
	changed := g.suppressing != on
	g.suppressing = on
	members := slices.Clone(g.members)
	s.alarms.mu.Unlock()
	if changed {
		s.applyGroupSuppression(members)
	}
	return nil
}

// Evaluate reads the DigitalVariables of a suppression group and makes it
// suppress while any of them is true (Part 9 §5.8, AlarmSuppressionGroupType).
func (g *AlarmGroup) Evaluate() error {
	on := false
	for _, v := range g.digital {
		n := g.srv.Node(v)
		if n == nil {
			continue
		}
		if dv := n.Value(); dv != nil && dv.Value != nil {
			if b, ok := dv.Value.Value().(bool); ok && b {
				on = true
			}
		}
	}
	return g.SetSuppressing(on)
}

// applyGroupSuppression sets the SuppressedState of each alarm to whether
// one of its suppression groups suppresses. evalMu must be held.
func (s *Server) applyGroupSuppression(conds []*Condition) {
	for _, c := range conds {
		s.alarms.mu.Lock()
		want := false
		for _, g := range s.alarms.groups.groups {
			if g.suppression && g.suppressing && slices.Contains(g.members, c) {
				want = true
			}
		}
		s.alarms.mu.Unlock()
		c.mu.RLock()
		cur := c.st.suppressed
		c.mu.RUnlock()
		if cur != want {
			_ = c.Update(ConditionUpdate{Suppressed: &want})
		}
	}
}

// joinSuppressionGroups adds a new condition to the suppression groups of
// its configuration (checked by checkConfig).
func (s *Server) joinSuppressionGroups(c *Condition) {
	for _, gid := range c.cfg.SuppressionGroups {
		if g, ok := s.AlarmGroup(gid); ok {
			_ = g.AddMember(c)
		}
	}
}

// leaveAlarmGroups removes a removed condition from its groups.
func (s *Server) leaveAlarmGroups(c *Condition) {
	s.alarms.groups.evalMu.Lock()
	defer s.alarms.groups.evalMu.Unlock()
	s.alarms.mu.Lock()
	var left []*AlarmGroup
	for _, g := range s.alarms.groups.groups {
		if i := slices.Index(g.members, c); i >= 0 {
			g.members = slices.Delete(g.members, i, i+1)
			left = append(left, g)
		}
	}
	s.alarms.mu.Unlock()
	for _, g := range left {
		g.setMember(c, false)
		g.unlink(c)
	}
}

// groupsOf returns the NodeIds of the groups an alarm is a member of,
// ordered.
func (s *Server) groupsOf(c *Condition) []*ua.NodeID {
	s.alarms.mu.Lock()
	defer s.alarms.mu.Unlock()
	var out []*ua.NodeID
	for _, g := range s.alarms.groups.groups {
		if slices.Contains(g.members, c) {
			out = append(out, g.id)
		}
	}
	slices.SortFunc(out, func(a, b *ua.NodeID) int { return strings.Compare(a.String(), b.String()) })
	return out
}
