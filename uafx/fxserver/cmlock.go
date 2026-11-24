// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
)

// The Lock of a set (§6.8.2, §6.7.4, OPC 10000-100 §7). A set that is not
// in edit is locked to the ConnectionManager: Locked TRUE, LockingClient
// the NodeId of the ConnectionManager, LockingUser "CM" (§6.8.2).
// StartEditing gives the Lock to the client session of the call (§6.7.4);
// it lasts MaxInactiveLockTime without RenewLock or a write of the set
// (OPC 10000-100 §7.2), and when it goes for any reason, by ExitLock,
// BreakLock, the end of the session or expiry, the set is treated as
// DiscardUpdates (§6.7.4). InitLock is refused: the Lock of a set is
// taken with StartEditing.

// setLock holds the NodeIds of the Methods of the Lock of a set.
type setLock struct {
	id                                 *ua.NodeID
	initLock, renew, exitLock, breakIt *ua.NodeID
}

// cmLockingUser is the LockingUser of a set not in edit (§6.8.2).
const cmLockingUser = "CM"

func (c *ConnectionManager) buildLock(p *projector, obj *server.Node, sid string) error {
	if c.ns.DI == 0 {
		return errNoDI
	}
	di := c.ns.DI
	lk, err := p.b.object(sid+".Lock", qn(di, "Lock"), ua.NewNumericNodeID(di, diLockingServicesType))
	if err != nil {
		return err
	}
	obj.AddRef(lk, server.RefTypeIDHasComponent, true)
	s := p.s
	s.lock = &setLock{id: lk.ID()}
	for _, m := range []struct {
		name string
		dt   uint32
		get  func(v *cmView) any
	}{
		{"Locked", id.Boolean, func(*cmView) any { return true }},
		{"LockingClient", id.String, func(v *cmView) any {
			if v.set.edit != nil {
				return v.set.lockClient
			}
			return c.id.String()
		}},
		{"LockingUser", id.String, func(v *cmView) any {
			if v.set.edit != nil {
				return v.set.lockUser
			}
			return cmLockingUser
		}},
		{"RemainingLockTime", id.Duration, func(v *cmView) any {
			if v.set.edit == nil {
				return 0.0
			}
			left := v.set.deadline.Sub(c.now())
			if left < 0 {
				left = 0
			}
			return float64(left / time.Second * 1000)
		}},
	} {
		if _, err := p.p(lk, sid+".Lock."+m.name, qn(di, m.name), dt0(m.dt), -1, m.get); err != nil {
			return err
		}
	}
	for _, m := range []struct {
		name string
		at   **ua.NodeID
		h    func(ctx context.Context, s *cmSet) (int32, ua.StatusCode)
	}{
		{"InitLock", &s.lock.initLock, func(context.Context, *cmSet) (int32, ua.StatusCode) { return lockBusy, ua.StatusGood }},
		{"RenewLock", &s.lock.renew, c.renewLock},
		{"ExitLock", &s.lock.exitLock, c.exitLock},
		{"BreakLock", &s.lock.breakIt, c.breakLock},
	} {
		n, err := c.methodOf(p.b, lk, sid+".Lock."+m.name, qn(di, m.name), c.lockDeclaration(m.name))
		if err != nil {
			return err
		}
		*m.at = n.ID()
		h, key := m.h, s.key
		c.srv.RegisterMethod(lk.ID(), n.ID(), func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if c.isClosed() {
				return nil, ua.StatusBadShutdown
			}
			c.mu.Lock()
			s := c.sets[key.String()]
			c.mu.Unlock()
			if s == nil {
				return nil, ua.StatusBadNodeIDUnknown
			}
			st, sc := h(ctx, s)
			if sc != ua.StatusGood {
				return nil, sc
			}
			return []*ua.Variant{ua.MustVariant(st)}, ua.StatusGood
		})
	}
	return nil
}

var errNoDI = errorf("the server has no DI namespace for the Lock of the sets")

func errorf(msg string) error { return &cmError{msg} }

type cmError struct{ msg string }

func (e *cmError) Error() string { return ErrConnectionManager.Error() + ": " + e.msg }
func (e *cmError) Unwrap() error { return ErrConnectionManager }

// methodOf adds a Method with the InputArguments and OutputArguments of
// its declaration decl, such as a Method of LockingServicesType (OPC
// 10000-100 Tables 68 to 74).
func (c *ConnectionManager) methodOf(b *nodeBuilder, parent *server.Node, sid string, bn *ua.QualifiedName, decl *ua.NodeID) (*server.Node, error) {
	n := server.NewNode(ua.NewStringNodeID(c.ns.CM, sid), server.Attributes{
		ua.AttributeIDNodeClass:      server.DataValueFromValue(uint32(ua.NodeClassMethod)),
		ua.AttributeIDBrowseName:     server.DataValueFromValue(bn),
		ua.AttributeIDDisplayName:    server.DataValueFromValue(ua.NewLocalizedText(bn.Name)),
		ua.AttributeIDDescription:    server.DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDExecutable:     server.DataValueFromValue(true),
		ua.AttributeIDUserExecutable: server.DataValueFromValue(true),
	}, []*ua.ReferenceDescription{}, nil)
	if err := b.add(n, nil); err != nil {
		return nil, err
	}
	parent.AddRef(n, server.RefTypeIDHasComponent, true)
	if decl == nil {
		return n, nil
	}
	for _, r := range c.browse(decl, dt0(id.HasProperty)) {
		if r.BrowseName == nil || r.BrowseName.Name != "InputArguments" && r.BrowseName.Name != "OutputArguments" {
			continue
		}
		src := c.srv.Node(r.NodeID.NodeID)
		if src == nil || src.Value() == nil {
			continue
		}
		v := src.Value().Value
		pn, err := b.variableOf(sid+"."+r.BrowseName.Name, &ua.QualifiedName{Name: r.BrowseName.Name}, dt0(id.Argument), 1, dt0(id.PropertyType), false,
			func() *ua.DataValue { return server.DataValueFromValue(v) })
		if err != nil {
			return nil, err
		}
		n.AddReference(pn, dt0(id.HasProperty), true)
	}
	return n, nil
}

// lockDeclaration is the Method name of LockingServicesType.
func (c *ConnectionManager) lockDeclaration(name string) *ua.NodeID {
	for _, r := range c.browse(ua.NewNumericNodeID(c.ns.DI, diLockingServicesType), dt0(id.HasComponent)) {
		if r.BrowseName != nil && r.BrowseName.Name == name {
			return r.NodeID.NodeID
		}
	}
	return nil
}

func (c *ConnectionManager) browse(n, refType *ua.NodeID) []*ua.ReferenceDescription {
	ns, err := c.srv.Namespace(int(n.Namespace()))
	if err != nil {
		return nil
	}
	res := ns.Browse(&ua.BrowseDescription{NodeID: n, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: refType,
		IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)})
	if res == nil || res.StatusCode != ua.StatusOK {
		return nil
	}
	var out []*ua.ReferenceDescription
	for _, r := range res.References {
		if r.NodeID != nil && r.NodeID.NodeID != nil {
			out = append(out, r)
		}
	}
	return out
}

// callerOwnsSet reports whether the session of the Method holds the Lock of
// s.
func callerOwnsSet(ctx context.Context, s *cmSet) bool {
	mc, ok := server.MethodCallerFromContext(ctx)
	return ok && s.edit != nil && ownerOf(mc.SessionID) == s.owner
}

// renewLock is RenewLock (OPC 10000-100 §7.6): the owner renews.
func (c *ConnectionManager) renewLock(ctx context.Context, s *cmSet) (int32, ua.StatusCode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !callerOwnsSet(ctx, s) {
		return lockBusy, ua.StatusGood
	}
	s.deadline = c.now().Add(c.maxInactive)
	c.syncSetLocked(s.key)
	return lockOK, ua.StatusGood
}

// exitLock is ExitLock (OPC 10000-100 §7.7): the owner leaves the edit,
// DiscardUpdates (§6.7.4).
func (c *ConnectionManager) exitLock(ctx context.Context, s *cmSet) (int32, ua.StatusCode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !callerOwnsSet(ctx, s) {
		return lockBusy, ua.StatusGood
	}
	c.loseLockLocked(s)
	return lockOK, ua.StatusGood
}

// breakLock is BreakLock (OPC 10000-100 §7.8), for whom the CMAuthorizer
// allows: the edit is discarded (§6.7.4). The Lock of the ConnectionManager
// itself cannot be broken.
func (c *ConnectionManager) breakLock(ctx context.Context, s *cmSet) (int32, ua.StatusCode) {
	if sc := c.authorize(ctx, CMRequest{Operation: CMBreakLock, Set: s.id, Key: s.key}); sc != ua.StatusOK {
		return 0, sc
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.edit == nil {
		return lockBusy, ua.StatusGood
	}
	c.loseLockLocked(s)
	return lockOK, ua.StatusGood
}

// loseLockLocked ends the edit of s: its Lock went (§6.7.4).
func (c *ConnectionManager) loseLockLocked(s *cmSet) {
	s.edit, s.owner = nil, ""
	c.m.EditLockLost(s.key)
	c.syncSetLocked(s.key)
}

// tickLocks expires the Locks of the sets in edit and updates their
// RemainingLockTime.
func (c *ConnectionManager) tickLocks() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for _, s := range c.sets {
		if s.edit == nil {
			continue
		}
		if !now.Before(s.deadline) {
			c.log.Debug("uafx: the Lock of a set in edit expired", "set", s.key.String())
			c.loseLockLocked(s)
			continue
		}
		c.syncSetLocked(s.key)
	}
}

// cmGuard releases the Locks of a session that ended (OPC 10000-100 §7.2).
type cmGuard struct{ c *ConnectionManager }

func (cmGuard) CheckWrite(context.Context, *server.Session, *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}

func (cmGuard) CheckCall(context.Context, *server.Session, *ua.NodeID, *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}

func (g cmGuard) SessionEnded(sess *server.Session) {
	if sess == nil || sess.ID() == nil {
		return
	}
	owner := ownerOf(sess.ID())
	c := g.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sets {
		if s.edit != nil && s.owner == owner {
			c.loseLockLocked(s)
		}
	}
}

// --- SelectionList writes ---------------------------------------------------

// writer takes a client's write of a SelectionList Variable of a set
// (§6.8.1): allowed for the holder of the Lock of the set in edit, with the
// value RestrictToList allows, as the CMAuthorizer decides. The value goes
// to the working copy; CommitUpdates makes it the next Version.
func (c *ConnectionManager) writer(x *cmVar) server.ValueWriter {
	return func(ctx context.Context, w *server.ValueWrite) ua.StatusCode {
		if c.isClosed() {
			return ua.StatusBadShutdown
		}
		if w.Value == nil || w.Value.Value == nil {
			return ua.StatusBadTypeMismatch
		}
		s := x.set
		if sc := c.authorize(ctx, CMRequest{Operation: CMWrite, Set: s.id, Key: s.key, Node: x.id, Session: w.Session}); sc != ua.StatusOK {
			return sc
		}
		c.mu.Lock()
		if c.sets[s.key.String()] != s {
			c.mu.Unlock()
			return ua.StatusBadNodeIDUnknown
		}
		if s.edit == nil || w.Session == nil || ownerOf(w.Session.ID()) != s.owner {
			// The set is locked to the ConnectionManager or another
			// client (§6.8.2).
			c.mu.Unlock()
			return ua.StatusBadLocked
		}
		old := x.cur.Load()
		sc := x.write(s.edit.Conf(), w.Value.Value)
		if sc == ua.StatusGood {
			s.deadline = c.now().Add(c.maxInactive)
			c.syncSetLocked(s.key)
		}
		c.mu.Unlock()
		c.auditWrite(ctx, s, x, old, w.Value, sc)
		return sc
	}
}

// auditWrite reports an AuditUpdateConnectionConfigurationSetEventType
// event for a write of set data (§6.8.1, §8.5 Table 113).
func (c *ConnectionManager) auditWrite(ctx context.Context, s *cmSet, x *cmVar, old, nv *ua.DataValue, sc ua.StatusCode) {
	if !c.srv.Auditing() {
		return
	}
	ov := &ua.Variant{}
	if old != nil && old.Value != nil {
		ov = old.Value
	}
	c.srv.ReportAuditEvent(ctx, &server.BaseEvent{
		EventType:  ua.NewNumericNodeID(c.ns.CM, fxcmid.AuditUpdateConnectionConfigurationSetEventType),
		SourceNode: x.id,
		SourceName: "Attribute/Write",
		Message:    ua.NewLocalizedText(x.name + " of " + s.key.String() + ": " + sc.Error()),
		Fields: map[string]*ua.Variant{
			"Status":                         ua.MustVariant(sc == ua.StatusGood),
			"AttributeId":                    ua.MustVariant(uint32(ua.AttributeIDValue)),
			"IndexRange":                     ua.MustVariant(""),
			"OldValue":                       ov,
			"NewValue":                       nv.Value,
			"ConnectionConfigurationSetNode": ua.MustVariant(s.id),
			"Name":                           ua.MustVariant(s.key.Name),
		},
	}, c.id)
}
