// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"crypto/x509"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// ControlGroups (Part 81 §6.5) restrict the Variables and Methods of a
// FunctionalEntity with the LockingServices of OPC 10000-100 §7: each of
// the ControlItemFolders ListToBlock and ListToRestrict of a ControlGroup
// has a Lock. While the Lock of ListToBlock is held, no one writes the
// Variables or calls the Methods it organizes; while the Lock of
// ListToRestrict is held, only its owner does (§6.5.2). Other requests
// fail with Bad_Locked (OPC 10000-100 §7.5). The owner is a client
// application, identified by the ApplicationUri it sent with CreateSession
// (the LockingClient, OPC 10000-100 §7.2), or a ConnectionEndpoint, as
// which EstablishConnections and CloseConnections act (§6.5.2).
//
// An item of a list that is an Object stands for the nodes of its
// hierarchy: §6.5.2 locks the "Variables or Methods in the hierarchical
// structure of instances" and lets the lists include Objects, without
// saying more. The Lock covers the Object, the nodes it reaches with
// HierarchicalReferences (Part 3 §7.3) and the Methods called on them,
// ControlGroups excepted. The nodes are found when EnableConnections runs:
// a node added below such an Object later is not covered. An item that
// stands for more than 4096 nodes makes EnableConnections fail rather
// than leave a part of it unprotected.
//
// Establishing, releasing and reassigning control and breaking a Lock need
// the ControlAuthorizer of ConnectionOptions; without one, the well-known
// Role ConnectionAdmin (§5.9), as §6.5.3 to §6.5.5 recommend for the
// ControlGroup Methods and OPC 10000-100 §7.8 for BreakLock.

// ControlOperation is an operation of a ControlGroup a ControlAuthorizer
// decides.
type ControlOperation int

const (
	// ControlEstablish is EstablishControl (Part 81 §6.5.3) and
	// EstablishControlCmd (§6.2.4.3.6).
	ControlEstablish ControlOperation = iota + 1
	// ControlRelease is ReleaseControl (§6.5.4).
	ControlRelease
	// ControlReassign is ReassignControl (§6.5.5) and ReassignControlCmd
	// (§6.2.4.3.8).
	ControlReassign
	// ControlBreakLock is BreakLock of the Lock of a ControlItemFolder
	// (OPC 10000-100 §7.8, Part 81 §6.5.2).
	ControlBreakLock
	// ControlCloseRemove is CloseConnections with Remove of a
	// ConnectionEndpoint that controls the ControlGroup, which releases it
	// (§6.2.5.2).
	ControlCloseRemove
	// ControlWriteAsEndpoint is SetConfigurationDataCmd writing, as a
	// ConnectionEndpoint (§6.2.4.3.7), a Variable of a Lock that endpoint
	// holds.
	ControlWriteAsEndpoint
)

// String returns the name of the Method.
func (o ControlOperation) String() string {
	switch o {
	case ControlEstablish:
		return "EstablishControl"
	case ControlRelease:
		return "ReleaseControl"
	case ControlReassign:
		return "ReassignControl"
	case ControlBreakLock:
		return "BreakLock"
	case ControlCloseRemove:
		return "CloseConnections"
	case ControlWriteAsEndpoint:
		return "SetConfigurationDataCmd"
	}
	return "ControlOperation(" + strconv.Itoa(int(o)) + ")"
}

// ControlRequest is an operation a ControlAuthorizer decides.
type ControlRequest struct {
	Operation ControlOperation
	// Group is the ControlGroup.
	Group *ua.NodeID
	// Lock is the Lock of BreakLock and ControlWriteAsEndpoint; nil for
	// the other operations.
	Lock *ua.NodeID
	// Endpoint is the ConnectionEndpoint of ControlCloseRemove and
	// ControlWriteAsEndpoint; nil for the other operations.
	Endpoint *ua.NodeID
	// Node is the Variable of ControlWriteAsEndpoint; nil for the other
	// operations.
	Node *ua.NodeID
	// LockContext names the owner EstablishControl and ReassignControl
	// give the ControlGroup to (Part 81 Table 64): an ApplicationUri, the
	// NodeId of a ConnectionEndpoint in string form, or "" for the caller.
	// EstablishControlCmd has the caller's ApplicationUri,
	// ReassignControlCmd the NodeId of the ConnectionEndpoint.
	LockContext string
	// Caller is the caller of the Method, or of EstablishConnections for
	// the commands; nil without one.
	Caller *server.MethodCaller
}

// ControlAuthorizer decides a ControlRequest: [ua.StatusOK] allows it, any
// other StatusCode is the result of the Method or command, usually
// Bad_UserAccessDenied (Part 81 Tables 65, 67 and 70, OPC 10000-100 §7.2).
// It runs before the operation, under the lock that serializes the
// connection Methods: it must not call them.
type ControlAuthorizer func(ctx context.Context, r ControlRequest) ua.StatusCode

// ConnectionAdmin returns the NodeId of the well-known Role ConnectionAdmin
// (Part 81 §5.9) in the Data namespace, which a [server.RoleMapper] grants
// to the sessions that may establish, release and reassign control and
// break Locks without a ControlAuthorizer; nil without a Data namespace.
func (n Namespaces) ConnectionAdmin() *ua.NodeID {
	if n.Data == 0 {
		return nil
	}
	return ua.NewNumericNodeID(n.Data, fxdataid.ServerServerCapabilitiesRoleSetConnectionAdmin)
}

// authorize decides r with the ControlAuthorizer, or by the Role
// ConnectionAdmin.
func (c *Connections) authorize(ctx context.Context, r ControlRequest) ua.StatusCode {
	if mc, ok := server.MethodCallerFromContext(ctx); ok {
		r.Caller = mc
	}
	if a := c.opts.ControlAuthorizer; a != nil {
		return a(ctx, r)
	}
	admin := c.ns.ConnectionAdmin()
	if r.Caller != nil && admin != nil && slices.ContainsFunc(r.Caller.Roles, admin.Equal) {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

// The LockStatus values of EstablishControl, ReassignControl and the
// LockingServices Methods (Part 81 Tables 64 and 69, OPC 10000-100 Tables
// 68, 70, 72 and 74).
const (
	lockOK      int32 = 0
	lockBusy    int32 = -1 // E_AlreadyLocked, or E_NotLocked
	lockInvalid int32 = -2 // E_Invalid
)

// endpointLockingUser is the LockingUser of a Lock a ConnectionEndpoint
// owns (Part 81 §6.5.2).
const endpointLockingUser = "UAFX"

// defaultMaxInactiveLockTime is the MaxInactiveLockTime of a server whose
// ServerCapabilities have none and that ConnectionOptions do not set.
const defaultMaxInactiveLockTime = time.Minute

// lockOwner is the owner of a Lock or the controller of a ControlGroup.
type lockOwner struct {
	client string // LockingClient
	user   string // LockingUser
	// endpoint is the ConnectionEndpoint that owns it; nil for a client.
	endpoint *endpoint
	// session is the session that took it for a client: the Lock goes
	// when the session ends (OPC 10000-100 §7.2).
	session *ua.NodeID
}

// same reports whether o and p are the same owner.
func (o *lockOwner) same(p *lockOwner) bool {
	switch {
	case o == nil || p == nil:
		return o == p
	case o.endpoint != nil || p.endpoint != nil:
		return o.endpoint == p.endpoint
	case o.client != "" || p.client != "":
		return o.client == p.client
	}
	return o.session != nil && o.session.Equal(p.session)
}

// itemLock is the Lock of a ControlItemFolder (Part 81 §6.5.6).
type itemLock struct {
	id     *ua.NodeID // the Lock Object
	folder *ua.NodeID
	group  *controlGroup
	block  bool // ListToBlock; else ListToRestrict
	items  []*ua.NodeID

	locked, client, user, remaining *ua.NodeID // its Properties

	// maxInactive is the MaxInactiveLockTime of the folder; 0 for that of
	// the server (Part 81 §6.5.6).
	maxInactive time.Duration

	owner    *lockOwner // nil when not locked
	deadline time.Time
	// active counts the writes and calls of its items that are running,
	// by who runs them (OPC 10000-100 §7.2).
	active map[actor]int
	// shown is the RemainingLockTime last written, in seconds.
	shown int64
}

// controlGroup is a ControlGroup (Part 81 §6.5).
type controlGroup struct {
	id              *ua.NodeID
	block, restrict *itemLock // nil when the group has no such Lock
	isControlled    *ua.NodeID

	// controller set IsControlled: EstablishControl or ReassignControl;
	// nil when the group is not controlled.
	controller *lockOwner
	// controlledBy is the SourceNode of the Controls Reference to the
	// group: the ConnectionEndpoint that controls it, or nil.
	controlledBy *ua.NodeID
}

func (g *controlGroup) locks() []*itemLock {
	var out []*itemLock
	for _, l := range []*itemLock{g.block, g.restrict} {
		if l != nil {
			out = append(out, l)
		}
	}
	return out
}

// controls holds the ControlGroups of the server.
type controls struct {
	mu          sync.Mutex
	groups      map[string]*controlGroup
	locks       map[string]*itemLock
	byItem      map[string][]*itemLock
	maxInactive time.Duration
	// clock replaces time.Now for the Locks in tests; nil is time.Now.
	clock atomic.Pointer[func() time.Time]
}

// now is the time of the Locks.
func (c *Connections) now() time.Time {
	if f := c.ctl.clock.Load(); f != nil {
		return (*f)()
	}
	return time.Now()
}

// actingKey marks the context of an EstablishConnections or
// CloseConnections command that acts as a ConnectionEndpoint (Part 81
// §6.5.2).
type actingKey struct{}

func actingAs(ctx context.Context, e *endpoint) context.Context {
	return context.WithValue(ctx, actingKey{}, e)
}

func actingEndpoint(ctx context.Context) *endpoint {
	e, _ := ctx.Value(actingKey{}).(*endpoint)
	return e
}

// --- setup ------------------------------------------------------------------

// setupControls finds the ControlGroups of the FunctionalEntities, serves
// their Methods and those of their Locks, and guards the items of the Locks.
func (c *Connections) setupControls() error {
	c.ctl.groups = map[string]*controlGroup{}
	c.ctl.locks = map[string]*itemLock{}
	c.ctl.byItem = map[string][]*itemLock{}
	c.ctl.maxInactive = c.serverMaxInactiveLockTime()
	for _, ac := range c.acs {
		for _, fe := range c.functionalEntities(ac) {
			for _, n := range c.hierarchy(c.childID(fe, "ControlGroups")) {
				if c.ctl.groups[n.String()] != nil || !c.isA(n, fxacid.ControlGroupType) {
					continue
				}
				if err := c.setupGroup(n); err != nil {
					return err
				}
			}
		}
	}
	if len(c.ctl.groups) > 0 {
		c.srv.AddGuard(lockGuard{c})
	}
	return nil
}

// serverMaxInactiveLockTime returns the MaxInactiveLockTime of the server
// (OPC 10000-100 §7.4): ConnectionOptions.MaxInactiveLockTime, which it
// writes to the Property of ServerCapabilities, else the value of that
// Property, else defaultMaxInactiveLockTime.
func (c *Connections) serverMaxInactiveLockTime() time.Duration {
	var prop *ua.NodeID
	if c.ns.DI != 0 {
		prop = ua.NewNumericNodeID(c.ns.DI, diMaxInactiveLockTime)
	}
	if d := c.opts.MaxInactiveLockTime; d > 0 {
		if prop != nil {
			c.write(prop, float64(d)/float64(time.Millisecond))
		}
		return d
	}
	if prop != nil {
		if d := durationOf(c.value(prop)); d > 0 {
			return d
		}
		c.write(prop, float64(defaultMaxInactiveLockTime)/float64(time.Millisecond))
	}
	return defaultMaxInactiveLockTime
}

// The MaxInactiveLockTime Property of ServerCapabilities (OPC 10000-100
// §7.4) and the Methods of LockingServicesType (§7.5 to §7.8) in the DI
// namespace (package diid).
const (
	diMaxInactiveLockTime = diid.MaxInactiveLockTime
	diInitLock            = diid.LockingServicesTypeInitLock
	diRenewLock           = diid.LockingServicesTypeRenewLock
	diExitLock            = diid.LockingServicesTypeExitLock
	diBreakLock           = diid.LockingServicesTypeBreakLock
)

// durationOf returns the Duration (milliseconds, Part 3 §8.13) v holds.
func durationOf(v *ua.Variant) time.Duration {
	if v == nil {
		return 0
	}
	ms, ok := v.Value().(float64)
	if !ok || math.IsNaN(ms) || ms <= 0 || ms > float64(math.MaxInt64/int64(time.Millisecond)) {
		return 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

func (c *Connections) setupGroup(n *ua.NodeID) error {
	g := &controlGroup{id: n, isControlled: c.childID(n, "IsControlled")}
	c.ctl.groups[n.String()] = g
	for _, f := range []struct {
		name  string
		block bool
		dst   **itemLock
	}{{"ListToBlock", true, &g.block}, {"ListToRestrict", false, &g.restrict}} {
		folder := c.childID(n, f.name)
		lock := c.diChild(folder, "Lock")
		if folder == nil || lock == nil {
			continue
		}
		l := &itemLock{id: lock, folder: folder, group: g, block: f.block,
			locked: c.diChild(lock, "Locked"), client: c.diChild(lock, "LockingClient"),
			user: c.diChild(lock, "LockingUser"), remaining: c.diChild(lock, "RemainingLockTime"),
			maxInactive: durationOf(c.value(c.diChild(folder, "MaxInactiveLockTime")))}
		seen := map[string]bool{}
		for _, r := range c.children(folder, id.Organizes) {
			nodes, err := c.controlled(r.NodeID.NodeID)
			if err != nil {
				return fmt.Errorf("%w: ControlGroup %s, %s: %w", ErrConnections, n, f.name, err)
			}
			for _, x := range nodes {
				if !seen[x.String()] {
					seen[x.String()] = true
					l.items = append(l.items, x)
					c.ctl.byItem[x.String()] = append(c.ctl.byItem[x.String()], l)
				}
			}
		}
		*f.dst = l
		c.ctl.locks[lock.String()] = l
		c.showLock(l)
		for _, m := range []struct {
			name string
			decl uint32
			h    server.MethodHandler
		}{
			{"InitLock", diInitLock, c.lockHandler(l, c.initLock)},
			{"RenewLock", diRenewLock, c.lockHandler(l, c.renewLock)},
			{"ExitLock", diExitLock, c.lockHandler(l, c.exitLock)},
			{"BreakLock", diBreakLock, c.lockHandler(l, c.breakLock)},
		} {
			mid := c.diChild(lock, m.name)
			if mid == nil {
				continue
			}
			if err := c.ensureArgumentsIn(mid, ua.NewNumericNodeID(c.ns.DI, m.decl)); err != nil {
				return err
			}
			c.srv.RegisterMethod(lock, mid, m.h)
		}
	}
	c.write(g.isControlled, false)
	for _, m := range []struct {
		name string
		decl uint32
		h    server.MethodHandler
	}{
		{"EstablishControl", fxacid.ControlGroupTypeEstablishControl, c.groupHandler(g, c.establishControl)},
		{"ReleaseControl", 0, c.groupHandler(g, c.releaseControl)},
		{"ReassignControl", fxacid.ControlGroupTypeReassignControl, c.groupHandler(g, c.reassignControl)},
	} {
		mid := c.childID(n, m.name)
		if mid == nil {
			continue
		}
		if m.decl != 0 {
			if err := c.ensureArguments(mid, m.decl); err != nil {
				return err
			}
		}
		c.srv.RegisterMethod(n, mid, m.h)
	}
	return nil
}

// maxControlled bounds the nodes an item of a ControlItemFolder stands for.
const maxControlled = 4096

// controlled returns the nodes the item n of a ControlItemFolder stands
// for: n and the nodes of its hierarchy, without ControlGroups and their
// members, whose Methods must stay callable. More nodes than the limit is
// an error: a Lock that covers a part of them would leave the rest
// unprotected.
func (c *Connections) controlled(n *ua.NodeID) ([]*ua.NodeID, error) {
	if c.isA(n, fxacid.ControlGroupType) {
		return nil, nil
	}
	limit := c.opts.maxControlled
	if limit <= 0 {
		limit = maxControlled
	}
	out := []*ua.NodeID{n}
	seen := map[string]bool{n.String(): true}
	for i := 0; i < len(out); i++ {
		for _, r := range c.children(out[i], id.HierarchicalReferences) {
			x := r.NodeID.NodeID
			if seen[x.String()] {
				continue
			}
			seen[x.String()] = true
			if c.isA(x, fxacid.ControlGroupType) {
				continue
			}
			if len(out) == limit {
				return nil, fmt.Errorf("item %s stands for more than %d nodes", n, limit)
			}
			out = append(out, x)
		}
	}
	return out, nil
}

// endpointLock returns a Lock that the ConnectionEndpoint e holds on the
// node n, or nil.
func (c *Connections) endpointLock(e *endpoint, n *ua.NodeID) *itemLock {
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	for _, l := range c.ctl.byItem[n.String()] {
		if l.owner != nil && l.owner.endpoint == e {
			return l
		}
	}
	return nil
}

// endpointGroups returns the ControlGroups the ConnectionEndpoint e
// controls.
func (c *Connections) endpointGroups(e *endpoint) []*ua.NodeID {
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	var out []*ua.NodeID
	for _, g := range c.ctl.groups {
		if g.controller != nil && g.controller.endpoint == e {
			out = append(out, g.id)
		}
	}
	return out
}

// --- the Guard ----------------------------------------------------------------

// actor is who runs a write or call: a ConnectionEndpoint a command acts
// as, or the client and session of the request.
type actor struct {
	endpoint *endpoint
	client   string
	session  string
}

func actorOf(ctx context.Context, sess *server.Session) actor {
	a := actor{}
	if ctx != nil {
		a.endpoint = actingEndpoint(ctx)
	}
	if sess != nil {
		a.client = sess.ClientApplicationURI()
		if id := sess.ID(); id != nil {
			a.session = id.String()
		}
	}
	return a
}

// permits reports whether the Lock of ListToRestrict owned by o lets a
// write or call of a, as isOwner does for a request.
func (o *lockOwner) permits(a actor) bool {
	switch {
	case o.endpoint != nil:
		return a.endpoint == o.endpoint
	case o.client != "":
		return a.endpoint == nil && a.client == o.client
	}
	return a.endpoint == nil && o.session != nil && o.session.String() == a.session
}

// prevented reports whether l, held by o, would prevent a write or call
// that is running: OPC 10000-100 §7.2 rejects the lock request then. It
// runs under c.ctl.mu.
func (l *itemLock) prevented(o *lockOwner) bool {
	for a := range l.active {
		if l.block || !o.permits(a) {
			return true
		}
	}
	return false
}

// lockGuard is the [server.SessionEndGuard] and [server.OperationGuard] of
// the Locks.
type lockGuard struct{ c *Connections }

// CheckWrite implements [server.Guard]: a Variable of a held Lock of
// ListToBlock is not written, one of ListToRestrict only by the owner of
// the Lock (Part 81 §6.5.2); a write of the owner renews the Lock (OPC
// 10000-100 §7.7).
func (g lockGuard) CheckWrite(ctx context.Context, sess *server.Session, n *ua.NodeID) ua.StatusCode {
	return g.c.check(ctx, sess, n)
}

// CheckCall implements [server.Guard] for the Methods of the Locks, and
// the Methods called on their Objects, as CheckWrite does for the
// Variables.
func (g lockGuard) CheckCall(ctx context.Context, sess *server.Session, object, method *ua.NodeID) ua.StatusCode {
	return g.c.check(ctx, sess, method, object)
}

// WriteDone implements [server.OperationGuard]: the write CheckWrite
// allowed is over.
func (g lockGuard) WriteDone(ctx context.Context, sess *server.Session, n *ua.NodeID) {
	g.c.operationDone(ctx, sess, n)
}

// CallDone implements [server.OperationGuard] for a call.
func (g lockGuard) CallDone(ctx context.Context, sess *server.Session, object, method *ua.NodeID) {
	g.c.operationDone(ctx, sess, method, object)
}

// covering returns the Locks whose items include the nodes ns. It runs
// under c.ctl.mu.
func (c *Connections) covering(ns []*ua.NodeID) []*itemLock {
	var ls []*itemLock
	for _, n := range ns {
		if n != nil {
			ls = append(ls, c.ctl.byItem[n.String()]...)
		}
	}
	return ls
}

// operationDone ends the operation check counted as active.
func (c *Connections) operationDone(ctx context.Context, sess *server.Session, ns ...*ua.NodeID) {
	a := actorOf(ctx, sess)
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	for _, l := range c.covering(ns) {
		if l.active[a]--; l.active[a] <= 0 {
			delete(l.active, a)
		}
	}
}

// check allows a write or call of the nodes ns or rejects it with
// Bad_Locked; an allowed one renews the Locks of its owner and is active
// until operationDone.
func (c *Connections) check(ctx context.Context, sess *server.Session, ns ...*ua.NodeID) ua.StatusCode {
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	ls := c.covering(ns)
	var renew []*itemLock
	for _, l := range ls {
		switch {
		case l.owner == nil:
		case l.block || !isOwner(ctx, sess, l.owner):
			return ua.StatusBadLocked
		default:
			renew = append(renew, l)
		}
	}
	now := c.now()
	for _, l := range renew {
		l.deadline = now.Add(c.timeout(l))
	}
	a := actorOf(ctx, sess)
	for _, l := range ls {
		if l.active == nil {
			l.active = map[actor]int{}
		}
		l.active[a]++
	}
	return ua.StatusOK
}

// SessionEnded implements [server.SessionEndGuard]: the Locks a session
// took go with it (OPC 10000-100 §7.2). IsControlled stays (Part 81
// §6.5.2). It waits for the EstablishConnections or CloseConnections call
// in progress, as tickLocks does: a session that ends during its own
// EstablishConnections does not take the Locks of EstablishControlCmd
// before ReassignControlCmd gives them to the ConnectionEndpoint.
func (g lockGuard) SessionEnded(sess *server.Session) {
	c := g.c
	sid := sess.ID()
	if sid == nil {
		return
	}
	c.call.Lock()
	defer c.call.Unlock()
	var changed []*itemLock
	c.ctl.mu.Lock()
	for _, l := range c.ctl.locks {
		if l.owner != nil && l.owner.endpoint == nil && sid.Equal(l.owner.session) {
			l.owner = nil
			changed = append(changed, l)
		}
	}
	c.ctl.mu.Unlock()
	c.showLock(changed...)
}

// isOwner reports whether the request of sess with ctx comes from o: a
// command acting as its ConnectionEndpoint, or a session of its client.
func isOwner(ctx context.Context, sess *server.Session, o *lockOwner) bool {
	if o.endpoint != nil {
		return ctx != nil && actingEndpoint(ctx) == o.endpoint
	}
	if sess == nil {
		return false
	}
	if o.client != "" {
		return sess.ClientApplicationURI() == o.client
	}
	return o.session != nil && o.session.Equal(sess.ID())
}

// callerOwns reports whether the caller of a Method is o.
func callerOwns(ctx context.Context, o *lockOwner) bool {
	if o.endpoint != nil {
		return actingEndpoint(ctx) == o.endpoint
	}
	mc, ok := server.MethodCallerFromContext(ctx)
	if !ok {
		return false
	}
	if o.client != "" {
		return mc.ClientApplicationURI == o.client
	}
	return o.session != nil && o.session.Equal(mc.SessionID)
}

// --- Locks ------------------------------------------------------------------

func (c *Connections) timeout(l *itemLock) time.Duration {
	if l.maxInactive > 0 {
		return l.maxInactive
	}
	return c.ctl.maxInactive
}

// conflict reports whether an item of l is in a held Lock of another
// ControlGroup with another owner than o (Part 81 §6.5.2).
func (c *Connections) conflict(l *itemLock, o *lockOwner) bool {
	for _, it := range l.items {
		for _, other := range c.ctl.byItem[it.String()] {
			if other.group != l.group && other.owner != nil && !other.owner.same(o) {
				return true
			}
		}
	}
	return false
}

// acquire takes the Locks of g for o, all or none (Part 81 §6.5.3).
// It runs under c.ctl.mu.
func (c *Connections) acquire(g *controlGroup, o *lockOwner) int32 {
	ls := g.locks()
	if len(ls) == 0 {
		return lockInvalid
	}
	for _, l := range ls {
		if l.owner != nil || c.conflict(l, o) || l.prevented(o) {
			return lockBusy
		}
	}
	now := c.now()
	for _, l := range ls {
		l.owner, l.deadline = o, now.Add(c.timeout(l))
	}
	return lockOK
}

// showLock writes the Properties of the Locks ls (OPC 10000-100 §7.2).
func (c *Connections) showLock(ls ...*itemLock) {
	type props struct {
		l            *itemLock
		locked       bool
		client, user string
		remaining    float64
	}
	now := c.now()
	var ps []props
	c.ctl.mu.Lock()
	for _, l := range ls {
		p := props{l: l}
		if l.owner != nil {
			left := l.deadline.Sub(now)
			if l.owner.endpoint != nil && l.owner.endpoint.Status() != uafx.ConnectionEndpointError {
				left = c.timeout(l)
			}
			left = max(left, 0)
			p.locked, p.client, p.user = true, l.owner.client, l.owner.user
			p.remaining = float64(left) / float64(time.Millisecond)
			l.shown = int64(left / time.Second)
		}
		ps = append(ps, p)
	}
	c.ctl.mu.Unlock()
	for _, p := range ps {
		c.write(p.l.locked, p.locked)
		c.write(p.l.client, p.client)
		c.write(p.l.user, p.user)
		c.write(p.l.remaining, p.remaining)
	}
}

// tickLocks renews the Locks of ConnectionEndpoints whose Status is not
// Error (Part 81 §6.5.2), releases the Locks that timed out (OPC 10000-100
// §7.4) and updates RemainingLockTime. It runs between calls, under
// c.call, as expireDue does: a Lock an EstablishConnections took with
// EstablishControlCmd does not time out before the ReassignControlCmd of
// the same call, however short the MaxInactiveLockTime.
func (c *Connections) tickLocks() {
	c.call.Lock()
	defer c.call.Unlock()
	now := c.now()
	var changed []*itemLock
	c.ctl.mu.Lock()
	for _, l := range c.ctl.locks {
		if l.owner == nil {
			continue
		}
		if e := l.owner.endpoint; e != nil && e.Status() != uafx.ConnectionEndpointError {
			l.deadline = now.Add(c.timeout(l))
		}
		switch left := l.deadline.Sub(now); {
		case left <= 0:
			l.owner = nil
			changed = append(changed, l)
		case int64(left/time.Second) != l.shown:
			changed = append(changed, l)
		}
	}
	c.ctl.mu.Unlock()
	c.showLock(changed...)
}

// lockHandler serves a Method of the Lock l with f, which returns the
// LockStatus.
func (c *Connections) lockHandler(l *itemLock, f func(ctx context.Context, l *itemLock) (int32, ua.StatusCode)) server.MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		c.call.Lock()
		defer c.call.Unlock()
		st, sc := f(ctx, l)
		if sc != ua.StatusOK {
			return nil, sc
		}
		c.showLock(l)
		return []*ua.Variant{ua.MustVariant(st)}, ua.StatusOK
	}
}

// callerOwner is the owner the caller of a Method becomes: its client.
func callerOwner(ctx context.Context) *lockOwner {
	o := &lockOwner{}
	if mc, ok := server.MethodCallerFromContext(ctx); ok {
		o.client, o.session, o.user = mc.ClientApplicationURI, mc.SessionID, userOf(mc.Identity)
	}
	return o
}

// initLock is InitLock (OPC 10000-100 §7.5). The LockingServices of a
// controlled ControlGroup are its controller's (Part 81 §6.5.2).
func (c *Connections) initLock(ctx context.Context, l *itemLock) (int32, ua.StatusCode) {
	o := callerOwner(ctx)
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	if g := l.group.controller; g != nil && (g.endpoint != nil || !callerOwns(ctx, g)) {
		return 0, ua.StatusBadUserAccessDenied
	}
	if l.owner != nil || c.conflict(l, o) || l.prevented(o) {
		return lockBusy, ua.StatusOK
	}
	l.owner, l.deadline = o, c.now().Add(c.timeout(l))
	return lockOK, ua.StatusOK
}

// renewLock is RenewLock (OPC 10000-100 §7.7): the owner only.
func (c *Connections) renewLock(ctx context.Context, l *itemLock) (int32, ua.StatusCode) {
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	switch {
	case l.owner == nil:
		return lockBusy, ua.StatusOK
	case !callerOwns(ctx, l.owner):
		return 0, ua.StatusBadUserAccessDenied
	}
	l.deadline = c.now().Add(c.timeout(l))
	return lockOK, ua.StatusOK
}

// exitLock is ExitLock (OPC 10000-100 §7.6): the owner only. IsControlled
// stays (Part 81 §6.5.2).
func (c *Connections) exitLock(ctx context.Context, l *itemLock) (int32, ua.StatusCode) {
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	switch {
	case l.owner == nil:
		return lockBusy, ua.StatusOK
	case !callerOwns(ctx, l.owner):
		return 0, ua.StatusBadUserAccessDenied
	}
	l.owner = nil
	return lockOK, ua.StatusOK
}

// breakLock is BreakLock (OPC 10000-100 §7.8), for whom authorize allows.
// IsControlled stays.
func (c *Connections) breakLock(ctx context.Context, l *itemLock) (int32, ua.StatusCode) {
	if sc := c.authorize(ctx, ControlRequest{Operation: ControlBreakLock, Group: l.group.id, Lock: l.id}); sc != ua.StatusOK {
		return 0, sc
	}
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	if l.owner == nil {
		return lockBusy, ua.StatusOK
	}
	l.owner = nil
	return lockOK, ua.StatusOK
}

// --- ControlGroup Methods -------------------------------------------------------

// groupHandler serves a Method of the ControlGroup g with f.
func (c *Connections) groupHandler(g *controlGroup, f func(ctx context.Context, g *controlGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)) server.MethodHandler {
	return func(ctx context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		c.call.Lock()
		defer c.call.Unlock()
		return f(ctx, g, args)
	}
}

// lockContext returns the LockContext argument; ok is false when it is not
// a String.
func lockContext(args []*ua.Variant) (string, bool) {
	if len(args) != 1 || args[0] == nil {
		return "", false
	}
	switch v := args[0].Value().(type) {
	case nil:
		return "", true
	case string:
		return v, true
	}
	return "", false
}

// ownerOf returns the owner a LockContext names (Part 81 Table 64): the
// ConnectionEndpoint whose NodeId it is in string form, or the client of
// that ApplicationUri; the caller's client for a null or empty one. It is
// nil for the NodeId of a node that is not a ConnectionEndpoint of the
// server.
func (c *Connections) ownerOf(ctx context.Context, lc string) *lockOwner {
	o := callerOwner(ctx)
	if lc == "" {
		return o
	}
	if n, err := ua.ParseNodeID(lc); err == nil && nodeIDString(lc) {
		c.mu.Lock()
		e := c.endpoints[n.String()]
		c.mu.Unlock()
		if e == nil {
			return nil
		}
		return &lockOwner{client: lc, user: endpointLockingUser, endpoint: e}
	}
	o.client = lc
	return o
}

// nodeIDString reports whether s is written as a NodeId (Part 6 §5.3.1.10):
// ua.ParseNodeID takes any other string as a String NodeId of namespace 0,
// an ApplicationUri too.
func nodeIDString(s string) bool {
	for _, p := range []string{"ns=", "nsu=", "i=", "s=", "g=", "b="} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// establishControl is EstablishControl (Part 81 §6.5.3).
func (c *Connections) establishControl(ctx context.Context, g *controlGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	lc, ok := lockContext(args)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	if sc := c.authorize(ctx, ControlRequest{Operation: ControlEstablish, Group: g.id, LockContext: lc}); sc != ua.StatusOK {
		return nil, sc
	}
	st := lockInvalid
	if o := c.ownerOf(ctx, lc); o != nil {
		st = c.control(g, o)
	}
	return []*ua.Variant{ua.MustVariant(st)}, ua.StatusOK
}

// control takes the Locks of g for o and makes o its controller.
func (c *Connections) control(g *controlGroup, o *lockOwner) int32 {
	c.ctl.mu.Lock()
	st := c.acquire(g, o)
	if st == lockOK {
		g.controller = o
	}
	c.ctl.mu.Unlock()
	if st == lockOK {
		c.showLock(g.locks()...)
		c.setControlled(g, o)
	}
	return st
}

// releaseControl is ReleaseControl (Part 81 §6.5.4). A ControlGroup a
// ConnectionEndpoint controls is released by CloseConnections (§6.5.2).
func (c *Connections) releaseControl(ctx context.Context, g *controlGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 0 {
		return nil, ua.StatusBadInvalidArgument
	}
	if sc := c.authorize(ctx, ControlRequest{Operation: ControlRelease, Group: g.id}); sc != ua.StatusOK {
		return nil, sc
	}
	if sc := c.mayChange(ctx, g); sc != ua.StatusOK {
		return nil, sc
	}
	c.release(g)
	return nil, ua.StatusOK
}

// mayChange reports whether the caller may release or reassign the control
// of g: its controller, or the owner of its Locks when it has none. A
// ConnectionEndpoint's are changed only by EstablishConnections and
// CloseConnections acting as it (Part 81 §6.5.2).
func (c *Connections) mayChange(ctx context.Context, g *controlGroup) ua.StatusCode {
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	owners := []*lockOwner{g.controller}
	for _, l := range g.locks() {
		owners = append(owners, l.owner)
	}
	for _, o := range owners {
		if o != nil && !callerOwns(ctx, o) {
			return ua.StatusBadUserAccessDenied
		}
	}
	return ua.StatusOK
}

// release releases the Locks of g, clears IsControlled and removes the
// Controls Reference (Part 81 §6.5.4).
func (c *Connections) release(g *controlGroup) {
	c.ctl.mu.Lock()
	for _, l := range g.locks() {
		l.owner = nil
	}
	g.controller = nil
	c.ctl.mu.Unlock()
	c.showLock(g.locks()...)
	c.setControlled(g, nil)
}

// reassignControl is ReassignControl (Part 81 §6.5.5).
func (c *Connections) reassignControl(ctx context.Context, g *controlGroup, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	lc, ok := lockContext(args)
	if !ok || lc == "" {
		return nil, ua.StatusBadInvalidArgument
	}
	if sc := c.authorize(ctx, ControlRequest{Operation: ControlReassign, Group: g.id, LockContext: lc}); sc != ua.StatusOK {
		return nil, sc
	}
	if sc := c.mayChange(ctx, g); sc != ua.StatusOK {
		return nil, sc
	}
	o := c.ownerOf(ctx, lc)
	if o == nil {
		return nil, ua.StatusBadInvalidArgument
	}
	return []*ua.Variant{ua.MustVariant(c.reassign(g, o))}, ua.StatusOK
}

// reassign gives the held Locks of g to o and makes o its controller.
func (c *Connections) reassign(g *controlGroup, o *lockOwner) int32 {
	c.ctl.mu.Lock()
	var held []*itemLock
	for _, l := range g.locks() {
		if l.owner != nil {
			held = append(held, l)
		}
	}
	st := lockOK
	switch {
	case len(held) == 0:
		st = lockBusy // E_NotLocked
	default:
		for _, l := range held {
			if c.conflict(l, o) {
				st = lockInvalid
			}
		}
	}
	if st == lockOK {
		now := c.now()
		for _, l := range held {
			l.owner, l.deadline = o, now.Add(c.timeout(l))
		}
		g.controller = o
	}
	c.ctl.mu.Unlock()
	if st == lockOK {
		c.showLock(held...)
		c.setControlled(g, o)
	}
	return st
}

// setControlled sets IsControlled of g and its Controls Reference (Part 81
// §6.5.2, OPC 10000-23): from the ConnectionEndpoint that controls it. For
// a client, §6.5.2 wants it from "the Object associated with the Client
// connection" of OPC 10000-100, which the server does not have: a
// ControlGroup a client controls has no Controls Reference, its Locks name
// the client in LockingClient.
func (c *Connections) setControlled(g *controlGroup, o *lockOwner) {
	controls := ua.NewNumericNodeID(0, id.Controls)
	gn := c.node(g.id)
	c.ctl.mu.Lock()
	prev := g.controlledBy
	g.controlledBy = nil
	if o != nil && o.endpoint != nil {
		g.controlledBy = o.endpoint.id
	}
	next := g.controlledBy
	c.ctl.mu.Unlock()
	if prev != nil && gn != nil && (next == nil || !prev.Equal(next)) {
		if s := c.node(prev); s != nil {
			s.RemoveRef(ua.NewExpandedNodeID(g.id, "", 0), controls, true)
		}
	}
	if next != nil && gn != nil && (prev == nil || !prev.Equal(next)) {
		if s := c.node(next); s != nil {
			s.AddReference(gn, controls, true)
		}
	}
	c.write(g.isControlled, o != nil)
}

// releaseEndpoint releases the ControlGroups the ConnectionEndpoint e
// controls and the Locks it owns: it is being removed (Part 81 §6.5.2,
// §6.2.5.2).
func (c *Connections) releaseEndpoint(e *endpoint) {
	var groups []*controlGroup
	var locks []*itemLock
	c.ctl.mu.Lock()
	for _, g := range c.ctl.groups {
		if g.controller != nil && g.controller.endpoint == e {
			groups = append(groups, g)
		}
	}
	for _, l := range c.ctl.locks {
		if l.owner != nil && l.owner.endpoint == e {
			l.owner = nil
			locks = append(locks, l)
		}
	}
	c.ctl.mu.Unlock()
	c.showLock(locks...)
	for _, g := range groups {
		c.release(g)
	}
}

// userOf returns the LockingUser of a client with the identity tok (OPC
// 10000-100 §7.2): the user name, the subject of the certificate, or
// "Anonymous".
func userOf(tok ua.IdentityToken) string {
	switch t := tok.(type) {
	case *ua.UserNameIdentityToken:
		return t.UserName
	case *ua.X509IdentityToken:
		if cert, err := x509.ParseCertificate(t.CertificateData); err == nil {
			return cert.Subject.String()
		}
		return "X509"
	case *ua.IssuedIdentityToken:
		return "Issued"
	}
	return "Anonymous"
}
