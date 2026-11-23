// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"crypto/x509"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/di/diid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxacid"
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
		for _, r := range c.children(folder, id.Organizes) {
			x := r.NodeID.NodeID
			l.items = append(l.items, x)
			c.ctl.byItem[x.String()] = append(c.ctl.byItem[x.String()], l)
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

// --- the Guard ----------------------------------------------------------------

// lockGuard is the [server.SessionEndGuard] of the Locks.
type lockGuard struct{ c *Connections }

// CheckWrite implements [server.Guard]: a Variable of a held Lock of
// ListToBlock is not written, one of ListToRestrict only by the owner of
// the Lock (Part 81 §6.5.2); a write of the owner renews the Lock (OPC
// 10000-100 §7.7).
func (g lockGuard) CheckWrite(ctx context.Context, sess *server.Session, n *ua.NodeID) ua.StatusCode {
	return g.c.check(ctx, sess, n)
}

// CheckCall implements [server.Guard] for the Methods of the Locks as
// CheckWrite does for the Variables.
func (g lockGuard) CheckCall(ctx context.Context, sess *server.Session, _, method *ua.NodeID) ua.StatusCode {
	return g.c.check(ctx, sess, method)
}

func (c *Connections) check(ctx context.Context, sess *server.Session, n *ua.NodeID) ua.StatusCode {
	if n == nil {
		return ua.StatusOK
	}
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	ls := c.ctl.byItem[n.String()]
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
	now := time.Now()
	for _, l := range renew {
		l.deadline = now.Add(c.timeout(l))
	}
	return ua.StatusOK
}

// SessionEnded implements [server.SessionEndGuard]: the Locks a session
// took go with it (OPC 10000-100 §7.2). IsControlled stays (Part 81
// §6.5.2).
func (g lockGuard) SessionEnded(sess *server.Session) {
	c := g.c
	sid := sess.ID()
	if sid == nil {
		return
	}
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
		if l.owner != nil || c.conflict(l, o) {
			return lockBusy
		}
	}
	now := time.Now()
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
	now := time.Now()
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
	now := time.Now()
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
	if l.owner != nil || c.conflict(l, o) {
		return lockBusy, ua.StatusOK
	}
	l.owner, l.deadline = o, time.Now().Add(c.timeout(l))
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
	l.deadline = time.Now().Add(c.timeout(l))
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

// breakLock is BreakLock (OPC 10000-100 §7.8): who may call it is the
// AccessController's and the RolePermissions' to decide. IsControlled
// stays.
func (c *Connections) breakLock(_ context.Context, l *itemLock) (int32, ua.StatusCode) {
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
		now := time.Now()
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
// §6.5.2, OPC 10000-23): from the ConnectionEndpoint that controls it. A
// client has no Object in the address space to be the SourceNode.
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
