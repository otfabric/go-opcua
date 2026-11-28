// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxcmid"
	"github.com/otfabric/go-opcua/uafx/fxdataid"
)

// ErrConnectionManager is the error of EnableConnectionManager.
var ErrConnectionManager = errors.New("fxserver: ConnectionManager")

// CMOperation is an operation on the ConnectionManager a CMAuthorizer
// decides.
type CMOperation int

// The operations of a CMAuthorizer.
const (
	// CMEdit is EditConnectionConfigurationSets on one set (§6.7.4).
	CMEdit CMOperation = iota + 1
	// CMProcess is ProcessConnectionConfigurationSets on one set (§6.7.5).
	CMProcess
	// CMWrite is a write of a SelectionList Variable of a set (§6.8.1).
	CMWrite
	// CMFileWrite is Open for writing of ConnectionManagerConfiguration
	// (F.3.2), and CloseAndUpdate of the written file, which asks again
	// (F.3.3).
	CMFileWrite
	// CMBreakLock is BreakLock of the Lock of a set (OPC 10000-100 §7.8).
	CMBreakLock
)

func (o CMOperation) String() string {
	switch o {
	case CMEdit:
		return "Edit"
	case CMProcess:
		return "Process"
	case CMWrite:
		return "Write"
	case CMFileWrite:
		return "FileWrite"
	case CMBreakLock:
		return "BreakLock"
	}
	return fmt.Sprintf("CMOperation(%d)", int(o))
}

// CMRequest is an operation a CMAuthorizer decides.
type CMRequest struct {
	Operation CMOperation
	// Set is the ConnectionConfigurationSet Object; nil for CMFileWrite.
	Set *ua.NodeID
	// Key is the identity of the set; zero for CMFileWrite.
	Key fxcm.SetKey
	// Edit is the Action of CMEdit, Process that of CMProcess.
	Edit    uafx.FxEdit
	Process uafx.FxProcess
	// Node is the Variable of CMWrite; nil for the other operations.
	Node *ua.NodeID
	// Caller is the caller of the Method; nil for CMWrite.
	Caller *server.MethodCaller
	// Session is the session of the write of CMWrite; nil for the other
	// operations.
	Session *server.Session
}

// CMAuthorizer decides a CMRequest: [ua.StatusOK] allows it, any other
// StatusCode is the result for the set, the write or the Method, usually
// Bad_UserAccessDenied (Part 81 Tables 82 and 86, F.40).
type CMAuthorizer func(ctx context.Context, r CMRequest) ua.StatusCode

// ConnectionManagerOptions configure EnableConnectionManager.
type ConnectionManagerOptions struct {
	// Manager is the engine whose sets the server exposes. It is not
	// closed by Close.
	Manager *fxcm.Manager
	// Editable adds the Edit Property to every set, which
	// EditConnectionConfigurationSets needs (§6.8.2, §6.7.4): a set without
	// it is Bad_InvalidState.
	Editable bool
	// File adds ConnectionManagerConfiguration (Annex F.3).
	File bool
	// Authorizer decides Edit, Process, SelectionList writes, file writes
	// and BreakLock. Nil: the sessions with the well-known Role
	// ConfigureAdmin (Part 3 §4.9.2), which §6.8.2 and F.3.2 recommend.
	Authorizer CMAuthorizer
	// MaxInactiveLockTime is how long the Lock of a set in edit lasts
	// without RenewLock or a write of the set (OPC 10000-100 §7.2). Zero:
	// the MaxInactiveLockTime of the ServerCapabilities of DI, else one
	// minute.
	MaxInactiveLockTime time.Duration
	// Logger receives debug messages; nil is slog.Default.
	Logger *slog.Logger
	// Log adds the ConnectionManagerLog (Part 81 §6.7.2), a LogObject of
	// OPC 10000-26, or completes the one the ConnectionManager has: a
	// record for every call of EditConnectionConfigurationSets and
	// ProcessConnectionConfigurationSets, every EstablishConnections and
	// CloseConnections call of the Manager, every failure of a run
	// (§8.10, §8.11), every transition of a set state machine (§6.9.2)
	// and every SelectionList write (§6.8.2); and the ConditionClassId
	// LogEntryConditionClassType on the events of §8.4 to §8.6. It needs
	// fxcm.Options.TraceCalls on the Manager (§6.7.2). nil: no log (Table
	// 77: Optional).
	Log *LogOptions
}

// ConnectionManager exposes an fxcm.Manager as the ConnectionManager
// Object of a server (Part 81 §6.7, §12.3): its sets as
// ConnectionConfigurationSetType Objects, EditConnectionConfigurationSets,
// ProcessConnectionConfigurationSets, the events of the set state machines
// and, optionally, ConnectionManagerConfiguration (F.3).
type ConnectionManager struct {
	srv  *server.Server
	ns   Namespaces
	opts ConnectionManagerOptions
	m    *fxcm.Manager
	log  *slog.Logger

	id     *ua.NodeID // FxRoot.ConnectionManager
	folder *ua.NodeID // its ConnectionConfigurationSets

	// mu guards the projection: the sets, their nodes and the edits.
	mu      sync.Mutex
	sets    map[string]*cmSet // by SetKey.String
	byNode  map[string]*cmSet // by the NodeId of the set Object
	folders map[string]*ua.NodeID
	nodes   []*ua.NodeID // the CM-level nodes it added

	maxInactive time.Duration
	clock       func() time.Time // nil is time.Now

	file *cmFile
	// records is the ConnectionManagerLog, nil without opts.Log.
	records *Log

	// The events of the Manager, handled in order by loop. amu is held
	// while events are applied, so that a drain of a Method handler or of
	// Flush and the one of loop apply them in the order they came.
	amu    sync.Mutex
	qmu    sync.Mutex
	queue  []fxcm.Event
	wake   chan struct{}
	stop   chan struct{}
	done   chan struct{}
	remove func()
	closed sync.Once
}

// EnableConnectionManager exposes opts.Manager on srv, which must have the
// UAFX CM model (AddModel with ModelCM): the sets of the Manager below
// FxRoot.ConnectionManager.ConnectionConfigurationSets, the Methods
// EditConnectionConfigurationSets and ProcessConnectionConfigurationSets,
// AggregatedCurrentState, the Diagnostics counters and Capabilities
// (§6.7.2, §6.7.6), and with opts.File ConnectionManagerConfiguration
// (F.3). It adds a Guard to srv, which releases the Lock of a set in edit
// when its session ends (§6.7.4): call it before srv starts.
func EnableConnectionManager(srv *server.Server, ns Namespaces, opts ConnectionManagerOptions) (*ConnectionManager, error) {
	if ns.CM == 0 || ns.Data == 0 {
		return nil, fmt.Errorf("%w: the server has no UAFX CM model", ErrConnectionManager)
	}
	if opts.Manager == nil {
		return nil, fmt.Errorf("%w: no Manager", ErrConnectionManager)
	}
	if opts.Log != nil {
		if err := opts.Log.check(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConnectionManager, err)
		}
		if !opts.Manager.Options().TraceCalls {
			// §6.7.2: with the log, the SpanContext is passed with
			// each EstablishConnections call.
			return nil, fmt.Errorf("%w: %w: a log needs fxcm.Options.TraceCalls (Part 81 §6.7.2)", ErrConnectionManager, ErrLog)
		}
	}
	c := &ConnectionManager{srv: srv, ns: ns, opts: opts, m: opts.Manager, log: opts.Logger,
		id:     ua.NewNumericNodeID(ns.CM, fxcmid.FxRootConnectionManager),
		folder: ua.NewNumericNodeID(ns.CM, fxcmid.FxRootConnectionManagerConnectionConfigurationSets),
		sets:   map[string]*cmSet{}, byNode: map[string]*cmSet{}, folders: map[string]*ua.NodeID{},
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	if c.log == nil {
		c.log = slog.Default()
	}
	if srv.Node(c.id) == nil || srv.Node(c.folder) == nil {
		return nil, fmt.Errorf("%w: the server has no FxRoot.ConnectionManager", ErrConnectionManager)
	}
	c.maxInactive = c.serverMaxInactiveLockTime()
	edit := ua.NewNumericNodeID(ns.CM, fxcmid.FxRootConnectionManagerEditConnectionConfigurationSets)
	process := ua.NewNumericNodeID(ns.CM, fxcmid.FxRootConnectionManagerProcessConnectionConfigurationSets)
	for _, m := range []*ua.NodeID{edit, process} {
		if srv.Node(m) == nil {
			return nil, fmt.Errorf("%w: no Method %v", ErrConnectionManager, m)
		}
	}
	if err := c.addMembers(); err != nil {
		c.dropAll()
		return nil, fmt.Errorf("%w: %w", ErrConnectionManager, err)
	}
	if opts.File {
		f, err := c.addFile()
		if err != nil {
			c.dropAll()
			return nil, fmt.Errorf("%w: %w", ErrConnectionManager, err)
		}
		c.file = f
	}
	if opts.Log != nil {
		if err := c.addLog(); err != nil {
			c.dropAll()
			return nil, fmt.Errorf("%w: ConnectionManagerLog: %w", ErrConnectionManager, err)
		}
	}
	srv.RegisterMethod(c.id, edit, c.editHandler)
	srv.RegisterMethod(c.id, process, c.processHandler)
	srv.AddGuard(cmGuard{c})
	c.remove = c.m.AddObserver(fxcm.ObserverFunc(c.enqueue))
	c.mu.Lock()
	for _, k := range c.m.Keys() {
		c.syncSetLocked(k)
	}
	c.mu.Unlock()
	go c.loop()
	return c, nil
}

// Close stops following the Manager. The nodes and Methods stay; the
// Methods fail with Bad_Shutdown.
func (c *ConnectionManager) Close() error {
	c.closed.Do(func() {
		c.remove()
		close(c.stop)
		<-c.done
	})
	return nil
}

// SetNode returns the NodeId of the ConnectionConfigurationSet Object of
// key, false when the Manager has no such set.
func (c *ConnectionManager) SetNode(key fxcm.SetKey) (*ua.NodeID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sets[key.String()]
	if s == nil {
		return nil, false
	}
	return s.id, true
}

func (c *ConnectionManager) isClosed() bool {
	select {
	case <-c.stop:
		return true
	default:
		return false
	}
}

func (c *ConnectionManager) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

// serverMaxInactiveLockTime is the MaxInactiveLockTime of the set Locks.
func (c *ConnectionManager) serverMaxInactiveLockTime() time.Duration {
	if d := c.opts.MaxInactiveLockTime; d > 0 {
		return d
	}
	if c.ns.DI != 0 {
		if n := c.srv.Node(ua.NewNumericNodeID(c.ns.DI, diMaxInactiveLockTime)); n != nil {
			if dv := n.Value(); dv != nil && dv.Status == ua.StatusOK {
				if d := durationOf(dv.Value); d > 0 {
					return d
				}
			}
		}
	}
	return defaultMaxInactiveLockTime
}

// --- authorization ----------------------------------------------------------

// ConfigureAdmin returns the NodeId of the well-known Role ConfigureAdmin
// (Part 3 §4.9.2), which a [server.RoleMapper] grants to the sessions that
// may configure sets without a CMAuthorizer (§6.8.2, F.3.2).
func ConfigureAdmin() *ua.NodeID { return ua.NewNumericNodeID(0, id.WellKnownRoleConfigureAdmin) }

func (c *ConnectionManager) authorize(ctx context.Context, r CMRequest) ua.StatusCode {
	if r.Caller == nil && r.Session == nil {
		if mc, ok := server.MethodCallerFromContext(ctx); ok {
			r.Caller = mc
		}
	}
	if a := c.opts.Authorizer; a != nil {
		return a(ctx, r)
	}
	var roles []*ua.NodeID
	switch {
	case r.Caller != nil:
		roles = r.Caller.Roles
	case r.Session != nil:
		roles = r.Session.Roles()
	}
	if slices.ContainsFunc(roles, ConfigureAdmin().Equal) {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

// --- the Methods ------------------------------------------------------------

// The Message tags of the records of the Methods (§6.7.4, §6.7.5).
const (
	cmEditTag    = "ConnectionManager/EditConnection"
	cmProcessTag = "ConnectionManager/ProcessConnection"
)

// lookupSet resolves an element of the sets argument (Tables 82 and 86).
func (c *ConnectionManager) lookupSet(n *ua.NodeID) (*cmSet, ua.StatusCode) {
	if n == nil || n.Type() == ua.NodeIDTypeTwoByte && n.IntID() == 0 && n.Namespace() == 0 {
		return nil, ua.StatusBadNodeIDInvalid
	}
	c.mu.Lock()
	s := c.byNode[n.String()]
	c.mu.Unlock()
	if s != nil {
		return s, ua.StatusGood
	}
	if c.srv.Node(n) == nil {
		return nil, ua.StatusBadNodeIDUnknown
	}
	return nil, ua.StatusBadInvalidArgument
}

// setsArgs decodes the arguments of both Methods: an Int32 enumeration and
// a NodeId array.
func setsArgs(args []*ua.Variant) (int32, []*ua.NodeID, ua.StatusCode) {
	if len(args) != 2 {
		return 0, nil, ua.StatusBadArgumentsMissing
	}
	a, ok := args[0].Value().(int32)
	if !ok {
		return 0, nil, ua.StatusBadTypeMismatch
	}
	var sets []*ua.NodeID
	switch v := args[1].Value().(type) {
	case []*ua.NodeID:
		sets = v
	case nil:
	default:
		return 0, nil, ua.StatusBadTypeMismatch
	}
	return a, sets, ua.StatusGood
}

// methodStatus is the result of a Method from the results of its sets
// (Tables 81 and 85): Good when all are Good, Bad_UserAccessDenied when
// every set was refused for it, else Uncertain.
func methodStatus(results []ua.StatusCode) ua.StatusCode {
	denied, bad := 0, 0
	for _, r := range results {
		if r != ua.StatusGood {
			bad++
		}
		if r == ua.StatusBadUserAccessDenied {
			denied++
		}
	}
	switch {
	case bad == 0:
		return ua.StatusGood
	case denied == len(results):
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusUncertain
}

// owner is the LockOwner of the session of a Method or a write: the Lock
// is given to the client session of the call (§6.7.4).
func ownerOf(sessionID *ua.NodeID) fxcm.LockOwner {
	if sessionID == nil {
		return ""
	}
	return fxcm.LockOwner(sessionID.String())
}

// editHandler is EditConnectionConfigurationSets (§6.7.4, Tables 80 to
// 82).
func (c *ConnectionManager) editHandler(ctx context.Context, object, method *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if c.isClosed() {
		c.auditCall(ctx, method, args, nil, ua.StatusBadShutdown)
		c.logMethod(ctx, cmEditTag, "", nil, nil, ua.StatusBadShutdown)
		return nil, ua.StatusBadShutdown
	}
	a, sets, sc := setsArgs(args)
	if sc != ua.StatusGood {
		// §6.7.4: an audit event for all calls.
		c.auditCall(ctx, method, args, nil, sc)
		c.logMethod(ctx, cmEditTag, "", nil, nil, sc)
		return nil, sc
	}
	action := uafx.FxEdit(a)
	if action != uafx.StartEditing && action != uafx.CommitUpdates && action != uafx.DiscardUpdates {
		c.auditCall(ctx, method, args, nil, ua.StatusBadInvalidArgument)
		c.logMethod(ctx, cmEditTag, action.String(), nil, nil, ua.StatusBadInvalidArgument)
		return nil, ua.StatusBadInvalidArgument
	}
	mc, _ := server.MethodCallerFromContext(ctx)
	var sess *ua.NodeID
	if mc != nil {
		sess = mc.SessionID
	}
	results := make([]ua.StatusCode, len(sets))
	for i, n := range sets {
		results[i] = c.editSet(ctx, n, action, sess)
	}
	// The address space shows the edit before the Method returns.
	c.drain()
	out := []*ua.Variant{ua.MustVariant(results)}
	st := methodStatus(results)
	c.auditCall(ctx, method, args, out, st)
	c.logMethod(ctx, cmEditTag, action.String(), sets, results, st)
	return out, st
}

func (c *ConnectionManager) editSet(ctx context.Context, n *ua.NodeID, action uafx.FxEdit, sess *ua.NodeID) ua.StatusCode {
	s, sc := c.lookupSet(n)
	if sc != ua.StatusGood {
		return sc
	}
	if sc := c.authorize(ctx, CMRequest{Operation: CMEdit, Set: s.id, Key: s.key, Edit: action}); sc != ua.StatusOK {
		return sc
	}
	if !c.opts.Editable {
		return ua.StatusBadInvalidState
	}
	owner := ownerOf(sess)
	if owner == "" {
		return ua.StatusBadInvalidState
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.expireLocked(s) {
		// The expired edit is gone; s may have been rebuilt. Library
		// interpretation: CommitUpdates of the edit that just expired is
		// Bad_InvalidState, not the Good of a commit outside edit, as its
		// changes were discarded.
		if action == uafx.CommitUpdates {
			return ua.StatusBadInvalidState
		}
		if s = c.sets[s.key.String()]; s == nil {
			return ua.StatusBadNodeIDUnknown
		}
	}
	switch action {
	case uafx.StartEditing:
		e, err := c.m.StartEdit(s.key, owner)
		if err != nil {
			return statusOr(err, ua.StatusBadInvalidState)
		}
		s.edit, s.owner = e, owner
		s.lockClient, s.lockUser = "", ""
		if mc, ok := server.MethodCallerFromContext(ctx); ok {
			s.lockClient, s.lockUser = mc.ClientApplicationURI, userOf(mc.Identity)
		}
		s.deadline = c.now().Add(c.maxInactive)
	case uafx.CommitUpdates:
		_, ok, err := c.m.CommitEdit(s.key, owner)
		if err != nil {
			if errors.Is(err, fxcm.ErrConfig) {
				// Library interpretation: an invalid working copy leaves
				// the set in edit; Table 82 has no code for it.
				return ua.StatusBadInvalidState
			}
			return statusOr(err, ua.StatusBadInvalidState)
		}
		if ok {
			s.edit, s.owner = nil, ""
		}
	case uafx.DiscardUpdates:
		ok, err := c.m.DiscardEdit(s.key, owner)
		if err != nil {
			return statusOr(err, ua.StatusBadInvalidState)
		}
		if ok {
			s.edit, s.owner = nil, ""
		}
	}
	c.syncSetLocked(s.key)
	return ua.StatusGood
}

// statusOr is the StatusCode of err, def when it has none.
func statusOr(err error, def ua.StatusCode) ua.StatusCode {
	if sc := fxcm.StatusOf(err); sc != ua.StatusBad {
		return sc
	}
	return def
}

// processHandler is ProcessConnectionConfigurationSets (§6.7.5, Tables 84
// to 86): it starts the runs and returns; the events of §8.7 to §8.9 tell
// the outcome.
func (c *ConnectionManager) processHandler(ctx context.Context, object, method *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if c.isClosed() {
		c.auditCall(ctx, method, args, nil, ua.StatusBadShutdown)
		c.logMethod(ctx, cmProcessTag, "", nil, nil, ua.StatusBadShutdown)
		return nil, ua.StatusBadShutdown
	}
	a, sets, sc := setsArgs(args)
	if sc != ua.StatusGood {
		// §6.7.5: an audit event for all calls.
		c.auditCall(ctx, method, args, nil, sc)
		c.logMethod(ctx, cmProcessTag, "", nil, nil, sc)
		return nil, sc
	}
	action := uafx.FxProcess(a)
	if fxcm.Activity(action) == 0 {
		c.auditCall(ctx, method, args, nil, ua.StatusBadNotSupported)
		c.logMethod(ctx, cmProcessTag, action.String(), nil, nil, ua.StatusBadNotSupported)
		return nil, ua.StatusBadNotSupported
	}
	results := make([]ua.StatusCode, len(sets))
	var keys []fxcm.SetKey
	var at []int
	for i, n := range sets {
		s, sc := c.lookupSet(n)
		if sc == ua.StatusGood {
			sc = c.authorize(ctx, CMRequest{Operation: CMProcess, Set: s.id, Key: s.key, Process: action})
		}
		if sc != ua.StatusOK {
			results[i] = sc
			continue
		}
		keys = append(keys, s.key)
		at = append(at, i)
	}
	for j, st := range c.m.Process(action, keys...) {
		if st.Err != nil {
			results[at[j]] = statusOr(st.Err, ua.StatusBadInvalidState)
		}
	}
	// A Good result means the run started (§6.7.5): the nodes show it
	// before the Method returns, so that a client that reads the state then
	// sees Processing or a later state of the run (it may have ended
	// already, §6.9.2), never the state before it.
	c.drain()
	out := []*ua.Variant{ua.MustVariant(results)}
	status := methodStatus(results)
	c.auditCall(ctx, method, args, out, status)
	c.logMethod(ctx, cmProcessTag, action.String(), sets, results, status)
	return out, status
}

// auditCall reports an AuditUpdateMethodResultEventType event for a call of
// one of the Methods, SourceNode the ConnectionManager (§6.7.4, §6.7.5).
func (c *ConnectionManager) auditCall(ctx context.Context, method *ua.NodeID, args, out []*ua.Variant, sc ua.StatusCode) {
	if !c.srv.Auditing() {
		return
	}
	if args == nil {
		args = []*ua.Variant{}
	}
	if out == nil {
		out = []*ua.Variant{}
	}
	name := "Method"
	if n := c.srv.Node(method); n != nil && n.BrowseName() != nil {
		name = n.BrowseName().Name
	}
	fields := map[string]*ua.Variant{
		"Status":          ua.MustVariant(sc.Uint32()&0x80000000 == 0),
		"MethodId":        ua.MustVariant(method),
		"InputArguments":  ua.MustVariant(variants(args)),
		"OutputArguments": ua.MustVariant(variants(out)),
		"StatusCodeId":    ua.MustVariant(sc),
	}
	if c.records != nil {
		fields = logEntryClass(fields)
	}
	c.srv.ReportAuditEvent(ctx, &server.BaseEvent{
		EventType:  ua.NewNumericNodeID(c.ns.Data, fxdataid.AuditUpdateMethodResultEventType),
		SourceNode: c.id,
		SourceName: "Method/" + name,
		Message:    ua.NewLocalizedText(name + ": " + sc.Error()),
		Fields:     fields,
	}, c.id)
}

// --- the events of the Manager ----------------------------------------------

func (c *ConnectionManager) enqueue(e fxcm.Event) {
	switch e.Kind {
	case fxcm.EventTransition, fxcm.EventCall, fxcm.EventMonitor,
		fxcm.EventSetAdded, fxcm.EventSetReplaced, fxcm.EventSetRemoved,
		fxcm.EventEditStarted, fxcm.EventCommitted, fxcm.EventEditEnded:
	default:
		return
	}
	c.qmu.Lock()
	c.queue = append(c.queue, e)
	c.qmu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// loop applies the events of the Manager to the address space, in order,
// and expires the Locks of the sets in edit.
func (c *ConnectionManager) loop() {
	defer close(c.done)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-c.wake:
			c.drain()
		case <-t.C:
			c.tickLocks()
		}
	}
}

// drain applies the events queued so far, in order: a barrier for the
// events reported before the call. An event queued before it is either in
// the batch it takes or was taken by a drain that held amu before it, and
// is applied when it gets amu. It takes one batch only, so that events
// that keep coming during a Method do not hold the Method up; the loop
// takes those after a wake.
func (c *ConnectionManager) drain() {
	c.amu.Lock()
	defer c.amu.Unlock()
	c.qmu.Lock()
	q := c.queue
	c.queue = nil
	c.qmu.Unlock()
	for _, e := range q {
		c.apply(e)
	}
}

// Flush applies the events the Manager reported so far to the address
// space: a caller that changed the Manager directly sees the change in the
// nodes afterwards.
func (c *ConnectionManager) Flush() { c.drain() }

func (c *ConnectionManager) apply(e fxcm.Event) {
	c.logEvent(e)
	switch e.Kind {
	case fxcm.EventTransition:
		c.mu.Lock()
		c.syncSetLocked(e.Set)
		s := c.sets[e.Set.String()]
		c.mu.Unlock()
		if s != nil {
			c.emitTransition(s, e)
		}
		c.refreshAggregated()
	case fxcm.EventCall:
		c.refreshCounters()
	default:
		// EventEditEnded carries no edit: it may come from an edit that
		// ended before another StartEditing (a Lock lost, then taken by
		// another session, §6.7.4). syncSetLocked ends the projected edit
		// only when the Manager has none, so a late event never ends the
		// edit of a later owner.
		c.mu.Lock()
		c.syncSetLocked(e.Set)
		c.mu.Unlock()
		c.refreshAggregated()
	}
}

// emitTransition reports the event of a transition (§6.9.2 Table 92,
// §8.6 to §8.9): ProcessingStarted on 1 and 4, ProcessingSucceeded on 2,
// ProcessingFailed on 3, SourceNode the ConnectionManager.
func (c *ConnectionManager) emitTransition(s *cmSet, e fxcm.Event) {
	t := e.Transition.Event()
	if t == 0 {
		return
	}
	action := e.Action
	if action < 0 {
		// Remove and Reconcile are no FxProcessEnum value: they close
		// what the set made, as ActionRemoveConnections does.
		action = uafx.ActionRemoveConnections
	}
	name := s.key.Name
	var sev uint16 = 200
	if e.Transition == fxcm.ProcessingToError {
		sev = 600
	}
	ev := &server.BaseEvent{
		EventType:  ua.NewNumericNodeID(c.ns.CM, t),
		SourceNode: c.id,
		SourceName: "ConnectionManager",
		Message:    ua.NewLocalizedText(fmt.Sprintf("%s of %s (%s)", e.Transition, s.key, action)),
		Severity:   sev,
		Fields: map[string]*ua.Variant{
			"ConnectionConfigurationSetNode": ua.MustVariant(s.id),
			"Name":                           ua.MustVariant(name),
			"Action":                         ua.MustVariant(int32(action)),
		},
	}
	if c.records != nil {
		ev.Fields = logEntryClass(ev.Fields)
	}
	if err := c.srv.EmitBaseEvent(c.id, ev); err != nil {
		c.log.Debug("uafx: event not emitted", "set", s.key.String(), "err", err)
	}
}

// --- the members of the ConnectionManager -----------------------------------

// addMembers adds the optional AggregatedCurrentState, Diagnostics and
// Capabilities (§6.7.2 Table 77, §6.7.6 Table 88).
func (c *ConnectionManager) addMembers() error {
	b := c.builder(&c.nodes)
	cm := c.srv.Node(c.id)
	agg, err := b.variable(c.id, "cm.AggregatedCurrentState", qn(c.ns.CM, "AggregatedCurrentState"), dt0(id.Boolean), -1, c.aggregated)
	if err != nil {
		return err
	}
	cm.AddRef(agg, server.RefTypeIDHasComponent, true)

	diag, err := b.object("cm.Diagnostics", qn(c.ns.DI, "Diagnostics"), ua.NewNumericNodeID(c.ns.DI, diFunctionalGroupType))
	if err != nil {
		return err
	}
	cm.AddRef(diag, server.RefTypeIDHasComponent, true)
	counters := []struct {
		name string
		get  func(fxcm.Counters) uint32
	}{
		{"EstablishCallCount", func(n fxcm.Counters) uint32 { return n.EstablishCallCount }},
		{"EstablishCallFailedCount", func(n fxcm.Counters) uint32 { return n.EstablishCallFailedCount }},
		{"CloseCallCount", func(n fxcm.Counters) uint32 { return n.CloseCallCount }},
		{"CloseCallFailedCount", func(n fxcm.Counters) uint32 { return n.CloseCallFailedCount }},
	}
	for _, k := range counters {
		get := k.get
		v, err := b.variable(diag.ID(), "cm.Diagnostics."+k.name, qn(c.ns.CM, k.name), dt0(id.UInt32), -1,
			func() any { return get(c.m.Counters()) })
		if err != nil {
			return err
		}
		diag.AddRef(v, server.RefTypeIDHasComponent, true)
	}

	caps, err := b.object("cm.Capabilities", qn(c.ns.CM, "Capabilities"), ua.NewNumericNodeID(c.ns.CM, fxcmid.ConnectionManagerCapabilitiesType))
	if err != nil {
		return err
	}
	cm.AddRef(caps, server.RefTypeIDHasComponent, true)
	o := c.m.Options()
	monitors := o.Monitor != nil
	for _, p := range []struct {
		name string
		dt   uint32
		v    any
	}{
		{"MaxConnectionConfigurationSets", id.UInt32, uint32(o.MaxConnectionConfigurationSets)},
		// The monitor of the Manager reads the Status of every endpoint of
		// the Connections it created, wherever they are (§6.7.6: All only
		// with Local).
		{"MonitorsLocalConnectionEndpoints", id.Boolean, monitors},
		{"MonitorsAllConnectionEndpoints", id.Boolean, monitors},
	} {
		v := p.v
		n, err := b.variable(caps.ID(), "cm.Capabilities."+p.name, qn(c.ns.CM, p.name), dt0(p.dt), -1, func() any { return v })
		if err != nil {
			return err
		}
		caps.AddReference(n, ua.NewNumericNodeID(c.ns.CM, fxcmid.HasCMCapability), true)
	}
	return nil
}

// aggregated is AggregatedCurrentState: TRUE when one or more set state
// machines are in Error (§6.7.2).
func (c *ConnectionManager) aggregated() any {
	for _, k := range c.m.Keys() {
		if st, ok := c.m.Status(k); ok && st.State == fxcm.StateError {
			return true
		}
	}
	return false
}

func (c *ConnectionManager) refreshAggregated() {
	c.srv.ChangeNotification(ua.NewStringNodeID(c.ns.CM, "cm.AggregatedCurrentState"))
}

func (c *ConnectionManager) refreshCounters() {
	for _, k := range []string{"EstablishCallCount", "EstablishCallFailedCount", "CloseCallCount", "CloseCallFailedCount"} {
		c.srv.ChangeNotification(ua.NewStringNodeID(c.ns.CM, "cm.Diagnostics."+k))
	}
}

// dropAll removes what EnableConnectionManager added after a failure.
func (c *ConnectionManager) dropAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cm := c.srv.Node(c.id)
	for i := len(c.nodes) - 1; i >= 0; i-- {
		n := c.nodes[i]
		if cm != nil {
			cm.RemoveRef(ua.NewExpandedNodeID(n, "", 0), dt0(id.HasComponent), true)
		}
		c.deleteNode(n)
	}
	c.nodes = nil
}

// deleteNode deletes the node n the ConnectionManager added.
func (c *ConnectionManager) deleteNode(n *ua.NodeID) {
	if ns, err := c.srv.Namespace(int(n.Namespace())); err == nil {
		if sc := ns.DeleteNode(n); sc != ua.StatusOK {
			c.log.Debug("uafx: node not deleted", "node", n, "status", sc)
		}
	}
}

// The DI nodes of the ConnectionManager.
const (
	diFunctionalGroupType = 1005 // FunctionalGroupType (OPC 10000-100 §4.5)
	diLockingServicesType = 6388 // LockingServicesType (OPC 10000-100 §7.2)
)

func qn(ns uint16, name string) *ua.QualifiedName {
	return &ua.QualifiedName{NamespaceIndex: ns, Name: name}
}
