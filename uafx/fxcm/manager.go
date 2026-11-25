// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// Defaults of Options (design §4.3, decision Q3).
const (
	DefaultCallTimeout                    = 30 * time.Second
	DefaultRollbackTimeout                = 2 * time.Minute
	DefaultParallelism                    = 8
	DefaultMaxConnectionConfigurationSets = 256
)

// Options configure a Manager.
type Options struct {
	// Dialer opens the sessions to the servers of the AutomationComponents
	// (§9.2, §13.2). Required; ClientDialer is the default implementation.
	Dialer Dialer
	// ApplicationURI is the ApplicationUri of this ConnectionManager, the
	// one its sessions present: the AutomationComponents record it in the
	// ConnectionManagerApplicationUri of the endpoints it creates (§6.6.2).
	// Required.
	ApplicationURI string
	// ExclusiveApplicationURI asserts that no other ConnectionManager uses
	// ApplicationURI, so that a matching ConnectionManagerApplicationUri
	// proves an endpoint ours after a lost response (design §5.4). Without
	// it such an endpoint stays Unresolved.
	ExclusiveApplicationURI bool
	// CallTimeout bounds each EstablishConnections and CloseConnections call
	// (decision D6). 0: DefaultCallTimeout.
	CallTimeout time.Duration
	// RollbackTimeout bounds the rollback of a run. 0:
	// DefaultRollbackTimeout.
	RollbackTimeout time.Duration
	// Parallelism bounds the AutomationComponents called at the same time
	// by one run (§6.7.3.2 recommends parallel calls). 0:
	// DefaultParallelism.
	Parallelism int
	// MaxConnectionConfigurationSets limits the sets (§6.7.6). 0:
	// DefaultMaxConnectionConfigurationSets.
	MaxConnectionConfigurationSets int
	// Retry processes a set in Error again by itself (§6.9.1, transition 4
	// by vendor-specific means), only as RetryAllowed says. Nil: never
	// (decision D5).
	Retry *RetryPolicy
	// Monitor watches the ConnectionEndpoints of the established
	// Connections (§4.7.2, §10.20). Nil: ConnectionState is
	// ConnectionNotMonitored.
	Monitor *MonitorOptions
	// Observer receives what the Manager does. It must not block.
	Observer Observer
	// Logger logs at Debug what the Observer receives, and failures. Nil:
	// slog.Default().
	Logger *slog.Logger
}

// RetryPolicy is when a set in Error is processed again: after Initial,
// doubled after each attempt up to Max, with up to a fifth of jitter, at
// most Attempts times in a row.
type RetryPolicy struct {
	Initial  time.Duration
	Max      time.Duration
	Attempts int
}

// MonitorOptions configure the monitoring of ConnectionEndpoints.
type MonitorOptions struct {
	// Interval is how often the Status of the endpoints is read. 0: 1 s.
	Interval time.Duration
	// Reestablish processes a set again, with the action of its last
	// establish run, when an endpoint of an established Connection
	// disappeared (§4.7.2: the CM could trigger it).
	Reestablish bool
}

// Counters are the Diagnostics of a ConnectionManager (§6.7.2 Table 78).
type Counters struct {
	EstablishCallCount       uint32
	EstablishCallFailedCount uint32
	CloseCallCount           uint32
	CloseCallFailedCount     uint32
}

// Manager is a UAFX ConnectionManager (OPC 10000-81 §6.7): it holds
// ConnectionConfigurationSets and processes them against the
// AutomationComponents. It is safe for concurrent use.
type Manager struct {
	opts Options
	log  *slog.Logger
	pool *pool
	res  resolutionCaches

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	runs atomic.Uint64

	mu     sync.Mutex
	sets   map[string]*set
	closed bool

	places placeLocks

	obs struct {
		mu   sync.RWMutex
		next int
		list map[int]Observer
	}

	counters struct {
		establish, establishFailed, close, closeFailed atomic.Uint32
	}

	monitorStop chan struct{}
}

// set is a ConnectionConfigurationSet of a Manager.
type set struct {
	mu      sync.Mutex
	cfg     *Config
	state   State
	edit    EditSlot
	diags   []*uafx.ConnectionDiagnostics
	records map[string]*record
	current *Run
	last    *Run
	// transition is the transition the state machine took last (§6.9.2),
	// 0 before the first.
	transition Transition
	// lastEstablish is the action of the last establish run, which the
	// monitor repeats with Reestablish.
	lastEstablish *uafx.FxProcess
	retries       int
	retry         *time.Timer
	removed       bool
}

// record is an EndpointRecord with what closing the endpoint needs.
type record struct {
	EndpointRecord
	addr   ServerAddress
	acNode *ua.NodeID
	// state is the last Status the monitor read, valid with monitored.
	state     uafx.ConnectionEndpointStatus
	monitored bool
}

func recordKey(addr ServerAddress, fe *ua.NodeID, name string) string {
	return addr.Address + "\x00" + strconv.Itoa(int(addr.SecurityMode)) + "\x00" + addr.SecurityPolicyURI + "\x00" + addr.ServerURI + "\x00" + fe.String() + "\x00" + name
}

func keyString(k SetKey) string {
	return strings.Join(append(slices.Clone(k.Folder), k.Name), "\x00")
}

// New returns a Manager without sets.
func New(opts Options) (*Manager, error) {
	if opts.Dialer == nil {
		return nil, managerError(ua.StatusBadInvalidArgument, "no Dialer")
	}
	if opts.ApplicationURI == "" {
		return nil, managerError(ua.StatusBadInvalidArgument, "no ApplicationURI: the ownership of endpoints is checked against it (§6.6.2)")
	}
	if opts.CallTimeout <= 0 {
		opts.CallTimeout = DefaultCallTimeout
	}
	if opts.RollbackTimeout <= 0 {
		opts.RollbackTimeout = DefaultRollbackTimeout
	}
	if opts.Parallelism <= 0 {
		opts.Parallelism = DefaultParallelism
	}
	if opts.MaxConnectionConfigurationSets <= 0 {
		opts.MaxConnectionConfigurationSets = DefaultMaxConnectionConfigurationSets
	}
	if r := opts.Retry; r != nil {
		cp := *r
		if cp.Initial <= 0 {
			cp.Initial = time.Second
		}
		if cp.Max < cp.Initial {
			cp.Max = cp.Initial
		}
		if cp.Attempts <= 0 {
			cp.Attempts = 1
		}
		opts.Retry = &cp
	}
	if mo := opts.Monitor; mo != nil {
		cp := *mo
		if cp.Interval <= 0 {
			cp.Interval = time.Second
		}
		opts.Monitor = &cp
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		opts: opts, log: log, pool: newPool(opts.Dialer),
		ctx: ctx, cancel: cancel,
		sets: map[string]*set{},
	}
	m.places.m = map[string]chan struct{}{}
	if opts.Monitor != nil {
		m.monitorStop = make(chan struct{})
		m.wg.Add(1)
		go m.monitor()
	}
	return m, nil
}

// Close stops the runs, retries and the monitor and closes the sessions.
// A run in progress, also the closes of a Replace or Remove, stops waiting
// for its calls (design §5.4: their outcome stays unknown) and ends in
// Error; Close returns after them. Later calls are ua.StatusBadShutdown.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	sets := make([]*set, 0, len(m.sets))
	for _, s := range m.sets {
		sets = append(sets, s)
	}
	m.mu.Unlock()
	for _, s := range sets {
		s.mu.Lock()
		if s.retry != nil {
			s.retry.Stop()
		}
		s.mu.Unlock()
	}
	m.cancel()
	if m.monitorStop != nil {
		close(m.monitorStop)
	}
	m.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), m.opts.CallTimeout)
	defer cancel()
	m.pool.close(ctx)
	return nil
}

// Options returns the Options of the Manager, with their defaults.
func (m *Manager) Options() Options { return m.opts }

// Counters returns the counters of the EstablishConnections and
// CloseConnections calls of the Manager (§6.7.2 Table 78). A call that
// returned Uncertain or Bad, or got no response, is a failed call.
func (m *Manager) Counters() Counters {
	return Counters{
		EstablishCallCount:       m.counters.establish.Load(),
		EstablishCallFailedCount: m.counters.establishFailed.Load(),
		CloseCallCount:           m.counters.close.Load(),
		CloseCallFailedCount:     m.counters.closeFailed.Load(),
	}
}

func (m *Manager) lookup(key SetKey) *set {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sets[keyString(key)]
}

// Keys returns the keys of the sets, sorted by Folder and Name.
func (m *Manager) Keys() []SetKey {
	m.mu.Lock()
	keys := make([]SetKey, 0, len(m.sets))
	for _, s := range m.sets {
		keys = append(keys, s.cfg.Key())
	}
	m.mu.Unlock()
	sort.Slice(keys, func(i, j int) bool { return keyString(keys[i]) < keyString(keys[j]) })
	return keys
}

// Config returns the committed configuration of a set.
func (m *Manager) Config(key SetKey) (*Config, bool) {
	s := m.lookup(key)
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg, true
}

// Status is a copy of the live state of a set.
type Status struct {
	State   State
	Version uint32
	// Editing is set while the set is in edit (Edit TRUE, §6.7.4).
	Editing bool
	// Diagnostics are the ConnectionsDiagnostics of the set (§6.8.2), one
	// per Connection, in the order of the set.
	Diagnostics []*uafx.ConnectionDiagnostics
	// Current is the run in progress, Last the last finished one.
	Current *Run
	Last    *Run
	// Transition is the transition the state machine of the set took last
	// (LastTransition, §6.9.2), 0 before the first.
	Transition Transition
	// Endpoints are the endpoints the Manager made, took or may have made
	// for the set (design §5.3).
	Endpoints []EndpointRecord
}

// Status returns the live state of a set.
func (m *Manager) Status(key SetKey) (Status, bool) {
	s := m.lookup(key)
	if s == nil {
		return Status{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status(m.opts.Monitor != nil), true
}

func (s *set) status(monitored bool) Status {
	st := Status{State: s.state, Version: s.cfg.version, Editing: s.edit.Editing() != nil, Current: s.current, Last: s.last, Transition: s.transition}
	st.Diagnostics = s.diagnostics(monitored)
	st.Endpoints = s.endpointList()
	return st
}

func (s *set) endpointList() []EndpointRecord {
	out := make([]EndpointRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r.EndpointRecord)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Endpoint.Connection != b.Endpoint.Connection {
			return a.Endpoint.Connection < b.Endpoint.Connection
		}
		if a.Endpoint.Endpoint != b.Endpoint.Endpoint {
			return a.Endpoint.Endpoint < b.Endpoint.Endpoint
		}
		return a.Name < b.Name
	})
	return out
}

// diagnostics returns a copy of the ConnectionsDiagnostics with the
// ConnectionState of now (§10.20).
func (s *set) diagnostics(monitored bool) []*uafx.ConnectionDiagnostics {
	out := make([]*uafx.ConnectionDiagnostics, len(s.diags))
	for i, d := range s.diags {
		cp := *d
		cp.ConnectionState = s.connectionState(s.cfg.conns[i], monitored)
		out[i] = &cp
	}
	return out
}

// connectionState returns the ConnectionState of cn (§10.20) from the
// records of its endpoints and the Status the monitor read.
func (s *set) connectionState(cn *connection, monitored bool) uafx.ConnectionState {
	if !monitored {
		return uafx.ConnectionNotMonitored
	}
	var st []uafx.ConnectionEndpointStatus
	for _, e := range cn.endpoints {
		r := s.recordOf(EndpointRef{cn.name, e.number})
		if r == nil || !r.Class.MayClose() || r.NodeID == nil {
			return ConnectionStateOf(true, false, 0, nil)
		}
		if !r.monitored {
			st = append(st, uafx.ConnectionEndpointInitial)
			continue
		}
		st = append(st, r.state)
	}
	if len(st) == 0 {
		return uafx.ConnectionNotEstablished
	}
	if len(st) == 1 {
		return ConnectionStateOf(true, true, st[0], nil)
	}
	return ConnectionStateOf(true, true, st[0], &st[1])
}

func (s *set) recordOf(ref EndpointRef) *record {
	for _, r := range s.records {
		if r.Endpoint == ref {
			return r
		}
	}
	return nil
}

// newDiagnostics returns the ConnectionsDiagnostics of a set that was not
// processed: no activity, no error (F.1.4).
func newDiagnostics(c *Config) []*uafx.ConnectionDiagnostics {
	out := make([]*uafx.ConnectionDiagnostics, len(c.conns))
	for i, cn := range c.conns {
		out[i] = &uafx.ConnectionDiagnostics{
			Name:            &ua.QualifiedName{Name: cn.name},
			ConnectionState: uafx.ConnectionNotMonitored,
			Endpoint1Status: ua.StatusGood, Endpoint2Status: ua.StatusGood,
		}
	}
	return out
}

// Add adds a set (F.3.3.2 ElementAdd): validated, Version 1, state Ready,
// not in edit, not processed (F.1.3, SM-8). A set of the same key is
// ua.StatusBadBrowseNameDuplicated; more than MaxConnectionConfigurationSets
// ua.StatusBadResourceUnavailable.
func (m *Manager) Add(conf *uafx.ConnectionConfigurationSetConf) (*Config, error) {
	cfg, err := NewConfig(conf)
	if err != nil {
		return nil, err
	}
	if err := m.addConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (m *Manager) addCheckLocked(k SetKey) error {
	switch {
	case m.closed:
		return managerError(ua.StatusBadShutdown, "the ConnectionManager is closed")
	case m.sets[keyString(k)] != nil:
		return managerError(ua.StatusBadBrowseNameDuplicated, "a set %s exists", k)
	case len(m.sets) >= m.opts.MaxConnectionConfigurationSets:
		return managerError(ua.StatusBadResourceUnavailable, "MaxConnectionConfigurationSets is %d", m.opts.MaxConnectionConfigurationSets)
	}
	return nil
}

func newSet(cfg *Config) *set {
	return &set{cfg: cfg, state: StateReady, diags: newDiagnostics(cfg), records: map[string]*record{}}
}

// Replace replaces a set (F.3.3.2 ElementReplace): conf is validated
// first, then the Connections of the old set are removed
// (CloseConnections with Remove TRUE for its known-owned endpoints), then
// conf becomes Version 1 of the set, in Ready, not processed. A set being
// processed or edited is ua.StatusBadInvalidState; no set of the key
// ua.StatusBadNoMatch. When a close fails, the old set stays, in Error,
// and the error has the StatusCode of the close (design §5.8).
func (m *Manager) Replace(ctx context.Context, conf *uafx.ConnectionConfigurationSetConf) (*Config, error) {
	cfg, err := NewConfig(conf)
	if err != nil {
		return nil, err
	}
	s, prev, err := m.claim(cfg.key)
	if err != nil {
		return nil, err
	}
	defer m.wg.Done()
	if err := m.removeConnections(ctx, s, prev); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cfg, s.state, s.diags, s.records, s.lastEstablish, s.retries = cfg, StateReady, newDiagnostics(cfg), map[string]*record{}, nil, 0
	s.current = nil
	s.mu.Unlock()
	m.observe(Event{Kind: EventSetReplaced, Set: cfg.key, Version: cfg.version})
	return cfg, nil
}

// Remove removes a set (F.3.3.2 ElementRemove): CloseConnections with
// Remove TRUE for its known-owned endpoints, then the set goes. A set
// being processed or edited is ua.StatusBadInvalidState; no set of the key
// ua.StatusBadNoMatch. When a close fails, the set stays, in Error.
func (m *Manager) Remove(ctx context.Context, key SetKey) error {
	s, prev, err := m.claim(key)
	if err != nil {
		return err
	}
	defer m.wg.Done()
	if err := m.removeConnections(ctx, s, prev); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.sets, keyString(key))
	m.mu.Unlock()
	s.mu.Lock()
	s.removed, s.current = true, nil
	s.mu.Unlock()
	m.observe(Event{Kind: EventSetRemoved, Set: key})
	return nil
}

// claim puts a set that is neither processed nor edited in Processing for
// a Replace or Remove, in one step under the lock of the set, so that no
// run starts on it meanwhile (Table 86: Process of a set in Processing is
// Bad_InvalidState). It returns the state the set was in. A claimed set
// is counted as a run, so that Close waits for it (as start does): the
// caller calls m.wg.Done when it is finished; a closed Manager is
// ua.StatusBadShutdown.
func (m *Manager) claim(key SetKey) (*set, State, error) {
	m.mu.Lock()
	closed := m.closed
	s := m.sets[keyString(key)]
	if !closed && s != nil {
		m.wg.Add(1)
	}
	m.mu.Unlock()
	switch {
	case closed:
		return nil, 0, managerError(ua.StatusBadShutdown, "the ConnectionManager is closed")
	case s == nil:
		return nil, 0, managerError(ua.StatusBadNoMatch, "no set %s", key)
	}
	s.mu.Lock()
	if s.edit.Editing() != nil {
		s.mu.Unlock()
		m.wg.Done()
		return nil, 0, managerError(ua.StatusBadInvalidState, "the set %s is being edited", key)
	}
	tr, err := Start(s.state)
	if err != nil {
		s.mu.Unlock()
		m.wg.Done()
		return nil, 0, managerError(ua.StatusBadInvalidState, "the set %s is being processed", key)
	}
	prev := s.state
	r := &Run{id: RunID(m.runs.Add(1)), key: key, version: s.cfg.version, action: ActionRemoveSet, done: make(chan struct{})}
	s.state, s.current, s.transition = StateProcessing, r, tr
	if s.retry != nil {
		s.retry.Stop()
		s.retry = nil
	}
	s.mu.Unlock()
	m.observe(Event{Kind: EventTransition, Set: key, Run: r.id, Transition: tr, Action: r.action})
	return s, prev, nil
}

// removeConnections closes the endpoints of s, which claim put in
// Processing from prev, for a Replace or Remove: a remove run. On a failure
// the set stays in Error. Close stops it as it stops a run.
func (m *Manager) removeConnections(ctx context.Context, s *set, prev State) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(m.ctx, cancel)()
	s.mu.Lock()
	r := s.current
	s.mu.Unlock()
	res := m.execute(ctx, s, r, prev)
	if res.State == StateError {
		return managerError(firstStatus(res.Failures), "the Connections of the set %s were not all closed", r.key)
	}
	return nil
}

func firstStatus(fs []Failure) ua.StatusCode {
	for _, f := range fs {
		if f.Status != ua.StatusGood && !f.consequence() {
			return f.Status
		}
	}
	return ua.StatusBadUnexpectedError
}

// Operation is one operation of a batch (F.3.3, Table F.40): exactly one of
// ElementAdd, ElementRemove, ElementReplace on Conf (for ElementRemove only
// its BrowseName and ConnectionConfigurationSetFolder count).
type Operation struct {
	Op   uafx.ConnectionConfigurationSetOperation
	Conf *uafx.ConnectionConfigurationSetConf
}

// Update applies a batch of operations as CloseAndUpdate does (F.3.3,
// design §5.8). First the whole batch is checked: one operation bit (FC-6,
// ua.StatusBadInvalidArgument; none ua.StatusBadNothingToDo), the names
// (ua.StatusBadBrowseNameDuplicated for an Add, ua.StatusBadNoMatch for a
// Remove or Replace), the state (ua.StatusBadInvalidState while processed
// or edited), and every new set. With requireComplete, one failure ends
// the call there: nothing is closed or changed, applied is false. Else the
// failed operations are dropped. Then the operations are applied in order;
// a remove or replace whose close fails fails (the old set stays, in
// Error), and with requireComplete the operations after it are skipped
// (ua.StatusBadInvalidState). applied is ChangesApplied of Table F.39:
// true when one or more operations were applied, false when none was.
// With requireComplete that is every operation, except when a close fails
// after earlier operations were applied: those stay applied and applied is
// true (library interpretation: Table F.39 has no value for a partial
// complete update; FALSE would say that nothing changed). results has one
// error per operation, nil for success.
func (m *Manager) Update(ctx context.Context, ops []Operation, requireComplete bool) (applied bool, results []error) {
	results = make([]error, len(ops))
	cfgs := make([]*Config, len(ops))
	m.mu.Lock()
	existing := map[string]bool{}
	for k := range m.sets {
		existing[k] = true
	}
	n := len(m.sets)
	m.mu.Unlock()
	for i, op := range ops {
		results[i] = m.checkOperation(op, existing, &n, &cfgs[i])
	}
	failed := slices.ContainsFunc(results, func(e error) bool { return e != nil })
	if failed && requireComplete {
		return false, results
	}
	stop := false
	for i, op := range ops {
		if results[i] != nil {
			continue
		}
		if stop {
			results[i] = managerError(ua.StatusBadInvalidState, "an earlier operation failed")
			continue
		}
		var err error
		switch op.Op {
		case uafx.ElementAdd:
			err = m.addConfig(cfgs[i])
		case uafx.ElementRemove:
			err = m.Remove(ctx, KeyOf(op.Conf))
		case uafx.ElementReplace:
			_, err = m.Replace(ctx, op.Conf)
		}
		if err != nil {
			results[i] = err
			stop = requireComplete
			continue
		}
		applied = true
	}
	return applied, results
}

func (m *Manager) addConfig(cfg *Config) error {
	m.mu.Lock()
	if err := m.addCheckLocked(cfg.key); err != nil {
		m.mu.Unlock()
		return err
	}
	m.sets[keyString(cfg.key)] = newSet(cfg)
	m.mu.Unlock()
	m.observe(Event{Kind: EventSetAdded, Set: cfg.key, Version: cfg.version})
	return nil
}

func (m *Manager) checkOperation(op Operation, existing map[string]bool, n *int, cfg **Config) error {
	switch op.Op {
	case uafx.ElementAdd, uafx.ElementRemove, uafx.ElementReplace:
	case 0:
		return managerError(ua.StatusBadNothingToDo, "no operation")
	default:
		return managerError(ua.StatusBadInvalidArgument, "the operation %v is not exactly one of ElementAdd, ElementRemove, ElementReplace (F.3.4)", op.Op)
	}
	if op.Conf == nil {
		return managerError(ua.StatusBadInvalidArgument, "no set")
	}
	k := keyString(KeyOf(op.Conf))
	if op.Op == uafx.ElementAdd {
		if existing[k] {
			return managerError(ua.StatusBadBrowseNameDuplicated, "a set %s exists", KeyOf(op.Conf))
		}
		if *n >= m.opts.MaxConnectionConfigurationSets {
			return managerError(ua.StatusBadResourceUnavailable, "MaxConnectionConfigurationSets is %d", m.opts.MaxConnectionConfigurationSets)
		}
	} else {
		if !existing[k] {
			return managerError(ua.StatusBadNoMatch, "no set %s", KeyOf(op.Conf))
		}
		s := m.lookup(KeyOf(op.Conf))
		if s != nil {
			s.mu.Lock()
			busy := s.state == StateProcessing || s.edit.Editing() != nil
			s.mu.Unlock()
			if busy {
				return managerError(ua.StatusBadInvalidState, "the set %s is being processed or edited", KeyOf(op.Conf))
			}
		}
	}
	if op.Op != uafx.ElementRemove {
		c, err := NewConfig(op.Conf)
		if err != nil {
			return err
		}
		*cfg = c
	}
	switch op.Op {
	case uafx.ElementAdd:
		existing[k] = true
		*n++
	case uafx.ElementRemove:
		delete(existing, k)
		*n--
	default:
	}
	return nil
}

// Process starts the processing of the sets with action (§6.7.5) and
// returns at once, one Started per key in the order of keys: Err is
// ua.StatusBadNodeIDUnknown for a key without a set, ua.StatusBadNotSupported
// for an action that is not one of FxProcessEnum, ua.StatusBadInvalidState
// for a set in Processing (Table 86); Run is set when the run started. A set
// in edit is processed with its last committed Config (decision D7).
func (m *Manager) Process(action uafx.FxProcess, keys ...SetKey) []Started {
	out := make([]Started, len(keys))
	for i, k := range keys {
		out[i] = m.start(k, action, false)
	}
	return out
}

// Started is the outcome of starting the processing of one set.
type Started struct {
	Run *Run
	Err error
}

// ActionReconcile is the Action of a Reconcile run: not a value of
// FxProcessEnum (§10.30 has no activity bit for it).
const ActionReconcile uafx.FxProcess = -1

// ActionRemoveSet is the Action of the run that closes the Connections of
// a set a Replace or Remove replaces or removes (F.3.3.2).
const ActionRemoveSet uafx.FxProcess = -2

func (m *Manager) start(k SetKey, action uafx.FxProcess, auto bool) Started {
	if action != ActionReconcile && Activity(action) == 0 {
		return Started{Err: managerError(ua.StatusBadNotSupported, "the action %v", action)}
	}
	// The run is counted under m.mu, so that Close, which sets closed
	// under it and then waits, sees it.
	m.mu.Lock()
	closed := m.closed
	s := m.sets[keyString(k)]
	if !closed && s != nil {
		m.wg.Add(1)
	}
	m.mu.Unlock()
	switch {
	case closed:
		return Started{Err: managerError(ua.StatusBadShutdown, "the ConnectionManager is closed")}
	case s == nil:
		return Started{Err: managerError(ua.StatusBadNodeIDUnknown, "no set %s", k)}
	}
	s.mu.Lock()
	tr, err := Start(s.state)
	if err != nil {
		s.mu.Unlock()
		m.wg.Done()
		return Started{Err: err}
	}
	if !auto {
		s.retries = 0
	}
	if s.retry != nil {
		s.retry.Stop()
		s.retry = nil
	}
	r := &Run{id: RunID(m.runs.Add(1)), key: s.cfg.Key(), version: s.cfg.version, action: action, done: make(chan struct{})}
	prev := s.state
	s.state = StateProcessing
	s.current, s.transition = r, tr
	s.mu.Unlock()
	m.observe(Event{Kind: EventTransition, Set: r.key, Run: r.id, Transition: tr, Action: r.action})
	go func() {
		defer m.wg.Done()
		m.execute(m.ctx, s, r, prev)
	}()
	return Started{Run: r}
}

// Reconcile starts a run that closes the known-owned endpoints of a set
// that its committed configuration does not need (survivors of an earlier
// Version or of a failed run, closes still pending) and checks its
// Unresolved endpoints again: one that disappeared is forgotten. It is a
// run without an Action of FxProcessEnum (ActionReconcile): transition 1 or
// 4 by vendor-specific means (§6.9.2).
func (m *Manager) Reconcile(key SetKey) Started { return m.start(key, ActionReconcile, false) }

// Verdict is the decision of Settle.
type Verdict int

// The verdicts of Settle.
const (
	// SettleOwned makes the endpoint KnownOwned: the next run closes it.
	SettleOwned Verdict = iota + 1
	// SettleForeign forgets the endpoint: the Manager never touches it.
	SettleForeign
)

// Settle decides an Unresolved endpoint of a set (design §5.4). It is an
// administrative decision: the Manager never makes it itself. The
// Observer receives it. An endpoint that is not Unresolved is
// ua.StatusBadInvalidState; no such endpoint ua.StatusBadNoMatch.
func (m *Manager) Settle(key SetKey, ep EndpointRef, verdict Verdict) error {
	if verdict != SettleOwned && verdict != SettleForeign {
		return managerError(ua.StatusBadInvalidArgument, "the verdict %d", verdict)
	}
	s := m.lookup(key)
	if s == nil {
		return managerError(ua.StatusBadNoMatch, "no set %s", key)
	}
	s.mu.Lock()
	var found *record
	var fk string
	for k, r := range s.records {
		if r.Endpoint == ep {
			found, fk = r, k
		}
	}
	switch {
	case found == nil:
		s.mu.Unlock()
		return managerError(ua.StatusBadNoMatch, "no endpoint %v of the set %s", ep, key)
	case found.Class != Unresolved:
		s.mu.Unlock()
		return managerError(ua.StatusBadInvalidState, "the endpoint %v is %v", ep, found.Class)
	case s.state == StateProcessing:
		s.mu.Unlock()
		return managerError(ua.StatusBadInvalidState, "the set %s is being processed", key)
	}
	if verdict == SettleOwned {
		found.Class = KnownOwned
	} else {
		delete(s.records, fk)
	}
	rec := found.EndpointRecord
	s.mu.Unlock()
	m.observe(Event{Kind: EventSettle, Set: key, Record: &rec, Verdict: verdict})
	return nil
}

// StartEdit is StartEditing (§6.7.4) of a set for owner: the set goes into
// edit with a working copy of its committed Config. See EditSlot.Start.
func (m *Manager) StartEdit(key SetKey, owner LockOwner) (*Edit, error) {
	s := m.lookup(key)
	if s == nil {
		return nil, managerError(ua.StatusBadNodeIDUnknown, "no set %s", key)
	}
	s.mu.Lock()
	started := s.edit.Editing() == nil
	e, err := s.edit.Start(s.cfg, owner)
	s.mu.Unlock()
	if err == nil && started {
		m.observe(Event{Kind: EventEditStarted, Set: key})
	}
	return e, err
}

// CommitEdit is CommitUpdates (§6.7.4): the working copy becomes the next
// Version of the set. See EditSlot.Commit. A change of the Name of an
// endpoint that is established (has a record) is refused with
// ua.StatusBadInvalidState and the set stays in edit (§6.12: the CM rejects
// it while the Connection is established).
func (m *Manager) CommitEdit(key SetKey, owner LockOwner) (*Config, bool, error) {
	s := m.lookup(key)
	if s == nil {
		return nil, false, managerError(ua.StatusBadNodeIDUnknown, "no set %s", key)
	}
	cfg, ok, err := m.commitLocked(s, owner)
	if ok {
		m.observe(Event{Kind: EventCommitted, Set: key, Version: cfg.version})
	}
	return cfg, ok, err
}

func (m *Manager) commitLocked(s *set, owner LockOwner) (*Config, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.edit.Editing()
	if e != nil && e.owner == owner {
		if next, err := newConfig(e.work, s.cfg.version+1); err == nil {
			for _, ref := range Renamed(s.cfg, next) {
				if r := s.recordOf(ref); r != nil {
					return nil, false, managerError(ua.StatusBadInvalidState, "the Name of the endpoint %v changes while it is established", ref)
				}
			}
		}
	}
	cfg, ok, err := s.edit.Commit(owner)
	if err != nil || !ok {
		return cfg, ok, err
	}
	s.cfg = cfg
	s.diags = remapDiagnostics(s.diags, cfg)
	return cfg, true, nil
}

// remapDiagnostics keeps the diagnostics of the Connections that keep
// their name and starts the others anew.
func remapDiagnostics(old []*uafx.ConnectionDiagnostics, cfg *Config) []*uafx.ConnectionDiagnostics {
	out := newDiagnostics(cfg)
	for i, cn := range cfg.conns {
		for _, d := range old {
			if d.Name != nil && d.Name.Name == cn.name {
				out[i] = d
			}
		}
	}
	return out
}

// DiscardEdit is DiscardUpdates (§6.7.4). See EditSlot.Discard.
func (m *Manager) DiscardEdit(key SetKey, owner LockOwner) (bool, error) {
	s := m.lookup(key)
	if s == nil {
		return false, managerError(ua.StatusBadNodeIDUnknown, "no set %s", key)
	}
	s.mu.Lock()
	ok, err := s.edit.Discard(owner)
	s.mu.Unlock()
	if ok {
		m.observe(Event{Kind: EventEditEnded, Set: key})
	}
	return ok, err
}

// EditLockLost ends the edit of a set whose Lock went (the owner's session
// ended, the Lock expired): DiscardUpdates (§6.7.4).
func (m *Manager) EditLockLost(key SetKey) bool {
	s := m.lookup(key)
	if s == nil {
		return false
	}
	s.mu.Lock()
	ok := s.edit.LockLost()
	s.mu.Unlock()
	if ok {
		m.observe(Event{Kind: EventEditEnded, Set: key})
	}
	return ok
}

// placeLocks serializes the runs of a Manager on one FunctionalEntity of
// one server for their scan and create steps (design §5.1), so that the
// absent-before check of the ownership proof cannot race.
type placeLocks struct {
	mu sync.Mutex
	m  map[string]chan struct{}
}

// lock takes the locks of keys, in order; release gives them back.
func (p *placeLocks) lock(ctx context.Context, keys []string) (release func(), err error) {
	keys = slices.Clone(keys)
	slices.Sort(keys)
	keys = slices.Compact(keys)
	var held []chan struct{}
	release = func() {
		for _, c := range held {
			<-c
		}
	}
	for _, k := range keys {
		p.mu.Lock()
		c := p.m[k]
		if c == nil {
			c = make(chan struct{}, 1)
			p.m[k] = c
		}
		p.mu.Unlock()
		select {
		case c <- struct{}{}:
			held = append(held, c)
		case <-ctx.Done():
			release()
			return func() {}, ctx.Err()
		}
	}
	return release, nil
}
