// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/otfabric/go-opcua/uafx/fxstore"
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
	// Store makes the Manager keep its sets, the records of its
	// endpoints, the journal of its runs and the intents of its calls
	// (design docs/design/uafx-persistent-connections.md §6): a set
	// change is durable before it is visible, and New loads them, every
	// endpoint record Unverified. A store that cannot be loaded, belongs
	// to another ApplicationURI or has a newer schema fails New. Nil:
	// memory only. The application owns the Store: the Manager never
	// closes it, and the application closes it after Close returns.
	Store fxstore.Store
	// StoreTimeout bounds each store operation, which has a context of
	// its own: the journal writes of a run are not cancelled by the
	// context of the run or by Close, so that what a call did is
	// recorded; only the settle of a fenced store ends with Close (the
	// store stays fenced until the next New). The store writes are
	// serialised: a slow store holds the other operations of the Manager
	// for up to StoreTimeout each, and Close waits for a write in
	// progress for up to StoreTimeout. 0: 10 s.
	StoreTimeout time.Duration
	// Verify configures the verification of the records loaded from the
	// Store (design §6.4, §6.5): in the background after New, and as the
	// first step of every run of a set.
	Verify VerifyOptions
	// SecurityKeyServer configures the SecurityGroups of the sets on
	// their SKS (§6.7.3.2, §6.7.3.3, E.5; the pull model only) and names
	// the SKS in the SecurityKeyServices of the secured groups of their
	// AutomationComponents. LocalSKS is an SKS in this process, RemoteSKS
	// one reached over OPC UA. Nil: the SecurityKeyServer of a set is
	// validated and otherwise not used.
	SecurityKeyServer SecurityKeyServer
	// TraceCalls passes a SpanContext with every EstablishConnections and
	// CloseConnections call, a TraceId per run and a SpanId per call, in
	// the AdditionalHeader of the request (OPC 10000-26 §5.6.4), and
	// reports it as Event.Trace, so that the records of the
	// AutomationComponentLogs follow those of the ConnectionManagerLog
	// ("the ConnectionManager shall provide the SpanContextDataType as part
	// of the EstablishConnection Method Call", Part 81 §6.7.2). A
	// ConnectionManager with a log needs it
	// (fxserver.ConnectionManagerOptions.Log).
	TraceCalls bool
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
	// spans are the SpanIds of the calls (span).
	spans atomic.Uint64

	mu     sync.Mutex
	sets   map[string]*set
	closed bool
	// reserved are the keys an Update with requireComplete adds, which no
	// other Add may take meanwhile (updateComplete).
	reserved map[string]bool
	// beforeCommit, set by tests only, runs in updateComplete right before
	// the batch is applied.
	beforeCommit func()

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
	// statusOf reads the Status of an endpoint for the monitor
	// (readStatus; a test replaces it before the monitor starts).
	statusOf func(ctx context.Context, r *record) (uafx.ConnectionEndpointStatus, bool, error)

	// sksStep serializes the SKS steps of the runs (configureSKS,
	// removeSKS), so that a SecurityGroup a run adds is not removed by
	// another that has not seen its set. sks are the SecurityGroups the
	// Manager added, by their store key (sksKey), under sksMu, which is
	// taken after every other lock.
	sksStep sync.Mutex
	sksMu   sync.Mutex
	sks     map[string]SecurityGroupRecord

	// p keeps the Manager in Options.Store; nil without one.
	p *persistence
	// crash, when set by a test, runs at the points of the journal
	// (crash_test.go).
	crash atomic.Pointer[func(string)]
}

// crashPoint runs the crash hook of the tests at a point of the journal.
func (m *Manager) crashPoint(name string) {
	if f := m.crash.Load(); f != nil {
		(*f)(name)
	}
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
	// runs counts the runs started on the set: the monitor drops an
	// observation made while a run started (and maybe ended).
	runs uint64
	// transition is the transition the state machine took last (§6.9.2),
	// 0 before the first.
	transition Transition
	// lastEstablish is the action of the last establish run, which the
	// monitor repeats with Reestablish.
	lastEstablish *uafx.FxProcess
	retries       int
	retry         *time.Timer
	removed       bool
	// held: a Replace, Remove or Update claimed the set (claim); no run or
	// edit starts on it until the change is made or the claim released.
	held bool
	// gen and fp are the generation and the fingerprint of the committed
	// record of cfg, with a Store (design §6.1).
	gen uint64
	fp  []byte
	// pending is a commit whose write had an unknown outcome, until the
	// Manager has followed the store.
	pending *pendingCommit
}

// pendingCommit is the commit of the edit edit as cfg, written at
// generation gen with fingerprint fp, whose outcome is unknown: when the
// store shows it, the edit ends with that Version; otherwise it stays
// open.
type pendingCommit struct {
	cfg  *Config
	gen  uint64
	fp   []byte
	edit *Edit
}

// errCommitPending refuses a change of an edit whose commit is being
// settled.
func errCommitPending(key SetKey) error {
	return managerError(ua.StatusBadInvalidState, "the outcome of the commit of the set %s is being settled", key)
}

// record is an EndpointRecord with what closing the endpoint needs.
type record struct {
	EndpointRecord
	addr   ServerAddress
	acNode *ua.NodeID
	// state is the last Status the monitor read, valid with monitored.
	state     uafx.ConnectionEndpointStatus
	monitored bool
	// The evidence of design §6.1 and §6.5, with a Store. nsa is the
	// NamespaceArray of the server the NodeIds are of; gen and fp the
	// generation and fingerprint of the set configuration of the run that
	// made or found the endpoint, epfp the SHA-256 of the
	// ConnectionEndpointConfiguration it sent; server the identity of the
	// server; created the Diagnostics CreationTime of the endpoint (zero
	// when not exposed); cmURI the ConnectionManagerApplicationUri read
	// from it, with cmObserved. stored is the class a loaded Unverified
	// record was written with.
	nsa        []string
	gen        uint64
	fp         []byte
	epfp       []byte
	server     serverEvidence
	created    time.Time
	cmURI      string
	cmObserved bool
	stored     Ownership
	// param is the parameter the endpoint was established, taken or
	// re-proved with (storedParam), qualified with nsa.
	param storedParam
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
	v := &opts.Verify
	if v.Timeout <= 0 {
		v.Timeout = DefaultVerifyTimeout
	}
	if v.Parallelism <= 0 {
		v.Parallelism = opts.Parallelism
	}
	if v.RetryInitial <= 0 {
		v.RetryInitial = DefaultVerifyRetryInitial
	}
	if v.RetryMax <= 0 {
		v.RetryMax = DefaultVerifyRetryMax
	}
	v.RetryMax = max(v.RetryMax, v.RetryInitial)
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		opts: opts, log: log, pool: newPool(opts.Dialer),
		ctx: ctx, cancel: cancel,
		sets: map[string]*set{}, sks: map[string]SecurityGroupRecord{},
	}
	m.places.m = map[string]chan struct{}{}
	if opts.Store != nil {
		p, err := openPersistence(m, opts)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("fxcm: the store: %w", err)
		}
		m.p = p
	}
	if opts.Monitor != nil {
		m.monitorStop = make(chan struct{})
		m.wg.Add(1)
		go m.monitor()
	}
	// The verification of the loaded records starts now; no
	// AutomationComponent needs to be reachable for New (design §6.4).
	m.startVerify()
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
	// Recovery is what the set owes after a restart and how far its
	// records are verified, with a Store (design §6.4); nil without one.
	Recovery *Recovery
}

// Status returns the live state of a set.
func (m *Manager) Status(key SetKey) (Status, bool) {
	s := m.lookup(key)
	if s == nil {
		return Status{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status(m.opts.Monitor != nil)
	if m.p != nil {
		r := m.p.recovery(s)
		st.Recovery = &r
	}
	return st, true
}

// StoreStatus returns the state of the store of the Manager, false without
// a Store.
func (m *Manager) StoreStatus() (StoreStatus, bool) {
	if m.p == nil {
		return StoreStatus{}, false
	}
	return m.p.status(), true
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
	case m.sets[keyString(k)] != nil || m.reserved[keyString(k)]:
		return managerError(ua.StatusBadBrowseNameDuplicated, "a set %s exists", k)
	case len(m.sets)+len(m.reserved) >= m.opts.MaxConnectionConfigurationSets:
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
	s, err := m.claim(cfg.key)
	if err != nil {
		return nil, err
	}
	defer m.wg.Done()
	cs := []setChange{{key: cfg.key, next: cfg, existing: true}}
	tx, err := m.plan(cs, []uafx.ConnectionConfigurationSetOperation{uafx.ElementReplace})
	if err != nil {
		m.release(s)
		return nil, err
	}
	run, err := m.removeConnections(ctx, s, tx)
	if err != nil {
		return nil, err
	}
	if m.p != nil {
		defer m.endRuns(run)
		cs[0].gen = tx.ops[0].New
		gens, fps, err := m.p.switchSets(cs, []RunID{run})
		if err != nil {
			// The Connections are closed; the old set stays, as the
			// store has it, and its run record shows the switch owed.
			m.release(s)
			return nil, err
		}
		m.replaceSet(s, cfg, gens[0], fps[0])
	} else {
		m.replaceSet(s, cfg, 0, nil)
	}
	m.observe(Event{Kind: EventSetReplaced, Set: cfg.key, Version: cfg.version})
	return cfg, nil
}

// replaceSet puts cfg, committed at generation gen with fingerprint fp
// (0 and nil without a Store), in the claimed set s, whose Connections are
// closed, and releases the claim: in one step under the lock of s, so that
// nothing sees the new Config with the old generation, or the set
// unclaimed before it has them.
func (m *Manager) replaceSet(s *set, cfg *Config, gen uint64, fp []byte) {
	s.mu.Lock()
	s.cfg, s.state, s.diags, s.records, s.lastEstablish, s.retries = cfg, StateReady, newDiagnostics(cfg), map[string]*record{}, nil, 0
	s.gen, s.fp = gen, fp
	s.current, s.held = nil, false
	s.mu.Unlock()
}

// Remove removes a set (F.3.3.2 ElementRemove): CloseConnections with
// Remove TRUE for its known-owned endpoints, then the set goes. A set
// being processed or edited is ua.StatusBadInvalidState; no set of the key
// ua.StatusBadNoMatch. When a close fails, the set stays, in Error.
func (m *Manager) Remove(ctx context.Context, key SetKey) error {
	s, err := m.claim(key)
	if err != nil {
		return err
	}
	defer m.wg.Done()
	cs := []setChange{{key: key, existing: true}}
	tx, err := m.plan(cs, []uafx.ConnectionConfigurationSetOperation{uafx.ElementRemove})
	if err != nil {
		m.release(s)
		return err
	}
	run, err := m.removeConnections(ctx, s, tx)
	if err != nil {
		return err
	}
	if m.p != nil {
		defer m.endRuns(run)
		if _, _, err := m.p.switchSets(cs, []RunID{run}); err != nil {
			m.release(s)
			return err
		}
	}
	m.mu.Lock()
	delete(m.sets, keyString(key))
	m.mu.Unlock()
	s.mu.Lock()
	s.removed, s.current, s.held = true, nil, false
	s.mu.Unlock()
	m.observe(Event{Kind: EventSetRemoved, Set: key})
	return nil
}

// claim holds a set that is neither processed nor edited for a Replace,
// Remove or Update, in one step under the lock of the set: while it is
// held no run, retry or edit starts on it (Table 86: Bad_InvalidState).
// The claim itself is no processing: the set keeps its state and no
// transition is taken (§6.9.2) until removeConnections or finishClaim
// starts the remove run, so a claim that is given back (unclaim) leaves no
// trace in the state machine or its events (§8.6 to §8.9). A claimed set
// is counted as a run, so that Close waits for it (as start does): the
// caller calls m.wg.Done when it is finished; a closed Manager is
// ua.StatusBadShutdown.
func (m *Manager) claim(key SetKey) (*set, error) {
	if m.p != nil {
		if err := m.p.checkRemote(key); err != nil {
			return nil, err
		}
	}
	m.mu.Lock()
	closed := m.closed
	s := m.sets[keyString(key)]
	if !closed && s != nil {
		m.wg.Add(1)
	}
	m.mu.Unlock()
	switch {
	case closed:
		return nil, managerError(ua.StatusBadShutdown, "the ConnectionManager is closed")
	case s == nil:
		return nil, managerError(ua.StatusBadNoMatch, "no set %s", key)
	}
	s.mu.Lock()
	if s.edit.Editing() != nil || s.held {
		s.mu.Unlock()
		m.wg.Done()
		return nil, managerError(ua.StatusBadInvalidState, "the set %s is being edited, replaced or removed", key)
	}
	if _, err := Start(s.state); err != nil {
		s.mu.Unlock()
		m.wg.Done()
		return nil, managerError(ua.StatusBadInvalidState, "the set %s is being processed", key)
	}
	s.held = true
	if s.retry != nil {
		s.retry.Stop()
		s.retry = nil
	}
	s.mu.Unlock()
	return s, nil
}

// beginRemove starts the remove run of the claimed set s: the set goes to
// Processing (transition 1 or 4, §6.9.2). It returns the run and the state
// the set was in.
func (m *Manager) beginRemove(s *set) (*Run, State) {
	s.mu.Lock()
	prev := s.state
	tr, _ := Start(prev) // a held set is never in Processing
	r := &Run{id: RunID(m.runs.Add(1)), key: s.cfg.key, version: s.cfg.version, action: ActionRemoveSet, done: make(chan struct{})}
	s.state, s.current, s.transition = StateProcessing, r, tr
	s.runs++
	s.mu.Unlock()
	m.observe(Event{Kind: EventTransition, Set: r.key, Run: r.id, Transition: tr, Action: r.action})
	return r, prev
}

// removeConnections runs the remove run of the claimed set s for a Replace
// or Remove: it closes the endpoints of s. On a failure the set stays in
// Error and the claim is released. Close stops it as it stops a run.
func (m *Manager) removeConnections(ctx context.Context, s *set, tx *txPlan) (RunID, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(m.ctx, cancel)()
	r, prev := m.beginRemove(s)
	r.tx = tx
	res := m.execute(ctx, s, r, prev)
	if res.State == StateError {
		m.release(s)
		return r.id, managerError(firstStatus(res.Failures), "the Connections of the set %s were not all closed", r.key)
	}
	return r.id, nil
}

// plan is, with a Store, the set change cs (operations ops) as the run
// that closes the first closing set journals it (design §6.2); nil
// without a Store.
func (m *Manager) plan(cs []setChange, ops []uafx.ConnectionConfigurationSetOperation) (*txPlan, error) {
	if m.p == nil {
		return nil, nil
	}
	tp, err := m.planOps(cs, ops)
	if err != nil {
		return nil, managerError(ua.StatusBadEncodingError, "the set change does not encode: %v", err)
	}
	return tp, nil
}

// endRuns ends the remove runs a set change kept active until its switch
// was written or failed: what they leave in the store is owed work.
func (m *Manager) endRuns(runs ...RunID) {
	if m.p == nil {
		return
	}
	for _, r := range runs {
		m.p.activate(r, false)
	}
	m.p.mu.Lock()
	m.p.refreshOwed()
	m.p.mu.Unlock()
}

// release ends the claim of s without a change.
func (m *Manager) release(s *set) {
	s.mu.Lock()
	s.held = false
	s.mu.Unlock()
}

// unclaim gives back the claim of s before anything was done to it: the
// set was never processed, so no run, transition or event results.
func (m *Manager) unclaim(s *set) {
	m.release(s)
	m.wg.Done()
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
// or edited), and every new set. results has one error per operation, nil
// for success; applied is ChangesApplied of Table F.39.
//
// Without requireComplete the failed operations are dropped and the others
// applied in order; a remove or replace whose close fails fails (the old
// set stays, in Error). applied is true when one or more operations were
// applied, false when none was.
//
// With requireComplete nothing changes unless every operation is applied:
// applied is true when all were, false when none was (Table F.39). See
// updateComplete.
func (m *Manager) Update(ctx context.Context, ops []Operation, requireComplete bool) (applied bool, results []error) {
	results = make([]error, len(ops))
	if len(ops) == 0 {
		// Nothing to apply: ChangesApplied FALSE either way (Table F.39;
		// CloseAndUpdate refuses an empty Body before it gets here).
		return false, results
	}
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
	if requireComplete {
		if failed {
			return false, results
		}
		return m.updateComplete(ctx, ops, cfgs, results)
	}
	for i, op := range ops {
		if results[i] != nil {
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
			continue
		}
		applied = true
	}
	return applied, results
}

// errNotApplied is the result of an operation of a complete update that
// was not applied because another one failed.
func errNotApplied() error {
	return managerError(ua.StatusBadInvalidState, "not applied: another operation of the batch failed (RequireCompleteUpdate)")
}

// updateComplete is Update with requireComplete: all or nothing (F.3.3,
// Table F.39). It claims every set the batch removes or replaces, so that
// no run or edit starts on them, and reserves the keys it adds. Closing
// Connections cannot be undone, so a batch whose removes and replaces
// would close the Connections of more than one set is refused with
// ua.StatusBadInvalidState (library interpretation: the Manager cannot
// guarantee it). The one close runs first; when it fails nothing changes
// and the set stays, in Error. Then all operations are applied at once
// under the lock of the Manager, where nothing can fail.
func (m *Manager) updateComplete(ctx context.Context, ops []Operation, cfgs []*Config, results []error) (bool, []error) {
	type claimed struct {
		i int
		s *set
	}
	// The whole update is counted as a run, also an add-only batch, so
	// that Close waits for it; a closed Manager applies nothing.
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		for j := range results {
			results[j] = managerError(ua.StatusBadShutdown, "the ConnectionManager is closed")
		}
		return false, results
	}
	m.wg.Add(1)
	m.mu.Unlock()
	defer m.wg.Done()
	var held []claimed
	fail := func(i int, err error) (bool, []error) {
		for j := range results {
			results[j] = errNotApplied()
		}
		results[i] = err
		for _, h := range held {
			m.unclaim(h.s)
		}
		return false, results
	}
	for i, op := range ops {
		if op.Op == uafx.ElementAdd {
			continue
		}
		s, err := m.claim(KeyOf(op.Conf))
		if err != nil {
			return fail(i, err)
		}
		held = append(held, claimed{i, s})
	}
	var closing []claimed
	for _, h := range held {
		h.s.mu.Lock()
		if len(h.s.records) > 0 {
			closing = append(closing, h)
		}
		h.s.mu.Unlock()
	}
	if len(closing) > 1 {
		return fail(closing[1].i, managerError(ua.StatusBadInvalidState,
			"with RequireCompleteUpdate a batch may close the Connections of one set only; %d sets have Connections", len(closing)))
	}
	m.mu.Lock()
	if m.reserved == nil {
		m.reserved = map[string]bool{}
	}
	var adds []string
	removing := map[string]bool{}
	for _, h := range held {
		if ops[h.i].Op == uafx.ElementRemove {
			removing[keyString(KeyOf(ops[h.i].Conf))] = true
		}
	}
	n := len(m.sets) + len(m.reserved)
	for i, op := range ops {
		if op.Op != uafx.ElementAdd {
			continue
		}
		k := keyString(cfgs[i].key)
		var err error
		switch {
		case m.closed:
			err = managerError(ua.StatusBadShutdown, "the ConnectionManager is closed")
		case m.reserved[k] || m.sets[k] != nil && !removing[k]:
			err = managerError(ua.StatusBadBrowseNameDuplicated, "a set %s exists", cfgs[i].key)
		case n-len(removing)+1 > m.opts.MaxConnectionConfigurationSets:
			err = managerError(ua.StatusBadResourceUnavailable, "MaxConnectionConfigurationSets is %d", m.opts.MaxConnectionConfigurationSets)
		}
		if err != nil {
			for _, a := range adds {
				delete(m.reserved, a)
			}
			m.mu.Unlock()
			return fail(i, err)
		}
		m.reserved[k] = true
		adds = append(adds, k)
		n++
	}
	m.mu.Unlock()
	unreserve := func() {
		m.mu.Lock()
		for _, a := range adds {
			delete(m.reserved, a)
		}
		m.mu.Unlock()
	}
	cs := make([]setChange, len(ops))
	opKinds := make([]uafx.ConnectionConfigurationSetOperation, len(ops))
	for i, op := range ops {
		opKinds[i] = op.Op
		switch op.Op {
		case uafx.ElementAdd:
			cs[i] = setChange{key: cfgs[i].key, next: cfgs[i]}
		case uafx.ElementRemove:
			cs[i] = setChange{key: KeyOf(op.Conf), existing: true}
		case uafx.ElementReplace:
			cs[i] = setChange{key: cfgs[i].key, next: cfgs[i], existing: true}
		}
	}
	var tx *txPlan
	if len(closing) > 0 {
		// The whole change is the parent transaction, journaled by the
		// first remove run before any close (design §6.2): a crash
		// between the closes and the switch leaves it owed.
		var err error
		if tx, err = m.plan(cs, opKinds); err != nil {
			unreserve()
			for j := range results {
				results[j] = err
			}
			for _, h := range held {
				m.unclaim(h.s)
			}
			return false, results
		}
	}
	var runs []RunID
	defer func() { m.endRuns(runs...) }()
	for n, h := range closing {
		var t *txPlan
		if n == 0 {
			t = tx
		}
		run, err := m.removeConnections(ctx, h.s, t)
		runs = append(runs, run)
		if err != nil {
			// The close left h in Error and released it; the other
			// claims are undone by fail.
			unreserve()
			m.wg.Done()
			held = slices.DeleteFunc(held, func(x claimed) bool { return x.s == h.s })
			return fail(h.i, err)
		}
	}
	if m.beforeCommit != nil {
		m.beforeCommit()
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed && len(closing) == 0 {
		// Close began while the update ran and nothing irreversible
		// happened yet: nothing is applied.
		unreserve()
		return fail(0, managerError(ua.StatusBadShutdown, "the ConnectionManager is closed"))
	}
	var gens []uint64
	var fps [][]byte
	if m.p != nil {
		// The whole batch in one write, before any of it is visible
		// (design §6.2), with the generations its transaction reserved.
		if tx != nil {
			for i := range cs {
				cs[i].gen = tx.ops[i].New
			}
		}
		var err error
		for _, c := range cs {
			if c.next != nil && !c.existing {
				if err = m.p.checkKey(c.key); err != nil {
					break
				}
			}
		}
		if err == nil {
			gens, fps, err = m.p.switchSets(cs, runs)
		}
		if err != nil {
			unreserve()
			for j := range results {
				results[j] = err
			}
			for _, h := range held {
				m.unclaim(h.s)
			}
			return false, results
		}
	}
	var events []Event
	m.mu.Lock()
	for _, a := range adds {
		delete(m.reserved, a)
	}
	for _, h := range held {
		if ops[h.i].Op == uafx.ElementRemove {
			delete(m.sets, keyString(KeyOf(ops[h.i].Conf)))
		}
	}
	for i, op := range ops {
		if op.Op == uafx.ElementAdd {
			ns := newSet(cfgs[i])
			if gens != nil {
				ns.gen, ns.fp = gens[i], fps[i]
			}
			m.sets[keyString(cfgs[i].key)] = ns
		}
	}
	m.mu.Unlock()
	for i, op := range ops {
		switch op.Op {
		case uafx.ElementAdd:
			events = append(events, Event{Kind: EventSetAdded, Set: cfgs[i].key, Version: cfgs[i].version})
		case uafx.ElementRemove:
			events = append(events, Event{Kind: EventSetRemoved, Set: KeyOf(op.Conf)})
		case uafx.ElementReplace:
			events = append(events, Event{Kind: EventSetReplaced, Set: cfgs[i].key, Version: cfgs[i].version})
		}
	}
	for _, h := range held {
		closed := slices.ContainsFunc(closing, func(x claimed) bool { return x.s == h.s })
		if !closed {
			// Nothing to close: the set leaves Processing.
			m.finishClaim(h.s)
		}
		switch ops[h.i].Op {
		case uafx.ElementRemove:
			h.s.mu.Lock()
			h.s.removed, h.s.current, h.s.held = true, nil, false
			h.s.mu.Unlock()
		case uafx.ElementReplace:
			var gen uint64
			var fp []byte
			if gens != nil {
				gen, fp = gens[h.i], fps[h.i]
			}
			m.replaceSet(h.s, cfgs[h.i], gen, fp)
		default:
			// Only removes and replaces are claimed.
		}
		m.wg.Done()
	}
	for _, e := range events {
		m.observe(e)
	}
	return true, results
}

// finishClaim is the remove run of a claimed set without Connections of a
// complete update that is applied: nothing to close, so the run goes
// through Processing to Ready at once (transition 1 or 4, then 2, §6.9.2)
// with a terminal result; the set stays held.
func (m *Manager) finishClaim(s *set) {
	r, _ := m.beginRemove(s)
	s.mu.Lock()
	tr, _ := Finish(StateProcessing, false)
	s.state, s.current, s.transition = StateReady, nil, tr
	r.result = &RunResult{State: s.state, Transition: tr, Diagnostics: s.diagnostics(m.opts.Monitor != nil)}
	s.last = r
	s.mu.Unlock()
	close(r.done)
	m.observe(Event{Kind: EventTransition, Set: r.key, Run: r.id, Transition: tr, Action: r.action})
}

// addConfig adds the set of cfg. With a Store the set record is committed
// before the set is visible (design §6.2); the key is reserved meanwhile.
func (m *Manager) addConfig(cfg *Config) error {
	k := keyString(cfg.key)
	m.mu.Lock()
	if err := m.addCheckLocked(cfg.key); err != nil {
		m.mu.Unlock()
		return err
	}
	s := newSet(cfg)
	if m.p != nil {
		if m.reserved == nil {
			m.reserved = map[string]bool{}
		}
		m.reserved[k] = true
		m.mu.Unlock()
		err := m.p.checkKey(cfg.key)
		if err == nil {
			s.gen, s.fp, err = m.p.putConfig(cfg)
		}
		m.mu.Lock()
		delete(m.reserved, k)
		if err != nil {
			m.mu.Unlock()
			return err
		}
	}
	m.sets[k] = s
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
	if m.p != nil {
		// The owed work of the set is done by the first step of the run
		// (recover); an owed set change only by a Reconcile, and the work
		// other sets owe fences the run until its independence is
		// proven (design §6.3, §6.4).
		if err := m.p.checkRun(k, action); err != nil {
			return Started{Err: err}
		}
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
	if err == nil && s.held {
		err = managerError(ua.StatusBadInvalidState, "the set %s is being replaced or removed", k)
	}
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
	s.runs++
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
	if m.p != nil {
		// A verdict on a set fenced by the work of another is refused
		// (fencedOf); on a set that owes work it is the administrative
		// decision of an unproven call, which completes its intent once
		// every place of it is decided (design §6.3).
		if err := m.p.checkBlocked(key); err != nil {
			return err
		}
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
	case found.Class != Unresolved && found.Class != Unverified:
		s.mu.Unlock()
		return managerError(ua.StatusBadInvalidState, "the endpoint %v is %v", ep, found.Class)
	case s.state == StateProcessing:
		s.mu.Unlock()
		return managerError(ua.StatusBadInvalidState, "the set %s is being processed", key)
	}
	if m.p != nil {
		// The verdict is durable before it is the record's (design §6.4).
		if err := m.p.settleRecord(s, found, verdict); err != nil {
			s.mu.Unlock()
			return err
		}
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
	if s.held {
		s.mu.Unlock()
		return nil, managerError(ua.StatusBadInvalidState, "the set %s is being replaced or removed", key)
	}
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
	if s.pending != nil {
		return nil, false, errCommitPending(s.cfg.key)
	}
	if m.p != nil && s.edit.Editing() != nil && s.edit.Editing().owner == owner {
		if err := m.p.checkConfig(s.cfg.key); err != nil {
			return nil, false, err
		}
	}
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
	open := s.edit.Editing()
	cfg, ok, err := s.edit.Commit(owner)
	if err != nil || !ok {
		return cfg, ok, err
	}
	if m.p != nil {
		// The next Version is durable before it is the set's (design
		// §6.2); a failed write leaves the edit open.
		gen, fp, err := m.p.putConfig(cfg)
		if err != nil {
			s.edit.edit = open
			if errors.Is(err, ua.StatusBadInternalError) {
				// Unknown: the edit and what it committed are kept
				// until the Manager has followed the store.
				s.pending = &pendingCommit{cfg: cfg, gen: gen, fp: fp, edit: open}
			}
			return nil, false, err
		}
		s.gen, s.fp = gen, fp
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
	if s.pending != nil {
		s.mu.Unlock()
		return false, errCommitPending(key)
	}
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
