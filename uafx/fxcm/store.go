// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// persistence keeps the sets, the endpoint records, the journal of the runs
// and the intents of the calls of a Manager in a store (design
// docs/design/uafx-persistent-connections.md §6). The domain holds what is
// committed. The memory of the Manager changes only after a write that
// makes the change durable commits (§6.2); what a call did on an
// AutomationComponent is real whatever the store says, so a record its
// completion could not write is kept in memory as Unresolved (reported,
// never closed) and its intent stays in the store (§6.3).
//
// Lock order: a set's mu, then mu, then owedMu. mu serializes the writes,
// so that the counters a write carries are those of the writes before it;
// nothing holding mu takes Manager.mu or a set's mu. A commit of an edit
// writes under the lock of its set; the other writes hold no Manager or
// set lock.
type persistence struct {
	m       *Manager
	d       *fxstore.Domain
	timeout time.Duration

	mu  sync.Mutex
	gen uint64 // the generation of the last committed set change

	// failed are the records that did not decode at the start, by key:
	// kept in the store, reported, never overwritten.
	failed map[string]error
	// owed is the work the journal shows after the start, by set key
	// (keyString): run records and unended call intents (§6.4). Under
	// owedMu, which is taken last: a set's lock may be held.
	owedMu sync.Mutex
	owed   map[string][]OwedWork

	settleMu sync.Mutex
	settling bool

	// stale are the run records of runs that never called (phase
	// planned), which the start deletes.
	stale []string
}

// defaultStoreTimeout bounds one store operation.
const defaultStoreTimeout = 10 * time.Second

// Settling of a fenced store: a bounded backoff.
const (
	settleInitial = 100 * time.Millisecond
	settleMax     = 10 * time.Second
)

// OwedWork is work the journal of a Manager showed after a restart, which
// it exposes and does not execute (design §6.3): the next Process or
// Reconcile of the set does it (stage C3.3). In this version it is kept in
// the store and reported.
type OwedWork struct {
	// Kind says what is owed.
	Kind OwedKind
	// Run is the run that owes it.
	Run RunID
	// Action is the action of that run.
	Action uafx.FxProcess
	// Address is the server of an unended call; empty otherwise.
	Address string
	// Names are the endpoint Names of an unended establish.
	Names []string
}

// OwedKind is a kind of OwedWork.
type OwedKind int

// The kinds of OwedWork.
const (
	// OwedReconcile: a run was executing; its calls that did not end are
	// unknown outcomes (C2 §5.4).
	OwedReconcile OwedKind = iota + 1
	// OwedRollback: a run with RollbackOnError TRUE aborted, or was
	// executing; its rollback (§6.7.3.2) did not finish.
	OwedRollback
	// OwedSetChange: a Replace or Remove was closing the Connections of
	// the set; the remaining closes and the switch are owed (§6.2).
	OwedSetChange
	// OwedCall: an EstablishConnections or CloseConnections was sent and
	// its outcome was never recorded: unknown, re-proved and never resent
	// (§6.3).
	OwedCall
)

func (k OwedKind) String() string {
	switch k {
	case OwedReconcile:
		return "Reconcile"
	case OwedRollback:
		return "Rollback"
	case OwedSetChange:
		return "SetChange"
	case OwedCall:
		return "Call"
	}
	return fmt.Sprintf("OwedKind(%d)", int(k))
}

// Recovery is what a set owes after a restart and how far its records are
// verified (design §6.4).
type Recovery struct {
	// Pending is the number of records not yet verified.
	Pending int
	// Unverified are the endpoints whose records were loaded and not
	// verified: reported, never closed, adopted or changed.
	Unverified []EndpointRecord
	// Owed is the work the journal shows.
	Owed []OwedWork
	// Done: nothing is pending or owed.
	Done bool
}

// StoreStatus is the state of the store of a Manager.
type StoreStatus struct {
	// Durability is what the store guarantees, when it says.
	Durability fxstore.Durability
	// Store is the state of its domain.
	Store fxstore.DomainStatus
	// Failed are the records that did not decode at the start, by key:
	// kept in the store, never overwritten.
	Failed map[string]error
}

// errStore is a store failure of the Manager.
var errStore = errors.New("fxcm: store")

// storeError returns the error of an operation whose write had outcome o:
// ua.StatusBadResourceUnavailable when the write definitely did not commit,
// ua.StatusBadInternalError when its outcome is unknown (decision C3-D13).
func storeError(o fxstore.Outcome, err error) error {
	st := ua.StatusBadResourceUnavailable
	if o == fxstore.Unknown {
		st = ua.StatusBadInternalError
	}
	return fmt.Errorf("%w: %w: %w", st, errStore, err)
}

// openPersistence opens the store of opts and loads it into m. A store
// that cannot be loaded, belongs to another owner or has a newer schema
// fails New: never a silent fallback to memory only (decision C3-D1).
func openPersistence(m *Manager, opts Options) (*persistence, error) {
	p := &persistence{m: m, timeout: opts.StoreTimeout, failed: map[string]error{}, owed: map[string][]OwedWork{}}
	if p.timeout <= 0 {
		p.timeout = defaultStoreTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	d, err := fxstore.OpenDomain(ctx, opts.Store, fxstore.DomainOptions{Namespace: "cm", Owner: opts.ApplicationURI, Schema: recordSchema})
	if err != nil {
		return nil, err
	}
	p.d = d
	p.load(d.State())
	if len(p.stale) > 0 {
		b := fxstore.Batch{}
		for _, k := range p.stale {
			b.Deletes = append(b.Deletes, k, "next/"+strings.TrimPrefix(k, "run/"))
		}
		if o, err := p.write(b, 0); o != fxstore.Committed {
			// Kept: a planned run owes nothing, the next start tries again.
			m.log.Warn("fxcm: the records of runs that never called were not deleted", "error", err)
		}
	}
	return p, nil
}

func (p *persistence) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), p.timeout)
}

// load puts the state st in the Manager: the sets in Ready, or in Error
// when the journal shows owed work, every endpoint record Unverified
// (decision C3-D9: no loaded ownership record is trusted), the counters
// past what any write may have used.
func (p *persistence) load(st map[string][]byte) {
	m := p.m
	var c countersRecord
	if v, ok := st["counters"]; ok {
		if err := decodeRecord(v, &c); err != nil {
			p.failed["counters"] = err
		}
	}
	p.gen = c.Generation
	runs := c.RunID
	byStore := map[string]*set{} // by set store key
	for _, k := range sortedKeys(st) {
		if !strings.HasPrefix(k, "set/") {
			continue
		}
		var r setRecord
		if err := decodeRecord(st[k], &r); err != nil {
			p.failed[k] = err
			continue
		}
		key := SetKey{Folder: r.Folder, Name: r.Name}
		if setStoreKey(key) != k {
			p.failed[k] = fmt.Errorf("%w: the key is not of the set %s", errRecord, key)
			continue
		}
		conf, err := decodeConf(r.Conf)
		if err == nil {
			var cfg *Config
			if cfg, err = newConfig(conf, r.Version); err == nil {
				s := newSet(cfg)
				s.gen, s.fp = r.Generation, r.Fingerprint
				m.sets[keyString(key)] = s
				byStore[k] = s
				p.gen = max(p.gen, r.Generation)
				continue
			}
		}
		p.failed[k] = err
	}
	for _, k := range sortedKeys(st) {
		v := st[k]
		switch {
		case strings.HasPrefix(k, "ep/"):
			var r epStored
			if err := decodeRecord(v, &r); err != nil {
				p.failed[k] = err
				continue
			}
			key := SetKey{Folder: r.Folder, Name: r.SetName}
			s := byStore[setStoreKey(key)]
			if s == nil {
				p.failed[k] = fmt.Errorf("%w: the endpoint record of %q is of no set the store holds (%s)", errRecord, r.Name, key)
				continue
			}
			if r.Endpoint < 0 || r.Endpoint > math.MaxInt32 || r.Class < int64(Foreign) || r.Class > int64(Unresolved) {
				p.failed[k] = fmt.Errorf("%w: the endpoint record of %q is out of range", errRecord, r.Name)
				continue
			}
			rec := r.record()
			if epStoreKey(key, recordKey(rec.addr, rec.FunctionalEntity, rec.Name)) != k {
				p.failed[k] = fmt.Errorf("%w: the key is not of the endpoint %q", errRecord, r.Name)
				continue
			}
			s.records[recordKey(rec.addr, rec.FunctionalEntity, rec.Name)] = rec
			runs = max(runs, r.Run)
		case strings.HasPrefix(k, "run/"):
			var r runRecord
			if err := decodeRecord(v, &r); err != nil {
				p.failed[k] = err
				continue
			}
			runs = max(runs, r.Run)
			if r.Phase == phasePlanned {
				p.stale = append(p.stale, k) // nothing owed: deleted
				continue
			}
			p.owe(SetKey{Folder: r.Folder, Name: r.SetName}, r.owed())
		case strings.HasPrefix(k, "call/"):
			var r callRecord
			if err := decodeRecord(v, &r); err != nil {
				p.failed[k] = err
				continue
			}
			runs = max(runs, r.Run)
		}
	}
	// An unended intent belongs to the set of its run.
	for _, k := range sortedKeys(st) {
		if !strings.HasPrefix(k, "call/") || p.failed[k] != nil {
			continue
		}
		var r callRecord
		_ = decodeRecord(st[k], &r)
		key := SetKey{Folder: r.Folder, Name: r.SetName}
		p.owe(key, OwedWork{Kind: OwedCall, Run: RunID(r.Run), Address: r.Address, Names: slices.Clone(r.Names)})
	}
	for ks, owed := range p.owed {
		if s := m.sets[ks]; s != nil && len(owed) > 0 {
			s.state = StateError
		}
	}
	m.runs.Store(runs)
}

// owe adds w to what the set k owes.
func (p *persistence) owe(k SetKey, w OwedWork) {
	ks := keyString(k)
	p.owedMu.Lock()
	p.owed[ks] = append(p.owed[ks], w)
	p.owedMu.Unlock()
}

// owed returns what the run record r shows owed (§6.3).
func (r *runRecord) owed() OwedWork {
	w := OwedWork{Run: RunID(r.Run), Action: uafx.FxProcess(r.Action)}
	switch {
	case uafx.FxProcess(r.Action) == ActionRemoveSet:
		// The closes of a Replace or Remove are never rolled back: what
		// is owed is the rest of the closes and the switch.
		w.Kind = OwedSetChange
	case r.Phase == phaseRollbackRequired, r.Phase == phaseExecuting && r.RollbackOnError:
		w.Kind = OwedRollback
	default:
		w.Kind = OwedReconcile
	}
	return w
}

// record returns the stored endpoint as a record of a set: Unverified,
// whatever class it was written with (decision C3-D9).
func (r *epStored) record() *record {
	addr := ServerAddress{Address: r.Address, SecurityMode: ua.MessageSecurityMode(r.SecurityMode), SecurityPolicyURI: r.SecurityPolicyURI, ServerURI: r.ServerURIConf}
	return &record{EndpointRecord: EndpointRecord{
		Set: SetKey{Folder: r.Folder, Name: r.SetName}, Endpoint: EndpointRef{Connection: r.Connection, Endpoint: int(r.Endpoint)},
		ServerURI: r.ServerURI, FunctionalEntity: orNil(r.FunctionalEntity), Name: r.Name, NodeID: orNil(r.NodeID),
		Class: Unverified, Run: RunID(r.Run), Version: r.Version, ClosePending: r.ClosePending,
	}, addr: addr, acNode: orNil(r.ACNode), nsa: r.Namespaces, gen: r.Generation, fp: r.Fingerprint, stored: Ownership(r.Class)}
}

// stored returns the record rec of the set s as it is stored.
func storedOf(s *set, rec *record) *epStored {
	class := rec.Class
	if class == Unverified {
		class = rec.stored // as loaded: unverified is not a class to write
	}
	return &epStored{
		Folder: rec.Set.Folder, SetName: rec.Set.Name, Connection: rec.Endpoint.Connection, Endpoint: int64(rec.Endpoint.Endpoint),
		Address: rec.addr.Address, SecurityMode: uint32(rec.addr.SecurityMode), SecurityPolicyURI: rec.addr.SecurityPolicyURI, ServerURIConf: rec.addr.ServerURI,
		Namespaces: rec.nsa, ServerURI: rec.ServerURI, ACNode: rec.acNode, FunctionalEntity: rec.FunctionalEntity, Name: rec.Name, NodeID: rec.NodeID,
		Class: int64(class), Run: uint64(rec.Run), Version: rec.Version, ClosePending: rec.ClosePending,
		Generation: rec.gen, Fingerprint: rec.fp,
	}
}

// apply writes b with the counters. The caller holds p.mu. An unknown
// outcome fences the store and starts settling it.
func (p *persistence) apply(b fxstore.Batch, gen uint64) (fxstore.Outcome, error) {
	if b.Puts == nil {
		b.Puts = map[string][]byte{}
	}
	cv, err := encodeRecord(&countersRecord{Generation: max(p.gen, gen), RunID: p.m.runs.Load()})
	if err != nil {
		return fxstore.NotCommitted, fxstore.AsNotCommitted(err)
	}
	b.Puts["counters"] = cv
	ctx, cancel := p.ctx()
	defer cancel()
	sets := false
	for k := range b.Puts {
		sets = sets || strings.HasPrefix(k, "set/")
	}
	for _, k := range b.Deletes {
		sets = sets || strings.HasPrefix(k, "set/")
	}
	if sets {
		p.m.crashPoint("set.before-apply")
	}
	o, err := p.d.Apply(ctx, b)
	if sets && o == fxstore.Committed {
		p.m.crashPoint("set.after-apply")
	}
	switch o {
	case fxstore.Committed:
		p.gen = max(p.gen, gen)
	case fxstore.Unknown:
		p.m.log.Warn("fxcm: the outcome of a store write is unknown; the store is fenced until it is settled", "error", err)
		p.startSettle()
	case fxstore.NotCommitted:
	}
	return o, err
}

// write is apply under p.mu.
func (p *persistence) write(b fxstore.Batch, gen uint64) (fxstore.Outcome, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.apply(b, gen)
}

// nextGen returns the generation of the next set change. The caller holds
// p.mu.
func (p *persistence) nextGen() uint64 { return p.gen + 1 }

// startSettle settles the fenced store in the background, with a bounded
// backoff, until it is settled or the Manager closed; then the sets follow
// the committed state (§3.5: no stale memory).
func (p *persistence) startSettle() {
	p.settleMu.Lock()
	defer p.settleMu.Unlock()
	if p.settling {
		return
	}
	p.settling = true
	p.m.wg.Add(1)
	go func() {
		defer p.m.wg.Done()
		wait := settleInitial
		for {
			ctx, cancel := p.ctx()
			ok, err := p.d.Settle(ctx)
			cancel()
			if ok {
				p.settleMu.Lock()
				p.settling = false
				p.settleMu.Unlock()
				p.m.log.Info("fxcm: the store is settled")
				p.follow()
				return
			}
			p.m.log.Warn("fxcm: the store is not settled yet", "error", err, "retry", wait)
			select {
			case <-p.m.ctx.Done():
				p.settleMu.Lock()
				p.settling = false
				p.settleMu.Unlock()
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, settleMax)
		}
	}()
}

// follow makes the sets follow the committed state after a settle: a set
// change whose write had an unknown outcome and committed after all is
// made, one that did not is not; a set the store has at another generation
// takes the stored Config. A set with a run, an edit or a claim keeps its
// memory: what it does next writes the store again, which the settled
// domain then allows. Endpoint records the store has and memory does not
// are added Unverified.
func (p *persistence) follow() {
	st := p.d.State()
	m := p.m
	stored := map[string]*setRecord{}
	var gen uint64
	for k, v := range st {
		if !strings.HasPrefix(k, "set/") {
			continue
		}
		var r setRecord
		if decodeRecord(v, &r) == nil {
			stored[k] = &r
			gen = max(gen, r.Generation)
		}
	}
	p.mu.Lock()
	p.gen = max(p.gen, gen)
	failed := make(map[string]bool, len(p.failed))
	for k := range p.failed {
		failed[k] = true
	}
	p.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for ks, s := range m.sets {
		s.mu.Lock()
		busy := s.current != nil || s.held || s.edit.Editing() != nil
		k := setStoreKey(s.cfg.key)
		r := stored[k]
		switch {
		case busy:
		case r == nil:
			if !failed[k] {
				delete(m.sets, ks)
				s.removed = true
			}
		case r.Generation != s.gen:
			if conf, err := decodeConf(r.Conf); err == nil {
				if cfg, err := newConfig(conf, r.Version); err == nil {
					s.cfg, s.diags, s.gen, s.fp = cfg, newDiagnostics(cfg), r.Generation, r.Fingerprint
				}
			}
		}
		delete(stored, k)
		s.mu.Unlock()
	}
	for _, r := range stored {
		key := SetKey{Folder: r.Folder, Name: r.Name}
		if m.reserved[keyString(key)] {
			continue
		}
		if conf, err := decodeConf(r.Conf); err == nil {
			if cfg, err := newConfig(conf, r.Version); err == nil {
				s := newSet(cfg)
				s.gen, s.fp = r.Generation, r.Fingerprint
				m.sets[keyString(key)] = s
			}
		}
	}
	for k, v := range st {
		if !strings.HasPrefix(k, "ep/") {
			continue
		}
		var r epStored
		if decodeRecord(v, &r) != nil || r.Endpoint < 0 || r.Endpoint > math.MaxInt32 || r.Class < int64(Foreign) || r.Class > int64(Unresolved) {
			continue
		}
		s := m.sets[keyString(SetKey{Folder: r.Folder, Name: r.SetName})]
		if s == nil {
			continue
		}
		rec := r.record()
		rk := recordKey(rec.addr, rec.FunctionalEntity, rec.Name)
		s.mu.Lock()
		if s.records[rk] == nil && s.current == nil {
			s.records[rk] = rec
		}
		s.mu.Unlock()
	}
}

// putSet adds the record of cfg at generation gen to b.
func putSet(b *fxstore.Batch, cfg *Config, gen uint64) (fp []byte, err error) {
	conf, fp, err := encodeConf(cfg.conf)
	if err != nil {
		return nil, err
	}
	v, err := encodeRecord(&setRecord{Folder: cfg.key.Folder, Name: cfg.key.Name, Version: cfg.version, Generation: gen, Fingerprint: fp, Conf: conf})
	if err != nil {
		return nil, err
	}
	if b.Puts == nil {
		b.Puts = map[string][]byte{}
	}
	b.Puts[setStoreKey(cfg.key)] = v
	return fp, nil
}

// recordsOf adds to b the delete of every endpoint record of the set key
// the committed state has.
func (p *persistence) deleteRecordsOf(b *fxstore.Batch, key SetKey) {
	st := p.d.State()
	for k, v := range st {
		if !strings.HasPrefix(k, "ep/") {
			continue
		}
		var r epStored
		if decodeRecord(v, &r) == nil && keyString(SetKey{Folder: r.Folder, Name: r.SetName}) == keyString(key) {
			b.Deletes = append(b.Deletes, k)
		}
	}
	slices.Sort(b.Deletes)
}

// status returns the StoreStatus.
func (p *persistence) status() StoreStatus {
	st := StoreStatus{Store: p.d.Status(), Failed: map[string]error{}}
	if d, ok := p.m.opts.Store.(fxstore.Durable); ok {
		st.Durability = d.Durability()
	}
	p.mu.Lock()
	for k, err := range p.failed {
		st.Failed[k] = err
	}
	p.mu.Unlock()
	return st
}

// recovery returns the Recovery of the set s. The caller holds s.mu.
func (p *persistence) recovery(s *set) Recovery {
	var r Recovery
	for _, rec := range s.records {
		if rec.Class == Unverified {
			r.Unverified = append(r.Unverified, rec.EndpointRecord)
		}
	}
	slices.SortFunc(r.Unverified, func(a, b EndpointRecord) int {
		return strings.Compare(a.Endpoint.Connection+"\x00"+a.Name, b.Endpoint.Connection+"\x00"+b.Name)
	})
	r.Pending = len(r.Unverified)
	p.owedMu.Lock()
	r.Owed = slices.Clone(p.owed[keyString(s.cfg.key)])
	p.owedMu.Unlock()
	r.Done = r.Pending == 0 && len(r.Owed) == 0
	return r
}

// sortedKeys returns the keys of st in order.
func sortedKeys(st map[string][]byte) []string {
	ks := make([]string, 0, len(st))
	for k := range st {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// errFailedRecord refuses a set whose key a record that did not decode
// holds: it is never overwritten (§3.2).
func (p *persistence) checkKey(key SetKey) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.failed[setStoreKey(key)]; err != nil {
		return managerError(ua.StatusBadInvalidState, "the store holds a record of the set %s that does not decode: %v", key, err)
	}
	return nil
}

// putConfig makes cfg the committed configuration of its set: a new
// generation. It returns the generation and the fingerprint, or the
// storeError of the write.
func (p *persistence) putConfig(cfg *Config) (uint64, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	gen := p.nextGen()
	var b fxstore.Batch
	fp, err := putSet(&b, cfg, gen)
	if err != nil {
		return 0, nil, storeError(fxstore.NotCommitted, err)
	}
	if o, err := p.apply(b, gen); o != fxstore.Committed {
		return 0, nil, storeError(o, err)
	}
	return gen, fp, nil
}

// setChange is one set change of a switch: next nil removes the set.
type setChange struct {
	key  SetKey
	next *Config
	// existing: the set exists and its endpoint records go.
	existing bool
}

// switchSets makes the changes durable in one write, with the end of the
// runs that closed their Connections (§6.2): a removed or replaced set
// loses its endpoint records and its run record. It returns the
// generation and fingerprint of each next Config, in the order of cs.
func (p *persistence) switchSets(cs []setChange, runs []RunID) ([]uint64, [][]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b fxstore.Batch
	gens := make([]uint64, len(cs))
	fps := make([][]byte, len(cs))
	gen := p.gen
	for i, c := range cs {
		gen++
		if c.existing {
			p.deleteRecordsOf(&b, c.key)
		}
		if c.next == nil {
			b.Deletes = append(b.Deletes, setStoreKey(c.key))
			continue
		}
		fp, err := putSet(&b, c.next, gen)
		if err != nil {
			return nil, nil, storeError(fxstore.NotCommitted, err)
		}
		gens[i], fps[i] = gen, fp
	}
	for _, r := range runs {
		b.Deletes = append(b.Deletes, runStoreKey(r), nextStoreKey(r))
	}
	if o, err := p.apply(b, gen); o != fxstore.Committed {
		return nil, nil, storeError(o, err)
	}
	return gens, fps, nil
}

// settleRecord writes the verdict of Settle on the record rec of the set s
// (key rk of its map). The caller holds s.mu.
func (p *persistence) settleRecord(s *set, rk string, rec *record, v Verdict) error {
	var b fxstore.Batch
	k := epStoreKey(s.cfg.key, rk)
	if v == SettleOwned {
		cp := *rec
		cp.Class = KnownOwned
		val, err := encodeRecord(storedOf(s, &cp))
		if err != nil {
			return storeError(fxstore.NotCommitted, err)
		}
		b.Puts = map[string][]byte{k: val}
	} else {
		b.Deletes = []string{k}
	}
	if o, err := p.write(b, 0); o != fxstore.Committed {
		return storeError(o, err)
	}
	return nil
}
