// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"errors"
	"fmt"
	"maps"
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
// Lock order: a set's mu, then mu, then owedMu, then a run's mu. mu
// serializes the writes, so that the counters a write carries are those of
// the writes before it, and a journal write holds the lock of its set from
// the snapshot of its records to the end of its write (lockJournal);
// nothing holding mu takes Manager.mu or a set's mu.
type persistence struct {
	m       *Manager
	d       *fxstore.Domain
	timeout time.Duration

	mu sync.Mutex
	// gen is the highest generation a write used or may have used: a
	// write with an unknown outcome consumes its generations too (§3.5:
	// never reused).
	gen uint64
	// fence is the consistency fence of the Manager: set by a write with
	// an unknown outcome, it refuses every write until the domain is
	// settled and the memory of the Manager follows what the store
	// committed (follow). The domain's own fence ends with the settle.
	fence bool

	// failed are the records that did not decode or are not valid, by
	// key: kept in the store, reported, never overwritten (§3.2).
	failed map[string]error
	// readOnly, when set, refuses every write: the counters cannot be
	// trusted, so no write may advance them.
	readOnly string
	// blockedAll, when set, refuses every remote operation: a record of
	// an endpoint, a run or a call that does not decode could be of any
	// set.
	blockedAll string
	// blockedSets refuse the remote operations of a set with a record
	// that is not valid, by keyString.
	blockedSets map[string]string

	// owed is the work the committed journal shows, by set key
	// (keyString), without the runs that are active; orphans the keys of
	// the obligations of no set the Manager has (an Add of a complete
	// Update owed, or a run whose set record is gone): no Add takes them.
	// Under owedMu, which is taken after mu.
	owedMu  sync.Mutex
	owed    map[string][]OwedWork
	orphans map[string]string
	// fenced is, by set key, the work other sets owe that the set takes
	// part in or shares a server with (fencedOf).
	fenced map[string][]OwedWork
	active map[RunID]bool
	// retained are the intents of active runs whose outcome is unknown
	// (run.retain), by run: they fence like the intents of ended runs.
	retained map[RunID]map[string]bool

	settleMu sync.Mutex
	settling bool

	// verifyMu guards the background verification (verify.go): verifying
	// while it runs, verifyAgain when records became Unverified meanwhile.
	verifyMu    sync.Mutex
	verifying   bool
	verifyAgain bool
	// unverified are the server Addresses on which a record is Unverified
	// (noteVerified clears them), verifyErr the error of the last attempt
	// on a server that failed. Under owedMu.
	unverified map[string]bool
	verifyErr  map[string]string

	// stale are the records of runs that never called (phase planned),
	// which the start deletes.
	stale []string
}

// defaultStoreTimeout bounds one store operation.
const defaultStoreTimeout = 10 * time.Second

// Settling of a fenced store and the reconciliation after it: a bounded
// backoff.
const (
	settleInitial = 100 * time.Millisecond
	settleMax     = 10 * time.Second
	followInitial = 10 * time.Millisecond
	followMax     = time.Second
)

// OwedWork is work the journal of a Manager shows, which it exposes and
// does not execute by itself (design §6.3): the first step of the next
// Process or Reconcile of the set does it (recover), and a Reconcile
// completes an owed set change. Until then it is reported and fences the
// operations that could bypass it.
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
	// Changes are the operations of a set change (OwedSetChange): every
	// operation of the Replace, Remove or complete Update, which are made
	// together after the closes.
	Changes []PlannedChange
}

// PlannedChange is one operation of a set change that is owed.
type PlannedChange struct {
	Op  uafx.ConnectionConfigurationSetOperation
	Set SetKey
	// Version is the Version of the set the operation commits, 0 for a
	// removal.
	Version uint32
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
	// OwedSetChange: a Replace, Remove or complete Update was closing the
	// Connections of the set; the remaining closes and the switch are
	// owed (§6.2).
	OwedSetChange
	// OwedCall: an EstablishConnections or CloseConnections was sent and
	// its outcome was never recorded or never proven: unknown, re-proved
	// and never resent (§6.3, decision C3-D13).
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

// Recovery is what a set owes and how far its records are verified (design
// §6.4).
type Recovery struct {
	// Pending is the number of records not yet verified.
	Pending int
	// Unverified are the endpoints whose records were loaded and not
	// verified: reported, never closed, adopted or changed. An unended
	// establish intent without an endpoint record holds its Names with
	// one (NodeID nil).
	Unverified []EndpointRecord
	// Owed is the work the journal shows. The first step of the next
	// Process or Reconcile of the set does it (a set change: a Reconcile
	// only); until then the set is not replaced, removed or updated
	// (Bad_InvalidState).
	Owed []OwedWork
	// Fenced is the work other sets owe that this set takes part in (an
	// operation of their set change), or that holds a server of this set
	// whose independence is not proven yet (fencedOf). While it is owed,
	// the remote operations of the set and its CommitEdit are refused
	// (Bad_InvalidState; library interpretation).
	Fenced []OwedWork
	// Unreachable are the servers (by Address) of Unverified records whose
	// last verification attempt failed, with its error; they are tried
	// again with a bounded backoff (VerifyOptions).
	Unreachable map[string]string
	// Blocked, when not empty, is why the remote operations of the set
	// are refused: a record of it in the store is not valid.
	Blocked string
	// Done: nothing is pending, owed or blocked.
	Done bool
}

// StoreStatus is the state of the store of a Manager.
type StoreStatus struct {
	// Durability is what the store guarantees, when it says.
	Durability fxstore.Durability
	// Store is the state of its domain.
	Store fxstore.DomainStatus
	// Reconciling: a write had an unknown outcome, and the Manager
	// refuses writes until the store is settled and its memory follows
	// what the store committed.
	Reconciling bool
	// Failed are the records that did not decode or are not valid, by
	// key: kept in the store, never overwritten.
	Failed map[string]error
	// ReadOnly, when not empty, is why every write is refused.
	ReadOnly string
	// BlockedAll, when not empty, is why every remote operation is
	// refused.
	BlockedAll string
	// Orphaned are the set keys an obligation of no current set holds:
	// no Add takes them (SetKey.String to the reason).
	Orphaned map[string]string
}

// errStore is a store failure of the Manager.
var errStore = errors.New("fxcm: store")

// errReconciling refuses a write while the Manager follows a settled store.
var errReconciling = errors.New("fxcm: an earlier write had an unknown outcome; the memory of the Manager is being reconciled with the store")

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
	p := &persistence{
		m: m, timeout: opts.StoreTimeout, failed: map[string]error{}, owed: map[string][]OwedWork{},
		orphans: map[string]string{}, active: map[RunID]bool{}, blockedSets: map[string]string{},
		unverified: map[string]bool{}, verifyErr: map[string]string{},
	}
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
	if len(p.stale) > 0 && p.readOnly == "" {
		b := fxstore.Batch{Deletes: p.stale}
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

// loaded is a state of the store decoded and checked.
type loaded struct {
	c     countersRecord
	sets  map[string]*setRecord // by store key
	eps   map[string]*epStored
	runs  map[string]*runRecord
	txs   map[string]*txRecord
	calls map[string]*callRecord
	// failed are the records that did not decode or are not valid, with
	// the set they are of when that is known (keyString, "" otherwise).
	failed map[string]error
	of     map[string]string
}

// decodeState decodes and checks st (design §3.2): every record against
// its key, the counters and the record it belongs to. The counters must
// be at or above every generation and RunID a record has: a write carries
// the counters it advances, so counters below a record are not the store's.
func decodeState(st map[string][]byte) *loaded {
	l := &loaded{
		sets: map[string]*setRecord{}, eps: map[string]*epStored{}, runs: map[string]*runRecord{}, txs: map[string]*txRecord{},
		calls: map[string]*callRecord{}, failed: map[string]error{}, of: map[string]string{},
	}
	fail := func(k string, err error, set string) {
		l.failed[k] = err
		l.of[k] = set
	}
	counters, hasCounters := st["counters"]
	if hasCounters {
		if err := decodeRecord(counters, &l.c); err != nil {
			fail("counters", err, "")
			hasCounters = false
		}
	}
	// The highest generation and RunID of the records, for the check of
	// the counters (and in their place when they do not decode).
	var high countersRecord
	type checker interface {
		check(k string, c countersRecord) error
	}
	decoded := map[string]checker{}
	setOf := map[string]string{}
	for _, k := range sortedKeys(st) {
		var v checker
		var set SetKey
		switch {
		case k == "counters":
			continue
		case strings.HasPrefix(k, "set/"):
			r := &setRecord{}
			err := decodeRecord(st[k], r)
			if err != nil {
				fail(k, err, "")
				continue
			}
			v, set = r, SetKey{Folder: r.Folder, Name: r.Name}
			high.Generation = max(high.Generation, r.Generation)
		case strings.HasPrefix(k, "ep/"):
			r := &epStored{}
			if err := decodeRecord(st[k], r); err != nil {
				fail(k, err, "")
				continue
			}
			v, set = r, SetKey{Folder: r.Folder, Name: r.SetName}
			high.Generation, high.RunID = max(high.Generation, r.Generation), max(high.RunID, r.Run)
		case strings.HasPrefix(k, "run/"):
			r := &runRecord{}
			if err := decodeRecord(st[k], r); err != nil {
				fail(k, err, "")
				continue
			}
			v, set = r, SetKey{Folder: r.Folder, Name: r.SetName}
			high.Generation, high.RunID = max(high.Generation, r.Generation, r.Next), max(high.RunID, r.Run)
		case strings.HasPrefix(k, "tx/"):
			r := &txRecord{}
			if err := decodeRecord(st[k], r); err != nil {
				fail(k, err, "")
				continue
			}
			v = r
			for _, o := range r.Ops {
				high.Generation = max(high.Generation, o.New, o.Old)
			}
			high.RunID = max(high.RunID, r.Run)
		case strings.HasPrefix(k, "call/"):
			r := &callRecord{}
			if err := decodeRecord(st[k], r); err != nil {
				fail(k, err, "")
				continue
			}
			v, set = r, SetKey{Folder: r.Folder, Name: r.SetName}
			high.Generation, high.RunID = max(high.Generation, r.Generation), max(high.RunID, r.Run)
		default:
			fail(k, errSemantic("a key outside the record layout"), "")
			continue
		}
		decoded[k] = v
		if set.Name != "" {
			setOf[k] = keyString(set)
		}
	}
	switch {
	case !hasCounters && len(decoded) > 0 && l.failed["counters"] == nil:
		fail("counters", errSemantic("records without counters"), "")
	case hasCounters && (l.c.Generation < high.Generation || l.c.RunID < high.RunID):
		fail("counters", errSemantic("the counters (%d, %d) are below the records (%d, %d)", l.c.Generation, l.c.RunID, high.Generation, high.RunID), "")
	}
	c := l.c
	if l.failed["counters"] != nil || !hasCounters {
		c = high
	}
	for _, k := range sortedKeys(st) {
		v := decoded[k]
		if v == nil {
			continue
		}
		if err := v.check(k, c); err != nil {
			fail(k, err, setOf[k])
			continue
		}
		switch r := v.(type) {
		case *setRecord:
			l.sets[k] = r
		case *epStored:
			l.eps[k] = r
		case *runRecord:
			l.runs[k] = r
		case *txRecord:
			l.txs[k] = r
		case *callRecord:
			l.calls[k] = r
		}
	}
	// The records that belong to another: each needs it.
	for k, r := range l.eps {
		if l.sets[setStoreKey(SetKey{Folder: r.Folder, Name: r.SetName})] == nil {
			fail(k, errSemantic("the endpoint record of %q is of no set the store holds", r.Name), setOf[k])
			delete(l.eps, k)
		}
	}
	for k, r := range l.txs {
		rr := l.runs[runStoreKey(RunID(r.Run))]
		if rr == nil || uafx.FxProcess(rr.Action) != ActionRemoveSet {
			fail(k, errSemantic("a set change of no set-change run"), "")
			delete(l.txs, k)
		}
	}
	for k, r := range l.calls {
		rr := l.runs[runStoreKey(RunID(r.Run))]
		if rr == nil || keyString(SetKey{Folder: rr.Folder, Name: rr.SetName}) != setOf[k] {
			fail(k, errSemantic("an intent of no run of its set"), setOf[k])
			delete(l.calls, k)
		}
	}
	for k, r := range l.runs {
		if uafx.FxProcess(r.Action) == ActionRemoveSet && r.Phase != phasePlanned && l.txs[txStoreKey(RunID(r.Run))] == nil {
			fail(k, errSemantic("a set-change run without its set change"), setOf[k])
			delete(l.runs, k)
		}
	}
	return l
}

// load puts the state st in the Manager: the sets in Ready, or in Error
// when the journal shows owed work, every endpoint record Unverified
// (decision C3-D9: no loaded ownership record is trusted), the counters
// past what any write may have used, and the blocks of the records that
// are not valid.
func (p *persistence) load(st map[string][]byte) {
	m := p.m
	l := decodeState(st)
	p.gen = l.c.Generation
	runs := l.c.RunID
	for k, err := range l.failed {
		p.failed[k] = err
		switch {
		case k == "counters":
			p.readOnly = fmt.Sprintf("the counters record: %v", err)
		case strings.HasPrefix(k, "set/"):
			// Holds its key (checkKey).
		case l.of[k] != "":
			p.blockedSets[l.of[k]] = fmt.Sprintf("the record %s: %v", k, err)
		default:
			p.blockedAll = fmt.Sprintf("the record %s: %v", k, err)
		}
	}
	for _, k := range sortedKeys(st) {
		r := l.sets[k]
		if r == nil {
			continue
		}
		p.gen = max(p.gen, r.Generation)
		conf, err := decodeConf(r.Conf)
		if err == nil {
			var cfg *Config
			if cfg, err = newConfig(conf, r.Version); err == nil {
				s := newSet(cfg)
				s.gen, s.fp = r.Generation, r.Fingerprint
				m.sets[keyString(cfg.key)] = s
				continue
			}
		}
		p.failed[k] = err
	}
	for _, r := range l.eps {
		s := m.sets[keyString(SetKey{Folder: r.Folder, Name: r.SetName})]
		if s == nil {
			continue // its set record did not make a set: reported there
		}
		rec := r.record()
		s.records[recordKey(rec.addr, rec.FunctionalEntity, rec.Name)] = rec
		runs = max(runs, r.Run)
	}
	for k, r := range l.runs {
		runs = max(runs, r.Run)
		if r.Phase == phasePlanned {
			// Nothing owed: deleted, with its set change.
			p.stale = append(p.stale, k, txStoreKey(RunID(r.Run)))
		}
	}
	for _, r := range l.calls {
		runs = max(runs, r.Run)
	}
	m.runs.Store(runs)
	for _, r := range l.eps {
		p.unverified[r.Address] = true
	}
	for _, r := range l.calls {
		p.unverified[r.Address] = true
	}
	p.owed, p.orphans, p.fenced = owedOf(l, p.active, p.unverified)
	for ks, s := range m.sets {
		attachIntents(s, l, p.active)
		if len(p.owed[ks]) > 0 || p.blockedSets[ks] != "" {
			s.state = StateError
		}
	}
}

// owedOf returns the work the journal l shows, by set, the keys of the
// obligations of no set l has (an Add of a set change, a run whose set
// record is gone) and, by set, the work of other sets that fences it
// (fencedOf). The runs in active are running: what they owe is theirs.
func owedOf(l *loaded, active map[RunID]bool, unverified map[string]bool) (owed map[string][]OwedWork, orphans map[string]string, fenced map[string][]OwedWork) {
	owed, orphans = journalOwed(l, active)
	return owed, orphans, fencedOf(l, owed, unverified)
}

// fencedOf returns, by set key, the work other sets owe that the set may
// depend on, conservatively (library interpretation of design §6.3):
//   - the set takes part in an owed set change (an operation of its
//     Replace, Remove or complete Update), until the change is made; or
//   - the set has a server (by its ServerAddress Address, or the server of
//     one of its endpoint records or call intents) in the domain of the
//     owed work: the server of an owed call, whose outcome is unknown
//     until its intent is resolved; and, for other owed work, the servers
//     of the set that owes it and of the sets of its set change on which
//     a record is not verified yet (unverified, design §6.4).
//
// The proof of independence (stage C3.3): once every record of a server
// is decided by the re-proof of §6.5 (KnownOwned, TakenPreconfigured or
// Unresolved, the last never closed) and no call on it has an unknown
// outcome, a run of another set on that server closes only the endpoints
// of its own records and creates only under Names its scan proves free;
// the owed work of the first set, done by its own runs, touches only the
// endpoints of its own records. Until then the remote operations and
// configuration changes of a fenced set are refused like those of the set
// that owes the work.
func fencedOf(l *loaded, owed map[string][]OwedWork, unverified map[string]bool) map[string][]OwedWork {
	servers := map[string]map[string]bool{}
	serve := func(k SetKey, addr string) {
		ks := keyString(k)
		if servers[ks] == nil {
			servers[ks] = map[string]bool{}
		}
		if addr != "" {
			servers[ks][addr] = true
		}
	}
	for _, r := range l.sets {
		k := SetKey{Folder: r.Folder, Name: r.Name}
		serve(k, "")
		if conf, err := decodeConf(r.Conf); err == nil {
			for _, sa := range conf.ServerAddresses {
				if sa != nil {
					serve(k, sa.Address)
				}
			}
		}
	}
	for _, r := range l.eps {
		serve(SetKey{Folder: r.Folder, Name: r.SetName}, r.Address)
	}
	for _, r := range l.calls {
		serve(SetKey{Folder: r.Folder, Name: r.SetName}, r.Address)
	}
	// The addresses of one server, by the ApplicationUri its records and
	// intents were made with: a domain takes them all (two discovery URLs
	// of one AutomationComponent are one server).
	uris := map[string][]string{}
	for _, r := range l.eps {
		if u := r.Server.ApplicationURI; u != "" && !slices.Contains(uris[u], r.Address) {
			uris[u] = append(uris[u], r.Address)
		}
	}
	for _, r := range l.calls {
		if u := r.Server.ApplicationURI; u != "" && !slices.Contains(uris[u], r.Address) {
			uris[u] = append(uris[u], r.Address)
		}
	}
	alias := func(domain map[string]bool) {
		for _, as := range uris {
			if slices.ContainsFunc(as, func(a string) bool { return domain[a] }) {
				for _, a := range as {
					domain[a] = true
				}
			}
		}
	}
	fenced := map[string][]OwedWork{}
	for _, oks := range sortedRecordKeys(owed) {
		for _, w := range owed[oks] {
			parts := map[string]bool{oks: true}
			for _, c := range w.Changes {
				parts[keyString(c.Set)] = true
			}
			domain := map[string]bool{}
			if w.Kind == OwedCall && w.Address != "" {
				domain[w.Address] = true
			}
			for ks := range parts {
				for a := range servers[ks] {
					if unverified[a] {
						domain[a] = true
					}
				}
			}
			alias(domain)
			cands := map[string]bool{}
			for ks := range servers {
				cands[ks] = true
			}
			for ks := range parts {
				cands[ks] = true
			}
			for _, ks := range sortedRecordKeys(cands) {
				if ks == oks {
					continue
				}
				shares := false
				for a := range servers[ks] {
					shares = shares || domain[a]
				}
				if parts[ks] || shares {
					fenced[ks] = append(fenced[ks], w)
				}
			}
		}
	}
	return fenced
}

// journalOwed is the owed work and the orphans of owedOf.
func journalOwed(l *loaded, active map[RunID]bool) (map[string][]OwedWork, map[string]string) {
	sets := map[string]bool{}
	for _, r := range l.sets {
		sets[keyString(SetKey{Folder: r.Folder, Name: r.Name})] = true
	}
	owed := map[string][]OwedWork{}
	orphans := map[string]string{}
	add := func(k SetKey, w OwedWork) {
		ks := keyString(k)
		owed[ks] = append(owed[ks], w)
		if !sets[ks] {
			orphans[ks] = fmt.Sprintf("the run %d of the set %s owes %v", w.Run, k, w.Kind)
		}
	}
	for _, k := range sortedRecordKeys(l.runs) {
		r := l.runs[k]
		if r.Phase == phasePlanned || active[RunID(r.Run)] {
			continue
		}
		w := r.owed()
		if tx := l.txs[txStoreKey(RunID(r.Run))]; tx != nil {
			for _, o := range tx.Ops {
				key := SetKey{Folder: o.Folder, Name: o.Name}
				w.Changes = append(w.Changes, PlannedChange{Op: uafx.ConnectionConfigurationSetOperation(o.Op), Set: key, Version: o.Version})
				if uafx.ConnectionConfigurationSetOperation(o.Op) == uafx.ElementAdd {
					orphans[keyString(key)] = fmt.Sprintf("the set change of run %d adds it", r.Run)
				}
			}
		}
		add(SetKey{Folder: r.Folder, Name: r.SetName}, w)
	}
	for _, k := range sortedRecordKeys(l.calls) {
		r := l.calls[k]
		if active[RunID(r.Run)] {
			continue
		}
		add(SetKey{Folder: r.Folder, Name: r.SetName}, OwedWork{Kind: OwedCall, Run: RunID(r.Run), Address: r.Address, Names: slices.Clone(r.Names)})
	}
	return owed, orphans
}

func sortedRecordKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// attachIntents gives every Name of an unended establish intent of s that
// has no endpoint record one, Unverified and without NodeId (design §6.3:
// the Names of an unknown outcome are re-proved, never assumed absent), so
// that no run creates, takes or forgets an endpoint under it. The caller
// holds s.mu or s is not shared yet.
func attachIntents(s *set, l *loaded, active map[RunID]bool) {
	for _, k := range sortedRecordKeys(l.calls) {
		c := l.calls[k]
		if c.Kind != callEstablish || keyString(SetKey{Folder: c.Folder, Name: c.SetName}) != keyString(s.cfg.key) || active[RunID(c.Run)] {
			continue
		}
		addr := ServerAddress{Address: c.Address, SecurityMode: ua.MessageSecurityMode(c.SecurityMode), SecurityPolicyURI: c.SecurityPolicyURI, ServerURI: c.ServerURIConf}
		ac, _ := unqualify(c.ACNode, c.Namespaces)
		for i, name := range c.Names {
			fe, _ := unqualify(c.FunctionalEntities[i], c.Namespaces)
			rk := recordKey(addr, fe, name)
			if s.records[rk] != nil {
				continue
			}
			ref, ok := s.cfg.endpointNamed(name)
			if !ok {
				ref = EndpointRef{Connection: name}
			}
			s.records[rk] = &record{EndpointRecord: EndpointRecord{
				Set: s.cfg.key, Endpoint: ref, ServerURI: c.Server.ApplicationURI, FunctionalEntity: fe, Name: name,
				Class: Unverified, Run: RunID(c.Run),
			}, addr: addr, acNode: ac, nsa: c.Namespaces, gen: c.Generation, fp: c.Fingerprint, stored: Unresolved, server: c.Server}
		}
	}
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
// whatever class it was written with (decision C3-D9). Its NodeIds are
// mapped with the NamespaceArray it was written with (checked at load).
func (r *epStored) record() *record {
	addr := ServerAddress{Address: r.Address, SecurityMode: ua.MessageSecurityMode(r.SecurityMode), SecurityPolicyURI: r.SecurityPolicyURI, ServerURI: r.ServerURIConf}
	fe, _ := unqualify(r.FunctionalEntity, r.Namespaces)
	n, _ := unqualify(r.NodeID, r.Namespaces)
	ac, _ := unqualify(r.ACNode, r.Namespaces)
	rec := &record{EndpointRecord: EndpointRecord{
		Set: SetKey{Folder: r.Folder, Name: r.SetName}, Endpoint: EndpointRef{Connection: r.Connection, Endpoint: int(r.Endpoint)},
		ServerURI: r.Server.ApplicationURI, FunctionalEntity: fe, Name: r.Name, NodeID: n,
		Class: Unverified, Run: RunID(r.Run), Version: r.Version, ClosePending: r.ClosePending,
	}, addr: addr, acNode: ac, nsa: r.Namespaces, gen: r.Generation, fp: r.Fingerprint, stored: Ownership(r.Class),
		server: r.Server, created: r.CreationTime, cmURI: r.CMApplicationURI, cmObserved: r.CMObserved, epfp: r.EndpointFingerprint, param: r.Param}
	if rec.ServerURI == "" {
		rec.ServerURI = r.ServerURIConf
	}
	return rec
}

// storedOf returns the record rec as it is stored.
func storedOf(rec *record) *epStored {
	class := rec.Class
	if class == Unverified {
		class = rec.stored // as loaded: unverified is not a class to write
	}
	return &epStored{
		Folder: rec.Set.Folder, SetName: rec.Set.Name, Connection: rec.Endpoint.Connection, Endpoint: int64(rec.Endpoint.Endpoint),
		Address: rec.addr.Address, SecurityMode: uint32(rec.addr.SecurityMode), SecurityPolicyURI: rec.addr.SecurityPolicyURI, ServerURIConf: rec.addr.ServerURI,
		Server: rec.server, Namespaces: rec.nsa,
		ACNode: qualify(rec.acNode, rec.nsa), FunctionalEntity: qualify(rec.FunctionalEntity, rec.nsa), Name: rec.Name, NodeID: qualify(rec.NodeID, rec.nsa),
		CreationTime: rec.created, CMApplicationURI: rec.cmURI, CMObserved: rec.cmObserved,
		Class: int64(class), Run: uint64(rec.Run), Version: rec.Version, ClosePending: rec.ClosePending,
		Generation: rec.gen, Fingerprint: rec.fp, EndpointFingerprint: rec.epfp, Param: rec.param,
	}
}

// epKeyOf is the store key of the record rec of the set key.
func epKeyOf(key SetKey, rec *record) string {
	return epStoreKey(key, rec.addr, qualify(rec.FunctionalEntity, rec.nsa), rec.Name)
}

// apply writes b with the counters. The caller holds p.mu. While the
// Manager reconciles after an unknown outcome, or its counters cannot be
// trusted, nothing is written. An unknown outcome consumes the generation
// gen, fences the Manager and starts settling the store.
func (p *persistence) apply(b fxstore.Batch, gen uint64) (fxstore.Outcome, error) {
	switch {
	case p.readOnly != "":
		return fxstore.NotCommitted, fxstore.AsNotCommitted(fmt.Errorf("%w: the store is read-only: %s", ua.StatusBadInvalidState, p.readOnly))
	case p.fence:
		return fxstore.NotCommitted, fxstore.AsNotCommitted(errReconciling)
	}
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
		p.refreshOwed()
	case fxstore.Unknown:
		p.gen = max(p.gen, gen)
		p.fence = true
		p.m.log.Warn("fxcm: the outcome of a store write is unknown; the store is fenced until it is settled and the Manager has followed it", "error", err)
		p.startSettle()
	case fxstore.NotCommitted:
	}
	return o, err
}

// refreshOwed computes what the committed journal owes. The caller holds
// p.mu.
func (p *persistence) refreshOwed() {
	l := decodeState(p.d.State())
	p.owedMu.Lock()
	p.owed, p.orphans, p.fenced = owedOf(l, p.active, p.unverified)
	p.owedMu.Unlock()
}

// activate marks the run id active, or no longer (finish): an active
// run's journal is its own, not owed work.
func (p *persistence) activate(id RunID, on bool) {
	p.owedMu.Lock()
	defer p.owedMu.Unlock()
	if on {
		p.active[id] = true
	} else {
		delete(p.active, id)
		delete(p.retained, id)
	}
}

// retain notes that the intent k of the active run id has an unknown
// outcome.
func (p *persistence) retain(id RunID, k string) {
	p.owedMu.Lock()
	defer p.owedMu.Unlock()
	if p.retained == nil {
		p.retained = map[RunID]map[string]bool{}
	}
	if p.retained[id] == nil {
		p.retained[id] = map[string]bool{}
	}
	p.retained[id][k] = true
}

// write is apply under p.mu.
func (p *persistence) write(b fxstore.Batch, gen uint64) (fxstore.Outcome, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.apply(b, gen)
}

// lockJournal locks s and the writes for a journal write: the snapshot of
// the records of s, its diff against the committed state and its write are
// one step, so that two completions never commit their snapshots out of
// order. It returns the unlock.
func (p *persistence) lockJournal(s *set) func() {
	s.mu.Lock()
	p.mu.Lock()
	return func() {
		p.mu.Unlock()
		s.mu.Unlock()
	}
}

// startSettle settles the fenced store in the background, with a bounded
// backoff, until it is settled or the Manager closed; then the memory of
// the Manager follows the committed state (§3.5: no stale memory), and only
// then the fence ends.
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
		defer func() {
			p.settleMu.Lock()
			p.settling = false
			p.settleMu.Unlock()
		}()
		wait := settleInitial
		for {
			ctx, cancel := p.ctx()
			ok, err := p.d.Settle(ctx)
			cancel()
			if ok {
				break
			}
			p.m.log.Warn("fxcm: the store is not settled yet", "error", err, "retry", wait)
			if !p.sleep(wait) {
				return
			}
			wait = min(2*wait, settleMax)
		}
		p.m.log.Info("fxcm: the store is settled")
		wait = followInitial
		for !p.follow() {
			// A set is busy: its run, claim or reserved key ends soon,
			// since nothing writes while the Manager is fenced.
			if !p.sleep(wait) {
				return
			}
			wait = min(2*wait, followMax)
		}
		p.mu.Lock()
		p.fence = false
		p.refreshOwed()
		p.mu.Unlock()
		p.m.log.Info("fxcm: the Manager follows the store again")
	}()
}

// sleep waits d, false when the Manager closed meanwhile.
func (p *persistence) sleep(d time.Duration) bool {
	select {
	case <-p.m.ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// follow makes the memory of the Manager follow the committed state after
// a settle: a set change whose write had an unknown outcome and committed
// after all is made, one that did not is not; a set the store has at
// another generation takes the stored Config (an open edit stays open);
// endpoint records the store has and memory does not are added
// Unverified, and so are the Names of unended establish intents; the sets
// that owe work go to Error. It returns false, and changes nothing, while
// a set is busy (a run or a claim) or a key the store has is reserved by
// an Add or an Update in progress: those end without writing, and follow
// is tried again.
func (p *persistence) follow() bool {
	st := p.d.State()
	l := decodeState(st)
	m := p.m
	p.owedMu.Lock()
	active := maps.Clone(p.active)
	unverified := maps.Clone(p.unverified)
	p.owedMu.Unlock()
	var events []Event
	defer func() {
		// Registered before the unlock of m.mu, so run after it (LIFO):
		// an observer may call into the Manager.
		for _, e := range events {
			m.observe(e)
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sets {
		s.mu.Lock()
		busy := s.current != nil || s.held
		s.mu.Unlock()
		if busy {
			return false
		}
	}
	for _, r := range l.sets {
		if m.reserved[keyString(SetKey{Folder: r.Folder, Name: r.Name})] {
			return false
		}
	}
	var gen uint64
	for _, r := range l.sets {
		gen = max(gen, r.Generation)
	}
	p.mu.Lock()
	p.gen = max(p.gen, gen, l.c.Generation)
	p.mu.Unlock()
	for ks, s := range m.sets {
		k := setStoreKey(s.cfg.key)
		r := l.sets[k]
		s.mu.Lock()
		if pc := s.pending; pc != nil {
			s.pending = nil
			if r != nil && r.Generation == pc.gen && string(r.Fingerprint) == string(pc.fp) {
				// The commit landed: its Version is the set's and the
				// edit it committed ends, exactly once (§6.7.4).
				s.cfg, s.gen, s.fp = pc.cfg, pc.gen, pc.fp
				s.diags = remapDiagnostics(s.diags, pc.cfg)
				if s.edit.edit == pc.edit {
					s.edit.edit = nil
				}
				events = append(events, Event{Kind: EventCommitted, Set: pc.cfg.key, Version: pc.cfg.version})
				s.mu.Unlock()
				continue
			}
			// It did not land: the edit stays open.
		}
		switch {
		case r == nil:
			if p.failed[k] == nil {
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
		s.mu.Unlock()
	}
	for _, r := range l.sets {
		key := SetKey{Folder: r.Folder, Name: r.Name}
		if m.sets[keyString(key)] != nil {
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
	for _, r := range l.eps {
		s := m.sets[keyString(SetKey{Folder: r.Folder, Name: r.SetName})]
		if s == nil {
			continue
		}
		rec := r.record()
		rk := recordKey(rec.addr, rec.FunctionalEntity, rec.Name)
		s.mu.Lock()
		if s.records[rk] == nil {
			s.records[rk] = rec
			// Unverified again: so is its server (design §6.4).
			unverified[rec.addr.Address] = true
		}
		s.mu.Unlock()
	}
	for _, c := range l.calls {
		if !active[RunID(c.Run)] {
			unverified[c.Address] = true
		}
	}
	owed, orphans, fenced := owedOf(l, active, unverified)
	for ks, s := range m.sets {
		s.mu.Lock()
		attachIntents(s, l, active)
		if len(owed[ks]) > 0 {
			s.state = StateError
		}
		s.mu.Unlock()
	}
	p.owedMu.Lock()
	p.owed, p.orphans, p.fenced, p.unverified = owed, orphans, fenced, unverified
	p.owedMu.Unlock()
	return true
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

// deleteRecordsOf adds to b the delete of every endpoint record of the set
// key the committed state has.
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
	st := StoreStatus{Store: p.d.Status(), Failed: map[string]error{}, Orphaned: map[string]string{}}
	if d, ok := p.m.opts.Store.(fxstore.Durable); ok {
		st.Durability = d.Durability()
	}
	p.mu.Lock()
	for k, err := range p.failed {
		st.Failed[k] = err
	}
	st.Reconciling, st.ReadOnly, st.BlockedAll = p.fence, p.readOnly, p.blockedAll
	p.mu.Unlock()
	p.owedMu.Lock()
	for k, why := range p.orphans {
		st.Orphaned[setKeyOf(k).String()] = why
	}
	p.owedMu.Unlock()
	return st
}

// setKeyOf is the SetKey of a keyString.
func setKeyOf(ks string) SetKey {
	parts := strings.Split(ks, "\x00")
	return SetKey{Folder: parts[:len(parts)-1], Name: parts[len(parts)-1]}
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
	ks := keyString(s.cfg.key)
	p.mu.Lock()
	r.Blocked = p.blockedSets[ks]
	if r.Blocked == "" {
		r.Blocked = p.blockedAll
	}
	p.mu.Unlock()
	p.owedMu.Lock()
	r.Owed = slices.Clone(p.owed[ks])
	r.Fenced = slices.Clone(p.fenced[ks])
	for _, rec := range s.records {
		if why := p.verifyErr[rec.addr.Address]; rec.Class == Unverified && why != "" {
			if r.Unreachable == nil {
				r.Unreachable = map[string]string{}
			}
			r.Unreachable[rec.addr.Address] = why
		}
	}
	p.owedMu.Unlock()
	r.Done = r.Pending == 0 && len(r.Owed) == 0 && len(r.Fenced) == 0 && r.Blocked == ""
	return r
}

// sortedKeys returns the keys of st in order.
func sortedKeys(st map[string][]byte) []string { return sortedRecordKeys(st) }

// checkKey refuses an Add of a set whose key a record that is not valid,
// or an obligation of no current set, holds: it is never overwritten
// (§3.2), and no Add bypasses the obligation; and every change while the
// store is read-only.
func (p *persistence) checkKey(key SetKey) error {
	p.mu.Lock()
	ro := p.readOnly
	failed := p.failed[setStoreKey(key)]
	p.mu.Unlock()
	p.owedMu.Lock()
	orphan := p.orphans[keyString(key)]
	p.owedMu.Unlock()
	switch {
	case ro != "":
		return managerError(ua.StatusBadInvalidState, "the store is read-only: %s", ro)
	case failed != nil:
		return managerError(ua.StatusBadInvalidState, "the store holds a record of the set %s that is not valid: %v", key, failed)
	case orphan != "":
		return managerError(ua.StatusBadInvalidState, "the store holds an obligation for the set %s: %s", key, orphan)
	}
	return nil
}

// checkRemote refuses an operation on the set key that changes its set or
// acts on its endpoints outside a run (a Replace, a Remove, an Update) while
// a record that is not valid could be of it, while it owes work, or while
// it takes part in, or shares a server with, work another set owes
// (fencedOf): the owed work is done by a Process or Reconcile of the set
// first (design §6.3), whose run starts with it (checkRun).
func (p *persistence) checkRemote(key SetKey) error {
	if err := p.checkBlocked(key); err != nil {
		return err
	}
	ks := keyString(key)
	p.owedMu.Lock()
	owed := slices.Clone(p.owed[ks])
	p.owedMu.Unlock()
	if len(owed) > 0 {
		return managerError(ua.StatusBadInvalidState, "the set %s owes %v of run %d: a Process or Reconcile of the set does it first", key, owed[0].Kind, owed[0].Run)
	}
	return nil
}

// checkBlocked refuses an operation on the endpoints of the set key while
// a record that is not valid could be of it, or while it takes part in, or
// shares a server with, work another set owes (fencedOf).
func (p *persistence) checkBlocked(key SetKey) error {
	ks := keyString(key)
	p.mu.Lock()
	all, blocked := p.blockedAll, p.blockedSets[ks]
	p.mu.Unlock()
	p.owedMu.Lock()
	fenced := slices.Clone(p.fenced[ks])
	p.owedMu.Unlock()
	switch {
	case all != "":
		return managerError(ua.StatusBadInvalidState, "the store holds a record that is not valid: %s", all)
	case blocked != "":
		return managerError(ua.StatusBadInvalidState, "the store holds a record of the set %s that is not valid: %s", key, blocked)
	case len(fenced) > 0:
		return managerError(ua.StatusBadInvalidState, "the set %s takes part in, or shares a server with, %v owed by run %d", key, fenced[0].Kind, fenced[0].Run)
	}
	return nil
}

// checkRun refuses a run of action on the set key while checkBlocked
// does, and a run other than a Reconcile while the set owes a set change:
// that change replaces or removes the set, which only a Reconcile completes
// (library interpretation of design §6.3). The other owed work (a call
// whose outcome is unknown, a rollback, a reconcile) is done by the first
// step of the run (recover).
func (p *persistence) checkRun(key SetKey, action uafx.FxProcess) error {
	if err := p.checkBlocked(key); err != nil {
		return err
	}
	if action == ActionReconcile {
		return nil
	}
	p.owedMu.Lock()
	defer p.owedMu.Unlock()
	for _, w := range p.owed[keyString(key)] {
		if w.Kind == OwedSetChange {
			return managerError(ua.StatusBadInvalidState, "the set %s owes the %v of run %d, which a Reconcile completes", key, w.Kind, w.Run)
		}
	}
	return nil
}

// checkConfig refuses a change of the configuration of the set key (a
// CommitEdit) while it takes part in, or shares a server with, work
// another set owes (fencedOf), or owes a set change itself: the owed
// change commits Versions of its sets, which a commit would overtake.
func (p *persistence) checkConfig(key SetKey) error {
	ks := keyString(key)
	p.owedMu.Lock()
	defer p.owedMu.Unlock()
	if f := p.fenced[ks]; len(f) > 0 {
		return managerError(ua.StatusBadInvalidState, "the set %s takes part in, or shares a server with, %v owed by run %d", key, f[0].Kind, f[0].Run)
	}
	for _, w := range p.owed[ks] {
		if w.Kind == OwedSetChange {
			return managerError(ua.StatusBadInvalidState, "the set %s owes the %v of run %d, which a Reconcile completes", key, w.Kind, w.Run)
		}
	}
	return nil
}

// unresolvedOn returns the server addresses on which an intent of the set
// key of a run other than run is in the store: its outcome is not proven.
func (p *persistence) unresolvedOn(key SetKey, run RunID) map[string]bool {
	out := map[string]bool{}
	for _, c := range decodeState(p.d.State()).calls {
		if keyString(SetKey{Folder: c.Folder, Name: c.SetName}) == keyString(key) && RunID(c.Run) != run {
			out[c.Address] = true
		}
	}
	return out
}

// fenceIntents refuses the intent c of a run of the set key while another
// set has an intent on the server of c, by its address or by the
// ApplicationUri of its server (two addresses of one server), of a run
// that is not active: the fence a run passed when it started is checked
// again before each of its calls, so that work another set came to owe
// meanwhile is not bypassed (design §6.3). The caller holds p.mu
// (lockJournal), under which every intent is written, so that the check
// and the write of the intent of c are one step and no other set writes an
// intent in between. An intent of
// another set's active run fences only when its outcome is unknown
// (retained); one still in flight is serialized by the place locks.
func (p *persistence) fenceIntents(key SetKey, c *callRecord) error {
	p.owedMu.Lock()
	active := maps.Clone(p.active)
	retained := map[string]bool{}
	for _, ks := range p.retained {
		maps.Copy(retained, ks)
	}
	p.owedMu.Unlock()
	return fencedBy(key, c, decodeState(p.d.State()).calls, active, retained)
}

// fencedBy is fenceIntents over the intents calls of the store, the active
// runs and the retained intents.
func fencedBy(key SetKey, c *callRecord, calls map[string]*callRecord, active map[RunID]bool, retained map[string]bool) error {
	for _, k := range sortedRecordKeys(calls) {
		o := calls[k]
		if keyString(SetKey{Folder: o.Folder, Name: o.SetName}) == keyString(key) || active[RunID(o.Run)] && !retained[k] {
			continue
		}
		if o.Address == c.Address || o.Server.ApplicationURI != "" && o.Server.ApplicationURI == c.Server.ApplicationURI {
			return managerError(ua.StatusBadInvalidState, "the set %s owes a call of unknown outcome on the server of %s (run %d)", SetKey{Folder: o.Folder, Name: o.SetName}, c.Address, o.Run)
		}
	}
	return nil
}

// heldName reports whether an owed intent of the set key holds the Name
// name on the server addr.
func (p *persistence) heldName(key SetKey, addr ServerAddress, name string) bool {
	p.owedMu.Lock()
	defer p.owedMu.Unlock()
	for _, w := range p.owed[keyString(key)] {
		if w.Kind == OwedCall && w.Address == addr.Address && slices.Contains(w.Names, name) {
			return true
		}
	}
	return false
}

// putConfig makes cfg the committed configuration of its set: a new
// generation. It returns the generation and the fingerprint, or the
// storeError of the write.
func (p *persistence) putConfig(cfg *Config) (uint64, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	gen := p.gen + 1
	var b fxstore.Batch
	fp, err := putSet(&b, cfg, gen)
	if err != nil {
		return 0, nil, storeError(fxstore.NotCommitted, err)
	}
	if o, err := p.apply(b, gen); o != fxstore.Committed {
		// The generation and fingerprint stay the caller's evidence of
		// a write with an unknown outcome.
		return gen, fp, storeError(o, err)
	}
	return gen, fp, nil
}

// setChange is one set change of a switch: next nil removes the set.
type setChange struct {
	key  SetKey
	next *Config
	// existing: the set exists and its endpoint records go.
	existing bool
	// gen is the generation the planned write of a set change reserved
	// for next, 0 for a new one.
	gen uint64
}

// switchSets makes the changes durable in one write, with the end of the
// runs that closed their Connections (§6.2): a removed or replaced set
// loses its endpoint records, its run record and its set change. It
// returns the generation and fingerprint of each next Config, in the order
// of cs.
func (p *persistence) switchSets(cs []setChange, runs []RunID) ([]uint64, [][]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b fxstore.Batch
	gens := make([]uint64, len(cs))
	fps := make([][]byte, len(cs))
	gen := p.gen
	top := gen
	for i, c := range cs {
		if c.existing {
			p.deleteRecordsOf(&b, c.key)
		}
		if c.next == nil {
			b.Deletes = append(b.Deletes, setStoreKey(c.key))
			continue
		}
		g := c.gen
		if g == 0 {
			gen++
			g = gen
		}
		top = max(top, g, gen)
		fp, err := putSet(&b, c.next, g)
		if err != nil {
			return nil, nil, storeError(fxstore.NotCommitted, err)
		}
		gens[i], fps[i] = g, fp
	}
	for _, r := range runs {
		b.Deletes = append(b.Deletes, runStoreKey(r), txStoreKey(r))
	}
	if o, err := p.apply(b, top); o != fxstore.Committed {
		return nil, nil, storeError(o, err)
	}
	return gens, fps, nil
}

// settleRecord writes the verdict of Settle on the record rec of the set s,
// with the completion of the intents of runs that are not active whose
// places the verdict decides the last (design §6.3). The caller holds s.mu.
func (p *persistence) settleRecord(s *set, rec *record, v Verdict) error {
	var b fxstore.Batch
	k := epKeyOf(s.cfg.key, rec)
	l := decodeState(p.d.State())
	p.owedMu.Lock()
	active := maps.Clone(p.active)
	p.owedMu.Unlock()
	undecided := func(r *record) bool { return r != rec && (r.Class == Unverified || r.Class == Unresolved) }
	for _, ck := range sortedRecordKeys(l.calls) {
		c := l.calls[ck]
		if keyString(SetKey{Folder: c.Folder, Name: c.SetName}) != keyString(s.cfg.key) || active[RunID(c.Run)] || !c.sameAddress(rec.addr) {
			continue
		}
		if !p.intentOpen(s, c, undecided) {
			b.Deletes = append(b.Deletes, ck)
		}
	}
	if v == SettleOwned {
		cp := *rec
		cp.Class = KnownOwned
		val, err := encodeRecord(storedOf(&cp))
		if err != nil {
			return storeError(fxstore.NotCommitted, err)
		}
		b.Puts = map[string][]byte{k: val}
	} else if _, ok := p.d.State()[k]; ok {
		b.Deletes = append(b.Deletes, k)
	}
	if o, err := p.write(b, 0); o != fxstore.Committed {
		return storeError(o, err)
	}
	return nil
}
