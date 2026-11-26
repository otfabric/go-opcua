// SPDX-License-Identifier: MIT

package fxcm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The journal of a run with a Store (design §6.3): the run record is
// written before the first call, with the set change of a Replace, Remove
// or complete Update; an intent before each call; and the completion of
// the intents of a step is one write with the endpoint records the step
// changed and the run record. A crash therefore leaves the obligations of
// the run and the evidence of every call whose outcome it did not record.
//
// Every journal write holds the lock of the set from the snapshot of its
// records to the end of its write (persistence.lockJournal): a write never
// commits an older snapshot after a newer one, and a write that fails
// changes, in memory, exactly the records it tried to write.

// journal is the journal state of a run.
type journal struct {
	// started: the run record is committed.
	started bool
	phase   uint8
	// intents are the keys of the committed intents not yet completed;
	// retained those that stay in the store, with the evidence of their
	// call: their completion was not written, or the outcome of the call
	// is unknown and not proven (decision C3-D13). The run record stays
	// with them (design §6.3).
	intents  []string
	retained map[string]bool
	n        int
	// tx is the set change of the run, nil for a Process.
	tx *txPlan
	// keep: the run record stays at the end of the run: its set change is
	// switched after it, or its rollback is owed.
	keep bool
	// rollbackOwed: the rollback did not finish, or was not started
	// because its phase could not be written.
	rollbackOwed bool
}

// txPlan is the set change of a run (§6.2): the operations of a Replace,
// Remove or complete Update. The planned write of the run reserves the
// generations of the sets it commits.
type txPlan struct {
	ops  []txOp
	cfgs []*Config // per op, nil for a removal
}

// planOps returns the txPlan of the set changes cs, Old filled from the
// sets the Manager has.
func (m *Manager) planOps(cs []setChange, ops []uafx.ConnectionConfigurationSetOperation) (*txPlan, error) {
	tp := &txPlan{}
	for i, c := range cs {
		o := txOp{Op: int32(ops[i]), Folder: c.key.Folder, Name: c.key.Name}
		if s := m.lookup(c.key); s != nil && c.existing {
			s.mu.Lock()
			o.Old = s.gen
			s.mu.Unlock()
		}
		if c.next != nil {
			conf, fp, err := encodeConf(c.next.conf)
			if err != nil {
				return nil, err
			}
			o.Version, o.Fingerprint, o.Conf = c.next.version, fp, conf
		}
		tp.ops = append(tp.ops, o)
		tp.cfgs = append(tp.cfgs, c.next)
	}
	return tp, nil
}

// store returns the persistence of the run's Manager, nil without one.
func (x *run) store() *persistence {
	if x.m == nil {
		return nil
	}
	return x.m.p
}

// errNoIntent stops a call whose intent was not written: nothing is sent
// (design §6.3).
func errNoIntent(err error) error {
	return failure(uafx.FxErrorRuntimeError, StatusOf(err), "the intent of the call was not written to the store, nothing was sent: %v", err)
}

// startJournal writes the run record, phase planned, before the run makes
// any call, with the set change of the run and the generations it
// reserves; the first intent moves it to executing (design §6.3: a crash
// before the first intent owes nothing). A run whose record is not written
// makes no call: it fails with the error of the write.
func (x *run) startJournal() error {
	p := x.store()
	if p == nil {
		return nil
	}
	p.activate(x.r.id, true)
	unlock := p.lockJournal(x.s)
	defer unlock()
	b := fxstore.Batch{Puts: map[string][]byte{}}
	gen := p.gen
	var next uint64
	if tp := x.j.tx; tp != nil {
		for i := range tp.ops {
			if tp.cfgs[i] != nil {
				gen++
				tp.ops[i].New = gen
				if keyString(tp.cfgs[i].key) == keyString(x.r.key) {
					next = gen
				}
			}
		}
		v, err := encodeRecord(&txRecord{Run: uint64(x.r.id), Ops: tp.ops})
		if err != nil {
			return storeError(fxstore.NotCommitted, err)
		}
		b.Puts[txStoreKey(x.r.id)] = v
	}
	rr := x.runRecordLocked(phasePlanned)
	rr.Next = next
	v, err := encodeRecord(rr)
	if err != nil {
		return storeError(fxstore.NotCommitted, err)
	}
	b.Puts[runStoreKey(x.r.id)] = v
	if o, err := p.apply(b, gen); o != fxstore.Committed {
		return storeError(o, err)
	}
	x.j.started, x.j.phase = true, phasePlanned
	return nil
}

// runRecordLocked returns the run record of x at phase. The caller holds
// x.s.mu.
func (x *run) runRecordLocked(phase uint8) *runRecord {
	var eps []string
	for _, rec := range x.s.records {
		if rec.Run == x.r.id {
			eps = append(eps, epKeyOf(x.r.key, rec))
		}
	}
	slices.Sort(eps)
	r := &runRecord{
		Run: uint64(x.r.id), Folder: x.r.key.Folder, SetName: x.r.key.Name, Generation: x.gen, Fingerprint: x.fp,
		Action: int32(x.r.action), RollbackOnError: x.cfg.RollbackOnError(), Phase: phase, Endpoints: eps,
	}
	if tp := x.j.tx; tp != nil {
		for i, o := range tp.ops {
			if tp.cfgs[i] != nil && keyString(tp.cfgs[i].key) == keyString(x.r.key) {
				r.Next = o.New
			}
		}
	}
	return r
}

// phase returns the phase of the run record.
func (x *run) phase() uint8 {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.j.phase
}

// setPhase moves the run record to phase and returns the error of a write
// that fails: the caller decides whether the step may go on without it.
func (x *run) setPhase(phase uint8) error {
	p := x.store()
	if p == nil || !x.j.started || x.phase() == phase {
		return nil
	}
	unlock := p.lockJournal(x.s)
	defer unlock()
	v, err := encodeRecord(x.runRecordLocked(phase))
	if err != nil {
		return storeError(fxstore.NotCommitted, err)
	}
	if o, err := p.apply(fxstore.Batch{Puts: map[string][]byte{runStoreKey(x.r.id): v}}, 0); o != fxstore.Committed {
		err = storeError(o, err)
		x.m.log.Warn("fxcm: the phase of the run was not written to the store", "set", x.r.key.String(), "run", x.r.id, "error", err)
		return err
	}
	x.mu.Lock()
	x.j.phase = phase
	x.mu.Unlock()
	return nil
}

// intend writes the intent of a call before it is sent, with the
// generation and fingerprint of the run's configuration. It returns its
// key ("" without a Store); an error means the call must not be sent.
func (x *run) intend(c *callRecord) (string, error) {
	p := x.store()
	if p == nil {
		return "", nil
	}
	if !x.j.started {
		return "", errNoIntent(fmt.Errorf("%w: the run has no run record", errStore))
	}
	c.Run, c.Generation, c.Fingerprint = uint64(x.r.id), x.gen, x.fp
	c.Folder, c.SetName = x.r.key.Folder, x.r.key.Name
	v, err := encodeRecord(c)
	if err != nil {
		return "", errNoIntent(err)
	}
	x.crashPoint("call.before-intent")
	k, err := func() (string, error) {
		unlock := p.lockJournal(x.s)
		defer unlock()
		x.mu.Lock()
		x.j.n++
		k := callStoreKey(x.r.id, x.j.n)
		planned := x.j.phase == phasePlanned
		x.mu.Unlock()
		b := fxstore.Batch{Puts: map[string][]byte{k: v}}
		if planned {
			// The first intent: the run is executing from this write on.
			rv, err := encodeRecord(x.runRecordLocked(phaseExecuting))
			if err != nil {
				return "", errNoIntent(err)
			}
			b.Puts[runStoreKey(x.r.id)] = rv
		}
		if o, err := p.apply(b, 0); o != fxstore.Committed {
			return "", errNoIntent(storeError(o, err))
		}
		x.mu.Lock()
		x.j.intents = append(x.j.intents, k)
		if planned {
			x.j.phase = phaseExecuting
		}
		x.mu.Unlock()
		return k, nil
	}()
	if err != nil {
		return "", err
	}
	x.crashPoint("call.after-intent")
	return k, nil
}

// retain keeps the intent k in the store: the outcome of its call is not
// proven (decision C3-D13).
func (x *run) retain(k string) {
	if k == "" {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.j.retained == nil {
		x.j.retained = map[string]bool{}
	}
	x.j.retained[k] = true
}

// crashPoint runs the crash hook of the tests.
func (x *run) crashPoint(name string) {
	if x.m != nil {
		x.m.crashPoint(name)
	}
}

// fingerprint is the SHA-256 of the encoding of v, nil when it does not
// encode.
func fingerprint(v any) []byte {
	b, err := ua.Encode(v)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

// establishIntent is the intent of an EstablishConnections of req on a.
func (x *run) establishIntent(a *acRun, req *uafx.EstablishConnectionsRequest, args []*ua.Variant) *callRecord {
	nsa := a.t.nsa
	c := &callRecord{Kind: callEstablish, ACNode: qualify(a.node, nsa), Namespaces: nsa, Server: a.t.server}
	c.Address, c.SecurityMode, c.SecurityPolicyURI, c.ServerURIConf = a.addr.Address, uint32(a.addr.SecurityMode), a.addr.SecurityPolicyURI, a.addr.ServerURI
	if b, err := ua.Encode(args); err == nil {
		c.Request = b
	}
	for _, cec := range req.ConnectionEndpointConfigurations {
		name := ""
		var pre *ua.NodeID
		absent := false
		if d := cec.ConnectionEndpoint; d != nil {
			if d.Parameter != nil {
				name = d.Parameter.Name
			}
			pre = d.Node
		}
		for _, ep := range a.eps {
			if ep.fe.Equal(cec.FunctionalEntityNode) && ep.e.conf.Name == name {
				absent = ep.obs == nil
			}
		}
		c.Names = append(c.Names, name)
		c.FunctionalEntities = append(c.FunctionalEntities, qualify(cec.FunctionalEntityNode, nsa))
		c.EndpointFingerprints = append(c.EndpointFingerprints, fingerprint(cec))
		c.AbsentBefore = append(c.AbsentBefore, absent)
		c.Preconfigured = append(c.Preconfigured, qualify(pre, nsa))
	}
	return c
}

// closeIntent is the intent of a CloseConnections of nodes on ac of the
// server t.
func closeIntent(t *target, ac *ua.NodeID, nodes []*ua.NodeID, remove bool) *callRecord {
	c := &callRecord{
		Kind: callClose, ACNode: qualify(ac, t.nsa), Namespaces: t.nsa, Remove: remove, Server: t.server,
		Address: t.addr.Address, SecurityMode: uint32(t.addr.SecurityMode), SecurityPolicyURI: t.addr.SecurityPolicyURI, ServerURIConf: t.addr.ServerURI,
	}
	for _, n := range nodes {
		c.Nodes = append(c.Nodes, qualify(n, t.nsa))
	}
	return c
}

// touched are the records a step changed: their keys in the set's map
// (recordKey) to their store keys, which a forgotten record still needs.
type touched map[string]string

// touch adds the record rec, of map key rk, to t.
func (x *run) touch(t touched, rk string, rec *record) {
	if t != nil && rec != nil {
		t[rk] = epKeyOf(x.r.key, rec)
	}
}

// touchAC adds the record rec, of map key rk, to the records the step of a
// changed.
func (x *run) touchAC(a *acRun, rk string, rec *record) {
	if a == nil || rec == nil {
		return
	}
	if a.touched == nil {
		a.touched = touched{}
	}
	x.touch(a.touched, rk, rec)
}

// sync completes the intents keys of calls whose results the run has
// applied: one write that deletes them, writes the endpoint records the
// step changed (recs) as memory has them now, and the run record (design
// §6.3: no committed state with a result but no intent, or an intent
// completed without its records). With end, every intent that is not
// retained is completed, every record of the set is compared with the
// store, and the run record goes too, unless the run keeps it.
//
// A write that does not commit leaves the intents in the store, and the
// records it tried to write that claim ownership (KnownOwned,
// TakenPreconfigured) Unresolved in memory: what the calls did is real,
// but the store cannot show it, so no later step trusts it. A record whose
// stored value is the one in memory was not part of the write and keeps
// its class.
func (x *run) sync(keys []string, recs touched, end bool) {
	p := x.store()
	if p == nil || !x.j.started {
		return
	}
	unlock := p.lockJournal(x.s)
	defer unlock()
	st := p.d.State()
	b := fxstore.Batch{Puts: map[string][]byte{}}
	x.mu.Lock()
	if end {
		keys = slices.DeleteFunc(slices.Clone(x.j.intents), func(k string) bool { return x.j.retained[k] })
	} else {
		keys = slices.DeleteFunc(slices.Clone(keys), func(k string) bool { return x.j.retained[k] })
	}
	retained := len(x.j.retained) > 0
	keep := x.j.keep || x.j.rollbackOwed
	phase := x.j.phase
	x.mu.Unlock()
	b.Deletes = append(b.Deletes, keys...)
	if end {
		recs = touched{}
		for rk, rec := range x.s.records {
			recs[rk] = epKeyOf(x.r.key, rec)
		}
		mine := map[string]bool{}
		for _, k := range recs {
			mine[k] = true
		}
		for k, v := range st {
			if !strings.HasPrefix(k, "ep/") || mine[k] {
				continue
			}
			var r epStored
			if decodeRecord(v, &r) == nil && keyString(SetKey{Folder: r.Folder, Name: r.SetName}) == keyString(x.r.key) {
				recs["\x00stored\x00"+k] = k
			}
		}
	}
	var claimed []*record
	for _, rk := range slices.Sorted(maps.Keys(recs)) {
		k := recs[rk]
		rec := x.s.records[rk]
		if rec == nil || epKeyOf(x.r.key, rec) != k {
			if _, ok := st[k]; ok {
				b.Deletes = append(b.Deletes, k)
			}
			continue
		}
		v, err := encodeRecord(storedOf(rec))
		if err != nil {
			continue
		}
		if !bytes.Equal(st[k], v) {
			b.Puts[k] = v
			if rec.Class.MayClose() {
				claimed = append(claimed, rec)
			}
		}
	}
	if end && !keep && !retained {
		b.Deletes = append(b.Deletes, runStoreKey(x.r.id), txStoreKey(x.r.id))
	} else {
		if end && x.j.rollbackOwed {
			phase = phaseRollbackRequired
		}
		v, err := encodeRecord(x.runRecordLocked(phase))
		if err == nil {
			b.Puts[runStoreKey(x.r.id)] = v
		}
	}
	o, err := p.apply(b, 0)
	if o == fxstore.Committed {
		x.mu.Lock()
		x.j.intents = slices.DeleteFunc(x.j.intents, func(k string) bool { return slices.Contains(keys, k) })
		x.j.phase = phase
		x.mu.Unlock()
		return
	}
	err = storeError(o, err)
	x.m.log.Warn("fxcm: the outcome of calls was not written to the store; their endpoints stay Unresolved", "set", x.r.key.String(), "run", x.r.id, "error", err)
	x.mu.Lock()
	if x.j.retained == nil {
		x.j.retained = map[string]bool{}
	}
	for _, k := range keys {
		x.j.retained[k] = true
	}
	x.res.Failures = append(x.res.Failures, Failure{FxError: uafx.FxErrorRuntimeError, Status: StatusOf(err)})
	x.mu.Unlock()
	for _, rec := range claimed {
		rec.Class = Unresolved
	}
}
