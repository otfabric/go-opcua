// SPDX-License-Identifier: MIT

package fxcm

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The journal of a run with a Store (design §6.3): the run record is
// written before the first call, an intent before each call, and the
// completion of the intents of a step is one write with the endpoint
// records that result from them and the run record. A crash therefore
// leaves the obligations of the run and the evidence of every call whose
// outcome it did not record.

// journal is the journal state of a run.
type journal struct {
	// started: the run record is committed.
	started bool
	phase   uint8
	// intents are the keys of the committed intents not yet completed;
	// lost those whose completion was not written: they stay in the
	// store, with the evidence of their call, and so does the run record
	// (design §6.3).
	intents []string
	lost    map[string]bool
	n       int
	// next is the Config a Replace switches to after its closes, nil for
	// a Remove or a Process.
	next *Config
	// keep: the run record stays at the end of the run (a Replace or
	// Remove whose switch is written after it).
	keep bool
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
// any call; the first intent moves it to executing (design §6.3: a crash
// before the first intent owes nothing). A run whose record is not written
// makes no call: it fails with the error of the write.
func (x *run) startJournal() error {
	p := x.store()
	if p == nil {
		return nil
	}
	if err := x.writeRun(phasePlanned, nil); err != nil {
		return err
	}
	x.j.started = true
	return nil
}

// runRecord returns the run record of x at phase.
func (x *run) runRecord(phase uint8) *runRecord {
	x.s.mu.Lock()
	gen := x.s.gen
	var eps []string
	for rk, rec := range x.s.records {
		if rec.Run == x.r.id {
			eps = append(eps, epStoreKey(x.r.key, rk))
		}
	}
	x.s.mu.Unlock()
	slices.Sort(eps)
	r := &runRecord{
		Run: uint64(x.r.id), Folder: x.r.key.Folder, SetName: x.r.key.Name, Generation: gen,
		Action: int32(x.r.action), RollbackOnError: x.cfg.RollbackOnError(), Phase: phase, Endpoints: eps,
	}
	return r
}

// writeRun writes the run record at phase with the extra changes of b.
func (x *run) writeRun(phase uint8, b *fxstore.Batch) error {
	p := x.store()
	rr := x.runRecord(phase)
	v, err := encodeRecord(rr)
	if err != nil {
		return storeError(fxstore.NotCommitted, err)
	}
	if b == nil {
		b = &fxstore.Batch{}
	}
	if b.Puts == nil {
		b.Puts = map[string][]byte{}
	}
	b.Puts[runStoreKey(x.r.id)] = v
	if x.j.next != nil && phase == phasePlanned {
		// A Replace: the switch it owes needs the next Config.
		conf, fp, err := encodeConf(x.j.next.conf)
		if err != nil {
			return storeError(fxstore.NotCommitted, err)
		}
		nv, err := encodeRecord(&setRecord{Folder: x.j.next.key.Folder, Name: x.j.next.key.Name, Version: x.j.next.version, Fingerprint: fp, Conf: conf})
		if err != nil {
			return storeError(fxstore.NotCommitted, err)
		}
		b.Puts[nextStoreKey(x.r.id)] = nv
	}
	if o, err := p.write(*b, 0); o != fxstore.Committed {
		return storeError(o, err)
	}
	x.mu.Lock()
	x.j.phase = phase
	x.mu.Unlock()
	return nil
}

// phase returns the phase of the run record.
func (x *run) phase() uint8 {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.j.phase
}

// setPhase moves the run record to phase. A write that fails is logged:
// the intents of the calls the phase makes are written before each, and
// a run whose record says less than it owes is still in the store.
func (x *run) setPhase(phase uint8) {
	if x.store() == nil || !x.j.started || x.phase() == phase {
		return
	}
	if err := x.writeRun(phase, nil); err != nil {
		x.m.log.Warn("fxcm: the phase of the run was not written to the store", "set", x.r.key.String(), "run", x.r.id, "error", err)
	}
}

// intend writes the intent of a call before it is sent. It returns its key
// ("" without a Store); an error means the call must not be sent.
func (x *run) intend(c *callRecord) (string, error) {
	p := x.store()
	if p == nil {
		return "", nil
	}
	if !x.j.started {
		return "", errNoIntent(fmt.Errorf("%w: the run has no run record", errStore))
	}
	x.s.mu.Lock()
	c.Run, c.Generation, c.Fingerprint = uint64(x.r.id), x.s.gen, x.s.fp
	x.s.mu.Unlock()
	c.Folder, c.SetName = x.r.key.Folder, x.r.key.Name
	v, err := encodeRecord(c)
	if err != nil {
		return "", errNoIntent(err)
	}
	x.mu.Lock()
	x.j.n++
	k := callStoreKey(x.r.id, x.j.n)
	planned := x.j.phase == phasePlanned
	x.mu.Unlock()
	b := fxstore.Batch{Puts: map[string][]byte{k: v}}
	if planned {
		// The first intent: the run is executing from this write on.
		rv, err := encodeRecord(x.runRecord(phaseExecuting))
		if err != nil {
			return "", errNoIntent(err)
		}
		b.Puts[runStoreKey(x.r.id)] = rv
	}
	x.crashPoint("call.before-intent")
	if o, err := p.write(b, 0); o != fxstore.Committed {
		return "", errNoIntent(storeError(o, err))
	}
	x.crashPoint("call.after-intent")
	x.mu.Lock()
	x.j.intents = append(x.j.intents, k)
	if planned && x.j.phase == phasePlanned {
		x.j.phase = phaseExecuting
	}
	x.mu.Unlock()
	return k, nil
}

// crashPoint runs the crash hook of the tests.
func (x *run) crashPoint(name string) {
	if x.m != nil {
		x.m.crashPoint(name)
	}
}

// establishIntent is the intent of an EstablishConnections of req on a.
func (x *run) establishIntent(a *acRun, req *uafx.EstablishConnectionsRequest, args []*ua.Variant) *callRecord {
	c := &callRecord{Kind: callEstablish, ACNode: a.node, Namespaces: a.t.nsa}
	c.Address, c.SecurityMode, c.SecurityPolicyURI, c.ServerURIConf = a.addr.Address, uint32(a.addr.SecurityMode), a.addr.SecurityPolicyURI, a.addr.ServerURI
	c.ServerURI = a.addr.ServerURI
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
		c.FunctionalEntities = append(c.FunctionalEntities, cec.FunctionalEntityNode)
		c.AbsentBefore = append(c.AbsentBefore, absent)
		c.Preconfigured = append(c.Preconfigured, pre)
	}
	return c
}

// closeIntent is the intent of a CloseConnections of nodes on ac of addr.
func closeIntent(addr ServerAddress, ac *ua.NodeID, nsa []string, nodes []*ua.NodeID, remove bool) *callRecord {
	return &callRecord{
		Kind: callClose, ACNode: ac, Namespaces: nsa, Nodes: nodes, Remove: remove,
		Address: addr.Address, SecurityMode: uint32(addr.SecurityMode), SecurityPolicyURI: addr.SecurityPolicyURI, ServerURIConf: addr.ServerURI, ServerURI: addr.ServerURI,
	}
}

// sync completes the intents keys of calls whose results the run has
// applied: one write that deletes them and writes the endpoint records of
// the set as memory has them now and the run record (design §6.3: no
// committed state with a result but no intent, or an intent completed
// without its records). The intents of calls still in flight on other
// AutomationComponents are not among keys; the records it writes early
// are harmless, as their intents still show the outcome unknown. With end,
// every intent left is completed and the run record goes too, unless the
// run keeps it for a switch.
//
// A write that does not commit leaves the intents in the store, and the
// records it would have written that claim ownership (KnownOwned,
// TakenPreconfigured) Unresolved in memory: what the calls did is real,
// but the store cannot show it, so no later step trusts it.
func (x *run) sync(keys []string, end bool) {
	p := x.store()
	if p == nil || !x.j.started {
		return
	}
	st := p.d.State()
	b := fxstore.Batch{Puts: map[string][]byte{}}
	x.mu.Lock()
	if end {
		keys = slices.DeleteFunc(slices.Clone(x.j.intents), func(k string) bool { return x.j.lost[k] })
	}
	lost := len(x.j.lost) > 0
	x.mu.Unlock()
	b.Deletes = append(b.Deletes, keys...)
	pfx := "ep/"
	mine := map[string]bool{}
	var claimed []*record
	x.s.mu.Lock()
	for rk, rec := range x.s.records {
		k := epStoreKey(x.r.key, rk)
		mine[k] = true
		v, err := encodeRecord(storedOf(x.s, rec))
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
	x.s.mu.Unlock()
	for k, v := range st {
		if !strings.HasPrefix(k, pfx) || mine[k] {
			continue
		}
		var r epStored
		if decodeRecord(v, &r) == nil && keyString(SetKey{Folder: r.Folder, Name: r.SetName}) == keyString(x.r.key) {
			b.Deletes = append(b.Deletes, k)
		}
	}
	var err error
	if end && !x.j.keep && !lost {
		b.Deletes = append(b.Deletes, runStoreKey(x.r.id), nextStoreKey(x.r.id))
		var o fxstore.Outcome
		if o, err = p.write(b, 0); o != fxstore.Committed {
			err = storeError(o, err)
		}
	} else {
		err = x.writeRun(x.phase(), &b)
	}
	if err == nil {
		x.mu.Lock()
		x.j.intents = slices.DeleteFunc(x.j.intents, func(k string) bool { return slices.Contains(keys, k) })
		x.mu.Unlock()
		return
	}
	x.m.log.Warn("fxcm: the outcome of calls was not written to the store; their endpoints stay Unresolved", "set", x.r.key.String(), "run", x.r.id, "error", err)
	x.mu.Lock()
	if x.j.lost == nil {
		x.j.lost = map[string]bool{}
	}
	for _, k := range keys {
		x.j.lost[k] = true
	}
	x.mu.Unlock()
	x.s.mu.Lock()
	for _, rec := range claimed {
		rec.Class = Unresolved
	}
	x.s.mu.Unlock()
	x.extraFailure(Failure{FxError: uafx.FxErrorRuntimeError, Status: StatusOf(err)})
}
