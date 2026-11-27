// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"slices"
	"strings"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The owed work of a set (design docs/design/uafx-persistent-connections.md
// §6.3), done by the first step of its next Process or Reconcile: the
// verification of its records and the resolution of its unended calls
// (verifyRun), the set-wide rollback of a run that aborted or was executing
// with RollbackOnError TRUE (§6.7.3.2), and the end of the run records whose
// work is done. A set change (Replace, Remove, complete Update) whose closes
// were interrupted is completed by a Reconcile only: its closes, then its
// switch (completeSetChange). Nothing is resent: a call whose outcome is
// unknown is re-proved (§6.5), and what stays Unverified or Unresolved is
// never closed.

// owedOfSet returns the owed work of the set key.
func (p *persistence) owedOfSet(key SetKey) []OwedWork {
	p.owedMu.Lock()
	defer p.owedMu.Unlock()
	return slices.Clone(p.owed[keyString(key)])
}

// recover is the first step of a run with a Store. It reports whether the
// action of the run may proceed: not when the owed rollback did not finish
// or the end of the owed work was not written (the obligations stay, and
// the run ends in Error). The servers on which an intent of the set is
// still unresolved after the verification are blocked for the run
// (x.blocked): no call of the run reaches them, the owed rollback's
// included, until the outcome is proven or Settle decides it.
func (x *run) recover(ctx context.Context) bool {
	p := x.store()
	if p == nil {
		return true
	}
	x.verifyRun(ctx)
	x.blocked = p.unresolvedOn(x.r.key, x.r.id)
	owed := p.owedOfSet(x.r.key)
	ok := true
	if slices.ContainsFunc(owed, func(w OwedWork) bool { return w.Kind == OwedRollback }) {
		ok = x.owedRollback(ctx, owed)
	}
	if !x.endOwedRuns(owed) {
		ok = false
	}
	if !ok {
		x.m.log.Warn("fxcm: the owed work of the set was not done; the action of the run does not run", "set", x.r.key.String(), "run", x.r.id)
		x.extraFailure(Failure{FxError: uafx.FxErrorRuntimeError, Status: ua.StatusBadInvalidState})
	}
	return ok
}

// failBlocked fails the endpoints of the run on a blocked server (recover)
// and reports whether there was one.
func (x *run) failBlocked() bool {
	any := false
	for _, ep := range x.eps {
		if x.blocked[x.cfg.serverAddress(ep.e.ac.server).Address] {
			x.fail(ep, Failure{FxError: uafx.FxErrorRuntimeError, Status: ua.StatusBadInvalidState})
			any = true
		}
	}
	return any
}

// blockedFailure is the failure of a call the run does not send to a
// blocked server.
func blockedFailure(fx uafx.FxError, addr ServerAddress) error {
	return failure(fx, ua.StatusBadInvalidState, "a call of the set on %s has an unknown outcome: nothing is sent there until it is proven or settled", addr.Address)
}

// owedRollback is the rollback the runs of owed owe (§6.7.3.2, CR-4): every
// closable endpoint of the set is closed with Remove TRUE, as the rollback
// of C2 closes them. It is done before the action of the run; a close that
// fails fails the run, and the rollback stays owed. It reports whether
// every close succeeded.
func (x *run) owedRollback(ctx context.Context, owed []OwedWork) bool {
	x.crashPoint("recover.rollback")
	recs, _ := x.closable()
	if len(recs) == 0 {
		return true
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), x.m.opts.RollbackTimeout)
	defer cancel()
	errs := x.closeRecords(rctx, recs, true)
	for _, r := range recs {
		if err := errs[r]; err != nil {
			if ep := x.epOf(r.Endpoint); ep != nil && r.Name == ep.e.conf.Name {
				x.failErr(ep, err, uafx.FxErrorCloseConnectionError)
			} else {
				x.extraFailure(failureOf(err, uafx.FxErrorCloseConnectionError))
			}
		}
	}
	x.m.log.Info("fxcm: the owed rollback closed the endpoints of the set", "set", x.r.key.String(), "run", x.r.id, "closed", len(recs)-len(errs), "failed", len(errs))
	return len(errs) == 0
}

// endOwedRuns deletes the run records of owed whose work is done: none of
// their intents is left, and for a rollback no record of the set may still
// be closed or decided (KnownOwned, TakenPreconfigured, Unverified,
// Unresolved of that run). A set change is completeSetChange's. It reports
// false when the write of the end failed.
func (x *run) endOwedRuns(owed []OwedWork) bool {
	p := x.store()
	var ends []RunID
	for _, w := range owed {
		switch w.Kind {
		case OwedRollback, OwedReconcile:
			if !slices.Contains(ends, w.Run) {
				ends = append(ends, w.Run)
			}
		case OwedSetChange, OwedCall:
		}
	}
	if len(ends) == 0 {
		return true
	}
	unlock := p.lockJournal(x.s)
	defer unlock()
	st := p.d.State()
	var b fxstore.Batch
	for _, id := range ends {
		if hasIntents(st, id) {
			continue
		}
		rollback := slices.ContainsFunc(owed, func(w OwedWork) bool { return w.Run == id && w.Kind == OwedRollback })
		if rollback && slices.ContainsFunc(mapValues(x.s.records), func(r *record) bool {
			return r.Run == id || r.Class == Unverified || r.Class.MayClose()
		}) {
			continue
		}
		b.Deletes = append(b.Deletes, runStoreKey(id), txStoreKey(id))
	}
	if len(b.Deletes) == 0 {
		return true
	}
	if o, err := p.apply(b, 0); o != fxstore.Committed {
		err = storeError(o, err)
		x.m.log.Warn("fxcm: the end of the owed work was not written to the store; it stays owed", "set", x.r.key.String(), "run", x.r.id, "error", err)
		x.extraFailure(failureOf(err, uafx.FxErrorRuntimeError))
		return false
	}
	return true
}

// hasIntents reports whether the state st holds an intent of the run id.
func hasIntents(st map[string][]byte, id RunID) bool {
	pfx := strings.TrimSuffix(callStoreKey(id, 1), "1")
	for k := range st {
		if strings.HasPrefix(k, pfx) {
			return true
		}
	}
	return false
}

func mapValues[K comparable, V any](m map[K]V) []V {
	out := make([]V, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// completeSetChange completes the set change the set owes, after the
// Reconcile run closed its Connections (§6.2, F.3.3.2): when the run did
// not fail, no record of the set is left and no intent of the run that
// owes it is unresolved, every operation of the change is written in one
// write with the end of that run, and then made in memory. A participant
// that is processed, held or edited, or a key an Add of the change takes
// that is in use, refuses it with Bad_InvalidState: the change stays owed.
func (x *run) completeSetChange() {
	p := x.store()
	if p == nil {
		return
	}
	var w *OwedWork
	for _, o := range p.owedOfSet(x.r.key) {
		if o.Kind == OwedSetChange {
			w = &o
			break
		}
	}
	if w == nil {
		return
	}
	x.mu.Lock()
	failed := len(x.res.Failures) > 0 || slices.ContainsFunc(x.eps, func(ep *epRun) bool { return ep.outcome != nil && ep.outcome.Kind == Failed })
	x.mu.Unlock()
	x.s.mu.Lock()
	left := len(x.s.records)
	x.s.mu.Unlock()
	st := p.d.State()
	l := decodeState(st)
	tx := l.txs[txStoreKey(w.Run)]
	refuse := func(format string, args ...any) {
		x.m.log.Warn("fxcm: the owed set change was not completed", "set", x.r.key.String(), "run", w.Run, "why", managerError(ua.StatusBadInvalidState, format, args...))
		x.extraFailure(Failure{FxError: uafx.FxErrorRuntimeError, Status: ua.StatusBadInvalidState})
	}
	switch {
	case failed:
		return // the failures of the run say why
	case left > 0:
		refuse("%d endpoint records of the set are left", left)
		return
	case hasIntents(st, w.Run):
		refuse("an intent of run %d is unresolved", w.Run)
		return
	case tx == nil:
		refuse("the set change of run %d is not in the store", w.Run)
		return
	}
	m := x.m
	cs := make([]setChange, len(tx.Ops))
	var held []*set
	release := func() {
		for _, s := range held {
			m.release(s)
		}
	}
	m.mu.Lock()
	for i, o := range tx.Ops {
		key := SetKey{Folder: o.Folder, Name: o.Name}
		op := uafx.ConnectionConfigurationSetOperation(o.Op)
		c := setChange{key: key, existing: op != uafx.ElementAdd, gen: o.New}
		if op != uafx.ElementRemove {
			conf, err := decodeConf(o.Conf)
			var cfg *Config
			if err == nil {
				cfg, err = newConfig(conf, o.Version)
			}
			if err != nil {
				m.mu.Unlock()
				release()
				refuse("the configuration of %s in the set change: %v", key, err)
				return
			}
			c.next = cfg
		}
		s := m.sets[keyString(key)]
		switch {
		case op == uafx.ElementAdd && (s != nil || m.reserved[keyString(key)]):
			m.mu.Unlock()
			release()
			refuse("the set %s the change adds exists", key)
			return
		case op != uafx.ElementAdd && s == nil:
			m.mu.Unlock()
			release()
			refuse("the set %s the change replaces or removes is gone", key)
			return
		case op != uafx.ElementAdd && s != x.s:
			s.mu.Lock()
			busy := s.current != nil || s.held || s.edit.Editing() != nil || len(s.records) > 0
			if !busy {
				s.held = true
				held = append(held, s)
			}
			s.mu.Unlock()
			if busy {
				m.mu.Unlock()
				release()
				refuse("the set %s of the change is processed, held, edited or has endpoints", key)
				return
			}
		}
		cs[i] = c
	}
	m.mu.Unlock()
	x.crashPoint("recover.before-switch")
	gens, fps, err := p.switchSets(cs, []RunID{w.Run})
	if err != nil {
		release()
		x.extraFailure(failureOf(err, uafx.FxErrorRuntimeError))
		return
	}
	var events []Event
	m.mu.Lock()
	for i, c := range cs {
		ks := keyString(c.key)
		switch {
		case c.next == nil:
			s := m.sets[ks]
			delete(m.sets, ks)
			s.mu.Lock()
			s.removed = true
			if s != x.s {
				s.current, s.held = nil, false
			}
			s.mu.Unlock()
			events = append(events, Event{Kind: EventSetRemoved, Set: c.key})
		case !c.existing:
			ns := newSet(c.next)
			ns.gen, ns.fp = gens[i], fps[i]
			m.sets[ks] = ns
			events = append(events, Event{Kind: EventSetAdded, Set: c.key, Version: c.next.version})
		default:
			s := m.sets[ks]
			s.mu.Lock()
			s.cfg, s.diags, s.records, s.lastEstablish, s.retries = c.next, newDiagnostics(c.next), map[string]*record{}, nil, 0
			s.gen, s.fp = gens[i], fps[i]
			if s != x.s {
				s.state, s.held = StateReady, false
			}
			s.mu.Unlock()
			events = append(events, Event{Kind: EventSetReplaced, Set: c.key, Version: c.next.version})
		}
	}
	m.mu.Unlock()
	m.log.Info("fxcm: the owed set change was completed", "set", x.r.key.String(), "run", w.Run, "operations", len(cs))
	for _, e := range events {
		m.observe(e)
	}
}
