// SPDX-License-Identifier: MIT

package storetest

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// flaws make a backend break one rule of the contract.
type flaws struct {
	loadErr, applyErr, closeErr, reopenErr bool
	extraKey, alias, deleteWins, noLimits  bool
	ignoreCtx, openAfterClose, forget      bool
	failConcurrent, foreignKeys, emptyLoad bool
}

// broken is a Store with flaws.
type broken struct {
	f      flaws
	mu     sync.Mutex
	m      map[string][]byte
	closed bool
	n      int
}

var errBroken = errors.New("broken")

func (b *broken) Load(ctx context.Context) (map[string][]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.f.loadErr:
		return nil, errBroken
	case b.closed && !b.f.openAfterClose:
		return nil, fxstore.ErrClosed
	case ctx.Err() != nil && !b.f.ignoreCtx:
		return nil, ctx.Err()
	case b.f.emptyLoad:
		return map[string][]byte{}, nil
	}
	out := b.m
	if !b.f.alias {
		out = maps.Clone(b.m)
		for k, v := range out {
			out[k] = append([]byte{}, v...)
		}
	}
	if out == nil {
		out = map[string][]byte{}
	}
	if b.f.extraKey {
		out["zz"] = []byte("extra")
	}
	if b.f.foreignKeys {
		out["other/x"] = []byte("x")
	}
	return out, nil
}

func (b *broken) Apply(ctx context.Context, batch fxstore.Batch) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n++
	switch {
	case b.closed && !b.f.openAfterClose:
		return fxstore.ErrClosed
	case b.f.applyErr:
		return errBroken
	case b.f.failConcurrent && b.n > 1:
		return errBroken
	case ctx.Err() != nil && !b.f.ignoreCtx:
		return fxstore.AsNotCommitted(ctx.Err())
	}
	if !b.f.noLimits {
		for k, v := range batch.Puts {
			if k == "" || len(v) > fxstore.DefaultMaxValue {
				return fxstore.AsNotCommitted(fxstore.ErrLimit)
			}
		}
	}
	if b.m == nil {
		b.m = map[string][]byte{}
	}
	put := func() {
		for k, v := range batch.Puts {
			if !b.f.alias {
				v = append([]byte{}, v...)
			}
			b.m[k] = v
		}
	}
	del := func() {
		for _, k := range batch.Deletes {
			delete(b.m, k)
		}
	}
	if b.f.deleteWins {
		put()
		del()
	} else {
		del()
		put()
	}
	return nil
}

func (b *broken) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.f.closeErr {
		return errBroken
	}
	return nil
}

func (b *broken) reopen() (fxstore.Store, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.f.reopenErr {
		return nil, errBroken
	}
	b.closed = false
	if b.f.forget {
		b.m = nil
	}
	return b, nil
}

func runChecks(f flaws) (failed []string) {
	for _, c := range checks {
		b := &broken{f: f}
		if err := c.run(context.Background(), b, b.reopen); err != nil {
			failed = append(failed, c.name)
		}
	}
	return failed
}

// TestChecksCatchFlaws: a backend that keeps the contract passes every
// check, and each flaw makes at least one fail.
func TestChecksCatchFlaws(t *testing.T) {
	t.Parallel()
	if failed := runChecks(flaws{}); len(failed) != 0 {
		t.Fatalf("a correct backend fails %v", failed)
	}
	for name, f := range map[string]flaws{
		"load error": {loadErr: true}, "apply error": {applyErr: true}, "close error": {closeErr: true},
		"reopen error": {reopenErr: true}, "extra key": {extraKey: true}, "aliases": {alias: true},
		"delete wins": {deleteWins: true}, "no limits": {noLimits: true}, "ignores the context": {ignoreCtx: true},
		"open after close": {openAfterClose: true}, "forgets": {forget: true}, "one apply only": {failConcurrent: true},
		"foreign keys": {foreignKeys: true}, "loads nothing": {emptyLoad: true},
	} {
		if failed := runChecks(f); len(failed) == 0 {
			t.Errorf("%s: no check fails", name)
		}
	}
}

// TestRunSkipsWithoutReopen: the durable check is skipped for a backend
// without reopen.
func TestRunSkipsWithoutReopen(t *testing.T) {
	t.Parallel()
	Run(t, func(t *testing.T) (fxstore.Store, func() (fxstore.Store, error)) { return &fxstore.MemoryStore{}, nil })
}
