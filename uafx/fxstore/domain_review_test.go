// SPDX-License-Identifier: MIT

package fxstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// notFenced fails unless d is unfenced and owes nothing.
func notFenced(t *testing.T, d *fxstore.Domain) {
	t.Helper()
	if st := d.Status(); st.Fenced || st.Required != 0 || st.Unresolved != nil {
		t.Fatalf("Status = %+v; want not fenced", st)
	}
}

// TestDomainRequirePermanent: a Require that can never commit is not owed
// and does not fence the domain, fenced or not.
func TestDomainRequirePermanent(t *testing.T) {
	ctx := context.Background()
	limited := func(t *testing.T, s fxstore.Store, l fxstore.Limits) *fxstore.Domain {
		t.Helper()
		o := opts
		o.Limits = l
		d, err := fxstore.OpenDomain(ctx, s, o)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	for _, c := range []struct {
		name  string
		store fxstore.Store
		lim   fxstore.Limits
		pre   fxstore.Batch
		b     fxstore.Batch
		want  error
	}{
		{"delete of meta", &fxstore.MemoryStore{}, fxstore.Limits{}, fxstore.Batch{}, fxstore.Batch{Deletes: []string{"meta"}}, fxstore.ErrInvalidKey},
		{"empty put key", &fxstore.MemoryStore{}, fxstore.Limits{}, fxstore.Batch{}, put("", "x"), fxstore.ErrInvalidKey},
		{"domain MaxKeys", &fxstore.MemoryStore{}, fxstore.Limits{MaxKeys: 2}, put("a", "1"), put("b", "1"), fxstore.ErrLimit},
		{"store MaxValue", &fxstore.MemoryStore{Limits: fxstore.Limits{MaxValue: 100}}, fxstore.Limits{}, fxstore.Batch{},
			fxstore.Batch{Puts: map[string][]byte{"big": make([]byte, 200)}}, fxstore.ErrLimit},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := limited(t, c.store, c.lim)
			if !c.pre.Empty() {
				apply(t, d, c.pre, fxstore.Committed)
			}
			o, err := d.Require(ctx, c.b)
			if o != fxstore.NotCommitted || !errors.Is(err, c.want) || !errors.Is(err, fxstore.ErrNotCommitted) {
				t.Fatalf("Require = %v, %v; want not committed, %v", o, err, c.want)
			}
			notFenced(t, d)
			if ok, err := d.Settle(ctx); !ok || err != nil {
				t.Fatalf("Settle = %v, %v", ok, err)
			}
			apply(t, d, fxstore.Batch{Deletes: []string{"a"}}, fxstore.Committed)
		})
	}
	t.Run("while fenced", func(t *testing.T) {
		f := storetest.NewFaulty(&fxstore.MemoryStore{})
		d := limited(t, f, fxstore.Limits{MaxKeys: 3})
		f.FailApply(storetest.FailNotCommitted)
		if o, _ := d.Require(ctx, put("a", "1")); o != fxstore.NotCommitted {
			t.Fatalf("Require = %v", o)
		}
		for _, c := range []struct {
			b    fxstore.Batch
			want error
		}{
			{fxstore.Batch{Deletes: []string{"meta"}}, fxstore.ErrInvalidKey},
			{put("", "x"), fxstore.ErrInvalidKey},
			// meta + a (owed) + b + c is over 3 keys.
			{fxstore.Batch{Puts: map[string][]byte{"b": nil, "c": nil}}, fxstore.ErrLimit},
		} {
			if o, err := d.Require(ctx, c.b); o != fxstore.NotCommitted || !errors.Is(err, c.want) || errors.Is(err, fxstore.ErrFenced) {
				t.Fatalf("Require(%v) while fenced = %v, %v; want %v", c.b, o, err, c.want)
			}
		}
		if st := d.Status(); st.Required != 1 {
			t.Fatalf("Status = %+v; want the valid write owed only", st)
		}
		if ok, err := d.Settle(ctx); !ok || err != nil {
			t.Fatalf("Settle = %v, %v", ok, err)
		}
		notFenced(t, d)
		if st := d.State(); len(st) != 1 || string(st["a"]) != "1" {
			t.Fatalf("State = %v", st)
		}
	})
}

// TestDomainSettleDropsPermanent: a required write that turns out never to
// commit when Settle writes it is dropped, not retried for ever.
func TestDomainSettleDropsPermanent(t *testing.T) {
	ctx := context.Background()
	t.Run("the unresolved write grew the state", func(t *testing.T) {
		f := storetest.NewFaulty(&fxstore.MemoryStore{})
		o := opts
		o.Limits = fxstore.Limits{MaxKeys: 2}
		d, err := fxstore.OpenDomain(ctx, f, o)
		if err != nil {
			t.Fatal(err)
		}
		f.FailApply(storetest.FailApplied)
		apply(t, d, put("a", "1"), fxstore.Unknown)
		// Owed against the state before a: meta + b.
		if o, err := d.Require(ctx, put("b", "1")); o != fxstore.NotCommitted || !errors.Is(err, fxstore.ErrFenced) {
			t.Fatalf("Require = %v, %v", o, err)
		}
		// a committed: meta + a + b is over the limit.
		if ok, err := d.Settle(ctx); ok || !errors.Is(err, fxstore.ErrLimit) {
			t.Fatalf("Settle = %v, %v; want false, ErrLimit", ok, err)
		}
		if ok, err := d.Settle(ctx); !ok || err != nil {
			t.Fatalf("Settle = %v, %v", ok, err)
		}
		notFenced(t, d)
		apply(t, d, fxstore.Batch{Deletes: []string{"a"}}, fxstore.Committed)
	})
	t.Run("the store refuses a lost required write", func(t *testing.T) {
		f := storetest.NewFaulty(&fxstore.MemoryStore{Limits: fxstore.Limits{MaxValue: 100}})
		d := open(t, f)
		f.FailApply(storetest.FailLost)
		if o, _ := d.Require(ctx, fxstore.Batch{Puts: map[string][]byte{"big": make([]byte, 200)}}); o != fxstore.Unknown {
			t.Fatalf("Require = %v", o)
		}
		if ok, err := d.Settle(ctx); ok || !errors.Is(err, fxstore.ErrLimit) {
			t.Fatalf("Settle = %v, %v; want false, ErrLimit", ok, err)
		}
		if ok, err := d.Settle(ctx); !ok || err != nil {
			t.Fatalf("Settle = %v, %v", ok, err)
		}
		notFenced(t, d)
	})
}

// TestDomainRequireCopiesBatch: a caller that reuses its batch after
// Require does not change the owed write.
func TestDomainRequireCopiesBatch(t *testing.T) {
	ctx := context.Background()
	for _, fault := range []storetest.Fault{storetest.FailNotCommitted, storetest.FailLost} {
		f := storetest.NewFaulty(&fxstore.MemoryStore{})
		d := open(t, f)
		apply(t, d, put("x", "0"), fxstore.Committed)
		v := []byte("1")
		b := fxstore.Batch{Puts: map[string][]byte{"a": v}, Deletes: []string{"x"}}
		f.FailApply(fault)
		if o, _ := d.Require(ctx, b); o == fxstore.Committed {
			t.Fatalf("Require = %v", o)
		}
		v[0] = '9'
		b.Puts["z"] = []byte("z")
		b.Deletes[0] = "a"
		if ok, err := d.Settle(ctx); !ok || err != nil {
			t.Fatalf("Settle = %v, %v", ok, err)
		}
		if st := d.State(); len(st) != 1 || string(st["a"]) != "1" {
			t.Fatalf("fault %v: State = %q; want only a=1", fault, st)
		}
	}
}

// TestDomainReadsDuringSlowWrite: State, Status and Schema do not wait for
// a backend Apply in progress (design §3.5).
func TestDomainReadsDuringSlowWrite(t *testing.T) {
	ctx := context.Background()
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	d := open(t, f)
	apply(t, d, put("a", "1"), fxstore.Committed)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	f.OnApply = func(fxstore.Batch) {
		entered <- struct{}{}
		<-release
	}
	reads := func(what string, rev uint64, fenced bool) {
		t.Helper()
		done := make(chan struct{})
		var st map[string][]byte
		var s fxstore.DomainStatus
		go func() {
			defer close(done)
			st, s = d.State(), d.Status()
			_ = d.Schema()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatalf("%s: State and Status wait for the store", what)
		}
		if string(st["a"]) != "1" || s.Revision != rev || s.Fenced != fenced {
			t.Fatalf("%s: State = %q, Status = %+v", what, st, s)
		}
	}
	run := func(fn func()) chan struct{} {
		done := make(chan struct{})
		go func() { defer close(done); fn() }()
		<-entered
		return done
	}
	// An Apply in progress.
	f.FailApply(storetest.FailLost)
	done := run(func() { _, _ = d.Apply(ctx, put("a", "2")) })
	reads("Apply", 1, false)
	release <- struct{}{}
	<-done
	// A confirming Apply of Settle in progress.
	done = run(func() { _, _ = d.Settle(ctx) })
	reads("Settle", 1, true)
	release <- struct{}{}
	<-done
	f.OnApply = nil
	notFenced(t, d)
	// What State and Status return belongs to the caller.
	st := d.State()
	st["a"][0] = 'x'
	st["new"] = nil
	if got := d.State(); len(got) != 1 || string(got["a"]) != "1" {
		t.Fatalf("State after the caller changed its copy = %q", got)
	}
}

// TestDomainStatusCopies: the UnresolvedWrite of a Status belongs to the
// caller.
func TestDomainStatusCopies(t *testing.T) {
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	d := open(t, f)
	f.FailApply(storetest.FailLost)
	apply(t, d, put("a", "1"), fxstore.Unknown)
	st := d.Status()
	st.Unresolved.Attempts = 99
	if got := d.Status(); got.Unresolved == nil || got.Unresolved.Attempts != 0 {
		t.Fatalf("Status = %+v", got.Unresolved)
	}
}
