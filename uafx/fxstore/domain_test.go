// SPDX-License-Identifier: MIT

package fxstore_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

var opts = fxstore.DomainOptions{Namespace: "ac", Owner: "urn:ac", Schema: 1}

func open(t *testing.T, s fxstore.Store) *fxstore.Domain {
	t.Helper()
	d, err := fxstore.OpenDomain(context.Background(), s, opts)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func put(k, v string) fxstore.Batch { return fxstore.Batch{Puts: map[string][]byte{k: []byte(v)}} }

func apply(t *testing.T, d *fxstore.Domain, b fxstore.Batch, want fxstore.Outcome) {
	t.Helper()
	if o, err := d.Apply(context.Background(), b); o != want {
		t.Fatalf("Apply = %v, %v; want %v", o, err, want)
	}
}

func TestDomainOpen(t *testing.T) {
	ctx := context.Background()
	m := &fxstore.MemoryStore{}
	if _, err := fxstore.OpenDomain(ctx, nil, opts); err == nil {
		t.Error("OpenDomain without a store")
	}
	if _, err := fxstore.OpenDomain(ctx, m, fxstore.DomainOptions{Namespace: "a/b"}); err == nil {
		t.Error("OpenDomain with a slash in the namespace")
	}
	d := open(t, m)
	apply(t, d, put("ep/1", "x"), fxstore.Committed)
	if d.Schema() != 1 {
		t.Errorf("Schema = %d", d.Schema())
	}
	if _, err := fxstore.OpenDomain(ctx, m, fxstore.DomainOptions{Namespace: "ac", Owner: "urn:other", Schema: 1}); !errors.Is(err, fxstore.ErrForeignOwner) {
		t.Errorf("foreign owner: %v", err)
	}
	if _, err := fxstore.OpenDomain(ctx, m, fxstore.DomainOptions{Namespace: "ac", Owner: "urn:ac", Schema: 0}); !errors.Is(err, fxstore.ErrSchema) {
		t.Errorf("newer schema: %v", err)
	}
	if _, err := fxstore.OpenDomain(ctx, m, fxstore.DomainOptions{Namespace: "cm", Owner: "urn:ac", Schema: 1}); err == nil {
		t.Error("keys of another namespace accepted")
	}
	f := storetest.NewFaulty(m)
	f.FailLoads(1)
	if _, err := fxstore.OpenDomain(ctx, f, opts); err == nil {
		t.Error("failed Load accepted")
	}
	for name, st := range map[string]map[string][]byte{
		"no meta":      {"ac/ep/1": []byte("x")},
		"corrupt meta": {"ac/meta": []byte{1, 2}},
		"newer meta":   {"ac/meta": []byte{9, 0, 0, 0, 0, 0, 0}},
		"meta length":  {"ac/meta": []byte{1, 1, 0, 200, 0, 0, 0, 1}},
		"oversized":    {"ac/meta": make([]byte, fxstore.DefaultMaxValue+1)},
	} {
		s := &fxstore.MemoryStore{}
		if err := s.Apply(ctx, fxstore.Batch{Puts: st}); err != nil && name != "oversized" {
			t.Fatal(err)
		}
		if name == "oversized" {
			s = &fxstore.MemoryStore{Limits: fxstore.Limits{MaxValue: 1 << 30}}
			_ = s.Apply(ctx, fxstore.Batch{Puts: st})
		}
		if _, err := fxstore.OpenDomain(ctx, s, opts); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestDomainApply(t *testing.T) {
	ctx := context.Background()
	m := &fxstore.MemoryStore{}
	d := open(t, m)
	apply(t, d, put("ep/1", "x"), fxstore.Committed)
	apply(t, d, fxstore.Batch{Puts: map[string][]byte{"ep/2": []byte("y")}, Deletes: []string{"ep/1"}}, fxstore.Committed)
	if st := d.State(); len(st) != 1 || string(st["ep/2"]) != "y" {
		t.Fatalf("State = %v", st)
	}
	if st := d.Status(); st.Revision != 2 || st.Fenced {
		t.Fatalf("Status = %+v", st)
	}
	for _, b := range []fxstore.Batch{put("meta", "x"), put("", "x"), {Deletes: []string{"meta"}}, {Deletes: []string{""}}} {
		apply(t, d, b, fxstore.NotCommitted)
	}
	// A put and a delete of the same key: the put wins.
	apply(t, d, fxstore.Batch{Puts: map[string][]byte{"ep/3": nil}, Deletes: []string{"ep/3"}}, fxstore.Committed)
	if _, ok := d.State()["ep/3"]; !ok {
		t.Error("the put of a deleted key is lost")
	}
	small := open(t, &fxstore.MemoryStore{})
	d2, err := fxstore.OpenDomain(ctx, &fxstore.MemoryStore{}, fxstore.DomainOptions{Namespace: "ac", Owner: "urn:ac", Schema: 1, Limits: fxstore.Limits{MaxKeys: 2}})
	if err != nil {
		t.Fatal(err)
	}
	apply(t, d2, put("a", "1"), fxstore.Committed)
	apply(t, d2, put("b", "2"), fxstore.NotCommitted) // meta + a + b
	apply(t, small, put("a", "1"), fxstore.Committed)
	d3, err := fxstore.OpenDomain(ctx, &fxstore.MemoryStore{}, fxstore.DomainOptions{Namespace: "ac", Rand: strings.NewReader("short")})
	if err != nil {
		t.Fatal(err)
	}
	apply(t, d3, put("a", "1"), fxstore.NotCommitted)
	if _, err := d3.Settle(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDomainNotCommittedDoesNotFence(t *testing.T) {
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	d := open(t, f)
	f.FailApply(storetest.FailNotCommitted)
	apply(t, d, put("a", "1"), fxstore.NotCommitted)
	apply(t, d, put("b", "2"), fxstore.Committed)
	if st := d.State(); len(st) != 1 || st["a"] != nil {
		t.Fatalf("State = %v", st)
	}
}

func TestDomainSettle(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name      string
		fault     storetest.Fault
		contained bool
	}{
		{"lost", storetest.FailLost, false},
		{"applied", storetest.FailApplied, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &fxstore.MemoryStore{}
			f := storetest.NewFaulty(m)
			d := open(t, f)
			apply(t, d, put("a", "1"), fxstore.Committed)
			f.FailApply(c.fault)
			apply(t, d, put("b", "2"), fxstore.Unknown)
			st := d.Status()
			if !st.Fenced || st.Unresolved == nil || st.Unresolved.Revision != 2 {
				t.Fatalf("Status after an unknown outcome = %+v", st)
			}
			// Fenced: a later write is refused without writing.
			n := f.Applies()
			if o, err := d.Apply(ctx, put("c", "3")); o != fxstore.NotCommitted || !errors.Is(err, fxstore.ErrFenced) {
				t.Fatalf("Apply while fenced = %v, %v", o, err)
			}
			if f.Applies() != n {
				t.Fatal("a fenced Apply wrote")
			}
			if _, ok := d.State()["b"]; ok {
				t.Fatal("State shows an unresolved write")
			}
			ok, err := d.Settle(ctx)
			if !ok || err != nil {
				t.Fatalf("Settle = %v, %v", ok, err)
			}
			_, has := d.State()["b"]
			if has != c.contained {
				t.Fatalf("after Settle, b present = %v; want %v", has, c.contained)
			}
			apply(t, d, put("c", "3"), fxstore.Committed)
			if st := d.Status(); st.Fenced || st.Revision <= 2 {
				t.Fatalf("Status after Settle = %+v", st)
			}
			// The store agrees with the domain.
			d2 := open(t, m)
			if len(d2.State()) != len(d.State()) {
				t.Fatalf("reloaded %v; domain %v", d2.State(), d.State())
			}
		})
	}
}

// TestDomainRepeatedConfirmations: the confirming writes are ambiguous
// too, several times; the domain keeps the identity and the evidence of
// the original write and settles it right in the end (acceptance criterion
// of C3.1).
func TestDomainRepeatedConfirmations(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name      string
		original  storetest.Fault
		confirms  []storetest.Fault
		contained bool
	}{
		{"applied, confirmations applied", storetest.FailApplied, []storetest.Fault{storetest.FailApplied, storetest.FailApplied}, true},
		{"applied, confirmations lost", storetest.FailApplied, []storetest.Fault{storetest.FailLost, storetest.FailLost}, true},
		{"lost, confirmations applied", storetest.FailLost, []storetest.Fault{storetest.FailApplied, storetest.FailLost, storetest.FailApplied}, false},
		{"lost, mixed", storetest.FailLost, []storetest.Fault{storetest.FailLost, storetest.FailNotCommitted, storetest.FailApplied}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &fxstore.MemoryStore{}
			f := storetest.NewFaulty(m)
			d := open(t, f)
			apply(t, d, put("a", "1"), fxstore.Committed)
			f.FailApply(c.original)
			apply(t, d, put("b", "2"), fxstore.Unknown)
			batch := d.Status().Unresolved.Batch
			f.FailApply(c.confirms...)
			for range c.confirms {
				if ok, err := d.Settle(ctx); ok || err == nil {
					t.Fatalf("Settle with an ambiguous confirmation = %v, %v", ok, err)
				}
				st := d.Status()
				if st.Unresolved == nil || st.Unresolved.Batch != batch {
					t.Fatalf("the original batch is lost: %+v", st.Unresolved)
				}
			}
			if st := d.Status(); st.Unresolved.Attempts != len(c.confirms) || st.Unresolved.Err == nil {
				t.Fatalf("Status = %+v", st.Unresolved)
			}
			if ok, err := d.Settle(ctx); !ok || err != nil {
				t.Fatalf("final Settle = %v, %v", ok, err)
			}
			if _, has := d.State()["b"]; has != c.contained {
				t.Fatalf("b present = %v; want %v", has, c.contained)
			}
			d2 := open(t, m)
			if _, has := d2.State()["b"]; has != c.contained {
				t.Fatalf("reloaded: b present = %v; want %v", has, c.contained)
			}
		})
	}
}

func TestDomainSettleErrors(t *testing.T) {
	ctx := context.Background()
	m := &fxstore.MemoryStore{}
	f := storetest.NewFaulty(m)
	d := open(t, f)
	if ok, err := d.Settle(ctx); !ok || err != nil {
		t.Fatalf("Settle of a settled domain = %v, %v", ok, err)
	}
	f.FailApply(storetest.FailLost)
	apply(t, d, put("a", "1"), fxstore.Unknown)
	f.FailLoads(1)
	if ok, err := d.Settle(ctx); ok || err == nil {
		t.Fatalf("Settle with a failing Load = %v, %v", ok, err)
	}
	// Another writer changed the store: the outcome stays unknown.
	if err := m.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"ac/x": nil}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.Settle(ctx); ok || err == nil {
		t.Fatalf("Settle on a store changed behind it = %v, %v", ok, err)
	}
	if err := m.Apply(ctx, fxstore.Batch{Deletes: []string{"ac/x"}, Puts: map[string][]byte{"ac/meta": {1, 2}}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.Settle(ctx); ok || err == nil {
		t.Fatalf("Settle on a corrupt meta key = %v, %v", ok, err)
	}
	if err := m.Apply(ctx, fxstore.Batch{Deletes: []string{"ac/meta"}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.Settle(ctx); !ok || err != nil {
		t.Fatalf("Settle = %v, %v", ok, err)
	}
	// Another writer appends a batch with a meta key the domain never wrote.
	f.FailApply(storetest.FailLost)
	apply(t, d, put("b", "1"), fxstore.Unknown)
	other := open(t, m)
	apply(t, other, put("c", "1"), fxstore.Committed)
	if ok, err := d.Settle(ctx); ok || err == nil {
		t.Fatalf("Settle on a foreign batch = %v, %v", ok, err)
	}
}

func TestDomainRequire(t *testing.T) {
	ctx := context.Background()
	m := &fxstore.MemoryStore{}
	f := storetest.NewFaulty(m)
	d := open(t, f)
	if o, _ := d.Require(ctx, put("a", "1")); o != fxstore.Committed {
		t.Fatalf("Require = %v", o)
	}
	// Not committed: owed and fenced.
	f.FailApply(storetest.FailNotCommitted)
	if o, _ := d.Require(ctx, put("b", "1")); o != fxstore.NotCommitted {
		t.Fatalf("Require = %v", o)
	}
	if st := d.Status(); !st.Fenced || st.Required != 1 {
		t.Fatalf("Status = %+v", st)
	}
	// A Require while fenced is owed too.
	if o, err := d.Require(ctx, put("c", "1")); o != fxstore.NotCommitted || !errors.Is(err, fxstore.ErrFenced) {
		t.Fatalf("Require while fenced = %v, %v", o, err)
	}
	f.FailApply(storetest.FailNotCommitted)
	if ok, _ := d.Settle(ctx); ok {
		t.Fatal("Settle with a failing write succeeded")
	}
	if ok, err := d.Settle(ctx); !ok || err != nil {
		t.Fatalf("Settle = %v, %v", ok, err)
	}
	if st := d.State(); len(st) != 3 {
		t.Fatalf("State = %v", st)
	}
	// Unknown and lost: owed again after the settle.
	f.FailApply(storetest.FailLost)
	if o, _ := d.Require(ctx, put("d", "1")); o != fxstore.Unknown {
		t.Fatalf("Require = %v", o)
	}
	if ok, err := d.Settle(ctx); !ok || err != nil {
		t.Fatalf("Settle = %v, %v", ok, err)
	}
	if _, ok := d.State()["d"]; !ok {
		t.Fatal("a required write lost by an unknown outcome is not written")
	}
	// An owed write whose own retry is unknown.
	f.FailApply(storetest.FailNotCommitted)
	_, _ = d.Require(ctx, put("e", "1"))
	f.FailApply(storetest.FailLost)
	if ok, _ := d.Settle(ctx); ok {
		t.Fatal("Settle with an unknown retry succeeded")
	}
	if ok, err := d.Settle(ctx); !ok || err != nil {
		t.Fatalf("Settle = %v, %v", ok, err)
	}
	if _, ok := d.State()["e"]; !ok {
		t.Fatal("e lost")
	}
	if len(open(t, m).State()) != len(d.State()) {
		t.Fatal("store and domain differ")
	}
}

func TestDomainOnFileStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir() + "/s"
	s, err := fxstore.OpenFile(dir, fxstore.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	d := open(t, s)
	apply(t, d, put("ep/1", "x"), fxstore.Committed)
	_ = s.Close()
	s2, err := fxstore.OpenFile(dir, fxstore.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	d2 := open(t, s2)
	if string(d2.State()["ep/1"]) != "x" || d2.Status().Revision != 1 {
		t.Fatalf("reopened: %v %+v", d2.State(), d2.Status())
	}
	if ok, err := d2.Settle(ctx); !ok || err != nil {
		t.Fatal(ok, err)
	}
}
