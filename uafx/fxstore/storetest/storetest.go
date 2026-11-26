// SPDX-License-Identifier: MIT

// Package storetest checks a backend against the contract of fxstore.Store
// (docs/design/uafx-persistent-connections.md §3), and injects faults into
// one for the tests of the protocols built on it.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// Open opens the backend under test. Each call of a test gets a fresh
// backend; reopen, when not nil, opens the same backend again after Close
// (for a durable one).
type Open func(t *testing.T) (s fxstore.Store, reopen func() (fxstore.Store, error))

// Run runs the contract tests against the backend open returns.
func Run(t *testing.T, open Open) {
	t.Helper()
	ctx := context.Background()
	t.Run("empty", func(t *testing.T) {
		s, _ := open(t)
		defer s.Close()
		st, err := s.Load(ctx)
		if err != nil || len(st) != 0 {
			t.Fatalf("Load of a new store = %v, %v; want empty", st, err)
		}
	})
	t.Run("apply and load", func(t *testing.T) {
		s, _ := open(t)
		defer s.Close()
		mustApply(t, s, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1"), "b": []byte("2"), "c": {}}})
		mustApply(t, s, fxstore.Batch{Puts: map[string][]byte{"b": []byte("3")}, Deletes: []string{"a", "missing"}})
		want(t, s, map[string][]byte{"b": []byte("3"), "c": {}})
	})
	t.Run("put wins over delete", func(t *testing.T) {
		s, _ := open(t)
		defer s.Close()
		mustApply(t, s, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1")}, Deletes: []string{"a"}})
		want(t, s, map[string][]byte{"a": []byte("1")})
	})
	t.Run("caller owns its maps", func(t *testing.T) {
		s, _ := open(t)
		defer s.Close()
		v := []byte("1")
		mustApply(t, s, fxstore.Batch{Puts: map[string][]byte{"a": v}})
		v[0] = 'x'
		st, err := s.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		st["a"][0] = 'y'
		want(t, s, map[string][]byte{"a": []byte("1")})
	})
	t.Run("limits are not committed", func(t *testing.T) {
		s, _ := open(t)
		defer s.Close()
		mustApply(t, s, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1")}})
		err := s.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"b": make([]byte, fxstore.DefaultMaxValue+1)}})
		if fxstore.OutcomeOf(err) != fxstore.NotCommitted || !errors.Is(err, fxstore.ErrLimit) {
			t.Fatalf("oversized value: %v; want not committed, ErrLimit", err)
		}
		err = s.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"": []byte("1")}})
		if fxstore.OutcomeOf(err) != fxstore.NotCommitted {
			t.Fatalf("empty key: %v; want not committed", err)
		}
		want(t, s, map[string][]byte{"a": []byte("1")})
	})
	t.Run("cancelled context", func(t *testing.T) {
		s, _ := open(t)
		defer s.Close()
		c, cancel := context.WithCancel(ctx)
		cancel()
		if err := s.Apply(c, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1")}}); fxstore.OutcomeOf(err) != fxstore.NotCommitted {
			t.Fatalf("Apply with a cancelled context: %v; want not committed", err)
		}
		if _, err := s.Load(c); err == nil {
			t.Fatal("Load with a cancelled context succeeded")
		}
		want(t, s, map[string][]byte{})
	})
	t.Run("concurrent applies", func(t *testing.T) {
		s, _ := open(t)
		defer s.Close()
		var wg sync.WaitGroup
		for i := range 16 {
			wg.Go(func() {
				if err := s.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{fmt.Sprint(i): {byte(i)}}}); err != nil {
					t.Errorf("Apply %d: %v", i, err)
				}
			})
		}
		wg.Wait()
		st, err := s.Load(ctx)
		if err != nil || len(st) != 16 {
			t.Fatalf("after 16 concurrent applies: %d keys, %v", len(st), err)
		}
	})
	t.Run("closed", func(t *testing.T) {
		s, _ := open(t)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(ctx); !errors.Is(err, fxstore.ErrClosed) {
			t.Fatalf("Load after Close: %v", err)
		}
		if err := s.Apply(ctx, fxstore.Batch{}); !errors.Is(err, fxstore.ErrClosed) || fxstore.OutcomeOf(err) != fxstore.NotCommitted {
			t.Fatalf("Apply after Close: %v", err)
		}
	})
	t.Run("reopen keeps the state", func(t *testing.T) {
		s, reopen := open(t)
		if reopen == nil {
			s.Close()
			t.Skip("the backend is not durable")
		}
		mustApply(t, s, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1")}})
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s2, err := reopen()
		if err != nil {
			t.Fatal(err)
		}
		defer s2.Close()
		want(t, s2, map[string][]byte{"a": []byte("1")})
	})
	t.Run("domain", func(t *testing.T) {
		s, _ := open(t)
		defer s.Close()
		d, err := fxstore.OpenDomain(ctx, s, fxstore.DomainOptions{Namespace: "ac", Owner: "urn:test", Schema: 1})
		if err != nil {
			t.Fatal(err)
		}
		if o, err := d.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"ep/1": []byte("x")}}); o != fxstore.Committed {
			t.Fatalf("Domain.Apply: %v, %v", o, err)
		}
		st, err := s.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for k := range st {
			if !strings.HasPrefix(k, "ac/") {
				t.Fatalf("key %q outside the namespace", k)
			}
		}
		d2, err := fxstore.OpenDomain(ctx, s, fxstore.DomainOptions{Namespace: "ac", Owner: "urn:test", Schema: 1})
		if err != nil {
			t.Fatal(err)
		}
		if got := d2.State(); !bytes.Equal(got["ep/1"], []byte("x")) || len(got) != 1 {
			t.Fatalf("reloaded domain: %v", got)
		}
	})
}

func mustApply(t *testing.T, s fxstore.Store, b fxstore.Batch) {
	t.Helper()
	if err := s.Apply(context.Background(), b); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func want(t *testing.T, s fxstore.Store, w map[string][]byte) {
	t.Helper()
	st, err := s.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(st) != len(w) {
		t.Fatalf("Load = %d keys %v; want %v", len(st), st, w)
	}
	for k, v := range w {
		if got, ok := st[k]; !ok || !bytes.Equal(got, v) {
			t.Fatalf("key %q = %q, %v; want %q", k, got, ok, v)
		}
	}
}

// Fault is what an injected failure does.
type Fault uint8

const (
	// FailNotCommitted: Apply writes nothing and returns ErrNotCommitted.
	FailNotCommitted Fault = iota + 1
	// FailLost: Apply writes nothing and returns an unknown outcome.
	FailLost
	// FailApplied: Apply writes the batch and returns an unknown outcome.
	FailApplied
	// FailLoad: Load returns an error.
	FailLoad
)

// ErrInjected is the error of an injected unknown outcome or Load failure.
var ErrInjected = errors.New("storetest: injected fault")

// Faulty wraps a Store and fails its Applies and Loads as queued.
type Faulty struct {
	fxstore.Store

	mu     sync.Mutex
	applys []Fault
	loads  int
	// OnApply, when set, runs before each Apply with its batch.
	OnApply func(b fxstore.Batch)
	n       int
}

// NewFaulty wraps s.
func NewFaulty(s fxstore.Store) *Faulty { return &Faulty{Store: s} }

// FailApply queues faults for the next Applies, one each.
func (f *Faulty) FailApply(faults ...Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applys = append(f.applys, faults...)
}

// FailLoads makes the next n Loads fail.
func (f *Faulty) FailLoads(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads += n
}

// Applies returns the number of Applies so far.
func (f *Faulty) Applies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

// Apply applies b unless a fault is queued.
func (f *Faulty) Apply(ctx context.Context, b fxstore.Batch) error {
	f.mu.Lock()
	f.n++
	var fault Fault
	if len(f.applys) > 0 {
		fault, f.applys = f.applys[0], f.applys[1:]
	}
	hook := f.OnApply
	f.mu.Unlock()
	if hook != nil {
		hook(b)
	}
	switch fault {
	case FailNotCommitted:
		return fxstore.AsNotCommitted(ErrInjected)
	case FailLost:
		return ErrInjected
	case FailApplied:
		if err := f.Store.Apply(ctx, b); err != nil {
			return err
		}
		return ErrInjected
	}
	return f.Store.Apply(ctx, b)
}

// Load loads unless a Load failure is queued.
func (f *Faulty) Load(ctx context.Context) (map[string][]byte, error) {
	f.mu.Lock()
	fail := f.loads > 0
	if fail {
		f.loads--
	}
	f.mu.Unlock()
	if fail {
		return nil, ErrInjected
	}
	return f.Store.Load(ctx)
}
