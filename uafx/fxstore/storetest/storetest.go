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
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			s, reopen := open(t)
			if c.durable && reopen == nil {
				_ = s.Close()
				t.Skip("the backend is not durable")
			}
			if err := c.run(context.Background(), s, reopen); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// check is one contract test. run owns s: it closes it.
type check struct {
	name string
	// durable: the check needs reopen.
	durable bool
	run     func(ctx context.Context, s fxstore.Store, reopen func() (fxstore.Store, error)) error
}

var checks = []check{
	{name: "empty", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		defer closeStore(s)
		return want(ctx, s, map[string][]byte{})
	}},
	{name: "apply and load", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		defer closeStore(s)
		if err := apply(ctx, s, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1"), "b": []byte("2"), "c": {}}}); err != nil {
			return err
		}
		if err := apply(ctx, s, fxstore.Batch{Puts: map[string][]byte{"b": []byte("3")}, Deletes: []string{"a", "missing"}}); err != nil {
			return err
		}
		return want(ctx, s, map[string][]byte{"b": []byte("3"), "c": {}})
	}},
	{name: "put wins over delete", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		defer closeStore(s)
		if err := apply(ctx, s, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1")}, Deletes: []string{"a"}}); err != nil {
			return err
		}
		return want(ctx, s, map[string][]byte{"a": []byte("1")})
	}},
	{name: "caller owns its maps", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		defer closeStore(s)
		v := []byte("1")
		if err := apply(ctx, s, fxstore.Batch{Puts: map[string][]byte{"a": v}}); err != nil {
			return err
		}
		v[0] = 'x'
		st, err := s.Load(ctx)
		if err != nil {
			return fmt.Errorf("Load: %w", err)
		}
		if a := st["a"]; len(a) > 0 {
			a[0] = 'y'
		}
		return want(ctx, s, map[string][]byte{"a": []byte("1")})
	}},
	{name: "limits are not committed", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		defer closeStore(s)
		if err := apply(ctx, s, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1")}}); err != nil {
			return err
		}
		err := s.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"b": make([]byte, fxstore.DefaultMaxValue+1)}})
		if fxstore.OutcomeOf(err) != fxstore.NotCommitted || !errors.Is(err, fxstore.ErrLimit) {
			return fmt.Errorf("oversized value: %v; want not committed, ErrLimit", err)
		}
		err = s.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"": []byte("1")}})
		if fxstore.OutcomeOf(err) != fxstore.NotCommitted {
			return fmt.Errorf("empty key: %v; want not committed", err)
		}
		return want(ctx, s, map[string][]byte{"a": []byte("1")})
	}},
	{name: "cancelled context", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		defer closeStore(s)
		c, cancel := context.WithCancel(ctx)
		cancel()
		if err := s.Apply(c, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1")}}); fxstore.OutcomeOf(err) != fxstore.NotCommitted {
			return fmt.Errorf("Apply with a cancelled context: %v; want not committed", err)
		}
		if _, err := s.Load(c); err == nil {
			return errors.New("load with a cancelled context succeeded")
		}
		return want(ctx, s, map[string][]byte{})
	}},
	{name: "concurrent applies", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		defer closeStore(s)
		var wg sync.WaitGroup
		errs := make([]error, 16)
		for i := range 16 {
			wg.Go(func() {
				if err := s.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{fmt.Sprint(i): {byte(i)}}}); err != nil {
					errs[i] = fmt.Errorf("Apply %d: %w", i, err)
				}
			})
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			return err
		}
		st, err := s.Load(ctx)
		if err != nil || len(st) != 16 {
			return fmt.Errorf("after 16 concurrent applies: %d keys, %v", len(st), err)
		}
		return nil
	}},
	{name: "closed", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		if err := s.Close(); err != nil {
			return fmt.Errorf("close: %w", err)
		}
		if _, err := s.Load(ctx); !errors.Is(err, fxstore.ErrClosed) {
			return fmt.Errorf("Load after Close: %v", err)
		}
		if err := s.Apply(ctx, fxstore.Batch{}); !errors.Is(err, fxstore.ErrClosed) || fxstore.OutcomeOf(err) != fxstore.NotCommitted {
			return fmt.Errorf("Apply after Close: %v", err)
		}
		return nil
	}},
	{name: "reopen keeps the state", durable: true, run: func(ctx context.Context, s fxstore.Store, reopen func() (fxstore.Store, error)) error {
		if err := apply(ctx, s, fxstore.Batch{Puts: map[string][]byte{"a": []byte("1")}}); err != nil {
			_ = s.Close()
			return err
		}
		if err := s.Close(); err != nil {
			return fmt.Errorf("close: %w", err)
		}
		s2, err := reopen()
		if err != nil {
			return fmt.Errorf("reopen: %w", err)
		}
		defer closeStore(s2)
		return want(ctx, s2, map[string][]byte{"a": []byte("1")})
	}},
	{name: "domain", run: func(ctx context.Context, s fxstore.Store, _ func() (fxstore.Store, error)) error {
		defer closeStore(s)
		o := fxstore.DomainOptions{Namespace: "ac", Owner: "urn:test", Schema: 1}
		d, err := fxstore.OpenDomain(ctx, s, o)
		if err != nil {
			return fmt.Errorf("OpenDomain: %w", err)
		}
		if out, err := d.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"ep/1": []byte("x")}}); out != fxstore.Committed {
			return fmt.Errorf("Domain.Apply: %v, %v", out, err)
		}
		st, err := s.Load(ctx)
		if err != nil {
			return fmt.Errorf("Load: %w", err)
		}
		for k := range st {
			if !strings.HasPrefix(k, "ac/") {
				return fmt.Errorf("key %q outside the namespace", k)
			}
		}
		d2, err := fxstore.OpenDomain(ctx, s, o)
		if err != nil {
			return fmt.Errorf("OpenDomain again: %w", err)
		}
		if got := d2.State(); !bytes.Equal(got["ep/1"], []byte("x")) || len(got) != 1 {
			return fmt.Errorf("reloaded domain: %v", got)
		}
		return nil
	}},
}

// closeStore closes s after a check; a failed Close is what the "closed"
// check tests.
func closeStore(s fxstore.Store) { _ = s.Close() }

func apply(ctx context.Context, s fxstore.Store, b fxstore.Batch) error {
	if err := s.Apply(ctx, b); err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	return nil
}

// want checks that s holds w, and nothing else.
func want(ctx context.Context, s fxstore.Store, w map[string][]byte) error {
	st, err := s.Load(ctx)
	if err != nil {
		return fmt.Errorf("Load: %w", err)
	}
	if len(st) != len(w) {
		return fmt.Errorf("Load = %d keys %v; want %v", len(st), st, w)
	}
	for k, v := range w {
		if got, ok := st[k]; !ok || !bytes.Equal(got, v) {
			return fmt.Errorf("key %q = %q, %v; want %q", k, got, ok, v)
		}
	}
	return nil
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

	mu       sync.Mutex
	applys   []Fault
	loads    int
	loadsErr error
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

// FailLoadsWith makes every Load fail with err until it is called again
// with nil.
func (f *Faulty) FailLoadsWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadsErr = err
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
	case FailLoad:
		// A Load fault does not fail an Apply.
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
	sticky := f.loadsErr
	f.mu.Unlock()
	if fail {
		return nil, ErrInjected
	}
	if sticky != nil {
		return nil, sticky
	}
	return f.Store.Load(ctx)
}
