// SPDX-License-Identifier: MIT

package fxstore

import (
	"context"
	"errors"
	"testing"
)

// lostStore loses every Apply: it writes nothing and reports an unknown
// outcome.
type lostStore struct{ MemoryStore }

func (s *lostStore) Apply(context.Context, Batch) error { return errors.New("lost") }

// TestDomainConfirmsBounded: the evidence of confirmations with an unknown
// outcome is bounded: past maxConfirms Settle stops confirming and the
// domain stays fenced, the original write kept.
func TestDomainConfirmsBounded(t *testing.T) {
	ctx := context.Background()
	s := &lostStore{}
	d, err := OpenDomain(ctx, &s.MemoryStore, DomainOptions{Namespace: "n", Owner: "o"})
	if err != nil {
		t.Fatal(err)
	}
	d.s = s
	if o, _ := d.Apply(ctx, Batch{Puts: map[string][]byte{"a": []byte("1")}}); o != Unknown {
		t.Fatalf("Apply = %v", o)
	}
	batch := d.Status().Unresolved.Batch
	for range maxConfirms + 5 {
		if ok, _ := d.Settle(ctx); ok {
			t.Fatal("settled on a store that loses every write")
		}
	}
	d.mu.Lock()
	n := len(d.unresolved.confirms)
	d.mu.Unlock()
	if n != maxConfirms {
		t.Fatalf("confirmations kept = %d; want %d", n, maxConfirms)
	}
	st := d.Status()
	if !st.Fenced || st.Unresolved == nil || st.Unresolved.Batch != batch {
		t.Fatalf("Status = %+v", st)
	}
}
