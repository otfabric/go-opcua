// SPDX-License-Identifier: MIT

package fxstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

func TestMemoryStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) (fxstore.Store, func() (fxstore.Store, error)) {
		return &fxstore.MemoryStore{}, nil
	})
}

func TestFileStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) (fxstore.Store, func() (fxstore.Store, error)) {
		dir := t.TempDir() + "/store"
		s, err := fxstore.OpenFile(dir, fxstore.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return s, func() (fxstore.Store, error) { return fxstore.OpenFile(dir, fxstore.Limits{}) }
	})
}

func TestFaultyContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) (fxstore.Store, func() (fxstore.Store, error)) {
		return storetest.NewFaulty(&fxstore.MemoryStore{}), nil
	})
}

func TestOutcome(t *testing.T) {
	for _, c := range []struct {
		err  error
		want fxstore.Outcome
	}{
		{nil, fxstore.Committed},
		{fxstore.ErrClosed, fxstore.NotCommitted},
		{fxstore.ErrFenced, fxstore.NotCommitted},
		{fxstore.AsNotCommitted(errors.New("x")), fxstore.NotCommitted},
		{errors.New("x"), fxstore.Unknown},
	} {
		if got := fxstore.OutcomeOf(c.err); got != c.want {
			t.Errorf("OutcomeOf(%v) = %v; want %v", c.err, got, c.want)
		}
	}
	if fxstore.AsNotCommitted(nil) != nil || fxstore.AsNotCommitted(fxstore.ErrClosed) != fxstore.ErrClosed {
		t.Error("AsNotCommitted changes nil or a not-committed error")
	}
	err := fxstore.AsNotCommitted(context.Canceled)
	if !errors.Is(err, context.Canceled) || err.Error() == "" {
		t.Errorf("AsNotCommitted loses its cause: %v", err)
	}
	for o, s := range map[fxstore.Outcome]string{fxstore.Committed: "committed", fxstore.NotCommitted: "not committed",
		fxstore.Unknown: "unknown", 0: "invalid"} {
		if o.String() != s {
			t.Errorf("%d.String() = %q", o, o.String())
		}
	}
	for d, s := range map[fxstore.Durability]string{fxstore.DurabilityNone: "none", fxstore.DurabilityProcessCrash: "process crash",
		fxstore.DurabilityPowerLoss: "power loss", 9: "invalid"} {
		if d.String() != s {
			t.Errorf("%d.String() = %q", d, d.String())
		}
	}
	if (fxstore.Batch{}).Empty() != true || (fxstore.Batch{Deletes: []string{"a"}}).Empty() {
		t.Error("Batch.Empty")
	}
	if (&fxstore.MemoryStore{}).Durability() != fxstore.DurabilityNone {
		t.Error("MemoryStore is durable")
	}
}

func TestMemoryStoreLimits(t *testing.T) {
	ctx := context.Background()
	m := &fxstore.MemoryStore{Limits: fxstore.Limits{MaxKeys: 2, MaxKey: 4, MaxTotal: 10}}
	for _, b := range []fxstore.Batch{
		{Puts: map[string][]byte{"a": nil, "b": nil, "c": nil}},
		{Puts: map[string][]byte{"toolong": nil}},
		{Puts: map[string][]byte{"a": make([]byte, 10)}},
	} {
		err := m.Apply(ctx, b)
		if !errors.Is(err, fxstore.ErrLimit) || fxstore.OutcomeOf(err) != fxstore.NotCommitted {
			t.Errorf("Apply(%v) = %v; want a not committed ErrLimit", b, err)
		}
	}
}
