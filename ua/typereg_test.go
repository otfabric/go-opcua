// SPDX-License-Identifier: MIT

package ua

import (
	stderrors "errors"
	"testing"

	"github.com/otfabric/go-opcua/errors"
)

func TestTypeRegistry_New_nilID(t *testing.T) {
	r := NewTypeRegistry()
	if got := r.New(nil); got != nil {
		t.Errorf("New(nil) = %v, want nil", got)
	}
}

func TestTypeRegistry_New_unknown(t *testing.T) {
	r := NewTypeRegistry()
	id := NewNumericNodeID(0, 999999)
	if got := r.New(id); got != nil {
		t.Errorf("New(unknown id) = %v, want nil", got)
	}
}

func TestTypeRegistry_Register_New_Lookup(t *testing.T) {
	r := NewTypeRegistry()
	type payload struct{ N int }
	id := NewNumericNodeID(0, 4242)

	if err := r.Register(id, &payload{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	v := r.New(id)
	if v == nil {
		t.Fatal("New returned nil for registered type")
	}
	p, ok := v.(*payload)
	if !ok || p == nil {
		t.Fatalf("New returned %T, want *payload", v)
	}

	looked := r.Lookup(&payload{N: 1})
	if looked == nil || !looked.Equal(id) {
		t.Errorf("Lookup = %v, want %v", looked, id)
	}
}

func TestTypeRegistry_Register_conflict(t *testing.T) {
	r := NewTypeRegistry()
	id := NewStringNodeID(0, "same-id")
	type A struct{}
	type B struct{}

	if err := r.Register(id, &A{}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := r.Register(id, &B{})
	if err == nil {
		t.Fatal("expected error registering different type for same id")
	}
	if !stderrors.Is(err, errors.ErrTypeAlreadyRegistered) {
		t.Errorf("error = %v, want ErrTypeAlreadyRegistered", err)
	}
}

func TestTypeRegistry_Register_sameTypeTwice(t *testing.T) {
	r := NewTypeRegistry()
	id := NewNumericNodeID(0, 77)
	type T struct{}

	if err := r.Register(id, &T{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(id, &T{}); err != nil {
		t.Errorf("Register same type twice: %v", err)
	}
}

func TestTypeRegistry_Lookup_unregistered(t *testing.T) {
	r := NewTypeRegistry()
	if r.Lookup(&struct{}{}) != nil {
		t.Error("Lookup unregistered type should return nil")
	}
}
