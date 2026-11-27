// SPDX-License-Identifier: MIT

// Package fxstore is the durable storage of the UAFX persistent
// connections: the ConnectionEndpoints an AutomationComponent restores after
// a restart (OPC 10000-81 §5.5.5, §6.6.2) and, later, the state of a
// ConnectionManager. The application supplies the backend, a [Store]; the
// library owns what it writes there, its format and its migration. The
// package has no dependency outside the standard library and go-opcua.
//
// A Store is a byte key-value map with an atomic [Store.Apply]. Its contract
// separates three outcomes of a write: committed (nil), definitely not
// committed (an error that wraps [ErrNotCommitted]) and unknown (any other
// error). A [Domain] is what the library writes through: one namespace of
// keys with a meta key that carries a revision and a batch identity, so that
// an unknown outcome can be settled later by a confirming write, and a
// fence that refuses new writes until it is.
//
// [MemoryStore] implements the contract in memory for tests and for
// applications that want its protocols without persistence: it survives no
// restart. [FileStore] is a reference backend on a local directory. The
// contract tests of package storetest check any backend.
//
// The design is docs/design/uafx-persistent-connections.md §3.
package fxstore

import (
	"context"
	"errors"
	"slices"
	"strconv"
)

// Store keeps the durable state of one AutomationComponent server or one
// ConnectionManager. One process owns it: the one that opened it.
//
// The methods are safe for concurrent use; Applies are serialized.
type Store interface {
	// Load returns the visible state: every key with its value. The
	// returned map and slices belong to the caller.
	Load(ctx context.Context) (map[string][]byte, error)
	// Apply makes the puts and deletes of b durable, all or none. It
	// returns nil when they are committed, an error that wraps
	// ErrNotCommitted when nothing of b was made durable, and any other
	// error when the outcome is unknown.
	//
	// A committed Apply makes durable the whole state it was applied to,
	// including every earlier batch Load could see at that moment (prefix
	// durability).
	//
	// Apply borrows b for the call: it must not change b, its map or its
	// value slices, nor keep them after it returns.
	Apply(ctx context.Context, b Batch) error
	// Close releases the store. Load and Apply after Close return
	// ErrClosed.
	Close() error
}

// Batch is one atomic write: Puts set keys to values, Deletes remove keys.
// A key in both is put.
type Batch struct {
	Puts    map[string][]byte
	Deletes []string
}

// Empty reports whether b changes nothing.
func (b Batch) Empty() bool { return len(b.Puts) == 0 && len(b.Deletes) == 0 }

var (
	// ErrNotCommitted wraps an Apply error that guarantees that nothing of
	// the batch was made durable.
	ErrNotCommitted = errors.New("fxstore: not committed")
	// ErrClosed is returned by a closed store. It wraps ErrNotCommitted.
	ErrClosed = notCommitted("fxstore: closed")
	// ErrLocked reports a store another writer owns.
	ErrLocked = errors.New("fxstore: store is locked by another writer")
	// ErrLimit reports a key, value or state over its Limits. From Apply
	// it wraps ErrNotCommitted.
	ErrLimit = errors.New("fxstore: limit exceeded")
	// ErrCorrupt reports stored data that does not decode.
	ErrCorrupt = errors.New("fxstore: corrupt data")
)

// notCommittedError is an error that wraps ErrNotCommitted.
type notCommittedError struct {
	msg string
	err error
}

func (e *notCommittedError) Error() string {
	if e.err != nil {
		return e.msg + ": " + e.err.Error()
	}
	return e.msg
}

func (e *notCommittedError) Is(target error) bool { return target == ErrNotCommitted }

func (e *notCommittedError) Unwrap() error { return e.err }

func notCommitted(msg string) error { return &notCommittedError{msg: msg} }

// AsNotCommitted returns err as an error that wraps ErrNotCommitted: for a
// backend whose write failed before anything could be durable.
func AsNotCommitted(err error) error {
	if err == nil || errors.Is(err, ErrNotCommitted) {
		return err
	}
	return &notCommittedError{msg: "fxstore: not committed", err: err}
}

// Outcome is the outcome of a write.
type Outcome uint8

const (
	// Committed: the write is durable.
	Committed Outcome = iota + 1
	// NotCommitted: nothing of the write is durable.
	NotCommitted
	// Unknown: the write may or may not be durable.
	Unknown
)

func (o Outcome) String() string {
	switch o {
	case Committed:
		return "committed"
	case NotCommitted:
		return "not committed"
	case Unknown:
		return "unknown"
	}
	return "invalid"
}

// OutcomeOf classifies the error of an Apply.
func OutcomeOf(err error) Outcome {
	switch {
	case err == nil:
		return Committed
	case errors.Is(err, ErrNotCommitted):
		return NotCommitted
	}
	return Unknown
}

// Durability is what a committed write survives.
type Durability uint8

const (
	// DurabilityNone: nothing; the state lives in memory (MemoryStore).
	DurabilityNone Durability = iota
	// DurabilityProcessCrash: a crash of the process, not necessarily a
	// power loss of the machine.
	DurabilityProcessCrash
	// DurabilityPowerLoss: a crash of the process and a power loss of the
	// machine, as far as the storage honours fsync.
	DurabilityPowerLoss
)

func (d Durability) String() string {
	switch d {
	case DurabilityNone:
		return "none"
	case DurabilityProcessCrash:
		return "process crash"
	case DurabilityPowerLoss:
		return "power loss"
	}
	return "invalid"
}

// Durable is implemented by a Store that says what its committed writes
// survive.
type Durable interface {
	Durability() Durability
}

// Limits bound what a store holds, so that a corrupt or hostile store
// cannot make its reader allocate without bound.
type Limits struct {
	// MaxKey is the longest key in bytes; 0 is 1024.
	MaxKey int
	// MaxValue is the largest value in bytes; 0 is 4 MiB.
	MaxValue int
	// MaxKeys is the number of keys; 0 is 65536.
	MaxKeys int
	// MaxTotal is the sum of the lengths of all keys and values; 0 is
	// 64 MiB.
	MaxTotal int64
}

// Default limits.
const (
	DefaultMaxKey   = 1024
	DefaultMaxValue = 4 << 20
	DefaultMaxKeys  = 65536
	DefaultMaxTotal = 64 << 20
)

// withDefaults returns l with its zero fields set to the defaults; a
// negative field is treated as zero.
func (l Limits) withDefaults() Limits {
	if l.MaxKey <= 0 {
		l.MaxKey = DefaultMaxKey
	}
	if l.MaxValue <= 0 {
		l.MaxValue = DefaultMaxValue
	}
	if l.MaxKeys <= 0 {
		l.MaxKeys = DefaultMaxKeys
	}
	if l.MaxTotal <= 0 {
		l.MaxTotal = DefaultMaxTotal
	}
	return l
}

// check checks a whole state against l.
func (l Limits) check(state map[string][]byte) error {
	l = l.withDefaults()
	if len(state) > l.MaxKeys {
		return &limitError{"keys", int64(len(state)), int64(l.MaxKeys)}
	}
	var total int64
	for k, v := range state {
		if err := l.checkEntry(k, v); err != nil {
			return err
		}
		total += int64(len(k)) + int64(len(v))
		if total > l.MaxTotal {
			return &limitError{"total size", total, l.MaxTotal}
		}
	}
	return nil
}

func (l Limits) checkEntry(k string, v []byte) error {
	switch {
	case k == "":
		return &limitError{"empty key", 0, 0}
	case len(k) > l.MaxKey:
		return &limitError{"key length", int64(len(k)), int64(l.MaxKey)}
	case len(v) > l.MaxValue:
		return &limitError{"value length", int64(len(v)), int64(l.MaxValue)}
	}
	return nil
}

type limitError struct {
	what       string
	got, limit int64
}

func (e *limitError) Error() string {
	if e.limit == 0 {
		return "fxstore: limit exceeded: " + e.what
	}
	return "fxstore: limit exceeded: " + e.what + " " + strconv.FormatInt(e.got, 10) + " over " + strconv.FormatInt(e.limit, 10)
}

func (e *limitError) Is(target error) bool { return target == ErrLimit }

// applyBatch returns state with b applied, as a new map; state is not
// changed.
func applyBatch(state map[string][]byte, b Batch) map[string][]byte {
	out := make(map[string][]byte, len(state)+len(b.Puts))
	for k, v := range state {
		out[k] = v
	}
	for _, k := range b.Deletes {
		delete(out, k)
	}
	for k, v := range b.Puts {
		out[k] = clone(v)
	}
	return out
}

func clone(v []byte) []byte {
	if v == nil {
		return []byte{}
	}
	return append([]byte(nil), v...)
}

func sortedKeys(state map[string][]byte) []string {
	keys := make([]string, 0, len(state))
	for k := range state {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func cloneState(state map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(state))
	for k, v := range state {
		out[k] = clone(v)
	}
	return out
}
