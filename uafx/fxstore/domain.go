// SPDX-License-Identifier: MIT

package fxstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"sync"
	"time"
)

// ErrFenced is returned by Domain.Apply while an earlier write of the
// domain has an unknown outcome or a required write is still owed: nothing
// is written. It wraps ErrNotCommitted.
var ErrFenced = notCommitted("fxstore: fenced until an earlier write is settled")

// ErrForeignOwner reports a store whose meta key names another owner.
var ErrForeignOwner = errors.New("fxstore: the store belongs to another owner")

// ErrSchema reports a store written by a newer version of the library.
var ErrSchema = errors.New("fxstore: unsupported schema")

// DomainOptions configure OpenDomain.
type DomainOptions struct {
	// Namespace is the key prefix of the domain without the slash: "ac"
	// for an AutomationComponent server, "cm" for a ConnectionManager.
	Namespace string
	// Owner identifies the owner, its ApplicationUri: a store whose meta
	// key names another owner is refused.
	Owner string
	// Schema is the version of the records the caller writes; a store with
	// a newer one is refused (ErrSchema). The caller migrates older ones.
	Schema uint16
	// Limits bound the state.
	Limits Limits
	// Rand is the source of batch identities; nil is crypto/rand.
	Rand io.Reader
}

// Domain is one namespace of a Store as the library writes it: every Apply
// also writes the meta key of the namespace with the next revision and a
// random batch identity, so that Load tells which batch the visible state
// ends with.
//
// An Apply with an unknown outcome fences the domain: later Applies fail
// with ErrFenced, without writing, until Settle establishes the outcome
// (design §3.3, §3.5). Settle loads the state, finds the revision it ends
// with, and confirms it with an Apply that writes only the meta key on top
// of it: when that commits, the loaded state is durable (prefix durability)
// and the unknown batch's outcome is known. A confirming Apply that is
// unknown itself is remembered with what its base contained, so repeated
// ambiguous confirmations never lose the identity or the evidence of the
// original batch.
//
// A Domain is safe for concurrent use; its writes are serialized. It starts
// no goroutines: the caller runs Settle, typically with a backoff.
type Domain struct {
	s   Store
	o   DomainOptions
	pfx string

	mu         sync.Mutex
	state      map[string][]byte // committed state, full keys, meta included
	schema     uint16
	rev        uint64
	id         batchID
	unresolved *unresolved
	required   []Batch // relative keys
}

type batchID [16]byte

func (b batchID) String() string { return hex.EncodeToString(b[:]) }

// unresolved is a write with an unknown outcome.
type unresolved struct {
	id       batchID
	rev      uint64
	base     batchID           // the batch the write was applied on
	before   map[string][]byte // the state without it
	after    map[string][]byte // the state with it
	required *Batch            // the write came from Require: owed if not committed
	// confirms are the confirming Applies whose outcome was unknown, with
	// whether the state they were built on contained the write.
	confirms map[batchID]bool
	maxRev   uint64
	since    time.Time
	attempts int
	lastErr  error
}

// meta is the value of the meta key.
type meta struct {
	schema uint16
	owner  string
	rev    uint64
	id     batchID
}

const metaFormat = 1

func (m meta) encode() []byte {
	b := []byte{metaFormat}
	b = binary.LittleEndian.AppendUint16(b, m.schema)
	b = appendLen(b, len(m.owner))
	b = append(b, m.owner...)
	b = binary.LittleEndian.AppendUint64(b, m.rev)
	return append(b, m.id[:]...)
}

func decodeMeta(b []byte) (meta, error) {
	var m meta
	bad := fmt.Errorf("%w: meta key", ErrCorrupt)
	if len(b) < 1+2+4 || b[0] != metaFormat {
		if len(b) > 0 && b[0] > metaFormat {
			return m, fmt.Errorf("%w: meta format %d", ErrSchema, b[0])
		}
		return m, bad
	}
	m.schema = binary.LittleEndian.Uint16(b[1:])
	n := binary.LittleEndian.Uint32(b[3:])
	b = b[7:]
	if int64(n) > int64(len(b)) || len(b)-int(n) != 8+16 {
		return m, bad
	}
	m.owner = string(b[:n])
	b = b[n:]
	m.rev = binary.LittleEndian.Uint64(b)
	copy(m.id[:], b[8:])
	return m, nil
}

// OpenDomain loads the namespace o.Namespace of s. It fails when the store
// cannot be loaded, holds keys outside the namespace, is over o.Limits,
// belongs to another owner (ErrForeignOwner), has a newer schema
// (ErrSchema) or a meta key that does not decode (ErrCorrupt).
func OpenDomain(ctx context.Context, s Store, o DomainOptions) (*Domain, error) {
	if s == nil || o.Namespace == "" || strings.Contains(o.Namespace, "/") {
		return nil, errors.New("fxstore: OpenDomain needs a store and a namespace")
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	o.Limits = o.Limits.withDefaults()
	d := &Domain{s: s, o: o, pfx: o.Namespace + "/"}
	state, err := s.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("fxstore: load: %w", err)
	}
	if err := o.Limits.check(state); err != nil {
		return nil, err
	}
	for k := range state {
		if !strings.HasPrefix(k, d.pfx) {
			return nil, fmt.Errorf("fxstore: key %q outside the namespace %q", k, o.Namespace)
		}
	}
	mv, ok := state[d.metaKey()]
	switch {
	case ok:
		m, err := decodeMeta(mv)
		if err != nil {
			return nil, err
		}
		if m.owner != o.Owner {
			return nil, fmt.Errorf("%w: %q, not %q", ErrForeignOwner, m.owner, o.Owner)
		}
		if m.schema > o.Schema {
			return nil, fmt.Errorf("%w: schema %d, this library writes %d", ErrSchema, m.schema, o.Schema)
		}
		d.schema, d.rev, d.id = m.schema, m.rev, m.id
	case len(state) > 0:
		return nil, fmt.Errorf("%w: records without a meta key", ErrCorrupt)
	}
	d.state = state
	return d, nil
}

func (d *Domain) metaKey() string { return d.pfx + "meta" }

// Schema returns the schema of the loaded records (0 for an empty store).
func (d *Domain) Schema() uint16 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.schema
}

// State returns the records of the domain as the domain knows them
// committed, by key relative to the namespace, without the meta key. While
// a write is unresolved it is the state before that write.
func (d *Domain) State() map[string][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.relative(d.state)
}

func (d *Domain) relative(state map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(state))
	for k, v := range state {
		if k != d.metaKey() {
			out[strings.TrimPrefix(k, d.pfx)] = clone(v)
		}
	}
	return out
}

// Apply writes b, its keys relative to the namespace, with the next
// revision. It returns the outcome and, unless committed, an error: a
// fenced domain is NotCommitted with ErrFenced.
func (d *Domain) Apply(ctx context.Context, b Batch) (Outcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fencedLocked() {
		return NotCommitted, ErrFenced
	}
	return d.applyLocked(ctx, b, nil)
}

// Require writes b like Apply and, unless the write commits, owes it: the
// domain stays fenced until Settle has written it. It is for the writes
// that make the store follow a change the runtime made already (a
// removal), which must not be lost.
func (d *Domain) Require(ctx context.Context, b Batch) (Outcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fencedLocked() {
		d.required = append(d.required, b)
		return NotCommitted, ErrFenced
	}
	o, err := d.applyLocked(ctx, b, &b)
	if o == NotCommitted {
		d.required = append(d.required, b)
	}
	return o, err
}

func (d *Domain) fencedLocked() bool { return d.unresolved != nil || len(d.required) > 0 }

// applyLocked applies b; req is b when it is required.
func (d *Domain) applyLocked(ctx context.Context, b Batch, req *Batch) (Outcome, error) {
	full, err := d.full(b)
	if err != nil {
		return NotCommitted, err
	}
	var id batchID
	if _, err := io.ReadFull(d.o.Rand, id[:]); err != nil {
		return NotCommitted, AsNotCommitted(fmt.Errorf("fxstore: batch identity: %w", err))
	}
	m := meta{schema: d.o.Schema, owner: d.o.Owner, rev: d.rev + 1, id: id}
	full.Puts[d.metaKey()] = m.encode()
	next := applyBatch(d.state, full)
	if err := d.o.Limits.check(next); err != nil {
		return NotCommitted, AsNotCommitted(err)
	}
	err = d.s.Apply(ctx, full)
	switch o := OutcomeOf(err); o {
	case Committed:
		d.state, d.rev, d.id, d.schema = next, m.rev, id, m.schema
		return o, nil
	case NotCommitted:
		return o, err
	default:
		d.unresolved = &unresolved{id: id, rev: m.rev, base: d.id, before: d.state, after: next, required: req,
			confirms: map[batchID]bool{}, maxRev: m.rev, since: time.Now(), lastErr: err}
		return Unknown, err
	}
}

// full returns b with full keys; it refuses the meta key and empty keys.
func (d *Domain) full(b Batch) (Batch, error) {
	out := Batch{Puts: make(map[string][]byte, len(b.Puts)+1)}
	for k, v := range b.Puts {
		if k == "" || k == "meta" {
			return Batch{}, AsNotCommitted(fmt.Errorf("fxstore: invalid key %q", k))
		}
		out.Puts[d.pfx+k] = v
	}
	for _, k := range b.Deletes {
		if k == "" || k == "meta" {
			return Batch{}, AsNotCommitted(fmt.Errorf("fxstore: invalid key %q", k))
		}
		if _, put := b.Puts[k]; !put {
			out.Deletes = append(out.Deletes, d.pfx+k)
		}
	}
	return out, nil
}

// Settle establishes the outcome of an unresolved write and writes the
// required ones. It returns true when the domain is no longer fenced, and
// the error of the step that kept it fenced. It writes nothing when the
// domain is not fenced.
func (d *Domain) Settle(ctx context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if u := d.unresolved; u != nil {
		u.attempts++
		if err := d.confirmLocked(ctx, u); err != nil {
			u.lastErr = err
			return false, err
		}
	}
	for len(d.required) > 0 {
		b := d.required[0]
		o, err := d.applyLocked(ctx, b, &b)
		switch o {
		case Committed:
			d.required = d.required[1:]
		case Unknown:
			d.required = d.required[1:]
			return false, err
		default:
			return false, err
		}
	}
	return true, nil
}

// confirmLocked runs one confirmation of u.
func (d *Domain) confirmLocked(ctx context.Context, u *unresolved) error {
	loaded, err := d.s.Load(ctx)
	if err != nil {
		return fmt.Errorf("fxstore: settle: load: %w", err)
	}
	mv, ok := loaded[d.metaKey()]
	var m meta
	if ok {
		if m, err = decodeMeta(mv); err != nil {
			return fmt.Errorf("fxstore: settle: %w", err)
		}
	}
	var contained bool
	switch c, isConfirm := u.confirms[m.id]; {
	case ok && m.id == u.id:
		contained = true
	case ok && isConfirm:
		contained = c
	case m.id == u.base:
		// The base: no meta key when the write was the first one.
		contained = false
	default:
		return fmt.Errorf("fxstore: settle: the store ends with an unknown batch %v", m.id)
	}
	want := u.before
	if contained {
		want = u.after
	}
	if !sameRecords(loaded, want, d.metaKey()) {
		return fmt.Errorf("fxstore: settle: the state of batch %v is not the one written", m.id)
	}
	var id batchID
	if _, err := io.ReadFull(d.o.Rand, id[:]); err != nil {
		return fmt.Errorf("fxstore: settle: batch identity: %w", err)
	}
	rev := max(u.maxRev, m.rev, d.rev) + 1
	cm := meta{schema: d.o.Schema, owner: d.o.Owner, rev: rev, id: id}
	err = d.s.Apply(ctx, Batch{Puts: map[string][]byte{d.metaKey(): cm.encode()}})
	switch OutcomeOf(err) {
	case Committed:
	case NotCommitted:
		return fmt.Errorf("fxstore: settle: confirm: %w", err)
	default:
		u.confirms[id] = contained
		u.maxRev = rev
		return fmt.Errorf("fxstore: settle: confirm: %w", err)
	}
	next := maps.Clone(want)
	next[d.metaKey()] = cm.encode()
	d.state, d.rev, d.id, d.schema = next, rev, id, cm.schema
	d.unresolved = nil
	if !contained && u.required != nil {
		d.required = append([]Batch{*u.required}, d.required...)
	}
	return nil
}

// sameRecords compares two states without the meta key.
func sameRecords(a, b map[string][]byte, metaKey string) bool {
	n := 0
	for k, v := range a {
		if k == metaKey {
			continue
		}
		n++
		w, ok := b[k]
		if !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	m := len(b)
	if _, ok := b[metaKey]; ok {
		m--
	}
	return n == m
}

// DomainStatus is the state of a Domain.
type DomainStatus struct {
	// Revision is the revision of the committed state.
	Revision uint64
	// Fenced: Apply refuses writes until Settle succeeds.
	Fenced bool
	// Unresolved is the write with an unknown outcome, if any.
	Unresolved *UnresolvedWrite
	// Required is the number of writes owed.
	Required int
}

// UnresolvedWrite describes a write with an unknown outcome.
type UnresolvedWrite struct {
	// Batch is the identity of the write, Revision its revision.
	Batch    string
	Revision uint64
	// Since is when it was written, Attempts how often Settle tried.
	Since    time.Time
	Attempts int
	// Confirmations is the number of confirming writes whose outcome was
	// unknown too.
	Confirmations int
	// Err is the last error.
	Err error
}

// Status returns the state of the domain.
func (d *Domain) Status() DomainStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := DomainStatus{Revision: d.rev, Fenced: d.fencedLocked(), Required: len(d.required)}
	if u := d.unresolved; u != nil {
		st.Unresolved = &UnresolvedWrite{Batch: u.id.String(), Revision: u.rev, Since: u.since, Attempts: u.attempts,
			Confirmations: len(u.confirms), Err: u.lastErr}
	}
	return st
}
