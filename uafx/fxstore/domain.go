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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// ErrInvalidKey reports a batch of Domain.Apply or Domain.Require with an
// empty key or the reserved key "meta". From Apply and Require it wraps
// ErrNotCommitted.
var ErrInvalidKey = errors.New("fxstore: invalid key")

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
// A Domain is safe for concurrent use; its writes are serialized. State,
// Status and Schema do not wait for a write in progress: they return what
// the domain knew before it (design §3.5: read-only access stays
// available). It starts no goroutines: the caller runs Settle, typically
// with a backoff.
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
	required   []Batch // relative keys, owned by the domain

	// snap is what State, Status and Schema read, published under mu
	// whenever a write, a settlement or the fence changes it.
	snap atomic.Pointer[snapshot]
}

// snapshot is the published view of a Domain. Its state map is the
// committed state map of the domain, which is never changed in place.
type snapshot struct {
	state      map[string][]byte
	schema     uint16
	status     DomainStatus
	unresolved UnresolvedWrite
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
	d.publishLocked()
	return d, nil
}

// publishLocked publishes the current state and status for State, Status
// and Schema.
func (d *Domain) publishLocked() {
	sn := &snapshot{state: d.state, schema: d.schema,
		status: DomainStatus{Revision: d.rev, Fenced: d.fencedLocked(), Required: len(d.required)}}
	if u := d.unresolved; u != nil {
		sn.unresolved = UnresolvedWrite{Batch: u.id.String(), Revision: u.rev, Since: u.since, Attempts: u.attempts,
			Confirmations: len(u.confirms), Err: u.lastErr}
		sn.status.Unresolved = &sn.unresolved
	}
	d.snap.Store(sn)
}

func (d *Domain) metaKey() string { return d.pfx + "meta" }

// Schema returns the schema of the loaded records (0 for an empty store).
func (d *Domain) Schema() uint16 { return d.snap.Load().schema }

// State returns the records of the domain as the domain knows them
// committed, by key relative to the namespace, without the meta key. While
// a write is unresolved or in progress it is the state before that write.
// The map and its values belong to the caller.
func (d *Domain) State() map[string][]byte { return d.relative(d.snap.Load().state) }

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
// fenced domain is NotCommitted with ErrFenced, an empty or "meta" key
// NotCommitted with ErrInvalidKey, a state over the Limits NotCommitted
// with ErrLimit. Apply does not keep b.
func (d *Domain) Apply(ctx context.Context, b Batch) (Outcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer d.publishLocked()
	if d.fencedLocked() {
		return NotCommitted, ErrFenced
	}
	return d.applyLocked(ctx, b, nil)
}

// Require writes b like Apply and, unless the write commits, owes it: the
// domain stays fenced until Settle has written it. It is for the writes
// that make the store follow a change the runtime made already (a
// removal), which must not be lost. While the domain is fenced b is owed
// without being written: NotCommitted with ErrFenced.
//
// A write that can never commit is not owed and does not fence the
// domain: a batch with an empty or "meta" key (ErrInvalidKey) or one that
// takes the state over the Limits of the domain or of the store
// (ErrLimit). Require returns NotCommitted with that error; the store does
// not follow the change.
//
// Require copies b: the caller may reuse it.
func (d *Domain) Require(ctx context.Context, b Batch) (Outcome, error) {
	b = cloneBatch(b)
	d.mu.Lock()
	defer d.mu.Unlock()
	defer d.publishLocked()
	if d.fencedLocked() {
		if err := d.validateOwedLocked(b); err != nil {
			return NotCommitted, err
		}
		d.required = append(d.required, b)
		return NotCommitted, ErrFenced
	}
	o, err := d.applyLocked(ctx, b, &b)
	if o == NotCommitted && !permanent(err) {
		d.required = append(d.required, b)
	}
	return o, err
}

// permanent reports an error of applyLocked that a retry of the same batch
// cannot cure: the domain never owes such a write.
func permanent(err error) bool { return errors.Is(err, ErrInvalidKey) || errors.Is(err, ErrLimit) }

// validateOwedLocked checks b, to be owed by a fenced domain, as its
// eventual write will: its keys, and the Limits of the domain on the
// committed state with the owed writes and b applied. The outcome of an
// unresolved write is not known yet, so Settle checks again.
func (d *Domain) validateOwedLocked(b Batch) error {
	next := d.state
	for _, r := range append(d.required[:len(d.required):len(d.required)], b) {
		full, err := d.full(r)
		if err != nil {
			return err
		}
		next = applyBatch(next, full)
	}
	m := meta{schema: d.o.Schema, owner: d.o.Owner}
	next[d.metaKey()] = m.encode()
	if err := d.o.Limits.check(next); err != nil {
		return AsNotCommitted(err)
	}
	return nil
}

// cloneBatch returns a deep copy of b.
func cloneBatch(b Batch) Batch {
	out := Batch{Deletes: slices.Clone(b.Deletes)}
	if b.Puts != nil {
		out.Puts = make(map[string][]byte, len(b.Puts))
		for k, v := range b.Puts {
			out.Puts[k] = bytes.Clone(v)
		}
	}
	return out
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
			return Batch{}, AsNotCommitted(fmt.Errorf("%w %q", ErrInvalidKey, k))
		}
		out.Puts[d.pfx+k] = v
	}
	for _, k := range b.Deletes {
		if k == "" || k == "meta" {
			return Batch{}, AsNotCommitted(fmt.Errorf("%w %q", ErrInvalidKey, k))
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
//
// A required write that can never commit (ErrInvalidKey, ErrLimit: the
// unresolved write it followed may have grown the state) is dropped, not
// retried: that Settle returns false with its error, and the next one goes
// on with the remaining writes.
func (d *Domain) Settle(ctx context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer d.publishLocked()
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
			if permanent(err) {
				d.required = d.required[1:]
				return false, fmt.Errorf("fxstore: settle: a required write can never be written and is dropped: %w", err)
			}
			return false, err
		}
	}
	return true, nil
}

// maxConfirms bounds the confirming Applies with an unknown outcome one
// unresolved write keeps the evidence of. Past it Settle stops confirming
// and the domain stays fenced until it is opened again: dropping the
// evidence of a confirmation that may still land would let a later
// settlement misjudge the store.
const maxConfirms = 64

// confirmLocked runs one confirmation of u.
func (d *Domain) confirmLocked(ctx context.Context, u *unresolved) error {
	if len(u.confirms) >= maxConfirms {
		return fmt.Errorf("fxstore: settle: %d confirmations with an unknown outcome; the domain stays fenced until it is opened again", len(u.confirms))
	}
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

// Status returns the state of the domain. It does not wait for a write in
// progress: it is the state before it.
func (d *Domain) Status() DomainStatus {
	sn := d.snap.Load()
	st := sn.status
	if st.Unresolved != nil {
		u := sn.unresolved
		st.Unresolved = &u
	}
	return st
}
