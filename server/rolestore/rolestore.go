// SPDX-License-Identifier: MIT

// Package rolestore persists the managed RoleSet of a server (OPC 10000-18,
// server.WithRoleManagement): the roles AddRole added (§4.2.2) and the
// Identities, Applications, ApplicationsExclude, Endpoints and
// EndpointsExclude of every role whose configuration can change (§4.4.1).
// A [Store] is the server.RoleSetStore of server.WithRoleSetStore: the
// server writes each change of its RoleSet in one atomic write, whatever
// makes it (the RoleSet and Role Methods of §4.2.2, §4.2.3 and §4.4.5 to
// §4.4.10, a Write of ApplicationsExclude or EndpointsExclude, and the
// server.RoleSet methods), and restores what it wrote when it starts again.
//
// It is built on package uafx/fxstore, the persistence of the library, as
// packages server/pushstore and server/pubsubstore are: a Store is one
// [fxstore.Domain] (namespace "roles") on an [fxstore.Store] backend, by
// default an [fxstore.FileStore] in a directory of its own ([OpenDir]).
// Each write is one Domain.Apply with the next revision. A write with an
// unknown outcome fences the store: later writes are refused until Settle
// has found what the backend holds and, where the write landed although
// the server did not apply it, has written the roles the server has back.
// A server therefore never restarts with a change it did not apply.
//
// The records, by key in the namespace:
//
//	root      the roles in their order: a format byte (1) and the keys
//	          of their records, a count and the keys, every count and
//	          length an unsigned varint of encoding/binary.
//	role/<h>  a role: a format byte (1), a flags byte (1: added by
//	          AddRole, 2: ApplicationsExclude, 4: EndpointsExclude),
//	          the namespace URIs of its NodeId and of its BrowseName
//	          (each a length and the bytes) and, in the OPC UA Binary
//	          encoding (Part 6 §5.2), its NodeId in namespace 0, the Name
//	          of its BrowseName, its Identities
//	          (IdentityMappingRuleType[]), Applications (String[]) and
//	          Endpoints (EndpointType[]).
//
// <h> is the first 16 bytes of the SHA-256 of the namespace URI and the
// NodeId of the role, in hexadecimal. The namespaces of a role are mapped
// to the NamespaceArray of the server when it is loaded, so that a role
// keeps its NodeId, "a Server shall persist the identifierType and
// identifier NodeId elements of a Node as well as the Namespace Uri which
// the namespaceIndex NodeId element references" (OPC 10000-3 §5.2.2), when
// its namespace has another index; a namespace the server does not have
// fails the load (ErrNamespace).
//
// The records hold the rules that grant the roles, SecurityAdmin
// included: who may change them may grant themselves any role. A
// FileStore creates its directory 0700 and its files 0600, and refuses a
// directory the group or others may write. An application that needs
// encryption or integrity protection at rest wraps the fxstore.Store it
// passes to Open.
package rolestore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// Namespace is the namespace of the records in the backend.
const Namespace = "roles"

// Schema is the version of the records this package writes.
const Schema = 1

// Options configure Open and OpenDir.
type Options struct {
	// Owner identifies the server, its ApplicationUri: a store another
	// owner wrote is refused (fxstore.ErrForeignOwner).
	Owner string
	// Limits bound the records (zero: the defaults of fxstore, 4 MiB per
	// record). A role larger than MaxValue cannot be stored.
	Limits fxstore.Limits
}

// Store is the store of the managed RoleSet of one server. It implements
// server.RoleSetStore. It is safe for concurrent use; its writes are
// serialized.
type Store struct {
	d       *fxstore.Domain
	backend fxstore.Store
	own     bool // Close closes backend

	mu sync.Mutex
	// restore, when not nil, is the state the store must hold again: that
	// before a write with an unknown outcome, which the server did not
	// apply.
	restore map[string][]byte
	closed  bool
}

var _ server.RoleSetStore = (*Store)(nil)

// ErrClosed is returned by a closed Store.
var ErrClosed = errors.New("rolestore: closed")

// Open opens the store on the backend s, which holds nothing else: the
// namespace "roles" must be the only one in it. It fails when s cannot be
// loaded, belongs to another owner, was written by a newer version, or
// holds records that do not decode (fxstore.ErrCorrupt). Close does not
// close s.
func Open(ctx context.Context, s fxstore.Store, o Options) (*Store, error) {
	d, err := fxstore.OpenDomain(ctx, s, fxstore.DomainOptions{Namespace: Namespace, Owner: o.Owner, Schema: Schema, Limits: o.Limits})
	if err != nil {
		return nil, fmt.Errorf("rolestore: %w", err)
	}
	if _, err := decodeState(d.State()); err != nil {
		return nil, err
	}
	return &Store{d: d, backend: s}, nil
}

// OpenDir opens the store in the directory dir with an fxstore.FileStore,
// creating it if missing. The directory belongs to the store: it holds the
// lock file and the data file of the FileStore and nothing else. Close
// closes the FileStore.
func OpenDir(ctx context.Context, dir string, o Options) (*Store, error) {
	fs, err := fxstore.OpenFile(dir, o.Limits)
	if err != nil {
		return nil, fmt.Errorf("rolestore: %w", err)
	}
	st, err := Open(ctx, fs, o)
	if err != nil {
		_ = fs.Close()
		return nil, err
	}
	st.own = true
	return st, nil
}

// Close closes the store, and the backend of OpenDir. Writes after Close
// fail with ErrClosed.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.own {
		return s.backend.Close()
	}
	return nil
}

// Status returns the state of the domain of the store: its revision and
// whether it is fenced.
func (s *Store) Status() fxstore.DomainStatus { return s.d.Status() }

// Settle resolves a write with an unknown outcome: it establishes what the
// backend holds (fxstore.Domain.Settle) and, when the write landed, writes
// the roles before it back. It returns true when the store accepts writes
// again. Every write settles first, so an application may leave Settle to
// the next change of the RoleSet or run it with a backoff.
func (s *Store) Settle(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	if err := s.settleLocked(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) settleLocked(ctx context.Context) error {
	if s.d.Status().Fenced {
		if ok, err := s.d.Settle(ctx); !ok {
			return fmt.Errorf("rolestore: settle: %w", err)
		}
	}
	if s.restore == nil {
		return nil
	}
	if b := diff(s.d.State(), s.restore); !b.Empty() {
		if _, err := s.d.Apply(ctx, b); err != nil {
			return fmt.Errorf("rolestore: settle: write the roles back: %w", err)
		}
	}
	s.restore = nil
	return nil
}

// diff returns the batch that takes the state cur to want.
func diff(cur, want map[string][]byte) fxstore.Batch {
	b := fxstore.Batch{Puts: map[string][]byte{}}
	for k, v := range want {
		if w, ok := cur[k]; !ok || string(w) != string(v) {
			b.Puts[k] = v
		}
	}
	for _, k := range slices.Sorted(maps.Keys(cur)) {
		if _, ok := want[k]; !ok {
			b.Deletes = append(b.Deletes, k)
		}
	}
	return b
}

// StoreRoleSet makes roles, their NodeIds and BrowseNames in the
// namespaces of namespaces, the stored roles in one atomic write of the
// records that change. It settles the store first. An error wraps
// fxstore.ErrNotCommitted when nothing of roles is durable; any other
// error is an unknown outcome, which fences the store until Settle.
func (s *Store) StoreRoleSet(ctx context.Context, roles []server.Role, namespaces []string) error {
	want, err := records(roles, namespaces)
	if err != nil {
		return fxstore.AsNotCommitted(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fxstore.AsNotCommitted(ErrClosed)
	}
	if err := s.settleLocked(ctx); err != nil {
		return fxstore.AsNotCommitted(err)
	}
	before := s.d.State()
	b := diff(before, want)
	if b.Empty() {
		return nil
	}
	o, err := s.d.Apply(ctx, b)
	switch o {
	case fxstore.Committed:
		return nil
	case fxstore.Unknown:
		s.restore = before
		return fmt.Errorf("rolestore: the outcome of the write is unknown; the store is fenced until it is settled: %w", err)
	default:
		return fmt.Errorf("rolestore: %w", err)
	}
}

// LoadRoleSet returns the stored roles with their NodeIds and BrowseNames
// in the namespaces of namespaces, nil when the store holds none. A
// namespace that namespaces does not have fails with ErrNamespace. The
// roles belong to the caller.
func (s *Store) LoadRoleSet(_ context.Context, namespaces []string) ([]server.Role, error) {
	recs, err := decodeState(s.d.State())
	if err != nil || recs == nil {
		return nil, err
	}
	out := make([]server.Role, 0, len(recs))
	for _, x := range recs {
		r, err := x.role(namespaces)
		if err != nil {
			return nil, fmt.Errorf("rolestore: the role %v: %w", x.b.NodeID, err)
		}
		out = append(out, r)
	}
	return out, nil
}
