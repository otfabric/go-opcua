// SPDX-License-Identifier: MIT

// Package pushstore persists the push certificate management of a server
// (OPC 10000-12 §7.10): the trust lists of its certificate groups, their
// certificates and private keys. A [Store] is the PushManagement.Store of
// package server: it writes each ApplyChanges and ResetToServerDefaults in
// one atomic write and restores what it wrote when the server is created
// again.
//
// It is built on package uafx/fxstore, the persistence of the library: a
// Store is one [fxstore.Domain] (namespace "push") on an [fxstore.Store]
// backend, by default an [fxstore.FileStore] in a directory of its own
// ([OpenDir]). Each write is one Domain.Apply with the next revision. A
// write with an unknown outcome fences the store: later writes are refused
// until Settle has found what the backend holds and, where the write landed
// although the server did not apply it, has written the state the server
// has back. A server therefore never restarts with changes it did not
// apply, and never with a part of an ApplyChanges.
//
// The records, by key in the namespace:
//
//	tl/<group>         the trust list of a group: a format byte (1), the
//	                   LastUpdateTime (Unix nanoseconds, a signed varint
//	                   of encoding/binary, 0 for none) and the
//	                   TrustListDataType in the OPC UA Binary encoding
//	                   (Part 6 §5.2).
//	cert/<group>/<t>   the certificate of type t (the numeric NodeId of
//	                   the CertificateType in namespace 0, decimal): a
//	                   format byte (1), a kind byte (0: deleted, 1: a
//	                   certificate) and, for a certificate, the DER
//	                   certificate, the private key in PKCS #8 DER
//	                   (unencrypted) and the DER issuers, each with a
//	                   uint32 little-endian length; the issuers follow
//	                   their uint32 count.
//
// <group> is the BrowseName of the group, path-escaped. A deleted
// certificate is kept as a record, so that a certificate of the
// configuration that DeleteCertificate removed stays removed after a
// restart. ResetToServerDefaults deletes every record: the server then
// starts with its configuration.
//
// The private keys are stored unencrypted: a FileStore creates its
// directory 0700 and its files 0600, and refuses a directory the group or
// others may write. An application that needs encryption at rest wraps the
// fxstore.Store it passes to Open. A key that cannot be exported in PKCS #8
// (a key in a hardware module) cannot be stored: the write fails and
// ApplyChanges with it.
package pushstore

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// Namespace is the namespace of the records in the backend.
const Namespace = "push"

// Schema is the version of the records this package writes.
const Schema = 1

// Group names of the default certificate groups (Part 12 §7.8.3).
const (
	DefaultApplicationGroup = "DefaultApplicationGroup"
	DefaultHTTPSGroup       = "DefaultHttpsGroup"
	DefaultUserTokenGroup   = "DefaultUserTokenGroup"
)

// Options configure Open and OpenDir.
type Options struct {
	// Owner identifies the server, its ApplicationUri: a store another
	// owner wrote is refused (fxstore.ErrForeignOwner).
	Owner string
	// Limits bound the records (zero: the defaults of fxstore, 4 MiB per
	// record). A trust list larger than MaxValue cannot be stored.
	Limits fxstore.Limits
}

// Store is the store of the push certificate management of one server. It
// implements server.CertificateBatchStore, server.CertificateLoadStore,
// server.CertificateGroupStore and server.CertificateDeleteStore. It is
// safe for concurrent use; its writes are serialized.
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

var (
	_ server.CertificateBatchStore  = (*Store)(nil)
	_ server.CertificateLoadStore   = (*Store)(nil)
	_ server.CertificateGroupStore  = (*Store)(nil)
	_ server.CertificateDeleteStore = (*Store)(nil)
)

// ErrClosed is returned by a closed Store.
var ErrClosed = errors.New("pushstore: closed")

var errNoCertificate = errors.New("pushstore: no certificate")

// Open opens the store on the backend s, which holds nothing else: the
// namespace "push" must be the only one in it. It fails when s cannot be
// loaded, belongs to another owner, was written by a newer version, or
// holds a record that does not decode (fxstore.ErrCorrupt). Close does not
// close s.
func Open(ctx context.Context, s fxstore.Store, o Options) (*Store, error) {
	d, err := fxstore.OpenDomain(ctx, s, fxstore.DomainOptions{Namespace: Namespace, Owner: o.Owner, Schema: Schema, Limits: o.Limits})
	if err != nil {
		return nil, fmt.Errorf("pushstore: %w", err)
	}
	st := &Store{d: d, backend: s}
	if _, err := decodeState(d.State()); err != nil {
		return nil, err
	}
	return st, nil
}

// OpenDir opens the store in the directory dir with an fxstore.FileStore,
// creating it if missing. The directory belongs to the store: it holds the
// lock file and the data file of the FileStore and nothing else. Close
// closes the FileStore.
func OpenDir(ctx context.Context, dir string, o Options) (*Store, error) {
	fs, err := fxstore.OpenFile(dir, o.Limits)
	if err != nil {
		return nil, fmt.Errorf("pushstore: %w", err)
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
// the state before it back. It returns true when the store accepts writes
// again. Every write settles first, so an application may leave Settle to
// the next ApplyChanges or run it with a backoff.
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
			return fmt.Errorf("pushstore: settle: %w", err)
		}
	}
	if s.restore == nil {
		return nil
	}
	cur := s.d.State()
	if !sameState(cur, s.restore) {
		b := fxstore.Batch{Puts: map[string][]byte{}}
		for k, v := range s.restore {
			if w, ok := cur[k]; !ok || string(w) != string(v) {
				b.Puts[k] = v
			}
		}
		for k := range cur {
			if _, ok := s.restore[k]; !ok {
				b.Deletes = append(b.Deletes, k)
			}
		}
		if _, err := s.d.Apply(ctx, b); err != nil {
			return fmt.Errorf("pushstore: settle: write the state back: %w", err)
		}
	}
	s.restore = nil
	return nil
}

func sameState(a, b map[string][]byte) bool {
	return maps.EqualFunc(a, b, func(x, y []byte) bool { return string(x) == string(y) })
}

// write settles and applies b; reset deletes every record instead. An
// error wraps fxstore.ErrNotCommitted when nothing of b is durable; any
// other error is an unknown outcome, which fences the store.
func (s *Store) write(ctx context.Context, b fxstore.Batch, reset bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fxstore.AsNotCommitted(ErrClosed)
	}
	if err := s.settleLocked(ctx); err != nil {
		return fxstore.AsNotCommitted(err)
	}
	before := s.d.State()
	if reset {
		b = fxstore.Batch{Deletes: slices.Collect(maps.Keys(before))}
	}
	o, err := s.d.Apply(ctx, b)
	switch o {
	case fxstore.Committed:
		return nil
	case fxstore.Unknown:
		s.restore = before
		return fmt.Errorf("pushstore: the outcome of the write is unknown; the store is fenced until it is settled: %w", err)
	default:
		return fmt.Errorf("pushstore: %w", err)
	}
}

// StoreChanges writes c in one atomic write: the trust lists and the
// certificates with their keys, and the deletions. With c.Reset it deletes
// every record instead.
func (s *Store) StoreChanges(ctx context.Context, c server.CertificateChanges) error {
	b := fxstore.Batch{Puts: map[string][]byte{}}
	if c.Reset {
		return s.write(ctx, b, true)
	}
	for _, x := range c.TrustLists {
		k, v, err := trustListRecord(x)
		if err != nil {
			return fxstore.AsNotCommitted(err)
		}
		b.Puts[k] = v
	}
	for _, x := range c.Certificates {
		k, v, err := certRecord(x)
		if err != nil {
			return fxstore.AsNotCommitted(err)
		}
		b.Puts[k] = v
	}
	return s.write(ctx, b, false)
}

// LoadCertificates returns what the store holds, sorted by key.
func (s *Store) LoadCertificates(context.Context) (server.CertificateChanges, error) {
	return decodeState(s.d.State())
}

// StoreTrustList writes the trust list of the DefaultApplicationGroup.
func (s *Store) StoreTrustList(ctx context.Context, tl *ua.TrustListDataType) error {
	return s.StoreChanges(ctx, server.CertificateChanges{TrustLists: []server.CertificateGroupTrustList{
		{Group: DefaultApplicationGroup, TrustList: tl, LastUpdateTime: time.Now()},
	}})
}

// StoreCertificate writes a certificate of the DefaultApplicationGroup.
func (s *Store) StoreCertificate(ctx context.Context, certificateType *ua.NodeID, cert []byte, issuers [][]byte, key crypto.Signer) error {
	if len(cert) == 0 {
		return fxstore.AsNotCommitted(errNoCertificate)
	}
	return s.StoreChanges(ctx, server.CertificateChanges{Certificates: []server.CertificateGroupChange{
		{Group: DefaultApplicationGroup, CertificateType: certificateType, Certificate: cert, Issuers: issuers, PrivateKey: key},
	}})
}

// StoreGroupTrustList writes the trust list of a certificate group, named
// by its NodeId (see GroupName).
func (s *Store) StoreGroupTrustList(ctx context.Context, certificateGroup *ua.NodeID, tl *ua.TrustListDataType) error {
	g, err := GroupName(certificateGroup)
	if err != nil {
		return fxstore.AsNotCommitted(err)
	}
	return s.StoreChanges(ctx, server.CertificateChanges{TrustLists: []server.CertificateGroupTrustList{
		{Group: g, TrustList: tl, LastUpdateTime: time.Now()},
	}})
}

// StoreGroupCertificate writes a certificate of a certificate group.
func (s *Store) StoreGroupCertificate(ctx context.Context, certificateGroup, certificateType *ua.NodeID, cert []byte, issuers [][]byte, key crypto.Signer) error {
	g, err := GroupName(certificateGroup)
	if err != nil {
		return fxstore.AsNotCommitted(err)
	}
	if len(cert) == 0 {
		return fxstore.AsNotCommitted(errNoCertificate)
	}
	return s.StoreChanges(ctx, server.CertificateChanges{Certificates: []server.CertificateGroupChange{
		{Group: g, CertificateType: certificateType, Certificate: cert, Issuers: issuers, PrivateKey: key},
	}})
}

// DeleteGroupCertificate records the deletion of the certificate of a type
// of a certificate group.
func (s *Store) DeleteGroupCertificate(ctx context.Context, certificateGroup, certificateType *ua.NodeID) error {
	g, err := GroupName(certificateGroup)
	if err != nil {
		return fxstore.AsNotCommitted(err)
	}
	return s.StoreChanges(ctx, server.CertificateChanges{Certificates: []server.CertificateGroupChange{
		{Group: g, CertificateType: certificateType},
	}})
}

// GroupName returns the BrowseName of the certificate group with the
// NodeId n: a null NodeId is the DefaultApplicationGroup (Part 12
// §7.10.4), the NodeIds of ServerConfiguration name the default groups,
// and the String NodeId "CertificateGroups.<Name>" a group of
// PushManagement.CertificateGroups, in any namespace.
func GroupName(n *ua.NodeID) (string, error) {
	switch {
	case n == nil || numeric0(n) && n.IntID() == 0:
		return DefaultApplicationGroup, nil
	case numeric0(n):
		switch n.IntID() {
		case id.ServerConfigurationCertificateGroupsDefaultApplicationGroup:
			return DefaultApplicationGroup, nil
		case id.ServerConfigurationCertificateGroupsDefaultHTTPSGroup:
			return DefaultHTTPSGroup, nil
		case id.ServerConfigurationCertificateGroupsDefaultUserTokenGroup:
			return DefaultUserTokenGroup, nil
		}
	case n.Type() == ua.NodeIDTypeString:
		if name, ok := strings.CutPrefix(n.StringID(), "CertificateGroups."); ok && name != "" {
			return name, nil
		}
	}
	return "", fmt.Errorf("pushstore: %v is not a certificate group", n)
}

// numeric0 reports whether n is a numeric NodeId of namespace 0.
func numeric0(n *ua.NodeID) bool {
	switch n.Type() {
	case ua.NodeIDTypeTwoByte, ua.NodeIDTypeFourByte, ua.NodeIDTypeNumeric:
		return n.Namespace() == 0
	case ua.NodeIDTypeString, ua.NodeIDTypeGUID, ua.NodeIDTypeByteString:
	}
	return false
}

// Record keys.
const (
	trustListPrefix = "tl/"
	certPrefix      = "cert/"
)

func trustListKey(group string) string { return trustListPrefix + url.PathEscape(group) }

func certKey(group string, certType uint32) string {
	return certPrefix + url.PathEscape(group) + "/" + strconv.FormatUint(uint64(certType), 10)
}

// parseKey parses the key of a record: the group, and for a certificate
// its type.
func parseKey(k string) (group string, certType uint32, isCert bool, err error) {
	bad := fmt.Errorf("%w: pushstore: record %q", fxstore.ErrCorrupt, k)
	if rest, ok := strings.CutPrefix(k, trustListPrefix); ok {
		g, err := url.PathUnescape(rest)
		if err != nil || g == "" || url.PathEscape(g) != rest {
			return "", 0, false, bad
		}
		return g, 0, false, nil
	}
	rest, ok := strings.CutPrefix(k, certPrefix)
	if !ok {
		return "", 0, false, bad
	}
	eg, et, ok := strings.Cut(rest, "/")
	if !ok {
		return "", 0, false, bad
	}
	g, err := url.PathUnescape(eg)
	if err != nil || g == "" || url.PathEscape(g) != eg {
		return "", 0, false, bad
	}
	t, err := strconv.ParseUint(et, 10, 32)
	if err != nil || t == 0 || strconv.FormatUint(t, 10) != et {
		return "", 0, false, bad
	}
	return g, uint32(t), true, nil
}

// decodeState decodes the records of the domain, sorted by key.
func decodeState(state map[string][]byte) (server.CertificateChanges, error) {
	var c server.CertificateChanges
	keys := slices.Sorted(maps.Keys(state))
	for _, k := range keys {
		g, t, isCert, err := parseKey(k)
		if err != nil {
			return server.CertificateChanges{}, err
		}
		if isCert {
			x, err := decodeCert(state[k])
			if err != nil {
				return server.CertificateChanges{}, fmt.Errorf("%w: record %q", err, k)
			}
			x.Group, x.CertificateType = g, ua.NewNumericNodeID(0, t)
			c.Certificates = append(c.Certificates, x)
			continue
		}
		x, err := decodeTrustList(state[k])
		if err != nil {
			return server.CertificateChanges{}, fmt.Errorf("%w: record %q", err, k)
		}
		x.Group = g
		c.TrustLists = append(c.TrustLists, x)
	}
	return c, nil
}

// trustListRecord returns the record of a trust list.
func trustListRecord(x server.CertificateGroupTrustList) (string, []byte, error) {
	if x.Group == "" {
		return "", nil, errors.New("pushstore: a trust list without a group")
	}
	v, err := encodeTrustList(x)
	if err != nil {
		return "", nil, err
	}
	return trustListKey(x.Group), v, nil
}

// certRecord returns the record of a certificate.
func certRecord(x server.CertificateGroupChange) (string, []byte, error) {
	t := x.CertificateType
	if x.Group == "" || t == nil || !numeric0(t) || t.IntID() == 0 {
		return "", nil, fmt.Errorf("pushstore: a certificate needs a group and a numeric CertificateType of namespace 0, not %q %v", x.Group, t)
	}
	v, err := encodeCert(x)
	if err != nil {
		return "", nil, err
	}
	return certKey(x.Group, t.IntID()), v, nil
}
