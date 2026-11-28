// SPDX-License-Identifier: MIT

package rolestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

const owner = "urn:otfabric:test:rolestore"

// nsA are the namespaces the roles of the tests are written in.
var nsA = []string{"http://opcfoundation.org/UA/", "urn:server", server.RolesNamespaceURI, "urn:app"}

// roles returns a well-known role, a role of a NodeSet with a small
// FourByte NodeId in namespace 3 and the roles AddRole added named by
// added, in namespace 2 with BrowseNames in namespace 3.
func roles(added ...string) []server.Role {
	out := []server.Role{
		{
			NodeID:     ua.RoleSecurityAdmin.NodeID(),
			BrowseName: &ua.QualifiedName{Name: "SecurityAdmin"},
			Identities: []*ua.IdentityMappingRuleType{
				{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "alice"},
				{CriteriaType: ua.IdentityCriteriaTypeAuthenticatedUser},
			},
			Applications: []string{"urn:client"},
			Endpoints: []*ua.EndpointType{{
				EndpointURL: "opc.tcp://localhost:4840", SecurityMode: ua.MessageSecurityModeSignAndEncrypt,
				SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			}},
			EndpointsExclude: true,
		},
		{NodeID: ua.NewFourByteNodeID(3, 5), BrowseName: &ua.QualifiedName{NamespaceIndex: 3, Name: "Plant"}, ApplicationsExclude: true, EndpointsExclude: true},
	}
	for _, name := range added {
		out = append(out, server.Role{
			NodeID: ua.NewStringNodeID(2, "3:"+name), BrowseName: &ua.QualifiedName{NamespaceIndex: 3, Name: name},
			Identities:          []*ua.IdentityMappingRuleType{{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: name}},
			ApplicationsExclude: true, EndpointsExclude: true, Removable: true,
		})
	}
	return out
}

// show returns roles as text, to compare them whatever the encoding of
// their NodeIds and whether their empty slices are nil.
func show(roles []server.Role) []string {
	out := []string{}
	for _, r := range roles {
		var ids, eps []string
		for _, x := range r.Identities {
			ids = append(ids, fmt.Sprintf("%d=%s", x.CriteriaType, x.Criteria))
		}
		for _, x := range r.Endpoints {
			eps = append(eps, fmt.Sprintf("%s|%d|%s|%s", x.EndpointURL, x.SecurityMode, x.SecurityPolicyURI, x.TransportProfileURI))
		}
		out = append(out, fmt.Sprintf("%s %d:%s ids=%v apps=%v/%t eps=%v/%t added=%t", r.NodeID, r.BrowseName.NamespaceIndex,
			r.BrowseName.Name, ids, r.Applications, r.ApplicationsExclude, eps, r.EndpointsExclude, r.Removable))
	}
	return out
}

func load(t *testing.T, s *Store) []server.Role {
	t.Helper()
	got, err := s.LoadRoleSet(context.Background(), nsA)
	require.NoError(t, err)
	return got
}

func openMem(t *testing.T, b fxstore.Store) *Store {
	t.Helper()
	s, err := Open(context.Background(), b, Options{Owner: owner})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = s.Close() })
	return s
}

// TestRoundTrip: the roles survive a reopen of the directory, in their
// order; the directory is 0700 and its files 0600; the same roles write
// nothing; a removal deletes the record.
func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "roles")
	s, err := OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	require.Nil(t, load(t, s), "an empty store holds no roles")

	rs := roles("B", "A")
	require.NoError(t, s.StoreRoleSet(ctx, rs, nsA))
	require.Equal(t, show(rs), show(load(t, s)))
	rev := s.Status().Revision
	require.NoError(t, s.StoreRoleSet(ctx, rs, nsA))
	require.Equal(t, rev, s.Status().Revision)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close())

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	ents, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, ents)
	for _, e := range ents {
		fi, err := e.Info()
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), e.Name())
	}

	s, err = OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.Equal(t, show(rs), show(load(t, s)))

	one := roles("A")
	require.NoError(t, s.StoreRoleSet(ctx, one, nsA))
	require.Equal(t, show(one), show(load(t, s)))
	require.Len(t, s.d.State(), 4)
	require.NoError(t, s.StoreRoleSet(ctx, nil, nsA))
	got := load(t, s)
	require.NotNil(t, got, "no roles is a RoleSet")
	require.Empty(t, got)
	require.Len(t, s.d.State(), 1)
}

// TestNamespaces: the NodeIds and BrowseNames are mapped to the
// NamespaceArray of the loader by URI, a namespace it does not have fails
// the load.
func TestNamespaces(t *testing.T) {
	ctx := context.Background()
	s := openMem(t, &fxstore.MemoryStore{})
	require.NoError(t, s.StoreRoleSet(ctx, roles("A"), nsA))

	// urn:app moves to 300, past what a FourByte NodeId holds; the roles
	// namespace to 1.
	to := make([]string, 301)
	for i := range to {
		to[i] = "urn:other:" + strconv.Itoa(i)
	}
	to[0], to[1], to[300] = nsA[0], server.RolesNamespaceURI, "urn:app"
	got, err := s.LoadRoleSet(ctx, to)
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.True(t, got[0].NodeID.Equal(ua.RoleSecurityAdmin.NodeID()))
	require.Equal(t, ua.NewNumericNodeID(300, 5).String(), got[1].NodeID.String())
	require.Equal(t, uint16(300), got[1].BrowseName.NamespaceIndex)
	require.Equal(t, "ns=1;s=3:A", got[2].NodeID.String(), "the identifier is kept (Part 3 §5.2.2)")
	require.Equal(t, uint16(300), got[2].BrowseName.NamespaceIndex)
	// The records do not depend on the indexes: written again in to they
	// are the same.
	before := s.d.State()
	require.NoError(t, s.StoreRoleSet(ctx, got, to))
	require.Equal(t, before, s.d.State())

	// A missing namespace fails, of the NodeId or of the BrowseName.
	_, err = s.LoadRoleSet(ctx, []string{nsA[0], nsA[1], "urn:app"})
	require.ErrorIs(t, err, ErrNamespace)
	_, err = s.LoadRoleSet(ctx, []string{nsA[0], nsA[1], server.RolesNamespaceURI})
	require.ErrorIs(t, err, ErrNamespace)
	only := roles()[1:]
	only[0].NodeID = ua.NewNumericNodeID(2, 5)
	require.NoError(t, s.StoreRoleSet(ctx, only, nsA))
	_, err = s.LoadRoleSet(ctx, []string{nsA[0], nsA[1], server.RolesNamespaceURI})
	require.ErrorIs(t, err, ErrNamespace)

	// A NamespaceArray past the indexes of a NodeId has no index for it.
	big := make([]string, 0x10001)
	for i := range big {
		big[i] = "urn:big:" + strconv.Itoa(i)
	}
	big[0] = nsA[0]
	big[0x10000] = server.RolesNamespaceURI
	_, err = s.LoadRoleSet(ctx, append(big, "urn:app"))
	require.ErrorIs(t, err, ErrNamespace)
}

// TestRecordsErrors: roles the store cannot write are not committed.
func TestRecordsErrors(t *testing.T) {
	ctx := context.Background()
	s := openMem(t, &fxstore.MemoryStore{})
	for name, edit := range map[string]func(r *server.Role){
		"no NodeId":           func(r *server.Role) { r.NodeID = nil },
		"no BrowseName":       func(r *server.Role) { r.BrowseName = nil },
		"empty BrowseName":    func(r *server.Role) { r.BrowseName = &ua.QualifiedName{} },
		"NodeId namespace":    func(r *server.Role) { r.NodeID = ua.NewNumericNodeID(9, 1) },
		"BrowseName namspace": func(r *server.Role) { r.BrowseName = &ua.QualifiedName{NamespaceIndex: 9, Name: "x"} },
	} {
		rs := roles()
		edit(&rs[1])
		err := s.StoreRoleSet(ctx, rs, nsA)
		require.Error(t, err, name)
		require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err), name)
	}
	rs := roles("A")
	rs = append(rs, rs[2])
	err := s.StoreRoleSet(ctx, rs, nsA)
	require.ErrorContains(t, err, "twice")
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
	require.Nil(t, load(t, s))
}

// failOnKey fails every Apply whose batch writes key: NotCommitted, or with
// an unknown outcome after the batch is applied (applied) or not.
type failOnKey struct {
	fxstore.Store
	mu    sync.Mutex
	key   string
	fault storetest.Fault
}

func (f *failOnKey) Apply(ctx context.Context, b fxstore.Batch) error {
	f.mu.Lock()
	key, fault := Namespace+"/"+f.key, f.fault
	f.mu.Unlock()
	_, put := b.Puts[key]
	if !put && !slices.Contains(b.Deletes, key) {
		return f.Store.Apply(ctx, b)
	}
	switch fault {
	case storetest.FailNotCommitted:
		return fxstore.AsNotCommitted(storetest.ErrInjected)
	case storetest.FailApplied:
		if err := f.Store.Apply(ctx, b); err != nil {
			return err
		}
	case storetest.FailLost, storetest.FailLoad:
	}
	return storetest.ErrInjected
}

func (f *failOnKey) set(key string, fault storetest.Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key, f.fault = key, fault
}

func mapStore(st map[string][]byte) fxstore.Store {
	m := &fxstore.MemoryStore{}
	_ = m.Apply(context.Background(), fxstore.Batch{Puts: st})
	return m
}

// TestFailedCommit: a backend that fails on any key of a change, for every
// outcome, leaves the roles before it: at once when nothing was written,
// after Settle when the outcome was unknown. Until it is settled the store
// refuses writes.
func TestFailedCommit(t *testing.T) {
	ctx := context.Background()
	base := roles("A", "B")
	upd := roles("A", "C")
	upd[0].Applications = nil
	key := func(r server.Role) string { return roleKey(nsA[r.NodeID.Namespace()], withNamespace(r.NodeID, 0)) }
	keys := []string{rootKey, key(upd[0]), key(base[3]), key(upd[3])}
	for _, fault := range []storetest.Fault{storetest.FailNotCommitted, storetest.FailLost, storetest.FailApplied} {
		for n, k := range keys {
			b := &failOnKey{Store: &fxstore.MemoryStore{}}
			s := openMem(t, b)
			require.NoError(t, s.StoreRoleSet(ctx, base, nsA))
			b.set(k, fault)
			err := s.StoreRoleSet(ctx, upd, nsA)
			require.Error(t, err, "key %d", n)
			require.Equal(t, show(base), show(load(t, s)))
			if fault == storetest.FailNotCommitted {
				require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
				require.False(t, s.Status().Fenced)
				continue
			}
			require.Equal(t, fxstore.Unknown, fxstore.OutcomeOf(err))
			require.True(t, s.Status().Fenced)
			b.set("", 0)
			ok, err := s.Settle(ctx)
			require.NoError(t, err)
			require.True(t, ok)
			require.False(t, s.Status().Fenced)
			require.Equal(t, show(base), show(load(t, s)))
			st, err := b.Load(ctx)
			require.NoError(t, err)
			require.Equal(t, show(base), show(load(t, openMem(t, mapStore(st)))))
			require.NoError(t, s.StoreRoleSet(ctx, upd, nsA))
			require.Equal(t, show(upd), show(load(t, s)))
		}
	}
}

// TestUnknownOutcome: a write with an unknown outcome fences the store;
// writes settle first and fail while the backend is unreachable; a write
// back that is unknown itself keeps the store fenced.
func TestUnknownOutcome(t *testing.T) {
	ctx := context.Background()
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	s := openMem(t, f)
	base, upd := roles("A"), roles("A", "B")
	require.NoError(t, s.StoreRoleSet(ctx, base, nsA))

	f.FailApply(storetest.FailApplied)
	require.Equal(t, fxstore.Unknown, fxstore.OutcomeOf(s.StoreRoleSet(ctx, upd, nsA)))
	require.True(t, s.Status().Fenced)

	f.FailLoads(2)
	ok, err := s.Settle(ctx)
	require.False(t, ok)
	require.ErrorIs(t, err, storetest.ErrInjected)
	err = s.StoreRoleSet(ctx, upd, nsA)
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
	require.True(t, s.Status().Fenced)

	// The domain settles, the write back is unknown and lands: still
	// fenced; the next Settle confirms it.
	f.FailApply(0, storetest.FailApplied)
	ok, err = s.Settle(ctx)
	require.False(t, ok)
	require.Error(t, err)
	require.True(t, s.Status().Fenced)
	ok, err = s.Settle(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, show(base), show(load(t, s)))

	// Lost: nothing to write back, the next write settles and applies.
	f.FailApply(storetest.FailLost)
	require.Equal(t, fxstore.Unknown, fxstore.OutcomeOf(s.StoreRoleSet(ctx, upd, nsA)))
	n := f.Applies()
	require.NoError(t, s.StoreRoleSet(ctx, upd, nsA))
	require.Equal(t, n+2, f.Applies(), "a confirmation and the write")
	require.Equal(t, show(upd), show(load(t, s)))

	// Not fenced: Settle writes nothing.
	n = f.Applies()
	ok, err = s.Settle(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, n, f.Applies())

	require.NoError(t, s.Close())
	_, err = s.Settle(ctx)
	require.ErrorIs(t, err, ErrClosed)
	err = s.StoreRoleSet(ctx, upd, nsA)
	require.ErrorIs(t, err, ErrClosed)
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
	_, err = f.Load(ctx)
	require.NoError(t, err, "Close of Open leaves the backend open")
}

// TestOpenErrors: a backend that does not load, of another owner, with
// keys of another namespace or records that do not decode is refused.
func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	f.FailLoads(1)
	_, err := Open(ctx, f, Options{Owner: owner})
	require.ErrorIs(t, err, storetest.ErrInjected)

	good := &fxstore.MemoryStore{}
	s := openMem(t, good)
	rs := roles("A")
	require.NoError(t, s.StoreRoleSet(ctx, rs, nsA))
	_, err = Open(ctx, good, Options{Owner: "urn:other"})
	require.ErrorIs(t, err, fxstore.ErrForeignOwner)
	st, err := good.Load(ctx)
	require.NoError(t, err)

	with := func(edit func(map[string][]byte)) error {
		cp := map[string][]byte{}
		for k, v := range st {
			cp[k] = bytes.Clone(v)
		}
		edit(cp)
		_, err := Open(ctx, mapStore(cp), Options{Owner: owner})
		return err
	}
	k := func(rel string) string { return Namespace + "/" + rel }
	keyOf := func(r server.Role) string { return roleKey(nsA[r.NodeID.Namespace()], withNamespace(r.NodeID, 0)) }
	a, admin := keyOf(rs[2]), keyOf(rs[0])
	require.Error(t, with(func(m map[string][]byte) { m["other/x"] = []byte{1} }))
	for name, edit := range map[string]func(map[string][]byte){
		"no root":        func(m map[string][]byte) { delete(m, k(rootKey)) },
		"bad root":       func(m map[string][]byte) { m[k(rootKey)] = []byte{9} },
		"extra record":   func(m map[string][]byte) { m[k("role/zz")] = []byte{1} },
		"missing record": func(m map[string][]byte) { delete(m, k(a)) },
		"bad record":     func(m map[string][]byte) { m[k(a)] = []byte{1, 0, 7} },
		"moved record":   func(m map[string][]byte) { m[k(a)] = m[k(admin)] },
		"twice":          func(m map[string][]byte) { m[k(rootKey)] = encodeRoot([]string{a, a}) },
	} {
		require.ErrorIs(t, with(edit), fxstore.ErrCorrupt, name)
	}

	// OpenDir: a directory that cannot be one, and a store of another
	// owner (the FileStore is closed again: a second open works).
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err = OpenDir(ctx, file, Options{Owner: owner})
	require.Error(t, err)
	dir := t.TempDir()
	d, err := OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	require.NoError(t, d.StoreRoleSet(ctx, roles("A"), nsA))
	require.NoError(t, d.Close())
	_, err = OpenDir(ctx, dir, Options{Owner: "urn:other"})
	require.ErrorIs(t, err, fxstore.ErrForeignOwner)
	d, err = OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	require.NoError(t, d.Close())
}

// TestRecordErrors: records that do not decode.
func TestRecordErrors(t *testing.T) {
	for _, b := range [][]byte{nil, {2}, {1, 0x80}, {1, 5, 1}, {1, 0, 0}} {
		_, err := decodeRoot(b)
		require.ErrorIs(t, err, fxstore.ErrCorrupt, "%x", b)
	}
	keys, err := decodeRoot(encodeRoot([]string{"a", ""}))
	require.NoError(t, err)
	require.Equal(t, []string{"a", ""}, keys)

	rec := func(nid *ua.NodeID, name string) []byte {
		x := &record{flags: flagRemovable, nodeNS: "urn:a", nameNS: "urn:b", b: body{NodeID: nid, BrowseName: name}}
		b, err := x.encode()
		require.NoError(t, err)
		return b
	}
	ok := rec(ua.NewStringNodeID(0, "x"), "x")
	for _, b := range [][]byte{
		nil, {2, 0}, {1, 8}, {1, 0, 0x80}, {1, 0, 0, 5}, {1, 0, 0, 0, 0xff},
		append(bytes.Clone(ok), 0),
		rec(ua.NewStringNodeID(1, "x"), "x"),
		rec(ua.NewStringNodeID(0, "x"), ""),
	} {
		_, err := decodeRecord(b)
		require.ErrorIs(t, err, fxstore.ErrCorrupt, "%x", b)
	}
	x, err := decodeRecord(ok)
	require.NoError(t, err)
	require.Equal(t, "urn:a", x.nodeNS)
	require.Equal(t, "urn:b", x.nameNS)
	require.Equal(t, byte(flagRemovable), x.flags)
}

// TestEncodeError: roles that do not encode are not committed.
func TestEncodeError(t *testing.T) {
	ctx := context.Background()
	s := openMem(t, &fxstore.MemoryStore{})
	defer func(e func(any) ([]byte, error)) { encode = e }(encode)
	fail := errors.New("no")
	encode = func(any) ([]byte, error) { return nil, fail }
	err := s.StoreRoleSet(ctx, roles(), nsA)
	require.ErrorIs(t, err, fail)
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
	require.Nil(t, load(t, s))
}

// blockingStore holds an Apply until release is closed.
type blockingStore struct {
	fxstore.Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingStore) Apply(ctx context.Context, batch fxstore.Batch) error {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.Store.Apply(ctx, batch)
}

// TestConcurrent: a load during a write sees the roles before it; writers
// and readers run together (under -race in CI) and the store ends with one
// of the RoleSets written, whole.
func TestConcurrent(t *testing.T) {
	ctx := context.Background()
	b := &blockingStore{Store: &fxstore.MemoryStore{}, entered: make(chan struct{}), release: make(chan struct{})}
	s := openMem(t, b)
	done := make(chan error)
	go func() { done <- s.StoreRoleSet(ctx, roles("A"), nsA) }()
	<-b.entered
	require.Nil(t, load(t, s), "the write in progress is not visible")
	close(b.release)
	require.NoError(t, <-done)
	require.Equal(t, show(roles("A")), show(load(t, s)))

	sets := [][]server.Role{roles("A"), roles("B", "C"), roles("C"), roles()}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 20 {
				if i%2 == 0 {
					require.NoError(t, s.StoreRoleSet(ctx, sets[(i+j)%len(sets)], nsA))
					continue
				}
				_, err := s.LoadRoleSet(ctx, nsA)
				require.NoError(t, err)
			}
		})
	}
	wg.Wait()
	final := show(load(t, s))
	require.True(t, slices.ContainsFunc(sets, func(rs []server.Role) bool { return slices.Equal(show(rs), final) }))
}
