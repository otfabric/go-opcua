// SPDX-License-Identifier: MIT

package pushstore

import (
	"context"
	"crypto"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

const owner = "urn:otfabric:test:pushstore"

var (
	rsaType   = ua.NewNumericNodeID(0, id.RsaSha256ApplicationCertificateType)
	p256Type  = ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType)
	httpsType = ua.NewNumericNodeID(0, id.HTTPSCertificateType)
)

func pki(t *testing.T) *testpki.PKI {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	return p
}

// changes returns changes of three groups, with certificates of every key
// kind the server has (RSA, ECDSA on a NIST and a Brainpool curve, Ed25519,
// Ed448) and a deletion.
func changes(t *testing.T) server.CertificateChanges {
	t.Helper()
	p := pki(t)
	when := time.Date(2026, 11, 28, 1, 2, 3, 4, time.UTC)
	c := server.CertificateChanges{
		TrustLists: []server.CertificateGroupTrustList{
			{Group: DefaultApplicationGroup, TrustList: &ua.TrustListDataType{
				TrustedCertificates: [][]byte{p.ClientCert, p.CACert},
				IssuerCertificates:  [][]byte{p.CACert},
				TrustedCrls:         [][]byte{},
				IssuerCrls:          [][]byte{},
			}, LastUpdateTime: when},
			{Group: DefaultUserTokenGroup, TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.UserCert}}},
			{Group: "Group/with space", TrustList: nil, LastUpdateTime: when},
		},
		Certificates: []server.CertificateGroupChange{
			{Group: DefaultApplicationGroup, CertificateType: rsaType, Certificate: p.ServerCert, Issuers: [][]byte{p.CACert}, PrivateKey: p.ServerKey},
			{Group: DefaultHTTPSGroup, CertificateType: httpsType},
		},
	}
	types := map[string]uint32{
		testpki.CurveP256:            id.EccNistP256ApplicationCertificateType,
		testpki.CurveBrainpoolP256r1: id.EccBrainpoolP256r1ApplicationCertificateType,
		testpki.CurveEd25519:         id.EccCurve25519ApplicationCertificateType,
		testpki.CurveEd448:           id.EccCurve448ApplicationCertificateType,
	}
	for curve, typ := range types {
		x := p.ECC.Server[curve]
		c.Certificates = append(c.Certificates, server.CertificateGroupChange{Group: "Ecc", CertificateType: ua.NewNumericNodeID(0, typ), Certificate: x.Cert, PrivateKey: x.Key})
	}
	return c
}

// normalized is c as LoadCertificates returns it: sorted by key, with the
// trust lists complete.
func normalized(c server.CertificateChanges) server.CertificateChanges {
	out := server.CertificateChanges{}
	for _, x := range c.TrustLists {
		tl := x.TrustList
		if tl == nil {
			tl = &ua.TrustListDataType{}
		}
		x.TrustList = &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksAll),
			TrustedCertificates: tl.TrustedCertificates, TrustedCrls: tl.TrustedCrls,
			IssuerCertificates: tl.IssuerCertificates, IssuerCrls: tl.IssuerCrls}
		out.TrustLists = append(out.TrustLists, x)
	}
	slices.SortFunc(out.TrustLists, func(a, b server.CertificateGroupTrustList) int {
		return compare(trustListKey(a.Group), trustListKey(b.Group))
	})
	out.Certificates = slices.Clone(c.Certificates)
	slices.SortFunc(out.Certificates, func(a, b server.CertificateGroupChange) int {
		return compare(certKey(a.Group, a.CertificateType.IntID()), certKey(b.Group, b.CertificateType.IntID()))
	})
	return out
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// requireSame checks that got holds the trust lists and certificates of
// want.
func requireSame(t *testing.T, want, got server.CertificateChanges) {
	t.Helper()
	want = normalized(want)
	require.Len(t, got.TrustLists, len(want.TrustLists))
	for i, w := range want.TrustLists {
		g := got.TrustLists[i]
		require.Equal(t, w.Group, g.Group)
		require.Equal(t, w.LastUpdateTime.UnixNano(), g.LastUpdateTime.UnixNano())
		require.Equal(t, w.TrustList.TrustedCertificates, g.TrustList.TrustedCertificates)
		require.Equal(t, w.TrustList.IssuerCertificates, g.TrustList.IssuerCertificates)
		require.Equal(t, len(w.TrustList.TrustedCrls), len(g.TrustList.TrustedCrls))
		require.Equal(t, len(w.TrustList.IssuerCrls), len(g.TrustList.IssuerCrls))
	}
	require.Len(t, got.Certificates, len(want.Certificates))
	for i, w := range want.Certificates {
		g := got.Certificates[i]
		require.Equal(t, w.Group, g.Group)
		require.True(t, w.CertificateType.Equal(g.CertificateType), "%v %v", w.CertificateType, g.CertificateType)
		require.Equal(t, w.Certificate, g.Certificate)
		require.Equal(t, len(w.Issuers), len(g.Issuers))
		require.Equal(t, w.Deleted(), g.Deleted())
		if !w.Deleted() {
			require.True(t, w.PrivateKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(g.PrivateKey.Public()))
		}
	}
}

func load(t *testing.T, s *Store) server.CertificateChanges {
	t.Helper()
	c, err := s.LoadCertificates(context.Background())
	require.NoError(t, err)
	return c
}

func openMem(t *testing.T, b fxstore.Store) *Store {
	t.Helper()
	s, err := Open(context.Background(), b, Options{Owner: owner})
	require.NoError(t, err)
	return s
}

// TestRoundTrip: what StoreChanges writes, LoadCertificates returns, also
// after the directory is opened again; the data file is 0600 in a 0700
// directory.
func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "push")
	s, err := OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	require.Empty(t, load(t, s).TrustLists)
	c := changes(t)
	require.NoError(t, s.StoreChanges(ctx, c))
	requireSame(t, c, load(t, s))
	require.Equal(t, uint64(1), s.Status().Revision)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close())

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	fi, err = os.Stat(filepath.Join(dir, "state"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	s2, err := OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	defer func() { _ = s2.Close() }()
	requireSame(t, c, load(t, s2))

	// A second change replaces records and keeps the others.
	p := pki(t)
	upd := server.CertificateChanges{TrustLists: []server.CertificateGroupTrustList{{Group: DefaultApplicationGroup,
		TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.StrangerCert}}}}}
	require.NoError(t, s2.StoreChanges(ctx, upd))
	want := changes(t)
	want.TrustLists[0] = upd.TrustLists[0]
	requireSame(t, want, load(t, s2))

	// Reset forgets every record.
	require.NoError(t, s2.StoreChanges(ctx, server.CertificateChanges{Reset: true, TrustLists: upd.TrustLists}))
	got := load(t, s2)
	require.Empty(t, got.TrustLists)
	require.Empty(t, got.Certificates)

	// Another owner, another directory in use.
	_, err = OpenDir(ctx, dir, Options{Owner: owner})
	require.ErrorIs(t, err, fxstore.ErrLocked)
	require.NoError(t, s2.Close())
	_, err = OpenDir(ctx, dir, Options{Owner: "urn:other"})
	require.ErrorIs(t, err, fxstore.ErrForeignOwner)
	// The failed Open released the directory.
	s3, err := OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	require.NoError(t, s3.Close())
	// A directory that cannot be created.
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err = OpenDir(ctx, file, Options{})
	require.Error(t, err)
}

// TestSingleMethods: the methods of CertificateStore, CertificateGroupStore
// and CertificateDeleteStore write one record each.
func TestSingleMethods(t *testing.T) {
	ctx := context.Background()
	p := pki(t)
	s := openMem(t, &fxstore.MemoryStore{})
	tl := &ua.TrustListDataType{TrustedCertificates: [][]byte{p.CACert}}
	require.NoError(t, s.StoreTrustList(ctx, tl))
	require.NoError(t, s.StoreCertificate(ctx, rsaType, p.ServerCert, nil, p.ServerKey))
	https := ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroup)
	require.NoError(t, s.StoreGroupTrustList(ctx, https, tl))
	require.NoError(t, s.StoreGroupCertificate(ctx, https, httpsType, p.ServerCert, [][]byte{p.CACert}, p.ServerKey))
	custom := ua.NewStringNodeID(3, "CertificateGroups.Outgoing")
	require.NoError(t, s.StoreGroupCertificate(ctx, custom, p256Type, p.ECC.Server[testpki.CurveP256].Cert, nil, p.ECC.Server[testpki.CurveP256].Key))
	require.NoError(t, s.DeleteGroupCertificate(ctx, custom, p256Type))
	require.Equal(t, uint64(6), s.Status().Revision)

	got := load(t, s)
	require.Len(t, got.TrustLists, 2)
	require.Equal(t, DefaultApplicationGroup, got.TrustLists[0].Group)
	require.False(t, got.TrustLists[0].LastUpdateTime.IsZero())
	require.Equal(t, DefaultHTTPSGroup, got.TrustLists[1].Group)
	require.Len(t, got.Certificates, 3)
	require.Equal(t, DefaultApplicationGroup, got.Certificates[0].Group)
	require.Equal(t, DefaultHTTPSGroup, got.Certificates[1].Group)
	require.Equal(t, [][]byte{p.CACert}, got.Certificates[1].Issuers)
	require.Equal(t, "Outgoing", got.Certificates[2].Group)
	require.True(t, got.Certificates[2].Deleted())

	// Arguments the store cannot keep: not committed, nothing written.
	for _, err := range []error{
		s.StoreCertificate(ctx, rsaType, nil, nil, p.ServerKey),
		s.StoreGroupCertificate(ctx, https, httpsType, nil, nil, p.ServerKey),
		s.StoreGroupCertificate(ctx, ua.NewStringNodeID(1, "x"), httpsType, p.ServerCert, nil, p.ServerKey),
		s.StoreGroupTrustList(ctx, ua.NewNumericNodeID(1, 5), tl),
		s.DeleteGroupCertificate(ctx, ua.NewGUIDNodeID(0, "72962B91-FA75-4AE6-8D28-B404DC7DAF63"), p256Type),
		s.StoreCertificate(ctx, ua.NewStringNodeID(0, "x"), p.ServerCert, nil, p.ServerKey),
		s.StoreCertificate(ctx, ua.NewNumericNodeID(0, 0), p.ServerCert, nil, p.ServerKey),
		s.StoreCertificate(ctx, nil, p.ServerCert, nil, p.ServerKey),
		s.StoreCertificate(ctx, rsaType, p.ServerCert, nil, nil),
		s.StoreCertificate(ctx, rsaType, p.ServerCert, nil, opaqueSigner{p.ServerKey}),
		s.StoreChanges(ctx, server.CertificateChanges{TrustLists: []server.CertificateGroupTrustList{{}}}),
		s.StoreChanges(ctx, server.CertificateChanges{TrustLists: []server.CertificateGroupTrustList{{Group: "x",
			TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{make([]byte, 5<<20)}}}}}),
	} {
		require.Error(t, err)
		require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err), "%v", err)
	}
	require.Equal(t, uint64(6), s.Status().Revision)
	require.False(t, s.Status().Fenced)
}

// opaqueSigner is a key that cannot be exported (a key in a hardware
// module).
type opaqueSigner struct{ crypto.Signer }

func TestGroupName(t *testing.T) {
	for _, tc := range []struct {
		n    *ua.NodeID
		want string
	}{
		{nil, DefaultApplicationGroup},
		{ua.NewTwoByteNodeID(0), DefaultApplicationGroup},
		{ua.NewNumericNodeID(0, 0), DefaultApplicationGroup},
		{ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroup), DefaultApplicationGroup},
		{ua.NewFourByteNodeID(0, id.ServerConfigurationCertificateGroupsDefaultHTTPSGroup), DefaultHTTPSGroup},
		{ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultUserTokenGroup), DefaultUserTokenGroup},
		{ua.NewStringNodeID(2, "CertificateGroups.A.B"), "A.B"},
	} {
		got, err := GroupName(tc.n)
		require.NoError(t, err, "%v", tc.n)
		require.Equal(t, tc.want, got)
	}
	for _, n := range []*ua.NodeID{
		ua.NewNumericNodeID(0, id.ServerConfiguration),
		ua.NewNumericNodeID(1, 0),
		ua.NewStringNodeID(2, "CertificateGroups."),
		ua.NewStringNodeID(2, "Other"),
		ua.NewByteStringNodeID(0, []byte{1}),
	} {
		_, err := GroupName(n)
		require.Error(t, err, "%v", n)
	}
}

// failOnKey fails every Apply whose batch writes key: NotCommitted, or with
// an unknown outcome after the batch is applied (applied) or not.
type failOnKey struct {
	fxstore.Store
	mu      sync.Mutex
	key     string
	fault   storetest.Fault
	applies int
}

func (f *failOnKey) Apply(ctx context.Context, b fxstore.Batch) error {
	f.mu.Lock()
	f.applies++
	key, fault := f.key, f.fault
	f.mu.Unlock()
	key = Namespace + "/" + key
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

// TestFailedCommit: a backend that fails on the n-th key of an
// ApplyChanges, for every n and every outcome, leaves the records of the
// state before it: at once when nothing was written, after Settle when the
// outcome was unknown. Until it is settled the store refuses writes.
func TestFailedCommit(t *testing.T) {
	ctx := context.Background()
	p := pki(t)
	base := server.CertificateChanges{TrustLists: []server.CertificateGroupTrustList{
		{Group: DefaultApplicationGroup, TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}}},
	}}
	upd := changes(t)
	var keys []string
	for _, x := range upd.TrustLists {
		keys = append(keys, trustListKey(x.Group))
	}
	for _, x := range upd.Certificates {
		keys = append(keys, certKey(x.Group, x.CertificateType.IntID()))
	}
	for _, fault := range []storetest.Fault{storetest.FailNotCommitted, storetest.FailLost, storetest.FailApplied} {
		for n, key := range keys {
			b := &failOnKey{Store: &fxstore.MemoryStore{}}
			s := openMem(t, b)
			require.NoError(t, s.StoreChanges(ctx, base))
			b.set(key, fault)
			err := s.StoreChanges(ctx, upd)
			require.Error(t, err, "key %d", n)
			requireSame(t, base, load(t, s))
			if fault == storetest.FailNotCommitted {
				require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
				require.False(t, s.Status().Fenced)
				continue
			}
			require.Equal(t, fxstore.Unknown, fxstore.OutcomeOf(err))
			require.True(t, s.Status().Fenced)
			// The backend is back; Settle restores the state before the
			// write, whether it landed or not.
			b.set("", 0)
			ok, err := s.Settle(ctx)
			require.NoError(t, err)
			require.True(t, ok)
			require.False(t, s.Status().Fenced)
			requireSame(t, base, load(t, s))
			st, err := b.Load(ctx)
			require.NoError(t, err)
			ref := openMem(t, mapStore(st))
			requireSame(t, base, load(t, ref))
			// Settled: the next write is accepted.
			require.NoError(t, s.StoreChanges(ctx, upd))
			requireSame(t, upd, load(t, s))
		}
	}
}

// mapStore is a MemoryStore holding st.
func mapStore(st map[string][]byte) fxstore.Store {
	m := &fxstore.MemoryStore{}
	_ = m.Apply(context.Background(), fxstore.Batch{Puts: st})
	return m
}

// TestUnknownOutcome: a write with an unknown outcome fences the store;
// writes settle first and fail while the backend is still unreachable; a
// write back that is unknown itself keeps the store fenced.
func TestUnknownOutcome(t *testing.T) {
	ctx := context.Background()
	p := pki(t)
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	s := openMem(t, f)
	base := server.CertificateChanges{TrustLists: []server.CertificateGroupTrustList{
		{Group: DefaultApplicationGroup, TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}}}}}
	require.NoError(t, s.StoreChanges(ctx, base))
	upd := changes(t)

	// Landed, but unknown.
	f.FailApply(storetest.FailApplied)
	require.Equal(t, fxstore.Unknown, fxstore.OutcomeOf(s.StoreChanges(ctx, upd)))
	require.True(t, s.Status().Fenced)

	// The backend cannot be loaded: Settle fails, a write is not committed
	// and keeps the store fenced.
	f.FailLoads(2)
	ok, err := s.Settle(ctx)
	require.False(t, ok)
	require.ErrorIs(t, err, storetest.ErrInjected)
	err = s.StoreChanges(ctx, upd)
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
	require.True(t, s.Status().Fenced)

	// The domain settles, the write back has an unknown outcome and lands:
	// still fenced; the next Settle confirms it.
	f.FailApply(0, storetest.FailApplied)
	ok, err = s.Settle(ctx)
	require.False(t, ok)
	require.Error(t, err)
	require.True(t, s.Status().Fenced)
	// Until it is settled the store knows the landed write committed.
	requireSame(t, upd, load(t, s))
	ok, err = s.Settle(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	requireSame(t, base, load(t, s))

	// Lost, unknown: nothing to write back, the next write settles and
	// is applied.
	f.FailApply(storetest.FailLost)
	require.Equal(t, fxstore.Unknown, fxstore.OutcomeOf(s.StoreChanges(ctx, upd)))
	require.True(t, s.Status().Fenced)
	n := f.Applies()
	require.NoError(t, s.StoreChanges(ctx, upd))
	require.Equal(t, n+2, f.Applies(), "a confirmation and the write")
	requireSame(t, upd, load(t, s))

	// A reset with an unknown outcome is written back too.
	f.FailApply(storetest.FailApplied)
	require.Error(t, s.StoreChanges(ctx, server.CertificateChanges{Reset: true}))
	ok, err = s.Settle(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	requireSame(t, upd, load(t, s))

	// Settle of a store that is not fenced writes nothing.
	n = f.Applies()
	ok, err = s.Settle(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, n, f.Applies())

	require.NoError(t, s.Close())
	_, err = s.Settle(ctx)
	require.ErrorIs(t, err, ErrClosed)
	err = s.StoreChanges(ctx, upd)
	require.ErrorIs(t, err, ErrClosed)
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
	// Close of Open leaves the backend open.
	_, err = f.Load(ctx)
	require.NoError(t, err)
}

// TestOpenErrors: a backend that does not load, holds keys of another
// namespace or a record that does not decode is refused.
func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	f := storetest.NewFaulty(&fxstore.MemoryStore{})
	f.FailLoads(1)
	_, err := Open(ctx, f, Options{})
	require.ErrorIs(t, err, storetest.ErrInjected)

	_, err = Open(ctx, mapStore(map[string][]byte{"cm/x": {1}}), Options{})
	require.Error(t, err)

	// A record the format does not know, written through a domain.
	m := &fxstore.MemoryStore{}
	d, err := fxstore.OpenDomain(ctx, m, fxstore.DomainOptions{Namespace: Namespace, Owner: owner, Schema: Schema})
	require.NoError(t, err)
	_, err = d.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"tl/x": {9}}})
	require.NoError(t, err)
	_, err = Open(ctx, m, Options{Owner: owner})
	require.ErrorIs(t, err, fxstore.ErrCorrupt)

	// A corrupt directory: OpenDir fails and releases it.
	dir := t.TempDir()
	fs, err := fxstore.OpenFile(dir, fxstore.Limits{})
	require.NoError(t, err)
	d, err = fxstore.OpenDomain(ctx, fs, fxstore.DomainOptions{Namespace: Namespace, Owner: owner, Schema: Schema})
	require.NoError(t, err)
	_, err = d.Apply(ctx, fxstore.Batch{Puts: map[string][]byte{"cert/x/1": {1, 1}}})
	require.NoError(t, err)
	require.NoError(t, fs.Close())
	_, err = OpenDir(ctx, dir, Options{Owner: owner})
	require.ErrorIs(t, err, fxstore.ErrCorrupt)
	fs, err = fxstore.OpenFile(dir, fxstore.Limits{})
	require.NoError(t, err)
	require.NoError(t, fs.Close())
}

// blockingStore blocks its Applies until release is closed, after
// signalling entered.
type blockingStore struct {
	fxstore.Store
	entered chan struct{}
	release chan struct{}
}

func (b *blockingStore) Apply(ctx context.Context, batch fxstore.Batch) error {
	b.entered <- struct{}{}
	<-b.release
	return b.Store.Apply(ctx, batch)
}

// TestConcurrent: a load during a write sees the state before it, and
// concurrent writers and readers keep the store consistent (-race).
func TestConcurrent(t *testing.T) {
	ctx := context.Background()
	p := pki(t)
	b := &blockingStore{Store: &fxstore.MemoryStore{}, entered: make(chan struct{}), release: make(chan struct{})}
	s := openMem(t, b)
	done := make(chan error, 1)
	upd := changes(t)
	go func() { done <- s.StoreChanges(ctx, upd) }()
	<-b.entered
	require.Empty(t, load(t, s).TrustLists, "a load during the write sees the state before it")
	require.Zero(t, s.Status().Revision)
	close(b.release)
	require.NoError(t, <-done)
	requireSame(t, upd, load(t, s))

	s2 := openMem(t, &fxstore.MemoryStore{})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tl := &ua.TrustListDataType{TrustedCertificates: [][]byte{p.ClientCert}}
			if i%2 == 1 {
				tl.TrustedCertificates = append(tl.TrustedCertificates, p.CACert)
			}
			assert.NoError(t, s2.StoreChanges(ctx, server.CertificateChanges{TrustLists: []server.CertificateGroupTrustList{
				{Group: DefaultApplicationGroup, TrustList: tl}, {Group: DefaultUserTokenGroup, TrustList: tl}}}))
		}()
		go func() {
			defer wg.Done()
			c, err := s2.LoadCertificates(ctx)
			assert.NoError(t, err)
			if len(c.TrustLists) == 2 {
				// Both groups come from the same write.
				assert.Equal(t, c.TrustLists[0].TrustList.TrustedCertificates, c.TrustLists[1].TrustList.TrustedCertificates)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, uint64(8), s2.Status().Revision)
}
