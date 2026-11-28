// SPDX-License-Identifier: MIT

package pubsubstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

const owner = "urn:otfabric:test:pubsubstore"

// nsA are the namespaces the configurations of the tests are written in.
var nsA = []string{"http://opcfoundation.org/UA/", "urn:server", "urn:a", "urn:b"}

// config returns a configuration with NodeIds in the namespaces 2 and 3 of
// nsA: published variables, targets of a reader, a NodeId in a Variant of
// the ConnectionProperties and an ExpandedNodeId.
func config(conns ...string) *ua.PubSubConfigurationDataType {
	pds := pubsub.PublishedDataItems("Data",
		pubsub.Var("x", ua.NewStringNodeID(2, "x"), ua.TypeIDDouble),
		pubsub.Var("y", ua.NewFourByteNodeID(3, 10), ua.TypeIDInt32))
	cfg := &ua.PubSubConfigurationDataType{Enabled: true, PublishedDataSets: []*ua.PublishedDataSetDataType{pds}}
	for i, name := range conns {
		c := pubsub.UDPConnection(name, "opc.udp://239.0.0.1:4840", uint16(i+1))
		c.ConnectionProperties = []*ua.KeyValuePair{
			{Key: &ua.QualifiedName{NamespaceIndex: 2, Name: "Node"}, Value: ua.MustVariant(ua.NewNumericNodeID(2, 7))},
			{Key: &ua.QualifiedName{Name: "Where"}, Value: ua.MustVariant(&ua.ExpandedNodeID{NodeID: ua.NewNumericNodeID(3, 1)})},
		}
		c.WriterGroups = []*ua.WriterGroupDataType{pubsub.WriterGroup("G", uint16(i+1), time.Second, pubsub.DataSetWriter("W", uint16(i+1), "Data"))}
		r := pubsub.DataSetReader("R", uint16(9), 1, 1, pubsub.MetaData("Data", pubsub.Field{Name: "x", Type: ua.TypeIDDouble}))
		r.SubscribedDataSet = ua.NewExtensionObject(&ua.TargetVariablesDataType{TargetVariables: []*ua.FieldTargetDataType{pubsub.Target(ua.NewStringNodeID(3, "t"))}})
		c.ReaderGroups = []*ua.ReaderGroupDataType{pubsub.ReaderGroup("RG", r)}
		cfg.Connections = append(cfg.Connections, c)
	}
	return cfg
}

func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, err := ua.Encode(v)
	require.NoError(t, err)
	return b
}

func requireSame(t *testing.T, want, got *ua.PubSubConfigurationDataType) {
	t.Helper()
	require.NotNil(t, got)
	require.Equal(t, encoded(t, want), encoded(t, got))
}

func load(t *testing.T, s *Store) *ua.PubSubConfigurationDataType {
	t.Helper()
	cfg, err := s.LoadPubSubConfiguration(context.Background(), nsA)
	require.NoError(t, err)
	return cfg
}

func openMem(t *testing.T, b fxstore.Store) *Store {
	t.Helper()
	s, err := Open(context.Background(), b, Options{Owner: owner})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = s.Close() })
	return s
}

// TestRoundTrip: a configuration survives a reopen of the directory, with
// its order and Enabled; the directory is 0700 and its files 0600; a
// change rewrites only the records that change.
func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "pubsub")
	s, err := OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	got, err := s.LoadPubSubConfiguration(ctx, nsA)
	require.NoError(t, err)
	require.Nil(t, got, "an empty store holds no configuration")

	cfg := config("B", "A")
	require.NoError(t, s.StorePubSubConfiguration(ctx, cfg, nsA))
	requireSame(t, cfg, load(t, s))
	rev := s.Status().Revision
	// The same configuration writes nothing.
	require.NoError(t, s.StorePubSubConfiguration(ctx, cfg, nsA))
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
	requireSame(t, cfg, load(t, s))

	// A removal deletes the record; nothing but the root remains for an
	// empty, disabled configuration, which is a configuration.
	one := config("A")
	require.NoError(t, s.StorePubSubConfiguration(ctx, one, nsA))
	requireSame(t, one, load(t, s))
	require.Len(t, s.d.State(), 3)
	empty := &ua.PubSubConfigurationDataType{}
	require.NoError(t, s.StorePubSubConfiguration(ctx, empty, nsA))
	got = load(t, s)
	require.NotNil(t, got)
	require.False(t, got.Enabled)
	require.Empty(t, got.Connections)
	require.Len(t, s.d.State(), 1)
}

// TestNamespaces: the NodeIds are mapped to the NamespaceArray of the
// loader, a NodeId of a namespace it does not have fails the load.
func TestNamespaces(t *testing.T) {
	ctx := context.Background()
	s := openMem(t, &fxstore.MemoryStore{})
	cfg := config("A")
	require.NoError(t, s.StorePubSubConfiguration(ctx, cfg, nsA))

	// urn:b moves to 300, past what a FourByte NodeId holds; urn:a to 1.
	to := make([]string, 301)
	for i := range to {
		to[i] = "urn:other:" + string(rune('a'+i%26)) + string(rune('0'+i/26%10)) + string(rune('0'+i/260))
	}
	to[0], to[1], to[300] = nsA[0], "urn:a", "urn:b"
	got, err := s.LoadPubSubConfiguration(ctx, to)
	require.NoError(t, err)
	items := got.PublishedDataSets[0].DataSetSource.Value.(*ua.PublishedDataItemsDataType)
	require.Equal(t, ua.NewStringNodeID(1, "x").String(), items.PublishedData[0].PublishedVariable.String())
	require.Equal(t, ua.NewNumericNodeID(300, 10).String(), items.PublishedData[1].PublishedVariable.String())
	tv := got.Connections[0].ReaderGroups[0].DataSetReaders[0].SubscribedDataSet.Value.(*ua.TargetVariablesDataType)
	require.Equal(t, ua.NewStringNodeID(300, "t").String(), tv.TargetVariables[0].TargetNodeID.String())
	props := got.Connections[0].ConnectionProperties
	require.Equal(t, ua.NewNumericNodeID(1, 7).String(), props[0].Value.Value().(*ua.NodeID).String())
	require.Equal(t, uint16(300), props[1].Value.Value().(*ua.ExpandedNodeID).NodeID.Namespace())

	// A missing namespace fails.
	_, err = s.LoadPubSubConfiguration(ctx, []string{nsA[0], nsA[1], "urn:a"})
	require.ErrorIs(t, err, ErrNamespace)
	_, err = s.LoadPubSubConfiguration(ctx, []string{nsA[0], nsA[1], "urn:b"})
	require.ErrorIs(t, err, ErrNamespace)
	// In a PubSubConnection.
	conn := config("A")
	conn.PublishedDataSets = nil
	conn.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetName = ""
	require.NoError(t, s.StorePubSubConfiguration(ctx, conn, nsA))
	_, err = s.LoadPubSubConfiguration(ctx, []string{nsA[0], nsA[1], "urn:a"})
	require.ErrorIs(t, err, ErrNamespace)
}

type deep struct{ Next *deep }

// TestRemap: the cases of the walk the configurations do not reach.
func TestRemap(t *testing.T) {
	m := newNSMap([]string{"u0", "u1"}, []string{"u0", "x", "u1"})
	// An index past the NamespaceArray of the record.
	require.ErrorIs(t, m.remap(&ua.FieldTargetDataType{TargetNodeID: ua.NewNumericNodeID(5, 1)}), fxstore.ErrCorrupt)
	// A FourByte NodeId in a Variant, which cannot be replaced.
	big := make([]string, 300)
	big[0], big[299] = "u0", "u1"
	err := newNSMap([]string{"u0", "u1"}, big).remap(ua.MustVariant(ua.NewFourByteNodeID(1, 2)))
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNamespace)
	// Nested too deeply.
	var d *deep
	for range maxDepth + 1 {
		d = &deep{Next: d}
	}
	require.ErrorIs(t, m.remap(d), fxstore.ErrCorrupt)
	// An ExpandedNodeId with a NamespaceUri or a ServerIndex is left.
	e := &ua.ExpandedNodeID{NodeID: ua.NewNumericNodeID(9, 1), NamespaceURI: "urn:x"}
	require.NoError(t, m.remap(e))
	require.NoError(t, m.remap(&ua.ExpandedNodeID{NodeID: ua.NewNumericNodeID(9, 1), ServerIndex: 1}))
	// Nil values and an empty Variant.
	var nilIface any
	require.NoError(t, m.remap(&struct {
		A any
		B *ua.Variant
		C *ua.ExpandedNodeID
		D any
		E []byte
		F time.Time
		g *ua.NodeID
	}{A: nilIface, B: &ua.Variant{}, D: ua.NewNumericNodeID(0, 1), E: []byte{1}, g: ua.NewNumericNodeID(1, 1)}))
	// The same index stays.
	n := ua.NewNumericNodeID(0, 5)
	require.NoError(t, m.remap(n))
	require.Equal(t, uint16(0), n.Namespace())
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

// TestFailedCommit: a backend that fails on the n-th key of a change, for
// every key and every outcome, leaves the configuration before it: at once
// when nothing was written, after Settle when the outcome was unknown.
// Until it is settled the store refuses writes.
func TestFailedCommit(t *testing.T) {
	ctx := context.Background()
	base := config("A", "B")
	upd := config("A", "C")
	upd.Enabled = false
	upd.PublishedDataSets[0].DataSetMetaData.Name = "Changed"
	keys := []string{rootKey, nameKey(pdsPrefix, "Data"), nameKey(connPrefix, "B"), nameKey(connPrefix, "C")}
	for _, fault := range []storetest.Fault{storetest.FailNotCommitted, storetest.FailLost, storetest.FailApplied} {
		for n, key := range keys {
			b := &failOnKey{Store: &fxstore.MemoryStore{}}
			s := openMem(t, b)
			require.NoError(t, s.StorePubSubConfiguration(ctx, base, nsA))
			b.set(key, fault)
			err := s.StorePubSubConfiguration(ctx, upd, nsA)
			require.Error(t, err, "key %d", n)
			requireSame(t, base, load(t, s))
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
			requireSame(t, base, load(t, s))
			st, err := b.Load(ctx)
			require.NoError(t, err)
			requireSame(t, base, load(t, openMem(t, mapStore(st))))
			require.NoError(t, s.StorePubSubConfiguration(ctx, upd, nsA))
			requireSame(t, upd, load(t, s))
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
	base, upd := config("A"), config("A", "B")
	require.NoError(t, s.StorePubSubConfiguration(ctx, base, nsA))

	f.FailApply(storetest.FailApplied)
	require.Equal(t, fxstore.Unknown, fxstore.OutcomeOf(s.StorePubSubConfiguration(ctx, upd, nsA)))
	require.True(t, s.Status().Fenced)

	f.FailLoads(2)
	ok, err := s.Settle(ctx)
	require.False(t, ok)
	require.ErrorIs(t, err, storetest.ErrInjected)
	err = s.StorePubSubConfiguration(ctx, upd, nsA)
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
	requireSame(t, base, load(t, s))

	// Lost: nothing to write back, the next write settles and applies.
	f.FailApply(storetest.FailLost)
	require.Equal(t, fxstore.Unknown, fxstore.OutcomeOf(s.StorePubSubConfiguration(ctx, upd, nsA)))
	n := f.Applies()
	require.NoError(t, s.StorePubSubConfiguration(ctx, upd, nsA))
	require.Equal(t, n+2, f.Applies(), "a confirmation and the write")
	requireSame(t, upd, load(t, s))

	// Not fenced: Settle writes nothing.
	n = f.Applies()
	ok, err = s.Settle(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, n, f.Applies())

	require.NoError(t, s.Close())
	_, err = s.Settle(ctx)
	require.ErrorIs(t, err, ErrClosed)
	err = s.StorePubSubConfiguration(ctx, upd, nsA)
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
	require.NoError(t, s.StorePubSubConfiguration(ctx, config("A"), nsA))
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
	require.Error(t, with(func(m map[string][]byte) { m["other/x"] = []byte{1} }))
	for name, edit := range map[string]func(map[string][]byte){
		"no root":         func(m map[string][]byte) { delete(m, k(rootKey)) },
		"bad root":        func(m map[string][]byte) { m[k(rootKey)] = []byte{9} },
		"extra record":    func(m map[string][]byte) { m[k("conn/zz")] = []byte{1} },
		"missing record":  func(m map[string][]byte) { delete(m, k(nameKey(connPrefix, "A"))) },
		"bad record":      func(m map[string][]byte) { m[k(nameKey(connPrefix, "A"))] = []byte{1, 0, 7} },
		"missing pds":     func(m map[string][]byte) { delete(m, k(nameKey(pdsPrefix, "Data"))) },
		"pds of the conn": func(m map[string][]byte) { m[k(nameKey(pdsPrefix, "Data"))] = m[k(nameKey(connPrefix, "A"))] },
		"renamed conn": func(m map[string][]byte) {
			m[k(rootKey)] = root{pds: []string{"Data"}, conns: []string{"Z"}}.encode()
			m[k(nameKey(connPrefix, "Z"))] = m[k(nameKey(connPrefix, "A"))]
			delete(m, k(nameKey(connPrefix, "A")))
		},
		"renamed pds": func(m map[string][]byte) {
			m[k(rootKey)] = root{pds: []string{"Z"}, conns: []string{"A"}}.encode()
			m[k(nameKey(pdsPrefix, "Z"))] = m[k(nameKey(pdsPrefix, "Data"))]
			delete(m, k(nameKey(pdsPrefix, "Data")))
		},
		"twice": func(m map[string][]byte) {
			m[k(rootKey)] = root{pds: []string{"Data"}, conns: []string{"A", "A"}}.encode()
		},
		"invalid": func(m map[string][]byte) {
			// The writer names a PublishedDataSet the store does not have.
			m[k(rootKey)] = root{conns: []string{"A"}}.encode()
			delete(m, k(nameKey(pdsPrefix, "Data")))
		},
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
	require.NoError(t, d.StorePubSubConfiguration(ctx, config("A"), nsA))
	require.NoError(t, d.Close())
	_, err = OpenDir(ctx, dir, Options{Owner: "urn:other"})
	require.ErrorIs(t, err, fxstore.ErrForeignOwner)
	d, err = OpenDir(ctx, dir, Options{Owner: owner})
	require.NoError(t, err)
	require.NoError(t, d.Close())
}

// TestRecordErrors: records that do not decode.
func TestRecordErrors(t *testing.T) {
	for _, b := range [][]byte{nil, {2, 0}, {1, 2}, {1, 0, 0x80}, {1, 0, 5, 1}, {1, 0, 1, 9, 'a'}, {1, 0, 0, 0, 0}} {
		_, err := decodeRoot(b)
		require.ErrorIs(t, err, fxstore.ErrCorrupt, "%x", b)
	}
	x, err := decodeRoot(root{enabled: true, pds: []string{"a"}, conns: []string{"b", ""}}.encode())
	require.NoError(t, err)
	require.Equal(t, root{enabled: true, pds: []string{"a"}, conns: []string{"b", ""}}, x)

	ok, err := encodeComponent(&ua.PubSubConnectionDataType{Name: "A"}, nsA)
	require.NoError(t, err)
	for _, b := range [][]byte{nil, {2}, {1, 0x80}, {1, 0, 0xff}, append(bytes.Clone(ok), 0)} {
		_, err := decodeComponent(b, new(ua.PubSubConnectionDataType))
		require.ErrorIs(t, err, fxstore.ErrCorrupt, "%x", b)
	}
	ns, err := decodeComponent(ok, new(ua.PubSubConnectionDataType))
	require.NoError(t, err)
	require.Equal(t, nsA, ns)
}

// TestEncodeError: a configuration that does not encode is not committed.
func TestEncodeError(t *testing.T) {
	ctx := context.Background()
	s := openMem(t, &fxstore.MemoryStore{})
	defer func(e func(any) ([]byte, error)) { encode = e }(encode)
	fail := errors.New("no")
	encode = func(any) ([]byte, error) { return nil, fail }
	err := s.StorePubSubConfiguration(ctx, config(), nsA)
	require.ErrorIs(t, err, fail)
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
	n := 0
	encode = func(v any) ([]byte, error) {
		if n++; n > 1 {
			return nil, fail
		}
		return ua.Encode(v)
	}
	err = s.StorePubSubConfiguration(ctx, config("A"), nsA)
	require.ErrorIs(t, err, fail)
	require.Equal(t, fxstore.NotCommitted, fxstore.OutcomeOf(err))
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

// TestConcurrent: a load during a write sees the configuration before it;
// writers and readers run together (under -race in CI) and the store ends
// with one of the configurations written, whole.
func TestConcurrent(t *testing.T) {
	ctx := context.Background()
	b := &blockingStore{Store: &fxstore.MemoryStore{}, entered: make(chan struct{}), release: make(chan struct{})}
	s := openMem(t, b)
	done := make(chan error)
	go func() { done <- s.StorePubSubConfiguration(ctx, config("A"), nsA) }()
	<-b.entered
	got, err := s.LoadPubSubConfiguration(ctx, nsA)
	require.NoError(t, err)
	require.Nil(t, got, "the write in progress is not visible")
	close(b.release)
	require.NoError(t, <-done)
	requireSame(t, config("A"), load(t, s))

	cfgs := []*ua.PubSubConfigurationDataType{config("A"), config("B", "C"), config("C"), config()}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 20 {
				if i%2 == 0 {
					require.NoError(t, s.StorePubSubConfiguration(ctx, cfgs[(i+j)%len(cfgs)], nsA))
					continue
				}
				_, err := s.LoadPubSubConfiguration(ctx, nsA)
				require.NoError(t, err)
			}
		})
	}
	wg.Wait()
	final := encoded(t, load(t, s))
	require.True(t, slices.ContainsFunc(cfgs, func(c *ua.PubSubConfigurationDataType) bool { return bytes.Equal(encoded(t, c), final) }))
}
