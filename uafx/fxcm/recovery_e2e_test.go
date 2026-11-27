// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/fxtest"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The tests of stage C3.3 (design docs/design/uafx-persistent-connections.md
// §6.4–§6.6, §8): the verification of the records a restarted Manager
// loads, the adoption of the endpoints it proves, and what it never does
// to what it cannot prove.

// established returns a store that holds the records of an established
// set "Recover" over a and b, the key of the set, and the NodeIds of the
// endpoints on a and b. The Manager that wrote it is closed.
func established(t *testing.T, a, b *ac, opts fxcm.Options) (*fxstore.MemoryStore, fxcm.SetKey, []*ua.NodeID) {
	t.Helper()
	return establishedWith(t, a, b, opts, true)
}

// establishedWith is established with the RollbackOnError of the set.
func establishedWith(t *testing.T, a, b *ac, opts fxcm.Options, rollback bool) (*fxstore.MemoryStore, fxcm.SetKey, []*ua.NodeID) {
	t.Helper()
	mem := &fxstore.MemoryStore{}
	opts.Store = mem
	m := newManager(t, opts)
	conf := e2eConf(t, "Recover", a, b)
	conf.RollbackOnError = rollback
	cfg, err := m.Add(conf)
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.NoError(t, m.Close())
	return mem, cfg.Key(), append(a.conns.Endpoints(), b.conns.Endpoints()...)
}

func endpointsOf(a, b *ac) []*ua.NodeID {
	return append(a.conns.Endpoints(), b.conns.Endpoints()...)
}

// verifyEvents records the EventVerified of a Manager.
type verifyEvents struct {
	mu     sync.Mutex
	failed map[string]int
	ok     map[string]int
}

func (v *verifyEvents) Observe(e fxcm.Event) {
	if e.Kind != fxcm.EventVerified || e.Record != nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failed == nil {
		v.failed, v.ok = map[string]int{}, map[string]int{}
	}
	if e.Err != nil {
		v.failed[e.Address]++
	} else {
		v.ok[e.Address]++
	}
}

func (v *verifyEvents) failures(addr string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.failed[addr]
}

// TestVerifyUnreachableE2E (§6.4): a server that cannot be reached leaves
// its records Unverified, is reported in Recovery.Unreachable and tried
// again with a backoff; nothing is closed, adopted or created for it. The
// records of the other server are proven meanwhile. Once it is reached,
// its records are proven too.
func TestVerifyUnreachableE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem, k, _ := established(t, a, b, fxcm.Options{})

	d := newHookDialer()
	d.identity = true
	var down atomic.Bool
	down.Store(true)
	d.fault = func(method string, addr fxcm.ServerAddress) error {
		if method == "Dial" && down.Load() && addr.Address == a.url {
			return ua.StatusBadCommunicationError
		}
		return nil
	}
	ev := &verifyEvents{}
	m := newManager(t, fxcm.Options{Store: mem, Dialer: d, Observer: ev, Verify: fxcm.VerifyOptions{RetryInitial: 5 * time.Millisecond, RetryMax: 20 * time.Millisecond}})
	require.Eventually(t, func() bool {
		st, _ := m.Status(k)
		_, unreachable := st.Recovery.Unreachable[a.url]
		return unreachable && ev.failures(a.url) >= 3 && slices.Contains(classes(st), fxcm.KnownOwned)
	}, 10*time.Second, 5*time.Millisecond, "a is retried with a backoff, b is proven")
	st, _ := m.Status(k)
	assert.False(t, st.Recovery.Done)
	for _, e := range st.Endpoints {
		if e.ServerURI == a.uri {
			assert.Equal(t, fxcm.Unverified, e.Class)
		} else {
			assert.Equal(t, fxcm.KnownOwned, e.Class)
		}
	}

	// A run verifies first and acts on nothing it could not prove: an
	// establish fails the Connection a's Unverified record holds and
	// creates or adopts nothing; its rollback (RollbackOnError TRUE,
	// §6.7.3.2, set-wide as in C2) closes b's proven endpoint and never
	// a's Unverified one.
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
	assert.Equal(t, fxcm.StateError, res.State)
	assert.Empty(t, res.Created)
	assert.Empty(t, res.Adopted)
	require.Len(t, res.Closed, 1, "%+v", res)
	assert.Equal(t, b.uri, res.Closed[0].ServerURI)
	assert.Equal(t, []string{"ToB"}, a.endpoints(), "the Unverified endpoint stays")
	assert.Empty(t, b.endpoints())
	res = process(t, m, uafx.ActionRemoveConnections, k)
	assert.Equal(t, fxcm.StateError, res.State)
	assert.Empty(t, res.Closed)
	assert.Equal(t, []string{"ToB"}, a.endpoints())

	down.Store(false)
	require.Eventually(t, func() bool {
		st, _ := m.Status(k)
		return st.Recovery == nil || st.Recovery.Done
	}, 10*time.Second, 5*time.Millisecond)
	st, _ = m.Status(k)
	assert.Equal(t, []fxcm.Ownership{fxcm.KnownOwned}, classes(st))
	res = process(t, m, uafx.ActionRemoveConnections, k)
	assert.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	assert.Empty(t, a.endpoints())
}

// nodeSet returns the NodeIds ns as sorted strings.
func nodeSet(ns []*ua.NodeID) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.String())
	}
	slices.Sort(out)
	return out
}

// TestVerifyCloseE2E (§6.4): Close cancels a verification that waits for
// a server, and leaves the records as they were stored.
func TestVerifyCloseE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem, _, _ := established(t, a, b, fxcm.Options{})
	before := storedKeys(t, mem, "ep/")

	d := newHookDialer()
	d.block = make(chan struct{})
	m, err := fxcm.New(fxcm.Options{Store: mem, Dialer: d, ApplicationURI: cmURI, Verify: fxcm.VerifyOptions{Timeout: time.Hour}})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return d.dials.Load() > 0 }, 10*time.Second, time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- m.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Close waits for the verification")
	}
	assert.Equal(t, before, storedKeys(t, mem, "ep/"))
}

// removedBehind returns a copy of the store of an established set
// "Recover", taken before the Manager that wrote it removed its endpoints:
// the records of endpoints that are gone.
func removedBehind(t *testing.T, a, b *ac) (*fxstore.MemoryStore, fxcm.SetKey) {
	t.Helper()
	mem := &fxstore.MemoryStore{}
	m := newManager(t, fxcm.Options{Store: mem})
	cfg, err := m.Add(e2eConf(t, "Recover", a, b))
	require.NoError(t, err)
	res := process(t, m, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	st, err := mem.Load(context.Background())
	require.NoError(t, err)
	res = process(t, m, uafx.ActionRemoveConnections, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	require.NoError(t, m.Close())
	require.Empty(t, a.endpoints())
	cp := &fxstore.MemoryStore{}
	require.NoError(t, cp.Apply(context.Background(), fxstore.Batch{Puts: st}))
	return cp, cfg.Key()
}

// TestVerifyAbsentE2E (§6.5): a record whose endpoint is gone is dropped.
func TestVerifyAbsentE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem, k := removedBehind(t, a, b)
	require.Len(t, storedKeys(t, mem, "ep/"), 2)
	m := newManager(t, fxcm.Options{Store: mem})
	require.Eventually(t, func() bool {
		st, _ := m.Status(k)
		return len(st.Endpoints) == 0 && (st.Recovery == nil || st.Recovery.Done)
	}, 10*time.Second, 5*time.Millisecond)
	assert.Empty(t, storedKeys(t, mem, "ep/"))
}

// TestVerifyForeignE2E (§6.5): an endpoint of the Name of a record with
// another NodeId, made by another ConnectionManager (its ApplicationUri,
// §6.6.2), is not ours: the record is dropped and the endpoint is never
// closed.
func TestVerifyForeignE2E(t *testing.T) {
	t.Parallel()
	a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
	mem, k := removedBehind(t, a, b)
	foreign := newForeignManager(t, "urn:go-opcua:fxcm:other")
	cfg, err := foreign.Add(e2eConf(t, "Recover", a, b))
	require.NoError(t, err)
	res := process(t, foreign, uafx.ActionEstablishConnectionsEnabled, cfg.Key())
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
	nodes := nodeSet(endpointsOf(a, b))

	m := newManager(t, fxcm.Options{Store: mem})
	require.Eventually(t, func() bool {
		st, _ := m.Status(k)
		return len(st.Endpoints) == 0
	}, 10*time.Second, 5*time.Millisecond, "the records are dropped")
	res = process(t, m, uafx.ActionRemoveConnections, k)
	assert.Empty(t, res.Closed, "a foreign endpoint is never closed")
	assert.Equal(t, nodes, nodeSet(endpointsOf(a, b)))
}

// newForeignManager is a Manager of the ApplicationUri uri.
func newForeignManager(t *testing.T, uri string) *fxcm.Manager {
	t.Helper()
	d := &fxcm.ClientDialer{Options: []opcua.Option{opcua.ApplicationURI(uri), opcua.AutoReconnect(false), opcua.InsecureNoSecurity()}}
	return newManager(t, fxcm.Options{Dialer: d, ApplicationURI: uri})
}

// setProperty sets the Property name of the node n of a to v, on the
// server side.
func setProperty(t *testing.T, a *ac, n *ua.NodeID, name string, v any) {
	t.Helper()
	ns, err := a.srv.Namespace(int(n.Namespace()))
	require.NoError(t, err)
	res := ns.Browse(&ua.BrowseDescription{NodeID: n, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: ua.NewNumericNodeID(0, id.References), IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)})
	for _, r := range res.References {
		if r.BrowseName != nil && r.BrowseName.Name == name {
			require.NoError(t, a.srv.Node(r.NodeID.NodeID).SetAttribute(ua.AttributeIDValue, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}))
			return
		}
	}
	t.Fatalf("%v has no %s", n, name)
}

// referenced returns the target and type of the forward Reference of n whose type
// has the BrowseName ToDataSetReader or ToDataSetWriter (kind is
// "DataSetReader" or "DataSetWriter").
func referenced(t *testing.T, a *ac, n *ua.NodeID, kind string) (target, refType *ua.NodeID) {
	t.Helper()
	ns, err := a.srv.Namespace(int(n.Namespace()))
	require.NoError(t, err)
	res := ns.Browse(&ua.BrowseDescription{NodeID: n, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: ua.NewNumericNodeID(0, id.References), IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)})
	for _, r := range res.References {
		if rt := a.srv.Node(r.ReferenceTypeID); rt != nil && rt.BrowseName().Name == "To"+kind {
			return r.NodeID.NodeID, r.ReferenceTypeID
		}
	}
	t.Fatalf("%v has no %s", n, kind)
	return nil, nil
}

// ownEndpoint returns the endpoint of Motion of a that is not preset.
func ownEndpoint(t *testing.T, a *ac) *ua.NodeID {
	t.Helper()
	for _, e := range a.conns.Endpoints() {
		if !e.Equal(a.id(fxtest.ConnPreset)) {
			return e
		}
	}
	t.Fatal("no endpoint")
	return nil
}

// TestAdoptionE2E (§6.6, C3-D6): what a restarted Manager does with the
// endpoints it proves.
func TestAdoptionE2E(t *testing.T) {
	t.Parallel()
	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		mem, k, nodes := established(t, a, b, fxcm.Options{})
		m := newManager(t, fxcm.Options{Store: mem, Verify: fxcm.VerifyOptions{Manual: true}})
		before := m.Counters()
		res := process(t, m, uafx.ActionEstablishConnectionsDisabled, k)
		require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
		assert.Len(t, res.Adopted, 2)
		assert.Empty(t, res.Created)
		assert.Equal(t, before.EstablishCallCount, m.Counters().EstablishCallCount)
		assert.Equal(t, before.CloseCallCount+2, m.Counters().CloseCallCount, "CloseConnections Remove FALSE (§6.2.5.2)")
		assert.Equal(t, nodeSet(nodes), nodeSet(endpointsOf(a, b)), "kept, disabled")
		st, ok := a.conns.Status(ownEndpoint(t, a))
		require.True(t, ok)
		assert.NotEqual(t, uafx.ConnectionEndpointOperational, st)
	})
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		mem, k, nodes := established(t, a, b, fxcm.Options{})
		m := newManager(t, fxcm.Options{Store: mem, Verify: fxcm.VerifyOptions{Manual: true}})
		res := process(t, m, uafx.ActionEstablishConnections, k)
		require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
		assert.Len(t, res.Adopted, 2)
		assert.Empty(t, res.Created)
		assert.Equal(t, nodeSet(nodes), nodeSet(endpointsOf(a, b)))
	})
	t.Run("changed is unresolved", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		mem, k, _ := established(t, a, b, fxcm.Options{})
		// The parameter of an endpoint is not the one recorded (its
		// CleanupTimeout, §6.6.2 Table 73): the re-proof makes it
		// Unresolved (§6.5), and it is never closed.
		setProperty(t, b, ownEndpoint(t, b), "CleanupTimeout", 7.0)
		m := newManager(t, fxcm.Options{Store: mem, Verify: fxcm.VerifyOptions{Manual: true}})
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
		require.Equal(t, fxcm.StateError, res.State, "%+v", res)
		assert.Empty(t, res.Adopted)
		assert.Empty(t, res.Created)
		assert.Equal(t, []string{"ToA"}, b.endpoints())
		st, _ := m.Status(k)
		for _, e := range st.Endpoints {
			if e.ServerURI == b.uri {
				assert.Equal(t, fxcm.Unresolved, e.Class)
			}
		}
	})
	// The communication of an endpoint changed by another PubSub
	// configuration mechanism (Part 14 §9.1.2, PS-2) under the same Names:
	// ownership, parameter and links prove nothing about what it
	// publishes or subscribes to, so it is not adopted (C3-D6); the run
	// closes both endpoints and creates them again (C2).
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, b *ac, ep *ua.NodeID)
	}{
		{"writer changed is not adopted", func(t *testing.T, b *ac, ep *ua.NodeID) {
			w, _ := referenced(t, b, ep, "DataSetWriter")
			setProperty(t, b, w, "KeyFrameCount", uint32(99))
		}},
		{"writer group changed is not adopted", func(t *testing.T, b *ac, ep *ua.NodeID) {
			w, _ := referenced(t, b, ep, "DataSetWriter")
			cid, ok := b.srv.PubSubComponentID(w)
			require.True(t, ok)
			info, err := b.srv.PubSub().Component(cid)
			require.NoError(t, err)
			g, ok := b.srv.PubSubNodeID(info.Parent)
			require.True(t, ok)
			setProperty(t, b, g, "PublishingInterval", 1234.0)
		}},
		{"reader changed is not adopted", func(t *testing.T, b *ac, ep *ua.NodeID) {
			r, _ := referenced(t, b, ep, "DataSetReader")
			setProperty(t, b, r, "MessageReceiveTimeout", 4321.0)
		}},
		{"reader group changed is not adopted", func(t *testing.T, b *ac, ep *ua.NodeID) {
			r, _ := referenced(t, b, ep, "DataSetReader")
			cid, ok := b.srv.PubSubComponentID(r)
			require.True(t, ok)
			info, err := b.srv.PubSub().Component(cid)
			require.NoError(t, err)
			g, ok := b.srv.PubSubNodeID(info.Parent)
			require.True(t, ok)
			setProperty(t, b, g, "MaxNetworkMessageSize", uint32(512))
		}},
		{"writer group message settings changed is not adopted", func(t *testing.T, b *ac, ep *ua.NodeID) {
			w, _ := referenced(t, b, ep, "DataSetWriter")
			cid, ok := b.srv.PubSubComponentID(w)
			require.True(t, ok)
			info, err := b.srv.PubSub().Component(cid)
			require.NoError(t, err)
			g, ok := b.srv.PubSubNodeID(info.Parent)
			require.True(t, ok)
			setProperty(t, b, childNamed(t, b, g, "MessageSettings"), "NetworkMessageContentMask", uint32(1))
		}},
		{"writer replaced is not adopted", func(t *testing.T, b *ac, ep *ua.NodeID) {
			// Removed and added again with the same Name through the
			// runtime: the endpoint's ToDataSetWriter names a writer that
			// is gone.
			w, _ := referenced(t, b, ep, "DataSetWriter")
			cid, ok := b.srv.PubSubComponentID(w)
			require.True(t, ok)
			info, err := b.srv.PubSub().Component(cid)
			require.NoError(t, err)
			require.NoError(t, b.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
				cfg, err := rt.DataSetWriterConfig(cid)
				if err != nil {
					return err
				}
				if err := rt.RemoveDataSetWriter(cid); err != nil {
					return err
				}
				_, err = rt.AddDataSetWriter(info.Parent, cfg)
				return err
			}))
			_, ok = b.srv.PubSub().Lookup(pubsub.KindDataSetWriter, info.Parent, info.Name)
			require.True(t, ok, "a writer of the Name is there")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
			mem, k, nodes := established(t, a, b, fxcm.Options{})
			tc.change(t, b, ownEndpoint(t, b))
			m := newManager(t, fxcm.Options{Store: mem, Verify: fxcm.VerifyOptions{Manual: true}})
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
			assert.Empty(t, res.Adopted, "%+v", res)
			assert.Len(t, res.Closed, 2)
			assert.NotEqual(t, nodeSet(nodes), nodeSet(endpointsOf(a, b)), "closed, not kept")
		})
	}
	t.Run("mixed falls back", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		mem, k, nodes := established(t, a, b, fxcm.Options{})
		// One endpoint has lost its DataSetReader (ToDataSetReader, §6.6.2)
		// that its Mode needs: it is proven ours, its parameter is the
		// recorded one, but it is not adoptable. Nothing is adopted: both
		// are closed first and created again (C2).
		ep := ownEndpoint(t, b)
		reader, rt := referenced(t, b, ep, "DataSetReader")
		require.True(t, b.srv.Node(ep).RemoveRef(ua.NewExpandedNodeID(reader, "", 0), rt, true))
		m := newManager(t, fxcm.Options{Store: mem, Verify: fxcm.VerifyOptions{Manual: true}})
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
		require.Equal(t, fxcm.StateReady, res.State, "%+v", res)
		assert.Empty(t, res.Adopted)
		assert.Len(t, res.Closed, 2)
		assert.Len(t, res.Created, 2)
		assert.NotEqual(t, nodeSet(nodes), nodeSet(endpointsOf(a, b)), "made again")
	})
	t.Run("rollback closes the adopted", func(t *testing.T) {
		t.Parallel()
		a, b := newAC(t, "a", fxserver.ConnectionOptions{}), newAC(t, "b", fxserver.ConnectionOptions{})
		mem, k, _ := established(t, a, b, fxcm.Options{})
		d := newHookDialer()
		d.identity = true
		d.answer = func(addr fxcm.ServerAddress, req *ua.CallMethodRequest) *ua.CallMethodResult {
			if addr.Address == b.url && len(req.InputArguments) != 2 {
				return &ua.CallMethodResult{StatusCode: ua.StatusBadInvalidState}
			}
			return nil
		}
		m := newManager(t, fxcm.Options{Store: mem, Dialer: d, Verify: fxcm.VerifyOptions{Manual: true}})
		res := process(t, m, uafx.ActionEstablishConnectionsEnabled, k)
		require.Equal(t, fxcm.StateError, res.State, "%+v", res)
		assert.Len(t, res.Adopted, 2, "%+v", res)
		assert.True(t, res.RollbackComplete)
		assert.Empty(t, a.endpoints(), "RollbackOnError closes the adopted endpoints (CR-4)")
		assert.Empty(t, b.endpoints())
		assert.Empty(t, storedKeys(t, mem, "ep/"))
	})
}
