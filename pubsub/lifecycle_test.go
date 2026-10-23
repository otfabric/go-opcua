// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestStateMachinePropagation(t *testing.T) {
	t.Parallel()
	pub, sub, _, rec := pubSubPair(t, 10*time.Millisecond, nil)
	conn := mustID(t, pub, KindConnection, Root, "pub")
	wg := mustID(t, pub, KindWriterGroup, conn, "wg")
	w := mustID(t, pub, KindDataSetWriter, wg, "w")
	for _, id := range []ComponentID{Root, conn, wg, w} {
		waitState(t, pub, id, ua.PubSubStateOperational)
	}

	// Disabling a parent pauses the enabled children.
	require.NoError(t, pub.Disable(conn))
	waitState(t, pub, conn, ua.PubSubStateDisabled)
	waitState(t, pub, wg, ua.PubSubStatePaused)
	waitState(t, pub, w, ua.PubSubStatePaused)
	require.ErrorIs(t, pub.Disable(conn), ua.StatusBadInvalidState)
	require.NoError(t, pub.Enable(conn))
	require.ErrorIs(t, pub.Enable(conn), ua.StatusBadInvalidState)
	waitState(t, pub, w, ua.PubSubStateOperational)

	// A disabled child stays disabled when its parent comes back.
	require.NoError(t, pub.Disable(w))
	require.NoError(t, pub.Disable(Root))
	waitState(t, pub, Root, ua.PubSubStateDisabled)
	waitState(t, pub, conn, ua.PubSubStatePaused)
	require.ErrorIs(t, pub.Disable(Root), ua.StatusBadInvalidState)
	require.NoError(t, pub.Enable(Root))
	waitState(t, pub, wg, ua.PubSubStateOperational)
	waitState(t, pub, w, ua.PubSubStateDisabled)
	require.NoError(t, pub.Enable(w))
	waitState(t, pub, w, ua.PubSubStateOperational)

	// Reader side: disabling the reader group pauses the reader.
	sconn := mustID(t, sub, KindConnection, Root, "sub")
	rg := mustID(t, sub, KindReaderGroup, sconn, "rg")
	r := mustID(t, sub, KindDataSetReader, rg, "r")
	waitState(t, sub, r, ua.PubSubStateOperational)
	require.NoError(t, sub.Disable(rg))
	waitState(t, sub, r, ua.PubSubStatePaused)
	require.NoError(t, sub.Enable(rg))
	waitState(t, sub, r, ua.PubSubStateOperational)

	_, err := pub.State(999)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	require.ErrorIs(t, pub.Enable(999), ua.StatusBadNotFound)
	pds := mustID(t, pub, KindPublishedDataSet, Root, "pds")
	require.ErrorIs(t, pub.Disable(pds), ua.StatusBadNotSupported)

	var states []ua.PubSubState
	for _, ev := range rec.events() {
		if ev.Type == EventStateChanged && ev.Component.ID == r {
			states = append(states, ev.Component.State)
		}
	}
	require.Contains(t, states, ua.PubSubStatePaused)
	require.Contains(t, states, ua.PubSubStateOperational)
}

func TestStartCloseLifecycle(t *testing.T) {
	// Not parallel: it counts goroutines.
	before := runtime.NumGoroutine()
	url := memURL(t)
	cfg := NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachReaderGroups(AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds"))),
			ReaderGroup("rg", DataSetReader("r", nil, 0, 0, nil))))
	p, err := New(cfg, withFakeCodec())
	require.NoError(t, err)
	s, _ := p.State(Root)
	require.Equal(t, ua.PubSubStatePaused, s)
	require.False(t, p.Running())

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, p.Start(cancelled))

	ctx, stop := context.WithCancel(context.Background())
	require.NoError(t, p.Start(ctx))
	require.NoError(t, p.Start(ctx), "idempotent")
	require.True(t, p.Running())
	conn := mustID(t, p, KindConnection, Root, "c")
	waitState(t, p, conn, ua.PubSubStateOperational)
	r := mustID(t, p, KindDataSetReader, mustID(t, p, KindReaderGroup, conn, "rg"), "r")
	waitState(t, p, r, ua.PubSubStateOperational)

	// Cancelling the context pauses everything; Start resumes.
	stop()
	waitState(t, p, Root, ua.PubSubStatePaused)
	waitState(t, p, conn, ua.PubSubStatePaused)
	require.Eventually(t, func() bool { return bus.subscribers(url) == 0 }, 2*time.Second, time.Millisecond)
	require.NoError(t, p.Start(context.Background()))
	waitState(t, p, conn, ua.PubSubStateOperational)

	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
	require.ErrorIs(t, p.Start(context.Background()), ErrClosed)
	_, err = p.AddConnection(memConnection("x", url, nil))
	require.ErrorIs(t, err, ErrClosed)
	require.ErrorIs(t, p.Enable(conn), ErrClosed)
	_, err = p.AddPublishedDataSet(testPDS("p2"))
	require.ErrorIs(t, err, ErrClosed)
	require.Equal(t, ua.StatusBadInvalidState, StatusCodeOf(ErrClosed))
	require.Zero(t, bus.subscribers(url))
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= before+2 }, 2*time.Second, 5*time.Millisecond,
		"goroutines leaked: %d > %d", runtime.NumGoroutine(), before)
}

func TestTransportRetry(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	bus.mu.Lock()
	bus.failOpen[url] = 2
	bus.mu.Unlock()
	rec := &recorder{}
	p := start(t, NewConfiguration(nil, memConnection("c", url, uint16(1))), WithEventHandler(rec.event))
	conn := mustID(t, p, KindConnection, Root, "c")
	waitState(t, p, conn, ua.PubSubStateOperational)
	var sawErr bool
	for _, ev := range rec.events() {
		if ev.Component.ID == conn && ev.Component.State == ua.PubSubStateError {
			sawErr = true
			require.Error(t, ev.Err)
		}
	}
	require.True(t, sawErr)

	_, err := New(NewConfiguration(nil, memConnection("c", "nosuch://x", nil)))
	require.NoError(t, err)
	q := start(t, NewConfiguration(nil, memConnection("c", "nosuch://x", nil)))
	waitState(t, q, mustID(t, q, KindConnection, Root, "c"), ua.PubSubStateError)
	st, err := q.Status(mustID(t, q, KindConnection, Root, "c"))
	require.NoError(t, err)
	require.ErrorContains(t, st.LastError, "no transport")
}

func TestSendAndSubscribeFailures(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	bus.mu.Lock()
	bus.failSend[url] = true
	bus.mu.Unlock()
	p := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds")))))
	require.Eventually(t, func() bool {
		st, _ := p.Status(Root)
		return st.Counters.SendErrors > 2
	}, 2*time.Second, time.Millisecond)

	// A broker reader whose subscription fails is retried.
	burl := memURL(t) + "b"
	q := start(t, NewConfiguration(nil, AttachReaderGroups(brokerConnection("c", burl, nil, MappingJSON),
		ReaderGroup("rg", SetReaderQueue(DataSetReader("r", nil, 0, 0, nil), "fail/topic", "")))))
	conn := mustID(t, q, KindConnection, Root, "c")
	require.Eventually(t, func() bool {
		st, _ := q.Status(conn)
		return st.LastError != nil
	}, 2*time.Second, time.Millisecond)
}

func TestRuntimeAddRemove(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(5)))
	rec := &recorder{}
	p := start(t, nil, WithDataSource(ds), WithDataSetHandler(rec.handler), WithEventHandler(rec.event))
	s, _ := p.State(Root)
	require.Equal(t, ua.PubSubStateOperational, s)

	pdsID, err := p.AddPublishedDataSet(PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32)))
	require.NoError(t, err)
	_, err = p.AddPublishedDataSet(PublishedDataItems("pds"))
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)

	conn, err := p.AddConnection(memConnection("c", url, uint16(1)))
	require.NoError(t, err)
	_, err = p.AddConnection(memConnection("c", url, uint16(1)))
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	wg, err := p.AddWriterGroup(conn, WriterGroup("wg", 1, 5*time.Millisecond))
	require.NoError(t, err)
	_, err = p.AddWriterGroup(conn, WriterGroup("wg2", 1, 5*time.Millisecond))
	require.ErrorIs(t, err, ua.StatusBadConfigurationError)
	_, err = p.AddWriterGroup(conn, WriterGroup("wg", 2, 5*time.Millisecond))
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	w, err := p.AddDataSetWriter(wg, DataSetWriter("w", 1, "pds"))
	require.NoError(t, err)
	_, err = p.AddDataSetWriter(wg, DataSetWriter("w2", 1, "pds"))
	require.ErrorIs(t, err, ua.StatusBadConfigurationError)
	_, err = p.AddDataSetWriter(wg, DataSetWriter("w", 2, "pds"))
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	_, err = p.AddDataSetWriter(wg, DataSetWriter("w3", 3, "nosuch"))
	require.ErrorIs(t, err, ua.StatusBadConfigurationError)
	rg, err := p.AddReaderGroup(conn, ReaderGroup("rg"))
	require.NoError(t, err)
	_, err = p.AddReaderGroup(conn, ReaderGroup("rg"))
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)
	r, err := p.AddDataSetReader(rg, DataSetReader("r", uint16(1), 1, 1, nil))
	require.NoError(t, err)
	_, err = p.AddDataSetReader(rg, DataSetReader("r", uint16(1), 1, 1, nil))
	require.ErrorIs(t, err, ua.StatusBadBrowseNameDuplicated)

	waitState(t, p, r, ua.PubSubStateOperational)
	require.Eventually(t, func() bool { return len(rec.dataSets()) > 0 }, 2*time.Second, time.Millisecond)
	ds0 := rec.dataSets()[0]
	require.Equal(t, int32(5), ds0.Fields[0].Value.Value.Value())

	// Not found errors.
	_, err = p.AddWriterGroup(999, WriterGroup("x", 9, time.Second))
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	_, err = p.AddReaderGroup(999, ReaderGroup("x"))
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	_, err = p.AddDataSetWriter(999, DataSetWriter("x", 9, ""))
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	_, err = p.AddDataSetReader(999, DataSetReader("x", nil, 0, 0, nil))
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	for _, f := range []func(ComponentID) error{p.RemoveConnection, p.RemoveWriterGroup, p.RemoveReaderGroup, p.RemoveDataSetWriter, p.RemoveDataSetReader, p.RemovePublishedDataSet, p.RemoveGroup} {
		require.ErrorIs(t, f(999), ua.StatusBadNotFound)
	}
	for _, f := range []func(ComponentID) (any, error){
		func(id ComponentID) (any, error) { return p.ConnectionConfig(id) },
		func(id ComponentID) (any, error) { return p.WriterGroupConfig(id) },
		func(id ComponentID) (any, error) { return p.ReaderGroupConfig(id) },
		func(id ComponentID) (any, error) { return p.DataSetWriterConfig(id) },
		func(id ComponentID) (any, error) { return p.DataSetReaderConfig(id) },
		func(id ComponentID) (any, error) { return p.PublishedDataSetConfig(id) },
		func(id ComponentID) (any, error) { return p.Status(id) },
		func(id ComponentID) (any, error) { return p.Component(id) },
	} {
		_, err := f(999)
		require.ErrorIs(t, err, ua.StatusBadNotFound)
	}

	// Configuration reflects the runtime.
	cfg := p.Configuration()
	require.True(t, cfg.Enabled)
	require.Len(t, cfg.PublishedDataSets, 1)
	require.Len(t, cfg.Connections, 1)
	require.Len(t, cfg.Connections[0].WriterGroups[0].DataSetWriters, 1)
	require.Len(t, cfg.Connections[0].ReaderGroups[0].DataSetReaders, 1)
	require.NoError(t, Validate(cfg))
	info, err := p.Component(w)
	require.NoError(t, err)
	require.Equal(t, KindDataSetWriter, info.Kind)
	require.Equal(t, wg, info.Parent)
	root, err := p.Component(Root)
	require.NoError(t, err)
	require.Equal(t, KindPubSub, root.Kind)
	require.Len(t, p.Components(), 6)

	// Removing the published data set removes its writer.
	require.NoError(t, p.RemovePublishedDataSet(pdsID))
	_, err = p.State(w)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	require.NoError(t, p.RemoveGroup(rg))
	_, err = p.State(r)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	require.ErrorIs(t, p.RemoveGroup(conn), ua.StatusBadNotFound)
	require.NoError(t, p.RemoveGroup(wg))
	require.NoError(t, p.RemoveConnection(conn))
	require.Empty(t, p.Components())

	var added, removed int
	for _, ev := range rec.events() {
		switch ev.Type {
		case EventAdded:
			added++
		case EventRemoved:
			removed++
		case EventStateChanged:
		}
	}
	require.Equal(t, 6, added)
	require.Equal(t, 6, removed)
	require.Equal(t, "Added", EventAdded.String())
	require.Equal(t, "Removed", EventRemoved.String())
	require.Equal(t, "StateChanged", EventStateChanged.String())
	require.Contains(t, EventType(9).String(), "9")
}

func TestRemoveWhileRunning(t *testing.T) {
	t.Parallel()
	pub, sub, _, _ := pubSubPair(t, 2*time.Millisecond, nil)
	conn := mustID(t, pub, KindConnection, Root, "pub")
	wg := mustID(t, pub, KindWriterGroup, conn, "wg")
	require.NoError(t, pub.RemoveDataSetWriter(mustID(t, pub, KindDataSetWriter, wg, "w")))
	require.NoError(t, pub.RemoveWriterGroup(wg))
	require.NoError(t, pub.RemoveConnection(conn))
	sconn := mustID(t, sub, KindConnection, Root, "sub")
	rg := mustID(t, sub, KindReaderGroup, sconn, "rg")
	require.NoError(t, sub.RemoveDataSetReader(mustID(t, sub, KindDataSetReader, rg, "r")))
	require.NoError(t, sub.RemoveReaderGroup(rg))
}

func TestManyGroupsConcurrently(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(1)))
	var pds []*ua.PublishedDataSetDataType
	conn := memConnection("pub", url, uint16(1))
	rconn := memConnection("sub", url, nil)
	const n = 12
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("pds%d", i)
		pds = append(pds, PublishedDataItems(name, Var("a", nodeA, ua.TypeIDInt32)))
		AttachWriterGroups(conn, WriterGroup(fmt.Sprintf("wg%d", i), uint16(i), 3*time.Millisecond, DataSetWriter("w", uint16(i), name)))
		AttachReaderGroups(rconn, ReaderGroup(fmt.Sprintf("rg%d", i), DataSetReader("r", uint16(1), uint16(i), uint16(i), nil)))
	}
	var mu sync.Mutex
	seen := map[uint16]int{}
	sub := start(t, NewConfiguration(nil, rconn), WithDataSetHandler(func(d *ReceivedDataSet) {
		mu.Lock()
		seen[d.WriterGroupID]++
		mu.Unlock()
	}))
	pub := start(t, NewConfiguration(pds, conn), WithDataSource(ds))
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 20 {
				_ = ds.Set(nodeA, int32(i*100+j))
				_, _ = pub.Status(Root)
				_ = sub.Components()
				_ = pub.Configuration()
			}
		}()
	}
	wg.Wait()
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if len(seen) != n {
			return false
		}
		for _, c := range seen {
			if c < 3 {
				return false
			}
		}
		return true
	}, 3*time.Second, time.Millisecond)
	// Toggle groups while they run.
	conn1 := mustID(t, pub, KindConnection, Root, "pub")
	for i := 1; i <= n; i++ {
		id := mustID(t, pub, KindWriterGroup, conn1, fmt.Sprintf("wg%d", i))
		require.NoError(t, pub.Disable(id))
		require.NoError(t, pub.Enable(id))
	}
}

func TestStatusCodeOf(t *testing.T) {
	t.Parallel()
	require.Equal(t, ua.StatusGood, StatusCodeOf(nil))
	require.Equal(t, ua.StatusBadConfigurationError, StatusCodeOf(configErr("x", "y")))
	require.Equal(t, ua.StatusBadInternalError, StatusCodeOf(errors.New("x")))
	require.Equal(t, ua.StatusBadNotFound, StatusCodeOf(notFound(KindConnection, 3)))
	require.Equal(t, "pubsub: y", (&ConfigError{Msg: "y"}).Error())
	for k := KindPubSub; k <= KindPublishedDataSet; k++ {
		require.NotContains(t, k.String(), "ComponentKind")
	}
	require.Contains(t, ComponentKind(42).String(), "42")
	require.Equal(t, "JSON", encJSON.String())
	require.Equal(t, "UADP", encUADP.String())
}
