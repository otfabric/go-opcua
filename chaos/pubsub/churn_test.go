// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// churn is the state of a churn scenario: a server whose PubSub runtime
// carries a checked base stream (connection "base" publishing data set
// "base" to its own reader) while workers add, remove, enable and disable
// other components.
type churn struct {
	t     *testing.T
	srv   *server.Server
	url   string
	rt    *pubsub.PubSub
	chk   *checker
	wd    *chaoskit.Watchdog
	ports []int
	sink  *chaoskit.ErrSink

	closed atomic.Bool
	ops    atomic.Int64
	fails  sync.Map // status -> count
}

func newChurn(t *testing.T) *churn {
	t.Helper()
	c := &churn{t: t, chk: newChecker(), wd: chaoskit.NewWatchdog(t)}
	c.sink = c.chk.sink
	for range 4 {
		c.ports = append(c.ports, freeUDPPort(t))
	}
	basePort := freeUDPPort(t)
	r := pubsub.DataSetReader("base", uint16(1), 1, 1, pubsub.DataSetMetaDataOf(counterPDS("base")))
	r.MessageReceiveTimeout = 2000
	base := pubsub.AttachReaderGroups(
		pubsub.AttachWriterGroups(pubsub.UDPConnection("base", udpURL(basePort), uint16(1)),
			pubsub.WriterGroup("basewg", 1, 10*time.Millisecond, pubsub.DataSetWriter("basew", 1, "base"))),
		pubsub.ReaderGroup("baserg", r))
	cfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{counterPDS("base")}, base)
	c.srv, c.url = testutil.NewTestServer(t, server.WithPubSub(cfg,
		pubsub.WithDataSource(newCounterSource()), pubsub.WithDataSetHandler(c.handle), pubsub.WithRetryInterval(50*time.Millisecond)))
	c.rt = c.srv.PubSub()
	c.chk.waitGrowth(t, 5, "base")
	return c
}

// handle checks the base stream strictly. The churn readers take whatever
// the churn writers send, from writers that come and go: their data sets
// must still be intact.
func (c *churn) handle(d *pubsub.ReceivedDataSet) {
	if d.ReaderName == "base" {
		c.chk.handle(d)
		return
	}
	if len(d.Fields) != 3 || !d.Complete {
		return
	}
	var vals [3]any
	for i, f := range d.Fields {
		if f.Value == nil || f.Value.Value == nil {
			return
		}
		vals[i] = f.Value.Value.Value()
	}
	n, ok1 := vals[0].(int64)
	s, ok2 := vals[1].(string)
	f, ok3 := vals[2].(float64)
	ds, _, _ := strings.Cut(s, "#")
	if !ok1 || !ok2 || !ok3 || s != checkString(ds, n) || f != float64(n)/4 {
		c.sink.Addf("reader %s: corrupt data set %v", d.ReaderName, vals)
	}
}

// check records the error of an operation: errors with a status the
// operation may fail with are expected, anything else is a violation.
func (c *churn) check(op string, err error) {
	c.ops.Add(1)
	if err == nil {
		return
	}
	if errors.Is(err, pubsub.ErrClosed) && c.closed.Load() {
		return
	}
	var sc ua.StatusCode
	if !errors.As(err, &sc) {
		if c.closed.Load() {
			return
		}
		c.sink.Addf("%s: unexpected error %v", op, err)
		return
	}
	switch sc {
	case ua.StatusBadNotFound, ua.StatusBadNodeIDUnknown, ua.StatusBadInvalidState, ua.StatusBadBrowseNameDuplicated,
		ua.StatusBadConfigurationError, ua.StatusBadNotSupported, ua.StatusBadInvalidArgument, ua.StatusBadNodeIDInvalid,
		ua.StatusBadMethodInvalid, ua.StatusBadObjectDeleted:
		v, _ := c.fails.LoadOrStore(sc.Error(), new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
	default:
		if c.closed.Load() {
			return
		}
		c.sink.Addf("%s: unexpected status %v (%v)", op, sc, err)
	}
}

// churnComponents returns the components other than the base stream.
func (c *churn) churnComponents(kinds ...pubsub.ComponentKind) []pubsub.ComponentInfo {
	var out []pubsub.ComponentInfo
	for _, x := range c.rt.Components() {
		if strings.HasPrefix(x.Name, "base") {
			continue
		}
		for _, k := range kinds {
			if x.Kind == k {
				out = append(out, x)
			}
		}
	}
	return out
}

func pick[T any](rng *rand.Rand, xs []T) (T, bool) {
	var zero T
	if len(xs) == 0 {
		return zero, false
	}
	return xs[rng.Intn(len(xs))], true
}

// apiWorker changes the runtime through its Go API.
func (c *churn) apiWorker(rng *rand.Rand, stop <-chan struct{}) {
	rt := c.rt
	for {
		select {
		case <-stop:
			return
		default:
		}
		n := rng.Intn(4)
		var op string
		err := c.wd.Do("api", func() error {
			switch rng.Intn(12) {
			case 0:
				op = "AddConnection"
				_, err := rt.AddConnection(pubsub.UDPConnection(fmt.Sprintf("cc%d", n), udpURL(c.ports[rng.Intn(len(c.ports))]), uint16(100+n)))
				return err
			case 1:
				op = "AddPublishedDataSet"
				_, err := rt.AddPublishedDataSet(counterPDS(fmt.Sprintf("p%d", n)))
				return err
			case 2:
				op = "RemovePublishedDataSet"
				if x, ok := pick(rng, c.churnComponents(pubsub.KindPublishedDataSet)); ok {
					return rt.RemovePublishedDataSet(x.ID)
				}
			case 3:
				op = "AddWriterGroup"
				if x, ok := pick(rng, c.churnComponents(pubsub.KindConnection)); ok {
					_, err := rt.AddWriterGroup(x.ID, pubsub.WriterGroup(fmt.Sprintf("g%d", n), uint16(10+rng.Intn(4)), time.Duration(5+rng.Intn(20))*time.Millisecond,
						pubsub.DataSetWriter(fmt.Sprintf("w%d", rng.Intn(3)), uint16(1+rng.Intn(3)), fmt.Sprintf("p%d", rng.Intn(4)))))
					return err
				}
			case 4:
				op = "AddDataSetWriter"
				if x, ok := pick(rng, c.churnComponents(pubsub.KindWriterGroup)); ok {
					_, err := rt.AddDataSetWriter(x.ID, pubsub.DataSetWriter(fmt.Sprintf("w%d", n), uint16(1+rng.Intn(4)), fmt.Sprintf("p%d", rng.Intn(4))))
					return err
				}
			case 5:
				op = "AddReaderGroup"
				if x, ok := pick(rng, c.churnComponents(pubsub.KindConnection)); ok {
					_, err := rt.AddReaderGroup(x.ID, pubsub.ReaderGroup(fmt.Sprintf("rg%d", n), pubsub.DataSetReader("r0", nil, 0, 0, nil)))
					return err
				}
			case 6:
				op = "AddDataSetReader"
				if x, ok := pick(rng, c.churnComponents(pubsub.KindReaderGroup)); ok {
					r := pubsub.DataSetReader(fmt.Sprintf("r%d", n), uint16(100+rng.Intn(4)), 0, 0, nil)
					r.MessageReceiveTimeout = float64(10 + rng.Intn(100))
					_, err := rt.AddDataSetReader(x.ID, r)
					return err
				}
			case 7:
				op = "Remove"
				if x, ok := pick(rng, c.churnComponents(pubsub.KindConnection, pubsub.KindWriterGroup, pubsub.KindReaderGroup, pubsub.KindDataSetWriter, pubsub.KindDataSetReader)); ok {
					switch x.Kind {
					case pubsub.KindConnection:
						return rt.RemoveConnection(x.ID)
					case pubsub.KindWriterGroup, pubsub.KindReaderGroup:
						return rt.RemoveGroup(x.ID)
					case pubsub.KindDataSetWriter:
						return rt.RemoveDataSetWriter(x.ID)
					default:
						return rt.RemoveDataSetReader(x.ID)
					}
				}
			case 8, 9:
				op = "Enable/Disable"
				if x, ok := pick(rng, c.churnComponents(pubsub.KindConnection, pubsub.KindWriterGroup, pubsub.KindReaderGroup, pubsub.KindDataSetWriter, pubsub.KindDataSetReader)); ok {
					if rng.Intn(2) == 0 {
						return rt.Enable(x.ID)
					}
					return rt.Disable(x.ID)
				}
			default:
				op = "read"
				_ = rt.Configuration()
				for _, x := range c.churnComponents(pubsub.KindConnection, pubsub.KindDataSetReader) {
					_, _ = rt.Status(x.ID)
				}
			}
			return nil
		})
		c.check(op, err)
	}
}

// remoteWorker changes the runtime through the methods of the information
// model, with its own session.
func (c *churn) remoteWorker(rng *rand.Rand, cl *opcua.Client, w int, stop <-chan struct{}) {
	r := remote.New(cl)
	ctx := context.Background()
	currentTime := ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime)
	all := func() []remote.Component {
		var out []remote.Component
		conns, err := r.Connections(ctx)
		if err != nil {
			return nil
		}
		for _, cn := range conns {
			if cn.Name == "base" {
				continue
			}
			out = append(out, cn)
			wgs, _ := r.WriterGroups(ctx, cn.NodeID)
			rgs, _ := r.ReaderGroups(ctx, cn.NodeID)
			out = append(out, wgs...)
			out = append(out, rgs...)
		}
		return out
	}
	for {
		select {
		case <-stop:
			return
		default:
		}
		n := rng.Intn(3)
		var op string
		err := c.wd.Do("remote", func() error {
			switch rng.Intn(9) {
			case 0:
				op = "remote AddConnection"
				cfg := pubsub.AttachWriterGroups(pubsub.UDPConnection(fmt.Sprintf("rc%d-%d", w, n), udpURL(c.ports[rng.Intn(len(c.ports))]), uint16(200+n)),
					pubsub.WriterGroup("wg", 1, 20*time.Millisecond))
				_, err := r.AddConnection(ctx, cfg)
				return err
			case 1:
				op = "remote AddPublishedDataItems"
				_, err := r.AddPublishedDataItems(ctx, fmt.Sprintf("rp%d", n), []string{"t"}, nil,
					[]*ua.PublishedVariableDataType{{PublishedVariable: currentTime, AttributeID: ua.AttributeIDValue}})
				return err
			case 2:
				op = "remote RemovePublishedDataSet"
				pdss, err := r.PublishedDataSets(ctx)
				if err != nil {
					return err
				}
				var mine []remote.Component
				for _, p := range pdss {
					if strings.HasPrefix(p.Name, "rp") {
						mine = append(mine, p)
					}
				}
				if x, ok := pick(rng, mine); ok {
					return r.RemovePublishedDataSet(ctx, x.NodeID)
				}
			case 3:
				op = "remote AddWriterGroup/AddDataSetWriter"
				conns, err := r.Connections(ctx)
				if err != nil {
					return err
				}
				var mine []remote.Component
				for _, cn := range conns {
					if cn.Name != "base" {
						mine = append(mine, cn)
					}
				}
				x, ok := pick(rng, mine)
				if !ok {
					return nil
				}
				g, err := r.AddWriterGroup(ctx, x.NodeID, pubsub.WriterGroup(fmt.Sprintf("rg%d", n), uint16(20+n), 15*time.Millisecond))
				if err != nil {
					return err
				}
				_, err = r.AddDataSetWriter(ctx, g, pubsub.DataSetWriter("w", 1, fmt.Sprintf("rp%d", rng.Intn(3))))
				return err
			case 4:
				op = "remote AddReaderGroup/AddDataSetReader"
				conns, err := r.Connections(ctx)
				if err != nil {
					return err
				}
				var mine []remote.Component
				for _, cn := range conns {
					if cn.Name != "base" {
						mine = append(mine, cn)
					}
				}
				x, ok := pick(rng, mine)
				if !ok {
					return nil
				}
				g, err := r.AddReaderGroup(ctx, x.NodeID, pubsub.ReaderGroup(fmt.Sprintf("rr%d", n)))
				if err != nil {
					return err
				}
				_, err = r.AddDataSetReader(ctx, g, pubsub.DataSetReader("r", nil, 0, 0, nil))
				return err
			case 5:
				op = "remote Enable/Disable"
				if x, ok := pick(rng, all()); ok {
					if rng.Intn(2) == 0 {
						return r.Enable(ctx, x.NodeID)
					}
					return r.Disable(ctx, x.NodeID)
				}
			case 6:
				op = "remote RemoveConnection"
				conns, err := r.Connections(ctx)
				if err != nil {
					return err
				}
				var mine []remote.Component
				for _, cn := range conns {
					if strings.HasPrefix(cn.Name, fmt.Sprintf("rc%d-", w)) {
						mine = append(mine, cn)
					}
				}
				if x, ok := pick(rng, mine); ok {
					return r.RemoveConnection(ctx, x.NodeID)
				}
			default:
				op = "remote State"
				if x, ok := pick(rng, all()); ok {
					_, err := r.State(ctx, x.NodeID)
					return err
				}
			}
			return nil
		})
		var re *remote.Error
		switch {
		case errors.As(err, &re):
			c.check(op, re.Status)
		case err != nil && !c.closed.Load():
			// A component removed by another worker between the
			// browse and the call.
			if errors.Is(err, ua.StatusBadNotFound) || errors.Is(err, ua.StatusBadNodeIDUnknown) {
				c.check(op, nil)
				continue
			}
			c.sink.Addf("%s: %v", op, err)
		default:
			c.check(op, nil)
		}
	}
}

// tree returns the components of the runtime as paths of names.
func runtimeTree(rt *pubsub.PubSub) []string {
	comps := rt.Components()
	byID := map[pubsub.ComponentID]pubsub.ComponentInfo{}
	for _, x := range comps {
		byID[x.ID] = x
	}
	var out []string
	for _, x := range comps {
		path := x.Name
		for p := x.Parent; p != pubsub.Root; p = byID[p].Parent {
			path = byID[p].Name + "/" + path
		}
		if x.Kind == pubsub.KindPublishedDataSet {
			path = "PublishedDataSets/" + path
		}
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// browseTree returns the components of the information model as paths of
// names.
func browseTree(ctx context.Context, r *remote.Client) ([]string, error) {
	var out []string
	conns, err := r.Connections(ctx)
	if err != nil {
		return nil, err
	}
	for _, cn := range conns {
		out = append(out, cn.Name)
		wgs, err := r.WriterGroups(ctx, cn.NodeID)
		if err != nil {
			return nil, err
		}
		for _, g := range wgs {
			out = append(out, cn.Name+"/"+g.Name)
			ws, err := r.DataSetWriters(ctx, g.NodeID)
			if err != nil {
				return nil, err
			}
			for _, w := range ws {
				out = append(out, cn.Name+"/"+g.Name+"/"+w.Name)
			}
		}
		rgs, err := r.ReaderGroups(ctx, cn.NodeID)
		if err != nil {
			return nil, err
		}
		for _, g := range rgs {
			out = append(out, cn.Name+"/"+g.Name)
			rs, err := r.DataSetReaders(ctx, g.NodeID)
			if err != nil {
				return nil, err
			}
			for _, x := range rs {
				out = append(out, cn.Name+"/"+g.Name+"/"+x.Name)
			}
		}
	}
	pdss, err := r.PublishedDataSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pdss {
		out = append(out, "PublishedDataSets/"+p.Name)
	}
	sort.Strings(out)
	return out, nil
}

// TestChaosRuntimeChurn adds, removes, enables and disables connections,
// groups, writers, readers and published data sets of a server's PubSub
// runtime while traffic flows: through the Go API from several goroutines
// and through the methods of the information model from several OPC UA
// clients at once. The base stream must keep flowing untouched, every
// operation must return in time with a status it may fail with, and
// afterwards the information model must show exactly the components of the
// runtime. Then the server is closed in the middle of the churn.
func TestChaosRuntimeChurn(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	c := newChurn(t)
	clients := make([]*opcua.Client, 3)
	for i := range clients {
		clients[i] = testutil.NewTestClient(t, c.url)
	}

	run := func(d time.Duration) {
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for i := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.apiWorker(rand.New(rand.NewSource(seed+int64(i))), stop)
			}()
		}
		for i, cl := range clients {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.remoteWorker(rand.New(rand.NewSource(seed+100+int64(i))), cl, i, stop)
			}()
		}
		time.Sleep(d)
		close(stop)
		c.wd.Wait("churn workers", &wg)
	}
	run(chaoskit.Duration(t, defaultDuration))
	t.Logf("%d operations", c.ops.Load())
	c.fails.Range(func(k, v any) bool {
		t.Logf("  %6d x %v", v.(*atomic.Int64).Load(), k)
		return true
	})

	// The base stream was never disturbed and still flows.
	c.chk.waitGrowth(t, 10, "base")
	if n := c.chk.count("base"); n < 50 {
		t.Errorf("base stream delivered only %d data sets", n)
	}

	// The information model shows the runtime.
	ctx := context.Background()
	r := remote.New(clients[0])
	var want, got []string
	ok := chaoskit.Eventually(5*time.Second, func() bool {
		want = runtimeTree(c.rt)
		var err error
		got, err = browseTree(ctx, r)
		return err == nil && strings.Join(want, "\n") == strings.Join(got, "\n")
	})
	if !ok {
		t.Errorf("information model differs from the runtime:\nruntime:\n  %s\nmodel:\n  %s", strings.Join(want, "\n  "), strings.Join(got, "\n  "))
	}
	for _, x := range c.rt.Components() {
		if _, ok := c.srv.PubSubNodeID(x.ID); !ok {
			t.Errorf("%v %q (%d) has no node", x.Kind, x.Name, x.ID)
		}
	}

	// Close the server while the workers keep going.
	stopAll := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.apiWorker(rand.New(rand.NewSource(seed+1000+int64(i))), stopAll)
		}()
	}
	time.Sleep(200 * time.Millisecond)
	c.closed.Store(true)
	if err := c.wd.Do("server Close", c.srv.Close); err != nil {
		t.Logf("server Close: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	close(stopAll)
	c.wd.Wait("workers after Close", &wg)
	if c.rt.Running() {
		t.Error("the runtime still runs after the server was closed")
	}
	c.sink.Report(t)
}
