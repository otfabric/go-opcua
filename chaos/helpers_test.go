// SPDX-License-Identifier: MIT

package chaos

import (
	"bytes"
	"context"
	stderrors "errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// ---------------------------------------------------------------------------
// knobs
// ---------------------------------------------------------------------------

const (
	envSeed     = "CHAOS_SEED"
	envDuration = "CHAOS_DURATION"
	envLog      = "CHAOS_LOG"

	// defaultDuration is the length of the fault-injection phase of each
	// randomized scenario when CHAOS_DURATION is not set.
	defaultDuration = 3 * time.Second

	// opLimit bounds every single client operation. An operation that has not
	// returned (with success or an error) after this long is a deadlock.
	opLimit = 45 * time.Second

	// settleLimit bounds every "eventually" condition (reconnect, resource
	// release, goroutine exit). It is generous (what it waits for takes a
	// few seconds at most, also under the race detector on a loaded
	// machine) but it is a budget, too: CI gives the package 120 s, and a
	// scenario that fails has to fail with its diagnosis inside that time
	// instead of running into the timeout of the test binary.
	settleLimit = 30 * time.Second

	// budgetReserve is what the waits leave of the time the test binary may
	// run (-timeout): time for the tests to report and clean up. minWait is
	// the least any wait gets.
	budgetReserve = 15 * time.Second
	minWait       = 3 * time.Second
)

// binaryStart is when this test binary started, binaryDeadline when its
// -timeout expires (zero without one).
var (
	binaryStart    = time.Now()
	deadlineOnce   sync.Once
	binaryDeadline time.Time
)

// withinBudget cuts a wait so that it ends budgetReserve before the test
// binary runs into its -timeout. Several waits that fail one after the other
// (a scenario that is stuck fails its recovery check, then the checks after
// it) would otherwise add up to more than CI gives the package, and the
// diagnosis of the first one would be lost in the timeout panic of the
// binary. Healthy tests never get near the deadline and are not affected.
func withinBudget(limit time.Duration) time.Duration {
	deadlineOnce.Do(func() {
		if f := flag.Lookup("test.timeout"); f != nil {
			if d, err := time.ParseDuration(f.Value.String()); err == nil && d > 0 {
				binaryDeadline = binaryStart.Add(d - budgetReserve)
			}
		}
	})
	if binaryDeadline.IsZero() {
		return limit
	}
	left := time.Until(binaryDeadline)
	if left < minWait {
		left = minWait
	}
	if limit > left {
		return left
	}
	return limit
}

var processSeed = time.Now().UnixNano()

// seedFor returns the seed for a scenario. CHAOS_SEED overrides the
// per-process random seed so a failure can be replayed.
func seedFor(t *testing.T) int64 {
	t.Helper()
	seed := processSeed
	if s := os.Getenv(envSeed); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("invalid %s=%q: %v", envSeed, s, err)
		}
		seed = v
	}
	t.Logf("chaos seed: %d (replay with %s=%d go test -race -run '^%s$' ./chaos/)", seed, envSeed, seed, t.Name())
	return seed
}

// debugLogger returns a logger for the server and the clients when CHAOS_LOG
// names a level (debug, info, warn, error), and nil otherwise.
func debugLogger() *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(os.Getenv(envLog))); err != nil || os.Getenv(envLog) == "" {
		return nil
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// chaosDuration returns the length of the fault-injection phase.
func chaosDuration(t *testing.T) time.Duration {
	t.Helper()
	s := os.Getenv(envDuration)
	if s == "" {
		return defaultDuration
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		t.Fatalf("invalid %s=%q", envDuration, s)
	}
	return d
}

// ---------------------------------------------------------------------------
// environment: server (+ optional chaos proxy)
// ---------------------------------------------------------------------------

const (
	numCounters = 4
	numScratch  = 8
	numBrowse   = 40
	blobSize    = 160 * 1024 // 3 chunks with the default 64k buffers
)

// env is a server behind a chaos proxy. The server can be stopped and
// replaced by a fresh instance while the proxy keeps its client-facing port.
type env struct {
	t     *testing.T
	seed  int64
	proxy *testutil.ChaosProxy

	// serverOpts are additional options for every server instance.
	serverOpts []server.Option

	// directPort is set for an environment without a proxy: the server
	// listens on this fixed port and clients connect to it directly.
	directPort int

	mu  sync.Mutex
	srv *server.Server
	nsp *server.NodeNameSpace // chaos namespace of srv

	ns uint16 // namespace index of the chaos nodes (stable across restarts)

	// counters holds the last value handed out for each counter node. Values
	// are only ever written in increasing order, see nextCounter.
	counters [numCounters]atomic.Int64

	// stopped servers whose resources must still drain
	old []*server.Server
}

func newEnv(t *testing.T, seed int64, serverOpts ...server.Option) *env {
	t.Helper()
	e := &env{t: t, seed: seed, serverOpts: serverOpts}
	e.proxy = testutil.NewChaosProxy(t, "", seed)
	e.startServer()
	t.Cleanup(func() { e.stopServer() })
	return e
}

// newDirectEnv creates an environment without a proxy. The server listens on
// a fixed port, so that a restarted instance is reachable at the very same
// address. The port is outside the ephemeral range, where no outgoing socket
// of a parallel package takes it, and the server listens and the client dials
// on 127.0.0.1: "localhost" may resolve to ::1 first, where another process
// can listen on the same port.
func newDirectEnv(t *testing.T, seed int64) *env {
	t.Helper()
	e := &env{t: t, seed: seed, directPort: testport.TCP(t)}
	e.startServer()
	t.Cleanup(func() { e.stopServer() })
	return e
}

// url is the endpoint clients dial: the chaos proxy, or the server itself in
// a direct environment.
func (e *env) url() string {
	if e.proxy == nil {
		return fmt.Sprintf("opc.tcp://127.0.0.1:%d", e.directPort)
	}
	return e.proxy.EndpointURL()
}

// directAddr is the server's real listen address, bypassing the proxy.
func (e *env) directAddr() string {
	return fmt.Sprintf("localhost:%d", e.server().Port())
}

func (e *env) server() *server.Server {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.srv
}

func (e *env) nodeID(name string) *ua.NodeID { return ua.NewStringNodeID(e.ns, name) }
func (e *env) counterID(i int) *ua.NodeID    { return e.nodeID(fmt.Sprintf("Counter%d", i)) }
func (e *env) scratchID(i int) *ua.NodeID    { return e.nodeID(fmt.Sprintf("Scratch%d", i)) }
func (e *env) blobID() *ua.NodeID            { return e.nodeID("Blob") }
func (e *env) folderID() *ua.NodeID          { return e.nodeID("Folder") }
func (e *env) methodID() *ua.NodeID          { return e.nodeID("Square") }
func (e *env) objectsID() *ua.NodeID         { return ua.NewNumericNodeID(e.ns, id.ObjectsFolder) }

// startServer creates and starts a new server instance and points the proxy
// at it. The server advertises the proxy's port as its endpoint and listens
// on an ephemeral port, so the client-visible endpoint is identical for every
// instance.
func (e *env) startServer() {
	e.t.Helper()
	opts := []server.Option{
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.SetLogger(debugLogger()),
	}
	opts = append(opts, e.serverOpts...)
	if e.proxy != nil {
		opts = append(opts, server.EndPoint("localhost", e.proxy.Port()), server.ListenOn("localhost:0"))
	} else {
		opts = append(opts, server.EndPoint("127.0.0.1", e.directPort))
	}
	srv, err := server.New(opts...)
	if err != nil {
		e.t.Fatalf("chaos: new server: %v", err)
	}
	nsp := e.populate(srv)
	// In a direct environment the port was in use by the previous instance a
	// moment ago; allow the bind a few attempts.
	if !eventually(15*time.Second, func() bool {
		err = srv.Start(context.Background())
		return err == nil
	}) {
		e.t.Fatalf("chaos: start server: %v", err)
	}
	e.mu.Lock()
	e.srv = srv
	e.nsp = nsp
	e.mu.Unlock()
	if e.proxy != nil {
		e.proxy.SetBackend(fmt.Sprintf("localhost:%d", srv.Port()))
	}
}

// stopServer closes the current server instance (if any).
func (e *env) stopServer() {
	e.mu.Lock()
	srv := e.srv
	e.srv = nil
	e.nsp = nil
	if srv != nil {
		e.old = append(e.old, srv)
	}
	e.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// restartServer replaces the server with a brand-new instance: all sessions,
// subscriptions and monitored items are lost, as after a process restart.
func (e *env) restartServer(downtime time.Duration) {
	e.proxy.SetRefuse(true)
	e.stopServer()
	e.proxy.DropAll()
	time.Sleep(downtime)
	e.startServer()
	e.proxy.SetRefuse(false)
}

// populate adds the chaos namespace to srv.
func (e *env) populate(srv *server.Server) *server.NodeNameSpace {
	e.t.Helper()
	root, err := srv.Namespace(0)
	if err != nil {
		e.t.Fatalf("chaos: namespace 0: %v", err)
	}
	ns := server.NewNodeNameSpace(srv, "http://otfabric.com/chaos")
	obj := ns.Objects()
	root.Objects().AddRef(obj, id.HasComponent, true)
	if e.ns == 0 {
		// The index is the same for every server instance. Workers read it
		// while a restart populates the next instance, so write it only once.
		e.ns = ns.ID()
	}

	add := func(parent *server.Node, name string, v any) {
		n := ns.AddNewVariableStringNode(name, v)
		parent.AddRef(n, id.HasComponent, true)
	}
	for i := 0; i < numCounters; i++ {
		// A restarted server continues at the last value handed out so that
		// the values observed by subscribers never go backwards.
		add(obj, fmt.Sprintf("Counter%d", i), e.counters[i].Load())
	}
	for i := 0; i < numScratch; i++ {
		add(obj, fmt.Sprintf("Scratch%d", i), int32(i))
	}
	add(obj, "Blob", bytes.Repeat([]byte{0xA5}, blobSize))

	folder := server.NewFolderNode(e.folderID(), "Folder")
	ns.AddNode(folder)
	obj.AddRef(folder, id.HasComponent, true)
	for i := 0; i < numBrowse; i++ {
		add(folder, fmt.Sprintf("Leaf%03d", i), int32(i))
	}

	method := server.NewFolderNode(e.methodID(), "Square")
	method.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(method)
	obj.AddRef(method, id.HasComponent, true)
	for prop, name := range map[string]string{"InputArguments": "n", "OutputArguments": "result"} {
		arg := ua.NewExtensionObject(&ua.Argument{
			Name:        name,
			DataType:    ua.NewNumericNodeID(0, id.Int32),
			ValueRank:   -1,
			Description: ua.NewLocalizedText(name),
		})
		value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]*ua.ExtensionObject{arg})}
		pn := server.NewNode(
			e.nodeID("Square."+prop),
			map[ua.AttributeID]*ua.DataValue{
				ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
				ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(prop)),
				ua.AttributeIDDataType:   server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
			},
			nil,
			func() *ua.DataValue { return value },
		)
		ns.AddNode(pn)
		method.AddRef(pn, id.HasProperty, true)
	}
	srv.RegisterMethod(obj.ID(), e.methodID(),
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 1 || args[0] == nil {
				return nil, ua.StatusBadArgumentsMissing
			}
			n, ok := args[0].Value().(int32)
			if !ok {
				return nil, ua.StatusBadInvalidArgument
			}
			return []*ua.Variant{ua.MustVariant(n * n)}, ua.StatusOK
		})
	return ns
}

// bump writes the next value of counter i directly into the address space of
// the running server, as an application embedding the server would. The
// values written to a counter strictly increase, also across restarts. It
// returns the value written, or 0 when no server is running.
func (e *env) bump(i int) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.nsp == nil {
		return 0
	}
	v := e.counters[i].Add(1)
	if sc := e.nsp.SetAttribute(e.counterID(i), ua.AttributeIDValue, server.DataValueFromValue(v)); sc != ua.StatusOK {
		e.t.Errorf("server-side write of Counter%d failed: %v", i, sc)
	}
	return v
}

// namespace returns the chaos namespace of the running server.
func (e *env) namespace() *server.NodeNameSpace {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.nsp
}

// clientOptions returns the options for a client that talks through the proxy.
func (e *env) clientOptions(rec *stateRecorder, extra ...opcua.Option) []opcua.Option {
	opts := []opcua.Option{
		opcua.InsecureNoSecurity(),
		opcua.DialTimeout(10 * time.Second),
		// Fault-free tests must never fail because the machine is slow, so
		// the default request timeout only guards against a hang. Scenarios
		// that inject faults pass a short timeout instead.
		opcua.RequestTimeout(30 * time.Second),
		opcua.ReconnectInterval(50 * time.Millisecond),
		opcua.AutoReconnect(true),
	}
	if rec != nil {
		opts = append(opts, opcua.WithConnStateHandler(rec.handle))
	}
	if l := debugLogger(); l != nil {
		opts = append(opts, opcua.WithLogger(l.With("side", "client")))
	}
	return append(opts, extra...)
}

// connect creates and connects a client through the proxy. The client is
// closed when the test ends unless the test closed it earlier.
func (e *env) connect(rec *stateRecorder, extra ...opcua.Option) *opcua.Client {
	e.t.Helper()
	c, err := e.dial(rec, extra...)
	if err != nil {
		e.t.Fatalf("chaos: connect: %v", err)
	}
	return c
}

func (e *env) dial(rec *stateRecorder, extra ...opcua.Option) (*opcua.Client, error) {
	c, err := opcua.NewClient(e.url(), append([]opcua.Option{opcua.InsecureNoSecurity()}, e.clientOptions(rec, extra...)...)...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		closeClient(c, rec)
		return nil, err
	}
	e.t.Cleanup(func() { closeClient(c, rec) })
	return c, nil
}

// closeClient closes c with a bounded context and tells the recorder that the
// user initiated the shutdown.
func closeClient(c *opcua.Client, rec *stateRecorder) {
	if rec != nil {
		rec.markClosing()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Close(ctx)
}

// resources returns the per-client resources held by the current server.
func (e *env) resources() testhook.ServerResources {
	srv := e.server()
	if srv == nil {
		return testhook.ServerResources{}
	}
	return testhook.ServerResourcesOf(srv)
}

// settleRequests waits until the server has handled every request that the
// clients of the storm sent. A worker that returned may have left a request
// behind: the proxy dropped its connection, or its RequestTimeout passed,
// after the server had read the request, and the server still handles what
// it read before a channel ended (a Call to Acknowledge or to Reset, say),
// possibly well after the worker gave up on it. A check of the server's
// state right after the storm would then race with that request.
//
// Once no channel is left, every request read has been handed to the
// server's request handler, which handles the requests of all channels one
// at a time in the order it takes them. The session that a new client then
// creates is handled after them, so when Connect returns they are done. The
// clients of the storm must all be closed.
func (e *env) settleRequests() {
	e.t.Helper()
	if !eventually(settleLimit, func() bool { return e.resources().Channels == 0 }) {
		e.t.Fatalf("server still holds %d channel(s) after the storm", e.resources().Channels)
	}
	c := e.connect(nil, opcua.AutoReconnect(false))
	closeClient(c, nil)
}

// requireServerDrained waits until the current server holds no channels,
// sessions, subscriptions or monitored items.
func (e *env) requireServerDrained(limit time.Duration) {
	e.t.Helper()
	var last testhook.ServerResources
	ok := eventually(limit, func() bool {
		last = e.resources()
		return last == testhook.ServerResources{}
	})
	if !ok {
		e.t.Errorf("server did not release client resources within %v: %+v; sessions: %v", limit, last, testhook.ServerSessionsOf(e.server()))
	}
}

// requireCleanClient verifies that the server still serves a brand-new client
// correctly: connect, read, write/read-back, browse, call, subscribe and
// receive a data change, then shut down cleanly.
func (e *env) requireCleanClient() {
	e.t.Helper()
	t := e.t

	var c *opcua.Client
	var err error
	// The listener backlog may still hold connections that were queued during
	// the storm, so allow a few attempts; each one is individually bounded.
	ok := eventually(settleLimit, func() bool {
		c, err = e.dial(nil, opcua.AutoReconnect(false), opcua.RequestTimeout(30*time.Second))
		return err == nil
	})
	if !ok {
		t.Errorf("clean client could not connect after the storm: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	want := int32(rand.Int31())
	if sc, err := c.WriteNodeValue(ctx, e.scratchID(0), want); err != nil || sc != ua.StatusOK {
		t.Errorf("clean client: write: status=%v err=%v", sc, err)
	}
	dv, err := c.ReadValue(ctx, e.scratchID(0))
	if err != nil {
		t.Errorf("clean client: read: %v", err)
	} else if got, _ := dv.Value.Value().(int32); got != want {
		t.Errorf("clean client: read back %v, want %v", dv.Value.Value(), want)
	}

	blob, err := c.ReadValue(ctx, e.blobID())
	if err != nil {
		t.Errorf("clean client: read blob: %v", err)
	} else if b, _ := blob.Value.Value().([]byte); len(b) != blobSize {
		t.Errorf("clean client: blob length %d, want %d", len(b), blobSize)
	}

	refs, err := c.BrowseAll(ctx, e.folderID())
	if err != nil {
		t.Errorf("clean client: browse: %v", err)
	} else if n := countLeaves(refs); n != numBrowse {
		t.Errorf("clean client: browse returned %d leaves, want %d", n, numBrowse)
	}

	res, err := c.CallMethod(ctx, e.objectsID(), e.methodID(), int32(7))
	if err != nil {
		t.Errorf("clean client: call: %v", err)
	} else if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != int32(49) {
		t.Errorf("clean client: call result %+v", res)
	}

	ch := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 20 * time.Millisecond}, ch)
	if err != nil {
		t.Errorf("clean client: subscribe: %v", err)
	} else {
		mres, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
			opcua.NewMonitoredItemCreateRequestWithDefaults(e.scratchID(1), ua.AttributeIDValue, 1))
		if err != nil || mres.Results[0].StatusCode != ua.StatusOK {
			t.Errorf("clean client: monitor: res=%+v err=%v", mres, err)
		}
		marker := int32(rand.Int31())
		if _, err := c.WriteNodeValue(ctx, e.scratchID(1), marker); err != nil {
			t.Errorf("clean client: write marker: %v", err)
		}
		deadline := time.After(settleLimit)
	wait:
		for {
			select {
			case n := <-ch:
				if n.Error != nil {
					continue
				}
				if dcn, ok := n.Value.(*ua.DataChangeNotification); ok {
					for _, mi := range dcn.MonitoredItems {
						if mi.Value != nil && mi.Value.Value != nil && mi.Value.Value.Value() == marker {
							break wait
						}
					}
				}
			case <-deadline:
				t.Errorf("clean client: no data change for the marker value within %v", settleLimit)
				break wait
			}
		}
		if err := sub.Cancel(ctx); err != nil {
			t.Errorf("clean client: cancel subscription: %v", err)
		}
	}
	closeClient(c, nil)
}

// ---------------------------------------------------------------------------
// generic helpers
// ---------------------------------------------------------------------------

// countLeaves returns the number of the static LeafNNN children among refs.
func countLeaves(refs []*ua.ReferenceDescription) int {
	n := 0
	for _, r := range refs {
		if r != nil && r.BrowseName != nil && strings.HasPrefix(r.BrowseName.Name, "Leaf") {
			n++
		}
	}
	return n
}

// eventually polls cond until it returns true or limit expires.
//
// A wait never runs past the time budget of the test binary, see
// withinBudget.
func eventually(limit time.Duration, cond func() bool) bool {
	limit = withinBudget(limit)
	deadline := time.Now().Add(limit)
	for wait := 5 * time.Millisecond; ; {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(wait)
		if wait < 200*time.Millisecond {
			wait *= 2
		}
	}
}

// waitGroupTimeout waits for wg and reports whether it finished within limit.
func waitGroupTimeout(wg *sync.WaitGroup, limit time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(withinBudget(limit)):
		return false
	}
}

// allStacks returns the stacks of all goroutines.
func allStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// ---------------------------------------------------------------------------
// deadlock watchdog
// ---------------------------------------------------------------------------

// watchdog tracks in-flight operations and fails the test when one of them
// does not return within opLimit.
type watchdog struct {
	t     *testing.T
	limit time.Duration

	mu    sync.Mutex
	ops   map[uint64]opInfo
	next  uint64
	fired bool

	stop chan struct{}
	done chan struct{}
}

type opInfo struct {
	name  string
	start time.Time
}

func newWatchdog(t *testing.T) *watchdog {
	w := &watchdog{
		t:     t,
		limit: opLimit,
		ops:   make(map[uint64]opInfo),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go w.run()
	t.Cleanup(w.close)
	return w
}

func (w *watchdog) close() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
}

func (w *watchdog) run() {
	defer close(w.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-tick.C:
			w.check()
		}
	}
}

func (w *watchdog) check() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return
	}
	for _, op := range w.ops {
		if d := time.Since(op.start); d > w.limit {
			w.fired = true
			w.t.Errorf("DEADLOCK: operation %q has not returned after %v\n%s", op.name, d.Round(time.Second), allStacks())
			return
		}
	}
}

// do runs fn and registers it with the watchdog while it is in flight.
func (w *watchdog) do(name string, fn func() error) error {
	w.mu.Lock()
	w.next++
	k := w.next
	w.ops[k] = opInfo{name: name, start: time.Now()}
	w.mu.Unlock()

	err := fn()

	w.mu.Lock()
	delete(w.ops, k)
	w.mu.Unlock()
	return err
}

// wait waits for wg and reports a deadlock if it does not finish in time.
func (w *watchdog) wait(what string, wg *sync.WaitGroup) bool {
	w.t.Helper()
	if waitGroupTimeout(wg, w.limit) {
		return true
	}
	w.mu.Lock()
	fired := w.fired
	w.fired = true
	w.mu.Unlock()
	if !fired {
		w.t.Errorf("DEADLOCK: %s did not finish within %v\n%s", what, w.limit, allStacks())
	}
	return false
}

// ---------------------------------------------------------------------------
// goroutine leak detection (stdlib only)
// ---------------------------------------------------------------------------

const modulePath = "github.com/otfabric/go-opcua"

// moduleGoroutines returns the stacks of all goroutines that run or were
// created by code of this module, keyed by goroutine id.
func moduleGoroutines() map[string]string {
	out := make(map[string]string)
	for _, g := range strings.Split(allStacks(), "\n\n") {
		if !strings.Contains(g, modulePath) {
			continue
		}
		header, _, _ := strings.Cut(g, "\n")
		fields := strings.Fields(header) // "goroutine 12 [running]:"
		if len(fields) < 2 {
			continue
		}
		out[fields[1]] = g
	}
	return out
}

// leakCheck snapshots the goroutines of this module and returns a function
// that verifies that no additional ones are left. Goroutines are given
// settleLimit to exit before they are reported.
//
// It must only be used in tests that do not run in parallel with others.
func leakCheck(t *testing.T) (verify func()) {
	t.Helper()
	baseline := moduleGoroutines()
	return func() {
		t.Helper()
		var leaked []string
		ok := eventually(settleLimit, func() bool {
			leaked = leaked[:0]
			for gid, stack := range moduleGoroutines() {
				if _, known := baseline[gid]; !known {
					leaked = append(leaked, stack)
				}
			}
			return len(leaked) == 0
		})
		if !ok {
			t.Errorf("GOROUTINE LEAK: %d goroutine(s) still running %v after shutdown:\n\n%s",
				len(leaked), settleLimit, strings.Join(leaked, "\n\n"))
		}
	}
}

// ---------------------------------------------------------------------------
// connection state recorder
// ---------------------------------------------------------------------------

// stateRecorder records the ConnState transitions reported through
// WithConnStateHandler and validates them against the legal state machine.
type stateRecorder struct {
	name          string
	autoReconnect bool

	mu      sync.Mutex
	seq     []opcua.ConnState
	closing int // len(seq) when the user started closing the client, or -1
}

func newStateRecorder(name string, autoReconnect bool) *stateRecorder {
	return &stateRecorder{name: name, autoReconnect: autoReconnect, closing: -1}
}

func (r *stateRecorder) handle(s opcua.ConnState) {
	r.mu.Lock()
	r.seq = append(r.seq, s)
	r.mu.Unlock()
}

// markClosing records that the user is about to call Close. Transitions
// reported from then on race with the shutdown and are only required to end
// in Closed.
func (r *stateRecorder) markClosing() {
	r.mu.Lock()
	if r.closing < 0 {
		r.closing = len(r.seq)
	}
	r.mu.Unlock()
}

func (r *stateRecorder) last() (opcua.ConnState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seq) == 0 {
		return 0, false
	}
	return r.seq[len(r.seq)-1], true
}

func (r *stateRecorder) snapshot() []opcua.ConnState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]opcua.ConnState(nil), r.seq...)
}

// legalNext lists the transitions a client may report while it is in use.
//
//	Closed       -> Connecting
//	Connecting   -> Connected | Closed
//	Connected    -> Disconnected
//	Disconnected -> Reconnecting | Connected | Closed(*)
//	Reconnecting -> Reconnecting | Connected
//
// (*) only without AutoReconnect: with AutoReconnect a client must never give
// up on its own, so Closed is only legal once the user calls Close.
// Disconnected -> Connected happens when only the subscriptions had to be
// repaired and the channel and session survived.
func (r *stateRecorder) legalNext(from, to opcua.ConnState) bool {
	switch from {
	case opcua.Closed:
		return to == opcua.Connecting
	case opcua.Connecting:
		return to == opcua.Connected || to == opcua.Closed
	case opcua.Connected:
		return to == opcua.Disconnected
	case opcua.Disconnected:
		return to == opcua.Reconnecting || to == opcua.Connected || (to == opcua.Closed && !r.autoReconnect)
	case opcua.Reconnecting:
		return to == opcua.Reconnecting || to == opcua.Connected
	}
	return false
}

// check validates the recorded sequence. If closed is true the client has
// been closed by the user and the final state must be Closed.
func (r *stateRecorder) check(t *testing.T, closed bool) {
	t.Helper()
	r.mu.Lock()
	seq := append([]opcua.ConnState(nil), r.seq...)
	closing := r.closing
	r.mu.Unlock()

	strict := len(seq)
	if closing >= 0 {
		strict = closing
	}
	prev := opcua.Closed
	for i := 0; i < strict; i++ {
		if !r.legalNext(prev, seq[i]) {
			t.Errorf("client %s: illegal ConnState transition %v -> %v at step %d of %v", r.name, prev, seq[i], i, seq)
			break
		}
		prev = seq[i]
	}
	if closed {
		if len(seq) == 0 || seq[len(seq)-1] != opcua.Closed {
			t.Errorf("client %s: last reported ConnState after Close is not Closed: %v", r.name, seq)
		}
	}
}

// ---------------------------------------------------------------------------
// error classification
// ---------------------------------------------------------------------------

// isConnectionError reports whether err is an error a caller must expect
// while the transport, secure channel or session is disturbed: the request
// did not complete because the connection, channel, session or subscription
// it was using went away or did not answer in time.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	// context of the caller
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// transport
	var netErr net.Error
	var uacpErr *uacp.Error
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, net.ErrClosed), errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.ECONNABORTED), errors.Is(err, syscall.ETIMEDOUT),
		stderrors.As(err, &netErr), stderrors.As(err, &uacpErr):
		return true
	}
	// secure channel / client state
	switch {
	case errors.Is(err, errors.ErrSecureChannelClosed), errors.Is(err, errors.ErrNotConnected),
		errors.Is(err, errors.ErrSessionClosed), errors.Is(err, errors.ErrSessionNotActivated):
		return true
	}
	// status codes reported by the server or synthesised by the client
	for _, sc := range []ua.StatusCode{
		ua.StatusBadTimeout,
		ua.StatusBadServerNotConnected,
		ua.StatusBadNotConnected,
		ua.StatusBadConnectionClosed,
		ua.StatusBadCommunicationError,
		ua.StatusBadSecureChannelClosed,
		ua.StatusBadSecureChannelIDInvalid,
		ua.StatusBadSecureChannelTokenUnknown,
		ua.StatusBadSessionIDInvalid,
		ua.StatusBadSessionClosed,
		ua.StatusBadSessionNotActivated,
		ua.StatusBadSubscriptionIDInvalid,
		ua.StatusBadNoSubscription,
		ua.StatusBadServerHalted,
		ua.StatusBadShutdown,
	} {
		if errors.Is(err, sc) {
			return true
		}
	}
	return false
}

// errorTally counts errors by class for the scenario summary.
type errorTally struct {
	mu sync.Mutex
	m  map[string]int
	ok atomic.Int64
}

func (e *errorTally) add(err error) {
	if err == nil {
		e.ok.Add(1)
		return
	}
	key := err.Error()
	if len(key) > 80 {
		key = key[:80]
	}
	e.mu.Lock()
	if e.m == nil {
		e.m = make(map[string]int)
	}
	e.m[key]++
	e.mu.Unlock()
}

func (e *errorTally) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "ok=%d", e.ok.Load())
	for k, v := range e.m {
		fmt.Fprintf(&b, "\n    %6d x %s", v, k)
	}
	return b.String()
}
