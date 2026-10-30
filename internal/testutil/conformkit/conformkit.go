// SPDX-License-Identifier: MIT

// Package conformkit holds the helpers of the conformance test packages
// (conformance and its subpackages): servers on OS-assigned ports, connected
// clients, polling and notification helpers. The conformance tests are split
// into several packages because CI gives every package 120 s under the race
// detector; the packages share these helpers instead of copying them.
package conformkit

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// WaitTimeout is the generous upper bound used when polling for an
// asynchronous effect (a notification, a state change). Tests return as soon as
// the condition holds; the bound only matters on a heavily loaded machine.
const WaitTimeout = 20 * time.Second

// FastInterval is the publishing interval used by subscription tests.
const FastInterval = 20 * time.Millisecond

// Eventually polls cond until it returns true or WaitTimeout elapses.
func Eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(WaitTimeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s: %s", WaitTimeout, msg)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// parallelTests remembers which tests were already marked parallel, since
// t.Parallel may be called only once per test.
var parallelTests sync.Map

// Parallel marks t as a parallel test (once). Every test that brings up its
// own server on an OS-assigned port calls it: each server start is costly
// under the race detector, so running such tests concurrently is what keeps
// the suite's wall time down. Tests that need a fixed port stay serial.
func Parallel(t *testing.T) {
	t.Helper()
	if _, done := parallelTests.LoadOrStore(t, true); !done {
		t.Parallel()
	}
}

// NewServer starts a server on an OS-assigned loopback port, with a None
// endpoint and anonymous access plus the given options, and returns it with
// its endpoint URL. Letting the OS pick the port (instead of probing for a
// free one first) rules out two concurrently starting servers ending up with
// the same port. The server is closed on test cleanup.
func NewServer(t *testing.T, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	return NewServerPrepared(t, nil, opts...)
}

// NewServerPrepared is NewServer with prepare, if not nil, run before the
// server starts. A server that a client reaches as soon as it starts (reverse
// connect, a client that reconnects to a restarted server) needs its nodes
// in place by then: the diagnostics namespace is created with the first
// session and would take the namespace index of nodes added later.
func NewServerPrepared(t *testing.T, prepare func(*server.Server), opts ...server.Option) (*server.Server, string) {
	t.Helper()
	Parallel(t)
	all := append([]server.Option{
		server.EndPoint("localhost", 0),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}, opts...)
	srv, err := server.New(append([]server.Option{server.InsecureNoSecurity()}, all...)...)
	require.NoError(t, err)
	if prepare != nil {
		prepare(srv)
	}
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	require.NotZero(t, srv.Port())
	return srv, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
}

// SetupWith stands up a server with the rich fixture and a connected client.
// prepare, if not nil, may add to the server (e.g. attach a historian or more
// nodes) before the client connects.
func SetupWith(t *testing.T, prepare func(srv *server.Server, f *testutil.Fixture), opts ...server.Option) (*opcua.Client, *testutil.Fixture, *server.Server, string) {
	t.Helper()
	srv, url := NewServer(t, opts...)
	f := testutil.AddFixture(t, srv)
	if prepare != nil {
		prepare(srv, f)
	}
	c := testutil.NewTestClient(t, url)
	return c, f, srv, url
}

// NewClient builds and connects an additional client against url. The client
// is closed on test cleanup.
func NewClient(t *testing.T, url string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	c, err := DialClient(t, url, opts...)
	require.NoError(t, err)
	return c
}

// DialClient builds a client with generous timeouts and connects it, returning
// the connect error so negative tests can assert on it.
func DialClient(t *testing.T, url string, opts ...opcua.Option) (*opcua.Client, error) {
	t.Helper()
	all := append([]opcua.Option{
		opcua.InsecureNoSecurity(),
		opcua.DialTimeout(30 * time.Second),
		opcua.RequestTimeout(30 * time.Second),
		// The client treats certain service faults (BadSessionIdInvalid,
		// BadSubscriptionIdInvalid, BadNoSubscription) as a sign that its
		// session or subscriptions are gone and, with automatic reconnect
		// enabled, replaces the session in the background. Many tests provoke
		// exactly these faults on purpose and then keep using the session,
		// so recovery is off unless a test asks for it.
		opcua.AutoReconnect(false),
	}, opts...)
	c, err := opcua.NewClient(url, append([]opcua.Option{opcua.InsecureNoSecurity()}, all...)...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		_ = c.Close(context.Background())
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, nil
}

// --- notification helpers ---------------------------------------------------

// sample is one flattened data-change sample.
type sample struct {
	handle uint32
	dv     *ua.DataValue
}

// sampleBuffer remembers data-change samples that were read from a notify
// channel but not yet claimed by an assertion, so awaiting one handle never
// discards samples of another that arrived in the same or an earlier publish.
type sampleBuffer struct {
	mu      sync.Mutex
	pending []sample
}

var sampleBuffers sync.Map // (<-chan *opcua.PublishNotificationData) -> *sampleBuffer

func bufferFor(ch <-chan *opcua.PublishNotificationData) *sampleBuffer {
	b, _ := sampleBuffers.LoadOrStore(ch, &sampleBuffer{})
	return b.(*sampleBuffer)
}

func (b *sampleBuffer) add(dcn *ua.DataChangeNotification) {
	for _, it := range dcn.MonitoredItems {
		b.pending = append(b.pending, sample{handle: it.ClientHandle, dv: it.Value})
	}
}

// take removes and returns the first pending sample for handle matching want.
// Older samples of the same handle are discarded with it.
func (b *sampleBuffer) take(handle uint32, want any) *ua.DataValue {
	for i, s := range b.pending {
		if s.handle != handle || s.dv == nil || s.dv.Value == nil || s.dv.Value.Value() != want {
			continue
		}
		kept := b.pending[:0:0]
		for j, o := range b.pending {
			if j == i || (j < i && o.handle == handle) {
				continue
			}
			kept = append(kept, o)
		}
		b.pending = kept
		return s.dv
	}
	return nil
}

// AwaitValue waits until a sample for handle with the given value has been
// received on ch and returns it. Samples for other handles are kept for later
// calls.
func AwaitValue(t *testing.T, ch <-chan *opcua.PublishNotificationData, handle uint32, want any) *ua.DataValue {
	t.Helper()
	b := bufferFor(ch)
	b.mu.Lock()
	defer b.mu.Unlock()
	deadline := time.After(WaitTimeout)
	for {
		if dv := b.take(handle, want); dv != nil {
			return dv
		}
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				b.add(dcn)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for handle %d to report %v", handle, want)
			return nil
		}
	}
}

// ExpectNoDataChange asserts that no data-change sample for handle is pending
// or arrives within the quiet window d.
func ExpectNoDataChange(t *testing.T, ch <-chan *opcua.PublishNotificationData, handle uint32, d time.Duration) {
	t.Helper()
	b := bufferFor(ch)
	b.mu.Lock()
	defer b.mu.Unlock()
	check := func() {
		for _, s := range b.pending {
			if s.handle == handle {
				t.Fatalf("unexpected data change for handle %d: %v", handle, s.dv.Value.Value())
			}
		}
	}
	check()
	timer := time.After(d)
	for {
		select {
		case msg := <-ch:
			if msg.Error != nil {
				continue
			}
			if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
				b.add(dcn)
			}
			check()
		case <-timer:
			return
		}
	}
}

// NextEvents blocks until the next publish carrying events and returns them.
func NextEvents(t *testing.T, ch <-chan *opcua.PublishNotificationData) []*ua.EventFieldList {
	t.Helper()
	deadline := time.After(WaitTimeout)
	for {
		select {
		case msg := <-ch:
			require.NoError(t, msg.Error)
			enl, ok := msg.Value.(*ua.EventNotificationList)
			if !ok || len(enl.Events) == 0 {
				continue
			}
			return enl.Events
		case <-deadline:
			t.Fatal("timed out waiting for an event notification")
			return nil
		}
	}
}

// WriteInt32 writes an int32 to a node and requires StatusOK.
func WriteInt32(t *testing.T, c *opcua.Client, id *ua.NodeID, v int32) {
	t.Helper()
	st, err := c.WriteNodeValue(context.Background(), id, v)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
}

// EndpointFor returns the endpoint advertised by the server for the given
// policy URI and mode.
func EndpointFor(t *testing.T, url, policyURI string, mode ua.MessageSecurityMode) *ua.EndpointDescription {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url, opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(30*time.Second))
	require.NoError(t, err)
	for _, ep := range eps {
		if ep.SecurityPolicyURI == policyURI && ep.SecurityMode == mode {
			return ep
		}
	}
	t.Fatalf("server does not advertise %s / %s", policyURI, mode)
	return nil
}

// PendingValues returns the values of the samples for handle that were
// received on ch (through AwaitValue) but not claimed yet.
func PendingValues(ch <-chan *opcua.PublishNotificationData, handle uint32) []any {
	b := bufferFor(ch)
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []any
	for _, s := range b.pending {
		if s.handle == handle {
			out = append(out, s.dv.Value.Value())
		}
	}
	return out
}

// RegistrationLog collects the events of a server's registration loop: pass
// its Handle to server.RegisterEventHandler.
type RegistrationLog struct {
	mu     sync.Mutex
	events []server.RegistrationEvent
}

// Handle records e.
func (l *RegistrationLog) Handle(e server.RegistrationEvent) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

// Snapshot returns the events recorded so far.
func (l *RegistrationLog) Snapshot() []server.RegistrationEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// Count returns the number of events that match.
func (l *RegistrationLog) Count(match func(server.RegistrationEvent) bool) int {
	n := 0
	for _, e := range l.Snapshot() {
		if match(e) {
			n++
		}
	}
	return n
}

// Registered matches a successful registration.
func Registered(e server.RegistrationEvent) bool { return e.Online && e.Err == nil }

// Unregistered matches a successful unregistration.
func Unregistered(e server.RegistrationEvent) bool { return !e.Online && e.Err == nil }

// Failed matches a failed registration or unregistration.
func Failed(e server.RegistrationEvent) bool { return e.Err != nil }
