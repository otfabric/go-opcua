// SPDX-License-Identifier: MIT

package chaos

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
)

// This file holds one focused, deterministic test for every product bug the
// randomized scenarios uncovered. Each test fails against the code as it was
// before the fix named in its comment.

// Bug: the server derived a new subscription's id from len(Subs)+1. After a
// delete that is the id of a subscription which still exists; the new
// subscription replaced it in the server's table and the client rejected the
// duplicate id with BadSubscriptionIdInvalid.
// Fix: server/subscription_service.go nextSubscriptionID.
func TestRegressionSubscriptionIDsAreNotReused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	c := e.connect(nil)
	ctx, cancel := opCtx()
	defer cancel()

	var streams []*stream
	for i := 0; i < 3; i++ {
		st, err := openStream(ctx, e, c, fmt.Sprintf("s%d", i), 4, false, i)
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, st)
	}
	// delete the first one, then create another
	if err := streams[0].sub.Cancel(ctx); err != nil {
		t.Fatal(err)
	}
	streams[0].close()

	st, err := openStream(ctx, e, c, "s3", 4, false, 3)
	if err != nil {
		t.Fatalf("subscribe after delete: %v", err)
	}
	streams = append(streams[1:], st)

	seen := map[uint32]bool{}
	for _, st := range streams {
		if seen[st.sub.SubscriptionID] {
			t.Fatalf("subscription id %d handed out twice", st.sub.SubscriptionID)
		}
		seen[st.sub.SubscriptionID] = true
	}
	if got := e.resources().Subscriptions; got != 3 {
		t.Fatalf("server holds %d subscriptions, want 3", got)
	}
	// every subscription (old and new) still delivers its own counter
	for _, st := range streams {
		h := int(st.handles()[0])
		want := e.bump(h)
		if !eventually(settleLimit, func() bool { return st.lastValue(h) >= want }) {
			t.Errorf("subscription %d (%s) does not deliver after a sibling was replaced", st.sub.SubscriptionID, st.name)
		}
		_ = st.sub.Cancel(ctx)
		st.close()
	}
}

// Bug: Browse of a node with a reference to a deleted node produced a
// ReferenceDescription with a nil TypeDefinition. The response could not be
// encoded, nothing was sent, and the client blocked until its timeout.
// Fix: server/namespace_node.go Browse (null NodeId for missing targets) and
// server/service_handlers.go handleService (ServiceFault when a response
// cannot be sent).
func TestRegressionBrowseWithDanglingReference(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	c := e.connect(nil)

	ns := e.namespace()
	n := ns.AddNewVariableStringNode("Doomed", int32(1))
	ns.Node(e.folderID()).AddRef(n, id.HasComponent, true)
	if sc := ns.DeleteNode(n.ID()); sc != ua.StatusOK {
		t.Fatalf("delete node: %v", sc)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	refs, err := c.BrowseAll(ctx, e.folderID())
	if err != nil {
		t.Fatalf("browse of a folder with a dangling reference: %v", err)
	}
	if n := countLeaves(refs); n != numBrowse {
		t.Fatalf("browse returned %d leaves, want %d", n, numBrowse)
	}
}

// Bug: the Read service applied TimestampsToReturn to the DataValue stored in
// the node instead of a copy. Besides racing with concurrent readers, a
// single Read with TimestampsToReturn=Neither erased the node's source
// timestamp for every later reader and subscriber.
// Fix: server/attribute_service.go Read.
func TestRegressionReadDoesNotMutateStoredValue(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	c := e.connect(nil)
	ctx, cancel := opCtx()
	defer cancel()

	read := func(ts ua.TimestampsToReturn) *ua.DataValue {
		t.Helper()
		res, err := c.Read(ctx, &ua.ReadRequest{
			NodesToRead:        []*ua.ReadValueID{{NodeID: e.scratchID(0), AttributeID: ua.AttributeIDValue}},
			TimestampsToReturn: ts,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res.Results[0]
	}

	// A DataValue set by the application is stored in the node as is.
	stamp := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	if sc := e.namespace().SetAttribute(e.scratchID(0), ua.AttributeIDValue, &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(int32(5)),
		SourceTimestamp: stamp,
	}); sc != ua.StatusOK {
		t.Fatalf("set value: %v", sc)
	}

	before := read(ua.TimestampsToReturnBoth)
	if !before.SourceTimestamp.Equal(stamp) {
		t.Fatalf("precondition: source timestamp %v, want %v", before.SourceTimestamp, stamp)
	}
	if dv := read(ua.TimestampsToReturnNeither); !dv.SourceTimestamp.IsZero() || !dv.ServerTimestamp.IsZero() {
		t.Fatalf("TimestampsToReturn=Neither returned timestamps: %+v", dv)
	}
	after := read(ua.TimestampsToReturnBoth)
	if !after.SourceTimestamp.Equal(before.SourceTimestamp) {
		t.Fatalf("a Read with TimestampsToReturn=Neither changed the stored source timestamp: before %v, after %v",
			before.SourceTimestamp, after.SourceTimestamp)
	}
}

// Bug: the server completed the HEL/ACK handshake inside its accept loop
// without a deadline. One TCP connection that never sent a HEL kept every
// later client from connecting, forever.
// Fix: uacp/conn.go Listener (background accept + handshake with deadline).
func TestRegressionIdleConnectionDoesNotBlockAccept(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)

	// several silent connections, held open for the whole test
	for i := 0; i < 3; i++ {
		idle, err := net.DialTimeout("tcp", e.directAddr(), 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = idle.Close() }()
	}

	done := make(chan error, 1)
	go func() {
		c, err := e.dial(nil, opcua.AutoReconnect(false))
		if err == nil {
			closeClient(c, nil)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("connect while idle connections are pending: %v", err)
		}
	case <-time.After(settleLimit):
		t.Fatalf("a client could not connect within %v while silent TCP connections were open", settleLimit)
	}
}

// Bug: sessions had no timeout. A client that vanished without CloseSession
// left its session in the server forever. In addition an idle subscription
// only advanced its lifetime counter once per keep-alive interval, so the
// subscriptions of a vanished client lived keep-alive × lifetime publishing
// intervals instead of lifetime intervals.
// Fix: server/session_broker.go reapExpired + server/server.go reapSessions,
// server/subscription_service.go run (lifetime counter).
func TestRegressionVanishedClientIsReclaimed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	c := e.connect(nil, opcua.AutoReconnect(false), opcua.SessionTimeout(500*time.Millisecond))
	ctx, cancel := opCtx()
	defer cancel()

	// An idle subscription: nothing is ever written to the monitored node.
	// Its lifetime is 150 publishing cycles of 20ms = 3s. Before the fix an
	// idle subscription only counted one cycle per keep-alive interval and
	// would have lived 50 x 150 x 20ms = 150s; the session, forever.
	ch := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 20 * time.Millisecond, MaxKeepAliveCount: 50, LifetimeCount: 150,
	}, ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(e.scratchID(3), ua.AttributeIDValue, 1)); err != nil {
		t.Fatal(err)
	}
	if r := e.resources(); r.Sessions != 1 || r.Subscriptions != 1 || r.MonitoredItems != 1 {
		t.Fatalf("precondition: %+v", r)
	}

	// The client vanishes: its packets disappear and it never says goodbye.
	e.proxy.SetBlackhole(testutil.ClientToServer, true)
	e.proxy.SetBlackhole(testutil.ServerToClient, true)

	e.requireServerSessionsAndSubscriptionsGone(settleLimit)
}

func (e *env) requireServerSessionsAndSubscriptionsGone(limit time.Duration) {
	e.t.Helper()
	if !eventually(limit, func() bool {
		r := e.resources()
		return r.Sessions == 0 && r.Subscriptions == 0 && r.MonitoredItems == 0
	}) {
		e.t.Errorf("server did not reclaim the resources of a vanished client within %v: %+v", limit, e.resources())
	}
}

// Bug: Server.Close did not stop the subscription goroutines. They kept
// running (and ticking) until their lifetime expired, long after the server
// was gone.
// Fix: server/server.go Close.
func TestRegressionServerCloseStopsSubscriptions(t *testing.T) {
	verify := leakCheck(t)
	e := newEnv(t, 1)
	c := e.connect(nil, opcua.AutoReconnect(false))
	ctx, cancel := opCtx()
	defer cancel()
	st, err := openStreamWith(ctx, e, c, "s", 4, &opcua.SubscriptionParameters{
		Interval: 50 * time.Millisecond, MaxKeepAliveCount: 100, LifetimeCount: 100000,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	e.stopServer()

	closeClient(c, nil)
	st.close()
	e.proxy.Close()
	verify()
}

// Bug: a subscription created by a request without a valid session had a nil
// Session. The next ModifySubscription / SetPublishingMode /
// DeleteSubscriptions on it dereferenced the nil pointer inside the server's
// single request-handling goroutine and crashed the process.
// Fix: server/subscription_service.go CreateSubscription rejects the request
// with BadSessionIdInvalid; ownership checks go through Subscription.ownedBy.
func TestRegressionSubscribeWithoutSession(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	c := e.connect(nil, opcua.AutoReconnect(false))
	ctx, cancel := opCtx()
	defer cancel()

	if _, err := c.DetachSession(ctx); err != nil {
		t.Fatal(err)
	}
	ch := make(chan *opcua.PublishNotificationData, 1)
	_, err := c.Subscribe(ctx, streamParams(), ch)
	if !isStatus(err, ua.StatusBadSessionIDInvalid) {
		t.Fatalf("Subscribe without a session: got %v, want BadSessionIdInvalid", err)
	}
	if got := e.resources().Subscriptions; got != 0 {
		t.Fatalf("server created %d subscription(s) for a request without a session", got)
	}
	e.requireCleanClient()
}

func isStatus(err error, want ua.StatusCode) bool {
	for err != nil {
		if sc, ok := err.(ua.StatusCode); ok {
			return sc == want
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Bug: CreateMonitoredItems on a subscription the server does not know
// failed with BadUnexpectedError instead of BadSubscriptionIdInvalid, so a
// client could not tell that its subscription was gone.
// Fix: server/monitored_item_service.go CreateMonitoredItems.
func TestRegressionMonitorOnUnknownSubscription(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	c := e.connect(nil, opcua.AutoReconnect(false))
	ctx, cancel := opCtx()
	defer cancel()

	err := c.Send(ctx, &ua.CreateMonitoredItemsRequest{
		SubscriptionID:     987654,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			opcua.NewMonitoredItemCreateRequestWithDefaults(e.scratchID(0), ua.AttributeIDValue, 1),
		},
	}, func(ua.Response) error { return nil })
	if !isStatus(err, ua.StatusBadSubscriptionIDInvalid) {
		t.Fatalf("CreateMonitoredItems on an unknown subscription: got %v, want BadSubscriptionIdInvalid", err)
	}
}

// Bug: a notification for a subscription was handed to its channel with a
// blocking send that only the client's shutdown could interrupt. A consumer
// that stopped reading after Cancel (the natural thing to do) left the
// client's single publish loop blocked forever, silently starving every
// other subscription of the client.
// Fix: subscription.go notify (aborts once the subscription is cancelled).
func TestRegressionCancelledSubscriptionDoesNotBlockPublishLoop(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	c := e.connect(nil)
	ctx, cancel := opCtx()
	defer cancel()

	var stop sync.WaitGroup
	done := make(chan struct{})
	stop.Add(1)
	go func() {
		defer stop.Done()
		for {
			select {
			case <-done:
				return
			default:
				e.bump(0)
				e.bump(1)
				time.Sleep(time.Millisecond)
			}
		}
	}()
	defer func() { close(done); stop.Wait() }()

	steady, err := openStream(ctx, e, c, "steady", 0, false, 0)
	if err != nil {
		t.Fatal(err)
	}

	for round := 0; round < 20; round++ {
		// An unbuffered channel nobody reads: every notification for this
		// subscription blocks the publish loop until Cancel.
		ch := make(chan *opcua.PublishNotificationData)
		sub, err := c.Subscribe(ctx, streamParams(), ch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
			opcua.NewMonitoredItemCreateRequestWithDefaults(e.counterID(1), ua.AttributeIDValue, 1)); err != nil {
			t.Fatal(err)
		}
		<-ch // the subscription is live and the next notification is on its way
		time.Sleep(30 * time.Millisecond)
		if err := sub.Cancel(ctx); err != nil {
			t.Fatal(err)
		}
		// from here on nobody reads ch

		before := steady.received.Load()
		if !eventually(settleLimit, func() bool { return steady.received.Load() > before }) {
			t.Fatalf("round %d: the publish loop is stuck delivering to a cancelled subscription; its sibling receives nothing", round)
		}
	}
	_ = steady.sub.Cancel(ctx)
	steady.close()
	steady.report(t)
}

// A plain connection loss: the client reconnects, restores its session and
// its subscriptions deliver again without any gap in ordering.
func TestRegressionReconnectResumesSubscriptions(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	rec := newStateRecorder("c", true)
	c := e.connect(rec)
	ctx, cancel := opCtx()
	defer cancel()

	var stop sync.WaitGroup
	done := make(chan struct{})
	stop.Add(1)
	go func() {
		defer stop.Done()
		for {
			select {
			case <-done:
				return
			default:
				e.bump(0)
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()
	defer func() { close(done); stop.Wait() }()

	st, err := openStreamWith(ctx, e, c, "s", 0, streamParams(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !eventually(settleLimit, func() bool { return st.received.Load() > 3 }) {
		t.Fatal("no data before the fault")
	}

	for round := 0; round < 3; round++ {
		reconnects := countState(rec, opcua.Reconnecting)
		e.proxy.DropAll()
		if !eventually(settleLimit, func() bool {
			return countState(rec, opcua.Reconnecting) > reconnects && c.State() == opcua.Connected
		}) {
			t.Fatalf("round %d: client did not reconnect: state %v, transitions %v", round, c.State(), rec.snapshot())
		}
		marker := e.counters[0].Load()
		if !eventually(settleLimit, func() bool { return st.lastValue(0) > marker }) {
			t.Fatalf("round %d: subscription did not resume after reconnect: last delivered %d, node at %d; client subscriptions %v, server %+v",
				round, st.lastValue(0), e.counters[0].Load(), c.SubscriptionIDs(), e.resources())
		}
	}
	rec.check(t, false)
	_ = st.sub.Cancel(ctx)
	st.close()
	st.report(t)
}

func countState(rec *stateRecorder, s opcua.ConnState) int {
	n := 0
	for _, x := range rec.snapshot() {
		if x == s {
			n++
		}
	}
	return n
}

// Bug: the server treated every *net.OpError returned by Accept as "the
// listener was closed" and left its accept loop. A HEL/ACK handshake that
// fails with a connection reset is such an error, so a single peer that
// connected and reset the connection stopped the server from accepting
// connections for good.
// Fix: server/server.go acceptAndRegister.
func TestRegressionHandshakeResetDoesNotStopAccepting(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)

	for i := 0; i < 5; i++ {
		conn, err := net.DialTimeout("tcp", e.directAddr(), 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// half a HEL header, then an abortive close (RST)
		if _, err := conn.Write([]byte("HEL")); err != nil {
			t.Fatal(err)
		}
		_ = conn.(*net.TCPConn).SetLinger(0)
		_ = conn.Close()
	}

	e.requireCleanClient()
}

// Bug: the client copied the security policy URI (and the sender
// certificate) of every OpenSecureChannel response into its own
// configuration, which is shared by all later reconnects. One damaged
// response therefore changed the client's security settings for good; with a
// policy URI that names no known policy every further attempt to open a
// channel failed and the client stayed in Reconnecting forever.
// Fix: uasc/secure_channel.go readChunk (a client checks the response against
// its configuration instead of adopting it).
func TestRegressionDamagedOpenResponseDoesNotPoisonClient(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	rec := newStateRecorder("c", true)
	c := e.connect(rec)

	// Damage the policy URI of exactly one OpenSecureChannel response.
	var damaged atomic.Bool
	e.proxy.SetMangle(testutil.ServerToClient, func(b []byte) []byte {
		if bytes.HasPrefix(b, []byte("OPN")) && bytes.Contains(b, []byte("SecurityPolicy#None")) && damaged.CompareAndSwap(false, true) {
			return bytes.Replace(b, []byte("SecurityPolicy#None"), []byte("SecurityPolicy#Nome"), 1)
		}
		return b
	})
	e.proxy.DropAll()

	if !eventually(settleLimit, func() bool { return damaged.Load() }) {
		t.Fatal("the client did not try to reconnect")
	}
	if !eventually(settleLimit, func() bool { return c.State() == opcua.Connected }) {
		t.Fatalf("client did not recover from one damaged OpenSecureChannel response: state %v, transitions %v", c.State(), rec.snapshot())
	}
	ctx, cancel := opCtx()
	defer cancel()
	if _, err := c.ReadValue(ctx, e.scratchID(0)); err != nil {
		t.Fatalf("read after recovery: %v", err)
	}
	rec.check(t, false)
}

// Bug: the server did not tie its services to a session. A request without
// an authentication token, or with the token of a session that had been
// closed, was served like any other, so a client could read and write the
// address space without ever authenticating, and closing a session did not
// end the access it gave.
// Fix: server/service_handlers.go checkSession.
func TestRegressionServicesRequireSession(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	c := e.connect(nil, opcua.AutoReconnect(false))
	ctx, cancel := opCtx()
	defer cancel()

	if _, err := c.ReadValue(ctx, e.scratchID(0)); err != nil {
		t.Fatalf("read within the session: %v", err)
	}
	if err := c.CloseSession(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := c.ReadValue(ctx, e.scratchID(0))
	if !isStatus(err, ua.StatusBadSessionIDInvalid) {
		t.Errorf("read after CloseSession: got %v, want BadSessionIdInvalid", err)
	}
	_, err = c.WriteNodeValue(ctx, e.scratchID(0), int32(99))
	if !isStatus(err, ua.StatusBadSessionIDInvalid) {
		t.Errorf("write after CloseSession: got %v, want BadSessionIdInvalid", err)
	}
	// discovery does not need a session
	if _, err := opcua.GetEndpoints(ctx, e.url()); err != nil {
		t.Errorf("GetEndpoints without a session: %v", err)
	}
}

// Bug: a frame of 8 to 11 bytes is a valid transport frame but shorter than
// the 12 byte secure conversation header; reading that header sliced beyond
// the frame and panicked. Any peer could crash a server (or a client) with a
// single such frame.
// Fix: uasc/secure_channel.go readChunk.
//
// The test plays every hostile byte stream of the catalogue against the
// server several times. The server has to survive all of them and must not
// keep any of the connections.
func TestRegressionRawFramesDoNotCrashOrLeak(t *testing.T) {
	t.Parallel()
	seed := seedFor(t)
	e := newEnv(t, seed)
	rng := rand.New(rand.NewSource(seed))
	addr := e.directAddr()

	for round := 0; round < 3; round++ {
		for _, a := range rawAttacks {
			if _, err := sendRawAttack(addr, "opc.tcp://"+addr, a, rng, 100*time.Millisecond); err != nil {
				t.Fatalf("attack %q: %v", a.name, err)
			}
		}
	}

	e.requireCleanClient()
	e.requireServerDrained(settleLimit)
}
