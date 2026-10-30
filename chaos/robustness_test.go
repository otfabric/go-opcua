// SPDX-License-Identifier: MIT

package chaos

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// connectDirect connects a client straight to the server, bypassing the
// proxy and whatever fault it applies.
func (e *env) connectDirect(opts ...opcua.Option) *opcua.Client {
	e.t.Helper()
	all := append([]opcua.Option{
		opcua.InsecureNoSecurity(),
		opcua.AutoReconnect(false),
		opcua.RequestTimeout(30 * time.Second),
	}, opts...)
	c, err := opcua.NewClient("opc.tcp://"+e.directAddr(), append([]opcua.Option{opcua.InsecureNoSecurity()}, all...)...)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		e.t.Fatalf("connect direct: %v", err)
	}
	e.t.Cleanup(func() { closeClient(c, nil) })
	return c
}

// Bug: all requests were handled and answered by one goroutine that wrote
// the responses itself, without a deadline. A single client that stopped
// reading blocked that goroutine in a socket write and with it every other
// client of the server, for as long as it liked.
// Fix: server/channel_writer.go (one response writer per secure channel,
// bounded, with a write timeout that drops only the stalled channel).
func TestRegressionStalledClientDoesNotStallOthers(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1, server.WithResponseWriteTimeout(2*time.Second))

	slow := e.connect(nil, opcua.AutoReconnect(false), opcua.SessionTimeout(2*time.Second))
	fast := e.connectDirect()

	if r := e.resources(); r.Channels != 2 {
		t.Fatalf("precondition: %+v", r)
	}

	// The slow client stops reading and asks for far more data than the
	// socket buffers can hold.
	e.proxy.SetStall(testutil.ServerToClient, true)
	var wg sync.WaitGroup
	for i := 0; i < 96; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, _ = slow.ReadValue(ctx, e.blobID())
		}()
	}

	// The healthy client is served throughout. Before the fix the first of
	// these reads hung until the stall ended.
	deadline := time.Now().Add(4 * time.Second)
	for n := 0; time.Now().Before(deadline) || n < 20; n++ {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		want := int32(n)
		if sc, err := fast.WriteNodeValue(ctx, e.scratchID(0), want); err != nil || sc != ua.StatusOK {
			cancel()
			t.Fatalf("healthy client write %d while another client is stalled: status=%v err=%v", n, sc, err)
		}
		dv, err := fast.ReadValue(ctx, e.scratchID(0))
		cancel()
		if err != nil {
			t.Fatalf("healthy client read %d while another client is stalled: %v", n, err)
		}
		if dv.Value.Value() != want {
			t.Fatalf("healthy client read back %v, want %v", dv.Value.Value(), want)
		}
	}

	// Only the stalled channel is dropped ...
	if !eventually(settleLimit, func() bool { return e.resources().Channels == 1 }) {
		t.Fatalf("the stalled channel was not dropped: %+v", e.resources())
	}
	// ... and what it held is released (its session by the session timeout).
	if !eventually(settleLimit, func() bool { return e.resources().Sessions == 1 }) {
		t.Fatalf("the session of the stalled client was not released: %+v", e.resources())
	}

	e.proxy.SetStall(testutil.ServerToClient, false)
	wg.Wait()

	// the healthy client is still on its original channel
	ctx, cancel := opCtx()
	defer cancel()
	if _, err := fast.ReadValue(ctx, e.scratchID(0)); err != nil {
		t.Fatalf("healthy client after the stalled one was dropped: %v", err)
	}
	if fast.State() != opcua.Connected {
		t.Fatalf("healthy client state %v", fast.State())
	}
}

// A client that sends requests faster than it reads the responses is slowed
// down (the server stops reading from it), not dropped, and gets every
// answer. With a limit of 4 requests in flight, 200 concurrent requests have
// to queue up in the transport.
func TestRegressionPendingResponseLimitAppliesBackPressure(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1, server.WithMaxPendingResponses(4))
	c := e.connect(nil, opcua.AutoReconnect(false))

	const requests = 200
	var wg sync.WaitGroup
	var sink errSink
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := opCtx()
			defer cancel()
			n := int32(i)
			res, err := c.CallMethod(ctx, e.objectsID(), e.methodID(), n)
			if err != nil {
				sink.addf("call %d: %v", i, err)
				return
			}
			if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != n*n {
				sink.addf("call %d: unexpected result %v %v", i, res.StatusCode, res.OutputArguments)
			}
		}(i)
	}
	wg.Wait()
	sink.report(t)

	// a subscription still works with the tiny limit: parked Publish
	// requests do not use up the in-flight slots
	ctx, cancel := opCtx()
	defer cancel()
	st, err := openStream(ctx, e, c, "s", 4, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		want := e.bump(0)
		if !eventually(settleLimit, func() bool { return st.lastValue(0) >= want }) {
			t.Fatalf("value %d not delivered", want)
		}
		if _, err := c.ReadValue(ctx, e.scratchID(0)); err != nil {
			t.Fatalf("read with a subscription active: %v", err)
		}
	}
	_ = st.sub.Cancel(ctx)
	st.close()
	st.report(t)
}

// logCapture is a slog handler that collects records.
type logCapture struct {
	mu   sync.Mutex
	recs []string
}

func (l *logCapture) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelError
}
func (l *logCapture) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logCapture) WithGroup(string) slog.Handler      { return l }
func (l *logCapture) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	})
	l.mu.Lock()
	l.recs = append(l.recs, b.String())
	l.mu.Unlock()
	return nil
}

func (l *logCapture) contains(substrs ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.recs {
		ok := true
		for _, s := range substrs {
			if !strings.Contains(r, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// panicOnDecode is an extension object whose decoder panics, standing in for
// a bug in a decoder that hostile or unexpected input can reach.
type panicOnDecode struct {
	Payload uint32
}

func (p *panicOnDecode) Decode([]byte) (int, error) {
	panic("chaos: decoder bug")
}

var panicOnDecodeID = ua.NewNumericNodeID(0, 4_000_000_123)

var registerPanicOnDecode sync.Once

// Bug: nothing in the server recovered from a panic. A panic in a handler,
// in application code a handler calls (method handlers, value functions) or
// in a decoder ended the whole process, for every client.
// Fix: recover at the server's goroutine boundaries: server/service_handlers.go
// serve (request fails with BadInternalError), server/channel_broker.go
// receive (channel dropped), plus the subscription, writer and helper
// goroutines.
func TestRegressionPanicsAreContained(t *testing.T) {
	t.Parallel()
	logs := &logCapture{}
	e := newEnv(t, 1, server.SetLogger(slog.New(logs)))
	ns := e.namespace()

	// a variable whose value function panics
	bomb := server.NewNode(
		e.nodeID("Bomb"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName("Bomb")),
		},
		nil,
		func() *ua.DataValue { panic("chaos: value function bug") },
	)
	ns.AddNode(bomb)
	ns.Objects().AddRef(bomb, id.HasComponent, true)

	// a method handler that panics for one argument value
	e.server().RegisterMethod(e.objectsID(), e.methodID(),
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			n, _ := args[0].Value().(int32)
			if n == 13 {
				panic("chaos: method handler bug")
			}
			return []*ua.Variant{ua.MustVariant(n * n)}, ua.StatusOK
		})

	victim := e.connect(nil) // AutoReconnect
	other := e.connectDirect()
	ctx, cancel := opCtx()
	defer cancel()

	healthy := func(c *opcua.Client, who, when string) {
		t.Helper()
		res, err := c.CallMethod(ctx, e.objectsID(), e.methodID(), int32(6))
		if err != nil {
			t.Fatalf("%s: call %s: %v", who, when, err)
		}
		if res.StatusCode != ua.StatusOK || res.OutputArguments[0].Value() != int32(36) {
			t.Fatalf("%s: call %s returned %v %v", who, when, res.StatusCode, res.OutputArguments)
		}
		if _, err := c.ReadValue(ctx, e.scratchID(0)); err != nil {
			t.Fatalf("%s: read %s: %v", who, when, err)
		}
	}

	// 1. panic in a value function, reached through Read
	_, err := victim.ReadValue(ctx, e.nodeID("Bomb"))
	if !isStatus(err, ua.StatusBadInternalError) {
		t.Fatalf("read of a node whose value function panics: got %v, want BadInternalError", err)
	}
	healthy(victim, "victim", "after the value function panic")
	healthy(other, "other client", "after the value function panic")
	if !logs.contains("recovered from panic", "value function bug", "stack=goroutine") {
		t.Error("the value function panic was not logged at Error level with its stack")
	}

	// 2. panic in a method handler
	_, err = victim.CallMethod(ctx, e.objectsID(), e.methodID(), int32(13))
	if !isStatus(err, ua.StatusBadInternalError) {
		t.Fatalf("call of a method whose handler panics: got %v, want BadInternalError", err)
	}
	healthy(victim, "victim", "after the method handler panic")
	healthy(other, "other client", "after the method handler panic")
	if !logs.contains("recovered from panic", "method handler bug") {
		t.Error("the method handler panic was not logged")
	}

	// 3. panic while the initial value of a monitored item is sampled, in a
	// goroutine of the server
	ch := make(chan *opcua.PublishNotificationData, 16)
	sub, err := victim.Subscribe(ctx, streamParams(), ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(e.nodeID("Bomb"), ua.AttributeIDValue, 1)); err != nil {
		t.Fatalf("monitor a node whose value function panics: %v", err)
	}
	if !eventually(settleLimit, func() bool { return logs.contains("recovered from panic", "sampling the initial value") }) {
		t.Error("the panic in the sampling goroutine was not logged")
	}
	healthy(victim, "victim", "after the sampling panic")
	if err := sub.Cancel(ctx); err != nil {
		t.Errorf("cancel: %v", err)
	}

	// 4. panic in a decoder: the request cannot be attributed, so the channel
	// it arrived on is dropped. The client reconnects; nobody else notices.
	registerPanicOnDecode.Do(func() { ua.RegisterExtensionObject(panicOnDecodeID, new(panicOnDecode)) })
	channels := e.resources().Channels
	wctx, wcancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, err = victim.Write(wctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID:      e.scratchID(1),
		AttributeID: ua.AttributeIDValue,
		Value: &ua.DataValue{
			EncodingMask: ua.DataValueValue,
			Value: ua.MustVariant(&ua.ExtensionObject{
				EncodingMask: ua.ExtensionObjectBinary,
				TypeID:       ua.NewExpandedNodeID(panicOnDecodeID, "", 0),
				Value:        &panicOnDecode{Payload: 7},
			}),
		},
	}}})
	wcancel()
	if err == nil {
		t.Fatal("a request whose decoding panics was answered")
	}
	if !isConnectionError(err) {
		t.Errorf("request whose decoding panics: unexpected error class: %v", err)
	}
	if !logs.contains("recovered from panic", "decoder bug", "receiving on a secure channel") {
		t.Error("the decoder panic was not logged")
	}
	healthy(other, "other client", "after the decoder panic")
	if other.State() != opcua.Connected {
		t.Fatalf("other client state %v after the decoder panic", other.State())
	}
	if !eventually(settleLimit, func() bool { return victim.State() == opcua.Connected && e.resources().Channels == channels }) {
		t.Fatalf("victim did not reconnect after its channel was dropped: state %v, server %+v", victim.State(), e.resources())
	}
	if !eventually(settleLimit, func() bool {
		c2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel2()
		_, err := victim.ReadValue(c2, e.scratchID(0))
		return err == nil
	}) {
		t.Fatal("victim is not served after it reconnected")
	}
}

// recoveryLog collects the events of WithSubscriptionRecoveryHandler.
type recoveryLog struct {
	mu     sync.Mutex
	events []opcua.SubscriptionRecoveryEvent
}

func (r *recoveryLog) handle(ev opcua.SubscriptionRecoveryEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *recoveryLog) forSubscription(id uint32) []opcua.SubscriptionRecoveryEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []opcua.SubscriptionRecoveryEvent
	for _, ev := range r.events {
		if ev.SubscriptionID == id {
			out = append(out, ev)
		}
	}
	return out
}

func containsID(ids []uint32, id uint32) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// startBumper advances the given counters until the returned function is
// called.
func startBumper(e *env, counters ...int) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				for _, i := range counters {
					e.bump(i)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

// Bug: when the lifetime of a subscription expired on the server (no Publish
// request arrived in time) the server deleted it without a word, and the
// client kept a subscription that would never deliver again while the
// connection and its other subscriptions looked perfectly healthy.
// Fix: the server announces the expiry with a StatusChangeNotification
// (server/subscription_service.go announceExpiry), and the client recreates
// a subscription the server reports as ended (client_sub.go
// deliverPublishResponse, recoverBrokenSubscriptions).
func TestRegressionExpiredSubscriptionIsRecreated(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	rec := newStateRecorder("c", true)
	var recoveries recoveryLog
	c := e.connect(rec, opcua.WithSubscriptionRecoveryHandler(recoveries.handle))
	ctx, cancel := opCtx()
	defer cancel()

	stop := startBumper(e, 0, 1)
	defer stop()

	// The sibling has a lifetime of a minute; the short one expires after 2s
	// without a Publish request.
	sibling, err := openStream(ctx, e, c, "sibling", 4, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	short, err := openStreamWith(ctx, e, c, "short", 4, &opcua.SubscriptionParameters{
		Interval: 20 * time.Millisecond, MaxKeepAliveCount: 5, LifetimeCount: 100,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !eventually(settleLimit, func() bool { return short.lastValue(0) > 0 && sibling.lastValue(1) > 0 }) {
		t.Fatal("no data before the fault")
	}

	siblingID := sibling.sub.SubscriptionID
	var shortID uint32
	for _, id := range c.SubscriptionIDs() {
		if id != siblingID {
			shortID = id
		}
	}
	states := len(rec.snapshot())

	// Starve the server of Publish requests: nothing the client sends
	// arrives, while the connection stays up.
	e.proxy.SetStall(testutil.ClientToServer, true)
	if !eventually(settleLimit, func() bool { return e.resources().Subscriptions == 1 }) {
		t.Fatalf("the short-lived subscription did not expire on the server: %+v", e.resources())
	}
	e.proxy.SetStall(testutil.ClientToServer, false)

	// The client learns about it, recreates the subscription with its
	// monitored item and keeps delivering to the same consumer.
	if !eventually(settleLimit, func() bool {
		ids := c.SubscriptionIDs()
		return len(ids) == 2 && !containsID(ids, shortID) && len(recoveries.forSubscription(shortID)) > 0
	}) {
		t.Fatalf("the expired subscription was not recreated: client subscriptions %v (expired: %d), server %+v", c.SubscriptionIDs(), shortID, e.resources())
	}
	marker := e.counters[0].Load()
	if !eventually(settleLimit, func() bool { return short.lastValue(0) > marker }) {
		t.Fatalf("the recreated subscription does not deliver: last %d, node at %d; server %+v", short.lastValue(0), e.counters[0].Load(), e.resources())
	}
	for _, ev := range recoveries.forSubscription(shortID) {
		if ev.Outcome != opcua.SubscriptionRecoveryRecreated {
			t.Errorf("recovery event for the expired subscription: %+v, want outcome recreated", ev)
		}
	}

	// The sibling was not disturbed: same subscription, still delivering,
	// no recovery event, and the connection state never changed.
	if !containsID(c.SubscriptionIDs(), siblingID) {
		t.Errorf("the sibling subscription %d was replaced: %v", siblingID, c.SubscriptionIDs())
	}
	if evs := recoveries.forSubscription(siblingID); len(evs) != 0 {
		t.Errorf("the sibling subscription went through a recovery: %+v", evs)
	}
	marker = e.counters[1].Load()
	if !eventually(settleLimit, func() bool { return sibling.lastValue(1) > marker }) {
		t.Errorf("the sibling subscription stopped delivering")
	}
	if got := rec.snapshot(); len(got) != states {
		t.Errorf("the connection state changed although only a subscription expired: %v", got)
	}
	if r := e.resources(); r.Subscriptions != 2 || r.MonitoredItems != 2 {
		t.Errorf("server after the recovery: %+v, want 2 subscriptions with 2 monitored items", r)
	}

	for _, st := range []*stream{short, sibling} {
		if err := st.sub.Cancel(ctx); err != nil {
			t.Errorf("cancel %s: %v", st.name, err)
		}
		st.close()
		st.report(t)
	}
	closeClient(c, rec)
	e.requireServerDrained(settleLimit)
}

// The same when the server no longer has any subscription for the session
// and answers Publish with BadNoSubscription (here: the subscriptions were
// deleted on the server). The client used to ignore that status and stopped
// publishing for good.
func TestRegressionBadNoSubscriptionRecreatesSubscriptions(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	rec := newStateRecorder("c", true)
	var recoveries recoveryLog
	c := e.connect(rec, opcua.RequestTimeout(2*time.Second), opcua.WithSubscriptionRecoveryHandler(recoveries.handle))
	ctx, cancel := opCtx()
	defer cancel()

	stop := startBumper(e, 0, 1)
	defer stop()

	var streams []*stream
	for i := 0; i < 2; i++ {
		st, err := openStream(ctx, e, c, fmt.Sprintf("s%d", i), 4, false, i)
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, st)
	}
	if !eventually(settleLimit, func() bool { return streams[0].lastValue(0) > 0 && streams[1].lastValue(1) > 0 }) {
		t.Fatal("no data before the fault")
	}
	old := c.SubscriptionIDs()
	states := len(rec.snapshot())

	for _, id := range old {
		e.server().SubscriptionService.DeleteSubscription(id)
	}

	if !eventually(settleLimit, func() bool {
		ids := c.SubscriptionIDs()
		if len(ids) != 2 {
			return false
		}
		for _, id := range old {
			if containsID(ids, id) || len(recoveries.forSubscription(id)) == 0 {
				return false
			}
		}
		return true
	}) {
		t.Fatalf("the subscriptions were not recreated: client %v (deleted: %v), server %+v", c.SubscriptionIDs(), old, e.resources())
	}
	for i, st := range streams {
		marker := e.counters[i].Load()
		if !eventually(settleLimit, func() bool { return st.lastValue(i) > marker }) {
			t.Fatalf("stream %s does not deliver after its subscription was recreated", st.name)
		}
	}
	if got := rec.snapshot(); len(got) != states {
		t.Errorf("the connection state changed although only subscriptions were lost: %v", got)
	}

	for _, st := range streams {
		if err := st.sub.Cancel(ctx); err != nil {
			t.Errorf("cancel %s: %v", st.name, err)
		}
		st.close()
		st.report(t)
	}
	closeClient(c, rec)
	e.requireServerDrained(settleLimit)
}
