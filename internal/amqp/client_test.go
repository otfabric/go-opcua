// SPDX-License-Identifier: MIT

package amqp_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/amqp"
	"github.com/otfabric/go-opcua/internal/testutil/amqpbroker"
)

var bg = context.Background()

func startBroker(t *testing.T, opts amqpbroker.Options) *amqpbroker.Broker {
	t.Helper()
	b := amqpbroker.New(opts)
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	return b
}

func dial(t *testing.T, opts amqp.Options) *amqp.Client {
	t.Helper()
	if opts.MinReconnectDelay == 0 {
		opts.MinReconnectDelay = 5 * time.Millisecond
		opts.MaxReconnectDelay = 50 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	c, err := amqp.Dial(ctx, opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type inbox chan *amqp.Message

func (in inbox) handle(m *amqp.Message) { in <- m }

func (in inbox) next(t *testing.T) *amqp.Message {
	t.Helper()
	select {
	case m := <-in:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message")
		return nil
	}
}

func (in inbox) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-in:
		t.Fatalf("unexpected message %q", m.Payload())
	case <-time.After(d):
	}
}

func dataMsg(s string) *amqp.Message {
	return &amqp.Message{Properties: &amqp.Properties{Subject: "ua-data", ContentType: "application/opcua+uadp"}, Data: [][]byte{[]byte(s)}}
}

func subscribe(t *testing.T, c *amqp.Client, address string, settled bool) (inbox, *amqp.Subscription) {
	t.Helper()
	in := make(inbox, 1000)
	sub, err := c.Subscribe(bg, address, settled, in.handle)
	require.NoError(t, err)
	return in, sub
}

func TestSendSubscribeTopic(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	pub := dial(t, amqp.Options{Server: b.URL()})
	sub := dial(t, amqp.Options{Server: "AMQP://" + b.Addr(), ContainerID: "sub"})
	require.True(t, pub.IsConnected())
	require.Equal(t, "sub", sub.ContainerID())
	require.NotEmpty(t, pub.ContainerID())

	in1, s1 := subscribe(t, sub, "opcua/data", false)
	in2, _ := subscribe(t, sub, "opcua/data", true)
	require.Equal(t, "opcua/data", s1.Address())

	for _, settled := range []bool{true, false} {
		require.NoError(t, pub.Send(bg, "opcua/data", dataMsg("m"), settled))
		for _, in := range []inbox{in1, in2} {
			m := in.next(t)
			require.Equal(t, []byte("m"), m.Payload())
			require.Equal(t, "ua-data", m.Properties.Subject)
			require.Equal(t, amqp.Symbol("application/opcua+uadp"), m.Properties.ContentType)
		}
	}
	// Nothing for an address without subscribers is kept.
	require.NoError(t, pub.Send(bg, "opcua/other", dataMsg("x"), false))
	in1.none(t, 20*time.Millisecond)

	require.NoError(t, s1.Unsubscribe(bg))
	require.NoError(t, s1.Unsubscribe(bg)) // idempotent
	require.NoError(t, pub.Send(bg, "opcua/data", dataMsg("after"), false))
	require.Equal(t, []byte("after"), in2.next(t).Payload())
	in1.none(t, 20*time.Millisecond)
}

func TestQueueCompetingConsumers(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	pub := dial(t, amqp.Options{Server: b.URL()})
	// Messages wait in a queue until a consumer comes.
	for i := range 10 {
		require.NoError(t, pub.Send(bg, "/queues/q", dataMsg(string(rune('a'+i))), false))
	}
	require.Equal(t, 10, b.Queued("/queues/q"))
	sub := dial(t, amqp.Options{Server: b.URL(), Credit: 2})
	in, _ := subscribe(t, sub, "/queues/q", false)
	for i := range 10 {
		require.Equal(t, []byte{byte('a' + i)}, in.next(t).Payload())
	}
	require.Eventually(t, func() bool { return b.Queued("/queues/q") == 0 }, 5*time.Second, time.Millisecond)
}

func TestLargeMessagesSpanFrames(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{MaxFrameSize: 512})
	pub := dial(t, amqp.Options{Server: b.URL(), MaxFrameSize: 512})
	sub := dial(t, amqp.Options{Server: b.URL(), MaxFrameSize: 600})
	in, _ := subscribe(t, sub, "big", false)
	big := bytes.Repeat([]byte("0123456789"), 10000)
	for _, settled := range []bool{false, true} {
		require.NoError(t, pub.Send(bg, "big", &amqp.Message{Data: [][]byte{big}}, settled))
		require.Equal(t, big, in.next(t).Payload())
	}
}

func TestSessionWindowReopens(t *testing.T) {
	// More transfer frames than half the session window of either side.
	b := startBroker(t, amqpbroker.Options{MaxFrameSize: 512})
	pub := dial(t, amqp.Options{Server: b.URL(), MaxFrameSize: 512})
	sub := dial(t, amqp.Options{Server: b.URL(), MaxFrameSize: 512, MaxMessageSize: 64 << 20})
	in, _ := subscribe(t, sub, "w", true)
	big := bytes.Repeat([]byte{7}, 450*40000) // ~40000 frames
	require.NoError(t, pub.Send(bg, "w", &amqp.Message{Data: [][]byte{big}}, false))
	select {
	case m := <-in:
		require.Equal(t, big, m.Payload())
	case <-time.After(30 * time.Second):
		t.Fatal("no message")
	}
}

func TestSASL(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{Users: map[string]string{"u": "p"}})
	c := dial(t, amqp.Options{Server: b.URL(), Username: "u", Password: "p", Hostname: "vhost:/"})
	require.True(t, c.IsConnected())

	// Bad credentials cannot be fixed by retrying.
	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	_, err := amqp.Dial(ctx, amqp.Options{Server: b.URL(), Username: "u", Password: "x"})
	var ce *amqp.ConnectError
	require.ErrorAs(t, err, &ce)
	require.True(t, ce.SASL)
	require.Equal(t, amqp.SASLAuth, ce.SASLCode)
	require.Contains(t, err.Error(), "authentication failed")
	// Mechanisms the broker does not offer (no ANONYMOUS with users).
	for _, m := range []string{"", "external"} {
		_, err = amqp.Dial(ctx, amqp.Options{Server: b.URL(), SASLMechanism: m})
		require.ErrorContains(t, err, "not offered")
	}
	// A mechanism the broker offers but refuses.
	b2 := startBroker(t, amqpbroker.Options{Users: map[string]string{"u": "p"}, Mechanisms: []string{"ANONYMOUS", "PLAIN"}})
	_, err = amqp.Dial(ctx, amqp.Options{Server: b2.URL()})
	require.ErrorAs(t, err, &ce)
	require.True(t, ce.SASL)
	// The broker requires SASL.
	_, err = amqp.Dial(ctx, amqp.Options{Server: b.URL(), SASLMechanism: amqp.SASLNone})
	require.ErrorContains(t, err, "protocol header")
}

func TestNoSASL(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	c := dial(t, amqp.Options{Server: b.URL(), SASLMechanism: amqp.SASLNone})
	in, _ := subscribe(t, c, "x", false)
	require.NoError(t, c.Send(bg, "x", dataMsg("hi"), false))
	require.Equal(t, []byte("hi"), in.next(t).Payload())
}

func TestTLSAndExternal(t *testing.T) {
	srv, cli, err := amqpbroker.TestTLS(true)
	require.NoError(t, err)
	b := startBroker(t, amqpbroker.Options{TLSConfig: srv, Users: map[string]string{"u": "p"}})
	require.Contains(t, b.URL(), "amqps://")
	var mech atomic.Value
	_ = mech
	// A client certificate selects EXTERNAL.
	c := dial(t, amqp.Options{Server: b.URL(), TLSConfig: cli})
	in, _ := subscribe(t, c, "t", false)
	require.NoError(t, c.Send(bg, "t", dataMsg("tls"), false))
	require.Equal(t, []byte("tls"), in.next(t).Payload())

	// Without a certificate EXTERNAL fails.
	_, plain, err := amqpbroker.TestTLS(false)
	require.NoError(t, err)
	plain.RootCAs = cli.RootCAs
	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	_, err = amqp.Dial(ctx, amqp.Options{Server: b.URL(), TLSConfig: plain, SASLMechanism: amqp.SASLExternal})
	require.ErrorContains(t, err, "SASL")
	// PLAIN over TLS.
	dial(t, amqp.Options{Server: b.URL(), TLSConfig: plain, Username: "u", Password: "p"})
	// An untrusted server certificate.
	_, err = amqp.Dial(ctx, amqp.Options{Server: b.URL(), ConnectTimeout: time.Second, MaxReconnectDelay: 10 * time.Millisecond})
	require.Error(t, err)
}

func TestOptionsErrors(t *testing.T) {
	for _, s := range []string{"http://h", "amqp://", ":"} {
		_, err := amqp.Dial(bg, amqp.Options{Server: s})
		require.Error(t, err, s)
	}
	_, err := amqp.Dial(bg, amqp.Options{Server: "amqp://h", SASLMechanism: "SCRAM-SHA-1"})
	require.ErrorContains(t, err, "SASL")
	// Nothing listens: Dial gives up when ctx ends.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	_, err = amqp.Dial(ctx, amqp.Options{Server: "amqp://" + addr, MinReconnectDelay: time.Millisecond})
	require.Error(t, err)
}

func TestOpenRefused(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	b := startBroker(t, amqpbroker.Options{RefuseOpen: func(o *amqp.Open) *amqp.Error {
		if refuse.Load() {
			return &amqp.Error{Condition: amqp.CondUnauthorizedAccess, Description: "vhost " + o.Hostname}
		}
		return nil
	}})
	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	_, err := amqp.Dial(ctx, amqp.Options{Server: b.URL(), Hostname: "vhost:x"})
	var ce *amqp.ConnectError
	require.ErrorAs(t, err, &ce)
	require.Equal(t, amqp.CondUnauthorizedAccess, ce.Err.Condition)
	require.Contains(t, err.Error(), "vhost vhost:x")
}

func TestOpenRefusedTransient(t *testing.T) {
	var n atomic.Int32
	b := startBroker(t, amqpbroker.Options{RefuseOpen: func(*amqp.Open) *amqp.Error {
		if n.Add(1) < 3 {
			return &amqp.Error{Condition: amqp.CondResourceLimit}
		}
		return nil
	}})
	c := dial(t, amqp.Options{Server: b.URL()})
	require.True(t, c.IsConnected())
	require.GreaterOrEqual(t, n.Load(), int32(3))
}

func TestOpenAndAttachProperties(t *testing.T) {
	var mu sync.Mutex
	var opens []*amqp.Open
	var attaches []*amqp.Attach
	b := startBroker(t, amqpbroker.Options{
		OnOpen:   func(o *amqp.Open) { mu.Lock(); opens = append(opens, o); mu.Unlock() },
		OnAttach: func(a *amqp.Attach) { mu.Lock(); attaches = append(attaches, a); mu.Unlock() },
	})
	c := dial(t, amqp.Options{
		Server: b.URL(), ContainerID: "cid", IdleTimeout: 10 * time.Second,
		ConnectionProperties: amqp.Map{{Key: amqp.Symbol("product"), Value: "go-opcua"}},
		SessionProperties:    amqp.Map{{Key: amqp.Symbol("s"), Value: "1"}},
		LinkProperties:       amqp.Map{{Key: amqp.Symbol("l"), Value: "2"}},
		SourceCapabilities:   []amqp.Symbol{"topic"},
		TargetCapabilities:   []amqp.Symbol{"queue"},
	})
	_, _ = subscribe(t, c, "src", true)
	require.NoError(t, c.Send(bg, "dst", dataMsg("x"), false))
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, opens, 1)
	require.Equal(t, "cid", opens[0].ContainerID)
	require.Equal(t, "127.0.0.1", opens[0].Hostname)
	require.Equal(t, uint32(5000), opens[0].IdleTimeout)
	v, ok := opens[0].Properties.Get(amqp.Symbol("product"))
	require.True(t, ok)
	require.Equal(t, "go-opcua", v)
	require.Len(t, attaches, 2)
	rcv, snd := attaches[0], attaches[1]
	require.Equal(t, amqp.RoleReceiver, rcv.Role)
	require.Equal(t, "src", rcv.Source.Address)
	require.Equal(t, []amqp.Symbol{"topic"}, rcv.Source.Capabilities)
	require.Equal(t, amqp.SenderSettleSettled, rcv.SndSettleMode)
	require.Equal(t, uint64(amqp.DefaultMaxMessageSize), rcv.MaxMessageSize)
	require.Equal(t, amqp.RoleSender, snd.Role)
	require.Equal(t, "dst", snd.Target.Address)
	require.Equal(t, []amqp.Symbol{"queue"}, snd.Target.Capabilities)
	require.Equal(t, amqp.SenderSettleUnsettled, snd.SndSettleMode)
	v, _ = snd.Properties.Get(amqp.Symbol("l"))
	require.Equal(t, "2", v)
}

func TestLinkRefused(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{RefuseAddress: func(a string) bool { return a == "nope" }})
	c := dial(t, amqp.Options{Server: b.URL()})
	for _, settled := range []bool{true, false} {
		err := c.Send(bg, "nope", dataMsg("x"), settled)
		var le *amqp.LinkError
		require.ErrorAs(t, err, &le)
		require.Equal(t, "nope", le.Address)
		require.Equal(t, amqp.CondNotFound, le.Err.Condition)
		require.Contains(t, err.Error(), "not-found")
	}
	_, err := c.Subscribe(bg, "nope", false, func(*amqp.Message) {})
	var le *amqp.LinkError
	require.ErrorAs(t, err, &le)
	// The client still works.
	in, _ := subscribe(t, c, "yes", false)
	require.NoError(t, c.Send(bg, "yes", dataMsg("ok"), false))
	require.Equal(t, []byte("ok"), in.next(t).Payload())
}

func TestOutcomes(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{Outcome: func(_ string, m *amqp.Message) amqp.DeliveryState {
		switch string(m.Payload()) {
		case "reject":
			return &amqp.Rejected{Error: &amqp.Error{Condition: amqp.CondInvalidField, Description: "bad"}}
		case "reject0":
			return &amqp.Rejected{}
		case "release":
			return &amqp.Released{}
		case "modify":
			return &amqp.Modified{DeliveryFailed: true}
		}
		return nil
	}})
	c := dial(t, amqp.Options{Server: b.URL()})
	for _, tc := range []struct{ body, msg string }{
		{"reject", "rejected: amqp:invalid-field: bad"}, {"reject0", "rejected"},
		{"release", "released"}, {"modify", "modified"},
	} {
		err := c.Send(bg, "o", dataMsg(tc.body), false)
		var de *amqp.DeliveryError
		require.ErrorAs(t, err, &de, tc.body)
		require.Contains(t, err.Error(), tc.msg)
	}
	require.NoError(t, c.Send(bg, "o", dataMsg("fine"), false))
	// Pre-settled messages have no outcome.
	require.NoError(t, c.Send(bg, "o", dataMsg("reject"), true))
}

func TestMessageTooLarge(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{MaxMessageSize: 100})
	c := dial(t, amqp.Options{Server: b.URL()})
	err := c.Send(bg, "x", &amqp.Message{Data: [][]byte{make([]byte, 200)}}, false)
	require.ErrorIs(t, err, amqp.ErrMessageTooLarge)
	require.NoError(t, c.Send(bg, "x", dataMsg("small"), false))
}

func TestReceiveLimitAndMalformed(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	pub := dial(t, amqp.Options{Server: b.URL(), MaxFrameSize: 512})
	sub := dial(t, amqp.Options{Server: b.URL(), MaxMessageSize: 1000, MaxFrameSize: 512})
	in, _ := subscribe(t, sub, "/queues/lim", false)
	// Too large (in one frame and in several): rejected and dropped.
	require.NoError(t, pub.Send(bg, "/queues/lim", &amqp.Message{Data: [][]byte{make([]byte, 400*4)}}, true))
	require.NoError(t, pub.Send(bg, "/queues/lim", dataMsg("ok"), true))
	require.Equal(t, []byte("ok"), in.next(t).Payload())
	in.none(t, 20*time.Millisecond)
}

func TestReconnectResendsUnsettled(t *testing.T) {
	var onces atomic.Int32
	b := startBroker(t, amqpbroker.Options{OnMessage: func(_ string, m *amqp.Message, _ bool) {
		if string(m.Payload()) == "once" {
			onces.Add(1)
		}
	}})
	var lost, connects atomic.Int32
	pub := dial(t, amqp.Options{Server: b.URL(),
		OnConnect:        func() { connects.Add(1) },
		OnConnectionLost: func(error) { lost.Add(1) }})
	sub := dial(t, amqp.Options{Server: b.URL()})
	in, _ := subscribe(t, sub, "/queues/r", false)

	// The broker routes the message but never settles it; the connection
	// breaks; the client sends it again on the next connection.
	b.SetWithholdDispositions(true)
	done := make(chan error, 1)
	go func() { done <- pub.Send(bg, "/queues/r", dataMsg("once"), false) }()
	require.Equal(t, []byte("once"), in.next(t).Payload())
	b.SetWithholdDispositions(false)
	b.DropConnections()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Send did not complete")
	}
	require.Equal(t, int32(2), onces.Load(), "at least once: sent again")
	require.Positive(t, lost.Load())
	require.GreaterOrEqual(t, connects.Load(), int32(2))

	// While disconnected a pre-settled Send fails at once.
	b.Stop()
	require.Eventually(t, func() bool { return !pub.IsConnected() }, 5*time.Second, time.Millisecond)
	require.ErrorIs(t, pub.Send(bg, "/queues/r", dataMsg("x"), true), amqp.ErrNotConnected)
	// An unsettled one waits for the broker.
	go func() { done <- pub.Send(bg, "/queues/r", dataMsg("later"), false) }()
	require.NoError(t, b.Start())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Send did not complete")
	}
	// The subscription came back too (with the copies of "once" that the
	// broker requeued when the connection of the consumer broke).
	for {
		if p := in.next(t).Payload(); string(p) != "once" {
			require.Equal(t, []byte("later"), p)
			break
		}
	}
}

func TestSubscribeWhileDisconnected(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	c := dial(t, amqp.Options{Server: b.URL()})
	b.Stop()
	require.Eventually(t, func() bool { return !c.IsConnected() }, 5*time.Second, time.Millisecond)
	in, sub := subscribe(t, c, "later", false)
	require.NoError(t, sub.Unsubscribe(bg)) // not attached: nothing to do
	in2, _ := subscribe(t, c, "later", false)
	require.NoError(t, b.Start())
	require.Eventually(t, func() bool { return b.LinkCount("later") == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, c.Send(bg, "later", dataMsg("x"), false))
	require.Equal(t, []byte("x"), in2.next(t).Payload())
	in.none(t, 10*time.Millisecond)
}

func TestBrokerDetachesReceiver(t *testing.T) {
	var refuse atomic.Bool
	b := startBroker(t, amqpbroker.Options{RefuseAddress: func(string) bool { return refuse.Load() }})
	c := dial(t, amqp.Options{Server: b.URL(), MinReconnectDelay: time.Millisecond, MaxReconnectDelay: 5 * time.Millisecond})
	in, _ := subscribe(t, c, "d", false)
	// Detached, then refused a few times: the client keeps trying.
	refuse.Store(true)
	require.Equal(t, 1, b.DetachLinks("d", &amqp.Error{Condition: amqp.CondDetachForced}))
	time.Sleep(20 * time.Millisecond)
	refuse.Store(false)
	require.Eventually(t, func() bool { return b.LinkCount("d") == 1 }, 5*time.Second, time.Millisecond)
	pub := dial(t, amqp.Options{Server: b.URL()})
	require.NoError(t, pub.Send(bg, "d", dataMsg("back"), false))
	require.Equal(t, []byte("back"), in.next(t).Payload())

	// A sender detached by the broker: the next Send attaches again.
	require.Equal(t, 2, b.DetachLinks("d", nil))
	require.Eventually(t, func() bool { return b.LinkCount("d") == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, pub.Send(bg, "d", dataMsg("again"), false))
	require.Equal(t, []byte("again"), in.next(t).Payload())
}

func TestBrokerClosesConnection(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	// The connection-lost errors have different concrete types (the
	// broker's close, a read error): keep them behind a mutex, an
	// atomic.Value panics on a store of another type.
	var mu sync.Mutex
	var lost []error
	c := dial(t, amqp.Options{Server: b.URL(), OnConnectionLost: func(err error) {
		mu.Lock()
		lost = append(lost, err)
		mu.Unlock()
	}})
	in, _ := subscribe(t, c, "c", false)
	b.CloseConnections(&amqp.Error{Condition: amqp.CondConnectionForced, Description: "maintenance"})
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(lost) > 0
	}, 5*time.Second, time.Millisecond)
	mu.Lock()
	require.ErrorContains(t, lost[0], "maintenance")
	mu.Unlock()
	require.Eventually(t, func() bool { return b.LinkCount("c") == 1 }, 5*time.Second, time.Millisecond)
	require.NoError(t, c.Send(bg, "c", dataMsg("x"), false))
	require.Equal(t, []byte("x"), in.next(t).Payload())
}

func TestIdleTimeout(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{IdleTimeout: 200 * time.Millisecond})
	var lost atomic.Int32
	c := dial(t, amqp.Options{Server: b.URL(), IdleTimeout: 100 * time.Millisecond, OnConnectionLost: func(error) { lost.Add(1) }})
	// Heartbeats in both directions keep the idle connection up.
	time.Sleep(500 * time.Millisecond)
	require.Zero(t, lost.Load())
	require.True(t, c.IsConnected())
	// A broker that falls silent is dropped and reconnected.
	b.SetSilent(true)
	require.Eventually(t, func() bool { return lost.Load() > 0 }, 5*time.Second, time.Millisecond)
	b.SetSilent(false)
	require.Eventually(t, c.IsConnected, 5*time.Second, time.Millisecond)
}

func TestSendContext(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	c := dial(t, amqp.Options{Server: b.URL()})
	b.SetWithholdDispositions(true)
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, c.Send(ctx, "x", dataMsg("x"), false), context.DeadlineExceeded)
	b.SetWithholdDispositions(false)
	require.NoError(t, c.Send(bg, "x", dataMsg("y"), false))
	// An unencodable message.
	require.Error(t, c.Send(bg, "x", &amqp.Message{Value: struct{}{}}, false))
}

func TestClose(t *testing.T) {
	b := startBroker(t, amqpbroker.Options{})
	c := dial(t, amqp.Options{Server: b.URL()})
	_, sub := subscribe(t, c, "x", false)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	require.ErrorIs(t, c.Send(bg, "x", dataMsg("x"), true), amqp.ErrClosed)
	_, err := c.Subscribe(bg, "x", false, func(*amqp.Message) {})
	require.ErrorIs(t, err, amqp.ErrClosed)
	require.NoError(t, sub.Unsubscribe(bg))
	require.False(t, c.IsConnected())
	_, err = c.Subscribe(bg, "x", false, nil)
	require.Error(t, err)
	require.Eventually(t, func() bool { return b.ClientCount() == 0 }, 5*time.Second, time.Millisecond)
}

func TestErrors(t *testing.T) {
	require.Contains(t, (&amqp.ConnectError{SASL: true, SASLCode: 9}).Error(), "unknown")
	require.Contains(t, (&amqp.ConnectError{Reason: "r"}).Error(), "r")
	require.Contains(t, (&amqp.LinkError{Address: "a"}).Error(), `"a"`)
	require.Contains(t, (&amqp.DeliveryError{State: &amqp.Accepted{}}).Error(), "unexpected")
	require.Equal(t, "c", (&amqp.Error{Condition: "c"}).Error())
	require.True(t, errors.Is(amqp.ErrClosed, amqp.ErrClosed))
}
