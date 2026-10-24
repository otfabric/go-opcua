// SPDX-License-Identifier: MIT

package amqpbroker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/amqp"
)

// rawConn is a client that speaks the frames itself: unlike the client of
// internal/amqp it leaves deliveries unsettled and does not answer a close.
type rawConn struct {
	t  *testing.T
	nc net.Conn
	br *bufio.Reader
}

// dialRaw opens a connection (without SASL) and a session.
func dialRaw(t *testing.T, b *Broker) *rawConn {
	t.Helper()
	nc, err := net.Dial("tcp", b.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	r := &rawConn{t: t, nc: nc, br: bufio.NewReader(nc)}
	if _, err := nc.Write(amqp.HeaderAMQP[:]); err != nil {
		t.Fatal(err)
	}
	var h [8]byte
	if _, err := io.ReadFull(r.br, h[:]); err != nil || h != amqp.HeaderAMQP {
		t.Fatalf("protocol header %q: %v", h, err)
	}
	r.send(&amqp.Open{ContainerID: "raw"})
	if _, ok := r.read().Body.(*amqp.Open); !ok {
		t.Fatal("no open")
	}
	r.send(&amqp.Begin{IncomingWindow: 1 << 20, OutgoingWindow: math.MaxUint32})
	if _, ok := r.read().Body.(*amqp.Begin); !ok {
		t.Fatal("no begin")
	}
	return r
}

func (r *rawConn) send(body amqp.Body) {
	r.t.Helper()
	buf, err := amqp.AppendFrame(nil, &amqp.Frame{Body: body})
	if err == nil {
		_, err = r.nc.Write(buf)
	}
	if err != nil {
		r.t.Fatal(err)
	}
}

// next returns the next frame with a body, or an error after d.
func (r *rawConn) next(d time.Duration) (*amqp.Frame, error) {
	_ = r.nc.SetReadDeadline(time.Now().Add(d))
	for {
		f, err := amqp.ReadFrame(r.br, 1<<20)
		if err != nil || f.Body != nil {
			return f, err
		}
	}
}

func (r *rawConn) read() *amqp.Frame {
	r.t.Helper()
	f, err := r.next(5 * time.Second)
	if err != nil {
		r.t.Fatal(err)
	}
	return f
}

// consume attaches a receiver link to address with credit and settles
// nothing.
func (r *rawConn) consume(address string, credit uint32) {
	r.t.Helper()
	r.send(&amqp.Attach{Name: "raw-" + address, Role: amqp.RoleReceiver, Source: &amqp.Source{Address: address}, Target: &amqp.Target{}})
	if _, ok := r.read().Body.(*amqp.Attach); !ok {
		r.t.Fatal("no attach")
	}
	var h, dc, nii uint32
	r.send(&amqp.Flow{NextIncomingID: &nii, IncomingWindow: 1 << 20, OutgoingWindow: math.MaxUint32, Handle: &h, DeliveryCount: &dc, LinkCredit: &credit})
}

// payload reads the next frame, a transfer, and returns its message body.
func (r *rawConn) payload() string {
	r.t.Helper()
	f := r.read()
	if _, ok := f.Body.(*amqp.Transfer); !ok {
		r.t.Fatalf("got %T, want a transfer", f.Body)
	}
	m := &amqp.Message{}
	if err := m.UnmarshalBinary(f.Payload); err != nil {
		r.t.Fatal(err)
	}
	return string(m.Payload())
}

func publish(t *testing.T, c *amqp.Client, address string, bodies ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range bodies {
		if err := c.Send(ctx, address, &amqp.Message{Data: [][]byte{[]byte(s)}}, false); err != nil {
			t.Fatal(err)
		}
	}
}

func startBroker(t *testing.T) (*Broker, *amqp.Client) {
	t.Helper()
	b := New(Options{})
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pub, err := amqp.Dial(ctx, amqp.Options{Server: b.URL(), IdleTimeout: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pub.Close() })
	return b, pub
}

// TestDropConnectionsRequeuesAtOnce: the unsettled messages of a consumer
// whose connection the broker drops are back in the queue when
// DropConnections returns, not once the goroutines of the connection got
// to it. Until then the queue went on dispatching to the dead consumer, and
// a subscriber that reconnected meanwhile got newer messages before the
// requeued ones, and discarded those as older by their sequence numbers.
func TestDropConnectionsRequeuesAtOnce(t *testing.T) {
	const q = "/queues/drop"
	b, pub := startBroker(t)
	a := dialRaw(t, b)
	a.consume(q, 10)
	publish(t, pub, q, "m1", "m2")
	for _, want := range []string{"m1", "m2"} {
		if got := a.payload(); got != want {
			t.Fatalf("consumer got %q, want %q", got, want)
		}
	}
	b.DropConnections()
	b.mu.Lock()
	n, consumers := len(b.queue(q).msgs), len(b.queue(q).consumers)
	b.mu.Unlock()
	if n != 2 || consumers != 0 {
		t.Fatalf("after DropConnections: %d messages queued, %d consumers; want 2 and 0", n, consumers)
	}
	c := dialRaw(t, b)
	c.consume(q, 10)
	publish(t, pub, q, "m3")
	for _, want := range []string{"m1", "m2", "m3"} {
		if got := c.payload(); got != want {
			t.Fatalf("new consumer got %q, want %q", got, want)
		}
	}
}

// TestCloseConnectionsStopsDispatch: after its close frame the broker
// sends nothing more on a connection (§2.4.3), also while the client has
// not answered it, and the messages stay queued for the next consumer.
func TestCloseConnectionsStopsDispatch(t *testing.T) {
	const q = "/queues/close"
	b, pub := startBroker(t)
	a := dialRaw(t, b)
	a.consume(q, 10)
	publish(t, pub, q, "m1")
	if got := a.payload(); got != "m1" {
		t.Fatalf("consumer got %q, want m1", got)
	}
	b.CloseConnections(&amqp.Error{Condition: amqp.CondInternalError})
	if n := b.Queued(q); n != 1 {
		t.Fatalf("after CloseConnections: %d messages queued, want 1 (the unsettled one)", n)
	}
	publish(t, pub, q, "m2") // the publisher reconnects
	if n := b.Queued(q); n != 2 {
		t.Fatalf("%d messages queued, want 2", n)
	}
	if _, ok := a.read().Body.(*amqp.Close); !ok {
		t.Fatal("no close")
	}
	if f, err := a.next(200 * time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("after its close the broker sent %v (%v)", f, err)
	}
}
