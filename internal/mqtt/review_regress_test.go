// SPDX-License-Identifier: MIT

package mqtt_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
)

// Regression: Close waited for the delivery goroutine, so a handler that
// closed the client waited for itself forever.
func TestCloseFromHandler(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL()})
	closed := make(chan error, 1)
	_, err := c.Subscribe(bg, "close/me", 0, func(*mqtt.Message) { closed <- c.Close() })
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "close/me", []byte("x"), 0, false))
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close called from a handler did not return")
	}
	require.ErrorIs(t, c.Publish(bg, "close/me", []byte("x"), 0, false), mqtt.ErrClosed)
}

// Close from another goroutine still waits for a running handler.
func TestCloseWaitsForHandler(t *testing.T) {
	b := startBroker(t, mqttbroker.Options{})
	c := dial(t, mqtt.Options{Server: b.URL()})
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	_, err := c.Subscribe(bg, "slow", 0, func(*mqtt.Message) {
		close(entered)
		<-release
		close(finished)
	})
	require.NoError(t, err)
	require.NoError(t, c.Publish(bg, "slow", []byte("x"), 0, false))
	<-entered
	done := make(chan struct{})
	go func() { _ = c.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("Close returned while a handler was running")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-done
	select {
	case <-finished:
	default:
		t.Fatal("Close returned before the handler")
	}
}

// Regression: with every packet identifier taken by publications the
// broker never acknowledged, allocID looped forever holding the client's
// mutex: Publish, Subscribe and even Close hung.
func TestPacketIdentifiersExhausted(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	go fakeBroker(t, l, func(_ net.Conn, read func() mqtt.Packet, _ func(mqtt.Packet)) {
		for read() != nil { // never acknowledges
		}
	})
	c := dial(t, mqtt.Options{Server: "mqtt://" + l.Addr().String()})
	gone, cancel := context.WithCancel(bg)
	cancel()
	// Written publications keep their identifiers until the broker
	// acknowledges them, after their callers gave up.
	for i := 0; ; i++ {
		err := c.Publish(gone, "t", []byte("x"), 1, false)
		if errors.Is(err, mqtt.ErrNoPacketID) {
			require.Greater(t, i, 60000)
			break
		}
		require.ErrorIs(t, err, context.Canceled)
		require.Less(t, i, 1<<16, "no limit")
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(bg, time.Second)
		defer cancel()
		_, err := c.Subscribe(ctx, "s", 1, func(*mqtt.Message) {})
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded) // the broker does not answer
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe hung")
	}
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
}

// Regression: a PUBACK (or PUBREC) for the packet identifier of a
// publication still waiting for send quota completed it, as delivered,
// although it had never been sent.
func TestAckOfUnsentPublicationIgnored(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	pubs := make(chan *mqtt.Publish, 10)
	acks := make(chan mqtt.Packet, 10)
	go fakeBroker5(t, l, &mqtt.Connack{Props: mqtt.Properties{ReceiveMaximum: mqtt.Ptr(uint16(1))}},
		func(read func() mqtt.Packet, write func(mqtt.Packet)) {
			go func() {
				for a := range acks {
					write(a)
				}
			}()
			defer close(acks)
			for {
				p := read()
				if p == nil {
					return
				}
				if pub, ok := p.(*mqtt.Publish); ok {
					pubs <- pub
				}
			}
		})
	c := dial5(t, mqtt.Options{Server: "mqtt://" + l.Addr().String()})
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- c.Publish(bg, "t", []byte("1"), 1, false) }()
	p1 := <-pubs
	go func() { second <- c.Publish(bg, "t", []byte("2"), 2, false) }()
	require.Eventually(t, func() bool { return mqtt.InflightCount(c) == 2 }, 5*time.Second, time.Millisecond)
	// The second one waits for quota; its identifier follows the first's.
	acks <- &mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: p1.PacketID + 1}
	acks <- &mqtt.Ack{Kind: mqtt.TypePuback, PacketID: p1.PacketID + 1}
	acks <- &mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: p1.PacketID + 1}
	select {
	case err := <-second:
		t.Fatalf("an unsent publication completed: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	acks <- &mqtt.Ack{Kind: mqtt.TypePuback, PacketID: p1.PacketID}
	require.NoError(t, <-first)
	p2 := <-pubs
	require.Equal(t, "2", string(p2.Payload))
	require.False(t, p2.Dup)
	acks <- &mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: p2.PacketID}
	acks <- &mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: p2.PacketID}
	require.NoError(t, <-second)
}

// Regression: over MQTT 3.1.1 a QoS 1 or 2 PUBLISH above MaxPacketSize was
// skipped without an acknowledgement, so the broker kept it in flight
// forever: after a few of them (the broker's in-flight window) it stopped
// delivering anything to the client, and redelivered them on reconnect.
func TestOversizedPublishIsAcknowledged(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	got := make(chan mqtt.Packet, 10)
	go fakeBroker(t, l, func(_ net.Conn, read func() mqtt.Packet, write func(mqtt.Packet)) {
		big := make([]byte, 4096)
		write(&mqtt.Publish{Topic: "a/b", QoS: 1, PacketID: 41, Payload: big})
		write(&mqtt.Publish{Topic: "a/b", QoS: 2, PacketID: 42, Payload: big})
		write(&mqtt.Publish{Topic: "a/b", QoS: 0, Payload: big})
		for p := read(); p != nil; p = read() {
			got <- p
			if a, ok := p.(*mqtt.Ack); ok && a.Kind == mqtt.TypePubrec {
				write(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: a.PacketID})
			}
		}
	})
	in := newInbox()
	dial(t, mqtt.Options{Server: "mqtt://" + l.Addr().String(), MaxPacketSize: 1024, DefaultHandler: in.handle})
	next := func() *mqtt.Ack {
		select {
		case p := <-got:
			a, ok := p.(*mqtt.Ack)
			require.True(t, ok, "got %T", p)
			return a
		case <-time.After(5 * time.Second):
			t.Fatal("no acknowledgement of the oversized PUBLISH")
			return nil
		}
	}
	require.Equal(t, mqtt.Ack{Kind: mqtt.TypePuback, PacketID: 41}, *next())
	require.Equal(t, mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: 42}, *next())
	require.Equal(t, mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: 42}, *next())
	in.none(t, 100*time.Millisecond) // dropped all the same
}

func TestTooLargeErrorPacketID(t *testing.T) {
	read := func(b []byte, max int) error {
		_, err := mqtt.ReadPacket(bufioReader(bytes.NewReader(b)), max)
		return err
	}
	pub, err := mqtt.Encode(&mqtt.Publish{Topic: "a/b", QoS: 2, PacketID: 9, Payload: make([]byte, 100)})
	require.NoError(t, err)
	var tl *mqtt.TooLargeError
	require.ErrorAs(t, read(pub, 50), &tl)
	require.ErrorIs(t, tl, mqtt.ErrTooLarge)
	require.Equal(t, mqtt.TooLargeError{Size: len(pub) - 2, Limit: 50, Type: mqtt.TypePublish, QoS: 2, PacketID: 9}, *tl)
	require.Contains(t, tl.Error(), "bytes, limit 50")
	// The stream goes on after the skipped packet.
	br := bufioReader(bytes.NewReader(append(append([]byte{}, pub...), 0xd0, 0)))
	_, err = mqtt.ReadPacket(br, 50)
	require.ErrorIs(t, err, mqtt.ErrTooLarge)
	p, err := mqtt.ReadPacket(br, 50)
	require.NoError(t, err)
	require.Equal(t, mqtt.TypePingresp, p.Type())

	// QoS 0, other packets and a topic longer than the packet: no identifier.
	pub0, err := mqtt.Encode(&mqtt.Publish{Topic: "a/b", Payload: make([]byte, 100)})
	require.NoError(t, err)
	require.ErrorAs(t, read(pub0, 50), &tl)
	require.Zero(t, tl.PacketID)
	bogus := []byte{0x32, 6, 0xff, 0xff, 1, 2, 3, 4}
	require.ErrorAs(t, read(bogus, 5), &tl)
	require.Zero(t, tl.PacketID)
	sub := []byte{0x90, 10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}
	require.ErrorAs(t, read(sub, 5), &tl)
	require.Zero(t, tl.PacketID)
	// Truncated: the stream ends.
	for _, n := range []int{3, 5, 8, 20} {
		require.ErrorIs(t, read(pub[:n], 50), io.ErrUnexpectedEOF, "%d bytes", n)
	}
}

// Regression: Close sent DISCONNECT under the write lock, so with a broker
// that stopped reading it waited for a blocked write's deadline: the
// keep-alive (or the broker's Server Keep Alive, up to 18 hours).
func TestCloseWithStalledBroker(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	stop := make(chan struct{})
	defer close(stop)
	go fakeBroker(t, l, func(net.Conn, func() mqtt.Packet, func(mqtt.Packet)) { <-stop }) // reads nothing
	c, err := mqtt.Dial(bg, mqtt.Options{Server: "mqtt://" + l.Addr().String(), KeepAlive: 300 * time.Second})
	require.NoError(t, err)
	var written atomic.Int64
	go func() {
		payload := make([]byte, 256<<10)
		for c.Publish(bg, "t", payload, 0, false) == nil {
			written.Add(1)
		}
	}()
	// Wait until a write blocks: the socket buffers are full.
	last := int64(-1)
	require.Eventually(t, func() bool {
		n := written.Load()
		stalled := n > 0 && n == last
		last = n
		return stalled
	}, 10*time.Second, 200*time.Millisecond)
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close waited for the blocked write")
	}
}
