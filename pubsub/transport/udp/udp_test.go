// SPDX-License-Identifier: MIT

package udp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// freePort returns a UDP port that is free on 127.0.0.1 right now.
func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := c.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, c.Close())
	return port
}

func open(t *testing.T, cfg transport.Config) *Conn {
	t.Helper()
	c, err := Open(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// collector gathers received messages.
type collector struct {
	mu   sync.Mutex
	msgs []*transport.Message
	ch   chan struct{}
}

func newCollector() *collector { return &collector{ch: make(chan struct{}, 1<<16)} }

func (c *collector) handle(m *transport.Message) {
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.mu.Unlock()
	c.ch <- struct{}{}
}

func (c *collector) wait(t *testing.T, n int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.After(timeout)
	for i := 0; i < n; i++ {
		select {
		case <-c.ch:
		case <-deadline:
			return false
		}
	}
	return true
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func (c *collector) get(i int) *transport.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.msgs[i]
}

func TestUnicastLoopback(t *testing.T) {
	port := freePort(t)
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", port)
	sub := open(t, transport.Config{URL: url})
	col := newCollector()
	cancel, err := sub.Subscribe(context.Background(), "ignored", 1, col.handle)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), sub.LocalAddr().String())

	pub := open(t, transport.Config{URL: url})
	require.Nil(t, pub.LocalAddr())
	require.Equal(t, MaxDatagramIPv4, pub.MaxMessageSize())
	require.NoError(t, pub.Send(context.Background(), []byte("hello"), transport.PublishOptions{Topic: "x"}))
	require.True(t, col.wait(t, 1, 5*time.Second))
	m := col.get(0)
	require.Equal(t, "hello", string(m.Payload))
	require.Empty(t, m.Topic)
	require.Equal(t, "127.0.0.1", m.Source.(*net.UDPAddr).IP.String())
	require.WithinDuration(t, time.Now(), m.Received, 5*time.Second)

	// After cancel the handler gets nothing; cancel is idempotent.
	require.NoError(t, cancel())
	require.NoError(t, cancel())
	col2 := newCollector()
	_, err = sub.Subscribe(context.Background(), "", 0, col2.handle)
	require.NoError(t, err)
	require.NoError(t, pub.Send(context.Background(), []byte("again"), transport.PublishOptions{}))
	require.True(t, col2.wait(t, 1, 5*time.Second))
	require.Equal(t, 1, col.count())
}

func TestLocalhostReceivesAll(t *testing.T) {
	port := freePort(t)
	sub := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://localhost:%d", port)})
	col := newCollector()
	_, err := sub.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	ua, ok := sub.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.True(t, ua.IP.IsUnspecified(), "wildcard bind, got %s", ua)

	pub := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://localhost:%d", port)})
	require.NoError(t, pub.Send(context.Background(), []byte("x"), transport.PublishOptions{}))
	require.True(t, col.wait(t, 1, 5*time.Second))

	// An empty host receives all too but cannot send.
	empty := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://:%d", freePort(t))})
	require.ErrorContains(t, empty.Send(context.Background(), []byte("x"), transport.PublishOptions{}), "no destination")
	_, err = empty.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
	require.NoError(t, err)
}

func TestListenAddress(t *testing.T) {
	port := freePort(t)
	sub := open(t, transport.Config{URL: "opc.udp://192.0.2.1:4840", ListenAddress: fmt.Sprintf("127.0.0.1:%d", port)})
	col := newCollector()
	_, err := sub.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	pub := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port)})
	require.NoError(t, pub.Send(context.Background(), []byte("x"), transport.PublishOptions{}))
	require.True(t, col.wait(t, 1, 5*time.Second))

	// Host only: the port of the URL.
	c := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://192.0.2.1:%d", freePort(t)), ListenAddress: "127.0.0.1"})
	_, err = c.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	// Port only: the wildcard address.
	c = open(t, transport.Config{URL: "opc.udp://192.0.2.1:4840", ListenAddress: fmt.Sprintf(":%d", freePort(t))})
	_, err = c.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)

	// Binding a foreign unicast address fails in Subscribe.
	c = open(t, transport.Config{URL: "opc.udp://192.0.2.1:4840"})
	_, err = c.Subscribe(context.Background(), "", 0, col.handle)
	require.ErrorContains(t, err, "bind")
}

func TestUnicastIPv6(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, probe.Close())
	url := fmt.Sprintf("opc.udp://[::1]:%d", port)
	sub := open(t, transport.Config{URL: url})
	col := newCollector()
	_, err = sub.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	pub := open(t, transport.Config{URL: url})
	require.Equal(t, MaxDatagramIPv6, pub.MaxMessageSize())
	require.NoError(t, pub.Send(context.Background(), []byte("six"), transport.PublishOptions{}))
	require.True(t, col.wait(t, 1, 5*time.Second))
	require.Equal(t, "six", string(col.get(0).Payload))
}

func TestLargeDatagrams(t *testing.T) {
	port := freePort(t)
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", port)
	sub := open(t, transport.Config{URL: url})
	col := newCollector()
	_, err := sub.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	pub := open(t, transport.Config{URL: url})

	big := bytes.Repeat([]byte("0123456789abcdef"), MaxDatagramIPv4/16+1)[:MaxDatagramIPv4]
	require.NoError(t, pub.Send(context.Background(), big, transport.PublishOptions{}))
	require.True(t, col.wait(t, 1, 5*time.Second))
	require.Equal(t, big, col.get(0).Payload)

	err = pub.Send(context.Background(), append(big, 'x'), transport.PublishOptions{})
	require.ErrorIs(t, err, transport.ErrMessageTooLarge)

	// A configured limit applies to both directions.
	small := open(t, transport.Config{URL: url, MaxMessageSize: 100})
	require.ErrorIs(t, small.Send(context.Background(), make([]byte, 101), transport.PublishOptions{}), transport.ErrMessageTooLarge)
	port2 := freePort(t)
	limited := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port2), MaxMessageSize: 100})
	col2 := newCollector()
	_, err = limited.Subscribe(context.Background(), "", 0, col2.handle)
	require.NoError(t, err)
	pub2 := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port2)})
	require.NoError(t, pub2.Send(context.Background(), make([]byte, 200), transport.PublishOptions{}))
	require.NoError(t, pub2.Send(context.Background(), make([]byte, 50), transport.PublishOptions{}))
	require.True(t, col2.wait(t, 1, 5*time.Second))
	require.Len(t, col2.get(0).Payload, 50)
}

func TestConcurrentSendReceive(t *testing.T) {
	port := freePort(t)
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", port)
	sub := open(t, transport.Config{URL: url})
	var got atomic.Int64
	var c1, c2 atomic.Int64
	_, err := sub.Subscribe(context.Background(), "", 0, func(*transport.Message) { got.Add(1); c1.Add(1) })
	require.NoError(t, err)
	_, err = sub.Subscribe(context.Background(), "", 0, func(m *transport.Message) {
		m.Payload[0] = 'X' // each subscriber owns its copy
		c2.Add(1)
	})
	require.NoError(t, err)

	pub := open(t, transport.Config{URL: url})
	const senders, per = 4, 200
	var wg sync.WaitGroup
	for s := 0; s < senders; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				_ = pub.Send(context.Background(), []byte(fmt.Sprintf("m-%d", i)), transport.PublishOptions{})
				if i%50 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	// Concurrent subscribe/cancel while receiving.
	for i := 0; i < 20; i++ {
		cancel, err := sub.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
		require.NoError(t, err)
		require.NoError(t, cancel())
	}
	wg.Wait()
	require.Eventually(t, func() bool { return got.Load() >= senders*per*95/100 }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return c1.Load() == c2.Load() }, 5*time.Second, 10*time.Millisecond)
}

func TestCloseSemantics(t *testing.T) {
	before := runtime.NumGoroutine()
	port := freePort(t)
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", port)
	c, err := Open(context.Background(), transport.Config{URL: url})
	require.NoError(t, err)
	_, err = c.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
	require.NoError(t, err)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	require.ErrorIs(t, c.Send(context.Background(), []byte("x"), transport.PublishOptions{}), transport.ErrClosed)
	_, err = c.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
	require.ErrorIs(t, err, transport.ErrClosed)
	// Close waited for the receive goroutine (no Eventually here: it runs
	// its condition in a goroutine of its own).
	require.LessOrEqual(t, runtime.NumGoroutine(), before)

	// The port is free again.
	c2 := open(t, transport.Config{URL: url})
	_, err = c2.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
	require.NoError(t, err)

	// Close without ever subscribing, and a Send racing with Close.
	c3, err := Open(context.Background(), transport.Config{URL: url})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			if err := c3.Send(context.Background(), []byte("x"), transport.PublishOptions{}); err != nil {
				require.ErrorIs(t, err, transport.ErrClosed)
				return
			}
		}
	}()
	require.NoError(t, c3.Close())
	<-done
}

func TestContext(t *testing.T) {
	c := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", freePort(t))})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, c.Send(ctx, []byte("x"), transport.PublishOptions{}), context.Canceled)
	_, err := c.Subscribe(ctx, "", 0, func(*transport.Message) {})
	require.ErrorIs(t, err, context.Canceled)
	_, err = c.Subscribe(context.Background(), "", 0, nil)
	require.Error(t, err)
	ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, c.Send(ctx, []byte("x"), transport.PublishOptions{}))
}

func TestOpenErrors(t *testing.T) {
	for _, url := range []string{
		"udp://127.0.0.1:4840",
		"opc.udp://127.0.0.1",
		"opc.udp://127.0.0.1:0",
		"opc.udp://127.0.0.1:70000",
		"opc.udp://127.0.0.1:x",
		"opc.udp://no-such-host.invalid:4840",
	} {
		_, err := Open(context.Background(), transport.Config{URL: url})
		require.Error(t, err, url)
	}
	_, err := Open(context.Background(), transport.Config{URL: "opc.udp://127.0.0.1:4840", Interface: "no-such-if0"})
	require.Error(t, err)
	_, err = Open(context.Background(), transport.Config{URL: "opc.udp://127.0.0.1:4840", Interface: "192.0.2.77"})
	require.Error(t, err)
	_, err = Open(context.Background(), transport.Config{URL: "opc.udp://127.0.0.1:4840", ListenAddress: "127.0.0.1:x"})
	require.Error(t, err)
	_, err = Open(context.Background(), transport.Config{URL: "opc.udp://127.0.0.1:4840", ListenAddress: "no-such-host.invalid"})
	require.Error(t, err)

	// A path after the address is ignored; an interface can be named by
	// one of its addresses.
	c := open(t, transport.Config{URL: "opc.udp://127.0.0.1:4840/path", Interface: "127.0.0.1"})
	require.NotNil(t, c.ifi)
}

func TestRegistry(t *testing.T) {
	require.Contains(t, transport.Schemes(), Scheme)
	c, err := transport.Open(context.Background(), transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", freePort(t))})
	require.NoError(t, err)
	require.NoError(t, c.Close())
}

func TestResolveName(t *testing.T) {
	a, err := resolve(context.Background(), "localhost")
	require.NoError(t, err)
	require.True(t, a.IsLoopback())
}
