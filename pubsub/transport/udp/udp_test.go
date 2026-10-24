// SPDX-License-Identifier: MIT

package udp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/leakcheck"
	"github.com/otfabric/go-opcua/internal/testutil/testport"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// freePort returns a UDP port that is free on 127.0.0.1 right now.
func freePort(t *testing.T) int {
	t.Helper()
	return testport.UDP(t)
}

// listen opens a connection for the config cfgFor builds around a free port
// and subscribes h on it, which binds the port. freePort cannot reserve the
// port: another test (CI runs packages in parallel) may bind it before we
// do, so a bind that finds the port taken is retried with another one.
func listen(t *testing.T, cfgFor func(port int) transport.Config, h transport.Handler) (c *Conn, port int, cancel func() error) {
	t.Helper()
	for range 20 {
		port = freePort(t)
		c, err := Open(context.Background(), cfgFor(port))
		require.NoError(t, err)
		cancel, err = c.Subscribe(context.Background(), "", 0, h)
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c, port, cancel
		}
		_ = c.Close()
		require.ErrorIs(t, err, syscall.EADDRINUSE)
	}
	t.Fatal("no free UDP port after 20 attempts")
	return nil, 0, nil
}

func loopback(port int) transport.Config {
	return transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port)}
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
	col := newCollector()
	sub, port, cancel := listen(t, loopback, col.handle)
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", port)
	require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), sub.LocalAddr().String())
	// A topic and QoS are ignored by the datagram transport.
	cancelIgnored, err := sub.Subscribe(context.Background(), "ignored", 1, func(*transport.Message) {})
	require.NoError(t, err)
	require.NoError(t, cancelIgnored())

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
	col := newCollector()
	sub, port, _ := listen(t, func(p int) transport.Config {
		return transport.Config{URL: fmt.Sprintf("opc.udp://localhost:%d", p)}
	}, col.handle)
	ua, ok := sub.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.True(t, ua.IP.IsUnspecified(), "wildcard bind, got %s", ua)

	pub := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://localhost:%d", port)})
	require.NoError(t, pub.Send(context.Background(), []byte("x"), transport.PublishOptions{}))
	require.True(t, col.wait(t, 1, 5*time.Second))

	// An empty host receives all too but cannot send.
	empty, _, _ := listen(t, func(p int) transport.Config {
		return transport.Config{URL: fmt.Sprintf("opc.udp://:%d", p)}
	}, func(*transport.Message) {})
	require.ErrorContains(t, empty.Send(context.Background(), []byte("x"), transport.PublishOptions{}), "no destination")
}

func TestListenAddress(t *testing.T) {
	col := newCollector()
	_, port, _ := listen(t, func(p int) transport.Config {
		return transport.Config{URL: "opc.udp://192.0.2.1:4840", ListenAddress: fmt.Sprintf("127.0.0.1:%d", p)}
	}, col.handle)
	pub := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port)})
	require.NoError(t, pub.Send(context.Background(), []byte("x"), transport.PublishOptions{}))
	require.True(t, col.wait(t, 1, 5*time.Second))

	// Host only: the port of the URL.
	c, _, _ := listen(t, func(p int) transport.Config {
		return transport.Config{URL: fmt.Sprintf("opc.udp://192.0.2.1:%d", p), ListenAddress: "127.0.0.1"}
	}, col.handle)
	require.Equal(t, "127.0.0.1", c.LocalAddr().(*net.UDPAddr).IP.String())
	// Port only: the wildcard address.
	c, _, _ = listen(t, func(p int) transport.Config {
		return transport.Config{URL: "opc.udp://192.0.2.1:4840", ListenAddress: fmt.Sprintf(":%d", p)}
	}, col.handle)
	require.True(t, c.LocalAddr().(*net.UDPAddr).IP.IsUnspecified())

	// Binding a foreign unicast address fails in Subscribe.
	c = open(t, transport.Config{URL: "opc.udp://192.0.2.1:4840"})
	_, err := c.Subscribe(context.Background(), "", 0, col.handle)
	require.ErrorContains(t, err, "bind")
}

func TestUnicastIPv6(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	require.NoError(t, probe.Close())
	col := newCollector()
	_, port, _ := listen(t, func(p int) transport.Config {
		return transport.Config{URL: fmt.Sprintf("opc.udp://[::1]:%d", p)}
	}, col.handle)
	url := fmt.Sprintf("opc.udp://[::1]:%d", port)
	pub := open(t, transport.Config{URL: url})
	require.Equal(t, MaxDatagramIPv6, pub.MaxMessageSize())
	require.NoError(t, pub.Send(context.Background(), []byte("six"), transport.PublishOptions{}))
	require.True(t, col.wait(t, 1, 5*time.Second))
	require.Equal(t, "six", string(col.get(0).Payload))
}

func TestLargeDatagrams(t *testing.T) {
	col := newCollector()
	_, port, _ := listen(t, loopback, col.handle)
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", port)
	pub := open(t, transport.Config{URL: url})

	big := bytes.Repeat([]byte("0123456789abcdef"), MaxDatagramIPv4/16+1)[:MaxDatagramIPv4]
	require.NoError(t, pub.Send(context.Background(), big, transport.PublishOptions{}))
	require.True(t, col.wait(t, 1, 5*time.Second))
	require.Equal(t, big, col.get(0).Payload)

	err := pub.Send(context.Background(), append(big, 'x'), transport.PublishOptions{})
	require.ErrorIs(t, err, transport.ErrMessageTooLarge)

	// A configured limit applies to both directions.
	small := open(t, transport.Config{URL: url, MaxMessageSize: 100})
	require.ErrorIs(t, small.Send(context.Background(), make([]byte, 101), transport.PublishOptions{}), transport.ErrMessageTooLarge)
	col2 := newCollector()
	_, port2, _ := listen(t, func(p int) transport.Config {
		return transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", p), MaxMessageSize: 100}
	}, col2.handle)
	pub2 := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port2)})
	require.NoError(t, pub2.Send(context.Background(), make([]byte, 200), transport.PublishOptions{}))
	require.NoError(t, pub2.Send(context.Background(), make([]byte, 50), transport.PublishOptions{}))
	require.True(t, col2.wait(t, 1, 5*time.Second))
	require.Len(t, col2.get(0).Payload, 50)
}

func TestConcurrentSendReceive(t *testing.T) {
	var got atomic.Int64
	var c1, c2 atomic.Int64
	sub, port, _ := listen(t, loopback, func(*transport.Message) { got.Add(1); c1.Add(1) })
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", port)
	_, err := sub.Subscribe(context.Background(), "", 0, func(m *transport.Message) {
		m.Payload[0] = 'X' // each subscriber owns its copy
		c2.Add(1)
	})
	require.NoError(t, err)

	pub := open(t, transport.Config{URL: url})
	const senders, per = 4, 200
	// The senders keep at most window datagrams ahead of the receiver: a
	// burst of 800 overflows the default receive buffer on Linux (some
	// 200 small datagrams) when the receiver is slowed down by the race
	// detector, and the kernel drops the rest silently. A sender gives up
	// waiting after a while, so that lost datagrams do not stall it.
	const window = 64
	var sent atomic.Int64
	var wg sync.WaitGroup
	for s := 0; s < senders; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				for deadline := time.Now().Add(100 * time.Millisecond); sent.Load()-got.Load() >= window && time.Now().Before(deadline); {
					time.Sleep(100 * time.Microsecond)
				}
				sent.Add(1)
				_ = pub.Send(context.Background(), []byte(fmt.Sprintf("m-%d", i)), transport.PublishOptions{})
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
	c, port, _ := listen(t, loopback, func(*transport.Message) {})
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", port)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	require.ErrorIs(t, c.Send(context.Background(), []byte("x"), transport.PublishOptions{}), transport.ErrClosed)
	_, err := c.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
	require.ErrorIs(t, err, transport.ErrClosed)
	// Close waited for the receive goroutine. The connections of earlier
	// tests are closed by their cleanups, so no receive loop may be left.
	// (Counting goroutines is not exact: other goroutines of the test binary
	// come and go.) A receive loop that has signalled its end may still be
	// returning when Close returns, so the stacks are polled briefly.
	require.Eventually(t, func() bool {
		return !strings.Contains(leakcheck.AllStacks(), "udp.(*Conn).receive")
	}, 2*time.Second, time.Millisecond, "a receive loop outlived Close")

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
