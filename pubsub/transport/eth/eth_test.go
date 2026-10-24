// SPDX-License-Identifier: MIT

package eth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// The tests of this file run the connection over fake links and fake
// interfaces; they need no privileges and run on every OS. They replace
// package variables and do not run in parallel.

var fakeInterfaces = map[string]*net.Interface{
	"eth0":  {Index: 2, Name: "eth0", MTU: 1500, HardwareAddr: macA, Flags: net.FlagUp | net.FlagMulticast},
	"jumbo": {Index: 3, Name: "jumbo", MTU: 9000, HardwareAddr: macA, Flags: net.FlagUp},
	"small": {Index: 4, Name: "small", MTU: 1000, HardwareAddr: macA, Flags: net.FlagUp},
	"lo":    {Index: 1, Name: "lo", MTU: 65536, Flags: net.FlagUp | net.FlagLoopback},
	"tun0":  {Index: 5, Name: "tun0", MTU: 1500, Flags: net.FlagUp | net.FlagPointToPoint},
}

type fakeFrame struct {
	b        []byte
	outgoing bool
	err      error
}

// fakeLink is a link whose received frames the test pushes and whose sent
// frames it inspects.
type fakeLink struct {
	cfg      linkConfig
	in       chan fakeFrame
	done     chan struct{}
	once     sync.Once
	closeErr error

	mu       sync.Mutex
	sent     [][]byte
	deadline time.Time
	writeErr error
}

func (l *fakeLink) read(buf []byte) (int, bool, error) {
	select {
	case f := <-l.in:
		if f.err != nil {
			return 0, false, f.err
		}
		return copy(buf, f.b), f.outgoing, nil
	case <-l.done:
		return 0, false, net.ErrClosed
	}
}

func (l *fakeLink) write(frame []byte, deadline time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.writeErr != nil {
		return l.writeErr
	}
	l.sent = append(l.sent, bytes.Clone(frame))
	l.deadline = deadline
	return nil
}

func (l *fakeLink) close() error {
	l.once.Do(func() { close(l.done) })
	return l.closeErr
}

func (l *fakeLink) frames() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sent
}

// fakeEnv installs the fake interfaces and links for one test.
type fakeEnv struct {
	mu      sync.Mutex
	links   []*fakeLink
	openErr error
}

func useFakes(t *testing.T) *fakeEnv {
	t.Helper()
	env := &fakeEnv{}
	oldOpen, oldIf := openLink, interfaceByName
	openLink = func(cfg linkConfig) (link, error) {
		env.mu.Lock()
		defer env.mu.Unlock()
		if env.openErr != nil {
			return nil, env.openErr
		}
		l := &fakeLink{cfg: cfg, in: make(chan fakeFrame, 64), done: make(chan struct{})}
		env.links = append(env.links, l)
		return l, nil
	}
	interfaceByName = func(name string) (*net.Interface, error) {
		if ifi, ok := fakeInterfaces[name]; ok {
			cp := *ifi
			return &cp, nil
		}
		return nil, errors.New("no such interface")
	}
	t.Cleanup(func() { openLink, interfaceByName = oldOpen, oldIf })
	return env
}

func (e *fakeEnv) link(t *testing.T, recv bool) *fakeLink {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, l := range e.links {
		if l.cfg.recv == recv {
			return l
		}
	}
	t.Fatalf("no link with recv=%v", recv)
	return nil
}

func openFake(t *testing.T, cfg transport.Config) *Conn {
	t.Helper()
	if cfg.Interface == "" {
		cfg.Interface = "eth0"
	}
	c, err := Open(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// collector gathers received messages.
type collector struct {
	ch chan *transport.Message
}

func newCollector() *collector { return &collector{ch: make(chan *transport.Message, 1024)} }

func (c *collector) handle(m *transport.Message) { c.ch <- m }

// next waits for the next message.
func (c *collector) next(t *testing.T) *transport.Message {
	t.Helper()
	select {
	case m := <-c.ch:
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("no message")
		return nil
	}
}

// none checks that nothing else arrived. It is called after next returned
// a later frame: the receive goroutine delivers in order.
func (c *collector) none(t *testing.T) {
	t.Helper()
	select {
	case m := <-c.ch:
		t.Fatalf("unexpected message %q", m.Payload)
	default:
	}
}

func frameTo(dst net.HardwareAddr, a Address, payload string) []byte {
	return append(header(dst, macB, a), payload...)
}

func TestOpenErrors(t *testing.T) {
	env := useFakes(t)
	ctx := context.Background()
	for _, tc := range []struct {
		cfg transport.Config
		msg string
	}{
		{transport.Config{URL: "opc.udp://1.2.3.4:5", Interface: "eth0"}, "not an opc.eth:// URL"},
		{transport.Config{URL: "opc.eth://01-00-5e-00-00-01"}, "needs a network interface"},
		{transport.Config{URL: "opc.eth://01-00-5e-00-00-01", Interface: "nope"}, `no interface "nope"`},
		{transport.Config{URL: "opc.eth://01-00-5e-00-00-01", Interface: "tun0"}, "has no Ethernet address"},
	} {
		_, err := Open(ctx, tc.cfg)
		require.ErrorContains(t, err, tc.msg)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err := Open(cctx, transport.Config{URL: "opc.eth://01-00-5e-00-00-01", Interface: "eth0"})
	require.ErrorIs(t, err, context.Canceled)

	env.openErr = errors.New("boom")
	_, err = Open(ctx, transport.Config{URL: "opc.eth://01-00-5e-00-00-01", Interface: "eth0"})
	require.ErrorContains(t, err, "boom")
	// Without a destination nothing is opened.
	c, err := Open(ctx, transport.Config{URL: "opc.eth://", Interface: "eth0"})
	require.NoError(t, err)
	require.NoError(t, c.Close())
}

func TestRegistered(t *testing.T) {
	useFakes(t)
	require.Contains(t, transport.Schemes(), Scheme)
	tc, err := transport.Open(context.Background(), transport.Config{URL: "opc.eth://01-00-5e-00-00-01", Interface: "eth0"})
	require.NoError(t, err)
	require.Equal(t, MaxPayload, tc.MaxMessageSize())
	require.NoError(t, tc.Close())
}

func TestSend(t *testing.T) {
	env := useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://01-00-5e-7f-00-01:100.5"})
	l := env.link(t, false)
	require.False(t, l.cfg.recv)
	require.Equal(t, "eth0", l.cfg.ifi.Name)

	require.NoError(t, c.Send(context.Background(), []byte("hello"), transport.PublishOptions{Topic: "ignored"}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	require.NoError(t, c.Send(ctx, []byte("world"), transport.PublishOptions{}))
	dl, _ := ctx.Deadline()
	require.Equal(t, dl, l.deadline)

	sent := l.frames()
	require.Len(t, sent, 2)
	require.Equal(t, append(header(grp, macA, Address{VLAN: true, VID: 100, PCP: 5}), "hello"...), sent[0])
	f, err := parseFrame(sent[1])
	require.NoError(t, err)
	require.Equal(t, "world", string(f.payload))
	require.Equal(t, macA, f.src)

	// The largest NetworkMessage fits, one byte more does not.
	require.NoError(t, c.Send(context.Background(), make([]byte, c.MaxMessageSize()), transport.PublishOptions{}))
	err = c.Send(context.Background(), make([]byte, c.MaxMessageSize()+1), transport.PublishOptions{})
	require.ErrorIs(t, err, transport.ErrMessageTooLarge)

	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	require.ErrorIs(t, c.Send(cctx, []byte("x"), transport.PublishOptions{}), context.Canceled)

	l.mu.Lock()
	l.writeErr = errors.New("link down")
	l.mu.Unlock()
	err = c.Send(context.Background(), []byte("x"), transport.PublishOptions{})
	require.ErrorContains(t, err, "send to 01-00-5e-7f-00-01:100.5 on eth0: link down")
	l.mu.Lock()
	l.writeErr = fmt.Errorf("wrapped: %w", net.ErrClosed)
	l.mu.Unlock()
	require.ErrorIs(t, c.Send(context.Background(), []byte("x"), transport.PublishOptions{}), transport.ErrClosed)

	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	require.ErrorIs(t, c.Send(context.Background(), []byte("x"), transport.PublishOptions{}), transport.ErrClosed)
}

func TestSendWithoutDestination(t *testing.T) {
	useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://"})
	err := c.Send(context.Background(), []byte("x"), transport.PublishOptions{})
	require.ErrorContains(t, err, "has no destination address")
}

func TestMaxMessageSize(t *testing.T) {
	tagged := MaxPayload
	if tagCountsAgainstMTU {
		tagged -= tagLen
	}
	for _, tc := range []struct {
		mtu        int
		vlan       bool
		configured int
		want       int
	}{
		{1500, false, 0, 1500},
		{1500, true, 0, tagged},
		{9000, true, 0, 1500},
		{65536, false, 0, 1500},
		{0, false, 0, 1500},
		{1000, false, 0, 1000},
		{1500, false, 600, 600},
		{1500, false, 9000, 1500},
	} {
		require.Equal(t, tc.want, maxMessageSize(tc.mtu, tc.vlan, tc.configured), "%+v", tc)
	}
	useFakes(t)
	require.Equal(t, 1000, openFake(t, transport.Config{URL: "opc.eth://01-00-5e-00-00-01", Interface: "small"}).MaxMessageSize())
	require.Equal(t, 1500, openFake(t, transport.Config{URL: "opc.eth://01-00-5e-00-00-01:1", Interface: "jumbo"}).MaxMessageSize())
}

func TestReceive(t *testing.T) {
	env := useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://01-00-5e-7f-00-01", Logger: slog.New(slog.DiscardHandler)})
	col := newCollector()
	cancel, err := c.Subscribe(context.Background(), "topic", 1, col.handle)
	require.NoError(t, err)
	l := env.link(t, true)
	require.Equal(t, grp, l.cfg.group)
	require.True(t, l.cfg.loopback)

	other := mustMAC("02-00-00-00-00-99")
	push := func(b []byte, outgoing bool) { l.in <- fakeFrame{b: b, outgoing: outgoing} }
	push(frameTo(other, Address{}, "other host"), false)                // dropped
	push(frameTo(mustMAC("01-00-5e-00-00-02"), Address{}, "g2"), false) // other group: dropped
	push(frameTo(macA, Address{}, "")[:13], false)                      // short: dropped
	push(frameTo(grp, Address{}, "group"), false)
	push(frameTo(macA, Address{}, "unicast"), false)
	push(frameTo(mustMAC("ff-ff-ff-ff-ff-ff"), Address{}, "broadcast"), false)
	push(frameTo(grp, Address{VLAN: true, VID: 7, PCP: 2}, "tagged"), false)
	push(frameTo(grp, Address{}, "own"), true) // loopback: delivered

	m := col.next(t)
	require.Equal(t, "group", string(m.Payload))
	require.Empty(t, m.Topic)
	require.Equal(t, Address{MAC: macB}, m.Source)
	require.WithinDuration(t, time.Now(), m.Received, time.Minute)
	require.Equal(t, "unicast", string(col.next(t).Payload))
	require.Equal(t, "broadcast", string(col.next(t).Payload))
	m = col.next(t)
	require.Equal(t, "tagged", string(m.Payload))
	require.Equal(t, Address{MAC: macB, VLAN: true, VID: 7, PCP: 2}, m.Source)
	require.Equal(t, "own", string(col.next(t).Payload))
	col.none(t)

	// A second subscriber gets its own copy.
	col2 := newCollector()
	_, err = c.Subscribe(context.Background(), "", 0, col2.handle)
	require.NoError(t, err)
	push(frameTo(grp, Address{}, "both"), false)
	m1, m2 := col.next(t), col2.next(t)
	require.Equal(t, "both", string(m1.Payload))
	require.Equal(t, "both", string(m2.Payload))
	m1.Payload[0] = 'X'
	require.Equal(t, "both", string(m2.Payload))

	// A read error is logged and the loop goes on.
	l.in <- fakeFrame{err: errors.New("transient")}
	require.NoError(t, cancel())
	require.NoError(t, cancel())
	push(frameTo(grp, Address{}, "after cancel"), false)
	require.Equal(t, "after cancel", string(col2.next(t).Payload))
	col.none(t)

	require.NoError(t, c.Close())
	_, err = c.Subscribe(context.Background(), "", 0, col.handle)
	require.ErrorIs(t, err, transport.ErrClosed)
}

func TestReceiveFilters(t *testing.T) {
	env := useFakes(t)
	off := false
	// Unicast URL, no loopback: no group joined, own frames dropped,
	// oversized frames dropped.
	c := openFake(t, transport.Config{URL: "opc.eth://02-00-00-00-00-0b", MulticastLoopback: &off, MaxMessageSize: 4})
	col := newCollector()
	_, err := c.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	l := env.link(t, true)
	require.Nil(t, l.cfg.group)
	require.False(t, l.cfg.loopback)
	l.in <- fakeFrame{b: frameTo(macA, Address{}, "own"), outgoing: true}
	l.in <- fakeFrame{b: frameTo(grp, Address{}, "grp")}
	l.in <- fakeFrame{b: frameTo(macA, Address{}, "large")}
	l.in <- fakeFrame{b: frameTo(macA, Address{}, "ok")}
	require.Equal(t, "ok", string(col.next(t).Payload))
	col.none(t)

	// Broadcast URL: nothing to join.
	b := openFake(t, transport.Config{URL: "opc.eth://ff-ff-ff-ff-ff-ff"})
	_, err = b.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	env.mu.Lock()
	last := env.links[len(env.links)-1]
	env.mu.Unlock()
	require.True(t, last.cfg.recv)
	require.Nil(t, last.cfg.group)
}

func TestReceiveLoopbackInterface(t *testing.T) {
	env := useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://01-00-5e-7f-00-01", Interface: "lo"})
	require.Equal(t, Address{MAC: make(net.HardwareAddr, 6)}, c.LocalAddr())
	col := newCollector()
	_, err := c.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	l := env.link(t, true)
	zero := make(net.HardwareAddr, 6)
	// The loopback interface delivers a sent frame twice: as outgoing and
	// as received. Only the received copy counts.
	l.in <- fakeFrame{b: frameTo(zero, Address{}, "twice"), outgoing: true}
	l.in <- fakeFrame{b: frameTo(zero, Address{}, "twice")}
	l.in <- fakeFrame{b: frameTo(zero, Address{}, "end")}
	require.Equal(t, "twice", string(col.next(t).Payload))
	require.Equal(t, "end", string(col.next(t).Payload))
	col.none(t)
}

// A frame this host sent that the network reflects back (Docker's networks,
// a bridge in hairpin mode) arrives once as outgoing and once as received
// from the interface's own address. Where the tap marks outgoing frames
// (Linux) the received copy is dropped: every frame is delivered once.
// Found with opcuactl pubsub publish / subscribe in one container, which
// printed every message twice.
func TestReceiveReflectedFrame(t *testing.T) {
	env := useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://01-00-5e-7f-00-01"})
	col := newCollector()
	_, err := c.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	l := env.link(t, true)
	own := append(header(grp, macA, Address{}), "own"...)
	l.in <- fakeFrame{b: own, outgoing: outgoingTap}
	l.in <- fakeFrame{b: own} // reflected
	l.in <- fakeFrame{b: frameTo(grp, Address{}, "end")}
	require.Equal(t, "own", string(col.next(t).Payload))
	if !outgoingTap {
		require.Equal(t, "own", string(col.next(t).Payload))
	}
	require.Equal(t, "end", string(col.next(t).Payload))
	col.none(t)
}

func TestSubscribeErrors(t *testing.T) {
	env := useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://01-00-5e-7f-00-01"})
	_, err := c.Subscribe(context.Background(), "", 0, nil)
	require.ErrorContains(t, err, "nil handler")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Subscribe(ctx, "", 0, func(*transport.Message) {})
	require.ErrorIs(t, err, context.Canceled)
	env.mu.Lock()
	env.openErr = errors.New("no bpf")
	env.mu.Unlock()
	_, err = c.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
	require.ErrorContains(t, err, "no bpf")
}

func TestCloseErrors(t *testing.T) {
	env := useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://01-00-5e-7f-00-01", MulticastLoopback: new(bool)})
	_, err := c.Subscribe(context.Background(), "", 0, func(*transport.Message) {})
	require.NoError(t, err)
	env.link(t, false).closeErr = errors.New("send close")
	env.link(t, true).closeErr = errors.New("recv close")
	err = c.Close()
	require.ErrorContains(t, err, "send close")
	require.ErrorContains(t, err, "recv close")
}

// A read error the link reports after Close ends the loop, whatever it is.
func TestReceiveErrorAfterClose(t *testing.T) {
	useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://"})
	l := &fakeLink{in: make(chan fakeFrame, 1), done: make(chan struct{})}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	l.in <- fakeFrame{err: errors.New("bad file descriptor")}
	c.wg.Add(1)
	c.receive(l) // returns
}

func TestPrivilegeError(t *testing.T) {
	err := privilegeError("open x", errors.New("denied"))
	require.ErrorContains(t, err, "pubsub/transport/eth: open x: denied (raw Ethernet access needs "+privilegeHint+")")
	require.ErrorIs(t, ErrNotSupported, errors.ErrUnsupported)
}

// Without the MAC address of the interface (macOS hides it from processes
// without privileges) every unicast frame is accepted.
func TestReceiveHiddenMAC(t *testing.T) {
	env := useFakes(t)
	old := macHidden
	macHidden = func(net.HardwareAddr) bool { return true }
	t.Cleanup(func() { macHidden = old })
	c := openFake(t, transport.Config{URL: "opc.eth://01-00-5e-7f-00-01"})
	col := newCollector()
	_, err := c.Subscribe(context.Background(), "", 0, col.handle)
	require.NoError(t, err)
	l := env.link(t, true)
	l.in <- fakeFrame{b: frameTo(mustMAC("01-00-5e-00-00-02"), Address{}, "other group")}
	l.in <- fakeFrame{b: frameTo(mustMAC("02-00-00-00-00-99"), Address{}, "unicast")}
	require.Equal(t, "unicast", string(col.next(t).Payload))
	col.none(t)
}
