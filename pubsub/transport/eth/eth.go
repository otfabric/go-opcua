// SPDX-License-Identifier: MIT

// Package eth is the Ethernet transport of OPC UA PubSub (Part 14 §7.3.3,
// transport profile pubsub-eth-uadp): UADP NetworkMessages as the payload of
// Ethernet II frames with EtherType 0xB62C, without IP and UDP headers.
//
// Importing the package registers the "opc.eth" scheme with
// [transport.Register].
//
// # Addresses
//
// The URL of a connection is opc.eth://<host>[:<VID>[.<PCP>]] (see
// [ParseURL]): host is the destination MAC address, unicast, multicast
// (opc.eth://01-00-5e-00-00-01) or broadcast; with a VID the frames carry
// an IEEE 802.1Q tag with that VLAN identifier and priority code point.
//
// Config.Interface (NetworkInterface of NetworkAddressDataType) names the
// interface ("eth0") and is required; the frames are sent with its MAC
// address as source.
//
// A subscription receives the frames of EtherType 0xB62C that arrive on the
// interface and are addressed to its MAC address, to the broadcast address
// or, if the URL is a multicast address, to that group, which it joins.
// The VLAN tag of a received frame is not a filter: on Linux the kernel
// removes the tag before raw sockets see the frame. To receive one VLAN
// only, use the VLAN interface (eth0.100) and a URL without VID. Frames
// this host sends are received too unless Config.MulticastLoopback is false.
//
// # Size
//
// A NetworkMessage is at most [MaxPayload] (1500) bytes, or the MTU of the
// interface if that is smaller (on the BSDs minus the 4 bytes of a VLAN
// tag); Send rejects larger ones with [transport.ErrMessageTooLarge]. Short
// frames are padded to the Ethernet minimum (60 bytes) by the hardware: a
// receiver gets the padding after a small NetworkMessage.
//
// # Operating systems
//
// Linux uses AF_PACKET raw sockets (CAP_NET_RAW or root), macOS and FreeBSD
// use BPF devices (/dev/bpf*, root or read-write access to the devices;
// joining a multicast group needs root on macOS). macOS hides the MAC
// address of an interface from processes without privileges: the kernel
// still sets the right source address, but a subscription then accepts every
// unicast frame the interface delivers. On other systems Open returns
// [ErrNotSupported].
package eth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/internal/goid"
	"github.com/otfabric/go-opcua/pubsub/transport"
)

// Scheme is the URL scheme of the Ethernet transport.
const Scheme = "opc.eth"

// readBuffer is the size of the receive buffer: larger than any frame of
// an interface with an MTU up to 64 KiB (the Linux loopback).
const readBuffer = 1<<16 + 64

// errorBackoff is the pause after a failed read.
const errorBackoff = 10 * time.Millisecond

func init() {
	transport.Register(Scheme, func(ctx context.Context, cfg transport.Config) (transport.Connection, error) {
		return Open(ctx, cfg)
	})
}

// interfaceByName looks up the interface; tests replace it.
var interfaceByName = net.InterfaceByName

// macHidden reports whether the MAC address of an interface is hidden;
// tests replace it.
var macHidden = osMACHidden

// Conn is an Ethernet PubSub connection.
type Conn struct {
	cfg     transport.Config
	log     *slog.Logger
	addr    Address
	ifi     *net.Interface
	mac     net.HardwareAddr // source address
	group   bool             // addr.MAC is a multicast group (not broadcast)
	ownMAC  bool             // mac is known: unicast frames are filtered
	loop    bool
	maxSize int
	header  []byte // nil: cannot send

	send link

	mu       sync.Mutex
	closed   bool
	recv     link
	handlers map[uint64]transport.Handler
	nextID   uint64
	wg       sync.WaitGroup
	// recvID is the goroutine id of the receive goroutine, so a Close
	// from a handler does not wait for itself.
	recvID atomic.Uint64
}

var _ transport.Connection = (*Conn)(nil)

// Open opens an Ethernet connection for cfg.URL on cfg.Interface. It opens
// the sending link if the URL has a MAC address; the receiving link is
// opened by Subscribe.
func Open(ctx context.Context, cfg transport.Config) (*Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, err := ParseURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.Interface == "" {
		return nil, fmt.Errorf("pubsub/transport/eth: %s needs a network interface (NetworkInterface)", cfg.URL)
	}
	ifi, err := interfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/eth: no interface %q: %w", cfg.Interface, err)
	}
	mac := ifi.HardwareAddr
	switch {
	case len(mac) == 6:
	case len(mac) == 0 && ifi.Flags&net.FlagLoopback != 0:
		mac = make(net.HardwareAddr, 6) // the Linux loopback: 00-00-00-00-00-00
	default:
		return nil, fmt.Errorf("pubsub/transport/eth: interface %s has no Ethernet address", ifi.Name)
	}
	c := &Conn{
		cfg:    cfg,
		log:    cfg.Logger,
		addr:   a,
		ifi:    ifi,
		mac:    mac,
		group:  isMulticast(a.MAC) && !isBroadcast(a.MAC),
		ownMAC: !macHidden(mac),
		loop:   true,
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if cfg.MulticastLoopback != nil {
		c.loop = *cfg.MulticastLoopback
	}
	c.maxSize = maxMessageSize(ifi.MTU, a.VLAN, cfg.MaxMessageSize)
	if a.MAC != nil {
		c.header = header(a.MAC, mac, a)
		if c.send, err = openLink(linkConfig{ifi: ifi}); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// maxMessageSize returns the largest NetworkMessage of a frame on an
// interface with the MTU, limited further by a configured maximum.
func maxMessageSize(mtu int, tagged bool, configured int) int {
	n := MaxPayload
	if mtu > 0 && mtu < n {
		n = mtu
	}
	if tagged && tagCountsAgainstMTU && n == mtu {
		n -= tagLen
	}
	if configured > 0 && configured < n {
		n = configured
	}
	return n
}

// Send transmits one NetworkMessage in one frame to the address of the
// connection. A NetworkMessage larger than MaxMessageSize fails with
// [transport.ErrMessageTooLarge]: the transport does not split messages.
func (c *Conn) Send(ctx context.Context, payload []byte, _ transport.PublishOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return transport.ErrClosed
	}
	if c.send == nil {
		return fmt.Errorf("pubsub/transport/eth: %s has no destination address", c.cfg.URL)
	}
	if len(payload) > c.maxSize {
		return fmt.Errorf("%w: %d bytes, limit %d", transport.ErrMessageTooLarge, len(payload), c.maxSize)
	}
	frame := make([]byte, len(c.header)+len(payload))
	copy(frame, c.header)
	copy(frame[len(c.header):], payload)
	dl, _ := ctx.Deadline()
	if err := c.send.write(frame, dl); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return transport.ErrClosed
		}
		return fmt.Errorf("pubsub/transport/eth: send to %s on %s: %w", c.addr, c.ifi.Name, err)
	}
	return nil
}

// Subscribe delivers every NetworkMessage received on the connection's
// interface and address to h. topic and qos are ignored. The first
// Subscribe opens the receiving link and joins the multicast group; an
// error doing so is returned here.
func (c *Conn) Subscribe(ctx context.Context, _ string, _ byte, h transport.Handler) (func() error, error) {
	if h == nil {
		return nil, errors.New("pubsub/transport/eth: nil handler")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, transport.ErrClosed
	}
	if c.recv == nil {
		cfg := linkConfig{ifi: c.ifi, recv: true, loopback: c.loop}
		if c.group {
			cfg.group = c.addr.MAC
		}
		l, err := openLink(cfg)
		if err != nil {
			return nil, err
		}
		c.recv = l
		c.handlers = map[uint64]transport.Handler{}
		c.wg.Add(1)
		go c.receive(l)
	}
	id := c.nextID
	c.nextID++
	c.handlers[id] = h
	var once sync.Once
	return func() error {
		once.Do(func() {
			c.mu.Lock()
			delete(c.handlers, id)
			c.mu.Unlock()
		})
		return nil
	}, nil
}

func (c *Conn) receive(l link) {
	defer c.wg.Done()
	c.recvID.Store(goid.ID())
	buf := make([]byte, readBuffer)
	var hs []transport.Handler
	for {
		n, outgoing, err := l.read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || c.isClosed() {
				return
			}
			// An unexpected error (the interface went down): do not spin.
			c.log.Debug("pubsub/transport/eth: receive", "error", err)
			time.Sleep(errorBackoff)
			continue
		}
		f, err := parseFrame(buf[:n])
		if err != nil {
			c.log.Debug("pubsub/transport/eth: dropping frame", "reason", err, "size", n)
			continue
		}
		if !c.accept(f, outgoing) {
			continue
		}
		if len(f.payload) > c.maxSize {
			c.log.Debug("pubsub/transport/eth: dropping oversized frame", "size", len(f.payload), "from", FormatMAC(f.src))
			continue
		}
		msg := &transport.Message{
			Payload:  append([]byte(nil), f.payload...),
			Source:   f.source(),
			Received: time.Now(),
		}
		c.mu.Lock()
		hs = hs[:0]
		for _, h := range c.handlers {
			hs = append(hs, h)
		}
		c.mu.Unlock()
		for i, h := range hs {
			m := msg
			if i > 0 { // each subscriber owns its payload
				cp := *msg
				cp.Payload = append([]byte(nil), msg.Payload...)
				m = &cp
			}
			h(m)
		}
	}
}

// accept reports whether a received frame is for this connection: sent to
// the interface's address, the broadcast address or the joined group. A
// frame this host sent is accepted with loopback only, and never on a
// loopback interface, which delivers it a second time as received.
func (c *Conn) accept(f frame, outgoing bool) bool {
	if outgoing && (!c.loop || c.ifi.Flags&net.FlagLoopback != 0) {
		return false
	}
	switch {
	case string(f.dst) == string(c.mac), isBroadcast(f.dst):
		return true
	case !isMulticast(f.dst):
		// Without the MAC address (macOS, unprivileged) every unicast
		// frame the interface delivers is accepted.
		return !c.ownMAC
	case c.group:
		return string(f.dst) == string(c.addr.MAC)
	}
	return false
}

func (c *Conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// MaxMessageSize is the largest payload Send accepts.
func (c *Conn) MaxMessageSize() int { return c.maxSize }

// LocalAddr returns the address of the interface: its MAC address and the
// VLAN tag of the URL.
func (c *Conn) LocalAddr() net.Addr {
	return Address{MAC: append(net.HardwareAddr(nil), c.mac...), VLAN: c.addr.VLAN, VID: c.addr.VID, PCP: c.addr.PCP}
}

// Close closes the links, leaves the multicast group and waits for the
// receive goroutine to end (unless it is called from a handler, which runs
// on that goroutine).
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	recv := c.recv
	c.mu.Unlock()
	var errs []error
	if c.send != nil {
		errs = append(errs, c.send.close())
	}
	if recv != nil {
		errs = append(errs, recv.close())
	}
	if goid.ID() != c.recvID.Load() {
		c.wg.Wait()
	}
	return errors.Join(errs...)
}
