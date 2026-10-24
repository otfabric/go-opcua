// SPDX-License-Identifier: MIT

// Package udp is the UDP transport of OPC UA PubSub (Part 14 §7.3.2): UADP
// NetworkMessages in UDP datagrams, unicast or multicast, IPv4 or IPv6.
//
// Importing the package registers the "opc.udp" scheme with
// [transport.Register].
//
// # Addresses
//
// The URL of a connection is opc.udp://host:port; the port is required.
//
//   - A multicast group (opc.udp://239.0.0.1:4840, opc.udp://[ff15::1]:4840)
//     is the destination of Send. Subscribe binds the port on the wildcard
//     address (or Config.ListenAddress) with SO_REUSEADDR and SO_REUSEPORT,
//     so that several subscribers on one host can share it, and joins the
//     group on Config.Interface (the system default if empty). Datagrams
//     are sent with Config.MulticastTTL (default 1) out of Config.Interface,
//     and loop back to this host unless Config.MulticastLoopback is false.
//   - A unicast address is the destination of Send. Subscribe binds that
//     address and port (or Config.ListenAddress), so it must be local.
//   - "localhost" and an empty host (opc.udp://:4840) select the wildcard
//     address for Subscribe ("receive all", as open62541 does); Send to
//     "localhost" goes to 127.0.0.1, an empty host cannot be sent to.
//
// Config.Interface is an interface name ("eth0") or one of its addresses.
// An IPv6 zone in the URL ([ff02::1%eth0]) selects the interface too.
//
// Sending uses its own socket bound to an ephemeral port; the receiving
// socket is opened by the first Subscribe. All subscribers of a connection
// get every datagram the connection receives.
package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/otfabric/go-opcua/internal/goid"
	"github.com/otfabric/go-opcua/pubsub/transport"
)

// Scheme is the URL scheme of the UDP transport.
const Scheme = "opc.udp"

// Largest UDP payloads: 65535 minus the IP and UDP headers.
const (
	MaxDatagramIPv4 = 65507
	MaxDatagramIPv6 = 65527
)

// Socket buffer sizes: the send buffer must hold the largest datagram (on
// macOS it limits the datagram size), the receive buffer absorbs bursts.
const (
	sendBuffer = 128 << 10
	recvBuffer = 1 << 20
)

func init() {
	transport.Register(Scheme, func(ctx context.Context, cfg transport.Config) (transport.Connection, error) {
		return Open(ctx, cfg)
	})
}

// Conn is a UDP PubSub connection.
type Conn struct {
	cfg     transport.Config
	log     *slog.Logger
	dest    netip.AddrPort // invalid: cannot send
	group   bool
	v6      bool
	ifi     *net.Interface
	bind    netip.AddrPort // receive address; unspecified: wildcard
	ttl     int
	loop    bool
	maxSize int

	send *net.UDPConn

	mu       sync.Mutex
	closed   bool
	recv     *net.UDPConn
	handlers map[uint64]transport.Handler
	nextID   uint64
	wg       sync.WaitGroup
	// recvID is the goroutine id of the receive goroutine, so a Close
	// from a handler does not wait for itself.
	recvID atomic.Uint64
}

var _ transport.Connection = (*Conn)(nil)

// Open opens a UDP connection for cfg.URL. It resolves the address and opens
// the sending socket; the receiving socket is opened by Subscribe.
func Open(ctx context.Context, cfg transport.Config) (*Conn, error) {
	host, port, zone, err := parseURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	c := &Conn{cfg: cfg, log: cfg.Logger, ttl: 1, loop: true}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if cfg.MulticastTTL > 0 {
		c.ttl = cfg.MulticastTTL
	}
	if cfg.MulticastLoopback != nil {
		c.loop = *cfg.MulticastLoopback
	}

	// The destination and the receive address.
	var addr netip.Addr
	switch strings.ToLower(host) {
	case "":
	case "localhost":
		addr = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	default:
		if addr, err = resolve(ctx, host); err != nil {
			return nil, err
		}
	}
	addr = addr.Unmap()
	if addr.IsValid() {
		c.dest = netip.AddrPortFrom(addr.WithZone(zone), port)
		c.v6 = addr.Is6()
		c.group = addr.IsMulticast()
	}
	switch {
	case cfg.ListenAddress != "":
		ap, err := parseListenAddress(ctx, cfg.ListenAddress, port)
		if err != nil {
			return nil, err
		}
		c.bind = ap
	case c.group || host == "" || strings.EqualFold(host, "localhost"):
		c.bind = netip.AddrPortFrom(netip.Addr{}, port) // wildcard
		if c.group && !c.v6 {
			c.bind = netip.AddrPortFrom(netip.IPv4Unspecified(), port)
		} else if c.group {
			c.bind = netip.AddrPortFrom(netip.IPv6Unspecified(), port)
		}
	default:
		c.bind = netip.AddrPortFrom(addr.WithZone(zone), port)
	}

	ifName := cfg.Interface
	if ifName == "" {
		ifName = zone
	}
	if ifName != "" {
		if c.ifi, err = findInterface(ifName); err != nil {
			return nil, err
		}
	}

	c.maxSize = cfg.MaxMessageSize
	if c.maxSize <= 0 {
		c.maxSize = MaxDatagramIPv4
		if c.v6 {
			c.maxSize = MaxDatagramIPv6
		}
	}

	if c.dest.IsValid() {
		if c.send, err = c.openSend(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func parseURL(url string) (host string, port uint16, zone string, err error) {
	rest, ok := strings.CutPrefix(url, Scheme+"://")
	if !ok {
		return "", 0, "", fmt.Errorf("pubsub/transport/udp: %q is not an %s:// URL", url, Scheme)
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	h, p, err := net.SplitHostPort(rest)
	if err != nil {
		return "", 0, "", fmt.Errorf("pubsub/transport/udp: %q: %w", url, err)
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, "", fmt.Errorf("pubsub/transport/udp: %q needs a port between 1 and 65535", url)
	}
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h, zone = h[:i], h[i+1:]
	}
	return h, uint16(n), zone, nil
}

func resolve(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("pubsub/transport/udp: resolve %q: %w", host, err)
	}
	for _, a := range addrs { // prefer IPv4
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return addrs[0], nil
}

func parseListenAddress(ctx context.Context, s string, port uint16) (netip.AddrPort, error) {
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		host, p = s, ""
	}
	if p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("pubsub/transport/udp: listen address %q: bad port", s)
		}
		port = uint16(n)
	}
	if host == "" {
		return netip.AddrPortFrom(netip.Addr{}, port), nil
	}
	a, err := resolve(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a.Unmap(), port), nil
}

func findInterface(name string) (*net.Interface, error) {
	if ifi, err := net.InterfaceByName(name); err == nil {
		return ifi, nil
	}
	ip, err := netip.ParseAddr(name)
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/udp: no interface %q", name)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/udp: list interfaces: %w", err)
	}
	for i := range ifs {
		for _, p := range interfaceAddrs(&ifs[i]) {
			if p == ip.Unmap() {
				return &ifs[i], nil
			}
		}
	}
	return nil, fmt.Errorf("pubsub/transport/udp: no interface with address %s", ip)
}

func interfaceAddrs(ifi *net.Interface) []netip.Addr {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// interfaceIPv4 returns the first IPv4 address of the interface, the
// unspecified address for nil.
func interfaceIPv4(ifi *net.Interface) [4]byte {
	if ifi != nil {
		for _, a := range interfaceAddrs(ifi) {
			if a.Is4() {
				return a.As4()
			}
		}
	}
	return [4]byte{}
}

func network(v6 bool) string {
	if v6 {
		return "udp6"
	}
	return "udp4"
}

// openSend opens the sending socket on an ephemeral port.
func (c *Conn) openSend() (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			_ = setBroadcast(fd) // best effort: only needed for broadcast addresses
			_ = growBuffer(fd, soSndBuf, sendBuffer)
			if c.group {
				serr = c.multicastOptions(fd)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	laddr := "0.0.0.0:0"
	if c.v6 {
		laddr = "[::]:0"
	}
	pc, err := lc.ListenPacket(context.Background(), network(c.v6), laddr)
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/udp: open send socket: %w", err)
	}
	return pc.(*net.UDPConn), nil
}

func (c *Conn) multicastOptions(fd uintptr) error {
	if c.ifi != nil {
		if err := setMulticastInterface(fd, c.v6, c.ifi); err != nil {
			return fmt.Errorf("multicast interface %s: %w", c.ifi.Name, err)
		}
	}
	if err := setMulticastTTL(fd, c.v6, c.ttl); err != nil {
		return fmt.Errorf("multicast TTL: %w", err)
	}
	if err := setMulticastLoop(fd, c.v6, c.loop); err != nil {
		return fmt.Errorf("multicast loopback: %w", err)
	}
	return nil
}

// openRecv opens the receiving socket and joins the group.
func (c *Conn) openRecv() (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			serr = setReuse(fd, c.group)
			_ = growBuffer(fd, soRcvBuf, recvBuffer) // best effort, the system may cap it
		})
		if err != nil {
			return err
		}
		return serr
	}}
	netw := "udp"
	if c.bind.Addr().IsValid() {
		netw = network(c.bind.Addr().Is6())
	}
	laddr := net.JoinHostPort("", strconv.Itoa(int(c.bind.Port())))
	if c.bind.Addr().IsValid() {
		laddr = c.bind.String()
	}
	pc, err := lc.ListenPacket(context.Background(), netw, laddr)
	if err != nil {
		return nil, fmt.Errorf("pubsub/transport/udp: bind %s: %w", laddr, err)
	}
	conn := pc.(*net.UDPConn)
	if c.group {
		rc, err := conn.SyscallConn()
		if err == nil {
			var jerr error
			err = rc.Control(func(fd uintptr) { jerr = joinGroup(fd, c.v6, c.dest.Addr(), c.ifi) })
			if err == nil {
				err = jerr
			}
		}
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("pubsub/transport/udp: join %s: %w", c.dest.Addr(), err)
		}
	}
	return conn, nil
}

// Send transmits one datagram to the address of the connection.
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
		return fmt.Errorf("pubsub/transport/udp: %s has no destination address", c.cfg.URL)
	}
	if len(payload) > c.maxSize {
		return fmt.Errorf("%w: %d bytes, limit %d", transport.ErrMessageTooLarge, len(payload), c.maxSize)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.send.SetWriteDeadline(dl)
	} else {
		_ = c.send.SetWriteDeadline(time.Time{})
	}
	if _, err := c.send.WriteToUDPAddrPort(payload, c.dest); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return transport.ErrClosed
		}
		return fmt.Errorf("pubsub/transport/udp: send to %s: %w", c.dest, err)
	}
	return nil
}

// Subscribe delivers every datagram received on the connection's address to
// h. topic and qos are ignored. The first Subscribe opens the receiving
// socket; a bind or join error is returned here.
func (c *Conn) Subscribe(ctx context.Context, _ string, _ byte, h transport.Handler) (func() error, error) {
	if h == nil {
		return nil, errors.New("pubsub/transport/udp: nil handler")
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
		conn, err := c.openRecv()
		if err != nil {
			return nil, err
		}
		c.recv = conn
		c.handlers = map[uint64]transport.Handler{}
		c.wg.Add(1)
		go c.receive(conn)
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

func (c *Conn) receive(conn *net.UDPConn) {
	defer c.wg.Done()
	c.recvID.Store(goid.ID())
	buf := make([]byte, 65536)
	var hs []transport.Handler
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Debug("pubsub/transport/udp: receive", "error", err)
			continue
		}
		if n > c.maxSize {
			c.log.Debug("pubsub/transport/udp: dropping oversized datagram", "size", n, "from", src)
			continue
		}
		msg := &transport.Message{
			Payload:  append([]byte(nil), buf[:n]...),
			Source:   net.UDPAddrFromAddrPort(netip.AddrPortFrom(src.Addr().Unmap(), src.Port())),
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

// MaxMessageSize is the largest payload Send accepts.
func (c *Conn) MaxMessageSize() int { return c.maxSize }

// LocalAddr returns the address of the receiving socket, nil before the
// first Subscribe.
func (c *Conn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recv == nil {
		return nil
	}
	return c.recv.LocalAddr()
}

// Close closes the sockets and waits for the receive goroutine to end
// (unless it is called from a handler, which runs on that goroutine).
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
		errs = append(errs, c.send.Close())
	}
	if recv != nil {
		errs = append(errs, recv.Close())
	}
	if goid.ID() != c.recvID.Load() {
		c.wg.Wait()
	}
	return errors.Join(errs...)
}
