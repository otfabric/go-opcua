// SPDX-License-Identifier: MIT

package testutil

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Direction identifies one of the two byte streams of a proxied connection.
type Direction int

const (
	// ClientToServer is the stream of bytes written by the client.
	ClientToServer Direction = iota
	// ServerToClient is the stream of bytes written by the server.
	ServerToClient
)

func (d Direction) String() string {
	if d == ClientToServer {
		return "client->server"
	}
	return "server->client"
}

// ChaosProxy is a fault-injecting TCP forwarder that sits between a client and
// a server. Tests dial the proxy instead of the server and then drive faults
// through the proxy's methods. All faults can be combined and are cleared
// again with [ChaosProxy.Heal].
//
// Supported faults:
//
//   - DropAll: abortive close (RST) of every proxied connection
//   - HalfClose: FIN in one direction only
//   - SetBlackhole: accept bytes in one direction but never deliver them
//   - SetStall: stop reading one direction so that the sender's writes block
//   - SetLatency: fixed delay plus uniformly distributed jitter per write
//   - SetFragment / SetThrottle: deliver the stream in tiny pieces and/or at a
//     limited byte rate to stress message reassembly
//   - TruncateNext: deliver only the first n bytes of a stream, then reset
//   - SetCorruption / CorruptNext: flip random bits
//   - SetMangle: rewrite the forwarded bytes with a custom function
//   - SetFrameMangle: drop, repeat, reorder or rewrite whole UACP messages
//   - SetRefuse: reset every new connection ("server down")
//   - SetBackend: retarget new connections (server restarted elsewhere)
//
// Every random decision is drawn from a single generator seeded at
// construction, so a fault schedule is reproducible from its seed up to the
// scheduling of the goroutines that drive the traffic.
type ChaosProxy struct {
	ln net.Listener

	mu      sync.Mutex
	rng     *rand.Rand
	backend string
	links   map[*chaosLink]struct{}
	closed  bool

	refuse atomic.Bool

	dirs [2]chaosDirState

	latency  atomic.Int64 // time.Duration
	jitter   atomic.Int64 // time.Duration
	fragment atomic.Int64 // max bytes per write; 0 = unlimited
	throttle atomic.Int64 // bytes per second; 0 = unlimited

	accepted atomic.Int64
	wg       sync.WaitGroup
}

type chaosDirState struct {
	blackhole   atomic.Bool
	stall       atomic.Bool
	corruptPPM  atomic.Int64 // probability per forwarded read, parts per million
	corruptNext atomic.Int64 // number of pending one-shot corruptions
	truncate    atomic.Int64 // bytes to still deliver before reset; <0 = disarmed
	mangle      atomic.Pointer[func([]byte) []byte]
	frameMangle atomic.Pointer[func([]byte) [][]byte]
}

// NewChaosProxy starts a proxy on an ephemeral localhost port which forwards
// to backend ("host:port"). backend may be empty and set later with
// SetBackend. The proxy is closed automatically when the test ends.
func NewChaosProxy(t testing.TB, backend string, seed int64) *ChaosProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testutil: chaos proxy listen: %v", err)
	}
	p := &ChaosProxy{
		ln:      ln,
		rng:     rand.New(rand.NewSource(seed)),
		backend: backend,
		links:   make(map[*chaosLink]struct{}),
	}
	for i := range p.dirs {
		p.dirs[i].truncate.Store(-1)
	}
	p.wg.Add(1)
	go p.acceptLoop()
	t.Cleanup(p.Close)
	return p
}

// Addr returns the proxy's listen address as "host:port".
func (p *ChaosProxy) Addr() string { return p.ln.Addr().String() }

// Port returns the proxy's listen port.
func (p *ChaosProxy) Port() int { return p.ln.Addr().(*net.TCPAddr).Port }

// EndpointURL returns the opc.tcp URL clients should dial. The host is
// "localhost" so that it matches servers created with EndPoint("localhost", …).
func (p *ChaosProxy) EndpointURL() string {
	return fmt.Sprintf("opc.tcp://localhost:%d", p.Port())
}

// SetBackend changes the address new connections are forwarded to. Existing
// connections are not affected.
func (p *ChaosProxy) SetBackend(addr string) {
	p.mu.Lock()
	p.backend = addr
	p.mu.Unlock()
}

// Accepted returns the number of connections accepted so far.
func (p *ChaosProxy) Accepted() int64 { return p.accepted.Load() }

// ActiveLinks returns the number of currently proxied connections.
func (p *ChaosProxy) ActiveLinks() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.links)
}

// DropAll abortively closes (RST) every proxied connection. New connections
// are still accepted.
func (p *ChaosProxy) DropAll() {
	for _, l := range p.snapshot() {
		l.reset()
	}
}

// HalfClose sends a FIN in the given direction on every proxied connection:
// the receiver of that direction sees EOF while the opposite direction keeps
// flowing.
func (p *ChaosProxy) HalfClose(d Direction) {
	for _, l := range p.snapshot() {
		l.halfClose(d)
	}
}

// SetBlackhole makes the proxy swallow all bytes flowing in direction d (the
// sender's writes still succeed) when on is true.
func (p *ChaosProxy) SetBlackhole(d Direction, on bool) { p.dirs[d].blackhole.Store(on) }

// SetStall stops the proxy from reading the bytes flowing in direction d
// while on is true. Unlike a blackhole nothing is lost: the data backs up in
// the socket buffers until the sender's writes block, as with a peer that
// has stopped reading. Forwarding continues when the stall is lifted.
func (p *ChaosProxy) SetStall(d Direction, on bool) { p.dirs[d].stall.Store(on) }

// SetLatency delays every forwarded write by d plus a uniformly distributed
// random duration in [0, jitter).
func (p *ChaosProxy) SetLatency(d, jitter time.Duration) {
	p.latency.Store(int64(d))
	p.jitter.Store(int64(jitter))
}

// SetFragment limits every forwarded write to at most n bytes so that
// messages arrive split across many TCP segments. n == 1 delivers the stream
// one byte at a time. Zero disables fragmentation.
func (p *ChaosProxy) SetFragment(n int) { p.fragment.Store(int64(n)) }

// SetThrottle limits the forwarding rate to roughly bytesPerSec in each
// direction of each connection. Zero disables throttling.
func (p *ChaosProxy) SetThrottle(bytesPerSec int) { p.throttle.Store(int64(bytesPerSec)) }

// TruncateNext arms a one-shot truncation: the next connection that carries
// data in direction d delivers only the next n bytes and is then reset, which
// cuts a message in the middle.
func (p *ChaosProxy) TruncateNext(d Direction, n int) { p.dirs[d].truncate.Store(int64(n)) }

// SetCorruption flips one random bit in a forwarded read of direction d with
// the given probability (0 disables).
func (p *ChaosProxy) SetCorruption(d Direction, probability float64) {
	p.dirs[d].corruptPPM.Store(int64(probability * 1e6))
}

// CorruptNext flips one random bit in each of the next n forwarded reads of
// direction d.
func (p *ChaosProxy) CorruptNext(d Direction, n int) { p.dirs[d].corruptNext.Store(int64(n)) }

// SetMangle installs a function that may rewrite every chunk of bytes
// forwarded in direction d (nil removes it). It is the tool for targeted
// corruption, for example altering one specific field of one specific
// message. fn is called from the proxy's goroutines, may modify its argument
// in place, and returns the bytes to forward. A chunk is whatever one read
// from the socket returned, so a message may span several chunks.
func (p *ChaosProxy) SetMangle(d Direction, fn func([]byte) []byte) {
	if fn == nil {
		p.dirs[d].mangle.Store(nil)
		return
	}
	p.dirs[d].mangle.Store(&fn)
}

// SetFrameMangle installs a function that sees every complete UACP message
// (HEL, ACK, ERR, RHE, OPN, MSG, CLO: an 8 byte header with the message size,
// then the body) forwarded in direction d and returns the messages to forward
// in its place (nil removes the function). Returning nothing drops the
// message while the connection stays up, returning it twice replays it, and a
// function that keeps a message and returns it with a later one reorders the
// stream or moves a message to another connection. fn is called from the
// proxy's goroutines for all connections, owns its argument and may modify
// it in place.
//
// While a function is installed the proxy reassembles the stream of each
// connection into messages, so a message is only forwarded once it is
// complete. Bytes that do not look like a UACP message are forwarded as they
// are.
func (p *ChaosProxy) SetFrameMangle(d Direction, fn func(msg []byte) [][]byte) {
	if fn == nil {
		p.dirs[d].frameMangle.Store(nil)
		return
	}
	p.dirs[d].frameMangle.Store(&fn)
}

// SetRefuse makes the proxy reset every new connection immediately while on
// is true, as if the server were down. Existing connections are not affected;
// combine with DropAll to simulate a crash.
func (p *ChaosProxy) SetRefuse(on bool) { p.refuse.Store(on) }

// Heal clears every standing fault (blackhole, stall, latency, fragmentation,
// throttling, corruption, mangling, truncation, refusal). It does not restore
// connections that were dropped, and bytes that were swallowed stay lost.
func (p *ChaosProxy) Heal() {
	p.refuse.Store(false)
	p.latency.Store(0)
	p.jitter.Store(0)
	p.fragment.Store(0)
	p.throttle.Store(0)
	for i := range p.dirs {
		p.dirs[i].blackhole.Store(false)
		p.dirs[i].stall.Store(false)
		p.dirs[i].corruptPPM.Store(0)
		p.dirs[i].corruptNext.Store(0)
		p.dirs[i].truncate.Store(-1)
		p.dirs[i].mangle.Store(nil)
		p.dirs[i].frameMangle.Store(nil)
	}
}

// Close stops the proxy and resets all connections. It waits for all proxy
// goroutines to exit.
func (p *ChaosProxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()

	_ = p.ln.Close()
	p.DropAll()
	p.wg.Wait()
}

func (p *ChaosProxy) snapshot() []*chaosLink {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*chaosLink, 0, len(p.links))
	for l := range p.links {
		out = append(out, l)
	}
	return out
}

// randInt63n draws from the seeded generator.
func (p *ChaosProxy) randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Int63n(n)
}

func (p *ChaosProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.accepted.Add(1)
		if p.refuse.Load() {
			abort(c)
			continue
		}
		p.wg.Add(1)
		go p.serve(c)
	}
}

func (p *ChaosProxy) serve(client net.Conn) {
	defer p.wg.Done()

	p.mu.Lock()
	backend := p.backend
	closed := p.closed
	p.mu.Unlock()
	if closed || backend == "" {
		abort(client)
		return
	}

	server, err := net.DialTimeout("tcp", backend, 10*time.Second)
	if err != nil {
		abort(client)
		return
	}

	l := &chaosLink{p: p, client: client, server: server, done: make(chan struct{})}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		l.reset()
		return
	}
	p.links[l] = struct{}{}
	p.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); l.pump(ClientToServer, client, server) }()
	go func() { defer wg.Done(); l.pump(ServerToClient, server, client) }()
	wg.Wait()

	// Both directions have finished: release the sockets.
	_ = client.Close()
	_ = server.Close()

	p.mu.Lock()
	delete(p.links, l)
	p.mu.Unlock()
}

// chaosLink is one proxied client<->server connection pair.
type chaosLink struct {
	p      *ChaosProxy
	client net.Conn
	server net.Conn

	once sync.Once
	done chan struct{}
}

// reset abortively closes both sides of the link.
func (l *chaosLink) reset() {
	l.once.Do(func() { close(l.done) })
	abort(l.client)
	abort(l.server)
}

func (l *chaosLink) halfClose(d Direction) {
	dst := l.server
	if d == ServerToClient {
		dst = l.client
	}
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// sleep waits for d or until the link is reset. It reports false when the
// link was reset.
func (l *chaosLink) sleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-l.done:
		return false
	case <-t.C:
		return true
	}
}

// pump copies src to dst applying the proxy's current faults for direction d.
func (l *chaosLink) pump(d Direction, src, dst net.Conn) {
	p := l.p
	st := &p.dirs[d]
	buf := make([]byte, 32*1024)
	var pending []byte // bytes of an incomplete message, see SetFrameMangle

	for {
		for st.stall.Load() {
			if !l.sleep(2 * time.Millisecond) {
				return
			}
		}
		n, err := src.Read(buf)
		// A stall that began while the read was pending holds this chunk too.
		for n > 0 && st.stall.Load() {
			if !l.sleep(2 * time.Millisecond) {
				return
			}
		}
		if n > 0 {
			b := buf[:n]

			// one-shot truncation: forward a prefix, then cut the link.
			if rem := st.truncate.Load(); rem >= 0 && st.truncate.CompareAndSwap(rem, -1) {
				if int64(len(b)) > rem {
					b = b[:rem]
				}
				if len(b) > 0 && !st.blackhole.Load() {
					_, _ = dst.Write(b)
				}
				l.reset()
				return
			}

			if fm := st.frameMangle.Load(); fm != nil || len(pending) > 0 {
				pending = append(pending, b...)
				if fm == nil {
					b, pending = pending, nil
				} else {
					b, pending = reframe(pending, *fm)
				}
			}

			if fn := st.mangle.Load(); fn != nil && len(b) > 0 {
				b = (*fn)(b)
			}

			if ppm := st.corruptPPM.Load(); ppm > 0 && p.randInt63n(1e6) < ppm {
				l.flipBit(b)
			} else if st.corruptNext.Load() > 0 && st.corruptNext.Add(-1) >= 0 {
				l.flipBit(b)
			}

			if lat, jit := p.latency.Load(), p.jitter.Load(); lat > 0 || jit > 0 {
				if !l.sleep(time.Duration(lat + p.randInt63n(jit))) {
					return
				}
			}

			if !l.forward(st, dst, b) {
				return
			}
		}
		if err != nil {
			// what is left of a message the sender did not complete
			if len(pending) > 0 && !l.forward(st, dst, pending) {
				return
			}
			// Propagate an orderly EOF as a half close so the peer can
			// still flush its own direction; anything else ends the link.
			if tc, ok := dst.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			return
		}
	}
}

// forward writes b to dst honouring blackhole, fragmentation and throttling.
// It reports false when the link is dead.
func (l *chaosLink) forward(st *chaosDirState, dst net.Conn, b []byte) bool {
	p := l.p
	for len(b) > 0 {
		chunk := b
		frag := p.fragment.Load()
		rate := p.throttle.Load()
		if frag > 0 && int64(len(chunk)) > frag {
			chunk = chunk[:frag]
		}
		if rate > 0 {
			// never send more than ~10ms worth of data in one piece
			if maxPiece := max(rate/100, 1); int64(len(chunk)) > maxPiece {
				chunk = chunk[:maxPiece]
			}
		}
		b = b[len(chunk):]

		if st.blackhole.Load() {
			continue
		}
		if _, err := dst.Write(chunk); err != nil {
			l.reset()
			return false
		}
		if rate > 0 {
			if !l.sleep(time.Duration(int64(len(chunk)) * int64(time.Second) / rate)) {
				return false
			}
		}
	}
	return true
}

// maxFrameSize is the largest message reframe waits for. A size field beyond
// it means that the stream is not (or no longer) UACP framed.
const maxFrameSize = 1 << 24

// reframe cuts the complete UACP messages off the front of stream, passes
// each one to fn and returns the bytes to forward and the incomplete rest.
func reframe(stream []byte, fn func([]byte) [][]byte) (out, rest []byte) {
	upper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	for len(stream) >= 8 {
		size := int(uint32(stream[4]) | uint32(stream[5])<<8 | uint32(stream[6])<<16 | uint32(stream[7])<<24)
		if !upper(stream[0]) || !upper(stream[1]) || !upper(stream[2]) || size < 8 || size > maxFrameSize {
			return append(out, stream...), nil
		}
		if len(stream) < size {
			break
		}
		for _, m := range fn(append([]byte(nil), stream[:size]...)) {
			out = append(out, m...)
		}
		stream = stream[size:]
	}
	if len(stream) == 0 {
		return out, nil
	}
	return out, append([]byte(nil), stream...)
}

func (l *chaosLink) flipBit(b []byte) {
	if len(b) == 0 {
		return
	}
	i := l.p.randInt63n(int64(len(b)))
	bit := l.p.randInt63n(8)
	b[i] ^= 1 << uint(bit)
}

// abort closes c so that the peer observes a connection reset rather than an
// orderly shutdown.
func abort(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}
