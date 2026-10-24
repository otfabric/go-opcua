// SPDX-License-Identifier: MIT

package testutil

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sink is a TCP server that records everything it receives per connection
// and, if echo is set, writes it back.
type sink struct {
	ln   net.Listener
	echo bool

	mu    sync.Mutex
	got   bytes.Buffer    // all connections
	each  []*bytes.Buffer // per connection, in the order they were accepted
	reads int
	eof   atomic.Int32
	conns []net.Conn
}

func newSink(t *testing.T, echo bool) *sink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{ln: ln, echo: echo}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			own := &bytes.Buffer{}
			s.each = append(s.each, own)
			s.mu.Unlock()
			go s.serve(c, own)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	return s
}

func (s *sink) serve(c net.Conn, own *bytes.Buffer) {
	defer func() { _ = c.Close() }()
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.got.Write(buf[:n])
			own.Write(buf[:n])
			s.reads++
			s.mu.Unlock()
			if s.echo {
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				s.eof.Add(1)
			}
			return
		}
	}
}

func (s *sink) received() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.got.Bytes()...)
}

// receivedOn returns what the i-th accepted connection received, nil if
// there is no such connection yet.
func (s *sink) receivedOn(i int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.each) {
		return nil
	}
	return append([]byte(nil), s.each[i].Bytes()...)
}

func (s *sink) readCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func (s *sink) write(t *testing.T, b []byte) {
	t.Helper()
	s.mu.Lock()
	conns := append([]net.Conn(nil), s.conns...)
	s.mu.Unlock()
	for _, c := range conns {
		if _, err := c.Write(b); err != nil {
			t.Fatalf("sink write: %v", err)
		}
	}
}

const proxyWait = 30 * time.Second

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(proxyWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func dialProxy(t *testing.T, p *ChaosProxy) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", p.Addr(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readFull(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(proxyWait))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

func TestChaosProxyForwardsBothDirections(t *testing.T) {
	s := newSink(t, true)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	c := dialProxy(t, p)

	msg := bytes.Repeat([]byte("opcua"), 5000)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, c, len(msg)); !bytes.Equal(got, msg) {
		t.Fatal("echoed data differs")
	}
	if p.Accepted() != 1 || p.ActiveLinks() != 1 {
		t.Fatalf("accepted=%d active=%d, want 1/1", p.Accepted(), p.ActiveLinks())
	}

	_ = c.Close()
	waitFor(t, "link teardown after client close", func() bool { return p.ActiveLinks() == 0 })
}

func TestChaosProxyFragmentAndThrottleKeepDataIntact(t *testing.T) {
	s := newSink(t, true)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	p.SetFragment(1)
	p.SetThrottle(20000)
	c := dialProxy(t, p)

	msg := make([]byte, 300)
	for i := range msg {
		msg[i] = byte(i)
	}
	start := time.Now()
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, c, len(msg)); !bytes.Equal(got, msg) {
		t.Fatal("fragmented data differs")
	}
	// 300 bytes at 20 kB/s take 15ms per direction; the echo overlaps with
	// the request, so the round trip takes at least that (lower bound only).
	if d := time.Since(start); d < 12*time.Millisecond {
		t.Errorf("throttled round trip took only %v", d)
	}
	// byte-wise delivery: the backend needed many reads
	if n := s.readCalls(); n < len(msg)/4 {
		t.Errorf("backend received the data in %d reads, expected fragmentation", n)
	}
}

func TestChaosProxyLatency(t *testing.T) {
	s := newSink(t, true)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	p.SetLatency(40*time.Millisecond, 10*time.Millisecond)
	c := dialProxy(t, p)

	start := time.Now()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	readFull(t, c, 4)
	if d := time.Since(start); d < 80*time.Millisecond {
		t.Errorf("round trip with 40ms latency per direction took only %v", d)
	}
}

func TestChaosProxyBlackhole(t *testing.T) {
	s := newSink(t, false)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	c := dialProxy(t, p)

	// establish the link
	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first byte", func() bool { return len(s.received()) == 1 })

	// client -> server swallowed: the write succeeds, nothing arrives
	p.SetBlackhole(ClientToServer, true)
	if _, err := c.Write([]byte("LOST")); err != nil {
		t.Fatalf("write into blackhole must succeed: %v", err)
	}
	// server -> client still flows
	s.write(t, []byte("ok"))
	if got := readFull(t, c, 2); string(got) != "ok" {
		t.Fatalf("got %q", got)
	}

	// server -> client swallowed as well
	p.SetBlackhole(ServerToClient, true)
	s.write(t, []byte("GONE"))
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, err := c.Read(make([]byte, 8)); n != 0 || err == nil {
		t.Fatalf("read through blackhole returned n=%d err=%v", n, err)
	}

	// healed: new data flows, swallowed data stays lost
	p.Heal()
	if _, err := c.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "byte after heal", func() bool { return len(s.received()) == 2 })
	if got := string(s.received()); got != "ab" {
		t.Fatalf("backend received %q, want %q", got, "ab")
	}
	s.write(t, []byte("c"))
	if got := readFull(t, c, 1); string(got) != "c" {
		t.Fatalf("got %q after heal", got)
	}
}

func TestChaosProxyStallBacksUpWithoutLosingData(t *testing.T) {
	s := newSink(t, false)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	c := dialProxy(t, p)
	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first byte", func() bool { return len(s.received()) == 1 })

	p.SetStall(ClientToServer, true)
	// give the pump time to notice the stall before more data arrives
	time.Sleep(50 * time.Millisecond)

	// Keep writing until the socket buffers are full and a write blocks.
	chunk := bytes.Repeat([]byte{0x42}, 64*1024)
	written := 0
	blocked := false
	for i := 0; i < 2000 && !blocked; i++ {
		_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := c.Write(chunk)
		written += n
		if err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				t.Fatalf("write: %v", err)
			}
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("writes never blocked although %d bytes are backed up", written)
	}
	if got := len(s.received()); got != 1 {
		t.Fatalf("backend received %d bytes during the stall, want 1", got)
	}

	// nothing is lost once the stall is lifted
	p.SetStall(ClientToServer, false)
	waitFor(t, "backed up data", func() bool { return len(s.received()) == 1+written })
}

func TestChaosProxyDropAllResetsButKeepsListening(t *testing.T) {
	s := newSink(t, true)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	c := dialProxy(t, p)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	readFull(t, c, 1)

	p.DropAll()
	_ = c.SetReadDeadline(time.Now().Add(proxyWait))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded on a dropped connection")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("dropped connection was not closed")
	}
	waitFor(t, "links gone", func() bool { return p.ActiveLinks() == 0 })

	c2 := dialProxy(t, p)
	if _, err := c2.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, c2, 1); string(got) != "y" {
		t.Fatalf("got %q", got)
	}
}

// TestChaosProxyDropAllWhileConnecting: a connection that the proxy accepted
// but had not yet linked to the backend when DropAll (and a refusal) came is
// reset too. It went on living, and a server the test meant to cut off
// stayed connected (TestChaosReverseConnect, "client unreachable").
func TestChaosProxyDropAllWhileConnecting(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		s := newSink(t, true)
		p := NewChaosProxy(t, s.ln.Addr().String(), 1)
		var once sync.Once
		hook := func() {
			once.Do(func() {
				p.SetRefuse(refuse)
				if !refuse {
					p.DropAll()
				}
			})
		}
		p.beforeLink.Store(&hook)
		c := dialProxy(t, p)
		_, _ = c.Write([]byte("x"))
		_ = c.SetReadDeadline(time.Now().Add(proxyWait))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatalf("refuse %v: read succeeded on a connection dropped while it was set up", refuse)
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("refuse %v: connection dropped while it was set up was not closed", refuse)
		}
		waitFor(t, "links gone", func() bool { return p.ActiveLinks() == 0 })
	}
}

func TestChaosProxyHalfClose(t *testing.T) {
	s := newSink(t, false)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	c := dialProxy(t, p)
	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first byte", func() bool { return len(s.received()) == 1 })

	// FIN towards the client only
	p.HalfClose(ServerToClient)
	_ = c.SetReadDeadline(time.Now().Add(proxyWait))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("client read: %v, want EOF", err)
	}
	// the other direction still works
	if _, err := c.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "byte after half close", func() bool { return string(s.received()) == "ab" })
	if s.eof.Load() != 0 {
		t.Fatal("backend saw EOF although only the client direction was closed")
	}

	// FIN towards the server
	p.HalfClose(ClientToServer)
	waitFor(t, "backend EOF", func() bool { return s.eof.Load() == 1 })
}

func TestChaosProxyTruncateNext(t *testing.T) {
	s := newSink(t, false)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	p.TruncateNext(ClientToServer, 5)
	c := dialProxy(t, p)

	if _, err := c.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "link reset after truncation", func() bool { return p.ActiveLinks() == 0 })
	// The link is reset right behind the prefix, so the backend sees at most
	// the prefix (a reset may discard bytes that were not read yet).
	if got := s.receivedOn(0); len(got) > 5 || !bytes.HasPrefix([]byte("01234"), got) {
		t.Fatalf("backend received %q, want a prefix of %q", got, "01234")
	}
	_ = c.SetReadDeadline(time.Now().Add(proxyWait))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection survived the truncation")
	}

	// one-shot: the next connection is not truncated
	c2 := dialProxy(t, p)
	if _, err := c2.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	// Per connection: the first one's goroutine in the sink may still read
	// its prefix after the second connection's data arrived.
	waitFor(t, "untruncated data", func() bool { return bytes.Equal(s.receivedOn(1), []byte("0123456789")) })
}

// corruptOnce sends msg through a fresh proxy with the given seed and returns
// what the backend received with one corrupted read.
func corruptOnce(t *testing.T, seed int64, msg []byte) []byte {
	t.Helper()
	s := newSink(t, false)
	p := NewChaosProxy(t, s.ln.Addr().String(), seed)
	p.CorruptNext(ClientToServer, 1)
	c := dialProxy(t, p)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "corrupted data", func() bool { return len(s.received()) == len(msg) })
	return s.received()
}

func TestChaosProxyCorruptionFlipsOneBitDeterministically(t *testing.T) {
	msg := bytes.Repeat([]byte{0x00}, 64)

	a := corruptOnce(t, 42, msg)
	bits := 0
	for i := range a {
		for x := a[i] ^ msg[i]; x != 0; x &= x - 1 {
			bits++
		}
	}
	if bits != 1 {
		t.Fatalf("%d bits differ, want exactly 1", bits)
	}

	// same seed, same flip
	if b := corruptOnce(t, 42, msg); !bytes.Equal(a, b) {
		t.Fatal("the same seed produced a different corruption")
	}

	// the probability based variant corrupts as well and can be switched off
	s := newSink(t, false)
	p := NewChaosProxy(t, s.ln.Addr().String(), 7)
	p.SetCorruption(ClientToServer, 1)
	c := dialProxy(t, p)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "data", func() bool { return len(s.received()) == len(msg) })
	if bytes.Equal(s.received(), msg) {
		t.Fatal("SetCorruption(1) did not alter the data")
	}
	p.SetCorruption(ClientToServer, 0)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "more data", func() bool { return len(s.received()) == 2*len(msg) })
	if !bytes.Equal(s.received()[len(msg):], msg) {
		t.Fatal("data altered although corruption was switched off")
	}
}

func TestChaosProxyMangle(t *testing.T) {
	s := newSink(t, false)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	p.SetMangle(ClientToServer, func(b []byte) []byte {
		return bytes.ReplaceAll(b, []byte("None"), []byte("Nope"))
	})
	c := dialProxy(t, p)
	if _, err := c.Write([]byte("policy#None")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "mangled data", func() bool { return len(s.received()) == 11 })
	if got := string(s.received()); got != "policy#Nope" {
		t.Fatalf("backend received %q", got)
	}

	p.SetMangle(ClientToServer, nil)
	if _, err := c.Write([]byte("None")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unmangled data", func() bool { return len(s.received()) == 15 })
	if got := string(s.received()); got != "policy#NopeNone" {
		t.Fatalf("backend received %q", got)
	}
}

// uacpMsg builds a UACP message of the given type with the given body.
func uacpMsg(typ string, body string) []byte {
	b := []byte(typ + "F\x00\x00\x00\x00" + body)
	b[4] = byte(len(b))
	return b
}

func TestChaosProxyFrameMangle(t *testing.T) {
	s := newSink(t, false)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	var held []byte
	p.SetFrameMangle(ClientToServer, func(m []byte) [][]byte {
		switch string(m[8:]) {
		case "drop":
			return nil
		case "twice":
			return [][]byte{m, m}
		case "hold":
			held = m
			return nil
		case "release":
			return [][]byte{m, held}
		case "edit":
			m[len(m)-1] = 'T'
		}
		return [][]byte{m}
	})
	c := dialProxy(t, p)

	var sent, want []byte
	for _, body := range []string{"a", "drop", "twice", "hold", "b", "release", "edit"} {
		sent = append(sent, uacpMsg("MSG", body)...)
	}
	for _, body := range []string{"a", "twice", "twice", "b", "release", "hold", "ediT"} {
		want = append(want, uacpMsg("MSG", body)...)
	}
	// Written in pieces that do not respect the message boundaries, with the
	// start of one more message whose rest follows later.
	tail := uacpMsg("CLO", "late")
	sent = append(sent, tail[:5]...)
	for len(sent) > 0 {
		n := min(7, len(sent))
		if _, err := c.Write(sent[:n]); err != nil {
			t.Fatal(err)
		}
		sent = sent[n:]
	}
	waitFor(t, "mangled messages", func() bool { return len(s.received()) == len(want) })
	if got := s.received(); !bytes.Equal(got, want) {
		t.Fatalf("backend received %q, want %q", got, want)
	}

	// Removing the function releases the incomplete message with the next
	// bytes; what is not UACP framed passes as it is.
	p.SetFrameMangle(ClientToServer, nil)
	rest := append(tail[5:], "not a message"...)
	if _, err := c.Write(rest); err != nil {
		t.Fatal(err)
	}
	want = append(append(want, tail...), "not a message"...)
	waitFor(t, "released message", func() bool { return len(s.received()) == len(want) })
	if got := s.received(); !bytes.Equal(got, want) {
		t.Fatalf("backend received %q, want %q", got, want)
	}

	// Unframed bytes are forwarded while a function is installed, too.
	p.SetFrameMangle(ClientToServer, func(m []byte) [][]byte { return nil })
	if _, err := c.Write([]byte("lowercase is no message type")); err != nil {
		t.Fatal(err)
	}
	want = append(want, "lowercase is no message type"...)
	waitFor(t, "unframed bytes", func() bool { return len(s.received()) == len(want) })
	if got := s.received(); !bytes.Equal(got, want) {
		t.Fatalf("backend received %q, want %q", got, want)
	}
}

func TestChaosProxyRefuseAndRetarget(t *testing.T) {
	a := newSink(t, true)
	b := newSink(t, false)
	p := NewChaosProxy(t, a.ln.Addr().String(), 1)

	// refused: the connection is reset right away
	p.SetRefuse(true)
	requireReset(t, p, "a refused connection")
	if p.ActiveLinks() != 0 {
		t.Fatal("a refused connection created a link")
	}

	// accepted again
	p.SetRefuse(false)
	c2 := dialProxy(t, p)
	if _, err := c2.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	readFull(t, c2, 1)

	// new connections go to the new backend, existing ones stay
	p.SetBackend(b.ln.Addr().String())
	c3 := dialProxy(t, p)
	if _, err := c3.Write([]byte("to-b")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "data at new backend", func() bool { return string(b.received()) == "to-b" })
	if _, err := c2.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	readFull(t, c2, 1)

	// an unreachable backend refuses
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := deadLn.Addr().String()
	_ = deadLn.Close()
	p.SetBackend(dead)
	requireReset(t, p, "a connection to an unreachable backend")
}

// requireReset dials the proxy and requires the connection to be reset. The
// reset may already surface in the dial itself.
func requireReset(t *testing.T, p *ChaosProxy, what string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", p.Addr(), 10*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(proxyWait))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatalf("read succeeded on %s", what)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s was left open", what)
	}
}

func TestChaosProxyCloseIsIdempotentAndStopsEverything(t *testing.T) {
	s := newSink(t, true)
	p := NewChaosProxy(t, s.ln.Addr().String(), 1)
	c := dialProxy(t, p)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	readFull(t, c, 1)

	p.Close()
	p.Close()
	if p.ActiveLinks() != 0 {
		t.Fatal("links survived Close")
	}
	if _, err := net.DialTimeout("tcp", p.Addr(), time.Second); err == nil {
		t.Fatal("proxy still accepts connections after Close")
	}
}
