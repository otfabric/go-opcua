// SPDX-License-Identifier: MIT

package websocket

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/leakcheck"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) { leakcheck.Main(m) }

// memConn is a net.Conn that reads from r and records what is written.
type memConn struct {
	r  io.Reader
	mu sync.Mutex
	w  bytes.Buffer
}

func (c *memConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *memConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.w.Write(p)
}
func (c *memConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.w.Bytes())
}
func (c *memConn) Close() error                     { return nil }
func (c *memConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

// serverReading returns a server side Conn that reads data.
func serverReading(data []byte, maxFrame int64) (*Conn, *memConn) {
	mc := &memConn{r: bytes.NewReader(data)}
	return newConn(mc, bufio.NewReader(mc), false, SubprotocolUACPForTest, maxFrame), mc
}

const SubprotocolUACPForTest = "opcua+uacp"

// frame builds a raw frame. A mask of nil means unmasked.
func frame(first byte, payload []byte, mask []byte) []byte {
	var b []byte
	b = append(b, first)
	m := byte(0)
	if mask != nil {
		m = 0x80
	}
	switch n := len(payload); {
	case n <= 125:
		b = append(b, m|byte(n))
	case n <= 0xffff:
		b = append(b, m|126)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, m|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	if mask == nil {
		return append(b, payload...)
	}
	b = append(b, mask...)
	for i, x := range payload {
		b = append(b, x^mask[i%4])
	}
	return b
}

var key = []byte{1, 2, 3, 4}

// closeCode returns the status code of the Close frame a server wrote.
func closeCode(t *testing.T, w []byte) int {
	t.Helper()
	i := bytes.LastIndexByte(w, 0x80|opClose)
	require.GreaterOrEqual(t, i, 0, "no close frame in %x", w)
	require.Equal(t, byte(2), w[i+1])
	return int(binary.BigEndian.Uint16(w[i+2:]))
}

func TestReadFrames(t *testing.T) {
	big := bytes.Repeat([]byte{0xab}, 70000)
	mid := bytes.Repeat([]byte{0xcd}, 300)
	var in []byte
	in = append(in, frame(0x80|opBinary, []byte("hello"), key)...)
	in = append(in, frame(0x80|opBinary, nil, key)...)                  // empty message
	in = append(in, frame(opBinary, []byte("frag"), key)...)            // first fragment
	in = append(in, frame(0x80|opPing, []byte("p"), key)...)            // control between fragments
	in = append(in, frame(0x80|opPong, nil, key)...)                    // ignored
	in = append(in, frame(0x80|opContinuation, []byte("ment"), key)...) // last fragment
	in = append(in, frame(0x80|opBinary, mid, key)...)
	in = append(in, frame(0x80|opBinary, big, key)...)
	in = append(in, frame(0x80|opClose, binary.BigEndian.AppendUint16(nil, 1001), key)...)

	c, mc := serverReading(in, 0)
	got, err := io.ReadAll(c)
	require.NoError(t, err, "a close frame ends the stream like EOF")
	want := append(append([]byte("hellofragment"), mid...), big...)
	require.Equal(t, want, got)

	// The ping was answered with a pong carrying its payload, the close with
	// a close carrying the same code; server frames are not masked.
	w := mc.written()
	require.True(t, bytes.HasPrefix(w, []byte{0x80 | opPong, 1, 'p'}), "%x", w)
	require.Equal(t, 1001, closeCode(t, w))

	_, err = c.Read(make([]byte, 1))
	require.Equal(t, io.EOF, err)
	require.Equal(t, 1001, c.CloseCode())

	n, err := c.Read(nil)
	require.Zero(t, n)
	require.Error(t, err)
}

func TestReadZeroLengthBuffer(t *testing.T) {
	c, _ := serverReading(frame(0x80|opBinary, []byte("x"), key), 0)
	n, err := c.Read(nil)
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestReadCloseWithoutCode(t *testing.T) {
	c, mc := serverReading(frame(0x80|opClose, nil, key), 0)
	_, err := c.Read(make([]byte, 4))
	require.Equal(t, io.EOF, err)
	require.Equal(t, 1005, c.CloseCode())
	require.Equal(t, CloseNormal, closeCode(t, mc.written()))
}

func TestReadProtocolErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		code int
		err  error
	}{
		{"rsv bits", frame(0x80|0x40|opBinary, []byte("x"), key), CloseProtocolError, ErrProtocol},
		{"unmasked client frame", frame(0x80|opBinary, []byte("x"), nil), CloseProtocolError, ErrProtocol},
		{"text", frame(0x80|opText, []byte("x"), key), CloseUnsupportedData, ErrUnsupportedData},
		{"reserved data opcode", frame(0x80|0x3, []byte("x"), key), CloseProtocolError, ErrProtocol},
		{"reserved control opcode", frame(0x80|0xB, nil, key), CloseProtocolError, ErrProtocol},
		{"continuation first", frame(0x80|opContinuation, []byte("x"), key), CloseProtocolError, ErrProtocol},
		{"binary inside fragmented", append(frame(opBinary, []byte("x"), key), frame(0x80|opBinary, []byte("y"), key)...), CloseProtocolError, ErrProtocol},
		{"fragmented control", frame(opPing, nil, key), CloseProtocolError, ErrProtocol},
		{"long control", frame(0x80|opPing, bytes.Repeat([]byte{1}, 126), key), CloseProtocolError, ErrProtocol},
		{"one byte close", frame(0x80|opClose, []byte{1}, key), CloseProtocolError, ErrProtocol},
		{"too large", frame(0x80|opBinary, bytes.Repeat([]byte{1}, 200), key), CloseMessageTooBig, ErrFrameTooLarge},
		{"huge length", append([]byte{0x80 | opBinary, 0x80 | 127, 0x80, 0, 0, 0, 0, 0, 0, 0}, key...), CloseProtocolError, ErrProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, mc := serverReading(tt.in, 100)
			_, err := io.ReadAll(c)
			require.ErrorIs(t, err, tt.err)
			require.Equal(t, tt.code, closeCode(t, mc.written()))
			// sticky
			_, err2 := c.Read(make([]byte, 1))
			require.Equal(t, err, err2)
		})
	}
}

func TestReadTruncated(t *testing.T) {
	full := frame(0x80|opBinary, bytes.Repeat([]byte{7}, 300), key)
	for _, n := range []int{1, 3, 5, 9, 20} {
		c, _ := serverReading(full[:n], 0)
		_, err := io.ReadAll(c)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF, "cut at %d", n)
	}
	ping := frame(0x80|opPing, []byte("abc"), key)
	c, _ := serverReading(ping[:len(ping)-1], 0)
	_, err := io.ReadAll(c)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)

	long := frame(0x80|opBinary, bytes.Repeat([]byte{7}, 70000), key)
	c, _ = serverReading(long[:5], 0)
	_, err = io.ReadAll(c)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)

	// clean EOF between frames
	c, _ = serverReading(nil, 0)
	_, err = c.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

func TestClientRejectsMaskedServerFrame(t *testing.T) {
	mc := &memConn{r: bytes.NewReader(frame(0x80|opBinary, []byte("x"), key))}
	c := newConn(mc, bufio.NewReader(mc), true, "", 0)
	_, err := c.Read(make([]byte, 4))
	require.ErrorIs(t, err, ErrProtocol)
}

func TestWriteFraming(t *testing.T) {
	for _, n := range []int{0, 5, 125, 126, 65535, 65536} {
		payload := bytes.Repeat([]byte{0x5a}, n)

		// server: unmasked
		mc := &memConn{r: bytes.NewReader(nil)}
		s := newConn(mc, bufio.NewReader(mc), false, "", 0)
		w, err := s.Write(payload)
		require.NoError(t, err)
		require.Equal(t, n, w)
		cl := newConn(&memConn{r: bytes.NewReader(mc.written())}, nil, true, "", 0)
		cl.br = bufio.NewReader(cl.nc)
		got := make([]byte, n)
		_, err = io.ReadFull(cl, got)
		require.NoError(t, err)
		require.Equal(t, payload, got)

		// client: masked, decoded by a server
		mc2 := &memConn{r: bytes.NewReader(nil)}
		c := newConn(mc2, bufio.NewReader(mc2), true, "", 0)
		_, err = c.Write(payload)
		require.NoError(t, err)
		require.NotZero(t, mc2.written()[1]&0x80, "client frames are masked")
		srv, _ := serverReading(mc2.written(), 0)
		_, err = io.ReadFull(srv, got)
		require.NoError(t, err)
		require.Equal(t, payload, got)
	}
}

func TestWriteAfterClose(t *testing.T) {
	mc := &memConn{r: bytes.NewReader(nil)}
	c := newConn(mc, bufio.NewReader(mc), false, "", 0)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close(), "idempotent")
	require.Equal(t, CloseNormal, closeCode(t, mc.written()))
	_, err := c.Write([]byte("x"))
	require.ErrorIs(t, err, net.ErrClosed)
}

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		ch <- c
	}()
	a, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	b := <-ch
	require.NotNil(t, b)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestHandshakeAndEcho(t *testing.T) {
	a, b := tcpPair(t)
	type res struct {
		c   *Conn
		req *http.Request
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, req, err := Accept(b, ServerOptions{Subprotocols: []string{"opcua+uacp"}})
		ch <- res{c, req, err}
	}()
	u, _ := url.Parse("wss://example.com:4843/ua/server?x=1")
	cc, err := Client(context.Background(), a, u, ClientOptions{
		Subprotocols: []string{"opcua+uajson", "opcua+uacp"},
		Header:       http.Header{"Origin": {"https://example.com"}},
	})
	require.NoError(t, err)
	r := <-ch
	require.NoError(t, r.err)
	require.Equal(t, "/ua/server?x=1", r.req.RequestURI)
	require.Equal(t, "https://example.com", r.req.Header.Get("Origin"))
	require.Equal(t, "opcua+uacp", cc.Subprotocol())
	require.Equal(t, "opcua+uacp", r.c.Subprotocol())
	require.Equal(t, a, cc.NetConn())
	require.NotNil(t, cc.LocalAddr())
	require.NotNil(t, cc.RemoteAddr())
	require.NoError(t, cc.SetDeadline(time.Time{}))
	require.NoError(t, cc.SetReadDeadline(time.Time{}))
	require.NoError(t, cc.SetWriteDeadline(time.Time{}))

	msg := bytes.Repeat([]byte("chunk"), 1000)
	go func() { _, _ = cc.Write(msg) }()
	got := make([]byte, len(msg))
	_, err = io.ReadFull(r.c, got)
	require.NoError(t, err)
	require.Equal(t, msg, got)

	go func() { _, _ = r.c.Write([]byte("back")) }()
	got = make([]byte, 4)
	_, err = io.ReadFull(cc, got)
	require.NoError(t, err)
	require.Equal(t, "back", string(got))

	// The client closes: the server sees the close, answers it, and the
	// client's next read sees the answer.
	require.NoError(t, cc.Close())
	_, err = r.c.Read(got)
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, r.c.Close())
}

// serve answers the handshake request on b with resp, after reading the
// request.
func serveRaw(t *testing.T, b net.Conn, resp func(key string) string) {
	t.Helper()
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(b))
		if err != nil {
			return
		}
		_, _ = io.WriteString(b, resp(req.Header.Get("Sec-WebSocket-Key")))
	}()
}

func TestClientHandshakeFailures(t *testing.T) {
	ok := func(key, proto string) string {
		s := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acceptKey(key) + "\r\n"
		if proto != "" {
			s += "Sec-WebSocket-Protocol: " + proto + "\r\n"
		}
		return s + "\r\n"
	}
	tests := []struct {
		name string
		resp func(string) string
	}{
		{"status", func(string) string { return "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n" }},
		{"garbage", func(string) string { return "garbage\r\n\r\n" }},
		{"no upgrade", func(k string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: " + acceptKey(k) + "\r\n\r\n"
		}},
		{"wrong accept", func(string) string { return ok("AAAAAAAAAAAAAAAAAAAAAA==", "opcua+uacp") }},
		{"no subprotocol", func(k string) string { return ok(k, "") }},
		{"other subprotocol", func(k string) string { return ok(k, "chat") }},
		{"huge header", func(string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nX: " + strings.Repeat("a", 2*maxHandshakeSize) + "\r\n\r\n"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := tcpPair(t)
			serveRaw(t, b, tt.resp)
			u, _ := url.Parse("wss://h/")
			_, err := Client(context.Background(), a, u, ClientOptions{Subprotocols: []string{"opcua+uacp"}})
			require.ErrorIs(t, err, ErrHandshake)
		})
	}
}

func TestClientHandshakeContext(t *testing.T) {
	a, _ := tcpPair(t) // the peer never answers
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	u, _ := url.Parse("wss://h")
	go func() {
		_, err := Client(ctx, a, u, ClientOptions{})
		errc <- err
	}()
	cancel()
	require.ErrorIs(t, <-errc, context.Canceled)

	a2, _ := tcpPair(t)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel2()
	_, err := Client(ctx2, a2, u, ClientOptions{})
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// a closed connection fails the request write
	a3, _ := tcpPair(t)
	_ = a3.Close()
	_, err = Client(context.Background(), a3, u, ClientOptions{})
	require.Error(t, err)
}

func TestAcceptFailures(t *testing.T) {
	good := "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEA==\r\nSec-WebSocket-Protocol: opcua+uacp\r\n\r\n"
	tests := []struct {
		name   string
		req    string
		status string
	}{
		{"garbage", "\x00\x01\x02\r\n\r\n", "400"},
		{"post", strings.Replace(good, "GET", "POST", 1), "405"},
		{"http/1.0", strings.Replace(good, "HTTP/1.1", "HTTP/1.0", 1), "400"},
		{"no upgrade", strings.Replace(good, "Upgrade: websocket\r\n", "", 1), "426"},
		{"version", strings.Replace(good, "Version: 13", "Version: 8", 1), "426"},
		{"key", strings.Replace(good, "AQIDBAUGBwgJCgsMDQ4PEA==", "short", 1), "400"},
		{"subprotocol", strings.Replace(good, "opcua+uacp", "chat", 1), "400"},
		{"huge", "GET / HTTP/1.1\r\nX: " + strings.Repeat("a", 2*maxHandshakeSize) + "\r\n\r\n", "400"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &memConn{r: strings.NewReader(tt.req)}
			_, _, err := Accept(mc, ServerOptions{Subprotocols: []string{"opcua+uacp"}})
			require.ErrorIs(t, err, ErrHandshake)
			require.True(t, strings.HasPrefix(string(mc.written()), "HTTP/1.1 "+tt.status), "%q", mc.written())
		})
	}

	// Without sub-protocols configured, any request is accepted and no
	// sub-protocol selected.
	mc := &memConn{r: strings.NewReader(good)}
	c, _, err := Accept(mc, ServerOptions{})
	require.NoError(t, err)
	require.Equal(t, "", c.Subprotocol())
	require.NotContains(t, string(mc.written()), "Sec-WebSocket-Protocol")
}

type failWriter struct{ memConn }

func (*failWriter) Write([]byte) (int, error) { return 0, errors.New("broken") }

func TestAcceptWriteFails(t *testing.T) {
	good := "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEA==\r\n\r\n"
	fw := &failWriter{memConn{r: strings.NewReader(good)}}
	_, _, err := Accept(fw, ServerOptions{})
	require.Error(t, err)

	// a ping cannot be answered: the read fails
	fw2 := &failWriter{memConn{r: bytes.NewReader(frame(0x80|opPing, nil, key))}}
	c := newConn(fw2, bufio.NewReader(fw2), false, "", 0)
	_, err = c.Read(make([]byte, 1))
	require.Error(t, err)
}
