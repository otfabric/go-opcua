// SPDX-License-Identifier: MIT

package uacp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// testWait is the generous bound for things that happen asynchronously.
const testWait = 30 * time.Second

// frame builds a UACP message with the given type ("RHEF", "HELF", ...).
func frame(typ string, body []byte) []byte {
	b := make([]byte, hdrlen, hdrlen+len(body))
	copy(b, typ)
	binary.LittleEndian.PutUint32(b[4:], uint32(hdrlen+len(body)))
	return append(b, body...)
}

// rheFrame builds a ReverseHello message.
func rheFrame(t *testing.T, serverURI, endpoint string) []byte {
	t.Helper()
	body, err := (&ReverseHello{ServerURI: serverURI, EndpointURL: endpoint}).Encode()
	require.NoError(t, err)
	return frame("RHEF", body)
}

// waitFor polls cond until it holds.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s: %s", testWait, msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// testReverseListener opens a listener on loopback that is closed on cleanup.
func testReverseListener(t *testing.T, cfg *ReverseListenerConfig) (*ReverseListener, string) {
	t.Helper()
	l, err := ListenReverse(context.Background(), "127.0.0.1:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l, l.Addr().String()
}

// dialRaw opens a plain TCP connection that is closed on cleanup.
func dialRaw(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, testWait)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// announce opens a connection and sends a ReverseHello message on it.
func announce(t *testing.T, addr, serverURI, endpoint string) net.Conn {
	t.Helper()
	c := dialRaw(t, addr)
	_, err := c.Write(rheFrame(t, serverURI, endpoint))
	require.NoError(t, err)
	return c
}

// readError reads an Error message from c and returns its code.
func readError(t *testing.T, c net.Conn) ua.StatusCode {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(testWait))
	var hdr [hdrlen]byte
	_, err := io.ReadFull(c, hdr[:])
	require.NoError(t, err, "expected an Error message")
	require.Equal(t, "ERRF", string(hdr[:4]))
	body := make([]byte, binary.LittleEndian.Uint32(hdr[4:])-hdrlen)
	_, err = io.ReadFull(c, body)
	require.NoError(t, err)
	var e Error
	_, err = e.Decode(body)
	require.NoError(t, err)
	require.Empty(t, e.Reason, "the reason of a refusal is not disclosed")
	return ua.StatusCode(e.ErrorCode)
}

// requireClosed asserts that the peer closes c without sending anything.
func requireClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(testWait))
	var b [1]byte
	n, err := c.Read(b[:])
	require.Zero(t, n)
	require.Error(t, err)
	var nerr net.Error
	require.False(t, errors.As(err, &nerr) && nerr.Timeout(), "connection was not closed: %v", err)
}

// serverHello answers the Hello of a client on a raw server-side connection
// and returns the endpoint URL the client named.
func serverHello(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(testWait))
	var hdr [hdrlen]byte
	_, err := io.ReadFull(c, hdr[:])
	require.NoError(t, err)
	require.Equal(t, "HELF", string(hdr[:4]))
	body := make([]byte, binary.LittleEndian.Uint32(hdr[4:])-hdrlen)
	_, err = io.ReadFull(c, body)
	require.NoError(t, err)
	var hel Hello
	_, err = hel.Decode(body)
	require.NoError(t, err)
	ack, err := (&Acknowledge{ReceiveBufSize: 8192, SendBufSize: 8192, MaxMessageSize: 1 << 20, MaxChunkCount: 16}).Encode()
	require.NoError(t, err)
	_, err = c.Write(frame("ACKF", ack))
	require.NoError(t, err)
	return hel.EndpointURL
}

func TestReadReverseHello(t *testing.T) {
	long := strings.Repeat("u", MaxReverseHelloURILength)
	str := func(s string) []byte {
		b := make([]byte, 4, 4+len(s))
		binary.LittleEndian.PutUint32(b, uint32(len(s)))
		return append(b, s...)
	}

	t.Run("valid", func(t *testing.T) {
		rhe, err := readReverseHello(bytes.NewReader(rheFrame(t, "urn:server", "opc.tcp://host:4840/path")))
		require.NoError(t, err)
		require.Equal(t, &ReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://host:4840/path"}, rhe)
	})
	t.Run("largest", func(t *testing.T) {
		msg := rheFrame(t, long, long)
		require.Len(t, msg, maxReverseHelloSize)
		rhe, err := readReverseHello(bytes.NewReader(msg))
		require.NoError(t, err)
		require.Equal(t, long, rhe.ServerURI)
		require.Equal(t, long, rhe.EndpointURL)
	})
	t.Run("null strings", func(t *testing.T) {
		rhe, err := readReverseHello(bytes.NewReader(frame("RHEF", bytes.Repeat([]byte{0xff}, 8))))
		require.NoError(t, err)
		require.Equal(t, &ReverseHello{}, rhe)
	})

	for _, tc := range []struct {
		name string
		msg  []byte
		code ua.StatusCode // 0: no Error message is owed (I/O error)
		is   error
	}{
		{name: "empty", msg: nil, is: io.EOF},
		{name: "truncated header", msg: []byte("RHEF\x10"), is: io.ErrUnexpectedEOF},
		{name: "truncated body", msg: rheFrame(t, "urn:server", "opc.tcp://host:4840")[:20], is: io.ErrUnexpectedEOF},
		{name: "hello instead", msg: frame("HELF", make([]byte, 24)), code: ua.StatusBadTCPMessageTypeInvalid, is: errors.ErrInvalidMessageType},
		{name: "secure channel message instead", msg: frame("OPNF", make([]byte, 24)), code: ua.StatusBadTCPMessageTypeInvalid, is: errors.ErrInvalidMessageType},
		{name: "intermediate chunk", msg: frame("RHEC", make([]byte, 8)), code: ua.StatusBadTCPMessageTypeInvalid, is: errors.ErrInvalidMessageType},
		{name: "too small", msg: frame("RHEF", make([]byte, 7)), code: ua.StatusBadTCPInternalError, is: errors.ErrMessageTooSmall},
		{name: "size below header", msg: []byte("RHEF\x04\x00\x00\x00"), code: ua.StatusBadTCPInternalError, is: errors.ErrMessageTooSmall},
		{name: "oversized", msg: append([]byte("RHEF"), 0x11, 0x20, 0x00, 0x00), code: ua.StatusBadTCPMessageTooLarge, is: errors.ErrMessageTooLarge},
		{name: "huge", msg: append([]byte("RHEF"), 0xff, 0xff, 0xff, 0x7f), code: ua.StatusBadTCPMessageTooLarge, is: errors.ErrMessageTooLarge},
		{name: "string longer than message", msg: frame("RHEF", append(str("urn:server"), 0x00, 0x10, 0x00, 0x00)), code: ua.StatusBadTCPInternalError},
		{name: "trailing bytes", msg: frame("RHEF", append(append(str("urn:server"), str("opc.tcp://h:1")...), 1, 2, 3)), code: ua.StatusBadTCPInternalError},
		{name: "server uri too long", msg: frame("RHEF", append(str(long+"x"), str("")...)), code: ua.StatusBadTCPMessageTooLarge, is: errors.ErrMessageTooLarge},
		{name: "endpoint url too long", msg: frame("RHEF", append(str(""), str(long+"x")...)), code: ua.StatusBadTCPMessageTooLarge, is: errors.ErrMessageTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rhe, err := readReverseHello(bytes.NewReader(tc.msg))
			require.Error(t, err)
			require.Nil(t, rhe)
			if tc.is != nil {
				require.ErrorIs(t, err, tc.is)
			}
			var rerr *reverseHelloError
			if tc.code == 0 {
				require.False(t, errors.As(err, &rerr), "an I/O error must not be answered: %v", err)
				return
			}
			require.ErrorAs(t, err, &rerr)
			require.Equal(t, tc.code, rerr.code)
			require.NotEmpty(t, rerr.Error())
		})
	}
}

// limitReader fails the test if more than limit bytes are read from it.
type limitReader struct {
	t     *testing.T
	r     io.Reader
	limit int
	n     int
}

func (l *limitReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += n
	if l.n > l.limit {
		l.t.Errorf("read %d bytes, the limit is %d", l.n, l.limit)
	}
	return n, err
}

// An oversized ReverseHello is refused after its header: the listener must
// not read (or allocate for) a body of a size the peer chooses.
func TestReadReverseHelloReadsNoOversizedBody(t *testing.T) {
	msg := append([]byte("RHEF"), 0x00, 0x00, 0x10, 0x00) // 1 MiB announced
	msg = append(msg, make([]byte, 64*1024)...)
	r := &limitReader{t: t, r: bytes.NewReader(msg), limit: hdrlen}
	_, err := readReverseHello(r)
	require.ErrorIs(t, err, errors.ErrMessageTooLarge)
}

func TestReverseDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	url := "opc.tcp://" + ln.Addr().String()
	ctx := context.Background()
	d := &ReverseDialer{Logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))}

	t.Run("invalid arguments", func(t *testing.T) {
		_, err := d.Dial(ctx, url, nil)
		require.Error(t, err)
		_, err = d.Dial(ctx, "http://127.0.0.1:1", &ReverseHello{})
		require.ErrorIs(t, err, errors.ErrInvalidEndpoint)
		_, err = d.Dial(ctx, url, &ReverseHello{ServerURI: strings.Repeat("x", MaxReverseHelloURILength+1)})
		require.ErrorIs(t, err, errors.ErrMessageTooLarge)
		_, err = d.Dial(ctx, url, &ReverseHello{EndpointURL: strings.Repeat("x", MaxReverseHelloURILength+1)})
		require.ErrorIs(t, err, errors.ErrMessageTooLarge)
	})

	t.Run("nobody listening", func(t *testing.T) {
		dead, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := dead.Addr().String()
		require.NoError(t, dead.Close())
		_, err = d.Dial(ctx, "opc.tcp://"+addr, &ReverseHello{ServerURI: "urn:server"})
		require.Error(t, err)
	})

	t.Run("cancelled", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := d.Dial(cctx, url, &ReverseHello{ServerURI: "urn:server"})
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("sends ReverseHello", func(t *testing.T) {
		conn, err := d.Dial(ctx, url, &ReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://server:4840"})
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		// the server's limits apply to the connection
		require.Equal(t, uint32(DefaultMaxChunkCount), conn.MaxChunkCount())

		peer, err := ln.Accept()
		require.NoError(t, err)
		defer func() { _ = peer.Close() }()
		_ = peer.SetReadDeadline(time.Now().Add(testWait))
		rhe, err := readReverseHello(peer)
		require.NoError(t, err)
		require.Equal(t, &ReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://server:4840"}, rhe)
	})
}

// reversePair returns the two ends of a reverse connection on which the
// ReverseHello message was sent and received: the server's Conn and the
// client's raw connection.
func reversePair(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	d := &ReverseDialer{Dialer: &net.Dialer{}, ACK: &Acknowledge{ReceiveBufSize: 8192, SendBufSize: 8192, MaxMessageSize: 1 << 20, MaxChunkCount: 64}}
	srv, err := d.Dial(context.Background(), "opc.tcp://"+ln.Addr().String(), &ReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://server:4840"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	peer, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })
	_ = peer.SetReadDeadline(time.Now().Add(testWait))
	_, err = readReverseHello(peer)
	require.NoError(t, err)
	_ = peer.SetReadDeadline(time.Time{})
	return srv, peer
}

func TestAcceptHello(t *testing.T) {
	const endpoint = "opc.tcp://server:4840"
	hello := func(t *testing.T, url string) []byte {
		t.Helper()
		body, err := (&Hello{ReceiveBufSize: 4096, SendBufSize: 4096, MaxMessageSize: 4096 * 8, MaxChunkCount: 8, EndpointURL: url}).Encode()
		require.NoError(t, err)
		return frame("HELF", body)
	}

	t.Run("hello acknowledged", func(t *testing.T) {
		srv, peer := reversePair(t)
		errCh := make(chan error, 1)
		go func() { errCh <- srv.AcceptHello(context.Background(), endpoint) }()

		_, err := peer.Write(hello(t, endpoint))
		require.NoError(t, err)
		_ = peer.SetReadDeadline(time.Now().Add(testWait))
		var hdr [hdrlen]byte
		_, err = io.ReadFull(peer, hdr[:])
		require.NoError(t, err)
		require.Equal(t, "ACKF", string(hdr[:4]))
		require.NoError(t, <-errCh)

		// the limits were negotiated down to the client's
		require.Equal(t, uint32(4096), srv.SendBufSize())
		require.Equal(t, uint32(4096), srv.ReceiveBufSize())
		require.Equal(t, uint32(8), srv.MaxChunkCount())
	})

	for _, tc := range []struct {
		name string
		msg  func(t *testing.T) []byte
		code ua.StatusCode
		is   error
	}{
		{"wrong endpoint", func(t *testing.T) []byte { return hello(t, "opc.tcp://other:4840") }, ua.StatusBadTCPEndpointURLInvalid, errors.ErrInvalidEndpoint},
		{"reverse hello echoed", func(t *testing.T) []byte { return rheFrame(t, "urn:server", endpoint) }, ua.StatusBadTCPMessageTypeInvalid, errors.ErrInvalidMessageType},
		{"acknowledge first", func(t *testing.T) []byte { return frame("ACKF", make([]byte, 20)) }, ua.StatusBadTCPInternalError, errors.ErrInvalidMessageType},
		{"open secure channel first", func(t *testing.T) []byte { return frame("OPNF", make([]byte, 32)) }, ua.StatusBadTCPInternalError, errors.ErrInvalidMessageType},
		{"malformed hello", func(t *testing.T) []byte { return frame("HELF", []byte{1, 2, 3}) }, ua.StatusBadTCPInternalError, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, peer := reversePair(t)
			errCh := make(chan error, 1)
			go func() { errCh <- srv.AcceptHello(context.Background(), endpoint) }()

			_, err := peer.Write(tc.msg(t))
			require.NoError(t, err)
			require.Equal(t, tc.code, readError(t, peer))
			err = <-errCh
			require.Error(t, err)
			if tc.is != nil {
				require.ErrorIs(t, err, tc.is)
			}
		})
	}

	t.Run("client refuses with an error message", func(t *testing.T) {
		srv, peer := reversePair(t)
		errCh := make(chan error, 1)
		go func() { errCh <- srv.AcceptHello(context.Background(), endpoint) }()
		sendError(peer, ua.StatusBadServerURIInvalid)
		require.ErrorIs(t, <-errCh, ua.StatusBadServerURIInvalid)
	})

	t.Run("client closes", func(t *testing.T) {
		srv, peer := reversePair(t)
		errCh := make(chan error, 1)
		go func() { errCh <- srv.AcceptHello(context.Background(), endpoint) }()
		require.NoError(t, peer.Close())
		require.ErrorIs(t, <-errCh, io.EOF)
	})

	// An idle reverse connection waits for the client as long as it takes:
	// only the context ends the waiting.
	t.Run("cancelled while idle", func(t *testing.T) {
		srv, _ := reversePair(t)
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- srv.AcceptHello(ctx, endpoint) }()
		select {
		case err := <-errCh:
			t.Fatalf("AcceptHello returned without a Hello: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		cancel()
		select {
		case err := <-errCh:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(testWait):
			t.Fatal("AcceptHello did not return after its context was cancelled")
		}
	})

	t.Run("deadline", func(t *testing.T) {
		srv, _ := reversePair(t)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, srv.AcceptHello(ctx, endpoint), context.DeadlineExceeded)
	})

	t.Run("already cancelled", func(t *testing.T) {
		srv, peer := reversePair(t)
		_, err := peer.Write(hello(t, endpoint))
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		require.ErrorIs(t, srv.AcceptHello(ctx, endpoint), context.Canceled)
	})
}

// A server that is sent a ReverseHello on a connection it accepted answers
// with an Error message. (It used to treat the ServerUri as an address and
// connect to it.)
func TestListenerRejectsReverseHello(t *testing.T) {
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	errCh := make(chan error, 1)
	go func() {
		_, err := ln.Accept(context.Background())
		errCh <- err
	}()

	c := dialRaw(t, ln.Addr().String())
	_, err = c.Write(rheFrame(t, "127.0.0.1:1", "opc.tcp://127.0.0.1:0"))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadTCPMessageTypeInvalid, readError(t, c))
	requireClosed(t, c)
	require.ErrorIs(t, <-errCh, errors.ErrInvalidMessageType)
}

func TestListenReverseAddress(t *testing.T) {
	ctx := context.Background()
	l, err := ListenReverse(ctx, "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	require.NotZero(t, l.Addr().(*net.TCPAddr).Port)
	require.NoError(t, l.Close())
	require.NoError(t, l.Close(), "Close is idempotent")

	_, err = ListenReverse(ctx, "http://127.0.0.1:0", nil)
	require.ErrorIs(t, err, errors.ErrInvalidEndpoint)
	_, err = ListenReverse(ctx, "127.0.0.1:not-a-port", nil)
	require.Error(t, err)

	// a closed listener hands out nothing
	_, _, err = l.Accept(ctx, nil)
	require.ErrorIs(t, err, net.ErrClosed)
	_, _, err = (&Dialer{}).AcceptReverse(ctx, l, "", nil)
	require.ErrorIs(t, err, net.ErrClosed)
	_, _, err = (&Dialer{}).AcceptReverse(ctx, nil, "", nil)
	require.Error(t, err)
}

// TestReverseHandshake runs the whole exchange between the two halves of the
// package: ReverseDialer and AcceptHello on the server, ReverseListener and
// AcceptReverse on the client.
func TestReverseHandshake(t *testing.T) {
	const endpoint = "opc.tcp://server:4840/ua"
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l, addr := testReverseListener(t, &ReverseListenerConfig{Logger: logger})
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()

	type result struct {
		conn *Conn
		rhe  *ReverseHello
		err  error
	}
	clientCh := make(chan result, 1)
	go func() {
		d := &Dialer{Dialer: &net.Dialer{Timeout: testWait}, Logger: logger}
		conn, rhe, err := d.AcceptReverse(ctx, l, "opc.tcp://fallback:1", func(rhe *ReverseHello) error {
			if rhe.ServerURI != "urn:server" {
				return errors.ErrReverseHelloRejected
			}
			return nil
		})
		clientCh <- result{conn, rhe, err}
	}()

	srv, err := (&ReverseDialer{Logger: logger}).Dial(ctx, "opc.tcp://"+addr, &ReverseHello{ServerURI: "urn:server", EndpointURL: endpoint})
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()
	require.NoError(t, srv.AcceptHello(ctx, endpoint))

	res := <-clientCh
	require.NoError(t, res.err)
	defer func() { _ = res.conn.Close() }()
	require.Equal(t, &ReverseHello{ServerURI: "urn:server", EndpointURL: endpoint}, res.rhe)
	require.Zero(t, l.Pending())

	// The connection carries messages in both directions.
	require.NoError(t, res.conn.Send("MSGF", &Message{Data: []byte("ping")}))
	b, err := srv.Receive()
	require.NoError(t, err)
	require.Equal(t, "ping", string(b[hdrlen:]))
	require.NoError(t, srv.Send("MSGF", &Message{Data: []byte("pong")}))
	b, err = res.conn.Receive()
	require.NoError(t, err)
	require.Equal(t, "pong", string(b[hdrlen:]))
}

// A server that announces no EndpointUrl is sent the client's own in Hello.
func TestAcceptReverseFallbackEndpoint(t *testing.T) {
	l, addr := testReverseListener(t, nil)
	srv := announce(t, addr, "urn:server", "")
	got := make(chan string, 1)
	go func() { got <- serverHello(t, srv) }()

	conn, rhe, err := (&Dialer{Dialer: &net.Dialer{Timeout: testWait}}).AcceptReverse(context.Background(), l, "opc.tcp://fallback:4840", nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.Empty(t, rhe.EndpointURL)
	require.Equal(t, "opc.tcp://fallback:4840", <-got)
	// the ACK of the server was taken over
	require.Equal(t, uint32(16), conn.MaxChunkCount())
}

func TestReverseListenerRefusals(t *testing.T) {
	t.Run("oversized message", func(t *testing.T) {
		l, addr := testReverseListener(t, nil)
		c := dialRaw(t, addr)
		_, err := c.Write(append([]byte("RHEF"), 0x00, 0x00, 0x01, 0x00))
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadTCPMessageTooLarge, readError(t, c))
		requireClosed(t, c)
		require.Zero(t, l.Pending())
	})

	t.Run("wrong message order", func(t *testing.T) {
		l, addr := testReverseListener(t, nil)
		body, err := (&Hello{EndpointURL: "opc.tcp://client:4840"}).Encode()
		require.NoError(t, err)
		c := dialRaw(t, addr)
		_, err = c.Write(frame("HELF", body))
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadTCPMessageTypeInvalid, readError(t, c))
		requireClosed(t, c)
		require.Zero(t, l.Pending())
	})

	t.Run("malformed message", func(t *testing.T) {
		_, addr := testReverseListener(t, nil)
		c := dialRaw(t, addr)
		_, err := c.Write(frame("RHEF", []byte{4, 0, 0, 0, 'u', 'r', 'n', ':', 0xff, 0xff, 0xff, 0x7f}))
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadTCPInternalError, readError(t, c))
		requireClosed(t, c)
	})

	t.Run("silent peer", func(t *testing.T) {
		_, addr := testReverseListener(t, &ReverseListenerConfig{HelloTimeout: 50 * time.Millisecond})
		requireClosed(t, dialRaw(t, addr))
	})

	t.Run("slow peer", func(t *testing.T) {
		_, addr := testReverseListener(t, &ReverseListenerConfig{HelloTimeout: 50 * time.Millisecond})
		c := dialRaw(t, addr)
		_, err := c.Write([]byte("RHEF\x40\x00"))
		require.NoError(t, err)
		requireClosed(t, c)
	})

	t.Run("filter", func(t *testing.T) {
		l, addr := testReverseListener(t, &ReverseListenerConfig{
			Filter: func(rhe *ReverseHello) error {
				switch rhe.ServerURI {
				case "urn:coded":
					return ua.StatusBadServerURIInvalid
				case "urn:plain":
					return errors.ErrReverseHelloRejected
				}
				return nil
			},
		})
		c := announce(t, addr, "urn:coded", "opc.tcp://server:4840")
		require.Equal(t, ua.StatusBadServerURIInvalid, readError(t, c))
		requireClosed(t, c)
		c = announce(t, addr, "urn:plain", "opc.tcp://server:4840")
		require.Equal(t, ua.StatusBadTCPEndpointURLInvalid, readError(t, c))
		requireClosed(t, c)
		require.Zero(t, l.Pending())

		announce(t, addr, "urn:welcome", "opc.tcp://server:4840")
		waitFor(t, func() bool { return l.Pending() == 1 }, "admitted server is pending")
	})
}

// The number of connections that have not announced themselves is bounded:
// further ones are dropped at once and the listener recovers when the slots
// are free again.
func TestReverseListenerLimitsUnannouncedConnections(t *testing.T) {
	const limit = 3
	l, addr := testReverseListener(t, &ReverseListenerConfig{MaxHandshakes: limit, HelloTimeout: testWait})

	silent := make([]net.Conn, limit)
	for i := range silent {
		silent[i] = dialRaw(t, addr)
	}
	waitFor(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.handshakes) == limit
	}, "all slots taken")

	for range 5 {
		requireClosed(t, dialRaw(t, addr))
	}

	// A slot becomes free when one of the silent peers announces itself or
	// goes away.
	_, err := silent[0].Write(rheFrame(t, "urn:server", "opc.tcp://server:4840"))
	require.NoError(t, err)
	require.NoError(t, silent[1].Close())
	waitFor(t, func() bool { return l.Pending() == 1 }, "announced connection is pending")
	waitFor(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.handshakes) == 1
	}, "slots released")
	announce(t, addr, "urn:other", "opc.tcp://other:4840")
	waitFor(t, func() bool { return l.Pending() == 2 }, "listener accepts again")
}

func TestReverseListenerPending(t *testing.T) {
	ctx := context.Background()

	t.Run("newest connection of a server wins", func(t *testing.T) {
		l, addr := testReverseListener(t, nil)
		first := announce(t, addr, "urn:server", "opc.tcp://server:4840")
		waitFor(t, func() bool { return l.Pending() == 1 }, "first pending")
		second := announce(t, addr, "urn:server", "opc.tcp://server:4840")
		requireClosed(t, first)
		require.Equal(t, 1, l.Pending())

		// another endpoint of the same server is a different connection
		announce(t, addr, "urn:server", "opc.tcp://server:4841")
		waitFor(t, func() bool { return l.Pending() == 2 }, "second endpoint pending")

		c, rhe, err := l.Accept(ctx, func(rhe *ReverseHello) error {
			if rhe.EndpointURL != "opc.tcp://server:4840" {
				return errors.ErrReverseHelloRejected
			}
			return nil
		})
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		require.Equal(t, "urn:server", rhe.ServerURI)
		require.Equal(t, second.LocalAddr().String(), c.RemoteAddr().String())
		require.Equal(t, 1, l.Pending())

		// The connection that was handed out is usable: its read deadline
		// was cleared again.
		_, err = second.Write([]byte("x"))
		require.NoError(t, err)
		_ = c.SetReadDeadline(time.Now().Add(testWait))
		var b [1]byte
		_, err = io.ReadFull(c, b[:])
		require.NoError(t, err)
	})

	t.Run("limit drops the oldest", func(t *testing.T) {
		l, addr := testReverseListener(t, &ReverseListenerConfig{MaxPending: 2})
		a := announce(t, addr, "urn:a", "")
		waitFor(t, func() bool { return l.Pending() == 1 }, "a pending")
		announce(t, addr, "urn:b", "")
		waitFor(t, func() bool { return l.Pending() == 2 }, "b pending")
		announce(t, addr, "urn:c", "")
		requireClosed(t, a)
		require.Equal(t, 2, l.Pending())

		_, rhe, err := l.Accept(ctx, nil)
		require.NoError(t, err)
		require.Equal(t, "urn:c", rhe.ServerURI, "the most recent connection is preferred")
	})

	t.Run("connection closed by the server is dropped", func(t *testing.T) {
		l, addr := testReverseListener(t, nil)
		c := announce(t, addr, "urn:server", "")
		waitFor(t, func() bool { return l.Pending() == 1 }, "pending")
		require.NoError(t, c.Close())
		waitFor(t, func() bool { return l.Pending() == 0 }, "dropped")
	})

	t.Run("server that talks before Hello is dropped", func(t *testing.T) {
		l, addr := testReverseListener(t, nil)
		c := announce(t, addr, "urn:server", "")
		waitFor(t, func() bool { return l.Pending() == 1 }, "pending")
		_, err := c.Write([]byte("unexpected"))
		require.NoError(t, err)
		requireClosed(t, c)
		require.Zero(t, l.Pending())
	})

	t.Run("close drops pending connections and wakes waiters", func(t *testing.T) {
		l, addr := testReverseListener(t, nil)
		c := announce(t, addr, "urn:server", "")
		waitFor(t, func() bool { return l.Pending() == 1 }, "pending")

		errCh := make(chan error, 1)
		go func() {
			_, _, err := l.Accept(ctx, func(*ReverseHello) error { return errors.ErrReverseHelloRejected })
			errCh <- err
		}()
		waitFor(t, func() bool {
			l.mu.Lock()
			defer l.mu.Unlock()
			return len(l.waiters) == 1
		}, "waiting")
		require.NoError(t, l.Close())
		require.ErrorIs(t, <-errCh, net.ErrClosed)
		requireClosed(t, c)
		require.Zero(t, l.Pending())
	})
}

func TestReverseListenerAcceptTimeout(t *testing.T) {
	t.Run("nothing connects", func(t *testing.T) {
		l, _ := testReverseListener(t, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, _, err := l.Accept(ctx, nil)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		l.mu.Lock()
		defer l.mu.Unlock()
		require.Empty(t, l.waiters, "the waiter is gone")
	})

	t.Run("other servers are pending", func(t *testing.T) {
		l, addr := testReverseListener(t, nil)
		announce(t, addr, "urn:other", "")
		waitFor(t, func() bool { return l.Pending() == 1 }, "pending")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, _, err := l.Accept(ctx, func(*ReverseHello) error { return errors.ErrReverseHelloRejected })
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorContains(t, err, "urn:other")
		require.Equal(t, 1, l.Pending(), "the connection stays for the client that wants it")
	})

	t.Run("a server was refused meanwhile", func(t *testing.T) {
		l, addr := testReverseListener(t, &ReverseListenerConfig{
			Filter: func(*ReverseHello) error { return errors.ErrReverseHelloRejected },
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errCh := make(chan error, 1)
		go func() {
			_, _, err := l.Accept(ctx, nil)
			errCh <- err
		}()
		waitFor(t, func() bool {
			l.mu.Lock()
			defer l.mu.Unlock()
			return len(l.waiters) == 1
		}, "waiting")
		c := announce(t, addr, "urn:refused", "")
		require.Equal(t, ua.StatusBadTCPEndpointURLInvalid, readError(t, c))
		cancel()
		err := <-errCh
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, errors.ErrReverseHelloRejected)
	})

	// Regression: the refusal happened after the caller began to wait but
	// before it called Accept (e.g. right after it opened the listener). It
	// used to be lost: the error said only "context canceled".
	t.Run("a server was refused before Accept was called", func(t *testing.T) {
		l, addr := testReverseListener(t, &ReverseListenerConfig{
			Filter: func(*ReverseHello) error { return errors.ErrReverseHelloRejected },
		})
		since := l.Rejected()
		c := announce(t, addr, "urn:refused", "")
		require.Equal(t, ua.StatusBadTCPEndpointURLInvalid, readError(t, c))
		require.Equal(t, since+1, l.Rejected())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, _, err := l.AcceptSince(ctx, nil, since)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorIs(t, err, errors.ErrReverseHelloRejected)

		ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel2()
		_, _, err = (&Dialer{}).AcceptReverseSince(ctx2, l, "", nil, since)
		require.ErrorIs(t, err, errors.ErrReverseHelloRejected)

		// Accept starts waiting when it is called: the refusal is older.
		ctx3, cancel3 := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel3()
		_, _, err = l.Accept(ctx3, nil)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.NotErrorIs(t, err, errors.ErrReverseHelloRejected)
	})

	t.Run("dial timeout bounds AcceptReverse", func(t *testing.T) {
		l, _ := testReverseListener(t, nil)
		d := &Dialer{Dialer: &net.Dialer{Timeout: 30 * time.Millisecond}}
		_, _, err := d.AcceptReverse(context.Background(), l, "", nil)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("dial timeout covers a server that does not acknowledge", func(t *testing.T) {
		l, addr := testReverseListener(t, nil)
		announce(t, addr, "urn:server", "opc.tcp://server:4840")
		d := &Dialer{Dialer: &net.Dialer{Timeout: 100 * time.Millisecond}}
		_, _, err := d.AcceptReverse(context.Background(), l, "", nil)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

// Several clients wait on one listener: each gets the connection of the
// server it asked for, whatever the order of arrival.
func TestReverseListenerDispatch(t *testing.T) {
	const n = 6
	l, addr := testReverseListener(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()

	uri := func(i int) string { return "urn:server:" + string(rune('a'+i)) }
	got := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, rhe, err := l.Accept(ctx, func(rhe *ReverseHello) error {
				if rhe.ServerURI != uri(i) {
					return errors.ErrReverseHelloRejected
				}
				return nil
			})
			if err != nil {
				t.Error(err)
				return
			}
			got[i] = rhe.ServerURI
			_ = c.Close()
		}()
	}
	// Half of the servers connect before their client waits, half after.
	waitFor(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.waiters) == n
	}, "all clients waiting")
	for i := n - 1; i >= 0; i-- {
		announce(t, addr, uri(i), "")
	}
	wg.Wait()
	for i := range n {
		require.Equal(t, uri(i), got[i])
	}
	require.Zero(t, l.Pending())
}

// A waiter that gives up at the moment a connection is handed to it passes
// the connection on instead of leaking it.
func TestReverseListenerAbandonedConnectionIsKept(t *testing.T) {
	l, addr := testReverseListener(t, nil)
	c := announce(t, addr, "urn:server", "")
	waitFor(t, func() bool { return l.Pending() == 1 }, "pending")

	// Take the connection the way a waiter that was just served and then
	// cancelled holds it.
	l.mu.Lock()
	p := l.pending[0]
	l.pending = nil
	l.mu.Unlock()
	require.True(t, l.claim(p))
	w := &reverseWaiter{ch: make(chan *reverseConn, 1)}
	w.ch <- p
	l.abandon(w)
	require.Equal(t, 1, l.Pending())

	got, _, err := l.Accept(context.Background(), nil)
	require.NoError(t, err)
	defer func() { _ = got.Close() }()
	require.Equal(t, c.LocalAddr().String(), got.RemoteAddr().String())
}

// A pending connection that broke without the listener noticing in time is
// skipped: AcceptReverse waits for the server to connect again.
func TestAcceptReverseSkipsBrokenConnection(t *testing.T) {
	l, addr := testReverseListener(t, nil)

	type result struct {
		conn *Conn
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		conn, _, err := (&Dialer{Dialer: &net.Dialer{Timeout: testWait}}).AcceptReverse(context.Background(), l, "", nil)
		resCh <- result{conn, err}
	}()
	waitFor(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.waiters) == 1
	}, "client waiting")

	// The first server closes the connection instead of acknowledging.
	broken := announce(t, addr, "urn:server", "opc.tcp://server:4840")
	_ = broken.SetReadDeadline(time.Now().Add(testWait))
	var hdr [hdrlen]byte
	_, err := io.ReadFull(broken, hdr[:])
	require.NoError(t, err)
	require.Equal(t, "HELF", string(hdr[:4]))
	require.NoError(t, broken.Close())

	// The client is waiting again and takes the next connection.
	waitFor(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.waiters) == 1
	}, "client waiting again")
	good := announce(t, addr, "urn:server", "opc.tcp://server:4840")
	require.Equal(t, "opc.tcp://server:4840", serverHello(t, good))
	res := <-resCh
	require.NoError(t, res.err)
	_ = res.conn.Close()
}

// An Error message is the server's answer to the Hello: AcceptReverse reports
// it instead of waiting for another connection.
func TestAcceptReverseReportsServerError(t *testing.T) {
	l, addr := testReverseListener(t, nil)
	srv := announce(t, addr, "urn:server", "opc.tcp://server:4840")
	go func() {
		var hdr [hdrlen]byte
		if _, err := io.ReadFull(srv, hdr[:]); err == nil {
			sendError(srv, ua.StatusBadTCPEndpointURLInvalid)
		}
	}()
	_, _, err := (&Dialer{Dialer: &net.Dialer{Timeout: testWait}}).AcceptReverse(context.Background(), l, "", nil)
	require.ErrorIs(t, err, ua.StatusBadTCPEndpointURLInvalid)
}

// pipeListener is a net.Listener whose connections are not TCP connections.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (p *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-p.conns:
		return c, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (p *pipeListener) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestNewReverseListenerRequiresTCP(t *testing.T) {
	pl := &pipeListener{conns: make(chan net.Conn, 1), closed: make(chan struct{})}
	l := NewReverseListener(pl, &ReverseListenerConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	defer func() { _ = l.Close() }()

	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	pl.conns <- server
	requireClosed(t, client)
	require.Zero(t, l.Pending())
}

// failingListener reports a temporary accept error before it works.
type failingListener struct {
	net.Listener
	mu     sync.Mutex
	failed int
}

func (f *failingListener) Accept() (net.Conn, error) {
	f.mu.Lock()
	if f.failed < 3 {
		f.failed++
		f.mu.Unlock()
		return nil, fmt.Errorf("accept: too many open files")
	}
	f.mu.Unlock()
	return f.Listener.Accept()
}

func TestReverseListenerSurvivesAcceptErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	l := NewReverseListener(&failingListener{Listener: ln}, &ReverseListenerConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	defer func() { _ = l.Close() }()

	announce(t, ln.Addr().String(), "urn:server", "")
	waitFor(t, func() bool { return l.Pending() == 1 }, "listener keeps accepting")
}

func FuzzReverseHelloRead(f *testing.F) {
	f.Add([]byte("RHEF\x10\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"))
	f.Add(append([]byte("RHEF\x1b\x00\x00\x00\x03\x00\x00\x00urn\x08\x00\x00\x00"), "opc.tcp:"...))
	f.Add([]byte("HELF\x08\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := &limitReader{t: t, r: bytes.NewReader(b), limit: maxReverseHelloSize}
		rhe, err := readReverseHello(r)
		if err != nil {
			return
		}
		if len(rhe.ServerURI) > MaxReverseHelloURILength || len(rhe.EndpointURL) > MaxReverseHelloURILength {
			t.Fatalf("limit not enforced: %d/%d", len(rhe.ServerURI), len(rhe.EndpointURL))
		}
	})
}
