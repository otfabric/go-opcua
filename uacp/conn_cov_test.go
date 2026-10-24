// SPDX-License-Identifier: MIT

package uacp

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// fakeServer accepts one connection on loopback and runs handle on it. It
// returns the endpoint URL. handle runs in its own goroutine and must report
// problems with t.Errorf, not t.Fatal.
func fakeServer(t *testing.T, handle func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(testWait))
		handle(c)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return "opc.tcp://" + ln.Addr().String()
}

// readMsg reads one UACP message from c.
func readMsg(c net.Conn) (string, []byte, error) {
	var hdr [hdrlen]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", nil, err
	}
	body := make([]byte, binary.LittleEndian.Uint32(hdr[4:])-hdrlen)
	if _, err := io.ReadFull(c, body); err != nil {
		return "", nil, err
	}
	return string(hdr[:4]), body, nil
}

// answerHello reads the Hello of the client and answers with raw.
func answerHello(t *testing.T, raw []byte) func(net.Conn) {
	return func(c net.Conn) {
		typ, _, err := readMsg(c)
		if err != nil || typ != "HELF" {
			t.Errorf("expected a Hello, got %q, %v", typ, err)
			return
		}
		if _, err := c.Write(raw); err != nil {
			t.Errorf("write: %v", err)
		}
	}
}

func testDialer() *Dialer { return &Dialer{Dialer: &net.Dialer{Timeout: testWait}} }

func ackBody(t *testing.T, a *Acknowledge) []byte {
	t.Helper()
	b, err := a.Encode()
	require.NoError(t, err)
	return b
}

// header builds a bare message header that announces size bytes.
func header(typ string, size uint32) []byte {
	b := make([]byte, hdrlen)
	copy(b, typ)
	binary.LittleEndian.PutUint32(b[4:], size)
	return b
}

func TestHandshake_MalformedServerAnswers(t *testing.T) {
	goodAck := &Acknowledge{ReceiveBufSize: 8192, SendBufSize: 8192, MaxMessageSize: 1 << 20, MaxChunkCount: 8}
	for _, tc := range []struct {
		name    string
		answer  []byte
		wantIs  error
		wantMsg string
	}{
		{"truncated Acknowledge", frame("ACKF", []byte{0, 0, 0, 0}), nil, "uacp: decode ACK failed"},
		{"Acknowledge of an unknown version", frame("ACKF", ackBody(t, &Acknowledge{Version: 1, ReceiveBufSize: 8192, SendBufSize: 8192})), errors.ErrInvalidState, "version=1"},
		{"message shorter than its header", header("ACKF", 4), errors.ErrMessageTooSmall, ""},
		{"message larger than the receive buffer", header("ACKF", DefaultReceiveBufSize+1), errors.ErrMessageTooLarge, ""},
		{"truncated Error", frame("ERRF", []byte{1, 2}), nil, "failed to decode ERRF message"},
		{"connection closed inside a message", append(header("ACKF", 28), ackBody(t, goodAck)[:10]...), io.ErrUnexpectedEOF, ""},
		{"connection closed before a message", nil, io.EOF, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := fakeServer(t, answerHello(t, tc.answer))
			conn, err := testDialer().Dial(context.Background(), ep)
			require.Nil(t, conn)
			require.Error(t, err)
			if tc.wantIs != nil {
				require.ErrorIs(t, err, tc.wantIs)
			}
			if tc.wantMsg != "" {
				require.ErrorContains(t, err, tc.wantMsg)
			}
		})
	}
}

// TestHandshake_UnexpectedMessageType: a server that answers the Hello with
// anything but Acknowledge or Error is told so with an Error message.
func TestHandshake_UnexpectedMessageType(t *testing.T) {
	got := make(chan ua.StatusCode, 1)
	ep := fakeServer(t, func(c net.Conn) {
		if typ, _, err := readMsg(c); err != nil || typ != "HELF" {
			t.Errorf("expected a Hello, got %q, %v", typ, err)
			return
		}
		if _, err := c.Write(frame("MSGF", []byte{1, 2, 3, 4})); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		typ, body, err := readMsg(c)
		if err != nil || typ != "ERRF" {
			t.Errorf("expected an Error, got %q, %v", typ, err)
			return
		}
		var e Error
		if _, err := e.Decode(body); err != nil {
			t.Errorf("decode Error: %v", err)
			return
		}
		got <- ua.StatusCode(e.ErrorCode)
	})
	_, err := testDialer().Dial(context.Background(), ep)
	require.ErrorIs(t, err, errors.ErrInvalidMessageType)
	require.ErrorContains(t, err, `"MSGF"`)
	require.Equal(t, ua.StatusBadTCPInternalError, <-got)
}

// TestDialer_LogsAndErrors covers the dialer's own failures and that it logs
// them when it has a logger.
func TestDialer_LogsAndErrors(t *testing.T) {
	var logs bytes.Buffer
	var mu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))
	logged := func() string {
		mu.Lock()
		defer mu.Unlock()
		return logs.String()
	}

	// An endpoint that does not parse.
	_, err := (&Dialer{Logger: logger}).Dial(context.Background(), "http://127.0.0.1:4840")
	require.ErrorIs(t, err, errors.ErrInvalidEndpoint)
	require.Contains(t, logged(), "connecting")

	// Nothing listens: the zero Dialer uses the default net.Dialer.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedEP := "opc.tcp://" + ln.Addr().String()
	require.NoError(t, ln.Close())
	_, err = (&Dialer{}).Dial(context.Background(), closedEP)
	var opErr *net.OpError
	require.ErrorAs(t, err, &opErr)
	require.Equal(t, "dial", opErr.Op)

	// The server refuses the Hello: the Error message is returned, and the
	// failed handshake is logged as a warning.
	errBody, err := (&Error{ErrorCode: uint32(ua.StatusBadTCPEndpointURLInvalid)}).Encode()
	require.NoError(t, err)
	ep := fakeServer(t, answerHello(t, frame("ERRF", errBody)))
	d := testDialer()
	d.Logger = logger
	_, err = d.Dial(context.Background(), ep)
	var uerr *Error
	require.ErrorAs(t, err, &uerr)
	require.ErrorIs(t, err, ua.StatusBadTCPEndpointURLInvalid)
	require.Contains(t, logged(), "level=WARN msg=\"HEL/ACK handshake failed\"")
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	type res struct {
		c   *net.TCPConn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.AcceptTCP()
		ch <- res{c, err}
	}()
	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	r := <-ch
	require.NoError(t, r.err)
	t.Cleanup(func() {
		_ = client.Close()
		_ = r.c.Close()
	})
	return client, r.c
}

func TestNewConn_NoConnection(t *testing.T) {
	c, err := NewConn(nil, nil)
	require.Nil(t, c)
	require.ErrorContains(t, err, "no connection")
}

func TestSend_Errors(t *testing.T) {
	a, b := tcpPair(t)
	c, err := NewConn(a, &Acknowledge{ReceiveBufSize: 8192, SendBufSize: 64})
	require.NoError(t, err)

	require.ErrorIs(t, c.Send("MSG", &Message{}), errors.ErrInvalidMessageType)
	require.ErrorIs(t, c.Send("MSGFF", &Message{}), errors.ErrInvalidMessageType)
	require.ErrorContains(t, c.Send("MSGF", make(chan int)), "uacp: encode msg failed")
	require.ErrorIs(t, c.Send("MSGF", &Message{Data: make([]byte, 64)}), errors.ErrMessageTooLarge)

	// None of these put a byte on the wire: the first thing the peer reads
	// is the message that fits.
	require.NoError(t, c.Send("MSGF", &Message{Data: []byte{0xca, 0xfe}}))
	typ, body, err := readMsg(b)
	require.NoError(t, err)
	require.Equal(t, "MSGF", typ)
	require.Equal(t, []byte{0xca, 0xfe}, body)

	// A write on a closed connection fails.
	require.NoError(t, c.Close())
	require.ErrorIs(t, c.Close(), io.EOF, "a second Close")
	require.ErrorContains(t, c.Send("MSGF", &Message{}), "uacp: write failed")
}

// TestHandshake_HelloDoesNotFit: a client whose send buffer cannot hold its
// own Hello fails without sending anything.
func TestHandshake_HelloDoesNotFit(t *testing.T) {
	a, b := tcpPair(t)
	c, err := NewConn(a, &Acknowledge{ReceiveBufSize: 8192, SendBufSize: 16})
	require.NoError(t, err)
	err = c.Handshake(context.Background(), "opc.tcp://127.0.0.1:4840")
	require.ErrorIs(t, err, errors.ErrMessageTooLarge)

	require.NoError(t, c.Close())
	_ = b.SetReadDeadline(time.Now().Add(testWait))
	n, err := b.Read(make([]byte, 1))
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
}

func TestListen_Errors(t *testing.T) {
	_, err := Listen(context.Background(), "http://127.0.0.1:0", nil)
	require.ErrorIs(t, err, errors.ErrInvalidEndpoint)

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = busy.Close() }()
	_, err = Listen(context.Background(), "opc.tcp://"+busy.Addr().String(), nil)
	var opErr *net.OpError
	require.ErrorAs(t, err, &opErr)
	require.Equal(t, "listen", opErr.Op)

}

// TestListen_ClonesACK: the listener keeps its own copy of the limits it was
// given, so changing the template later does not change it.
func TestListen_ClonesACK(t *testing.T) {
	ack := &Acknowledge{ReceiveBufSize: 8192, SendBufSize: 8192, MaxMessageSize: 1 << 16, MaxChunkCount: 4}
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", ack)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	ack.MaxChunkCount = 99
	ack.SendBufSize = 1 << 20

	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	type res struct {
		c   *Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept(ctx)
		accepted <- res{c, err}
	}()
	cli, err := testDialer().Dial(ctx, "opc.tcp://"+ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = cli.Close() }()
	r := <-accepted
	require.NoError(t, r.err)
	defer func() { _ = r.c.Close() }()

	require.Equal(t, uint32(4), cli.MaxChunkCount())
	require.Equal(t, uint32(1<<16), cli.MaxMessageSize())
	require.Equal(t, uint32(8192), cli.ReceiveBufSize(), "the buffer sizes of the server")
	require.Equal(t, uint32(4), r.c.MaxChunkCount())
	require.Equal(t, uint32(8192), r.c.SendBufSize())
}

// TestListener_UnacceptedConnectionDroppedOnClose: a connection that
// completed the handshake but was never taken with Accept is closed with the
// listener, and Accept honours its context.
func TestListener_UnacceptedConnectionDroppedOnClose(t *testing.T) {
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)

	// Start the accept loop, but do not wait for a connection.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, err := ln.Accept(ctx)
	require.Nil(t, c)
	require.ErrorIs(t, err, context.Canceled)

	cli, err := testDialer().Dial(context.Background(), "opc.tcp://"+ln.Addr().String())
	require.NoError(t, err, "the handshake completes without Accept")
	defer func() { _ = cli.Close() }()

	require.NoError(t, ln.Close())
	_ = cli.SetReadDeadline(time.Now().Add(testWait))
	_, err = cli.Receive()
	require.ErrorIs(t, err, io.EOF, "the listener closed the connection nobody accepted")

	_, err = ln.Accept(context.Background())
	require.ErrorIs(t, err, net.ErrClosed)
}

// TestListener_AcceptErrorsAreReported: an error of the TCP accept is handed
// to Accept and the listener keeps accepting afterwards.
func TestListener_AcceptErrorsAreReported(t *testing.T) {
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()

	// An expired deadline makes every TCP accept fail.
	require.NoError(t, ln.l.SetDeadline(time.Now()))
	for range 2 {
		_, err = ln.Accept(ctx)
		var nerr net.Error
		require.ErrorAs(t, err, &nerr)
		require.True(t, nerr.Timeout())
	}

	require.NoError(t, ln.l.SetDeadline(time.Time{}))
	dialed := make(chan error, 1)
	go func() {
		c, err := testDialer().Dial(ctx, "opc.tcp://"+ln.Addr().String())
		if err == nil {
			_ = c.Close()
		}
		dialed <- err
	}()
	// The accept loop may report one more expired accept that was already
	// under way before the deadline was cleared.
	for {
		c, err := ln.Accept(ctx)
		if err == nil {
			_ = c.Close()
			break
		}
		var nerr net.Error
		require.ErrorAs(t, err, &nerr)
		require.True(t, nerr.Timeout())
	}
	require.NoError(t, <-dialed)
}

// TestListener_AckDoesNotFit: a client that offers a receive buffer too small
// for the Acknowledge fails the handshake and is told so.
func TestListener_AckDoesNotFit(t *testing.T) {
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	hel, err := (&Hello{ReceiveBufSize: 16, SendBufSize: 8192, EndpointURL: "opc.tcp://" + ln.Addr().String()}).Encode()
	require.NoError(t, err)
	_, err = raw.Write(frame("HELF", hel))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	_, err = ln.Accept(ctx)
	require.ErrorIs(t, err, errors.ErrMessageTooLarge)
	// The Error message, unlike the Acknowledge, fits in 16 bytes.
	require.Equal(t, ua.StatusBadTCPInternalError, readError(t, raw))
	requireClosed(t, raw)
}

func TestEndpointMatch_Fallbacks(t *testing.T) {
	// URLs that do not parse are compared as strings.
	require.True(t, endpointMatch("opc.tcp://host/%zz", "opc.tcp://host/%zz"))
	require.False(t, endpointMatch("opc.tcp://host/%zz", "opc.tcp://host/%zy"))
	require.False(t, endpointMatch("opc.tcp://host:4840/", "opc.tcp://host/%zz"))

	// A client URL without a port means the default port.
	require.True(t, endpointMatch("opc.tcp://host/", "opc.tcp://host:4840/"))
	require.False(t, endpointMatch("opc.tcp://host/", "opc.tcp://host:4841/"))
}

// TestListener_CloseAfterAcceptError: Close ends an accept loop that is
// backing off after an accept error.
func TestListener_CloseAfterAcceptError(t *testing.T) {
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	require.NoError(t, ln.l.SetDeadline(time.Now()))

	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	_, err = ln.Accept(ctx)
	var nerr net.Error
	require.ErrorAs(t, err, &nerr)
	require.True(t, nerr.Timeout())

	require.NoError(t, ln.Close())
	_, err = ln.Accept(ctx)
	require.ErrorIs(t, err, net.ErrClosed)
	// The leak check of TestMain verifies that the accept loop stopped.
}
