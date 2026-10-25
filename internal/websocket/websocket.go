// SPDX-License-Identifier: MIT

// Package websocket is the small part of RFC 6455 that the OPC UA WebSocket
// transport (Part 6 §7.5) needs: the opening handshake of a client and of a
// server, and a net.Conn that carries a byte stream in binary messages.
//
// With the sub-protocol opcua+uacp every WebSocket frame holds one OPC UA
// MessageChunk (Part 6 §7.5.2). The UACP layer writes each chunk with a
// single Write, and Write sends it as a single binary frame. On the receiving
// side the chunks are self-delimiting, so Read hands out the payload of the
// data frames as a stream and never buffers a whole message: a peer cannot
// make the reader allocate more than the caller's buffer, whatever length it
// announces.
//
// With the sub-protocol opcua+uajson every WebSocket message holds one OPC UA
// message in the JSON encoding (Part 6 §7.5.2). ReadMessage and WriteText
// serve that sub-protocol: they read and write whole messages, and a message
// larger than the limit of the reader ends the connection with status 1009.
//
// What is not implemented because the OPC UA sub-protocols have no use for
// it: text messages on the byte stream of Read (they end the connection with
// status 1003), extensions (no extension is ever negotiated, so frames with
// RSV bits set are a protocol error) and sending pings.
package websocket

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // mandated by RFC 6455 §4.2.2 for Sec-WebSocket-Accept
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"
	"unicode/utf8"
)

// Frame opcodes (RFC 6455 §5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// Close status codes (RFC 6455 §7.4.1).
const (
	CloseNormal          = 1000
	CloseProtocolError   = 1002
	CloseUnsupportedData = 1003
	CloseInvalidPayload  = 1007
	CloseMessageTooBig   = 1009

	// closeNoStatus stands for a Close frame without a status code
	// (RFC 6455 §7.4.1); it is never sent.
	closeNoStatus = 1005
)

// DefaultMaxFrameSize is the largest frame payload a Conn accepts unless
// configured otherwise.
const DefaultMaxFrameSize = 16 << 20

// maxControlPayload is the limit of a control frame payload (RFC 6455 §5.5).
const maxControlPayload = 125

// closeWriteTimeout bounds the write of the Close frame when the connection
// is closed.
const closeWriteTimeout = time.Second

var (
	// ErrProtocol is returned for a frame that violates RFC 6455.
	ErrProtocol = errors.New("websocket: protocol error")
	// ErrFrameTooLarge is returned for a frame larger than the limit.
	ErrFrameTooLarge = errors.New("websocket: frame too large")
	// ErrUnsupportedData is returned for a text message read with Read.
	ErrUnsupportedData = errors.New("websocket: text messages are not supported")
	// ErrMessageTooLarge is returned by ReadMessage for a message larger
	// than its limit.
	ErrMessageTooLarge = errors.New("websocket: message too large")
	// ErrInvalidUTF8 is returned by ReadMessage for a text message that is
	// not valid UTF-8 (RFC 6455 §8.1).
	ErrInvalidUTF8 = errors.New("websocket: text message is not valid UTF-8")
)

// Conn is a WebSocket connection that implements net.Conn. Read and Write
// can be used concurrently with each other; Read must not be called from two
// goroutines at once, and neither must Write.
type Conn struct {
	nc net.Conn
	br *bufio.Reader

	// client is true for the side that opened the connection; it masks the
	// frames it sends and refuses masked frames (RFC 6455 §5.1).
	client      bool
	subprotocol string
	maxFrame    int64

	// read state, owned by the reader
	remaining int64   // payload bytes of the current data frame not read yet
	masked    bool    // the current frame is masked
	mask      [4]byte // its masking key
	maskPos   int     // position in the key
	inMessage bool    // a fragmented message is under way
	messages  bool    // ReadMessage is used: text messages are accepted
	text      bool    // the current message is a text message
	readErr   error   // sticky: the stream ended or broke
	peerClose int     // status code of the peer's Close frame

	wmu       sync.Mutex // serialises frames on the wire
	closeSent bool       // under wmu
	closeOnce sync.Once
	closeErr  error
}

// newConn wraps nc, of which br is the buffered reader the handshake used.
func newConn(nc net.Conn, br *bufio.Reader, client bool, subprotocol string, maxFrame int64) *Conn {
	if maxFrame <= 0 {
		maxFrame = DefaultMaxFrameSize
	}
	return &Conn{nc: nc, br: br, client: client, subprotocol: subprotocol, maxFrame: maxFrame}
}

// Subprotocol returns the sub-protocol negotiated in the opening handshake.
func (c *Conn) Subprotocol() string { return c.subprotocol }

// CloseCode returns the status code of the Close frame the peer sent, or 0
// if it has not sent one. It must not be called concurrently with Read.
func (c *Conn) CloseCode() int { return c.peerClose }

// NetConn returns the underlying connection.
func (c *Conn) NetConn() net.Conn { return c.nc }

// Read reads payload bytes of the binary messages the peer sends. Control
// frames are handled on the way: a ping is answered, a pong is ignored and a
// Close frame is answered and ends the stream with io.EOF, the error a
// closed TCP connection gives; CloseCode tells the status of the peer then.
func (c *Conn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	for c.remaining == 0 {
		if err := c.nextFrame(); err != nil {
			c.readErr = err
			return 0, err
		}
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.br.Read(p)
	c.unmask(p[:n])
	c.remaining -= int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF // the frame was cut short
		}
		c.readErr = err
	}
	return n, err
}

func (c *Conn) unmask(b []byte) {
	if !c.masked {
		return
	}
	for i := range b {
		b[i] ^= c.mask[c.maskPos&3]
		c.maskPos++
	}
}

// nextFrame reads frame headers until it has found the next data frame with
// a payload, handling the control frames in between.
func (c *Conn) nextFrame() error {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return err
	}
	fin := hdr[0]&0x80 != 0
	if hdr[0]&0x70 != 0 {
		return c.fail(CloseProtocolError, fmt.Errorf("%w: reserved bits set", ErrProtocol))
	}
	op := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	length := int64(hdr[1] & 0x7f)

	switch length {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return unexpected(err)
		}
		length = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return unexpected(err)
		}
		l := binary.BigEndian.Uint64(b[:])
		if l > math.MaxInt64 {
			return c.fail(CloseProtocolError, fmt.Errorf("%w: invalid payload length", ErrProtocol))
		}
		length = int64(l)
	}

	// A client masks every frame, a server none (RFC 6455 §5.1).
	if masked == c.client {
		return c.fail(CloseProtocolError, fmt.Errorf("%w: wrong masking", ErrProtocol))
	}
	c.masked = masked
	c.maskPos = 0
	if masked {
		if _, err := io.ReadFull(c.br, c.mask[:]); err != nil {
			return unexpected(err)
		}
	}

	if op >= opClose {
		return c.control(op, fin, length)
	}

	switch op {
	case opContinuation:
		if !c.inMessage {
			return c.fail(CloseProtocolError, fmt.Errorf("%w: continuation without a message", ErrProtocol))
		}
	case opBinary, opText:
		if c.inMessage {
			return c.fail(CloseProtocolError, fmt.Errorf("%w: new message inside a fragmented one", ErrProtocol))
		}
		if op == opText && !c.messages {
			return c.fail(CloseUnsupportedData, ErrUnsupportedData)
		}
		c.text = op == opText
	default:
		return c.fail(CloseProtocolError, fmt.Errorf("%w: reserved opcode %#x", ErrProtocol, op))
	}
	if length > c.maxFrame {
		return c.fail(CloseMessageTooBig, fmt.Errorf("%w: %d > %d bytes", ErrFrameTooLarge, length, c.maxFrame))
	}
	c.inMessage = !fin
	c.remaining = length
	return nil
}

// control handles a control frame.
func (c *Conn) control(op byte, fin bool, length int64) error {
	if !fin || length > maxControlPayload {
		return c.fail(CloseProtocolError, fmt.Errorf("%w: invalid control frame", ErrProtocol))
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return unexpected(err)
	}
	c.unmask(payload)

	switch op {
	case opPing:
		if err := c.writeFrame(opPong, payload); err != nil {
			return err
		}
		return nil
	case opPong:
		return nil
	case opClose:
		code := closeNoStatus
		switch {
		case len(payload) == 1:
			return c.fail(CloseProtocolError, fmt.Errorf("%w: invalid close payload", ErrProtocol))
		case len(payload) >= 2:
			code = int(binary.BigEndian.Uint16(payload))
		}
		c.peerClose = code
		// Answer with the status code received (RFC 6455 §5.5.1).
		if code == closeNoStatus {
			code = CloseNormal
		}
		_ = c.writeClose(code)
		return io.EOF
	default:
		return c.fail(CloseProtocolError, fmt.Errorf("%w: reserved opcode %#x", ErrProtocol, op))
	}
}

// ReadMessage reads the next message the peer sends, text or binary, with
// the frames of a fragmented message joined. A message larger than maxSize
// bytes ends the connection with status 1009 (Part 6 §7.5.2) and
// ErrMessageTooLarge; the payload is buffered as it arrives, so a peer that
// only announces a large frame does not make the reader allocate it. Control
// frames are handled as by Read. A Conn is read either with Read or with
// ReadMessage, not with both.
func (c *Conn) ReadMessage(maxSize int64) ([]byte, error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	c.messages = true
	var msg bytes.Buffer
	for {
		if err := c.nextFrame(); err != nil {
			if errors.Is(err, ErrFrameTooLarge) {
				err = fmt.Errorf("%w: %w", ErrMessageTooLarge, err)
			}
			c.readErr = err
			return nil, err
		}
		if int64(msg.Len())+c.remaining > maxSize {
			c.readErr = c.fail(CloseMessageTooBig, fmt.Errorf("%w: more than %d bytes", ErrMessageTooLarge, maxSize))
			return nil, c.readErr
		}
		start := msg.Len()
		if _, err := io.CopyN(&msg, c.br, c.remaining); err != nil {
			c.readErr = unexpected(err)
			return nil, c.readErr
		}
		c.unmask(msg.Bytes()[start:])
		c.remaining = 0
		if c.inMessage {
			continue
		}
		if c.text && !utf8.Valid(msg.Bytes()) {
			c.readErr = c.fail(CloseInvalidPayload, ErrInvalidUTF8)
			return nil, c.readErr
		}
		return msg.Bytes(), nil
	}
}

// WriteText sends p as one text message in a single frame. It may be called
// concurrently with itself and with Write: frames are never interleaved.
func (c *Conn) WriteText(p []byte) error {
	return c.writeFrame(opText, p)
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// fail sends a Close frame with code and returns err.
func (c *Conn) fail(code int, err error) error {
	_ = c.writeClose(code)
	return err
}

// Write sends p as one binary frame.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.writeFrame(opBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeClose sends a Close frame with code unless one has been sent.
func (c *Conn) writeClose(code int) error {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(code))
	return c.writeFrame(opClose, b[:])
}

// writeFrame sends one frame with the FIN bit set. After a Close frame
// nothing is sent any more.
func (c *Conn) writeFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeFrameLocked(op, payload)
}

func (c *Conn) writeFrameLocked(op byte, payload []byte) error {
	if c.closeSent {
		return net.ErrClosed
	}
	frame := appendFrame(make([]byte, 0, len(payload)+14), op, payload, c.client)
	if op == opClose {
		c.closeSent = true
	}
	_, err := c.nc.Write(frame)
	return err
}

// appendFrame appends a final frame with opcode op to b. A client frame is
// masked with a random key.
func appendFrame(b []byte, op byte, payload []byte, mask bool) []byte {
	b = append(b, 0x80|op)
	var maskBit byte
	if mask {
		maskBit = 0x80
	}
	switch n := len(payload); {
	case n <= 125:
		b = append(b, maskBit|byte(n))
	case n <= math.MaxUint16:
		b = append(b, maskBit|126)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, maskBit|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	if !mask {
		return append(b, payload...)
	}
	var key [4]byte
	_, _ = rand.Read(key[:])
	b = append(b, key[:]...)
	start := len(b)
	b = append(b, payload...)
	for i := range payload {
		b[start+i] ^= key[i&3]
	}
	return b
}

// Close sends a Close frame (best effort) and closes the connection. A write
// that is stuck on a peer that does not read is not waited for: the Close
// frame is skipped then.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		if c.wmu.TryLock() {
			if !c.closeSent {
				_ = c.nc.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
				_ = c.writeFrameLocked(opClose, binary.BigEndian.AppendUint16(nil, CloseNormal))
			}
			c.wmu.Unlock()
		}
		c.closeErr = c.nc.Close()
	})
	return c.closeErr
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr { return c.nc.LocalAddr() }

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// SetDeadline sets the read and write deadlines of the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error { return c.nc.SetDeadline(t) }

// SetReadDeadline sets the read deadline of the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.nc.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline of the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.nc.SetWriteDeadline(t) }

// acceptKey is the Sec-WebSocket-Accept value for key (RFC 6455 §4.2.2).
func acceptKey(key string) string {
	h := sha1.New() //nolint:gosec // see import
	h.Write([]byte(key))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
