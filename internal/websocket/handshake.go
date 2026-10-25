// SPDX-License-Identifier: MIT

package websocket

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxHandshakeSize bounds the HTTP request or response of the opening
// handshake, headers included.
const maxHandshakeSize = 16 << 10

// ErrHandshake is returned when the opening handshake fails.
var ErrHandshake = errors.New("websocket: handshake failed")

// limitedReader returns a buffered reader of nc that reads at most
// maxHandshakeSize bytes until the returned function lifts the limit.
func limitedReader(nc net.Conn) (*bufio.Reader, func()) {
	lr := &io.LimitedReader{R: nc, N: maxHandshakeSize}
	return bufio.NewReader(lr), func() { lr.N = math.MaxInt64 }
}

// watch applies ctx to the blocking I/O on nc until the returned function is
// called; the function reports whether ctx ended first.
func watch(ctx context.Context, nc net.Conn) func() error {
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = nc.SetDeadline(time.Now()) })
	return func() error {
		if !stop() {
			return ctx.Err()
		}
		_ = nc.SetDeadline(time.Time{})
		return nil
	}
}

// ClientOptions configure the opening handshake of a client.
type ClientOptions struct {
	// Subprotocols are offered in Sec-WebSocket-Protocol, in order of
	// preference. The server has to select one of them.
	Subprotocols []string
	// Header holds additional request headers.
	Header http.Header
	// MaxFrameSize limits the payload of a received frame;
	// DefaultMaxFrameSize if zero.
	MaxFrameSize int64
}

// Client performs the opening handshake (RFC 6455 §4.1) on nc, which is
// already connected (and TLS secured) to the host of u. Only the host, path
// and query of u are used. The handshake is bounded by ctx.
func Client(ctx context.Context, nc net.Conn, u *url.URL, opts ClientOptions) (*Conn, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])

	done := watch(ctx, nc)
	c, err := clientHandshake(nc, u, key, opts)
	if cerr := done(); cerr != nil {
		return nil, cerr
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// The connection deadline is the deadline of ctx: it may expire a
		// moment before ctx reports it.
		if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	return c, nil
}

func clientHandshake(nc net.Conn, u *url.URL, key string, opts ClientOptions) (*Conn, error) {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: %s\r\n", path, u.Host)
	b.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	if len(opts.Subprotocols) > 0 {
		fmt.Fprintf(&b, "Sec-WebSocket-Protocol: %s\r\n", strings.Join(opts.Subprotocols, ", "))
	}
	for k, vs := range opts.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(nc, b.String()); err != nil {
		return nil, err
	}

	br, unlimit := limitedReader(nc)
	req := &http.Request{Method: http.MethodGet, URL: u}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("%w: server answered %s", ErrHandshake, resp.Status)
	}
	if !headerHasToken(resp.Header, "Upgrade", "websocket") || !headerHasToken(resp.Header, "Connection", "upgrade") {
		return nil, fmt.Errorf("%w: missing upgrade headers", ErrHandshake)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		return nil, fmt.Errorf("%w: wrong Sec-WebSocket-Accept", ErrHandshake)
	}
	proto := strings.TrimSpace(resp.Header.Get("Sec-WebSocket-Protocol"))
	if len(opts.Subprotocols) > 0 {
		// Part 6 §7.5.2: a client whose sub-protocol the server does not
		// support closes the connection and reports an error.
		ok := false
		for _, p := range opts.Subprotocols {
			ok = ok || p == proto
		}
		if !ok {
			return nil, fmt.Errorf("%w: server selected sub-protocol %q, offered %v", ErrHandshake, proto, opts.Subprotocols)
		}
	}
	unlimit()
	return newConn(nc, br, true, proto, opts.MaxFrameSize), nil
}

// ServerOptions configure the opening handshake of a server.
type ServerOptions struct {
	// Subprotocols are the sub-protocols the server supports. The first one
	// the client offers is selected; a client that offers none of them is
	// refused.
	Subprotocols []string
	// MaxFrameSize limits the payload of a received frame;
	// DefaultMaxFrameSize if zero.
	MaxFrameSize int64
}

// Accept reads the opening handshake of a client from nc and answers it
// (RFC 6455 §4.2). The caller bounds it with a deadline on nc. A request that
// is not a valid WebSocket upgrade is refused with an HTTP error status.
func Accept(nc net.Conn, opts ServerOptions) (*Conn, *http.Request, error) {
	br, unlimit := limitedReader(nc)
	req, err := http.ReadRequest(br)
	if err != nil {
		reject(nc, http.StatusBadRequest, "")
		return nil, nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	_ = req.Body.Close()

	switch {
	case req.Method != http.MethodGet:
		reject(nc, http.StatusMethodNotAllowed, "")
		return nil, nil, fmt.Errorf("%w: method %s", ErrHandshake, req.Method)
	case !req.ProtoAtLeast(1, 1):
		reject(nc, http.StatusBadRequest, "")
		return nil, nil, fmt.Errorf("%w: %s", ErrHandshake, req.Proto)
	case !headerHasToken(req.Header, "Upgrade", "websocket") || !headerHasToken(req.Header, "Connection", "upgrade"):
		reject(nc, http.StatusUpgradeRequired, "Upgrade: websocket\r\nConnection: Upgrade\r\n")
		return nil, nil, fmt.Errorf("%w: not a WebSocket upgrade", ErrHandshake)
	case req.Header.Get("Sec-WebSocket-Version") != "13":
		reject(nc, http.StatusUpgradeRequired, "Sec-WebSocket-Version: 13\r\n")
		return nil, nil, fmt.Errorf("%w: unsupported version %q", ErrHandshake, req.Header.Get("Sec-WebSocket-Version"))
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	if k, err := base64.StdEncoding.DecodeString(key); err != nil || len(k) != 16 {
		reject(nc, http.StatusBadRequest, "")
		return nil, nil, fmt.Errorf("%w: invalid Sec-WebSocket-Key", ErrHandshake)
	}

	proto := selectSubprotocol(req.Header, opts.Subprotocols)
	if proto == "" && len(opts.Subprotocols) > 0 {
		reject(nc, http.StatusBadRequest, "")
		return nil, nil, fmt.Errorf("%w: no supported sub-protocol in %q", ErrHandshake, req.Header.Values("Sec-WebSocket-Protocol"))
	}

	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Accept: %s\r\n", acceptKey(key))
	if proto != "" {
		fmt.Fprintf(&b, "Sec-WebSocket-Protocol: %s\r\n", proto)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(nc, b.String()); err != nil {
		return nil, nil, err
	}
	unlimit()
	return newConn(nc, br, false, proto, opts.MaxFrameSize), req, nil
}

// reject answers a handshake request with an HTTP error.
func reject(nc net.Conn, status int, extra string) {
	_, _ = fmt.Fprintf(nc, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status), extra)
}

// selectSubprotocol returns the first sub-protocol offered in h that is in
// supported.
func selectSubprotocol(h http.Header, supported []string) string {
	for _, v := range h.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			for _, s := range supported {
				if p == s {
					return p
				}
			}
		}
	}
	return ""
}

// headerHasToken reports whether the comma separated header name contains
// token, case-insensitively.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}
