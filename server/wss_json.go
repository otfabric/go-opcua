// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// The WebSocket transport with the sub-protocol opcua+uajson (Part 6 §7.5.2,
// transport profile wss-uajson). The opc.wss listener hands such
// connections over after the WebSocket upgrade. Each WebSocket message is a
// JSON message (Part 6 §5.4.9) with one request, and the server answers it
// with one JSON message. There is no HEL/ACK and no secure conversation: the
// requests are served on a virtual SecureChannel with the security policy
// None, shared by all such connections, as HTTPS does (https.go).
//
// The requests of a connection are served concurrently and answered as they
// complete, so a Publish request that waits for a notification holds up no
// other request. The RequestHandle of a response tells the client which
// request it answers (Part 4 §7.33).
const (
	// wssJSONMaxInFlight is the number of requests of one connection that
	// are served at the same time. The connection is not read while that
	// many wait for their response.
	wssJSONMaxInFlight = 64

	// wssJSONIdleTimeout is how long a connection without a request in
	// flight is kept open.
	wssJSONIdleTimeout = httpsIdleTimeout
)

// wssJSONServer serves the opcua+uajson connections of a Server.
type wssJSONServer struct {
	srv *Server
	vc  *virtualChannels

	mu     sync.Mutex
	closed bool
	conns  map[uacp.MessageConn]struct{}
	wg     sync.WaitGroup // connections being served
}

func newWSSJSONServer(s *Server) *wssJSONServer {
	return &wssJSONServer{srv: s, conns: make(map[uacp.MessageConn]struct{})}
}

// start creates the virtual channel. It is called before the first
// connection is served.
func (w *wssJSONServer) start() {
	w.vc = newVirtualChannels(w.srv, map[string]ua.MessageSecurityMode{ua.SecurityPolicyURINone: ua.MessageSecurityModeNone})
}

// close closes the connections, ends their requests and waits for them.
func (w *wssJSONServer) close() {
	w.mu.Lock()
	w.closed = true
	conns := w.conns
	w.conns = make(map[uacp.MessageConn]struct{})
	w.mu.Unlock()
	if w.vc != nil {
		w.vc.stop()
	}
	for c := range conns {
		_ = c.Close()
	}
	w.wg.Wait()
	if w.vc != nil {
		w.vc.close()
	}
}

// add registers a connection being served; it reports false once the server
// is closing.
func (w *wssJSONServer) add(c uacp.MessageConn) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	w.conns[c] = struct{}{}
	w.wg.Add(1)
	return true
}

func (w *wssJSONServer) remove(c uacp.MessageConn) {
	w.mu.Lock()
	delete(w.conns, c)
	w.mu.Unlock()
	_ = c.Close()
	w.wg.Done()
}

// wssJSONConn is the state of one connection.
type wssJSONConn struct {
	c uacp.MessageConn

	// slots limits the requests in flight.
	slots chan struct{}

	// mu guards inFlight and the read deadline that depends on it: a
	// connection is only idle without a request in flight.
	mu       sync.Mutex
	inFlight int

	// wmu serialises the responses with their write deadlines.
	wmu sync.Mutex
}

// begin counts a request in flight.
func (cc *wssJSONConn) begin() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.inFlight++
	_ = cc.c.SetReadDeadline(time.Time{})
}

// end counts a request done; the connection is idle without any.
func (cc *wssJSONConn) end() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.inFlight--
	if cc.inFlight == 0 {
		_ = cc.c.SetReadDeadline(time.Now().Add(wssJSONIdleTimeout))
	}
}

// serve serves the requests of one connection until it closes. It runs in a
// goroutine of the listener.
func (w *wssJSONServer) serve(c uacp.MessageConn) {
	if !w.add(c) {
		_ = c.Close()
		return
	}
	// The end of the connection ends its requests: their responses have
	// nowhere to go.
	ctx, cancel := context.WithCancel(context.Background())
	var requests sync.WaitGroup
	defer func() {
		cancel()
		_ = c.Close() // unblocks the writes
		requests.Wait()
		w.remove(c)
	}()
	defer func() {
		if p := recover(); p != nil {
			logPanic(w.srv.cfg.logger, "serving an opcua+uajson connection", p)
		}
	}()

	cc := &wssJSONConn{c: c, slots: make(chan struct{}, wssJSONMaxInFlight)}
	_ = c.SetReadDeadline(time.Now().Add(wssJSONIdleTimeout))
	for {
		// A message larger than the limit closes the connection with
		// status 1009 (Part 6 §7.5.2).
		b, err := c.ReadMessage(httpsMaxRequestSize)
		if err != nil {
			w.srv.cfg.logger.Debug("wss json: connection ended", "remote_addr", c.RemoteAddr(), "error", err)
			return
		}
		select {
		case cc.slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		cc.begin()
		requests.Add(1)
		go func() {
			defer requests.Done()
			defer func() { <-cc.slots }()
			defer cc.end()
			w.handle(ctx, cc, b)
		}()
	}
}

// handle serves one request and writes its response.
func (w *wssJSONServer) handle(ctx context.Context, cc *wssJSONConn, body []byte) {
	defer func() {
		if p := recover(); p != nil {
			logPanic(w.srv.cfg.logger, "serving an opcua+uajson request", p)
		}
	}()
	req, resp := w.srv.decodeDirectRequest(body, true)
	if req != nil {
		if resp = w.vc.serve(ctx, ua.SecurityPolicyURINone, req); resp == nil {
			return // the connection or the server ended
		}
	}
	b, err := w.srv.encodeDirectResponse(resp, true)
	if err != nil {
		_ = cc.c.Close()
		return
	}
	timeout := w.srv.cfg.responseWriteTimeout
	if timeout <= 0 {
		timeout = defaultResponseWriteTimeout
	}
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	_ = cc.c.SetWriteDeadline(time.Now().Add(timeout))
	if err := cc.c.WriteMessage(b); err != nil {
		w.srv.cfg.logger.Debug("wss json: cannot write a response", "error", err)
		_ = cc.c.Close()
	}
}
