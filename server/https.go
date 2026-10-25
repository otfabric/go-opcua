// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
)

// The HTTPS transport (Part 6 §7.4, UA Binary). Every request is an HTTP
// POST and is answered in the HTTP response. There is no secure
// conversation: "All HTTPS communications via a URL shall be treated as a
// single SecureChannel that is shared by multiple Clients" (§7.4.1). The
// server therefore keeps one virtual SecureChannel per security policy that
// it offers over HTTPS. It has the policy, the mode and the application
// instance certificate the session services need for the nonce signatures,
// and a response writer that hands each response to the HTTP request
// waiting for it. The requests go through the same request handler as those
// of opc.tcp. A Publish request is held until a subscription answers it,
// which makes it a long poll.
const (
	// httpsMaxRequestSize limits the body of an HTTPS request.
	httpsMaxRequestSize = uacp.DefaultMaxMessageSize

	// httpsReadTimeout bounds reading the headers and, separately, the body
	// of a request: a peer that sends them slowly (slowloris) is dropped.
	httpsReadTimeout = 10 * time.Second

	// httpsIdleTimeout is how long an idle keep-alive connection is kept.
	httpsIdleTimeout = 2 * time.Minute

	// httpsMaxHeaderBytes limits the request headers.
	httpsMaxHeaderBytes = 64 << 10
)

// httpsChannel is the virtual SecureChannel of one security policy.
type httpsChannel struct {
	sc *uasc.SecureChannel
	w  *channelWriter

	mu      sync.Mutex
	waiting map[uint32]chan ua.Response // by request id
}

// deliver hands resp to the request reqID if it still waits for it. It never
// blocks; the response of a request whose client has gone is dropped.
func (c *httpsChannel) deliver(reqID uint32, resp ua.Response) {
	c.mu.Lock()
	ch := c.waiting[reqID]
	delete(c.waiting, reqID)
	c.mu.Unlock()
	if ch != nil {
		ch <- resp // buffered, one response per request
	}
}

func (c *httpsChannel) wait(reqID uint32) chan ua.Response {
	ch := make(chan ua.Response, 1)
	c.mu.Lock()
	c.waiting[reqID] = ch
	c.mu.Unlock()
	return ch
}

// isWaiting reports whether request reqID still waits for its response.
func (c *httpsChannel) isWaiting(reqID uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.waiting[reqID]
	return ok
}

func (c *httpsChannel) forget(reqID uint32) {
	c.mu.Lock()
	delete(c.waiting, reqID)
	c.mu.Unlock()
}

// httpsServer serves the HTTPS endpoints of a Server.
type httpsServer struct {
	srv *Server
	ln  net.Listener
	hs  *http.Server

	channels map[string]*httpsChannel // by security policy URI
	nextID   atomic.Uint32

	// ctx ends with close; it ends the requests that wait in the server.
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	started  bool
	closed   bool
	handlers sync.WaitGroup // requests being served
	served   chan struct{}  // closed when Serve has returned
}

// newHTTPSServer listens on addr and prepares the virtual channels. Serving
// starts with start.
func newHTTPSServer(ctx context.Context, s *Server, addr string, tlsConfig *tls.Config) (*httpsServer, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	h := &httpsServer{
		srv:      s,
		ln:       ln,
		channels: make(map[string]*httpsChannel),
		served:   make(chan struct{}),
	}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.hs = &http.Server{
		Handler:           h,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: httpsReadTimeout,
		IdleTimeout:       httpsIdleTimeout,
		MaxHeaderBytes:    httpsMaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.cfg.logger.Handler(), slog.LevelDebug),
	}
	return h, nil
}

// httpsModes returns the security mode of the virtual channel of each
// security policy offered over HTTPS: the strongest mode enabled for it.
func (s *Server) httpsModes() map[string]ua.MessageSecurityMode {
	modes := make(map[string]ua.MessageSecurityMode)
	for _, sec := range s.cfg.enabledSec {
		if !uasc.HTTPSPolicySupported(sec.secPolicy) {
			continue
		}
		if sec.secMode > modes[sec.secPolicy] {
			modes[sec.secPolicy] = sec.secMode
		}
	}
	if len(s.cfg.enabledSec) == 0 {
		modes[ua.SecurityPolicyURINone] = ua.MessageSecurityModeNone
	}
	return modes
}

// start creates the virtual channels and starts serving.
func (h *httpsServer) start() {
	s := h.srv
	for policy, mode := range s.httpsModes() {
		cfg := &uasc.Config{SecurityPolicyURI: policy, SecurityMode: mode, Logger: s.cfg.logger}
		if cert, key, ok := s.cfg.identityFor(policy); ok {
			cfg.Certificate, cfg.LocalPrivateKey = cert, key
		} else if policy == ua.SecurityPolicyURINone {
			cfg.Certificate = s.cfg.certificate
		}
		sc := uasc.NewCryptoChannel(cfg)
		w := newChannelWriter(sc, nil, s.cfg.logger, s.cfg.responseWriteTimeout, s.cfg.maxPendingResponses)
		c := &httpsChannel{sc: sc, w: w, waiting: make(map[uint32]chan ua.Response)}
		w.deliver = c.deliver
		w.waiting = c.isWaiting
		h.channels[policy] = c
		s.cb.addWriter(sc, w)
		go w.run()
	}
	h.mu.Lock()
	h.started = true
	h.mu.Unlock()
	go func() {
		defer close(h.served)
		err := h.hs.ServeTLS(h.ln, "", "")
		if err != nil && !stderrors.Is(err, http.ErrServerClosed) {
			s.cfg.logger.Warn("https: serving stopped", "error", err)
		}
	}()
}

// close stops serving: the listener and the connections are closed, the
// requests that wait are ended and waited for.
func (h *httpsServer) close() {
	h.mu.Lock()
	h.closed = true
	started := h.started
	h.mu.Unlock()
	h.cancel()
	_ = h.hs.Close()
	if started {
		<-h.served
	} else {
		_ = h.ln.Close()
	}
	h.handlers.Wait()
	for _, c := range h.channels {
		h.srv.cb.removeWriter(c.sc)
		c.w.close()
		<-c.w.exited
	}
}

// enter registers a request being served; it reports false once the server
// is closing.
func (h *httpsServer) enter() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.handlers.Add(1)
	return true
}

// ServeHTTP serves one request: Part 6 §7.4.4, a POST with a UA Binary body.
func (h *httpsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.enter() {
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	defer h.handlers.Done()
	defer func() {
		if p := recover(); p != nil {
			logPanic(h.srv.cfg.logger, "serving an HTTPS request", p)
		}
	}()

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "OPC UA requests are HTTP POST requests", http.StatusMethodNotAllowed)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil ||
		(mt != uasc.HTTPSContentType && mt != uasc.HTTPSContentTypeLegacy) {
		http.Error(w, "Content-Type must be "+uasc.HTTPSContentType, http.StatusUnsupportedMediaType)
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(httpsReadTimeout))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httpsMaxRequestSize))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if stderrors.As(err, &tooLarge) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}
	// The response of a Publish request may take a while: the request has
	// been read, and the end of the connection must not be mistaken for a
	// slow body (net/http would cancel the request).
	_ = rc.SetReadDeadline(time.Time{})

	resp := h.handle(r.Context(), r.Header.Get(uasc.HTTPSSecurityPolicyHeader), body)
	if resp == nil {
		// The client went away, or the server is closing.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	b, err := uasc.EncodeServiceMessage(resp)
	if err != nil {
		h.srv.cfg.logger.Warn("https: cannot encode response", "type", fmt.Sprintf("%T", resp), "error", err)
		b, err = uasc.EncodeServiceMessage(&ua.ServiceFault{ResponseHeader: responseHeader(requestHandleOf(resp), ua.StatusBadEncodingError)})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	timeout := h.srv.cfg.responseWriteTimeout
	if timeout <= 0 {
		timeout = defaultResponseWriteTimeout
	}
	_ = rc.SetWriteDeadline(time.Now().Add(timeout))
	w.Header().Set("Content-Type", uasc.HTTPSContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	_, _ = w.Write(b)
}

// publishAbandoned reports whether a parked Publish request can no longer be
// answered because the HTTP request that carried it has ended.
func (s *Server) publishAbandoned(pr PubReq) bool {
	w := s.channelWriter(pr.Channel)
	return w != nil && w.waiting != nil && !w.waiting(pr.ID)
}

// requestHandleOf returns the request handle a response carries.
func requestHandleOf(resp ua.Response) uint32 {
	if hdr := resp.Header(); hdr != nil {
		return hdr.RequestHandle
	}
	return 0
}

// handle decodes a request, has it served and returns its response, or nil
// if ctx or the server ended first.
func (h *httpsServer) handle(ctx context.Context, policy string, body []byte) ua.Response {
	_, v, err := ua.DecodeService(body)
	if err != nil {
		status := ua.StatusBadDecodingError
		if stderrors.Is(err, ua.StatusBadServiceUnsupported) {
			status = ua.StatusBadServiceUnsupported
		}
		return &ua.ServiceFault{ResponseHeader: responseHeader(0, status)}
	}
	req, ok := v.(ua.Request)
	if !ok {
		return &ua.ServiceFault{ResponseHeader: responseHeader(0, ua.StatusBadServiceUnsupported)}
	}
	if policy == "" {
		// Without the header the server assumes None (Part 6 §7.4.1).
		policy = ua.SecurityPolicyURINone
	}
	c := h.channels[policy]
	if c == nil {
		return &ua.ServiceFault{ResponseHeader: responseHeader(requestHandle(req), ua.StatusBadSecurityPolicyRejected)}
	}
	if hdr := req.Header(); hdr != nil {
		h.srv.sb.touchToken(hdr.AuthenticationToken)
	}

	// A select between a ready send and a done context picks either, so an
	// ended request is caught here before it can be served.
	if ctx.Err() != nil || h.ctx.Err() != nil {
		return nil
	}
	// Take an in-flight slot like a request on a secure conversation; it
	// is released when the response has been handed over.
	if !c.w.acquire(ctx) {
		return nil
	}
	reqID := h.nextID.Add(1)
	if reqID == 0 {
		reqID = h.nextID.Add(1)
	}
	resp := c.wait(reqID)
	defer c.forget(reqID)

	select {
	case h.srv.cb.msgChan <- inbound{reqID: reqID, req: req, sc: c.sc, w: c.w}:
	case <-ctx.Done():
		c.w.release()
		return nil
	case <-h.ctx.Done():
		c.w.release()
		return nil
	}
	select {
	case r := <-resp:
		return r
	case <-ctx.Done():
		return nil
	case <-h.ctx.Done():
		return nil
	}
}
