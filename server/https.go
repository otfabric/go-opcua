// SPDX-License-Identifier: MIT

package server

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
)

// The HTTPS transport (Part 6 §7.4), with UA Binary (§7.4.4) and, with
// EnableUAJSON, UA JSON (§7.4.5). Every request is an HTTP POST and is
// answered in the HTTP response. There is no secure conversation: "All
// HTTPS communications via a URL shall be treated as a single SecureChannel
// that is shared by multiple Clients" (§7.4.1). The server therefore keeps
// one virtual SecureChannel per security policy that it offers over HTTPS.
// It has the policy, the mode and the application instance certificate the
// session services need for the nonce signatures, and a response writer that
// hands each response to the request waiting for it. The requests go through
// the same request handler as those of opc.tcp. A Publish request is held
// until a subscription answers it, which makes it a long poll. The
// WebSockets with the sub-protocol opcua+uajson (wss_json.go) have no secure
// conversation either and use virtual SecureChannels the same way.
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

// virtualChannel is the virtual SecureChannel of one security policy.
type virtualChannel struct {
	sc *uasc.SecureChannel
	w  *channelWriter

	mu      sync.Mutex
	waiting map[uint32]chan ua.Response // by request id
}

// deliver hands resp to the request reqID if it still waits for it. It never
// blocks; the response of a request whose client has gone is dropped.
func (c *virtualChannel) deliver(reqID uint32, resp ua.Response) {
	c.mu.Lock()
	ch := c.waiting[reqID]
	delete(c.waiting, reqID)
	c.mu.Unlock()
	if ch != nil {
		ch <- resp // buffered, one response per request
	}
}

func (c *virtualChannel) wait(reqID uint32) chan ua.Response {
	ch := make(chan ua.Response, 1)
	c.mu.Lock()
	c.waiting[reqID] = ch
	c.mu.Unlock()
	return ch
}

// isWaiting reports whether request reqID still waits for its response.
func (c *virtualChannel) isWaiting(reqID uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.waiting[reqID]
	return ok
}

func (c *virtualChannel) forget(reqID uint32) {
	c.mu.Lock()
	delete(c.waiting, reqID)
	c.mu.Unlock()
}

// virtualChannels are the virtual SecureChannels of a transport without
// secure conversation, one per security policy.
type virtualChannels struct {
	srv      *Server
	channels map[string]*virtualChannel // by security policy URI
	nextID   atomic.Uint32

	// ctx ends with stop; it ends the requests that wait in the server.
	ctx    context.Context
	cancel context.CancelFunc
}

// newVirtualChannels creates the virtual channels of the security policies
// in modes, each with the mode given for it, and starts their writers.
func newVirtualChannels(s *Server, modes map[string]ua.MessageSecurityMode) *virtualChannels {
	v := &virtualChannels{srv: s, channels: make(map[string]*virtualChannel)}
	v.ctx, v.cancel = context.WithCancel(context.Background())
	for policy, mode := range modes {
		cfg := &uasc.Config{SecurityPolicyURI: policy, SecurityMode: mode, Logger: s.cfg.logger}
		if cert, key, ok := s.cfg.identityFor(policy); ok {
			cfg.Certificate, cfg.LocalPrivateKey = cert, key
		} else if policy == ua.SecurityPolicyURINone {
			cfg.Certificate = s.cfg.certificate
		}
		sc := uasc.NewCryptoChannel(cfg)
		w := newChannelWriter(sc, nil, s.cfg.logger, s.cfg.responseWriteTimeout, s.cfg.maxPendingResponses)
		c := &virtualChannel{sc: sc, w: w, waiting: make(map[uint32]chan ua.Response)}
		w.deliver = c.deliver
		w.waiting = c.isWaiting
		v.channels[policy] = c
		s.cb.addWriter(sc, w)
		go w.run()
	}
	return v
}

// stop ends the requests that wait for their response.
func (v *virtualChannels) stop() { v.cancel() }

// close stops the channels' writers. The requests must have ended.
func (v *virtualChannels) close() {
	v.cancel()
	for _, c := range v.channels {
		v.srv.cb.removeWriter(c.sc)
		c.w.close()
		<-c.w.exited
	}
}

// serve has req served on the virtual channel of policy and returns its
// response, or nil if ctx or the channels ended first.
func (v *virtualChannels) serve(ctx context.Context, policy string, req ua.Request) ua.Response {
	if policy == "" {
		// Without the header the server assumes None (Part 6 §7.4.1).
		policy = ua.SecurityPolicyURINone
	}
	c := v.channels[policy]
	if c == nil {
		return &ua.ServiceFault{ResponseHeader: responseHeader(requestHandle(req), ua.StatusBadSecurityPolicyRejected)}
	}
	if hdr := req.Header(); hdr != nil {
		v.srv.sb.touchToken(hdr.AuthenticationToken)
	}

	// A select between a ready send and a done context picks either, so an
	// ended request is caught here before it can be served.
	if ctx.Err() != nil || v.ctx.Err() != nil {
		return nil
	}
	// Take an in-flight slot like a request on a secure conversation; it
	// is released when the response has been handed over.
	if !c.w.acquire(ctx) {
		return nil
	}
	reqID := v.nextID.Add(1)
	if reqID == 0 {
		reqID = v.nextID.Add(1)
	}
	resp := c.wait(reqID)
	defer c.forget(reqID)

	select {
	case v.srv.cb.msgChan <- inbound{reqID: reqID, req: req, sc: c.sc, w: c.w}:
	case <-ctx.Done():
		c.w.release()
		return nil
	case <-v.ctx.Done():
		c.w.release()
		return nil
	}
	select {
	case r := <-resp:
		return r
	case <-ctx.Done():
		return nil
	case <-v.ctx.Done():
		return nil
	}
}

// httpsServer serves the HTTPS endpoints of a Server.
type httpsServer struct {
	srv *Server
	ln  net.Listener
	hs  *http.Server

	// vc are the virtual channels, created by start.
	vc *virtualChannels

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
		srv:    s,
		ln:     ln,
		served: make(chan struct{}),
	}
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
	h.mu.Lock()
	h.vc = newVirtualChannels(s, s.httpsModes())
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
	if started {
		h.vc.stop()
	}
	_ = h.hs.Close()
	if started {
		<-h.served
	} else {
		_ = h.ln.Close()
	}
	h.handlers.Wait()
	if started {
		h.vc.close()
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

// ServeHTTP serves one request: a POST with a UA Binary body (Part 6
// §7.4.4) or, with EnableUAJSON, a JSON message (§7.4.5).
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
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var isJSON bool
	switch {
	case err != nil:
	case mt == uasc.HTTPSContentType || mt == uasc.HTTPSContentTypeLegacy:
	case h.srv.cfg.uajson && (mt == uasc.HTTPSJSONContentType || mt == uasc.HTTPSJSONContentTypeLegacy):
		isJSON = true
	default:
		err = stderrors.New("unsupported")
	}
	if err != nil {
		want := uasc.HTTPSContentType
		if h.srv.cfg.uajson {
			want += " or " + uasc.HTTPSJSONContentType
		}
		http.Error(w, "Content-Type must be "+want, http.StatusUnsupportedMediaType)
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(httpsReadTimeout))
	body, status := readHTTPSBody(w, r, isJSON)
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return
	}
	// The response of a Publish request may take a while: the request has
	// been read, and the end of the connection must not be mistaken for a
	// slow body (net/http would cancel the request).
	_ = rc.SetReadDeadline(time.Time{})

	resp := h.handle(r.Context(), r.Header.Get(uasc.HTTPSSecurityPolicyHeader), body, isJSON)
	if resp == nil {
		// The client went away, or the server is closing.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	b, err := h.srv.encodeDirectResponse(resp, isJSON)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	timeout := h.srv.cfg.responseWriteTimeout
	if timeout <= 0 {
		timeout = defaultResponseWriteTimeout
	}
	_ = rc.SetWriteDeadline(time.Now().Add(timeout))
	if isJSON {
		// The media type of the request: application/json, or
		// application/opcua+uajson for a client that sent that.
		w.Header().Set("Content-Type", mt)
	} else {
		w.Header().Set("Content-Type", uasc.HTTPSContentType)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	_, _ = w.Write(b)
}

// readHTTPSBody reads the body of a request, at most httpsMaxRequestSize
// bytes. A JSON message may be gzip compressed (Part 6 §7.4.5); the limit
// applies to it decompressed. It returns the HTTP status of a body that
// cannot be read.
func readHTTPSBody(w http.ResponseWriter, r *http.Request, isJSON bool) ([]byte, int) {
	var in io.Reader = http.MaxBytesReader(w, r.Body, httpsMaxRequestSize)
	switch enc := r.Header.Get("Content-Encoding"); {
	case enc == "" || strings.EqualFold(enc, "identity"):
	case isJSON && strings.EqualFold(enc, "gzip"):
		zr, err := gzip.NewReader(in)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		in = io.LimitReader(zr, httpsMaxRequestSize+1)
	default:
		return nil, http.StatusUnsupportedMediaType
	}
	body, err := io.ReadAll(in)
	var tooLarge *http.MaxBytesError
	switch {
	case stderrors.As(err, &tooLarge) || len(body) > httpsMaxRequestSize:
		return nil, http.StatusRequestEntityTooLarge
	case err != nil:
		return nil, http.StatusBadRequest
	}
	return body, http.StatusOK
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
func (h *httpsServer) handle(ctx context.Context, policy string, body []byte, isJSON bool) ua.Response {
	req, fault := h.srv.decodeDirectRequest(body, isJSON)
	if fault != nil {
		return fault
	}
	return h.vc.serve(ctx, policy, req)
}

// decodeDirectRequest decodes the request of a transport without secure
// conversation, in UA Binary or as a JSON message. A body that is not a
// request is answered with the ServiceFault it returns instead.
func (s *Server) decodeDirectRequest(body []byte, isJSON bool) (ua.Request, ua.Response) {
	var (
		v   any
		err error
	)
	if isJSON {
		v, err = uasc.DecodeServiceMessageJSON(body, s.namespaceURIs())
	} else {
		_, v, err = ua.DecodeService(body)
	}
	if err != nil {
		status := ua.StatusBadDecodingError
		if stderrors.Is(err, ua.StatusBadServiceUnsupported) {
			status = ua.StatusBadServiceUnsupported
		}
		s.cfg.logger.Debug("cannot decode a request", "json", isJSON, "error", err)
		handle := uint32(0)
		if isJSON {
			handle = jsonRequestHandle(body)
		}
		return nil, &ua.ServiceFault{ResponseHeader: responseHeader(handle, status)}
	}
	req, ok := v.(ua.Request)
	if !ok {
		return nil, &ua.ServiceFault{ResponseHeader: responseHeader(0, ua.StatusBadServiceUnsupported)}
	}
	return req, nil
}

// jsonRequestHandle returns the RequestHandle of a JSON message that cannot
// be decoded as a whole, 0 if it has none, so that the fault answering it
// can be correlated (Part 4 §7.33: the handle is returned in the response).
func jsonRequestHandle(body []byte) uint32 {
	type header struct {
		RequestHeader struct{ RequestHandle uint32 }
	}
	var m struct {
		header
		Body header // the 1.04 form
	}
	if json.Unmarshal(body, &m) != nil {
		return 0
	}
	if m.RequestHeader.RequestHandle != 0 {
		return m.RequestHeader.RequestHandle
	}
	return m.Body.RequestHeader.RequestHandle
}

// encodeDirectResponse encodes the response of a transport without secure
// conversation. A response that cannot be encoded is replaced by a
// ServiceFault with BadEncodingError.
func (s *Server) encodeDirectResponse(resp ua.Response, isJSON bool) ([]byte, error) {
	encode := func(v ua.Response) ([]byte, error) {
		if isJSON {
			return uasc.EncodeServiceMessageJSON(v, s.namespaceURIs())
		}
		return uasc.EncodeServiceMessage(v)
	}
	b, err := encode(resp)
	if err != nil {
		s.cfg.logger.Warn("cannot encode a response", "type", fmt.Sprintf("%T", resp), "json", isJSON, "error", err)
		b, err = encode(&ua.ServiceFault{ResponseHeader: responseHeader(requestHandleOf(resp), ua.StatusBadEncodingError)})
	}
	return b, err
}

// namespaceURIs returns the NamespaceArray of the server.
func (s *Server) namespaceURIs() []string {
	v := s.nsView.Load()
	if v == nil {
		return nil
	}
	uris := make([]string, len(*v))
	for i, ns := range *v {
		uris[i] = ns.Name()
	}
	return uris
}
