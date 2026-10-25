// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/websocket"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// The UA JSON mappings of HTTPS and WebSockets (transport profiles
// https-uajson and wss-uajson) have no secure conversation either. A service
// request or response is a JSON message: "Messages are encoded as
// ExtensionObjects" (Part 6 §5.4.9), which in the JSON encoding of OPC UA
// 1.05 is a JSON object with the UaTypeId of the DataType of the message
// followed by the fields of the structure (Part 6 §5.4.2.16). The messages
// are written in the compact form (Part 6 §7.4.2, Table 80: application/json
// is "OPC UA JSON Compact"); the verbose form and the 1.04 form are accepted
// as well. Over HTTPS each message is the body of an HTTP POST or response
// with the Content-Type application/json (Part 6 §7.4.5). Over a WebSocket
// with the sub-protocol opcua+uajson each message is one WebSocket message
// (Part 6 §7.5.2).
//
// Without a secure conversation the security policy can only matter for the
// session signatures. HTTPS names it in the OPCUA-SecurityPolicy header; a
// WebSocket has no such header, so wss-uajson endpoints use the policy None
// and TLS alone protects the messages.
const (
	// HTTPSJSONContentType is the Content-Type of JSON messages over HTTPS
	// (Part 6 §7.4.5).
	HTTPSJSONContentType = "application/json"

	// HTTPSJSONContentTypeLegacy is the Content-Type of JSON messages over
	// HTTPS that UA-.NETStandard uses. A server accepts it next to
	// HTTPSJSONContentType and answers with the Content-Type of the request.
	HTTPSJSONContentTypeLegacy = "application/opcua+uajson"

	// MaxWebSocketJSONMessageSize is the size limit of a JSON message a
	// client receives over a WebSocket; a larger one ends the connection
	// with status 1009 (Part 6 §7.5.2).
	MaxWebSocketJSONMessageSize = MaxHTTPSMessageSize

	// maxIdleWebSockets is the number of idle WebSockets a wss-uajson
	// channel keeps for the next requests.
	maxIdleWebSockets = 8

	// webSocketIdleTimeout is how long a wss-uajson channel keeps an idle
	// WebSocket. It is shorter than the time a server waits for the next
	// request, so that a request is not sent on a WebSocket the server is
	// closing.
	webSocketIdleTimeout = 30 * time.Second
)

// EncodeServiceMessageJSON encodes a service request or response as a JSON
// message (Part 6 §5.4.9) in the compact form. With namespaces, the
// NamespaceArray of the server, the NodeIds of namespaces other than 0 are
// written with their namespace URI (Part 6 §5.4.2.10).
func EncodeServiceMessageJSON(v any, namespaces []string) ([]byte, error) {
	if ua.ServiceTypeID(v) == 0 {
		return nil, fmt.Errorf("%w: %T", errors.ErrUnknownService, v)
	}
	return ua.EncodeJSON(ua.NewExtensionObject(v), ua.WithNamespaceArray(namespaces))
}

// DecodeServiceMessageJSON decodes a JSON message (Part 6 §5.4.9) into the
// service request or response it holds. It accepts the compact and verbose
// forms of OPC UA 1.05 and the form of 1.04. namespaces is the NamespaceArray
// the namespace URIs of NodeIds are looked up in. The errors wrap
// ua.StatusBadDecodingError, or ua.StatusBadServiceUnsupported for a message
// that is not a service request or response.
//
// The compact form leaves out the fields that have their default value, and
// a decoded message has no value for them: a structure or a NodeId that was
// left out is nil. The message is therefore completed the way the UA Binary
// decoder fills in every field, by passing it through UA Binary, so that the
// services see the same message whatever the encoding.
func DecodeServiceMessageJSON(b []byte, namespaces []string) (any, error) {
	var x *ua.ExtensionObject
	if err := ua.DecodeJSON(b, &x, ua.WithNamespaceArray(namespaces)); err != nil {
		return nil, err
	}
	if x == nil || x.Value == nil {
		return nil, fmt.Errorf("%w: the message is not a service message", ua.StatusBadDecodingError)
	}
	if ua.ServiceTypeID(x.Value) == 0 {
		return nil, fmt.Errorf("%w: %T is not a service message", ua.StatusBadServiceUnsupported, x.Value)
	}
	bin, err := EncodeServiceMessage(x.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: %T: %v", ua.StatusBadDecodingError, x.Value, err)
	}
	_, v, err := ua.DecodeService(bin)
	if err != nil {
		return nil, fmt.Errorf("%w: %T: %v", ua.StatusBadDecodingError, x.Value, err)
	}
	return v, nil
}

// NewWebSocketJSONChannel returns a client channel to an opc.wss endpoint
// with the transport profile wss-uajson (Part 6 §7.5.2). There is no secure
// conversation: every request is a JSON message sent over a TLS secured
// WebSocket with the sub-protocol opcua+uajson, which dialer opens with its
// TLSConfig, and the next message on that WebSocket is the response. A
// WebSocket carries one request at a time, so a server that serves the
// requests of a WebSocket one after the other does not hold the others up
// behind a Publish request: the channel opens another WebSocket while all
// are busy, and keeps up to 8 idle ones for the next requests. Open does
// nothing, the WebSockets are opened when needed.
//
// cfg must have the security policy None and the mode None: unlike HTTPS a
// WebSocket cannot name a policy for the session signatures. errCh receives
// the errors that ask for recovery, as for NewHTTPSChannel.
func NewWebSocketJSONChannel(endpoint string, dialer *uacp.Dialer, cfg *Config, errCh chan<- error) (*SecureChannel, error) {
	if err := checkDirectConfig(cfg, errCh); err != nil {
		return nil, err
	}
	if cfg.SecurityPolicyURI != ua.SecurityPolicyURINone {
		return nil, fmt.Errorf("%w: %s over opcua+uajson, which only has None", errors.ErrUnsupportedSecurityPolicy, cfg.SecurityPolicyURI)
	}
	if _, err := uacp.ParseWebSocketEndpoint(endpoint); err != nil {
		return nil, err
	}
	if dialer == nil {
		dialer = &uacp.Dialer{}
	}
	t := &directTransport{
		json: true,
		ws: &wsPool{
			dial:  func(ctx context.Context) (uacp.MessageConn, error) { return dialer.DialWebSocketJSON(ctx, endpoint) },
			conns: make(map[uacp.MessageConn]struct{}),
		},
	}
	return newDirectChannel(endpoint, cfg, errCh, t), nil
}

// IsWebSocketJSON reports whether the channel is a wss-uajson channel
// (NewWebSocketJSONChannel).
func (s *SecureChannel) IsWebSocketJSON() bool { return s.direct != nil && s.direct.ws != nil }

// wsPool holds the WebSockets of a wss-uajson channel.
type wsPool struct {
	dial func(ctx context.Context) (uacp.MessageConn, error)

	mu     sync.Mutex
	idle   []idleConn
	conns  map[uacp.MessageConn]struct{} // all open ones, idle or busy
	closed bool
}

// idleConn is an idle WebSocket and when it became idle.
type idleConn struct {
	c     uacp.MessageConn
	since time.Time
}

// get returns an idle WebSocket or opens a new one.
func (p *wsPool) get(ctx context.Context) (uacp.MessageConn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.ErrSecureChannelClosed
	}
	var stale []uacp.MessageConn
	for n := len(p.idle); n > 0; n-- {
		ic := p.idle[n-1]
		p.idle = p.idle[:n-1]
		if time.Since(ic.since) < webSocketIdleTimeout {
			p.mu.Unlock()
			closeAll(stale)
			return ic.c, nil
		}
		delete(p.conns, ic.c)
		stale = append(stale, ic.c)
	}
	p.mu.Unlock()
	closeAll(stale)

	c, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return nil, errors.ErrSecureChannelClosed
	}
	p.conns[c] = struct{}{}
	return c, nil
}

// put returns a WebSocket that is done with its request.
func (p *wsPool) put(c uacp.MessageConn) {
	p.mu.Lock()
	if !p.closed && len(p.idle) < maxIdleWebSockets {
		p.idle = append(p.idle, idleConn{c: c, since: time.Now()})
		p.mu.Unlock()
		return
	}
	delete(p.conns, c)
	p.mu.Unlock()
	_ = c.Close()
}

// discard closes a WebSocket whose state is unknown: its request failed or
// was given up.
func (p *wsPool) discard(c uacp.MessageConn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	_ = c.Close()
}

// close closes all WebSockets; the requests on them fail.
func (p *wsPool) close() {
	p.mu.Lock()
	p.closed = true
	conns := p.conns
	p.conns = make(map[uacp.MessageConn]struct{})
	p.idle = nil
	p.mu.Unlock()
	for c := range conns {
		_ = c.Close()
	}
}

func closeAll(conns []uacp.MessageConn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

// exchangeWebSocket sends an encoded request on a WebSocket of the channel
// and returns the message that answers it. The end of ctx closes the
// WebSocket: a response may still be on its way, so it cannot carry another
// request.
func (s *SecureChannel) exchangeWebSocket(ctx context.Context, reqID uint32, body []byte) ([]byte, error) {
	p := s.direct.ws
	c, err := p.get(ctx)
	switch {
	case stderrors.Is(err, errors.ErrSecureChannelClosed):
		return nil, err
	case err != nil:
		return nil, &lostError{err}
	}
	stop := context.AfterFunc(ctx, func() { p.discard(c) })
	if err := c.WriteMessage(body); err != nil {
		stop()
		p.discard(c)
		return nil, &lostError{err}
	}
	b, err := c.ReadMessage(MaxWebSocketJSONMessageSize)
	if !stop() {
		return nil, ctx.Err() // discarded
	}
	if err != nil {
		p.discard(c)
		if stderrors.Is(err, websocket.ErrMessageTooLarge) {
			return nil, fmt.Errorf("%w: response larger than %d bytes", errors.ErrMessageTooLarge, MaxWebSocketJSONMessageSize)
		}
		return nil, &lostError{err}
	}
	p.put(c)
	s.cfg.Logger.Debug("wss recv", "request_id", reqID, "bytes", len(b))
	return b, nil
}
