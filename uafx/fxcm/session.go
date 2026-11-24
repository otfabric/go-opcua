// SPDX-License-Identifier: MIT

package fxcm

import (
	"context"
	"fmt"
	"sync"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// ServerAddress is where a ConnectionManager reaches the server of an
// AutomationComponent (§9.2): the current values of the SelectionLists of a
// ServerAddressConf.
type ServerAddress struct {
	// Address is the DiscoveryUrl of the server.
	Address string
	// SecurityMode and SecurityPolicyURI select the endpoint; an empty
	// SecurityPolicyURI selects the best policy both support (§9.2).
	SecurityMode      ua.MessageSecurityMode
	SecurityPolicyURI string
	// ServerURI, when not empty, is the ApplicationUri the server must
	// have (§9.2).
	ServerURI string
}

func (c *Config) serverAddress(s *serverAddress) ServerAddress {
	return ServerAddress{
		Address:           s.conf.Address,
		SecurityMode:      s.conf.SecurityMode,
		SecurityPolicyURI: s.conf.SecurityPolicyURI,
		ServerURI:         s.conf.ServerURI,
	}
}

// Dialer opens a session to the server of a ServerAddress (§9.2, §13.2).
type Dialer interface {
	Dial(ctx context.Context, addr ServerAddress) (Session, error)
}

// Session is what the ConnectionManager needs of a session to a server
// (§13.1). Its methods are the OPC UA services of the same name; an error
// is a failure of the service, a StatusCode of a result is in the result.
// It must be safe for concurrent use.
type Session interface {
	NamespaceArray(ctx context.Context) ([]string, error)
	Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error)
	Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error)
	TranslateBrowsePaths(ctx context.Context, req *ua.TranslateBrowsePathsToNodeIDsRequest) (*ua.TranslateBrowsePathsToNodeIDsResponse, error)
	Call(ctx context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error)
	Close(ctx context.Context) error
}

// ClientDialer is the default Dialer: GetEndpoints on the Address, the
// endpoint opcua.SelectEndpoint selects for the SecurityMode and
// SecurityPolicyUri (§13.2.1), a check of the ServerUri against the
// ApplicationUri of the endpoint, and an opcua.Client with automatic
// reconnection and session recovery (CL-1). With a secured endpoint the
// client verifies that the server certificate is bound to that
// ApplicationUri.
type ClientDialer struct {
	// Options are the options of every client: the ApplicationURI of the
	// ConnectionManager (required for the ownership checks, §6.6.2), the
	// certificate and key, the user identity. The endpoint options are
	// added from the selected endpoint.
	Options []opcua.Option
	// Certificate is the DER certificate given in Options, used to select
	// an endpoint whose policy can use it (opcua.SelectEndpoint).
	Certificate []byte
	// AuthType is the user token type of the identity in Options. Default
	// Anonymous.
	AuthType ua.UserTokenType
}

// Dial implements Dialer.
func (d *ClientDialer) Dial(ctx context.Context, addr ServerAddress) (Session, error) {
	eps, err := opcua.GetEndpoints(ctx, addr.Address, d.Options...)
	if err != nil {
		return nil, fmt.Errorf("fxcm: GetEndpoints %s: %w", addr.Address, err)
	}
	ep, err := opcua.SelectEndpoint(eps, addr.SecurityPolicyURI, addr.SecurityMode, d.Certificate)
	if err != nil {
		return nil, fmt.Errorf("fxcm: %s: no endpoint for %v %q: %w: %w", addr.Address, addr.SecurityMode, addr.SecurityPolicyURI, ua.StatusBadSecurityPolicyRejected, err)
	}
	if err := checkServerURI(addr, ep); err != nil {
		return nil, err
	}
	opts := append([]opcua.Option{opcua.SecurityFromEndpoint(ep, d.AuthType)}, d.Options...)
	c, err := opcua.NewClient(ep.EndpointURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("fxcm: client for %s: %w", addr.Address, err)
	}
	if err := c.Connect(ctx); err != nil {
		_ = c.Close(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("fxcm: connect %s: %w", addr.Address, err)
	}
	return &clientSession{c: c}, nil
}

// checkServerURI checks the ServerUri of addr against the ApplicationUri of
// the selected endpoint (§9.2: a ServerUri that is not null verifies the
// server).
func checkServerURI(addr ServerAddress, ep *ua.EndpointDescription) error {
	if addr.ServerURI == "" {
		return nil
	}
	got := ""
	if ep.Server != nil {
		got = ep.Server.ApplicationURI
	}
	if got != addr.ServerURI {
		return fmt.Errorf("fxcm: %s is %q, not the ServerUri %q: %w", addr.Address, got, addr.ServerURI, ua.StatusBadServerURIInvalid)
	}
	return nil
}

// clientSession is a Session of an opcua.Client.
type clientSession struct{ c *opcua.Client }

func (s *clientSession) NamespaceArray(ctx context.Context) ([]string, error) {
	return s.c.NamespaceArray(ctx)
}

func (s *clientSession) Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	return s.c.Read(ctx, req)
}

func (s *clientSession) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	return s.c.Browse(ctx, req)
}

func (s *clientSession) TranslateBrowsePaths(ctx context.Context, req *ua.TranslateBrowsePathsToNodeIDsRequest) (*ua.TranslateBrowsePathsToNodeIDsResponse, error) {
	var out *ua.TranslateBrowsePathsToNodeIDsResponse
	err := s.c.Send(ctx, req, func(r ua.Response) error {
		var ok bool
		if out, ok = r.(*ua.TranslateBrowsePathsToNodeIDsResponse); !ok {
			return fmt.Errorf("fxcm: TranslateBrowsePathsToNodeIds: a %T", r)
		}
		return nil
	})
	return out, err
}

func (s *clientSession) Call(ctx context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	return s.c.Call(ctx, req)
}

func (s *clientSession) Close(ctx context.Context) error { return s.c.Close(ctx) }

// pool holds one session per ServerAddress, shared by the runs and the
// monitor (design §5.1). A session that failed is dropped, so that the next
// use dials again.
type pool struct {
	dialer Dialer

	mu       sync.Mutex
	sessions map[ServerAddress]*pooled
	closed   bool
}

type pooled struct {
	ready chan struct{}
	s     Session
	err   error
}

func newPool(d Dialer) *pool {
	return &pool{dialer: d, sessions: map[ServerAddress]*pooled{}}
}

// get returns the session of addr, dialing it when there is none. Callers
// that ask while a dial is in progress wait for it.
func (p *pool) get(ctx context.Context, addr ServerAddress) (Session, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, managerError(ua.StatusBadShutdown, "the ConnectionManager is closed")
	}
	e := p.sessions[addr]
	if e == nil {
		e = &pooled{ready: make(chan struct{})}
		p.sessions[addr] = e
		p.mu.Unlock()
		e.s, e.err = p.dialer.Dial(ctx, addr)
		close(e.ready)
		p.mu.Lock()
		closed := p.closed
		if e.err != nil || closed {
			if p.sessions[addr] == e {
				delete(p.sessions, addr)
			}
		}
		p.mu.Unlock()
		if closed && e.err == nil {
			_ = e.s.Close(context.WithoutCancel(ctx))
			return nil, managerError(ua.StatusBadShutdown, "the ConnectionManager is closed")
		}
		return e.s, e.err
	}
	p.mu.Unlock()
	select {
	case <-e.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return e.s, e.err
}

// drop closes s and forgets it, if it is still the session of addr.
func (p *pool) drop(ctx context.Context, addr ServerAddress, s Session) {
	p.mu.Lock()
	e := p.sessions[addr]
	if e == nil || e.s != s {
		p.mu.Unlock()
		return
	}
	delete(p.sessions, addr)
	p.mu.Unlock()
	_ = s.Close(context.WithoutCancel(ctx))
}

// close closes all sessions; get fails afterwards.
func (p *pool) close(ctx context.Context) {
	p.mu.Lock()
	p.closed = true
	all := p.sessions
	p.sessions = map[ServerAddress]*pooled{}
	p.mu.Unlock()
	for _, e := range all {
		<-e.ready
		if e.err == nil {
			_ = e.s.Close(ctx)
		}
	}
}
