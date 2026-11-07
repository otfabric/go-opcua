// SPDX-License-Identifier: MIT

package server

import (
	"net"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// SessionObserver is told about client connections and sessions as they
// begin and end, for logging and auditing in the application. Set it with
// [WithSessionObserver].
//
// The methods are called synchronously where the event happens: on the
// goroutine of the connection, or on the request dispatcher for the session
// events. The dispatcher handles the requests of all clients, so a session
// method that blocks holds up every client of the server, not only its own.
// They must not block; hand slow work to another goroutine. A
// panicking method is recovered and logged, and does not affect the
// connection or the session. Embed [BaseSessionObserver] to implement only
// some of the methods.
type SessionObserver interface {
	// OnConnectionOpened is called when a client connection completed the
	// transport handshake (Hello/Acknowledge, Part 6 §7.1.3), for opc.tcp,
	// reverse and opc.wss connections. opc.https has no connections.
	OnConnectionOpened(remote net.Addr)

	// OnConnectionClosed is called when that connection ended, by either
	// side, after it was open for duration.
	OnConnectionClosed(remote net.Addr, duration time.Duration)

	// OnSessionActivated is called after a successful ActivateSession
	// (Part 4 §5.6.3), the first one of a session and every later one
	// (info.Reactivated), e.g. when the client moves the session to a new
	// secure channel after a reconnect.
	OnSessionActivated(info SessionInfo)

	// OnSessionClosed is called when an activated session ended. A session
	// that was created but never activated is not reported.
	OnSessionClosed(info SessionInfo, reason SessionCloseReason)

	// OnRejected is called when the server refused a client's
	// OpenSecureChannel (e.g. an untrusted application certificate),
	// CreateSession or ActivateSession (e.g. a wrong password or a token
	// type no endpoint offers). A request the server cannot decrypt or
	// verify is not reported.
	OnRejected(r Rejection)
}

// BaseSessionObserver implements [SessionObserver] with methods that do
// nothing. Embed it to implement only the methods of interest; it keeps an
// observer compiling when methods are added to the interface.
type BaseSessionObserver struct{}

func (BaseSessionObserver) OnConnectionOpened(net.Addr)                     {}
func (BaseSessionObserver) OnConnectionClosed(net.Addr, time.Duration)      {}
func (BaseSessionObserver) OnSessionActivated(SessionInfo)                  {}
func (BaseSessionObserver) OnSessionClosed(SessionInfo, SessionCloseReason) {}
func (BaseSessionObserver) OnRejected(Rejection)                            {}

// SessionInfo describes a session for a [SessionObserver]. Every call gets
// its own copy, which the observer may keep; ID is shared with the server and
// must not be modified.
type SessionInfo struct {
	// ID is the SessionId (CreateSession).
	ID *ua.NodeID
	// Name is the SessionName the client chose (CreateSession).
	Name string
	// Client describes the client application (CreateSession
	// ClientDescription): ApplicationName, ApplicationURI, ProductURI.
	Client *ua.ApplicationDescription
	// EndpointURL is the endpoint the client asked for (CreateSession).
	EndpointURL string
	// RemoteAddr is the address of the client on the secure channel of the
	// last activation; nil over opc.https.
	RemoteAddr net.Addr
	// SecurityPolicyURI and SecurityMode are those of that secure channel.
	SecurityPolicyURI string
	SecurityMode      ua.MessageSecurityMode
	// IdentityType is the kind of user identity token of the last
	// activation, and User the user it names: the user name, the subject of
	// an X.509 user certificate, or empty (anonymous, issued token).
	IdentityType ua.UserTokenType
	User         string
	// Created is when the session was created, Activated when it was last
	// activated.
	Created   time.Time
	Activated time.Time
	// Reactivated is set for an ActivateSession of a session that was
	// activated before.
	Reactivated bool
}

// SessionCloseReason tells why a session ended.
type SessionCloseReason int

const (
	// SessionClosedByClient: the client called CloseSession (Part 4 §5.6.4).
	SessionClosedByClient SessionCloseReason = iota + 1
	// SessionTimedOut: the client did not use the session within its
	// revised session timeout (Part 4 §5.6.2), e.g. because its connection
	// was lost and it did not come back.
	SessionTimedOut
	// SessionClosedByServer: the server shut down, or it was full and closed
	// the session to make room for a new one: the session's secure channel
	// had closed and its client had not come back (WithMaxSessions).
	SessionClosedByServer
)

func (r SessionCloseReason) String() string {
	switch r {
	case SessionClosedByClient:
		return "closed by client"
	case SessionTimedOut:
		return "timed out"
	case SessionClosedByServer:
		return "closed by server"
	}
	return "unknown"
}

// WithSessionObserver sets the observer of client connections and sessions
// (nil: none). See [SessionObserver].
func WithSessionObserver(o SessionObserver) Option {
	return func(s *serverConfig) error {
		s.sessionObserver = o
		return nil
	}
}

// sessionObs is what a session keeps for the session observer. It does not
// depend on the server diagnostics, which can be switched off.
type sessionObs struct {
	mu   sync.Mutex
	info SessionInfo
}

// describe records the CreateSession description of the session.
func (o *sessionObs) describe(id *ua.NodeID, req *ua.CreateSessionRequest) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.info.ID = id
	o.info.Name = req.SessionName
	o.info.Client = req.ClientDescription
	o.info.EndpointURL = req.EndpointURL
}

// activate records an activation over sc with the identity tok.
func (o *sessionObs) activate(sc *uasc.SecureChannel, tok ua.IdentityToken, reactivated bool, at time.Time) SessionInfo {
	o.mu.Lock()
	defer o.mu.Unlock()
	if sc != nil {
		o.info.RemoteAddr = sc.RemoteAddr()
		o.info.SecurityPolicyURI = sc.SecurityPolicyURI()
		o.info.SecurityMode = sc.SecurityMode()
	}
	o.info.User, _ = userOf(tok)
	o.info.IdentityType = tokenTypeOf(tok)
	o.info.Activated = at
	o.info.Reactivated = reactivated
	return o.info.clone()
}

// snapshot returns a copy of the info.
func (o *sessionObs) snapshot() SessionInfo {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.info.clone()
}

// clone returns a copy of i that shares no mutable data with i but the ID.
func (i SessionInfo) clone() SessionInfo {
	if i.Client != nil {
		c := *i.Client
		if c.ApplicationName != nil {
			name := *c.ApplicationName
			c.ApplicationName = &name
		}
		c.DiscoveryURLs = slices.Clone(c.DiscoveryURLs)
		i.Client = &c
	}
	return i
}

// The observe methods call the session observer, if there is one, and
// recover a panic in it.

func (s *Server) observeConnectionOpened(remote net.Addr) {
	if o := s.cfg.sessionObserver; o != nil {
		defer s.recoverObserver("OnConnectionOpened")
		o.OnConnectionOpened(remote)
	}
}

func (s *Server) observeConnectionClosed(remote net.Addr, opened time.Time) {
	if o := s.cfg.sessionObserver; o != nil {
		defer s.recoverObserver("OnConnectionClosed")
		o.OnConnectionClosed(remote, time.Since(opened))
	}
}

func (s *Server) observeSessionActivated(sc *uasc.SecureChannel, sess *session, reactivated bool) {
	info := sess.obs.activate(sc, sess.identityToken, reactivated, time.Now())
	if o := s.cfg.sessionObserver; o != nil {
		defer s.recoverObserver("OnSessionActivated")
		o.OnSessionActivated(info)
	}
}

func (s *Server) observeSessionClosed(sess *session, reason SessionCloseReason) {
	if !sess.activated.Load() {
		return
	}
	if o := s.cfg.sessionObserver; o != nil {
		defer s.recoverObserver("OnSessionClosed")
		o.OnSessionClosed(sess.obs.snapshot(), reason)
	}
}

func (s *Server) recoverObserver(method string) {
	if r := recover(); r != nil {
		logPanic(s.cfg.logger, "calling SessionObserver."+method, r)
	}
}
