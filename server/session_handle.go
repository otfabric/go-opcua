// SPDX-License-Identifier: MIT

package server

import (
	"slices"

	"github.com/otfabric/go-opcua/ua"
)

// Session is the session a request came in on, as an [AccessController]
// sees it. It is read-only: it reports who the session is, not the secrets
// of the session (the AuthenticationToken, the nonces). A nil *Session is a
// request without a session; its methods return zero values.
type Session struct {
	s *session
}

// handle returns the Session of s, nil for a nil s.
func (s *session) handle() *Session {
	if s == nil {
		return nil
	}
	if s.pub.s != nil {
		return &s.pub
	}
	return &Session{s: s}
}

// ID returns the NodeId of the session (the SessionId of CreateSession).
func (h *Session) ID() *ua.NodeID {
	if h == nil {
		return nil
	}
	return h.s.ID
}

// Identity returns the user identity token the session was activated with;
// nil before ActivateSession. The token is the one the client sent: the
// password of a UserNameIdentityToken is still encrypted.
func (h *Session) Identity() ua.IdentityToken {
	if h == nil {
		return nil
	}
	return h.s.identityToken
}

// Roles returns the role NodeIds granted to the session (Part 18 §4.4). The
// slice is a copy.
func (h *Session) Roles() []*ua.NodeID {
	if h == nil {
		return nil
	}
	return slices.Clone(h.s.roles)
}

// ClientCertificate returns the application instance certificate (DER) the
// client sent in CreateSession; nil without one.
func (h *Session) ClientCertificate() []byte {
	if h == nil {
		return nil
	}
	return slices.Clone(h.s.remoteCertificate)
}
