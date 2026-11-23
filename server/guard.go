// SPDX-License-Identifier: MIT

package server

import (
	"context"

	"github.com/otfabric/go-opcua/ua"
)

// A Guard vets the changes clients make to the address space, after the
// [AccessController] allowed them. Where the AccessController decides who
// may do what, a Guard decides what the state of the server allows at the
// time, such as the locks of the LockingServices of OPC 10000-100 §7, which
// reject the modifications of a locked element by other applications with
// Bad_Locked (§7.5).
//
// The server consults its Guards, in the order they were added, for every
// Variable value a client writes (the Write service and [Server.WriteValue])
// and for every Method a client calls (the Call service). A Guard returns
// [ua.StatusOK] to allow the change or the Bad StatusCode to reject it with.
// The [Session] is that of the request (nil without one); ctx is that of the
// request, or of the Method call for [Server.WriteValue].
//
// A Guard is called on the goroutine of the request and must not block.
// A Guard that also implements [SessionEndGuard] learns when sessions end.
type Guard interface {
	CheckWrite(ctx context.Context, session *Session, nodeID *ua.NodeID) ua.StatusCode
	CheckCall(ctx context.Context, session *Session, objectID, methodID *ua.NodeID) ua.StatusCode
}

// SessionEndGuard is a [Guard] that is told when a session ended, so that
// it can release what the session held (OPC 10000-100 §7.2: a lock is
// removed when its Session ends).
type SessionEndGuard interface {
	Guard
	SessionEnded(session *Session)
}

// AddGuard adds g to the Guards of the server. Add Guards before the server
// starts.
func (s *Server) AddGuard(g Guard) {
	if g == nil {
		return
	}
	s.guardMu.Lock()
	defer s.guardMu.Unlock()
	var gs []Guard
	if p := s.guards.Load(); p != nil {
		gs = append(gs, *p...)
	}
	gs = append(gs, g)
	s.guards.Store(&gs)
}

// guardList returns the Guards of the server.
func (s *Server) guardList() []Guard {
	if p := s.guards.Load(); p != nil {
		return *p
	}
	return nil
}

// guardWrite returns the first rejection of a write of nid by a Guard.
func (s *Server) guardWrite(ctx context.Context, sess *session, nid *ua.NodeID) ua.StatusCode {
	for _, g := range s.guardList() {
		if st := g.CheckWrite(ctx, sess.handle(), nid); st != ua.StatusOK {
			return st
		}
	}
	return ua.StatusOK
}

// guardCall returns the first rejection of a call of methodID on objectID
// by a Guard.
func (s *Server) guardCall(ctx context.Context, sess *session, objectID, methodID *ua.NodeID) ua.StatusCode {
	for _, g := range s.guardList() {
		if st := g.CheckCall(ctx, sess.handle(), objectID, methodID); st != ua.StatusOK {
			return st
		}
	}
	return ua.StatusOK
}

// guardSessionEnded tells the SessionEndGuards that sess ended.
func (s *Server) guardSessionEnded(sess *session) {
	for _, g := range s.guardList() {
		if e, ok := g.(SessionEndGuard); ok {
			func() {
				defer func() {
					if r := recover(); r != nil {
						logPanic(s.cfg.logger, "calling SessionEndGuard.SessionEnded", r)
					}
				}()
				e.SessionEnded(sess.handle())
			}()
		}
	}
}
