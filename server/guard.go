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
// A Guard that also implements [SessionEndGuard] learns when sessions end,
// one that implements [OperationGuard] when the operations it allowed are
// over.
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

// OperationGuard is a [Guard] that is told when a write or call it allowed
// is over, so that it knows which operations are active: OPC 10000-100 §7.2
// rejects a lock request while operations are active that the lock would
// prevent. The server calls WriteDone, with the arguments of CheckWrite,
// at the end of the Write request or of [Server.WriteValue], and CallDone
// when the Method returned; a Guard that allowed an operation another Guard
// rejected is told right away. They must not block.
type OperationGuard interface {
	Guard
	WriteDone(ctx context.Context, session *Session, nodeID *ua.NodeID)
	CallDone(ctx context.Context, session *Session, objectID, methodID *ua.NodeID)
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

// noDone is the done of an operation no OperationGuard follows.
func noDone() {}

// guardWrite returns the first rejection of a write of nid by a Guard, or
// Good and done, which tells the OperationGuards the write is over.
func (s *Server) guardWrite(ctx context.Context, sess *session, nid *ua.NodeID) (ua.StatusCode, func()) {
	h := sess.handle()
	return s.guard(func(g Guard) ua.StatusCode { return g.CheckWrite(ctx, h, nid) },
		func(g OperationGuard) { g.WriteDone(ctx, h, nid) })
}

// guardCall is guardWrite for a call of methodID on objectID.
func (s *Server) guardCall(ctx context.Context, sess *session, objectID, methodID *ua.NodeID) (ua.StatusCode, func()) {
	h := sess.handle()
	return s.guard(func(g Guard) ua.StatusCode { return g.CheckCall(ctx, h, objectID, methodID) },
		func(g OperationGuard) { g.CallDone(ctx, h, objectID, methodID) })
}

// guard asks the Guards with check and returns the first rejection, after
// telling the OperationGuards that allowed the operation that it is over;
// or Good and the func that tells them.
func (s *Server) guard(check func(Guard) ua.StatusCode, done func(OperationGuard)) (ua.StatusCode, func()) {
	var allowed []OperationGuard
	finish := func() {
		for i := len(allowed) - 1; i >= 0; i-- {
			func() {
				defer func() {
					if r := recover(); r != nil {
						logPanic(s.cfg.logger, "telling an OperationGuard an operation is over", r)
					}
				}()
				done(allowed[i])
			}()
		}
	}
	for _, g := range s.guardList() {
		if st := check(g); st != ua.StatusOK {
			finish()
			return st, noDone
		}
		if og, ok := g.(OperationGuard); ok {
			allowed = append(allowed, og)
		}
	}
	if len(allowed) == 0 {
		return ua.StatusOK, noDone
	}
	return ua.StatusOK, finish
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
