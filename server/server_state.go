// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"math"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// ServerStateChange is a change of the state of the server: the input
// arguments of RequestServerStateChange (OPC 10000-5 §9.4).
type ServerStateChange struct {
	// State is the requested state.
	State ua.ServerState
	// EstimatedReturnTime is when the server is expected to be RUNNING_0
	// again; the zero time (the null DateTime) when it is not known. It
	// is ignored when State is RUNNING_0.
	EstimatedReturnTime time.Time
	// SecondsTillShutdown is the time until the shutdown, "ignored unless
	// the state is set to SHUTDOWN_4 or restart is set to True".
	SecondsTillShutdown uint32
	// Reason is the reason of the change, the ShutdownReason of a shutdown;
	// nil for none.
	Reason *ua.LocalizedText
	// Restart asks for a restart before the change: "If the restart is
	// True the server changes it state to SHUTDOWN_4 before the restart if
	// secondsTillShutdown is not 0."
	Restart bool
}

// ServerStateChangeFunc carries out a RequestServerStateChange an
// administrator called (OPC 10000-5 §9.4). It returns ua.StatusOK to accept
// the change, which the server then publishes ([Server.SetServerState]),
// or the StatusCode of the call, ua.StatusBadInvalidState when "The
// requested state was not accepted by the server". [MethodCallerFromContext] gives the
// caller. The function runs in the Call service: what takes time (a
// shutdown after SecondsTillShutdown, a restart) it starts and returns.
type ServerStateChangeFunc func(ctx context.Context, change ServerStateChange) ua.StatusCode

// WithServerStateChange sets the function that carries out
// RequestServerStateChange. The library does not stop, suspend or restart
// the server by itself: without the function every request is
// Bad_InvalidState.
func WithServerStateChange(f ServerStateChangeFunc) Option {
	return func(s *serverConfig) error {
		s.stateChange = f
		return nil
	}
}

// SetServerState publishes a change of the state of the server in the
// ServerStatus and the EstimatedReturnTime Property of the Server Object,
// as an accepted RequestServerStateChange does (OPC 10000-5 §9.4):
//
//   - the State becomes c.State; with c.Restart it becomes SHUTDOWN_4 when
//     c.SecondsTillShutdown is not 0 and is left as it is otherwise, as
//     the server restarts at once;
//   - EstimatedReturnTime becomes c.EstimatedReturnTime, the null DateTime
//     when c.State is RUNNING_0: "the Property EstimatedReturnTime shall
//     be set to null if the new state is RUNNING_0" (§9.4, §6.3.1);
//   - in SHUTDOWN_4, SecondsTillShutdown counts down from
//     c.SecondsTillShutdown ("Approximate number of seconds until the
//     Server will be shut down", §12.10) and ShutdownReason is c.Reason;
//     in another state, where neither applies, they are 0 and the empty
//     LocalizedText.
//
// It changes nothing else: the application stops or restarts the server.
// [Server.Start] sets RUNNING_0 and [Server.Close] SHUTDOWN_4.
func (s *Server) SetServerState(c ServerStateChange) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !c.Restart:
		s.status.State = c.State
	case c.SecondsTillShutdown != 0:
		s.status.State = ua.ServerStateShutdown
	}
	s.estimatedReturnTime = c.EstimatedReturnTime
	if c.State == ua.ServerStateRunning {
		s.estimatedReturnTime = time.Time{}
	}
	s.shutdownAt = time.Time{}
	s.status.SecondsTillShutdown = 0
	s.status.ShutdownReason = &ua.LocalizedText{}
	if s.status.State == ua.ServerStateShutdown {
		s.shutdownAt = now.Add(time.Duration(c.SecondsTillShutdown) * time.Second)
		if c.Reason != nil {
			s.status.ShutdownReason = c.Reason
		}
	}
}

// EstimatedReturnTime returns the value of the EstimatedReturnTime
// Property of the Server Object (OPC 10000-5 §6.3.1), the zero time when it
// is null.
func (s *Server) EstimatedReturnTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.estimatedReturnTime
}

// secondsTillShutdownLocked returns the seconds until shutdownAt, rounded
// up. Caller must hold s.mu.
func (s *Server) secondsTillShutdownLocked(now time.Time) uint32 {
	if s.shutdownAt.IsZero() || s.status.State != ua.ServerStateShutdown {
		return s.status.SecondsTillShutdown
	}
	left := math.Ceil(s.shutdownAt.Sub(now).Seconds())
	switch {
	case left <= 0:
		return 0
	case left > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(left)
}

// bindEstimatedReturnTime serves the EstimatedReturnTime Property of the
// Server Object from the server, the null DateTime until a state change
// sets it. The NodeSet gives the Property no value.
func (s *Server) bindEstimatedReturnTime() {
	n := s.ownNode(id.ServerEstimatedReturnTime)
	if n == nil {
		return
	}
	n.mu.Lock()
	n.val = func() *ua.DataValue { return DataValueFromValue(s.EstimatedReturnTime()) }
	n.mu.Unlock()
}
