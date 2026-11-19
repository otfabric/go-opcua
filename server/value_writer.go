// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// ValueWrite is a client's Write of the Value Attribute of a Variable that has
// a [ValueWriter] (Part 4 §5.10.4).
type ValueWrite struct {
	// Session is the session the Write arrived in.
	Session *Session
	// NodeID is the Variable written.
	NodeID *ua.NodeID
	// Value is the DataValue as the client wrote it. Its StatusCode and
	// timestamps, which the server refuses for a value it stores
	// (Bad_WriteNotSupported, Part 4 §5.10.4), are the writer's to take or
	// refuse. With an IndexRange it is the current value with the range
	// replaced, without status or timestamps.
	Value *ua.DataValue
}

// ValueWriter takes a client's Write of the Value of a Variable in place of the
// server. It returns the status of the operation: StatusOK when the value was
// taken, a Bad code otherwise (Bad_OutOfRange, Bad_TypeMismatch,
// Bad_CommunicationError, Bad_UserAccessDenied…).
//
// The server does not store the value: the writer decides what the Variable
// holds afterwards, typically by updating it with [Node.SetAttribute] or its
// value function and calling [Server.ChangeNotification].
//
// A writer may take as long as the application needs, e.g. to write a device
// and read the value back. It runs off the goroutine that handles the
// requests of every client, so a slow writer holds up only the Write request
// it serves. The writes of one session reach the writers in the order the
// session sent them. ctx ends when the server closes or when the TimeoutHint
// of the request elapsed.
type ValueWriter func(ctx context.Context, w *ValueWrite) ua.StatusCode

// SetValueWriter sets the writer that takes clients' Writes of the Value of
// this Variable (nil: the server stores a written value, the default). The
// AccessLevel, UserAccessLevel, AccessRestrictions and the AccessController
// are applied before the writer is called, as for a stored value.
func (n *Node) SetValueWriter(fn ValueWriter) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.writer = fn
}

// ValueWriter returns the writer set with SetValueWriter, nil if there is none.
func (n *Node) ValueWriter() ValueWriter {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.writer
}

// laterKey keys the *later of the request the dispatcher is serving.
type laterKey struct{}

// later lets a handler answer its request after it returned: the request
// keeps its in-flight slot until the response is queued.
type later struct {
	srv   *Server
	sc    *uasc.SecureChannel
	w     *channelWriter
	reqID uint32
	kept  bool
}

// answerLater takes the request of ctx out of the dispatcher's hands: the
// handler returns a nil response and calls reply exactly once. It returns
// nil when the request cannot be answered later (no dispatcher in ctx, as in
// unit tests that call a handler directly): the handler then answers now.
func answerLater(ctx context.Context) func(req ua.Request, resp ua.Response) {
	l, _ := ctx.Value(laterKey{}).(*later)
	if l == nil {
		return nil
	}
	l.kept = true
	return func(req ua.Request, resp ua.Response) {
		addDiagnostics(req, resp)
		l.srv.diag.publishResponse(resp)
		if l.w != nil {
			if err := l.w.send(l.reqID, resp); err != nil {
				l.srv.cfg.logger.Debug("response dropped", "error", err)
			}
			return
		}
		if err := l.srv.writeDirect(l.sc, l.reqID, resp); err != nil {
			l.srv.cfg.logger.Debug("response dropped", "error", err)
		}
	}
}

// valueWriteJob is one Write operation that a ValueWriter takes.
type valueWriteJob struct {
	index  int
	writer ValueWriter
	write  *ValueWrite
}

// writeQueue orders the deferred Writes of one session.
type writeQueue struct {
	mu   sync.Mutex
	last chan struct{} // closed when the session's latest deferred Write is done
}

// next returns the channel to wait for before a new deferred Write of the
// session runs, and the one that Write closes when it is done.
func (q *writeQueue) next() (prev, done chan struct{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	prev, done = q.last, make(chan struct{})
	q.last = done
	return prev, done
}

// runValueWriters calls the writers of jobs off the dispatcher, in order and
// after the session's earlier deferred Writes, puts their status into the
// results and calls answer with them.
func (s *Server) runValueWriters(ctx context.Context, sess *session, hdr *ua.RequestHeader, jobs []valueWriteJob, results []ua.StatusCode, answer func([]ua.StatusCode)) {
	prev, done := sess.writes.next()
	wctx, cancel := ctx, context.CancelFunc(func() {})
	if hdr != nil && hdr.TimeoutHint > 0 {
		wctx, cancel = context.WithTimeout(ctx, time.Duration(hdr.TimeoutHint)*time.Millisecond)
	}
	s.writers.Add(1)
	go func() {
		defer s.writers.Done()
		defer cancel()
		defer close(done)
		if prev != nil {
			select {
			case <-prev:
			case <-wctx.Done():
			}
		}
		for _, j := range jobs {
			results[j.index] = s.callValueWriter(wctx, j)
		}
		answer(results)
	}()
}

// callValueWriter calls one writer. A panic fails the operation with
// Bad_InternalError, an expired ctx with Bad_Timeout before the call.
func (s *Server) callValueWriter(ctx context.Context, j valueWriteJob) (st ua.StatusCode) {
	if ctx.Err() != nil {
		return ua.StatusBadTimeout
	}
	defer func() {
		if r := recover(); r != nil {
			logPanic(s.cfg.logger, "writing a value", r, "node_id", j.write.NodeID)
			st = ua.StatusBadInternalError
		}
	}()
	return j.writer(ctx, j.write)
}
