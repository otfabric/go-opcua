// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The session keep-alive (SessionKeepAlive).
//
// A server terminates a session "if the Client fails to issue a Service
// request on the Session within the timeout period negotiated by the Server
// in the CreateSession Service response", and "Clients shall be prepared to
// submit requests in a timely manner to prevent the Session from closing
// automatically" (Part 4 §5.7.2.1). The preferred way to monitor the
// connection is the keep-alive of a Subscription; without one "the
// connection can be monitored by periodically reading the State Variable"
// of the ServerStatus (Part 4 §6.7). Neither clause says when to send the
// request or what a client does when it fails: half the revised session
// timeout, and handling a keep-alive without a response as a lost
// connection, are the design of this client.

// keepAlivePoll is the longest the keep-alive waits before it looks again
// while the client has no session or is not Connected.
const keepAlivePoll = time.Second

// keepAliveEpoch is the reference of lastSessionRequest. time.Since uses
// the monotonic clock, which a change of the wall clock does not move.
var keepAliveEpoch = time.Now()

// noteSessionRequest records that a request is being sent in the session.
func (c *Client) noteSessionRequest() {
	c.lastSessionRequest.Store(int64(time.Since(keepAliveEpoch)))
}

// sessionIdle returns how long the client has sent no request in its
// session.
func (c *Client) sessionIdle() time.Duration {
	return time.Since(keepAliveEpoch) - time.Duration(c.lastSessionRequest.Load())
}

// startKeepAlive starts the session keep-alive and returns the function that
// stops it and waits until it has stopped. The connection monitor runs it
// for as long as it runs itself.
func (c *Client) startKeepAlive(ctx context.Context) (stop func()) {
	if c.cfg.keepAliveOff {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.keepSessionAlive(ctx)
	}()
	return func() {
		cancel()
		<-done
	}
}

// keepSessionAlive sends a keep-alive whenever the session has been idle for
// its keep-alive interval, until ctx is done.
func (c *Client) keepSessionAlive(ctx context.Context) {
	// The session has just been activated.
	c.noteSessionRequest()
	t := time.NewTimer(c.keepAliveStep(ctx))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(c.keepAliveStep(ctx))
		}
	}
}

// keepAliveStep sends a keep-alive if the session has been idle for its
// keep-alive interval and returns how long to wait before the next step.
//
// Nothing is sent while the client is not Connected: during a reconnect the
// connection monitor sends the requests, and a client that has given up
// (Disconnected without AutoReconnect, Closed) has nothing to keep alive.
func (c *Client) keepAliveStep(ctx context.Context) time.Duration {
	s := c.Session()
	if s == nil {
		return keepAlivePoll
	}
	iv := c.cfg.keepAliveInterval(s.RevisedTimeout())
	if iv <= 0 {
		return keepAlivePoll
	}
	if c.State() != Connected {
		return min(iv, keepAlivePoll)
	}
	if idle := c.sessionIdle(); idle < iv {
		return iv - idle
	}
	c.sendKeepAlive(ctx, s)
	return iv
}

// sendKeepAlive reads the State of the ServerStatus in session s, without
// retries, and hands a failure that shows the connection or the session
// lost to the connection monitor.
func (c *Client) sendKeepAlive(ctx context.Context, s *Session) {
	errs := c.secureChannelErrors()
	req := &ua.ReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnNeither,
		NodesToRead: []*ua.ReadValueID{{
			NodeID:      ua.NewNumericNodeID(0, id.ServerServerStatusState),
			AttributeID: ua.AttributeIDValue,
		}},
	}
	// Any response shows the session alive; its value is not used.
	err := c.doSend(ctx, req, func(ua.Response) error { return nil })
	if ctx.Err() != nil {
		// stopped: a failure is that of the stop
		return
	}
	c.keepAliveFailed(s, errs, err)
}

// keepAliveFailed hands err, the result of a keep-alive sent in session s
// while errs was the error channel of the secure channel, to the connection
// monitor if it shows the connection or the session lost, and reports
// whether it did.
//
// Bad_Timeout is a keep-alive without a response within the RequestTimeout:
// a connection that is gone without being closed (a peer that vanished, a
// network that drops everything) is noticed only that way.
// Bad_SessionClosed is what the server returns to outstanding requests when
// it terminates the session (Part 4 §5.7.2.1). Every other failure needs
// nothing from the keep-alive: the secure channel reports a broken
// connection and Bad_SessionIdInvalid to the monitor itself, and any other
// answer shows that the server received the request.
func (c *Client) keepAliveFailed(s *Session, errs chan error, err error) bool {
	if err == nil {
		return false
	}
	if !errors.Is(err, ua.StatusBadTimeout) && !errors.Is(err, ua.StatusBadSessionClosed) {
		c.cfg.logger.Debug("session keep-alive failed", "error", err)
		return false
	}
	// A failure of a session or a secure channel the client has replaced
	// since, or one during a recovery, says nothing about the present ones.
	if c.Session() != s || c.secureChannelErrors() != errs || c.State() != Connected {
		return false
	}
	c.cfg.logger.Warn("session keep-alive failed, handling the connection as lost", "error", err)
	select {
	case errs <- fmt.Errorf("opcua: session keep-alive: %w", err):
	default:
		// An error is pending already; the monitor acts on that one.
	}
	return true
}
