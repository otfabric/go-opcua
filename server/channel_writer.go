// SPDX-License-Identifier: MIT

package server

import (
	"context"
	stderrors "errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
)

const (
	// defaultResponseWriteTimeout is how long a response may take to be
	// written to a client before its connection is dropped.
	defaultResponseWriteTimeout = 15 * time.Second

	// defaultMaxPendingResponses is the number of requests of one secure
	// channel that may be in flight (received, but their response not yet
	// written) at a time.
	defaultMaxPendingResponses = 256

	// publishBacklog is the number of responses that may be queued for a
	// channel on top of maxPending without belonging to a request that holds
	// a slot. These are the Publish responses: a Publish request is parked
	// (and its slot released) until a subscription has something to send.
	publishBacklog = 128
)

// errChannelGone is returned when a response is handed to a channel that has
// been closed.
var errChannelGone = stderrors.New("server: secure channel closed")

// errChannelBacklog is returned when a channel does not drain its Publish
// responses.
var errChannelBacklog = stderrors.New("server: too many responses pending on secure channel")

// outbound is a response waiting to be written to a channel.
type outbound struct {
	reqID uint32
	resp  ua.Response
	// slotted is true when the request this response belongs to holds one of
	// the channel's in-flight slots, which is released once it is written.
	slotted bool
}

// channelWriter writes the responses of one secure channel.
//
// Requests of all channels are handled one after the other by a single
// goroutine. If that goroutine also wrote the responses, one client that
// stopped reading would block it in a socket write and with it every other
// client. Each channel therefore has its own writer goroutine fed through a
// bounded queue: the handler only enqueues.
//
//   - Responses are written in the order they were queued, by one goroutine,
//     so the order of responses and the sequence numbers on the channel are
//     exactly what they would be with direct writes.
//   - The queue cannot overflow from requests: a channel's read loop takes an
//     in-flight slot before it hands a request to the handler and blocks when
//     none is free. A client that does not read its responses is thus simply
//     not read from any more (TCP back pressure) instead of costing memory.
//   - A response that cannot be written within the write timeout means the
//     peer has stopped reading. Only that channel is torn down.
type channelWriter struct {
	sc      *uasc.SecureChannel
	conn    *uacp.Conn
	logger  *slog.Logger
	timeout time.Duration

	queue chan outbound
	slots chan struct{}

	// unslotted counts the queued responses that hold no slot.
	unslotted atomic.Int32

	done    chan struct{} // closed when the channel is being torn down
	exited  chan struct{} // closed when run has returned
	stopped sync.Once

	// deliver, if set, takes the responses instead of the secure channel:
	// the HTTPS transport hands each one to the HTTP request it answers.
	// It must not block. conn is nil then.
	deliver func(reqID uint32, resp ua.Response)
}

func newChannelWriter(sc *uasc.SecureChannel, conn *uacp.Conn, logger *slog.Logger, timeout time.Duration, maxPending int) *channelWriter {
	if timeout <= 0 {
		timeout = defaultResponseWriteTimeout
	}
	if maxPending <= 0 {
		maxPending = defaultMaxPendingResponses
	}
	if logger == nil {
		logger = silentLogger()
	}
	return &channelWriter{
		sc:      sc,
		conn:    conn,
		logger:  logger,
		timeout: timeout,
		queue:   make(chan outbound, maxPending+publishBacklog),
		slots:   make(chan struct{}, maxPending),
		done:    make(chan struct{}),
		exited:  make(chan struct{}),
	}
}

// acquire takes an in-flight slot for a request that was just received. It
// blocks while the channel has maxPending requests in flight and reports
// false if the channel or ctx ended first.
func (w *channelWriter) acquire(ctx context.Context) bool {
	select {
	case w.slots <- struct{}{}:
		return true
	case <-w.done:
		return false
	case <-ctx.Done():
		return false
	}
}

// release returns the slot of a request that needs no response now (a parked
// Publish request) or whose response has been written.
func (w *channelWriter) release() {
	select {
	case <-w.slots:
	default:
	}
}

// send queues the response of a request that holds a slot. It does not block:
// the queue has room for every slot.
func (w *channelWriter) send(reqID uint32, resp ua.Response) error {
	select {
	case <-w.done:
		w.release()
		return errChannelGone
	default:
	}
	select {
	case w.queue <- outbound{reqID: reqID, resp: resp, slotted: true}:
		return nil
	case <-w.done:
		w.release()
		return errChannelGone
	}
}

// sendUnslotted queues a response whose request holds no slot (a Publish
// response sent by a subscription). It never blocks; if the channel already
// has publishBacklog such responses waiting, the client is not draining them
// and errChannelBacklog is returned.
func (w *channelWriter) sendUnslotted(reqID uint32, resp ua.Response) error {
	select {
	case <-w.done:
		return errChannelGone
	default:
	}
	if w.unslotted.Add(1) > publishBacklog {
		w.unslotted.Add(-1)
		return errChannelBacklog
	}
	select {
	case w.queue <- outbound{reqID: reqID, resp: resp}:
		return nil
	default:
		// cannot happen while the accounting above holds
		w.unslotted.Add(-1)
		return errChannelBacklog
	}
}

// run writes queued responses until the channel is torn down.
func (w *channelWriter) run() {
	defer close(w.exited)
	defer func() {
		// A panic while encoding a response must not take the process down.
		// The stream may be in an undefined state, so drop the channel.
		if r := recover(); r != nil {
			logPanic(w.logger, "writing a response", r)
			w.close()
		}
	}()
	for {
		select {
		case <-w.done:
			return
		case o := <-w.queue:
			w.write(o)
		}
	}
}

func (w *channelWriter) write(o outbound) {
	defer func() {
		if o.slotted {
			w.release()
		} else {
			w.unslotted.Add(-1)
		}
	}()

	if w.deliver != nil {
		w.deliver(o.reqID, o.resp)
		return
	}

	// The watchdog closes the connection, which is what unblocks a write to
	// a peer that has stopped reading, wherever that write is stuck.
	watchdog := time.AfterFunc(w.timeout, func() {
		w.logger.Warn("response not written in time, dropping the connection",
			"remote_addr", w.sc.RemoteAddr(), "timeout", w.timeout)
		w.close()
	})
	err := w.sc.SendResponseWithContext(context.Background(), o.reqID, o.resp)
	watchdog.Stop()
	if err == nil {
		return
	}
	w.logger.Warn("error sending response", "error", err)

	if isConnError(err) {
		// Part of the message may be on the wire: the stream is unusable.
		w.close()
		return
	}
	// The response could not be sent although the connection is fine, most
	// likely because it could not be encoded. Never leave the request
	// unanswered: the client would block until its timeout.
	if _, isFault := o.resp.(*ua.ServiceFault); isFault {
		return
	}
	fault := &ua.ServiceFault{ResponseHeader: responseHeader(0, ua.StatusBadEncodingError)}
	if ferr := w.sc.SendResponseWithContext(context.Background(), o.reqID, fault); ferr != nil {
		w.logger.Warn("error sending service fault", "error", ferr)
		if isConnError(ferr) {
			w.close()
		}
	}
}

// close tears the channel down: no further responses are accepted and the
// connection is closed, which ends the channel's read loop as well.
func (w *channelWriter) close() {
	w.stopped.Do(func() {
		close(w.done)
		if w.conn != nil {
			_ = w.conn.Close()
		}
	})
}

// isConnError reports whether err means that the connection is broken, as
// opposed to a response that could not be produced. A secure channel without
// an active security token cannot send anything either.
func isConnError(err error) bool {
	var netErr net.Error
	return stderrors.As(err, &netErr) ||
		stderrors.Is(err, errors.ErrSecureChannelClosed) ||
		stderrors.Is(err, net.ErrClosed) ||
		stderrors.Is(err, io.EOF) ||
		stderrors.Is(err, io.ErrUnexpectedEOF) ||
		stderrors.Is(err, os.ErrDeadlineExceeded)
}
