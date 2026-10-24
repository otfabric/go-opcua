// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	opcuaerrors "github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// cwPair is an open secure channel between a client and a server side whose
// responses go through a channelWriter, without a Server around it: the test
// receives the requests and decides what to answer. The client is connected
// through a proxy that can stop forwarding the server's responses, which
// makes the server side see a client that has stopped reading.
type cwPair struct {
	w      *channelWriter
	ssc    *uasc.SecureChannel // server side
	sconn  *uacp.Conn
	csc    *uasc.SecureChannel // client side
	proxy  *cwProxy
	reqs   chan *uasc.MessageBody
	stop   chan struct{}
	recvDn chan struct{}
}

// cwProxy forwards a TCP connection in both directions. pause stops the
// forwarding of what the server sends.
type cwProxy struct {
	l        net.Listener
	paused   atomic.Bool
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    []net.Conn
}

func newCWProxy(t *testing.T, target string) *cwProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &cwProxy{l: l, stop: make(chan struct{})}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		c, err := l.Accept()
		if err != nil {
			return
		}
		s, err := net.Dial("tcp", target)
		if err != nil {
			_ = c.Close()
			return
		}
		// Small buffers towards the server, so that a response of a few
		// hundred kilobytes cannot be absorbed by the kernel.
		_ = s.(*net.TCPConn).SetReadBuffer(4096)
		p.mu.Lock()
		p.conns = append(p.conns, c, s)
		p.mu.Unlock()
		p.wg.Add(2)
		go func() {
			defer p.wg.Done()
			_, _ = io.Copy(s, c)
			_ = s.Close() // pass the end of the connection on
		}()
		go func() {
			defer p.wg.Done()
			defer func() { _ = c.Close() }() // pass the end of the connection on
			buf := make([]byte, 4096)
			for {
				if p.paused.Load() {
					<-p.stop
					return
				}
				n, err := s.Read(buf)
				if n > 0 {
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}()
	return p
}

func (p *cwProxy) addr() string { return p.l.Addr().String() }

func (p *cwProxy) close() {
	p.stopOnce.Do(func() { close(p.stop) })
	_ = p.l.Close()
	p.mu.Lock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

func newCWPair(t *testing.T, timeout time.Duration, maxPending int) *cwPair {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	l, err := uacp.Listen(ctx, "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	proxy := newCWProxy(t, l.Addr().String())
	endpoint := "opc.tcp://" + proxy.addr()
	type acc struct {
		c   *uacp.Conn
		err error
	}
	accepted := make(chan acc, 1)
	go func() {
		c, err := l.Accept(ctx)
		accepted <- acc{c, err}
	}()
	cconn, err := uacp.Dial(ctx, endpoint)
	if err != nil {
		proxy.close()
		require.NoError(t, err)
	}
	a := <-accepted
	if a.err != nil {
		_ = cconn.Close()
		proxy.close()
		require.NoError(t, a.err)
	}
	sconn := a.c

	scfg := defaultChannelConfig()
	scfg.Logger = silentLogger()
	ssc, err := uasc.NewServerSecureChannel(endpoint, sconn, scfg, make(chan error, 1), 1, 1, 1)
	require.NoError(t, err)
	csc, err := uasc.NewSecureChannel(endpoint, cconn, &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    30 * time.Second,
		Logger:            silentLogger(),
	}, make(chan error, 1))
	require.NoError(t, err)

	p := &cwPair{
		w:      newChannelWriter(ssc, sconn, silentLogger(), timeout, maxPending),
		ssc:    ssc,
		sconn:  sconn,
		csc:    csc,
		proxy:  proxy,
		reqs:   make(chan *uasc.MessageBody),
		stop:   make(chan struct{}),
		recvDn: make(chan struct{}),
	}
	// The server side's read loop: OpenSecureChannel is answered inside
	// Receive, requests are handed to the test.
	go func() {
		defer close(p.recvDn)
		for {
			msg := ssc.Receive(context.Background())
			if msg.Err != nil {
				return
			}
			if msg.Request() == nil {
				continue
			}
			select {
			case p.reqs <- msg:
			case <-p.stop:
				return
			}
		}
	}()
	go p.w.run()
	t.Cleanup(func() {
		close(p.stop)
		p.w.close()
		<-p.w.exited
		_ = csc.Close()
		_ = ssc.Close()
		p.proxy.close()
		<-p.recvDn
	})
	require.NoError(t, csc.Open(ctx))
	return p
}

// call sends a request from the client side and returns a channel with the
// response (or the error) once it arrives.
type cwResult struct {
	resp ua.Response
	err  error
}

func (p *cwPair) call(req ua.Request) <-chan cwResult {
	out := make(chan cwResult, 1)
	go func() {
		var got ua.Response
		err := p.csc.SendRequest(context.Background(), req, nil, func(r ua.Response) error {
			got = r
			return nil
		})
		out <- cwResult{got, err}
	}()
	return out
}

func (p *cwPair) nextRequest(t *testing.T) *uasc.MessageBody {
	t.Helper()
	select {
	case m := <-p.reqs:
		return m
	case <-time.After(30 * time.Second):
		t.Fatal("no request received")
		return nil
	}
}

func cwWait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(30 * time.Second):
		t.Fatal("timed out")
		var zero T
		return zero
	}
}

func cwReadRequest() *ua.ReadRequest {
	return &ua.ReadRequest{
		RequestHeader: &ua.RequestHeader{RequestHandle: 7, Timestamp: time.Now(), AdditionalHeader: ua.NewExtensionObject(nil)},
		NodesToRead:   []*ua.ReadValueID{},
	}
}

func cwHeader(sc ua.StatusCode) *ua.ResponseHeader {
	return responseHeader(7, sc)
}

// unencodable is a response that the binary encoder rejects: a reference
// without a NodeID.
func unencodable() *ua.BrowseResponse {
	return &ua.BrowseResponse{ResponseHeader: cwHeader(ua.StatusOK), Results: []*ua.BrowseResult{{
		References: []*ua.ReferenceDescription{{
			ReferenceTypeID: ua.NewNumericNodeID(0, 1),
			BrowseName:      &ua.QualifiedName{},
			DisplayName:     &ua.LocalizedText{},
		}},
	}}}
}

func TestChannelWriterCov_Defaults(t *testing.T) {
	w := newChannelWriter(nil, nil, nil, 0, 0)
	require.NotNil(t, w.logger)
	require.Equal(t, defaultResponseWriteTimeout, w.timeout)
	require.Equal(t, defaultMaxPendingResponses, cap(w.slots))
	require.Equal(t, defaultMaxPendingResponses+publishBacklog, cap(w.queue))
}

func TestChannelWriterCov_RoundTrip(t *testing.T) {
	p := newCWPair(t, 0, 2)
	res := p.call(cwReadRequest())
	msg := p.nextRequest(t)
	require.True(t, p.w.acquire(context.Background()))
	require.NoError(t, p.w.send(msg.RequestID, &ua.ReadResponse{ResponseHeader: cwHeader(ua.StatusOK), Results: []*ua.DataValue{}}))
	r := cwWait(t, res)
	require.NoError(t, r.err)
	require.IsType(t, &ua.ReadResponse{}, r.resp)
	// The slot is returned once the response is written.
	require.Eventually(t, func() bool { return len(p.w.slots) == 0 }, 30*time.Second, time.Millisecond)
}

// A response that cannot be encoded is replaced by a ServiceFault so that the
// client is not left waiting, and the channel stays usable.
func TestChannelWriterCov_EncodingErrorAnsweredWithFault(t *testing.T) {
	p := newCWPair(t, 0, 2)
	res := p.call(cwReadRequest())
	msg := p.nextRequest(t)
	require.True(t, p.w.acquire(context.Background()))
	require.NoError(t, p.w.send(msg.RequestID, unencodable()))
	r := cwWait(t, res)
	require.ErrorIs(t, r.err, ua.StatusBadEncodingError)

	// Same channel, next request: answered normally.
	res = p.call(cwReadRequest())
	msg = p.nextRequest(t)
	require.True(t, p.w.acquire(context.Background()))
	require.NoError(t, p.w.send(msg.RequestID, &ua.ReadResponse{ResponseHeader: cwHeader(ua.StatusOK), Results: []*ua.DataValue{}}))
	r = cwWait(t, res)
	require.NoError(t, r.err)
}

// encoderFunc is an extension object body with a custom binary encoding, as
// an application may register: here one that fails or panics.
type encoderFunc func() ([]byte, error)

func (f encoderFunc) Encode() ([]byte, error) { return f() }

func headerWithBody(f encoderFunc) *ua.ResponseHeader {
	h := cwHeader(ua.StatusOK)
	h.AdditionalHeader = &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewFourByteExpandedNodeID(1, 4711),
		Value:        f,
	}
	return h
}

func cwOK() *ua.ReadResponse {
	return &ua.ReadResponse{ResponseHeader: cwHeader(ua.StatusOK), Results: []*ua.DataValue{}}
}

func cwClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s not closed", what)
	}
}

func TestChannelWriterCov_AcquireEnds(t *testing.T) {
	p := newCWPair(t, 0, 1)
	ctx := context.Background()
	require.True(t, p.w.acquire(ctx))

	// No slot free: a cancelled context ends the wait.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	require.False(t, p.w.acquire(cctx))

	// ... and so does the channel being torn down.
	got := make(chan bool, 1)
	go func() { got <- p.w.acquire(ctx) }()
	p.w.close()
	require.False(t, cwWait(t, got))
	cwClosed(t, p.w.exited, "writer")
}

func TestChannelWriterCov_SendAfterClose(t *testing.T) {
	p := newCWPair(t, 0, 2)
	require.True(t, p.w.acquire(context.Background()))
	p.w.close()
	require.ErrorIs(t, p.w.send(1, cwOK()), errChannelGone)
	require.Empty(t, p.w.slots, "the slot of the dropped response is returned")
	require.ErrorIs(t, p.w.sendUnslotted(2, cwOK()), errChannelGone)
	require.Zero(t, p.w.unslotted.Load())
	cwClosed(t, p.recvDn, "server read loop")
}

func TestChannelWriterCov_UnslottedBacklog(t *testing.T) {
	// A writer whose responses are not drained.
	w := newChannelWriter(nil, nil, nil, 0, 1)
	for i := 0; i < publishBacklog; i++ {
		require.NoError(t, w.sendUnslotted(uint32(i), cwOK()))
	}
	require.ErrorIs(t, w.sendUnslotted(999, cwOK()), errChannelBacklog)
	require.Equal(t, int32(publishBacklog), w.unslotted.Load())
	// A request that holds a slot still gets its response queued.
	require.True(t, w.acquire(context.Background()))
	require.NoError(t, w.send(1000, cwOK()))
	require.Len(t, w.queue, publishBacklog+1)
}

// A Publish response (no slot) is written and its backlog entry released.
func TestChannelWriterCov_UnslottedWritten(t *testing.T) {
	p := newCWPair(t, 0, 2)
	res := p.call(cwReadRequest())
	msg := p.nextRequest(t)
	require.NoError(t, p.w.sendUnslotted(msg.RequestID, cwOK()))
	r := cwWait(t, res)
	require.NoError(t, r.err)
	require.IsType(t, &ua.ReadResponse{}, r.resp)
	require.Eventually(t, func() bool { return p.w.unslotted.Load() == 0 }, 30*time.Second, time.Millisecond)
}

// A ServiceFault that cannot be encoded is not replaced by another fault.
func TestChannelWriterCov_BrokenFaultNotRetried(t *testing.T) {
	p := newCWPair(t, 0, 2)
	res := p.call(cwReadRequest())
	msg := p.nextRequest(t)
	require.True(t, p.w.acquire(context.Background()))
	broken := &ua.ServiceFault{ResponseHeader: headerWithBody(func() ([]byte, error) {
		return nil, errors.New("cannot encode")
	})}
	require.NoError(t, p.w.send(msg.RequestID, broken))
	require.Eventually(t, func() bool { return len(p.w.slots) == 0 }, 30*time.Second, time.Millisecond)
	// Had a substitute fault been sent, the client would have it by now; it
	// gets the next response for its request instead.
	require.True(t, p.w.acquire(context.Background()))
	require.NoError(t, p.w.send(msg.RequestID, cwOK()))
	r := cwWait(t, res)
	require.NoError(t, r.err)
	require.IsType(t, &ua.ReadResponse{}, r.resp)
}

// A response written to a connection that is gone tears the channel down.
func TestChannelWriterCov_ConnectionGone(t *testing.T) {
	p := newCWPair(t, 0, 2)
	require.NoError(t, p.sconn.Close())
	require.True(t, p.w.acquire(context.Background()))
	require.NoError(t, p.w.send(1, cwOK()))
	cwClosed(t, p.w.done, "writer done")
	cwClosed(t, p.w.exited, "writer")
	require.ErrorIs(t, p.w.sendUnslotted(2, cwOK()), errChannelGone)
}

// The response cannot be encoded and the connection is gone as well: the
// fault that replaces it cannot be written either and the channel is torn
// down.
func TestChannelWriterCov_FaultOnDeadConnection(t *testing.T) {
	p := newCWPair(t, 0, 2)
	require.NoError(t, p.sconn.Close())
	require.True(t, p.w.acquire(context.Background()))
	require.NoError(t, p.w.send(1, unencodable()))
	cwClosed(t, p.w.done, "writer done")
	cwClosed(t, p.w.exited, "writer")
}

// A panic while encoding a response ends the channel, not the process.
func TestChannelWriterCov_EncoderPanic(t *testing.T) {
	p := newCWPair(t, 0, 2)
	res := p.call(cwReadRequest())
	msg := p.nextRequest(t)
	require.True(t, p.w.acquire(context.Background()))
	require.NoError(t, p.w.send(msg.RequestID, &ua.ReadResponse{
		ResponseHeader: headerWithBody(func() ([]byte, error) { panic("encoder bug") }),
		Results:        []*ua.DataValue{},
	}))
	cwClosed(t, p.w.exited, "writer")
	cwClosed(t, p.w.done, "writer done")
	cwClosed(t, p.recvDn, "server read loop")
	// The client sees its connection end instead of waiting for its timeout.
	r := cwWait(t, res)
	require.Error(t, r.err)
}

// A client that stops reading: the write of a large response blocks and the
// watchdog drops the connection after the write timeout.
func TestChannelWriterCov_WriteTimeout(t *testing.T) {
	p := newCWPair(t, 200*time.Millisecond, 2)
	require.NoError(t, p.sconn.SetWriteBuffer(4096))
	p.proxy.paused.Store(true)

	big := &ua.ReadResponse{ResponseHeader: cwHeader(ua.StatusOK), Results: []*ua.DataValue{
		DataValueFromValue(make([]byte, 1500*1024)),
	}}
	// The socket buffers are sized by the kernel (autotuned, often several
	// MB on loopback): queue responses until they are full and a write
	// blocks past its deadline, whatever their size.
	start := time.Now()
	sent := 0
queue:
	for ; sent < 64; sent++ {
		err := p.w.sendUnslotted(uint32(sent+1), big)
		switch {
		case errors.Is(err, errChannelGone), errors.Is(err, errChannelBacklog):
			break queue // timed out already, or the queue is full: wait
		case err != nil:
			t.Fatalf("send: %v", err)
		}
		select {
		case <-p.w.done:
			break queue
		case <-time.After(50 * time.Millisecond):
		}
	}
	cwClosed(t, p.w.done, "writer done")
	require.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond, "dropped before the timeout")
	t.Logf("the write timed out after %d response(s) of 1.5 MB", sent)
	cwClosed(t, p.w.exited, "writer")
	cwClosed(t, p.recvDn, "server read loop")
	// A torn-down writer refuses new responses instead of queueing them.
	require.ErrorIs(t, p.w.sendUnslotted(1000, big), errChannelGone)
	require.ErrorIs(t, p.w.send(1001, big), errChannelGone)
}

// Errors that leave nothing to send on, and those that do not.
func TestChannelWriterCov_IsConnError(t *testing.T) {
	for _, err := range []error{
		net.ErrClosed,
		io.EOF,
		io.ErrUnexpectedEOF,
		os.ErrDeadlineExceeded,
		&net.OpError{Op: "write", Err: net.ErrClosed},
		// a channel whose security token is not (or no longer) active
		fmt.Errorf("send: %w", opcuaerrors.ErrSecureChannelClosed),
	} {
		require.True(t, isConnError(err), "%v", err)
	}
	for _, err := range []error{ua.StatusBadEncodingError, opcuaerrors.ErrUnknownService} {
		require.False(t, isConnError(err), "%v", err)
	}
}

// A response for a channel whose security token is not active (the window
// in which the server has answered OpenSecureChannel but not yet installed
// the token): nothing can be sent on it, not even the ServiceFault that
// replaces a response that cannot be encoded. The writer ends the channel
// instead of keeping it.
func TestChannelWriterCov_NoActiveToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l, err := uacp.Listen(ctx, "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	accepted := make(chan *uacp.Conn, 1)
	go func() {
		c, _ := l.Accept(ctx)
		accepted <- c
	}()
	cconn, err := uacp.Dial(ctx, "opc.tcp://"+l.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = cconn.Close() })
	sconn := <-accepted
	require.NotNil(t, sconn)

	scfg := defaultChannelConfig()
	scfg.Logger = silentLogger()
	ssc, err := uasc.NewServerSecureChannel("opc.tcp://"+l.Addr().String(), sconn, scfg, make(chan error, 1), 1, 1, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ssc.Close() })

	w := newChannelWriter(ssc, sconn, silentLogger(), time.Second, 2)
	go w.run()
	require.True(t, w.acquire(context.Background()))
	require.NoError(t, w.send(1, unencodable()))
	cwClosed(t, w.done, "writer done")
	cwClosed(t, w.exited, "writer")
}
