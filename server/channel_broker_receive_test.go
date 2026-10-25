// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// brokerPair is an open secure channel whose server side is read by the
// channel broker's receive loop. Nothing handles the requests the broker
// hands on: the test takes them from the broker itself, or leaves them
// waiting as a request handler that is busy with other channels would.
type brokerPair struct {
	cb  *channelBroker
	w   *channelWriter
	csc *uasc.SecureChannel
}

func newBrokerPair(t *testing.T) *brokerPair {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()

	l, err := uacp.Listen(dialCtx, "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	endpoint := "opc.tcp://" + l.Addr().String()
	type acc struct {
		c   *uacp.Conn
		err error
	}
	accepted := make(chan acc, 1)
	go func() {
		c, err := l.Accept(dialCtx)
		accepted <- acc{c, err}
	}()
	cconn, err := uacp.Dial(dialCtx, endpoint)
	require.NoError(t, err)
	a := <-accepted
	require.NoError(t, a.err)
	sconn := a.c

	scfg := defaultChannelConfig()
	scfg.Logger = silentLogger()
	ssc, err := uasc.NewServerSecureChannel(endpoint, sconn, scfg, make(chan error, 1), 1, 1, 1)
	require.NoError(t, err)
	csc, err := uasc.NewSecureChannel(endpoint, cconn, &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    10 * time.Second,
		Logger:            silentLogger(),
	}, make(chan error, 1))
	require.NoError(t, err)

	p := &brokerPair{
		cb:  newChannelBroker(silentLogger(), endpoint, nil),
		w:   newChannelWriter(ssc, sconn, silentLogger(), 0, 0),
		csc: csc,
	}
	received := make(chan struct{})
	go p.w.run()
	go func() {
		defer close(received)
		p.cb.receive(ctx, ssc, p.w, 1)
	}()
	t.Cleanup(func() {
		cancel()
		p.w.close()
		<-p.w.exited
		_ = csc.Close()
		_ = ssc.Close()
		_ = cconn.Close()
		<-received
	})
	require.NoError(t, csc.Open(dialCtx))
	return p
}

// call sends a request from the client side and returns a channel with the
// response (or the error) once it arrives.
func (p *brokerPair) call(req ua.Request) <-chan cwResult {
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

// A channel's requests wait for the server's request handler, which serves
// every channel one request at a time. The channel must go on reading while
// they wait: a token renewal that the client sends behind them used to sit
// unread in the socket until the handler took them, and on a busy server
// the token it renews ran out meanwhile and the channel was closed.
func TestChannelBroker_RenewalIsNotHeldUpByWaitingRequests(t *testing.T) {
	p := newBrokerPair(t)

	// Two requests the handler does not get to, read by the server before
	// the client renews (each takes an in-flight slot when it is read).
	first := p.call(cwReadRequest())
	require.Eventually(t, func() bool { return len(p.w.slots) == 1 }, 30*time.Second, time.Millisecond,
		"the first request was not read")
	second := p.call(cwReadRequest())
	require.Eventually(t, func() bool { return len(p.w.slots) == 2 }, 30*time.Second, time.Millisecond,
		"the second request was not read while the first one waits for the handler")

	// The renewal is answered all the same, from the read loop.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, p.csc.Renew(ctx), "the renewal waited for the request handler")

	// Once the handler gets to them, the requests are answered in the order
	// they were sent, secured with the new token.
	for _, res := range []<-chan cwResult{first, second} {
		in, ok := p.cb.ReadMessage(ctx)
		require.True(t, ok, "the requests are handed to the request handler")
		require.NoError(t, in.w.send(in.msg.RequestID, &ua.ReadResponse{ResponseHeader: cwHeader(ua.StatusOK), Results: []*ua.DataValue{}}))
		r := cwWait(t, res)
		require.NoError(t, r.err)
	}
}

// The requests read before a channel ends are still handed to the request
// handler: a client that sends CloseSession and closes the channel right
// after must not leave its session behind.
func TestChannelBroker_RequestsReadBeforeTheEndAreHandled(t *testing.T) {
	p := newBrokerPair(t)

	_ = p.call(cwReadRequest())
	// The client closes the channel (CloseSecureChannel) while the request
	// waits for the handler.
	require.Eventually(t, func() bool { return len(p.w.slots) == 1 }, 30*time.Second, time.Millisecond,
		"the request was not read")
	// Close reports the end of the connection, which the server answers
	// the CloseSecureChannel with.
	_ = p.csc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	in, ok := p.cb.ReadMessage(ctx)
	require.True(t, ok, "the request read before the channel ended was dropped")
	_, isRead := in.msg.Request().(*ua.ReadRequest)
	require.True(t, isRead)
}
