// SPDX-License-Identifier: MIT

package amqp_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/amqp"
)

// peer is a hand-driven broker for the protocol corner cases the
// in-process broker does not produce.
type peer struct {
	t    *testing.T
	ln   net.Listener
	conn net.Conn
	br   *bufio.Reader
}

func newPeer(t *testing.T) *peer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &peer{t: t, ln: ln}
	t.Cleanup(func() {
		_ = ln.Close()
		if p.conn != nil {
			_ = p.conn.Close()
		}
	})
	return p
}

func (p *peer) url() string { return "amqp://" + p.ln.Addr().String() }

func (p *peer) acceptRaw() {
	p.t.Helper()
	if p.conn != nil {
		_ = p.conn.Close()
	}
	_ = p.ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := p.ln.Accept()
	require.NoError(p.t, err)
	p.conn, p.br = conn, bufio.NewReader(conn)
}

func (p *peer) header() [8]byte {
	p.t.Helper()
	var h [8]byte
	_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadFull(p.br, h[:])
	require.NoError(p.t, err)
	return h
}

func (p *peer) raw(b []byte) {
	p.t.Helper()
	_, err := p.conn.Write(b)
	require.NoError(p.t, err)
}

func (p *peer) sendType(typ byte, channel uint16, body amqp.Body, payload []byte) {
	p.t.Helper()
	b, err := amqp.AppendFrame(nil, &amqp.Frame{Type: typ, Channel: channel, Body: body, Payload: payload})
	require.NoError(p.t, err)
	p.raw(b)
}

func (p *peer) send(body amqp.Body) { p.sendType(amqp.FrameAMQP, 0, body, nil) }

func (p *peer) read() *amqp.Frame {
	p.t.Helper()
	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		f, err := amqp.ReadFrame(p.br, 1<<20)
		require.NoError(p.t, err)
		if f.Body != nil {
			return f
		}
	}
}

func expect[T amqp.Body](p *peer) T {
	p.t.Helper()
	f := p.read()
	b, ok := f.Body.(T)
	require.True(p.t, ok, "got %T", f.Body)
	return b
}

// closed reports whether the client closed the connection.
func (p *peer) closed() bool {
	_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := amqp.ReadFrame(p.br, 1<<20)
		if err != nil {
			return true
		}
		if _, ok := f.Body.(*amqp.Close); ok {
			return true
		}
	}
}

// handshake runs SASL ANONYMOUS, open and begin.
func (p *peer) handshake(open *amqp.Open) {
	p.t.Helper()
	p.acceptRaw()
	require.Equal(p.t, amqp.HeaderSASL, p.header())
	p.raw(amqp.HeaderSASL[:])
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLMechanisms{Mechanisms: []amqp.Symbol{"ANONYMOUS"}}, nil)
	init := p.read().Body.(*amqp.SASLInit)
	require.Equal(p.t, amqp.Symbol("ANONYMOUS"), init.Mechanism)
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLOutcome{Code: amqp.SASLOk}, nil)
	require.Equal(p.t, amqp.HeaderAMQP, p.header())
	p.raw(amqp.HeaderAMQP[:])
	expect[*amqp.Open](p)
	if open == nil {
		open = &amqp.Open{ContainerID: "peer", MaxFrameSize: 1 << 20}
	}
	p.send(open)
	begin := expect[*amqp.Begin](p)
	rc := uint16(0)
	p.send(&amqp.Begin{RemoteChannel: &rc, NextOutgoingID: 0, IncomingWindow: 1000, OutgoingWindow: 1000})
	require.Equal(p.t, uint32(1<<16), begin.IncomingWindow)
}

// dialPeer connects a client to p, which runs the handshake.
func dialPeer(t *testing.T, p *peer, opts amqp.Options) *amqp.Client {
	t.Helper()
	opts.Server = p.url()
	if opts.MinReconnectDelay == 0 {
		opts.MinReconnectDelay = time.Millisecond
		opts.MaxReconnectDelay = 5 * time.Millisecond
	}
	type res struct {
		c   *amqp.Client
		err error
	}
	ch := make(chan res, 1)
	go func() {
		ctx, cancel := context.WithTimeout(bg, 10*time.Second)
		defer cancel()
		c, err := amqp.Dial(ctx, opts)
		ch <- res{c, err}
	}()
	p.handshake(nil)
	r := <-ch
	require.NoError(t, r.err)
	t.Cleanup(func() { _ = r.c.Close() })
	return r.c
}

// attachSender answers the attach of a client sender and grants credit.
func (p *peer) attachSender(credit uint32) *amqp.Attach {
	p.t.Helper()
	a := expect[*amqp.Attach](p)
	require.Equal(p.t, amqp.RoleSender, a.Role)
	p.send(&amqp.Attach{Name: a.Name, Handle: 10 + a.Handle, Role: amqp.RoleReceiver, Source: a.Source, Target: a.Target})
	if credit > 0 {
		dc := uint32(0)
		h := 10 + a.Handle
		p.send(&amqp.Flow{IncomingWindow: 1000, NextOutgoingID: 0, OutgoingWindow: 1000, Handle: &h, DeliveryCount: &dc, LinkCredit: &credit})
	}
	return a
}

func TestPeerDrainEchoAndSettlement(t *testing.T) {
	p := newPeer(t)
	c := dialPeer(t, p, amqp.Options{})

	done := make(chan error, 1)
	go func() { done <- c.Send(bg, "q", dataMsg("1"), false) }()
	p.attachSender(1)
	tr := expect[*amqp.Transfer](p)
	require.Equal(t, uint32(0), *tr.DeliveryID)
	require.False(t, *tr.Settled)
	// A non-terminal state does not end the delivery; an unsettled
	// accepted does, and the client settles it.
	p.send(&amqp.Disposition{Role: amqp.RoleReceiver, First: 0, State: &amqp.Received{}})
	p.send(&amqp.Disposition{Role: amqp.RoleReceiver, First: 0, State: &amqp.Accepted{}})
	require.NoError(t, <-done)
	d := expect[*amqp.Disposition](p)
	require.Equal(t, amqp.RoleSender, d.Role)
	require.True(t, d.Settled)
	// Dispositions of the other direction and of unknown ids are ignored.
	p.send(&amqp.Disposition{Role: amqp.RoleSender, First: 0, Settled: true})
	p.send(&amqp.Disposition{Role: amqp.RoleReceiver, First: 50, Last: u32p(60), Settled: true})

	// Drain: the client has nothing to send and gives the credit back.
	h, dc, credit := uint32(10), uint32(1), uint32(5)
	nii := uint32(1)
	p.send(&amqp.Flow{NextIncomingID: &nii, IncomingWindow: 1000, OutgoingWindow: 1000, Handle: &h, DeliveryCount: &dc, LinkCredit: &credit, Drain: true})
	f := expect[*amqp.Flow](p)
	require.Equal(t, uint32(6), *f.DeliveryCount)
	require.Equal(t, uint32(0), *f.LinkCredit)
	// Echo on the link and on the session.
	p.send(&amqp.Flow{IncomingWindow: 1000, OutgoingWindow: 1000, Handle: &h, Echo: true})
	f = expect[*amqp.Flow](p)
	require.NotNil(t, f.Handle)
	p.send(&amqp.Flow{IncomingWindow: 1000, OutgoingWindow: 1000, Echo: true})
	f = expect[*amqp.Flow](p)
	require.Nil(t, f.Handle)
	// A flow for an unknown handle is ignored.
	unknown := uint32(99)
	p.send(&amqp.Flow{IncomingWindow: 1000, OutgoingWindow: 1000, Handle: &unknown})

	// No credit: the message waits; when Send gives up it is dropped.
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, c.Send(ctx, "q", dataMsg("2"), false), context.DeadlineExceeded)
	// With credit and a closed session window the message waits too.
	credit = 1
	dc = 6
	zero := uint32(0)
	p.send(&amqp.Flow{NextIncomingID: &nii, IncomingWindow: zero, OutgoingWindow: 1000, Handle: &h, DeliveryCount: &dc, LinkCredit: &credit, Drain: true})
	f = expect[*amqp.Flow](p) // drained again
	require.Equal(t, uint32(7), *f.DeliveryCount)
	credit = 1
	dc = 7
	p.send(&amqp.Flow{NextIncomingID: &nii, IncomingWindow: zero, OutgoingWindow: 1000, Handle: &h, DeliveryCount: &dc, LinkCredit: &credit})
	go func() { done <- c.Send(bg, "q", dataMsg("3"), false) }()
	time.Sleep(20 * time.Millisecond)
	p.send(&amqp.Flow{NextIncomingID: &nii, IncomingWindow: 10, OutgoingWindow: 1000})
	tr = expect[*amqp.Transfer](p)
	require.False(t, *tr.Settled)
	p.send(&amqp.Disposition{Role: amqp.RoleReceiver, First: *tr.DeliveryID, Settled: true, State: &amqp.Accepted{}})
	require.NoError(t, <-done)
}

func TestPeerReceiveCornerCases(t *testing.T) {
	p := newPeer(t)
	var lost atomic.Int32
	c := dialPeer(t, p, amqp.Options{Credit: 4, OnConnectionLost: func(error) { lost.Add(1) }})

	in := make(inbox, 10)
	subDone := make(chan error, 1)
	var sub *amqp.Subscription
	go func() {
		var err error
		sub, err = c.Subscribe(bg, "src", false, in.handle)
		subDone <- err
	}()
	a := expect[*amqp.Attach](p)
	require.Equal(t, amqp.RoleReceiver, a.Role)
	p.send(&amqp.Attach{Name: a.Name, Handle: 7, Role: amqp.RoleSender, Source: a.Source, Target: a.Target, InitialDeliveryCount: 100})
	require.NoError(t, <-subDone)
	f := expect[*amqp.Flow](p)
	require.Equal(t, uint32(4), *f.LinkCredit)
	require.Equal(t, uint32(100), *f.DeliveryCount)

	msg, err := dataMsg("multi").MarshalBinary()
	require.NoError(t, err)
	id, tag := uint32(0), []byte{1}
	settled := true
	// Two frames; the second settles the delivery.
	p.sendType(amqp.FrameAMQP, 0, &amqp.Transfer{Handle: 7, DeliveryID: &id, DeliveryTag: tag, More: true}, msg[:5])
	p.sendType(amqp.FrameAMQP, 0, &amqp.Transfer{Handle: 7, Settled: &settled}, msg[5:])
	require.Equal(t, []byte("multi"), in.next(t).Payload())
	// An aborted delivery is dropped.
	id++
	p.sendType(amqp.FrameAMQP, 0, &amqp.Transfer{Handle: 7, DeliveryID: &id, DeliveryTag: tag, More: true}, msg[:5])
	p.sendType(amqp.FrameAMQP, 0, &amqp.Transfer{Handle: 7, Aborted: true}, nil)
	// A malformed message is rejected.
	id++
	p.sendType(amqp.FrameAMQP, 0, &amqp.Transfer{Handle: 7, DeliveryID: &id, DeliveryTag: tag}, []byte{0x99})
	d := expect[*amqp.Flow](p) // credit replenished after half was used
	require.GreaterOrEqual(t, *d.LinkCredit, uint32(3))
	disp := expect[*amqp.Disposition](p)
	require.IsType(t, &amqp.Rejected{}, disp.State)
	require.Equal(t, id, disp.First)
	in.none(t, 10*time.Millisecond)

	// The broker detaches the link without error and refuses it once.
	p.send(&amqp.Detach{Handle: 7})
	expect[*amqp.Detach](p)
	a = expect[*amqp.Attach](p)
	p.send(&amqp.Attach{Name: a.Name, Handle: 8, Role: amqp.RoleSender, Target: a.Target})
	p.send(&amqp.Detach{Handle: 8, Closed: true, Error: &amqp.Error{Condition: amqp.CondNotFound}})
	expect[*amqp.Detach](p)
	a = expect[*amqp.Attach](p)
	p.send(&amqp.Attach{Name: a.Name, Handle: 9, Role: amqp.RoleSender, Source: a.Source, Target: a.Target})
	expect[*amqp.Flow](p)
	// Unsubscribe: the client detaches and waits for the answer.
	unsub := make(chan error, 1)
	go func() { unsub <- sub.Unsubscribe(bg) }()
	det := expect[*amqp.Detach](p)
	require.True(t, det.Closed)
	p.send(&amqp.Detach{Handle: 9, Closed: true})
	require.NoError(t, <-unsub)

	// A transfer on a handle that is not attached breaks the connection.
	p.sendType(amqp.FrameAMQP, 0, &amqp.Transfer{Handle: 77, DeliveryID: &id}, msg)
	require.True(t, p.closed())
	p.handshake(nil)
	require.Eventually(t, func() bool { return lost.Load() == 1 }, 5*time.Second, time.Millisecond)

	// So does an attach the client did not ask for.
	p.send(&amqp.Attach{Name: "x", Handle: 1, Role: amqp.RoleSender})
	require.True(t, p.closed())
	p.handshake(nil)
	// And a first transfer without delivery-id, on a link of the client.
	go func() { _, _ = c.Subscribe(bg, "src2", true, in.handle) }()
	a = expect[*amqp.Attach](p)
	require.Equal(t, amqp.SenderSettleSettled, a.SndSettleMode)
	p.send(&amqp.Attach{Name: a.Name, Handle: 3, Role: amqp.RoleSender, Source: a.Source, Target: a.Target, SndSettleMode: amqp.SenderSettleSettled})
	expect[*amqp.Flow](p)
	p.sendType(amqp.FrameAMQP, 0, &amqp.Transfer{Handle: 3}, msg)
	require.True(t, p.closed())
	p.handshake(nil)
	// The resubscription after the reconnect: answer it twice (a handle
	// in use).
	a = expect[*amqp.Attach](p)
	p.send(&amqp.Attach{Name: a.Name, Handle: 3, Role: amqp.RoleSender, Source: a.Source, Target: a.Target})
	expect[*amqp.Flow](p)
	p.send(&amqp.Attach{Name: a.Name, Handle: 3, Role: amqp.RoleSender, Source: a.Source, Target: a.Target})
	require.True(t, p.closed())
	p.handshake(nil)
	expect[*amqp.Attach](p)
	// A frame on another channel, a SASL frame, an unexpected performative.
	for _, f := range []*amqp.Frame{
		{Channel: 5, Body: &amqp.Flow{}},
		{Type: amqp.FrameSASL, Body: &amqp.SASLOutcome{}},
		{Body: &amqp.Open{ContainerID: "again"}},
	} {
		b, err := amqp.AppendFrame(nil, f)
		require.NoError(t, err)
		p.raw(b)
		require.True(t, p.closed())
		p.handshake(nil)
		expect[*amqp.Attach](p)
	}
	// The broker ends the session: the client answers and reconnects.
	p.send(&amqp.End{Error: &amqp.Error{Condition: "amqp:session:window-violation"}})
	expect[*amqp.End](p)
	expect[*amqp.Close](p)
	p.handshake(nil)
	expect[*amqp.Attach](p)
	// A frame above the client's limit.
	p.sendType(amqp.FrameAMQP, 0, &amqp.Transfer{Handle: 3}, make([]byte, amqp.DefaultMaxFrameSize))
	require.True(t, p.closed())
}

func TestPeerHandshakeFailures(t *testing.T) {
	p := newPeer(t)
	dialErr := func(opts amqp.Options) chan error {
		opts.Server = p.url()
		opts.MinReconnectDelay = time.Millisecond
		opts.MaxReconnectDelay = 5 * time.Millisecond
		ch := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(bg, 3*time.Second)
			defer cancel()
			c, err := amqp.Dial(ctx, opts)
			if c != nil {
				_ = c.Close()
			}
			ch <- err
		}()
		return ch
	}
	// The server answers the SASL header with another one.
	ch := dialErr(amqp.Options{})
	p.acceptRaw()
	p.header()
	p.raw([]byte("HTTP/1.1"))
	require.ErrorContains(t, <-ch, "protocol header")
	// The server does not use SASL.
	ch = dialErr(amqp.Options{})
	p.acceptRaw()
	p.header()
	p.raw(amqp.HeaderAMQP[:])
	require.ErrorContains(t, <-ch, "NONE")
	// A wrong AMQP header after SASL is not retried either.
	ch = dialErr(amqp.Options{SASLMechanism: amqp.SASLPlain, Username: "u"})
	p.acceptRaw()
	p.header()
	p.raw(amqp.HeaderSASL[:])
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLMechanisms{Mechanisms: []amqp.Symbol{"PLAIN"}}, nil)
	expect[*amqp.SASLInit](p)
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLOutcome{Code: amqp.SASLOk}, nil)
	p.header()
	p.raw(amqp.HeaderTLS[:])
	require.ErrorContains(t, <-ch, "protocol header")

	// Transient failures are retried until the context ends.
	ch = dialErr(amqp.Options{SASLMechanism: amqp.SASLPlain, Username: "u"})
	// A challenge is answered; a non-SASL frame fails the attempt.
	p.acceptRaw()
	p.header()
	p.raw(amqp.HeaderSASL[:])
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLMechanisms{Mechanisms: []amqp.Symbol{"PLAIN"}}, nil)
	init := expect[*amqp.SASLInit](p)
	require.Equal(t, []byte("\x00u\x00"), init.InitialResponse)
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLChallenge{Challenge: []byte("c")}, nil)
	expect[*amqp.SASLResponse](p)
	p.send(&amqp.Close{})
	// sasl-mechanisms expected, got something else.
	p.acceptRaw()
	p.header()
	p.raw(amqp.HeaderSASL[:])
	p.send(&amqp.Close{})
	// A temporary SASL failure.
	p.acceptRaw()
	p.header()
	p.raw(amqp.HeaderSASL[:])
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLMechanisms{Mechanisms: []amqp.Symbol{"PLAIN"}}, nil)
	expect[*amqp.SASLInit](p)
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLOutcome{Code: amqp.SASLSysTemp}, nil)
	// No open.
	p.acceptRaw()
	p.header()
	p.raw(amqp.HeaderSASL[:])
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLMechanisms{Mechanisms: []amqp.Symbol{"PLAIN"}}, nil)
	expect[*amqp.SASLInit](p)
	p.sendType(amqp.FrameSASL, 0, &amqp.SASLOutcome{Code: amqp.SASLOk}, nil)
	p.header()
	p.raw(amqp.HeaderAMQP[:])
	expect[*amqp.Open](p)
	p.send(&amqp.Begin{})
	// A close without error instead of the begin, then a begin for
	// another channel, then something else.
	for _, body := range []amqp.Body{&amqp.Close{}, &amqp.Begin{IncomingWindow: 1}, &amqp.End{}} {
		p.acceptRaw()
		p.header()
		p.raw(amqp.HeaderSASL[:])
		p.sendType(amqp.FrameSASL, 0, &amqp.SASLMechanisms{Mechanisms: []amqp.Symbol{"PLAIN"}}, nil)
		expect[*amqp.SASLInit](p)
		p.sendType(amqp.FrameSASL, 0, &amqp.SASLOutcome{Code: amqp.SASLOk}, nil)
		p.header()
		p.raw(amqp.HeaderAMQP[:])
		expect[*amqp.Open](p)
		p.send(&amqp.Open{ContainerID: "p"})
		expect[*amqp.Begin](p)
		p.send(body)
	}
	p.acceptRaw() // and silence until the deadline
	err := <-ch
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
}

func TestPeerCloseDuringSubscribe(t *testing.T) {
	p := newPeer(t)
	c := dialPeer(t, p, amqp.Options{})
	// The connection breaks while Subscribe waits: the subscription is
	// kept and attached on the next connection.
	ch := make(chan error, 1)
	go func() {
		_, err := c.Subscribe(bg, "s", false, func(*amqp.Message) {})
		ch <- err
	}()
	expect[*amqp.Attach](p)
	_ = p.conn.Close()
	require.NoError(t, <-ch)
	p.handshake(nil)
	a := expect[*amqp.Attach](p)
	require.Equal(t, "s", a.Source.Address)

	// Subscribe gives up when its context ends: the half-attached link is
	// detached.
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	_, err := c.Subscribe(ctx, "t", false, func(*amqp.Message) {})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	a = expect[*amqp.Attach](p)
	require.Equal(t, "t", a.Source.Address)
	expect[*amqp.Detach](p)
	// The answers arrive late.
	p.send(&amqp.Attach{Name: a.Name, Handle: 4, Role: amqp.RoleSender, Source: a.Source, Target: a.Target})
	p.send(&amqp.Detach{Handle: 4, Closed: true})

	// Unsubscribe gives up when its context ends.
	go func() {
		_, err := c.Subscribe(bg, "u", false, func(*amqp.Message) {})
		ch <- err
	}()
	a = expect[*amqp.Attach](p)
	p.send(&amqp.Attach{Name: a.Name, Handle: 5, Role: amqp.RoleSender, Source: a.Source, Target: a.Target})
	require.NoError(t, <-ch)
	expect[*amqp.Flow](p)
	// The broker closes the connection with an error; the client answers.
	p.send(&amqp.Close{Error: &amqp.Error{Condition: amqp.CondConnectionForced}})
	expect[*amqp.Close](p)
	p.handshake(nil)
	expect[*amqp.Attach](p)
	expect[*amqp.Attach](p)
}

func TestPeerUnsubscribeTimeout(t *testing.T) {
	p := newPeer(t)
	c := dialPeer(t, p, amqp.Options{})
	ch := make(chan *amqp.Subscription, 1)
	go func() {
		s, err := c.Subscribe(bg, "u", false, func(*amqp.Message) {})
		require.NoError(t, err)
		ch <- s
	}()
	a := expect[*amqp.Attach](p)
	p.send(&amqp.Attach{Name: a.Name, Handle: 5, Role: amqp.RoleSender, Source: a.Source, Target: a.Target})
	sub := <-ch
	expect[*amqp.Flow](p)
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, sub.Unsubscribe(ctx), context.DeadlineExceeded)
	expect[*amqp.Detach](p)
	// Close while a Send waits for credit.
	errc := make(chan error, 1)
	go func() { errc <- c.Send(bg, "q", dataMsg("x"), false) }()
	p.attachSender(0)
	require.NoError(t, c.Close())
	require.ErrorIs(t, <-errc, amqp.ErrClosed)
}

func u32p(n uint32) *uint32 { return &n }
