// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// rcWait is the generous bound for things that happen asynchronously.
const rcWait = 30 * time.Second

func rcEventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(rcWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s: %s", rcWait, msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// rcServer returns an unstarted server without an address space: enough for
// everything up to the secure channel.
func rcServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	s, err := newServerNoNS(append([]Option{
		EndPoint("localhost", 0),
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
		ApplicationURI("urn:otfabric:test:reverse"),
	}, opts...)...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func rcListener(t *testing.T) (*uacp.ReverseListener, string) {
	t.Helper()
	l, err := uacp.ListenReverse(context.Background(), "127.0.0.1:0", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l, "opc.tcp://" + l.Addr().String()
}

var rcFast = ReverseConnectRetryInterval(10*time.Millisecond, 50*time.Millisecond)

func TestReverseConnectStateString(t *testing.T) {
	for st, want := range map[ReverseConnectState]string{
		ReverseConnectConnecting: "Connecting",
		ReverseConnectWaiting:    "Waiting",
		ReverseConnectConnected:  "Connected",
		ReverseConnectBackoff:    "Backoff",
		ReverseConnectClosed:     "Closed",
		ReverseConnectState(42):  "ReverseConnectState(42)",
	} {
		require.Equal(t, want, st.String())
	}
}

func TestReverseConnectConfigDefaults(t *testing.T) {
	c := newReverseConnectConfig(nil)
	require.Equal(t, DefaultReverseConnectRetryInterval, c.retryInterval)
	require.Equal(t, DefaultReverseConnectMaxRetryInterval, c.maxRetry)
	require.Equal(t, DefaultReverseConnectMaxConnections, c.maxConnections)
	require.Empty(t, c.endpointURL)

	c = newReverseConnectConfig([]ReverseConnectOption{
		nil,
		ReverseConnectRetryInterval(time.Minute, time.Second), // max below initial
		ReverseConnectMaxConnections(-1),
		ReverseConnectEndpointURL("opc.tcp://announced:4840"),
	})
	require.Equal(t, time.Minute, c.retryInterval)
	require.Equal(t, time.Minute, c.maxRetry, "the upper bound is at least the initial delay")
	require.Equal(t, DefaultReverseConnectMaxConnections, c.maxConnections)
	require.Equal(t, "opc.tcp://announced:4840", c.endpointURL)

	c = newReverseConnectConfig([]ReverseConnectOption{ReverseConnectRetryInterval(0, -1), ReverseConnectMaxConnections(3)})
	require.Equal(t, DefaultReverseConnectRetryInterval, c.retryInterval)
	require.Equal(t, DefaultReverseConnectMaxRetryInterval, c.maxRetry)
	require.Equal(t, 3, c.maxConnections)
}

func TestApplicationURIOption(t *testing.T) {
	_, err := newServerNoNS(ApplicationURI(""))
	require.Error(t, err)

	s, err := newServerNoNS(ApplicationURI("urn:explicit"))
	require.NoError(t, err)
	require.Equal(t, "urn:explicit", s.cfg.applicationURI)
}

// A target can be added, inspected and removed before the server is started;
// one that is still there becomes active with Start.
func TestReverseConnectBeforeStart(t *testing.T) {
	l, clientURL := rcListener(t)
	s := rcServer(t, WithReverseConnect(clientURL, rcFast))
	require.Empty(t, s.ReverseConnects(), "configured targets are created by Start")

	early, err := s.AddReverseConnect(clientURL, rcFast)
	require.NoError(t, err)
	removed, err := s.AddReverseConnect(clientURL, rcFast)
	require.NoError(t, err)
	require.Equal(t, []*ReverseConnect{early, removed}, s.ReverseConnects())
	require.Equal(t, ReverseConnectConnecting, early.State())
	require.NoError(t, early.Err())
	require.Zero(t, early.Connections())
	require.Equal(t, clientURL, early.ClientURL())

	require.NoError(t, removed.Close())
	require.Equal(t, ReverseConnectClosed, removed.State())
	require.Equal(t, []*ReverseConnect{early}, s.ReverseConnects())

	require.NoError(t, s.Start(context.Background()))
	rcs := s.ReverseConnects()
	require.Len(t, rcs, 2, "the early target and the configured one")
	// Both announce themselves; the listener keeps the newer connection of
	// the same server.
	rcEventually(t, func() bool {
		return rcs[0].State() == ReverseConnectWaiting || rcs[1].State() == ReverseConnectWaiting
	}, "a target has announced itself")
	rcEventually(t, func() bool { return l.Pending() == 1 }, "announced connection pending")

	// The announcement names the server and its first endpoint.
	c, rhe, err := l.Accept(context.Background(), nil)
	require.NoError(t, err)
	_ = c.Close()
	require.Equal(t, "urn:otfabric:test:reverse", rhe.ServerURI)
	require.Equal(t, s.URLs()[0], rhe.EndpointURL)
	require.Contains(t, rhe.EndpointURL, net.JoinHostPort("localhost", strconv.Itoa(s.Port())))

	// Starting a started target again changes nothing.
	rcs[0].start(context.Background())

	require.NoError(t, s.Close())
	for _, rc := range rcs {
		require.Equal(t, ReverseConnectClosed, rc.State())
	}
	require.Empty(t, s.ReverseConnects())
	_, err = s.AddReverseConnect(clientURL)
	require.ErrorContains(t, err, "closed")
	// A target of a closed server does not start.
	removed.start(context.Background())
	require.Equal(t, ReverseConnectClosed, removed.State())
}

// A client that takes a connection and answers with Hello gets a secure
// channel on it; the server reports the connection as in use and opens the
// next idle one.
func TestReverseConnectServesConnection(t *testing.T) {
	l, clientURL := rcListener(t)
	s := rcServer(t)
	require.NoError(t, s.Start(context.Background()))
	rc, err := s.AddReverseConnect(clientURL, rcFast, ReverseConnectMaxConnections(2))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), rcWait)
	defer cancel()
	d := &uacp.Dialer{Dialer: &net.Dialer{Timeout: rcWait}}
	c1, rhe, err := d.AcceptReverse(ctx, l, "", nil)
	require.NoError(t, err)
	require.Equal(t, s.URLs()[0], rhe.EndpointURL)
	rcEventually(t, func() bool { return rc.Connections() == 1 && rc.State() == ReverseConnectConnected }, "first connection in use")
	rcEventually(t, func() bool { return s.resourceCounts().Channels == 1 }, "channel registered")

	// The next idle connection is on its way already.
	c2, _, err := d.AcceptReverse(ctx, l, "", nil)
	require.NoError(t, err)
	rcEventually(t, func() bool { return rc.Connections() == 2 }, "second connection in use")

	// The limit is reached: no third connection is offered...
	require.Zero(t, l.Pending())
	short, cancelShort := context.WithTimeout(ctx, 100*time.Millisecond)
	_, _, err = l.Accept(short, nil)
	cancelShort()
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// ...until one of the two is released.
	require.NoError(t, c1.Close())
	rcEventually(t, func() bool { return l.Pending() == 1 }, "idle connection after a slot became free")
	require.NoError(t, c2.Close())
	rcEventually(t, func() bool { return rc.Connections() == 0 && s.resourceCounts().Channels == 0 }, "connections released")
	require.NoError(t, rc.Err())
}

// A client that answers the announcement with something else than Hello is
// dropped and the server tries again after a delay.
func TestReverseConnectRetriesAfterBadClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ACKF\x1c\x00\x00\x00" + "01234567890123456789")) // not a Hello
			accepted <- c
		}
	}()

	s := rcServer(t)
	require.NoError(t, s.Start(context.Background()))
	rc, err := s.AddReverseConnect("opc.tcp://"+ln.Addr().String(), rcFast)
	require.NoError(t, err)

	for range 3 {
		select {
		case c := <-accepted:
			defer func() { _ = c.Close() }()
		case <-time.After(rcWait):
			t.Fatal("server did not retry")
		}
	}
	rcEventually(t, func() bool { return rc.Err() != nil }, "failure reported")
	require.Zero(t, rc.Connections())
	require.Zero(t, s.resourceCounts().Channels)
	require.NoError(t, rc.Close())
	require.NoError(t, rc.Close())
}

func TestFirstEndpointURL(t *testing.T) {
	s, err := newServerNoNS(ListenOn("127.0.0.1:4840"))
	require.NoError(t, err)
	require.Equal(t, "opc.tcp://127.0.0.1:4840", s.firstEndpointURL(), "falls back to the listen address")
	require.Equal(t, context.Background(), s.serveContext())

	s, err = newServerNoNS(EndPoint("advertised", 4840), ListenOn("127.0.0.1:4840"))
	require.NoError(t, err)
	require.Equal(t, "opc.tcp://advertised:4840", s.firstEndpointURL())
}
