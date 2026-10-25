// SPDX-License-Identifier: MIT

package session

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// Reverse connect (Part 6 §7.1.3): the server opens the TCP connection to a
// listening client and announces itself with a ReverseHello message.

// reverseServer starts a None server with the fixture that announces itself
// as appURI to the client listening at clientURL.
func reverseServer(t *testing.T, appURI, clientURL string, opts ...server.Option) (*server.Server, *testutil.Fixture, string) {
	t.Helper()
	all := append([]server.Option{
		server.ApplicationURI(appURI),
		server.WithReverseConnect(clientURL, fastReverseRetry),
	}, opts...)
	// The fixture before Start: the server connects to a waiting client at
	// once, and its first session creates the diagnostics namespace.
	var f *testutil.Fixture
	srv, url := conformkit.NewServerPrepared(t, func(srv *server.Server) { f = testutil.AddFixture(t, srv) }, all...)
	return srv, f, url
}

// isAddrInUse reports whether err says that a listen address is taken.
func isAddrInUse(err error) bool {
	return err != nil && strings.Contains(err.Error(), "address already in use")
}

// withListenPort calls fn with loopback addresses whose port was free a
// moment ago until fn does not fail because the port was taken by somebody
// else in the meantime, and returns fn's error. It is for tests of clients
// that open their own listener, for which the port must be known up front.
func withListenPort(t *testing.T, fn func(addr string) error) error {
	t.Helper()
	var err error
	for range 20 {
		addr := fmt.Sprintf("127.0.0.1:%d", freeCustomPort(t))
		if err = fn(addr); !isAddrInUse(err) {
			return err
		}
	}
	return err
}

// requireReverseConnected asserts that the client's channel really runs over
// a connection the server opened: the target reports it as in use.
func requireReverseConnected(t *testing.T, srv *server.Server, connections int) *server.ReverseConnect {
	t.Helper()
	rcs := srv.ReverseConnects()
	require.Len(t, rcs, 1)
	rc := rcs[0]
	eventually(t, func() bool {
		return rc.State() == server.ReverseConnectConnected && rc.Connections() == connections
	}, fmt.Sprintf("reverse connect target reports %d connection(s) in use", connections))
	require.NoError(t, rc.Err())
	return rc
}

// TestReverseConnect_None covers the basic exchange without security: the
// server connects to the listening client, and reads, writes and a
// subscription work over that connection.
func TestReverseConnect_None(t *testing.T) {
	const appURI = "urn:otfabric:conformance:reverse:none"
	l, clientURL := reverseListener(t, nil)
	srv, f, url := reverseServer(t, appURI, clientURL)
	ctx := context.Background()

	c := newClient(t, url, opcua.ReverseConnectListener(l, opcua.ReverseServerURI(appURI)))
	rc := requireReverseConnected(t, srv, 1)
	require.Equal(t, clientURL, rc.ClientURL())
	require.Equal(t, "Connected", rc.State().String())

	// The session was created for the announced endpoint.
	eps := c.Session().ServerEndpoints()
	require.Len(t, eps, 1)
	require.Equal(t, url, eps[0].EndpointURL)
	require.Equal(t, appURI, eps[0].Server.ApplicationURI)

	dv, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())

	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(ctx) })
	awaitValue(t, ch, 0, int32(42))
	writeInt32(t, c, f.Int32, 1001)
	awaitValue(t, ch, 0, int32(1001))

	// A request large enough to need several chunks in both directions.
	ids := make([]*ua.NodeID, 600)
	for i := range ids {
		ids[i] = f.Int32Array
	}
	dvs, err := c.ReadValues(ctx, ids...)
	require.NoError(t, err)
	require.Len(t, dvs, len(ids))

	// Closing the client frees the connection; the server keeps an idle one
	// ready, which the listener holds for the next client.
	require.NoError(t, c.Close(ctx))
	eventually(t, func() bool { return rc.Connections() == 0 }, "connection released")
	eventually(t, func() bool { return rc.State() == server.ReverseConnectWaiting }, "idle connection announced")
	eventually(t, func() bool { return l.Pending() == 1 }, "idle connection pending at the listener")

	c2 := newClient(t, url, opcua.ReverseConnectListener(l, opcua.ReverseServerURI(appURI)))
	dv, err = c2.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(1001), dv.Value.Value())
}

// TestReverseConnect_Secure runs the discovery helpers and secured sessions
// over reverse connections: the endpoints are fetched through one, and then
// used for signed and encrypted channels with full certificate validation.
func TestReverseConnect_Secure(t *testing.T) {
	l, clientURL := reverseListener(t, nil)
	srv, url := newServer(t, secureServerOpts(t, server.WithReverseConnect(clientURL, fastReverseRetry))...)
	f := testutil.AddFixture(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	reverse := opcua.ReverseConnectListener(l, opcua.ReverseServerURI(serverAppURI))
	discovery := []opcua.Option{reverse, opcua.DialTimeout(30 * time.Second), opcua.RequestTimeout(30 * time.Second)}

	eps, err := opcua.GetEndpoints(ctx, url, discovery...)
	require.NoError(t, err)
	require.NotEmpty(t, eps)

	servers, err := opcua.FindServers(ctx, url, discovery...)
	require.NoError(t, err)
	require.Len(t, servers, 1)
	require.Equal(t, serverAppURI, servers[0].ApplicationURI)

	// Only a discovery server implements FindServersOnNetwork; what matters
	// here is that the request reaches the server over a reverse connection.
	_, err = opcua.FindServersOnNetwork(ctx, url, discovery...)
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)

	for _, tc := range []struct {
		policy string
		mode   ua.MessageSecurityMode
	}{
		{ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign},
		{ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt},
		{ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.MessageSecurityModeSignAndEncrypt},
		{ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt},
	} {
		t.Run(shortPolicy(tc.policy)+"/"+tc.mode.String(), func(t *testing.T) {
			var ep *ua.EndpointDescription
			for _, e := range eps {
				if e.SecurityPolicyURI == tc.policy && e.SecurityMode == tc.mode {
					ep = e
				}
			}
			require.NotNil(t, ep, "endpoint advertised")

			c := newClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeAnonymous), reverse)...)
			require.Equal(t, tc.policy, c.SecurityPolicy())
			require.Equal(t, tc.mode, c.SecurityMode())

			want := "reverse-" + shortPolicy(tc.policy) + "-" + tc.mode.String()
			st, err := c.WriteNodeValue(ctx, f.String, want)
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, st)
			dv, err := c.ReadValue(ctx, f.String)
			require.NoError(t, err)
			require.Equal(t, want, dv.Value.Value())

			sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
			require.NoError(t, err)
			awaitValue(t, ch, 0, int32(42))
			require.NoError(t, sub.Cancel(ctx))
			require.NoError(t, c.Close(ctx))
		})
	}
}

// TestReverseConnect_ServerURIMustMatchCertificate verifies that a secured
// client does not accept a reverse connection announced under another name
// than the ApplicationUri of the server certificate it trusts.
func TestReverseConnect_ServerURIMustMatchCertificate(t *testing.T) {
	const announced = "urn:otfabric:conformance:reverse:impostor"
	l, clientURL := reverseListener(t, nil)

	// The endpoint description of a correctly configured server.
	_, goodURL := secureServer(t)
	ep := endpointFor(t, goodURL, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)

	// A server with the same certificate that announces another ServerUri.
	_, url := newServer(t, secureServerOpts(t,
		server.ApplicationURI(announced),
		server.WithReverseConnect(clientURL, fastReverseRetry),
	)...)

	_, err := dialClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeAnonymous),
		opcua.ReverseConnectListener(l))...)
	require.ErrorIs(t, err, errors.ErrReverseHelloRejected)
	require.ErrorContains(t, err, announced)
	require.ErrorContains(t, err, serverAppURI)
}

// TestReverseConnect_MismatchRejected verifies that a client with a listener
// of its own turns away a server that announces an unexpected ServerUri or
// EndpointUrl, keeps waiting, and reports the refusal when it gives up. The
// server sees the refusal as the error of its connection attempt.
func TestReverseConnect_MismatchRejected(t *testing.T) {
	const appURI = "urn:otfabric:conformance:reverse:actual"
	srv, url := newServer(t, server.ApplicationURI(appURI))
	testutil.AddFixture(t, srv)

	for _, tc := range []struct {
		name     string
		endpoint string
		opts     []opcua.ReverseConnectOption
		status   ua.StatusCode
		detail   string
	}{
		{
			name:     "ServerUri",
			endpoint: url,
			opts:     []opcua.ReverseConnectOption{opcua.ReverseServerURI("urn:otfabric:conformance:reverse:expected")},
			status:   ua.StatusBadServerURIInvalid,
			detail:   "ServerUri",
		},
		{
			name:     "EndpointUrl",
			endpoint: "opc.tcp://elsewhere.invalid:4840",
			opts:     []opcua.ReverseConnectOption{opcua.ReverseServerURI(appURI)},
			status:   ua.StatusBadTCPEndpointURLInvalid,
			detail:   "EndpointUrl",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var rc *server.ReverseConnect
			err := withListenPort(t, func(addr string) error {
				c, err := opcua.NewClient(tc.endpoint,
					opcua.ReverseConnect(addr, tc.opts...),
					opcua.DialTimeout(0), // wait until the context is done
					opcua.AutoReconnect(false),
				)
				require.NoError(t, err)
				defer func() { _ = c.Close(context.Background()) }()

				errCh := make(chan error, 1)
				go func() { errCh <- c.Connect(ctx) }()

				rc, err = srv.AddReverseConnect("opc.tcp://"+addr, fastReverseRetry)
				require.NoError(t, err)
				defer func() { require.NoError(t, rc.Close()) }()

				// The server is refused, again and again...
				deadline := time.After(waitTimeout)
				for !errors.Is(rc.Err(), tc.status) {
					select {
					case err := <-errCh:
						return err // failed to listen, or connected after all
					case <-deadline:
						return fmt.Errorf("server was not refused, last error: %v", rc.Err())
					case <-time.After(5 * time.Millisecond):
					}
				}
				require.Zero(t, rc.Connections())

				// ...while the client keeps waiting for the right one.
				select {
				case err := <-errCh:
					return fmt.Errorf("Connect returned early: %w", err)
				default:
				}
				cancel()
				return <-errCh
			})
			require.ErrorIs(t, err, context.Canceled)
			require.ErrorIs(t, err, errors.ErrReverseHelloRejected)
			require.ErrorContains(t, err, tc.detail)
		})
	}
	require.Empty(t, srv.ReverseConnects(), "closed targets are removed")
}

// TestReverseConnect_OwnListener covers a client that opens its own listener:
// discovery and a session over it, and that the listener is released when
// the client closes.
func TestReverseConnect_OwnListener(t *testing.T) {
	const appURI = "urn:otfabric:conformance:reverse:own"
	srv, url := newServer(t, server.ApplicationURI(appURI))
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	err := withListenPort(t, func(addr string) error {
		rc, err := srv.AddReverseConnect("opc.tcp://"+addr, fastReverseRetry)
		require.NoError(t, err)
		defer func() { require.NoError(t, rc.Close()) }()

		reverse := opcua.ReverseConnect("opc.tcp://"+addr, opcua.ReverseServerURI(appURI))
		eps, err := opcua.GetEndpoints(ctx, url, reverse, opcua.DialTimeout(30*time.Second))
		if err != nil {
			return err
		}
		require.Len(t, eps, 1)
		require.Equal(t, appURI, eps[0].Server.ApplicationURI)

		// The helper has released the port again: the next client can
		// listen on it.
		c, err := opcua.NewClient(url, reverse,
			opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(30*time.Second), opcua.AutoReconnect(false))
		require.NoError(t, err)
		defer func() { _ = c.Close(ctx) }()
		if err := c.Connect(ctx); err != nil {
			return err
		}
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
		require.NoError(t, c.Close(ctx))

		// Nothing listens on the address any more.
		eventually(t, func() bool {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				_ = conn.Close()
			}
			return err != nil
		}, "listener closed with the client")
		return nil
	})
	require.NoError(t, err)

	// Invalid listen addresses are rejected when the client is created.
	for _, addr := range []string{"", "no-port", "http://127.0.0.1:4841"} {
		_, err := opcua.NewClient(url, opcua.ReverseConnect(addr))
		require.Error(t, err, addr)
	}
	_, err = opcua.NewClient(url, opcua.ReverseConnectListener(nil))
	require.Error(t, err)
}

// TestReverseConnect_ServerRetriesUntilClientListens verifies that a server
// keeps trying, with a growing delay, while nothing accepts its reverse
// connection, and connects once the client is there.
func TestReverseConnect_ServerRetriesUntilClientListens(t *testing.T) {
	const appURI = "urn:otfabric:conformance:reverse:retry"

	// The server's target is a proxy that turns every connection away, as if
	// the client were not listening yet.
	proxy := testutil.NewChaosProxy(t, "", 1)
	proxy.SetRefuse(true)
	srv, f, url := reverseServer(t, appURI, proxy.EndpointURL())

	rc := srv.ReverseConnects()[0]
	eventually(t, func() bool {
		return proxy.Accepted() >= 3 && rc.State() == server.ReverseConnectBackoff && rc.Err() != nil
	}, "server retries and reports the failure")
	require.Zero(t, rc.Connections())

	// The client starts listening.
	l, _ := reverseListener(t, nil)
	proxy.SetBackend(l.Addr().String())
	proxy.SetRefuse(false)

	c := newClient(t, url, opcua.ReverseConnectListener(l, opcua.ReverseServerURI(appURI)))
	dv, err := c.ReadValue(context.Background(), f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())
	eventually(t, func() bool { return rc.State() == server.ReverseConnectConnected && rc.Err() == nil }, "target connected")
}

// TestReverseConnect_AutoReconnectAfterServerRestart verifies that a client
// goes back to waiting for the server when the connection is lost and
// restores its session and subscriptions once the server, here a brand-new
// instance, connects again.
func TestReverseConnect_AutoReconnectAfterServerRestart(t *testing.T) {
	const appURI = "urn:otfabric:conformance:reverse:restart"
	l, clientURL := reverseListener(t, nil)
	srv1, f1, url1 := reverseServer(t, appURI, clientURL)
	ctx := context.Background()

	// The client is created without an endpoint URL: it uses whatever the
	// server announces, which changes with the restart.
	states := &stateRecorder{}
	c := newClient(t, "",
		opcua.ReverseConnectListener(l, opcua.ReverseServerURI(appURI)),
		opcua.AutoReconnect(true),
		opcua.ReconnectInterval(50*time.Millisecond),
		opcua.WithConnStateHandler(states.Record),
	)
	eps := c.Session().ServerEndpoints()
	require.Len(t, eps, 1)
	require.Equal(t, url1, eps[0].EndpointURL)
	oldSession := c.Session().SessionID().String()

	ch := make(chan *opcua.PublishNotificationData, 256)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
	require.NoError(t, err)
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(f1.Int32, ua.AttributeIDValue, 7))
	require.NoError(t, err)
	awaitValue(t, ch, 7, int32(42))
	writeInt32(t, c, f1.Int32, 77)
	awaitValue(t, ch, 7, int32(77))

	// Take the server away.
	rc1 := srv1.ReverseConnects()[0]
	require.NoError(t, srv1.Close())
	require.Equal(t, server.ReverseConnectClosed, rc1.State())
	require.Empty(t, srv1.ReverseConnects())
	eventually(t, func() bool { return states.Seen(opcua.Reconnecting) }, "client starts waiting for the server again")

	// A new instance of the same application connects from another port.
	_, f2, url2 := reverseServer(t, appURI, clientURL)
	require.NotEqual(t, url1, url2)
	require.Equal(t, f1.NSIndex, f2.NSIndex, "the recreated monitored item names the node by the first instance's index")
	eventually(t, func() bool { return states.SeenAfter(opcua.Reconnecting, opcua.Connected) }, "client reconnects")
	eventually(t, func() bool { return c.State() == opcua.Connected && c.Session() != nil }, "state Connected")
	require.NotEqual(t, oldSession, c.Session().SessionID().String())
	eps = c.Session().ServerEndpoints()
	require.Len(t, eps, 1)
	require.Equal(t, url2, eps[0].EndpointURL)

	// The subscription was recreated and delivers the new server's values
	// on the original channel.
	awaitValue(t, ch, 7, int32(42))
	writeInt32(t, c, f2.Int32, 78)
	awaitValue(t, ch, 7, int32(78))
	require.NoError(t, sub.Cancel(ctx))
}

// TestReverseConnect_SeveralServersOneListener verifies that one listener
// serves several servers: every client gets the connection of the server
// whose ServerUri it expects, whatever the order in which they arrive.
func TestReverseConnect_SeveralServersOneListener(t *testing.T) {
	const n = 4
	l, clientURL := reverseListener(t, nil)
	ctx := context.Background()

	type target struct {
		uri string
		url string
		f   *testutil.Fixture
		srv *server.Server
	}
	targets := make([]target, n)
	for i := range targets {
		uri := fmt.Sprintf("urn:otfabric:conformance:reverse:multi:%d", i)
		srv, f, url := reverseServer(t, uri, clientURL)
		require.NoError(t, srv.Node(f.Int32).SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(int32(1000+i))))
		targets[i] = target{uri: uri, url: url, f: f, srv: srv}
	}

	// All servers have announced themselves before any client asks.
	eventually(t, func() bool { return l.Pending() == n }, "every server has a pending connection")

	var wg sync.WaitGroup
	clients := make([]*opcua.Client, n)
	errs := make([]error, n)
	for i := n - 1; i >= 0; i-- {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The endpoint URL is left to the server: only the ServerUri
			// selects the connection.
			clients[i], errs[i] = dialClient(t, "", opcua.ReverseConnectListener(l, opcua.ReverseServerURI(targets[i].uri)))
		}()
	}
	wg.Wait()
	for i, tg := range targets {
		require.NoError(t, errs[i])
		dv, err := clients[i].ReadValue(ctx, tg.f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(1000+i), dv.Value.Value(), "client %d talks to server %d", i, i)
		eps := clients[i].Session().ServerEndpoints()
		require.Len(t, eps, 1)
		require.Equal(t, tg.uri, eps[0].Server.ApplicationURI)
		require.Equal(t, tg.url, eps[0].EndpointURL)
		requireReverseConnected(t, tg.srv, 1)
	}

	// A client asking for a server that never connects gives up when its
	// time is over and says which servers are there instead.
	stranger, err := opcua.NewClient("",
		opcua.ReverseConnectListener(l, opcua.ReverseServerURI("urn:otfabric:conformance:reverse:multi:nobody")),
		opcua.DialTimeout(200*time.Millisecond))
	require.NoError(t, err)
	eventually(t, func() bool { return l.Pending() == n }, "every server offers its next idle connection")
	err = stranger.Connect(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, targets[0].uri)
	require.NoError(t, stranger.Close(ctx))
}

// TestReverseConnect_RuntimeTargets covers adding and removing targets at run
// time, the connection limit and the announced endpoint URL.
func TestReverseConnect_RuntimeTargets(t *testing.T) {
	const appURI = "urn:otfabric:conformance:reverse:runtime"
	l, clientURL := reverseListener(t, nil)
	srv, url := newServer(t, server.ApplicationURI(appURI))
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()
	require.Empty(t, srv.ReverseConnects())

	_, err := srv.AddReverseConnect("http://not-opc-tcp:1")
	require.Error(t, err)
	_, err = server.New(server.WithReverseConnect("127.0.0.1:4840"))
	require.Error(t, err, "the client URL must be an opc.tcp URL")

	// The server announces another spelling of its endpoint; a client
	// without an endpoint URL of its own adopts it.
	announced := strings.Replace(url, "localhost", "LOCALHOST", 1)
	rc, err := srv.AddReverseConnect(clientURL,
		fastReverseRetry,
		server.ReverseConnectEndpointURL(announced),
		server.ReverseConnectMaxConnections(1),
	)
	require.NoError(t, err)
	require.Equal(t, []*server.ReverseConnect{rc}, srv.ReverseConnects())

	reverse := opcua.ReverseConnectListener(l, opcua.ReverseServerURI(appURI))
	c1 := newClient(t, "", reverse)
	dv, err := c1.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())
	require.Equal(t, 1, rc.Connections())

	// The limit is reached, so the server does not offer a second
	// connection: another client waits in vain...
	c2, err := opcua.NewClient("", reverse, opcua.DialTimeout(300*time.Millisecond), opcua.AutoReconnect(false))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c2.Close(ctx) })
	require.ErrorIs(t, c2.Connect(ctx), context.DeadlineExceeded)
	require.Zero(t, l.Pending())
	require.Equal(t, 1, rc.Connections())

	// ...until the first one is gone. A client created with the usual
	// spelling of the endpoint URL accepts the announced one as well: host
	// names are compared without regard to case.
	require.NoError(t, c1.Close(ctx))
	c3 := newClient(t, url, reverse)
	_, err = c3.ReadValue(ctx, f.Int32)
	require.NoError(t, err)

	// Removing the target closes its connection; the client notices.
	require.NoError(t, rc.Close())
	require.Equal(t, server.ReverseConnectClosed, rc.State())
	require.Zero(t, rc.Connections())
	require.Empty(t, srv.ReverseConnects())
	eventually(t, func() bool {
		_, err := c3.ReadValue(ctx, f.Int32)
		return err != nil
	}, "client loses the removed connection")
	require.NoError(t, rc.Close(), "Close is idempotent")

	// A closed server takes no further targets.
	require.NoError(t, srv.Close())
	_, err = srv.AddReverseConnect(clientURL)
	require.Error(t, err)
}

// TestReverseConnect_ListenerFilter verifies the admission filter of a shared
// listener: a server it refuses is turned away at the door.
func TestReverseConnect_ListenerFilter(t *testing.T) {
	const allowed = "urn:otfabric:conformance:reverse:allowed"
	const denied = "urn:otfabric:conformance:reverse:denied"
	l, clientURL := reverseListener(t, &uacp.ReverseListenerConfig{
		Filter: func(rhe *uacp.ReverseHello) error {
			if rhe.ServerURI != allowed {
				return fmt.Errorf("server %q is not admitted: %w", rhe.ServerURI, ua.StatusBadServerURIInvalid)
			}
			return nil
		},
	})

	bad, _, _ := reverseServer(t, denied, clientURL)
	rc := bad.ReverseConnects()[0]
	eventually(t, func() bool { return errors.Is(rc.Err(), ua.StatusBadServerURIInvalid) }, "denied server is refused")
	require.Zero(t, l.Pending())

	good, f, url := reverseServer(t, allowed, clientURL)
	c := newClient(t, url, opcua.ReverseConnectListener(l))
	dv, err := c.ReadValue(context.Background(), f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())
	requireReverseConnected(t, good, 1)
}
