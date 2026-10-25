// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// fault returns a handler that fails every request with status.
func fault(status ua.StatusCode) server.Handler {
	return func(context.Context, *uasc.SecureChannel, ua.Request, uint32) (ua.Response, error) {
		return nil, status
	}
}

// closedPortURL is the URL of a port nobody listens on.
func closedPortURL(t *testing.T) string {
	return fmt.Sprintf("opc.tcp://localhost:%d", testport.TCP(t))
}

func TestClientCovDiscoveryHelpers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, url := testutil.NewTestServer(t)

	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)
	require.NotEmpty(t, eps)
	require.Equal(t, ua.MessageSecurityModeNone, eps[0].SecurityMode)

	srvs, err := opcua.FindServers(ctx, url)
	require.NoError(t, err)
	require.NotEmpty(t, srvs)

	// a plain server does not implement FindServersOnNetwork
	_, err = opcua.FindServersOnNetwork(ctx, url)
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)

	// invalid options are reported before dialing
	badOpt := opcua.RemoteCertificateFile("/does/not/exist.der")
	_, err = opcua.GetEndpoints(ctx, url, badOpt)
	require.Error(t, err)
	_, err = opcua.FindServers(ctx, url, badOpt)
	require.Error(t, err)
	_, err = opcua.FindServersOnNetwork(ctx, url, badOpt)
	require.Error(t, err)
	_, err = opcua.NewClient(url, badOpt)
	require.Error(t, err)

	// nobody listening
	dead := closedPortURL(t)
	_, err = opcua.GetEndpoints(ctx, dead)
	require.Error(t, err)
	_, err = opcua.FindServers(ctx, dead)
	require.Error(t, err)
	_, err = opcua.FindServersOnNetwork(ctx, dead)
	require.Error(t, err)
}

func TestClientCovDiscoveryHelperServiceErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.GetEndpointsRequestEncodingDefaultBinary: fault(ua.StatusBadTooManyOperations),
		id.FindServersRequestEncodingDefaultBinary:  fault(ua.StatusBadTooManyOperations),
		id.FindServersOnNetworkRequestEncodingDefaultBinary: respond(func(r ua.Request) ua.Response {
			return &ua.FindServersOnNetworkResponse{
				ResponseHeader: okHeader(r),
				Servers: []*ua.ServerOnNetwork{{
					RecordID:           7,
					ServerName:         "lds-entry",
					DiscoveryURL:       "opc.tcp://somewhere:4840",
					ServerCapabilities: []string{"DA"},
				}},
			}
		}),
	})

	_, err := opcua.GetEndpoints(ctx, url)
	require.ErrorIs(t, err, ua.StatusBadTooManyOperations)
	_, err = opcua.FindServers(ctx, url)
	require.ErrorIs(t, err, ua.StatusBadTooManyOperations)

	srvs, err := opcua.FindServersOnNetwork(ctx, url)
	require.NoError(t, err)
	require.Len(t, srvs, 1)
	require.Equal(t, "lds-entry", srvs[0].ServerName)
	require.Equal(t, uint32(7), srvs[0].RecordID)
}

func TestClientCovConnectTwice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, url := testutil.NewTestServer(t)
	c := connectCovClient(t, url)

	require.ErrorIs(t, c.Connect(ctx), errors.ErrAlreadyConnected)
	require.ErrorIs(t, c.Dial(ctx), errors.ErrAlreadyConnected)
	require.Equal(t, opcua.Connected, c.State())
}

// A Connect that fails at any step leaves the client Closed and without a
// secure channel or session.
func TestClientCovConnectFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		handlers map[uint16]server.Handler
		want     ua.StatusCode
	}{
		{"CreateSession", map[uint16]server.Handler{
			id.CreateSessionRequestEncodingDefaultBinary: fault(ua.StatusBadTooManySessions),
		}, ua.StatusBadTooManySessions},
		{"ActivateSession", map[uint16]server.Handler{
			id.ActivateSessionRequestEncodingDefaultBinary: fault(ua.StatusBadIdentityTokenRejected),
		}, ua.StatusBadIdentityTokenRejected},
		{"UpdateNamespaces", map[uint16]server.Handler{
			id.ReadRequestEncodingDefaultBinary: fault(ua.StatusBadUserAccessDenied),
		}, ua.StatusBadUserAccessDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, url := newScriptedServer(t, tt.handlers)
			var states []opcua.ConnState
			var mu sync.Mutex
			c := newCovClient(t, url, opcua.WithConnStateHandler(func(s opcua.ConnState) {
				mu.Lock()
				states = append(states, s)
				mu.Unlock()
			}))
			err := c.Connect(context.Background())
			require.ErrorIs(t, err, tt.want)
			require.Equal(t, opcua.Closed, c.State())
			require.Nil(t, c.SecureChannel())
			require.Nil(t, c.Session())
			mu.Lock()
			require.Equal(t, opcua.Connecting, states[0])
			mu.Unlock()
		})
	}

	t.Run("Dial", func(t *testing.T) {
		c := newCovClient(t, closedPortURL(t))
		require.Error(t, c.Connect(context.Background()))
		require.Equal(t, opcua.Closed, c.State())
	})
}

func TestClientCovSessionWithoutChannel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := newCovClient(t, closedPortURL(t))

	_, err := c.CreateSession(ctx, opcua.DefaultSessionConfig())
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)

	_, err = c.ReadValue(ctx, ua.NewNumericNodeID(0, id.Server))
	require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
}

// A session created next to the client's own one and activated replaces it;
// DetachSession hands it out without closing it.
func TestClientCovSessionLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, url := testutil.NewTestServer(t)
	c := connectCovClient(t, url)

	first := c.Session()
	require.NotNil(t, first)

	s, err := c.CreateSession(ctx, opcua.DefaultSessionConfig())
	require.NoError(t, err)
	require.NotNil(t, s.SessionID())
	require.NotEqual(t, first.SessionID().String(), s.SessionID().String())
	require.NoError(t, c.ActivateSession(ctx, s))
	require.Same(t, s, c.Session())

	// the client works in the new session
	_, err = c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)

	// the old session was closed: activating it again fails
	require.Error(t, c.ActivateSession(ctx, first))
	require.Same(t, s, c.Session())

	detached, err := c.DetachSession(ctx)
	require.NoError(t, err)
	require.Same(t, s, detached)
	require.Nil(t, c.Session())

	// without a session requests fail on the server
	_, err = c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.Error(t, err)

	// a detached session can be activated again
	require.NoError(t, c.ActivateSession(ctx, detached))
	_, err = c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)
	require.NoError(t, c.CloseSession(ctx))
	require.Nil(t, c.Session())
}

func TestClientCovSessionAccessorsWithoutResponse(t *testing.T) {
	t.Parallel()
	var s opcua.Session
	require.Nil(t, s.SessionID())
	require.Nil(t, s.ServerEndpoints())
	require.Zero(t, s.MaxRequestMessageSize())
	require.Zero(t, s.RevisedTimeout())
}

// retryFunc is a RetryPolicy built from a function.
type retryFunc func(attempt int, err error) (bool, time.Duration)

func (f retryFunc) ShouldRetry(attempt int, err error) (bool, time.Duration) { return f(attempt, err) }

// flakyRead fails the first n Read requests for ns=1 nodes with status.
func flakyRead(n int32, status ua.StatusCode, calls *atomic.Int32) server.Handler {
	ok := readHandler(func(*ua.ReadValueID) *ua.DataValue { return valueDV(int32(5)) })
	return func(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
		req := r.(*ua.ReadRequest)
		if req.NodesToRead[0].NodeID.Namespace() == 1 && calls.Add(1) <= n {
			return nil, status
		}
		return ok(ctx, sc, r, reqID)
	}
}

func TestClientCovRetryPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	node := ua.NewStringNodeID(1, "flaky")

	t.Run("succeeds after retries", func(t *testing.T) {
		var calls atomic.Int32
		_, url := newScriptedServer(t, map[uint16]server.Handler{
			id.ReadRequestEncodingDefaultBinary: flakyRead(2, ua.StatusBadResourceUnavailable, &calls),
		})
		c := connectCovClient(t, url, opcua.WithRetryPolicy(opcua.ExponentialBackoff(time.Millisecond, 5*time.Millisecond, 5)))
		dv, err := c.ReadValue(ctx, node)
		require.NoError(t, err)
		require.Equal(t, int32(5), dv.Value.Value())
		require.Equal(t, int32(3), calls.Load())
	})

	t.Run("gives up", func(t *testing.T) {
		var calls atomic.Int32
		_, url := newScriptedServer(t, map[uint16]server.Handler{
			id.ReadRequestEncodingDefaultBinary: flakyRead(100, ua.StatusBadResourceUnavailable, &calls),
		})
		c := connectCovClient(t, url, opcua.WithRetryPolicy(opcua.ExponentialBackoff(time.Millisecond, 2*time.Millisecond, 2)))
		_, err := c.ReadValue(ctx, node)
		require.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
		require.Equal(t, int32(3), calls.Load(), "first attempt plus two retries")
	})

	t.Run("context cancelled while waiting", func(t *testing.T) {
		var calls atomic.Int32
		_, url := newScriptedServer(t, map[uint16]server.Handler{
			id.ReadRequestEncodingDefaultBinary: flakyRead(100, ua.StatusBadResourceUnavailable, &calls),
		})
		rctx, cancel := context.WithCancel(ctx)
		defer cancel()
		c := connectCovClient(t, url, opcua.WithRetryPolicy(retryFunc(func(int, error) (bool, time.Duration) {
			cancel()
			return true, time.Hour
		})))
		_, err := c.ReadValue(rctx, node)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, int32(1), calls.Load())
	})
}

type recordingMetrics struct {
	mu                               sync.Mutex
	requests, responses, errs, tmout []string
	lastErr                          error
}

func (m *recordingMetrics) OnRequest(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, s)
}

func (m *recordingMetrics) OnResponse(s string, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, s)
}

func (m *recordingMetrics) OnError(s string, _ time.Duration, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errs = append(m.errs, s)
	m.lastErr = err
}

func (m *recordingMetrics) OnTimeout(s string, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tmout = append(m.tmout, s)
}

func TestClientCovMetrics(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, url := newScriptedServer(t, map[uint16]server.Handler{
		id.WriteRequestEncodingDefaultBinary: fault(ua.StatusBadTimeout),
		id.CallRequestEncodingDefaultBinary:  fault(ua.StatusBadMethodInvalid),
	})
	m := &recordingMetrics{}
	c := connectCovClient(t, url, opcua.WithMetrics(m))

	_, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)
	_, err = c.WriteNodeValue(ctx, ua.NewStringNodeID(1, "x"), int32(1))
	require.ErrorIs(t, err, ua.StatusBadTimeout)
	_, err = c.CallMethod(ctx, ua.NewStringNodeID(1, "o"), ua.NewStringNodeID(1, "m"))
	require.ErrorIs(t, err, ua.StatusBadMethodInvalid)

	m.mu.Lock()
	defer m.mu.Unlock()
	require.Contains(t, m.requests, "Read")
	require.Contains(t, m.responses, "Read")
	require.Equal(t, []string{"Write"}, m.tmout)
	require.Equal(t, []string{"Call"}, m.errs)
	require.ErrorIs(t, m.lastErr, ua.StatusBadMethodInvalid)
}
