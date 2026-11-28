// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// keepAliveServer is a server that counts the keep-alives (Reads of the
// State of the ServerStatus) and answers them with fault, if one is set. It
// sits behind proxy when one is given.
type keepAliveServer struct {
	url   string
	reads atomic.Int32
	fault atomic.Uint32 // ua.StatusCode, 0: answer
}

func newKeepAliveServer(t *testing.T, proxy *testutil.ChaosProxy) *keepAliveServer {
	t.Helper()
	ks := &keepAliveServer{}
	values := readHandler(func(*ua.ReadValueID) *ua.DataValue { return valueDV(int32(0)) })
	handlers := map[uint16]server.Handler{
		id.ReadRequestEncodingDefaultBinary: func(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
			if n := r.(*ua.ReadRequest).NodesToRead[0].NodeID; n.Namespace() == 0 && n.IntID() == id.ServerServerStatusState {
				ks.reads.Add(1)
				if f := ks.fault.Load(); f != 0 {
					return nil, ua.StatusCode(f)
				}
			}
			return values(ctx, sc, r, reqID)
		},
	}
	if proxy == nil {
		_, ks.url = newScriptedServer(t, handlers)
		return ks
	}
	proxy.SetBackend(newProxiedServer(t, proxy, handlers))
	ks.url = proxy.EndpointURL()
	return ks
}

// waitKeepAlives waits until the server has seen n more keep-alives.
func (ks *keepAliveServer) waitKeepAlives(t *testing.T, n int32) {
	t.Helper()
	want := ks.reads.Load() + n
	require.Eventually(t, func() bool { return ks.reads.Load() >= want }, recoveryTimeout, 5*time.Millisecond,
		"expected %d keep-alives", n)
}

// TestSessionKeepAliveKeepsIdleSessionOpen: a client without subscriptions
// that sends nothing keeps its session past the revised session timeout;
// with the keep-alive off the server terminates it (Part 4 §5.7.2.1).
func TestSessionKeepAliveKeepsIdleSessionOpen(t *testing.T) {
	t.Parallel()
	// The keep-alive interval is a twentieth of the session timeout: a stall
	// of the race-instrumented process longer than the timeout (seen at 2 s
	// on a CI runner) would expire the session it keeps.
	const timeout = 4 * time.Second
	_, url := newScriptedServer(t, nil)
	ctx := context.Background()

	rec := &recorder{}
	kept := connectCovClient(t, url, append(rec.options(), opcua.SessionTimeout(timeout), opcua.SessionKeepAlive(200*time.Millisecond))...)
	gone := connectCovClient(t, url, opcua.SessionTimeout(timeout), opcua.SessionKeepAlive(0))
	require.Equal(t, timeout, kept.Session().RevisedTimeout())
	sid := kept.Session().SessionID().String()

	// Idle for more than two session timeouts.
	time.Sleep(2*timeout + timeout/2)

	_, err := kept.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)
	require.Equal(t, sid, kept.Session().SessionID().String(), "the session was kept, not replaced")
	states, _ := rec.snapshot()
	require.NotContains(t, states, opcua.Disconnected)

	_, err = gone.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)
}

// TestSessionKeepAliveOnlyWhenIdle: a client in use sends no keep-alive,
// and an idle one sends one per interval.
func TestSessionKeepAliveOnlyWhenIdle(t *testing.T) {
	t.Parallel()
	ks := newKeepAliveServer(t, nil)
	c := connectCovClient(t, ks.url, opcua.SessionKeepAlive(time.Second))
	ctx := context.Background()

	// Busy for two and a half intervals, a request every 20 ms.
	before := ks.reads.Load()
	for end := time.Now().Add(2500 * time.Millisecond); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		_, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusCurrentTime))
		require.NoError(t, err)
	}
	require.Equal(t, before, ks.reads.Load(), "a client in use sends no keep-alive")

	// Idle: one keep-alive per interval.
	ks.waitKeepAlives(t, 2)
}

// TestSessionKeepAliveDeadConnection: a connection that is gone without
// being closed (everything is dropped, nothing is reset) is noticed by the
// keep-alive that gets no response. The client goes to Disconnected and
// reconnects, restoring its session.
func TestSessionKeepAliveDeadConnection(t *testing.T) {
	t.Parallel()
	proxy := testutil.NewChaosProxy(t, "", 1)
	ks := newKeepAliveServer(t, proxy)
	rec := &recorder{}
	c := connectCovClient(t, ks.url, append(rec.options(),
		opcua.SessionKeepAlive(100*time.Millisecond), opcua.RequestTimeout(time.Second))...)
	sid := c.Session().SessionID().String()
	ks.waitKeepAlives(t, 1)

	proxy.SetBlackhole(testutil.ClientToServer, true)
	proxy.SetBlackhole(testutil.ServerToClient, true)
	require.Eventually(t, func() bool {
		states, _ := rec.snapshot()
		return slices.Contains(states, opcua.Disconnected)
	}, recoveryTimeout, 5*time.Millisecond, "the dead connection was not noticed")
	proxy.SetBlackhole(testutil.ClientToServer, false)
	proxy.SetBlackhole(testutil.ServerToClient, false)

	rec.waitRecovered(t, c)
	require.Equal(t, sid, c.Session().SessionID().String(), "the session was restored")
	_, err := c.ReadValue(context.Background(), ua.NewNumericNodeID(0, id.ServerServerStatusState))
	require.NoError(t, err)
	ks.waitKeepAlives(t, 1)
}

// TestSessionKeepAliveDeadConnectionNoReconnect: without AutoReconnect the
// client reports the dead connection and stays Disconnected; Close returns.
func TestSessionKeepAliveDeadConnectionNoReconnect(t *testing.T) {
	t.Parallel()
	proxy := testutil.NewChaosProxy(t, "", 1)
	ks := newKeepAliveServer(t, proxy)
	states := make(chan opcua.ConnState, 16)
	c := connectCovClient(t, ks.url, opcua.WithConnStateChan(states),
		opcua.SessionKeepAlive(100*time.Millisecond), opcua.RequestTimeout(time.Second))
	require.Equal(t, opcua.Connecting, <-states)
	require.Equal(t, opcua.Connected, <-states)

	proxy.SetBlackhole(testutil.ClientToServer, true)
	proxy.SetBlackhole(testutil.ServerToClient, true)
	select {
	case s := <-states:
		require.Equal(t, opcua.Disconnected, s)
	case <-time.After(recoveryTimeout):
		t.Fatal("the dead connection was not noticed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), recoveryTimeout)
	defer cancel()
	require.NoError(t, c.Close(ctx))
	require.Equal(t, opcua.Closed, c.State())
}

// TestSessionKeepAliveSessionClosed: a keep-alive the server answers with
// Bad_SessionClosed, as it answers the outstanding requests of a session it
// terminates (Part 4 §5.7.2.1), makes the client recover.
func TestSessionKeepAliveSessionClosed(t *testing.T) {
	t.Parallel()
	ks := newKeepAliveServer(t, nil)
	rec := &recorder{}
	c := connectCovClient(t, ks.url, append(rec.options(), opcua.SessionKeepAlive(100*time.Millisecond))...)

	ks.fault.Store(uint32(ua.StatusBadSessionClosed))
	require.Eventually(t, func() bool {
		states, _ := rec.snapshot()
		return slices.Contains(states, opcua.Disconnected)
	}, recoveryTimeout, 5*time.Millisecond)
	ks.fault.Store(0)
	rec.waitRecovered(t, c)
	ks.waitKeepAlives(t, 1)
}

// TestSessionKeepAliveServerAnswers: a keep-alive the server answers with
// another fault reached the server and leaves the client as it is.
func TestSessionKeepAliveServerAnswers(t *testing.T) {
	t.Parallel()
	ks := newKeepAliveServer(t, nil)
	rec := &recorder{}
	c := connectCovClient(t, ks.url, append(rec.options(), opcua.SessionKeepAlive(50*time.Millisecond))...)

	ks.fault.Store(uint32(ua.StatusBadUserAccessDenied))
	ks.waitKeepAlives(t, 5)
	require.Equal(t, opcua.Connected, c.State())
	states, _ := rec.snapshot()
	require.NotContains(t, states, opcua.Disconnected)
}

// TestSessionKeepAliveWithoutSession: after CloseSession nothing is kept
// alive.
func TestSessionKeepAliveWithoutSession(t *testing.T) {
	t.Parallel()
	ks := newKeepAliveServer(t, nil)
	c := connectCovClient(t, ks.url, opcua.SessionKeepAlive(50*time.Millisecond))
	ks.waitKeepAlives(t, 1)
	require.NoError(t, c.CloseSession(context.Background()))
	reads := ks.reads.Load()
	time.Sleep(500 * time.Millisecond)
	// one may have been under way
	require.LessOrEqual(t, ks.reads.Load(), reads+1)
}

// TestSessionKeepAliveCloseRace closes clients whose keep-alive runs all
// the time, from several goroutines and while requests are under way. Run
// with -race; TestMain fails the binary if a keep-alive goroutine is left.
func TestSessionKeepAliveCloseRace(t *testing.T) {
	t.Parallel()
	ks := newKeepAliveServer(t, nil)
	for i := range 10 {
		c := connectCovClient(t, ks.url, opcua.AutoReconnect(i%2 == 0), opcua.SessionKeepAlive(time.Millisecond))
		ks.waitKeepAlives(t, 1)
		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() {
				_, _ = c.ReadValue(context.Background(), ua.NewNumericNodeID(0, id.ServerServerStatusState))
			})
			wg.Go(func() { _ = c.Close(context.Background()) })
		}
		wg.Wait()
		require.Equal(t, opcua.Closed, c.State())
	}
}
