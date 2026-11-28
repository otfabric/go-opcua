// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingMetrics counts the requests per service.
type countingMetrics struct {
	mu       sync.Mutex
	requests map[string]int
}

func (m *countingMetrics) OnRequest(svc string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.requests == nil {
		m.requests = map[string]int{}
	}
	m.requests[svc]++
}
func (m *countingMetrics) OnResponse(string, time.Duration)     {}
func (m *countingMetrics) OnError(string, time.Duration, error) {}
func (m *countingMetrics) OnTimeout(string, time.Duration)      {}

func (m *countingMetrics) count(svc string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests[svc]
}

// keepAliveTestSession is a session with the revised timeout revised.
func keepAliveTestSession(revised time.Duration) *Session {
	return &Session{
		revisedTimeout: revised,
		resp:           &ua.CreateSessionResponse{AuthenticationToken: ua.NewNumericNodeID(0, 4711)},
	}
}

func TestSessionKeepAliveOption(t *testing.T) {
	t.Parallel()
	cfg, err := ApplyConfig()
	require.NoError(t, err)
	assert.False(t, cfg.keepAliveOff, "on by default")
	assert.Zero(t, cfg.keepAlive)

	cfg, err = ApplyConfig(SessionKeepAlive(3 * time.Second))
	require.NoError(t, err)
	assert.False(t, cfg.keepAliveOff)
	assert.Equal(t, 3*time.Second, cfg.keepAlive)

	cfg, err = ApplyConfig(SessionKeepAlive(3*time.Second), SessionKeepAlive(0))
	require.NoError(t, err)
	assert.True(t, cfg.keepAliveOff)

	_, err = NewClient("opc.tcp://example.com:4840", InsecureNoSecurity(), SessionKeepAlive(-time.Second))
	require.ErrorContains(t, err, "SessionKeepAlive: negative interval -1s")
}

func TestKeepAliveInterval(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		opt       Option
		revised   time.Duration
		want      time.Duration
		wantNever bool
	}{
		{name: "default is half the revised timeout", revised: 20 * time.Minute, want: 10 * time.Minute},
		{name: "default of a short session", revised: 200 * time.Millisecond, want: 100 * time.Millisecond},
		{name: "set below the revised timeout", opt: SessionKeepAlive(30 * time.Second), revised: time.Minute, want: 30 * time.Second},
		{name: "set to the revised timeout", opt: SessionKeepAlive(time.Minute), revised: time.Minute, want: 30 * time.Second},
		{name: "set above the revised timeout", opt: SessionKeepAlive(time.Hour), revised: time.Minute, want: 30 * time.Second},
		{name: "off", opt: SessionKeepAlive(0), revised: time.Minute, wantNever: true},
		{name: "no revised timeout", revised: 0, wantNever: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.opt != nil {
				opts = append(opts, tc.opt)
			}
			cfg, err := ApplyConfig(opts...)
			require.NoError(t, err)
			got := cfg.keepAliveInterval(tc.revised)
			if tc.wantNever {
				assert.Zero(t, got)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestKeepAliveStep covers when a step sends a keep-alive and how long the
// next one waits, without a server: the client has no secure channel, so a
// keep-alive that is sent fails with Bad_ServerNotConnected, which the
// metrics count and nobody acts on.
func TestKeepAliveStep(t *testing.T) {
	t.Parallel()
	m := &countingMetrics{}
	c, err := NewClient("opc.tcp://example.com:4840", InsecureNoSecurity(), WithMetrics(m), SessionKeepAlive(time.Minute))
	require.NoError(t, err)
	ctx := context.Background()

	// no session
	assert.Equal(t, keepAlivePoll, c.keepAliveStep(ctx))

	// a session without a revised timeout
	c.setSession(keepAliveTestSession(0))
	assert.Equal(t, keepAlivePoll, c.keepAliveStep(ctx))

	// not Connected: looks again after the interval, at most keepAlivePoll
	c.setSession(keepAliveTestSession(2 * time.Hour))
	for _, s := range []ConnState{Closed, Connecting, Disconnected, Reconnecting} {
		c.atomicState.Store(s)
		assert.Equal(t, keepAlivePoll, c.keepAliveStep(ctx), s)
	}
	c.setSession(keepAliveTestSession(400 * time.Millisecond))
	c.atomicState.Store(Reconnecting)
	assert.Equal(t, 200*time.Millisecond, c.keepAliveStep(ctx))
	assert.Zero(t, m.count("Read"), "nothing is sent unless Connected")

	// Connected and recently used: waits for the rest of the interval
	c.setSession(keepAliveTestSession(2 * time.Hour))
	c.atomicState.Store(Connected)
	c.noteSessionRequest()
	wait := c.keepAliveStep(ctx)
	assert.Greater(t, wait, 59*time.Second)
	assert.LessOrEqual(t, wait, time.Minute)
	assert.Zero(t, m.count("Read"))

	// Connected and idle for the interval: sends, and waits a whole one
	c.lastSessionRequest.Store(int64(time.Since(keepAliveEpoch) - 2*time.Minute))
	assert.Equal(t, time.Minute, c.keepAliveStep(ctx))
	assert.Equal(t, 1, m.count("Read"))
	select {
	case err := <-c.secureChannelErrors():
		t.Fatalf("Bad_ServerNotConnected was handed to the monitor: %v", err)
	default:
	}

	// stopped: a keep-alive that fails because of the stop is not reported
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	c.sendKeepAlive(stopped, c.Session())
	assert.Equal(t, 2, m.count("Read"))
	assert.Empty(t, c.secureChannelErrors())
}

func TestKeepAliveFailed(t *testing.T) {
	t.Parallel()
	c := newNotifyTestClient(t)
	s := keepAliveTestSession(time.Minute)
	c.setSession(s)
	c.atomicState.Store(Connected)
	errs := c.secureChannelErrors()

	// The keep-alive worked, or the server answered: nothing to do.
	for _, err := range []error{nil, ua.StatusBadUserAccessDenied, ua.StatusBadTooManyOperations, ua.StatusBadServerNotConnected} {
		assert.False(t, c.keepAliveFailed(s, errs, err), "%v", err)
	}
	assert.Empty(t, errs)

	// Failures of what the client has replaced since, or during a
	// recovery.
	assert.False(t, c.keepAliveFailed(keepAliveTestSession(time.Minute), errs, ua.StatusBadTimeout), "other session")
	assert.False(t, c.keepAliveFailed(s, make(chan error, 1), ua.StatusBadTimeout), "other secure channel")
	c.atomicState.Store(Reconnecting)
	assert.False(t, c.keepAliveFailed(s, errs, ua.StatusBadTimeout), "reconnecting")
	assert.Empty(t, errs)
	c.atomicState.Store(Connected)

	// No response, and a session the server terminated: the connection is
	// lost.
	for _, status := range []ua.StatusCode{ua.StatusBadTimeout, ua.StatusBadSessionClosed} {
		require.True(t, c.keepAliveFailed(s, errs, status), "%v", status)
		got := <-errs
		require.ErrorIs(t, got, status)
		require.ErrorContains(t, got, "opcua: session keep-alive")
	}

	// An error is pending already: the keep-alive does not block.
	errs <- ua.StatusBadSecureChannelIDInvalid
	require.True(t, c.keepAliveFailed(s, errs, ua.StatusBadTimeout))
	require.ErrorIs(t, <-errs, ua.StatusBadSecureChannelIDInvalid)
	assert.Empty(t, errs)
}

func TestStartKeepAliveOff(t *testing.T) {
	t.Parallel()
	c, err := NewClient("opc.tcp://example.com:4840", InsecureNoSecurity(), SessionKeepAlive(0))
	require.NoError(t, err)
	stop := c.startKeepAlive(context.Background())
	stop()
}

// TestStartKeepAliveStops: the keep-alive goroutine ends when it is
// stopped, and when the context of the monitor ends.
func TestStartKeepAliveStops(t *testing.T) {
	t.Parallel()
	c := newNotifyTestClient(t)
	c.startKeepAlive(context.Background())()

	ctx, cancel := context.WithCancel(context.Background())
	stop := c.startKeepAlive(ctx)
	cancel()
	stop()
}
