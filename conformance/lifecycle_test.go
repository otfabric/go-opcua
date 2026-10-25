// SPDX-License-Identifier: MIT

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/stretchr/testify/require"
)

// subscriptionState asks the server, from a session that does not own the
// subscription, whether subID exists. A subscription owned by another session
// answers BadSessionIDInvalid; a deleted one BadSubscriptionIDInvalid.
func subscriptionState(t *testing.T, observer *opcua.Client, subID uint32) ua.StatusCode {
	t.Helper()
	resp, err := observer.SetPublishingMode(context.Background(), true, subID)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	return resp.Results[0]
}

var (
	subscriptionAlive = ua.StatusBadSessionIDInvalid
	subscriptionGone  = ua.StatusBadSubscriptionIDInvalid
)

func TestSession_Properties(t *testing.T) {
	srv, url := newServer(t)
	testutil.AddFixture(t, srv)
	c := newClient(t, url, opcua.SessionName("conformance-session"), opcua.SessionTimeout(5*time.Minute))

	s := c.Session()
	require.NotNil(t, s)
	require.NotNil(t, s.SessionID())
	require.Equal(t, ua.NodeIDTypeGUID, s.SessionID().Type())
	require.Equal(t, 5*time.Minute, s.RevisedTimeout())
	require.Zero(t, s.MaxRequestMessageSize())

	eps := s.ServerEndpoints()
	require.Len(t, eps, 1)
	require.Equal(t, url, eps[0].EndpointURL)
	require.Equal(t, ua.SecurityPolicyURINone, eps[0].SecurityPolicyURI)

	// Two sessions never share an id.
	c2 := newClient(t, url)
	require.NotEqual(t, s.SessionID().String(), c2.Session().SessionID().String())
}

// TestSession_TimeoutRevision verifies the server's revision of the requested
// session timeout: in-range values are kept, out-of-range ones fall back to
// the server default.
func TestSession_TimeoutRevision(t *testing.T) {
	_, url := newServer(t)
	for _, tc := range []struct {
		requested, revised time.Duration
	}{
		// (Very short in-range timeouts are not used here: the server enforces
		// them, and a slow machine would lose the session while connecting.)
		{30 * time.Second, 30 * time.Second},
		{90 * time.Second, 90 * time.Second},
		{30 * time.Minute, 30 * time.Minute},
		{50 * time.Millisecond, 60 * time.Second},
		{2 * time.Hour, 60 * time.Second},
	} {
		t.Run(tc.requested.String(), func(t *testing.T) {
			c := newClient(t, url, opcua.SessionTimeout(tc.requested))
			require.Equal(t, tc.revised, c.Session().RevisedTimeout())
		})
	}
}

// TestSession_TimeoutEnforced verifies the server closes a session that stays
// idle for longer than its revised timeout, while a session that keeps issuing
// requests lives on.
func TestSession_TimeoutEnforced(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()
	const timeout = 3 * time.Second

	idle := newClient(t, url, opcua.SessionTimeout(timeout))
	busy := newClient(t, url, opcua.SessionTimeout(timeout))
	require.Equal(t, timeout, idle.Session().RevisedTimeout())

	// Keep one session busy for one and a half timeouts.
	deadline := time.Now().Add(timeout + timeout/2)
	for time.Now().Before(deadline) {
		dv, err := busy.ReadValue(ctx, f.Int32)
		require.NoError(t, err, "a session in use must not time out")
		require.Equal(t, int32(42), dv.Value.Value())
		time.Sleep(100 * time.Millisecond)
	}

	// The other one was idle all that time and is gone.
	_, err := idle.ReadValue(ctx, f.Int32)
	require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)
	// The busy one is still fine.
	dv, err := busy.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())
}

// TestSession_RequiresActivation verifies services are refused without an
// activated session.
func TestSession_RequiresActivation(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	c, err := opcua.NewClient(url,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.DialTimeout(30*time.Second),
		opcua.RequestTimeout(30*time.Second),
		opcua.AutoReconnect(false),
	)
	require.NoError(t, err)
	require.NoError(t, c.Dial(ctx))
	t.Cleanup(func() { _ = c.Close(ctx) })

	// A secure channel alone is enough for discovery...
	eps, err := c.GetEndpoints(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, eps.Endpoints)

	// ...but not for the address space: no session at all,
	_, err = c.ReadValue(ctx, f.Int32)
	require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)

	// Creating a session does not make it usable yet: the client only adopts
	// it once it has been activated.
	cfg := opcua.DefaultSessionConfig()
	cfg.UserIdentityToken = &ua.AnonymousIdentityToken{PolicyID: "anonymous_none"}
	sess, err := c.CreateSession(ctx, cfg)
	require.NoError(t, err)
	require.Nil(t, c.Session())
	_, err = c.ReadValue(ctx, f.Int32)
	require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)

	// Once activated, the same session works.
	require.NoError(t, c.ActivateSession(ctx, sess))
	dv, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())
}

// TestSession_ReactivateOnNewChannel detaches a session from one client and
// activates it on a brand-new secure channel, the building block of session
// recovery. Ownership of the session's subscription proves it is the same
// server-side session.
func TestSession_ReactivateOnNewChannel(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	c1 := newClient(t, url)
	// A very slow subscription: it must simply keep existing while its
	// original channel goes away.
	sub, err := c1.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *opcua.PublishNotificationData, 8))
	require.NoError(t, err)
	sessionID := c1.Session().SessionID().String()

	sess, err := c1.DetachSession(ctx)
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Nil(t, c1.Session(), "DetachSession must remove the session from the client")
	// Closing the client now closes the channel but must not close the session.
	require.NoError(t, c1.Close(ctx))

	observer := newClient(t, url)
	require.Equal(t, subscriptionAlive, subscriptionState(t, observer, sub.SubscriptionID))

	// Second client: open a channel only, then adopt the detached session.
	c2, err := opcua.NewClient(url,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.DialTimeout(30*time.Second),
		opcua.RequestTimeout(30*time.Second),
	)
	require.NoError(t, err)
	require.NoError(t, c2.Dial(ctx))
	t.Cleanup(func() { _ = c2.Close(ctx) })
	require.Nil(t, c2.Session())

	require.NoError(t, c2.ActivateSession(ctx, sess))
	require.Equal(t, sessionID, c2.Session().SessionID().String())

	// The adopted session works for ordinary service calls...
	dv, err := c2.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())

	// ...and still owns the subscription created over the first channel.
	resp, err := c2.SetPublishingMode(ctx, false, sub.SubscriptionID)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, resp.Results)

	// Closing the session through the new channel removes the subscription.
	require.NoError(t, c2.CloseSession(ctx))
	require.Nil(t, c2.Session())
	require.Equal(t, subscriptionGone, subscriptionState(t, observer, sub.SubscriptionID))
}

// TestSession_ActivateReplacesPrevious verifies that activating a second
// session on a client closes the one it replaces.
func TestSession_ActivateReplacesPrevious(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()
	c := newClient(t, url)
	observer := newClient(t, url)

	first := c.Session()
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *opcua.PublishNotificationData, 8))
	require.NoError(t, err)
	require.Equal(t, subscriptionAlive, subscriptionState(t, observer, sub.SubscriptionID))

	cfg := opcua.DefaultSessionConfig()
	cfg.SessionName = "second"
	cfg.SessionTimeout = 2 * time.Minute
	cfg.UserIdentityToken = &ua.AnonymousIdentityToken{PolicyID: "anonymous_none"}
	second, err := c.CreateSession(ctx, cfg)
	require.NoError(t, err)
	require.Equal(t, 2*time.Minute, second.RevisedTimeout())
	require.NotEqual(t, first.SessionID().String(), second.SessionID().String())
	// CreateSession alone does not switch the client over.
	require.Equal(t, first.SessionID().String(), c.Session().SessionID().String())

	require.NoError(t, c.ActivateSession(ctx, second))
	require.Equal(t, second.SessionID().String(), c.Session().SessionID().String())

	// The replaced session was closed together with its subscriptions.
	require.Equal(t, subscriptionGone, subscriptionState(t, observer, sub.SubscriptionID))
	// The first session can no longer be activated.
	require.ErrorIs(t, c.ActivateSession(ctx, first), ua.StatusBadSessionIDInvalid)

	dv, err := c.ReadValue(ctx, f.Int32)
	require.NoError(t, err)
	require.Equal(t, int32(42), dv.Value.Value())
}

// TestSession_CloseDeletesSubscriptionsAndItems verifies CloseSession releases
// the session's subscriptions and monitored items on the server.
func TestSession_CloseDeletesSubscriptionsAndItems(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()
	c := newClient(t, url)
	observer := newClient(t, url)

	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *opcua.PublishNotificationData, 8))
	require.NoError(t, err)
	mon, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 1))
	require.NoError(t, err)
	itemID := mon.Results[0].MonitoredItemID

	itemState := func() ua.StatusCode {
		var out ua.StatusCode
		err := observer.Send(ctx, &ua.SetMonitoringModeRequest{
			SubscriptionID:   sub.SubscriptionID,
			MonitoringMode:   ua.MonitoringModeReporting,
			MonitoredItemIDs: []uint32{itemID},
		}, func(r ua.Response) error {
			out = r.(*ua.SetMonitoringModeResponse).Results[0]
			return nil
		})
		require.NoError(t, err)
		return out
	}
	require.Equal(t, ua.StatusBadSessionIDInvalid, itemState(), "item must exist and belong to another session")

	require.NoError(t, c.CloseSession(ctx))
	require.Nil(t, c.Session())
	require.Equal(t, subscriptionGone, subscriptionState(t, observer, sub.SubscriptionID))
	require.Equal(t, ua.StatusBadMonitoredItemIDInvalid, itemState())

	// A second CloseSession without a session is a no-op.
	require.NoError(t, c.CloseSession(ctx))
}

func TestClient_ConnectErrors(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	t.Run("NotConnected", func(t *testing.T) {
		c, err := opcua.NewClient(url)
		require.NoError(t, err)
		require.Equal(t, opcua.Closed, c.State())
		_, err = c.ReadValue(ctx, f.Int32)
		require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
		_, err = c.CreateSession(ctx, opcua.DefaultSessionConfig())
		require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
		// Closing a never-connected client is harmless.
		require.NoError(t, c.Close(ctx))
	})

	t.Run("ConnectTwice", func(t *testing.T) {
		c := newClient(t, url)
		require.ErrorIs(t, c.Connect(ctx), errors.ErrAlreadyConnected)
		require.ErrorIs(t, c.Dial(ctx), errors.ErrAlreadyConnected)
		// The failed second Connect must not have damaged the live connection.
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("AfterClose", func(t *testing.T) {
		c := newClient(t, url)
		require.NoError(t, c.Close(ctx))
		require.Equal(t, opcua.Closed, c.State())
		require.Nil(t, c.SecureChannel())
		require.Nil(t, c.Session())
		_, err := c.ReadValue(ctx, f.Int32)
		require.ErrorIs(t, err, ua.StatusBadServerNotConnected)
		require.NoError(t, c.Close(ctx), "Close must be idempotent")
	})

	t.Run("NothingListening", func(t *testing.T) {
		// Port 1 is reserved and never has a listener.
		dead := "opc.tcp://localhost:1"
		states := make(chan opcua.ConnState, 16)
		c, err := opcua.NewClient(dead, opcua.DialTimeout(5*time.Second), opcua.WithConnStateChan(states))
		require.NoError(t, err)
		require.Error(t, c.Connect(ctx))
		require.Nil(t, c.SecureChannel())
		require.Equal(t, opcua.Connecting, <-states)
	})

	t.Run("WrongEndpointPath", func(t *testing.T) {
		// The server registered no path, so any path is accepted at the
		// transport level and the session still gets the server's endpoints.
		c := newClient(t, url+"/some/path")
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("WrongHost", func(t *testing.T) {
		// Same listener, but the HELLO names a host the server does not serve.
		other := strings.Replace(url, "localhost", "127.0.0.1", 1)
		c, err := opcua.NewClient(other, opcua.DialTimeout(10*time.Second))
		require.NoError(t, err)
		require.ErrorIs(t, c.Connect(ctx), ua.StatusBadTCPEndpointURLInvalid)
	})
}

// logCounter is an slog.Handler that counts records by message.
type logCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (l *logCounter) Enabled(context.Context, slog.Level) bool { return true }
func (l *logCounter) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	if l.counts == nil {
		l.counts = map[string]int{}
	}
	l.counts[r.Message]++
	l.mu.Unlock()
	return nil
}
func (l *logCounter) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logCounter) WithGroup(string) slog.Handler      { return l }
func (l *logCounter) count(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[msg]
}

// TestChannel_RenewalUnderTraffic runs requests and a subscription across
// several automatic security-token renewals of a short-lived secure channel.
func TestChannel_RenewalUnderTraffic(t *testing.T) {
	parallel(t)
	for _, tc := range []struct {
		name string
		opts func(t *testing.T, url string) []opcua.Option
		srv  func(t *testing.T) []server.Option
	}{
		{
			name: "None",
			opts: func(*testing.T, string) []opcua.Option { return nil },
			srv:  func(*testing.T) []server.Option { return nil },
		},
		{
			name: "SignAndEncrypt",
			opts: func(t *testing.T, url string) []opcua.Option {
				ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
				return secureClientOpts(t, ep, ua.UserTokenTypeAnonymous)
			},
			srv: func(t *testing.T) []server.Option { return secureServerOpts(t) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, url := newServer(t, tc.srv(t)...)
			f := testutil.AddFixture(t, srv)
			ctx := context.Background()

			logs := &logCounter{}
			// A 4s token lifetime is renewed by the client after 75% (3s).
			// The server keeps a token for 125% of its lifetime, so a
			// renewal has 2s to get through on a busy machine.
			c := newClient(t, url, append(tc.opts(t, url),
				opcua.Lifetime(4*time.Second),
				opcua.WithLogger(slog.New(logs)),
			)...)
			const tokenMsg = "received security token"
			// At least: a connect slower than 3s has renewed it already.
			require.GreaterOrEqual(t, logs.count(tokenMsg), 1)

			sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = sub.Cancel(ctx) })
			awaitValue(t, ch, 0, int32(42))

			// Keep writing and reading until the token has been renewed twice;
			// every write must be delivered through the subscription.
			deadline := time.Now().Add(waitTimeout)
			var n int32
			for logs.count(tokenMsg) < 3 {
				require.True(t, time.Now().Before(deadline), "token was renewed only %d times", logs.count(tokenMsg)-1)
				n++
				writeInt32(t, c, f.Int32, 1000+n)
				awaitValue(t, ch, 0, 1000+n)
				dv, err := c.ReadValue(ctx, f.Int32)
				require.NoError(t, err)
				require.Equal(t, 1000+n, dv.Value.Value())
			}
			require.Equal(t, opcua.Connected, c.State())

			// An explicit renewal is possible at any time as well.
			before := logs.count(tokenMsg)
			require.NoError(t, c.SecureChannel().Renew(ctx))
			// At least: an automatic renewal may have been due at the same time.
			require.GreaterOrEqual(t, logs.count(tokenMsg), before+1)
			writeInt32(t, c, f.Int32, 7)
			awaitValue(t, ch, 0, int32(7))
		})
	}
}

func TestClient_SkipNamespaceUpdate(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	eager := newClient(t, url)
	require.Contains(t, eager.Namespaces(), "http://otfabric.com/conformance")

	lazy := newClient(t, url, opcua.SkipNamespaceUpdate())
	require.Empty(t, lazy.Namespaces(), "namespace table must not be fetched on connect")

	// The table can still be fetched on demand and then matches.
	require.NoError(t, lazy.UpdateNamespaces(ctx))
	require.Equal(t, eager.Namespaces(), lazy.Namespaces())
	idx, err := lazy.FindNamespace(ctx, "http://otfabric.com/conformance")
	require.NoError(t, err)
	require.Equal(t, f.NSIndex, idx)
}

// TestClient_IdentityOptions exercises the descriptive client options. The
// server does not expose the client description, so the assertions are that a
// session is established and usable with each of them set.
func TestClient_IdentityOptions(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	c := newClient(t, url,
		opcua.ApplicationName("conformance client"),
		opcua.ApplicationURI("urn:otfabric:conformance:client"),
		opcua.ProductURI("urn:otfabric:conformance"),
		opcua.Locales("de-DE", "en-US"),
		opcua.SessionName("identity-options"),
		opcua.RandomRequestID(),
		opcua.AutoReconnect(false),
		opcua.ReconnectInterval(time.Second),
	)
	// With a random request-id seed, many sequential requests must still be
	// matched to their own responses.
	for i := int32(0); i < 50; i++ {
		writeInt32(t, c, f.Int32, i)
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, i, dv.Value.Value())
	}
}

// TestTransport_TinyBuffersChunking forces both directions onto the minimum
// buffer size so large requests and responses are split into many chunks.
func TestTransport_TinyBuffersChunking(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	c := newClient(t, url,
		opcua.ReceiveBufferSize(8192),
		opcua.SendBufferSize(8192),
	)

	// ~300 KiB payload: dozens of chunks for the write request and again for
	// the read response.
	payload := bytes.Repeat([]byte("0123456789abcdef"), 300*1024/16)
	payload[0], payload[len(payload)-1] = 0xAA, 0x55
	st, err := c.WriteNodeValue(ctx, f.ByteString, payload)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)

	dv, err := c.ReadValue(ctx, f.ByteString)
	require.NoError(t, err)
	got, ok := dv.Value.Value().([]byte)
	require.True(t, ok)
	require.True(t, bytes.Equal(payload, got), "payload corrupted across chunks (len %d vs %d)", len(payload), len(got))

	// The default-buffer client sees the very same bytes.
	dv, err = newClient(t, url).ReadValue(ctx, f.ByteString)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, dv.Value.Value().([]byte)))
}

// TestTransport_LimitsEnforced verifies responses exceeding the negotiated
// chunk-count or message-size limit are rejected by the client while the
// connection stays usable for requests that fit.
func TestTransport_LimitsEnforced(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	payload := bytes.Repeat([]byte{0x42}, 200*1024)
	st, err := newClient(t, url).WriteNodeValue(ctx, f.ByteString, payload)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)

	t.Run("MaxChunkCount", func(t *testing.T) {
		c := newClient(t, url,
			opcua.ReceiveBufferSize(8192),
			opcua.SendBufferSize(8192),
			opcua.MaxChunkCount(4),
			opcua.AutoReconnect(false),
		)
		// 200 KiB needs ~25 chunks of 8 KiB: over the limit of 4.
		_, err := c.ReadValue(ctx, f.ByteString)
		require.ErrorIs(t, err, errors.ErrTooManyChunks)

		// A response within the limit still works on the same connection.
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("MaxMessageSize", func(t *testing.T) {
		c := newClient(t, url,
			opcua.MaxMessageSize(64*1024),
			opcua.AutoReconnect(false),
		)
		_, err := c.ReadValue(ctx, f.ByteString)
		require.ErrorIs(t, err, errors.ErrMessageTooLarge)

		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
	})

	t.Run("WithinLimits", func(t *testing.T) {
		c := newClient(t, url,
			opcua.ReceiveBufferSize(8192),
			opcua.SendBufferSize(8192),
			opcua.MaxChunkCount(64),
			opcua.MaxMessageSize(1024*1024),
		)
		dv, err := c.ReadValue(ctx, f.ByteString)
		require.NoError(t, err)
		require.True(t, bytes.Equal(payload, dv.Value.Value().([]byte)))
	})

	t.Run("DialerACK", func(t *testing.T) {
		// The same limits supplied through a custom Dialer.
		c := newClient(t, url, ackDialer(&uacp.Acknowledge{
			ReceiveBufSize: 8192,
			SendBufSize:    8192,
			MaxChunkCount:  4,
		}), opcua.AutoReconnect(false))
		_, err := c.ReadValue(ctx, f.ByteString)
		require.ErrorIs(t, err, errors.ErrTooManyChunks)
	})
}

// TestTransport_BackPressureNeverDropsRequests runs many concurrent requests
// over one channel against a server that allows only a single request of a
// channel to be in flight. The limit must only slow the client down: every
// request still gets its own, correct response.
func TestTransport_BackPressureNeverDropsRequests(t *testing.T) {
	srv, url := newServer(t, server.WithMaxPendingResponses(1))
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()
	c := newClient(t, url)

	nodes := []*ua.NodeID{f.Int16, f.Int32, f.Int64, f.Uint16, f.Uint32, f.Uint64, f.Double, f.String}
	want := []any{int16(-1234), int32(42), int64(-9_000_000_000), uint16(4321), uint32(4242), uint64(9_000_000_000), 3.14159, "hello"}

	const workers, rounds = 32, 10
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			for r := 0; r < rounds; r++ {
				i := (w + r) % len(nodes)
				dv, err := c.ReadValue(ctx, nodes[i])
				if err != nil {
					errs <- fmt.Errorf("worker %d round %d: %w", w, r, err)
					return
				}
				if dv.Value.Value() != want[i] {
					errs <- fmt.Errorf("worker %d round %d: node %s returned %v, want %v", w, r, nodes[i], dv.Value.Value(), want[i])
					return
				}
			}
			errs <- nil
		}(w)
	}
	for w := 0; w < workers; w++ {
		require.NoError(t, <-errs)
	}

	// Parked Publish requests do not count against the limit: a subscription
	// keeps delivering while ordinary requests continue.
	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f.Int32).Start(ctx)
	require.NoError(t, err)
	defer func() { _ = sub.Cancel(ctx) }()
	awaitValue(t, ch, 0, int32(42))
	writeInt32(t, c, f.Int32, 43)
	awaitValue(t, ch, 0, int32(43))
}

// TestTransport_RequestTooLargeForServer verifies a request exceeding the
// server's message-size limit is refused without taking the channel down.
func TestTransport_RequestTooLargeForServer(t *testing.T) {
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()
	c := newClient(t, url, opcua.AutoReconnect(false))

	// The server's limit is uacp.DefaultMaxMessageSize (2 MiB).
	tooBig := bytes.Repeat([]byte{0x01}, uacp.DefaultMaxMessageSize+64*1024)
	_, err := c.WriteNodeValue(ctx, f.ByteString, tooBig)
	require.Error(t, err)

	// The original value is untouched and the connection still works.
	dv, err := c.ReadValue(ctx, f.ByteString)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, dv.Value.Value())
}

func TestClient_ConnStateNotifications(t *testing.T) {
	srv, url := newServer(t)
	testutil.AddFixture(t, srv)
	ctx := context.Background()

	var mu sync.Mutex
	var viaFunc []opcua.ConnState
	viaChan := make(chan opcua.ConnState, 64)

	c, err := opcua.NewClient(url,
		opcua.DialTimeout(30*time.Second),
		opcua.RequestTimeout(30*time.Second),
		opcua.WithConnStateHandler(func(s opcua.ConnState) {
			mu.Lock()
			viaFunc = append(viaFunc, s)
			mu.Unlock()
		}),
		opcua.WithConnStateChan(viaChan),
	)
	require.NoError(t, err)
	require.Equal(t, opcua.Closed, c.State())
	require.Empty(t, viaChan, "no notification before Connect")

	require.NoError(t, c.Connect(ctx))
	require.Equal(t, opcua.Connected, c.State())
	require.Equal(t, opcua.Connecting, <-viaChan)
	require.Equal(t, opcua.Connected, <-viaChan)

	require.NoError(t, c.Close(ctx))
	require.Equal(t, opcua.Closed, c.State())
	require.Equal(t, opcua.Closed, <-viaChan)

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(viaFunc), 3)
	require.Equal(t, []opcua.ConnState{opcua.Connecting, opcua.Connected, opcua.Closed}, viaFunc[:3])
	for _, s := range viaFunc[3:] {
		require.Equal(t, opcua.Closed, s, "only Closed may follow Close")
	}
	require.Equal(t, "Connected", opcua.Connected.String())
}

// metricsRecorder implements both opcua.ClientMetrics and server.ServerMetrics.
type metricsRecorder struct {
	mu        sync.Mutex
	requests  map[string]int
	responses map[string]int
	errs      map[string][]error
	timeouts  map[string]int
}

func newMetricsRecorder() *metricsRecorder {
	return &metricsRecorder{
		requests:  map[string]int{},
		responses: map[string]int{},
		errs:      map[string][]error{},
		timeouts:  map[string]int{},
	}
}

func (m *metricsRecorder) OnRequest(svc string) {
	m.mu.Lock()
	m.requests[svc]++
	m.mu.Unlock()
}

func (m *metricsRecorder) OnResponse(svc string, d time.Duration) {
	m.mu.Lock()
	m.responses[svc]++
	m.mu.Unlock()
}

func (m *metricsRecorder) OnError(svc string, d time.Duration, err error) {
	m.mu.Lock()
	m.errs[svc] = append(m.errs[svc], err)
	m.mu.Unlock()
}

func (m *metricsRecorder) OnTimeout(svc string, d time.Duration) {
	m.mu.Lock()
	m.timeouts[svc]++
	m.mu.Unlock()
}

func (m *metricsRecorder) snapshot(svc string) (req, resp, errs, timeouts int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests[svc], m.responses[svc], len(m.errs[svc]), m.timeouts[svc]
}

// TestMetrics_ClientAndServerHooks verifies the per-service metrics callbacks
// on both sides for successful, failing and timed-out requests.
func TestMetrics_ClientAndServerHooks(t *testing.T) {
	parallel(t)
	cm, sm := newMetricsRecorder(), newMetricsRecorder()
	srv, url := newServer(t, server.WithMetrics(sm))
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	// The server dispatches requests serially, so the blocked handler must be
	// released as soon as the timeout has been observed.
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	slowID := ua.NewStringNodeID(f.NSIndex, "Slow")
	slow := server.NewFolderNode(slowID, "Slow")
	slow.SetNodeClass(ua.NodeClassMethod)
	f.NS.AddNode(slow)
	srv.RegisterMethod(f.MethodObject, slowID,
		func(ctx context.Context, _, _ *ua.NodeID, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			<-release
			return nil, ua.StatusOK
		})

	c := newClient(t, url, opcua.WithMetrics(cm), opcua.RequestTimeout(2*time.Second), opcua.AutoReconnect(false))

	t.Run("Success", func(t *testing.T) {
		req0, resp0, _, _ := cm.snapshot("Read")
		sreq0, sresp0, _, _ := sm.snapshot("Read")
		for i := 0; i < 3; i++ {
			_, err := c.ReadValue(ctx, f.Int32)
			require.NoError(t, err)
		}
		req, resp, errs, timeouts := cm.snapshot("Read")
		require.Equal(t, 3, req-req0)
		require.Equal(t, 3, resp-resp0)
		require.Zero(t, errs)
		require.Zero(t, timeouts)

		sreq, sresp, serrs, _ := sm.snapshot("Read")
		require.Equal(t, 3, sreq-sreq0)
		require.Equal(t, 3, sresp-sresp0)
		require.Zero(t, serrs)
	})

	t.Run("ServiceNames", func(t *testing.T) {
		_, err := c.BrowseAll(ctx, f.MethodObject)
		require.NoError(t, err)
		_, err = c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(2))
		require.NoError(t, err)
		_, err = c.WriteNodeValue(ctx, f.Int32, int32(42))
		require.NoError(t, err)
		for _, svc := range []string{"Browse", "Call", "Write"} {
			req, resp, _, _ := cm.snapshot(svc)
			require.Equal(t, 1, req, "client %s requests", svc)
			require.Equal(t, 1, resp, "client %s responses", svc)
			sreq, sresp, _, _ := sm.snapshot(svc)
			require.Equal(t, 1, sreq, "server %s requests", svc)
			require.Equal(t, 1, sresp, "server %s responses", svc)
		}
		// Session establishment is visible on the server side.
		sreq, sresp, _, _ := sm.snapshot("CreateSession")
		require.Equal(t, 1, sreq)
		require.Equal(t, 1, sresp)
		sreq, sresp, _, _ = sm.snapshot("ActivateSession")
		require.Equal(t, 1, sreq)
		require.Equal(t, 1, sresp)
	})

	t.Run("ServiceFault", func(t *testing.T) {
		_, err := c.QueryNext(ctx, &ua.QueryNextRequest{ContinuationPoint: []byte("nope")})
		require.ErrorIs(t, err, ua.StatusBadContinuationPointInvalid)

		req, resp, errs, timeouts := cm.snapshot("QueryNext")
		require.Equal(t, 1, req)
		require.Zero(t, resp)
		require.Equal(t, 1, errs)
		require.Zero(t, timeouts)
		require.ErrorIs(t, cm.errs["QueryNext"][0], ua.StatusBadContinuationPointInvalid)

		sreq, sresp, serrs, _ := sm.snapshot("QueryNext")
		require.Equal(t, 1, sreq)
		require.Zero(t, sresp)
		require.Equal(t, 1, serrs)
		require.ErrorIs(t, sm.errs["QueryNext"][0], ua.StatusBadContinuationPointInvalid)
	})

	t.Run("Timeout", func(t *testing.T) {
		_, err := c.CallMethod(ctx, f.MethodObject, slowID)
		unblock()
		require.ErrorIs(t, err, ua.StatusBadTimeout)
		req, resp, errs, timeouts := cm.snapshot("Call")
		require.Equal(t, 2, req)
		require.Equal(t, 1, resp, "only the earlier successful Call")
		require.Zero(t, errs, "a timeout is reported through OnTimeout, not OnError")
		require.Equal(t, 1, timeouts)
	})
}

// countingRetry retries up to max times and records every consultation.
type countingRetry struct {
	max      int
	attempts atomic.Int32
	mu       sync.Mutex
	errs     []error
}

func (r *countingRetry) ShouldRetry(attempt int, err error) (bool, time.Duration) {
	r.attempts.Add(1)
	r.mu.Lock()
	r.errs = append(r.errs, err)
	r.mu.Unlock()
	return attempt < r.max, time.Millisecond
}

func TestClient_RetryPolicy(t *testing.T) {
	sm := newMetricsRecorder()
	srv, url := newServer(t, server.WithMetrics(sm))
	f := testutil.AddFixture(t, srv)
	ctx := context.Background()

	t.Run("RetriesFailingRequest", func(t *testing.T) {
		policy := &countingRetry{max: 3}
		c := newClient(t, url, opcua.WithRetryPolicy(policy))
		before, _, _, _ := sm.snapshot("QueryNext")

		_, err := c.QueryNext(ctx, &ua.QueryNextRequest{ContinuationPoint: []byte("nope")})
		require.ErrorIs(t, err, ua.StatusBadContinuationPointInvalid)

		// 1 initial attempt + 3 retries reached the server; the policy was
		// consulted after each failure, the last time answering "stop".
		after, _, _, _ := sm.snapshot("QueryNext")
		require.Equal(t, 4, after-before)
		require.Equal(t, int32(4), policy.attempts.Load())
		for _, e := range policy.errs {
			require.ErrorIs(t, e, ua.StatusBadContinuationPointInvalid)
		}
	})

	t.Run("NotConsultedOnSuccess", func(t *testing.T) {
		policy := &countingRetry{max: 3}
		c := newClient(t, url, opcua.WithRetryPolicy(policy))
		dv, err := c.ReadValue(ctx, f.Int32)
		require.NoError(t, err)
		require.Equal(t, int32(42), dv.Value.Value())
		require.Zero(t, policy.attempts.Load())
	})

	t.Run("NoRetry", func(t *testing.T) {
		c := newClient(t, url, opcua.WithRetryPolicy(opcua.NoRetry()))
		before, _, _, _ := sm.snapshot("QueryNext")
		_, err := c.QueryNext(ctx, &ua.QueryNextRequest{ContinuationPoint: []byte("nope")})
		require.ErrorIs(t, err, ua.StatusBadContinuationPointInvalid)
		after, _, _, _ := sm.snapshot("QueryNext")
		require.Equal(t, 1, after-before)
	})

	t.Run("ExponentialBackoff", func(t *testing.T) {
		c := newClient(t, url, opcua.WithRetryPolicy(opcua.ExponentialBackoff(time.Millisecond, 4*time.Millisecond, 2)))
		before, _, _, _ := sm.snapshot("QueryNext")
		_, err := c.QueryNext(ctx, &ua.QueryNextRequest{ContinuationPoint: []byte("nope")})
		require.ErrorIs(t, err, ua.StatusBadContinuationPointInvalid)
		after, _, _, _ := sm.snapshot("QueryNext")
		require.Equal(t, 3, after-before, "initial attempt plus MaxAttempts retries")
	})

	t.Run("CancelledWhileBackingOff", func(t *testing.T) {
		c := newClient(t, url, opcua.WithRetryPolicy(opcua.NewExponentialBackoff(opcua.ExponentialBackoffConfig{
			BaseDelay: time.Hour,
			MaxDelay:  time.Hour,
		})))
		cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		_, err := c.QueryNext(cctx, &ua.QueryNextRequest{ContinuationPoint: []byte("nope")})
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}
