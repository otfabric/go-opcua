// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// recoveryTimeout bounds every wait for the connection monitor. Recovery
// normally takes milliseconds; the bound only matters when it hangs.
const recoveryTimeout = 30 * time.Second

// recorder collects the connection states and subscription recovery events
// a client reports.
type recorder struct {
	mu     sync.Mutex
	states []opcua.ConnState
	events []opcua.SubscriptionRecoveryEvent
}

func (r *recorder) options() []opcua.Option {
	return []opcua.Option{
		opcua.AutoReconnect(true),
		opcua.ReconnectInterval(20 * time.Millisecond),
		opcua.WithConnStateHandler(func(s opcua.ConnState) {
			r.mu.Lock()
			r.states = append(r.states, s)
			r.mu.Unlock()
		}),
		opcua.WithSubscriptionRecoveryHandler(func(ev opcua.SubscriptionRecoveryEvent) {
			r.mu.Lock()
			r.events = append(r.events, ev)
			r.mu.Unlock()
		}),
	}
}

// reset forgets everything recorded so far.
func (r *recorder) reset() {
	r.mu.Lock()
	r.states, r.events = nil, nil
	r.mu.Unlock()
}

func (r *recorder) snapshot() ([]opcua.ConnState, []opcua.SubscriptionRecoveryEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.states), slices.Clone(r.events)
}

// waitRecovered waits until the client has gone through a reconnect and is
// Connected again.
func (r *recorder) waitRecovered(t *testing.T, c *opcua.Client) {
	t.Helper()
	require.Eventually(t, func() bool {
		states, _ := r.snapshot()
		return slices.Contains(states, opcua.Disconnected) &&
			states[len(states)-1] == opcua.Connected && c.State() == opcua.Connected
	}, recoveryTimeout, 5*time.Millisecond, "client did not recover")
}

// waitEvent waits for a recovery event with the given outcome and returns it.
func (r *recorder) waitEvent(t *testing.T, outcome opcua.SubscriptionRecoveryOutcome) opcua.SubscriptionRecoveryEvent {
	t.Helper()
	var found opcua.SubscriptionRecoveryEvent
	require.Eventually(t, func() bool {
		_, events := r.snapshot()
		for _, ev := range events {
			if ev.Outcome == outcome {
				found = ev
				return true
			}
		}
		return false
	}, recoveryTimeout, 5*time.Millisecond, "no recovery event %q", outcome)
	return found
}

// subscribe creates a subscription whose notifications are drained until the
// test ends, and returns its id.
func subscribe(t *testing.T, c *opcua.Client) uint32 {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *opcua.PublishNotificationData, 64)
	// A keep-alive every 150 ms: the server answers a Publish request, and the
	// client sends the next one, at least that often.
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond, MaxKeepAliveCount: 3}, ch)
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	// read the id before the client can recreate the subscription
	return sub.SubscriptionID
}

// Transfer modes of the trigger server.
const (
	transferDelegate int32 = iota
	transferGap            // delegate, but claim the next sequence number is gone
	transferUnsupported
	transferFails
	transferNoResults
)

// triggerServer is a server whose Read of node ns=1;s=trigger:<code> fails
// with that status code, which the client's connection monitor reacts on.
// TransferSubscriptions, Republish and CreateSubscription go to the
// built-in services unless switched to a fault.
type triggerServer struct {
	srv          atomic.Pointer[server.Server]
	url          string
	transferMode atomic.Int32
	republishOne atomic.Bool // answer the next Republish with a made-up message
	// answer every Republish with Good and an empty NotificationMessage
	// (sequence number 0), as opcua-asyncio 2.1.0 does for a sequence number
	// it does not hold
	republishEmpty atomic.Bool
	createFails    atomic.Bool  // fail CreateSubscription
	createCalls    atomic.Int32 // failed CreateSubscription calls
	noSub          atomic.Bool  // answer the next Publish with BadNoSubscription
}

var triggerCodes = map[string]ua.StatusCode{
	"SecureChannelIdInvalid": ua.StatusBadSecureChannelIDInvalid,
	"SessionIdInvalid":       ua.StatusBadSessionIDInvalid,
	"SubscriptionIdInvalid":  ua.StatusBadSubscriptionIDInvalid,
	"CertificateInvalid":     ua.StatusBadCertificateInvalid,
}

func newTriggerServer(t *testing.T) *triggerServer {
	t.Helper()
	ts := &triggerServer{}
	nsRead := readHandler(func(*ua.ReadValueID) *ua.DataValue { return valueDV(int32(1)) })
	read := func(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
		req := r.(*ua.ReadRequest)
		if code, ok := strings.CutPrefix(req.NodesToRead[0].NodeID.StringID(), "trigger:"); ok {
			return nil, triggerCodes[code]
		}
		return nsRead(ctx, sc, r, reqID)
	}
	transfer := func(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
		switch ts.transferMode.Load() {
		case transferUnsupported:
			return nil, ua.StatusBadServiceUnsupported
		case transferFails:
			return nil, ua.StatusBadTooManyOperations
		case transferNoResults:
			return &ua.TransferSubscriptionsResponse{ResponseHeader: okHeader(r)}, nil
		}
		resp, err := ts.srv.Load().SubscriptionService.TransferSubscriptions(ctx, sc, r, reqID)
		if res, ok := resp.(*ua.TransferSubscriptionsResponse); ok && ts.transferMode.Load() == transferGap {
			for _, tr := range res.Results {
				tr.AvailableSequenceNumbers = []uint32{1 << 30}
			}
		}
		return resp, err
	}
	republish := func(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
		req := r.(*ua.RepublishRequest)
		if ts.republishEmpty.Load() {
			return &ua.RepublishResponse{
				ResponseHeader:      okHeader(r),
				NotificationMessage: &ua.NotificationMessage{},
			}, nil
		}
		if ts.republishOne.CompareAndSwap(true, false) {
			return &ua.RepublishResponse{
				ResponseHeader:      okHeader(r),
				NotificationMessage: &ua.NotificationMessage{SequenceNumber: req.RetransmitSequenceNumber, PublishTime: time.Now()},
			}, nil
		}
		return ts.srv.Load().SubscriptionService.Republish(ctx, sc, r, reqID)
	}
	create := func(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
		if ts.createFails.Load() {
			ts.createCalls.Add(1)
			return nil, ua.StatusBadTooManySubscriptions
		}
		return ts.srv.Load().SubscriptionService.CreateSubscription(ctx, sc, r, reqID)
	}
	publish := func(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
		if ts.noSub.CompareAndSwap(true, false) {
			return nil, ua.StatusBadNoSubscription
		}
		return ts.srv.Load().SubscriptionService.Publish(ctx, sc, r, reqID)
	}
	srv, url := newScriptedServer(t, map[uint16]server.Handler{
		id.PublishRequestEncodingDefaultBinary:               publish,
		id.ReadRequestEncodingDefaultBinary:                  read,
		id.TransferSubscriptionsRequestEncodingDefaultBinary: transfer,
		id.RepublishRequestEncodingDefaultBinary:             republish,
		id.CreateSubscriptionRequestEncodingDefaultBinary:    create,
	})
	ts.srv.Store(srv)
	ts.url = url
	return ts
}

// noSubscription makes the server answer the next Publish request with
// BadNoSubscription, as it does when the session has no subscription (only a
// Publish request gets that status code).
func (ts *triggerServer) noSubscription() { ts.noSub.Store(true) }

// trigger makes the server fail a Read with the given status code.
func trigger(t *testing.T, c *opcua.Client, code string) {
	t.Helper()
	_, err := c.ReadValue(context.Background(), ua.NewStringNodeID(1, "trigger:"+code))
	require.ErrorIs(t, err, triggerCodes[code])
}

// The connection monitor reacts on the status codes that mean the secure
// channel, the session or the subscriptions are gone, and recovers them.
func TestClientCovMonitorTriggers(t *testing.T) {
	ts := newTriggerServer(t)
	rec := &recorder{}
	c := connectCovClient(t, ts.url, rec.options()...)
	subID := subscribe(t, c)
	ctx := context.Background()

	readOK := func() {
		t.Helper()
		dv, err := c.ReadValue(ctx, ua.NewStringNodeID(1, "plain"))
		require.NoError(t, err)
		require.Equal(t, int32(1), dv.Value.Value())
	}

	t.Run("secure channel invalid", func(t *testing.T) {
		rec.reset()
		trigger(t, c, "SecureChannelIdInvalid")
		rec.waitRecovered(t, c)
		// the session survived on the server: it is restored, and with it
		// the subscription
		ev := rec.waitEvent(t, opcua.SubscriptionRecoveryTransferred)
		require.Equal(t, subID, ev.SubscriptionID)
		readOK()
	})

	t.Run("secure channel invalid/republish answered without the message", func(t *testing.T) {
		// A Good RepublishResponse whose NotificationMessage is not the one
		// asked for ends the retransmission like BadMessageNotAvailable: the
		// client neither rewinds its sequence numbers to it nor asks again
		// and again.
		ts.republishEmpty.Store(true)
		t.Cleanup(func() { ts.republishEmpty.Store(false) })
		rec.reset()
		trigger(t, c, "SecureChannelIdInvalid")
		rec.waitRecovered(t, c)
		ev := rec.waitEvent(t, opcua.SubscriptionRecoveryTransferred)
		require.Equal(t, subID, ev.SubscriptionID)
		readOK()
	})

	outcomes := []struct {
		name      string
		mode      int32
		republish bool
		want      opcua.SubscriptionRecoveryOutcome
	}{
		{"transferred", transferDelegate, false, opcua.SubscriptionRecoveryTransferred},
		{"republished", transferDelegate, true, opcua.SubscriptionRecoveryRepublished},
		{"unrecoverable gap", transferGap, false, opcua.SubscriptionRecoveryUnrecoverableGap},
		{"partial", transferGap, true, opcua.SubscriptionRecoveryPartial},
		{"transfer unsupported", transferUnsupported, false, opcua.SubscriptionRecoveryRecreated},
		{"transfer fails", transferFails, false, opcua.SubscriptionRecoveryRecreated},
		{"transfer without results", transferNoResults, false, opcua.SubscriptionRecoveryRecreated},
	}
	for _, tt := range outcomes {
		t.Run("session invalid/"+tt.name, func(t *testing.T) {
			ts.transferMode.Store(tt.mode)
			ts.republishOne.Store(tt.republish)
			t.Cleanup(func() {
				ts.transferMode.Store(transferDelegate)
				ts.republishOne.Store(false)
			})
			before := c.Session().SessionID().String()
			rec.reset()
			trigger(t, c, "SessionIdInvalid")
			rec.waitRecovered(t, c)
			rec.waitEvent(t, tt.want)
			require.NotEqual(t, before, c.Session().SessionID().String(), "a new session is created")
			require.Len(t, c.SubscriptionIDs(), 1)
			readOK()
		})
	}

	t.Run("subscription invalid", func(t *testing.T) {
		rec.reset()
		trigger(t, c, "SubscriptionIdInvalid")
		rec.waitRecovered(t, c)
		rec.waitEvent(t, opcua.SubscriptionRecoveryTransferred)
		readOK()
	})

	t.Run("certificate invalid", func(t *testing.T) {
		rec.reset()
		trigger(t, c, "CertificateInvalid")
		rec.waitRecovered(t, c)
		readOK()
	})

	t.Run("no subscription", func(t *testing.T) {
		rec.reset()
		before := c.SubscriptionIDs()
		ts.noSubscription()
		// not a connection problem: the subscriptions are recreated, the
		// connection stays up
		rec.waitEvent(t, opcua.SubscriptionRecoveryRecreated)
		states, _ := rec.snapshot()
		require.NotContains(t, states, opcua.Disconnected)
		require.Eventually(t, func() bool {
			ids := c.SubscriptionIDs()
			return len(ids) == 1 && ids[0] != before[0]
		}, recoveryTimeout, 5*time.Millisecond)
	})

	t.Run("recreation retried", func(t *testing.T) {
		// The recreation of a subscription fails until the server accepts
		// subscriptions again; the monitor keeps trying.
		ts.createFails.Store(true)
		ts.createCalls.Store(0)
		rec.reset()
		ts.noSubscription()
		require.Eventually(t, func() bool { return ts.createCalls.Load() >= 3 }, recoveryTimeout, 5*time.Millisecond)
		_, events := rec.snapshot()
		require.Empty(t, events, "no recovery while the server refuses")
		ts.createFails.Store(false)
		rec.waitEvent(t, opcua.SubscriptionRecoveryRecreated)
	})

	t.Run("recreation during reconnect retried", func(t *testing.T) {
		ts.createFails.Store(true)
		ts.createCalls.Store(0)
		ts.transferMode.Store(transferUnsupported)
		t.Cleanup(func() { ts.transferMode.Store(transferDelegate) })
		rec.reset()
		trigger(t, c, "SessionIdInvalid")
		rec.waitRecovered(t, c)
		require.Eventually(t, func() bool { return ts.createCalls.Load() >= 2 }, recoveryTimeout, 5*time.Millisecond)
		ts.createFails.Store(false)
		rec.waitEvent(t, opcua.SubscriptionRecoveryRecreated)
		readOK()
	})
}

// Activating a new session moves the client's subscriptions into it: they are
// recreated there.
func TestClientCovActivateSessionRecreatesSubscriptions(t *testing.T) {
	_, url := testutil.NewTestServer(t)
	rec := &recorder{}
	c := connectCovClient(t, url, rec.options()...)
	oldID := subscribe(t, c)
	ctx := context.Background()

	s, err := c.CreateSession(ctx, opcua.DefaultSessionConfig())
	require.NoError(t, err)
	require.NoError(t, c.ActivateSession(ctx, s))
	ev := rec.waitEvent(t, opcua.SubscriptionRecoveryRecreated)
	require.Equal(t, oldID, ev.SubscriptionID)
	require.Eventually(t, func() bool {
		ids := c.SubscriptionIDs()
		return len(ids) == 1 && ids[0] != oldID
	}, recoveryTimeout, 5*time.Millisecond)
	states, _ := rec.snapshot()
	require.NotContains(t, states, opcua.Disconnected)
}

// failingServer is a server whose service typeID always fails; calls counts
// the failures. It sits behind proxy; the backend address is returned.
func failingServer(t *testing.T, proxy *testutil.ChaosProxy, typeID uint16, status ua.StatusCode, calls *atomic.Int32) string {
	t.Helper()
	return newProxiedServer(t, proxy, map[uint16]server.Handler{
		typeID: func(context.Context, *uasc.SecureChannel, ua.Request, uint32) (ua.Response, error) {
			calls.Add(1)
			return nil, status
		},
	})
}

// The connection is lost and the server is replaced by others that fail the
// recovery in each of its steps, until a working one comes up.
func TestClientCovMonitorServerReplaced(t *testing.T) {
	proxy := testutil.NewChaosProxy(t, "", 1)
	first := newProxiedServer(t, proxy, nil)
	var createFails, activateFails, namespaceFails atomic.Int32
	noCreate := failingServer(t, proxy, id.CreateSessionRequestEncodingDefaultBinary, ua.StatusBadTooManySessions, &createFails)
	noActivate := failingServer(t, proxy, id.ActivateSessionRequestEncodingDefaultBinary, ua.StatusBadIdentityTokenRejected, &activateFails)
	noNamespaces := failingServer(t, proxy, id.ReadRequestEncodingDefaultBinary, ua.StatusBadUserAccessDenied, &namespaceFails)
	last := newProxiedServer(t, proxy, nil)
	proxy.SetBackend(first)
	rec := &recorder{}
	c := connectCovClient(t, proxy.EndpointURL(), rec.options()...)
	oldSub := subscribe(t, c)
	oldSession := c.Session().SessionID().String()

	// The server goes down: dialing fails and is retried.
	proxy.SetRefuse(true)
	accepted := proxy.Accepted()
	proxy.DropAll()
	require.Eventually(t, func() bool { return proxy.Accepted() >= accepted+2 }, recoveryTimeout, 5*time.Millisecond)

	// A server comes up that cannot create sessions.
	proxy.SetBackend(noCreate)
	proxy.SetRefuse(false)
	require.Eventually(t, func() bool { return createFails.Load() >= 2 }, recoveryTimeout, 5*time.Millisecond)

	// One that cannot activate them.
	proxy.SetBackend(noActivate)
	require.Eventually(t, func() bool { return activateFails.Load() >= 3 }, recoveryTimeout, 5*time.Millisecond)

	// One whose namespace table cannot be read: the session is created and
	// activated, the recovery fails afterwards, and the session is restored
	// on the next attempt but fails again.
	proxy.SetBackend(noNamespaces)
	require.Eventually(t, func() bool { return namespaceFails.Load() >= 3 }, recoveryTimeout, 5*time.Millisecond)

	// Finally a working server, which does not know the subscription.
	proxy.SetBackend(last)
	rec.waitRecovered(t, c)
	rec.waitEvent(t, opcua.SubscriptionRecoveryRecreated)
	require.NotEqual(t, oldSession, c.Session().SessionID().String())
	ids := c.SubscriptionIDs()
	require.Len(t, ids, 1)
	require.NotEqual(t, oldSub, ids[0], "the subscription was recreated")

	ss, err := c.ServerStatus(context.Background())
	require.NoError(t, err)
	require.Equal(t, ua.ServerStateRunning, ss.State)
}

// A connection that breaks without the server going away is recovered with
// the same session.
func TestClientCovMonitorConnectionDropped(t *testing.T) {
	proxy := testutil.NewChaosProxy(t, "", 1)
	proxy.SetBackend(newProxiedServer(t, proxy, nil))
	rec := &recorder{}
	c := connectCovClient(t, proxy.EndpointURL(), rec.options()...)
	subID := subscribe(t, c)
	session := c.Session().SessionID().String()

	proxy.DropAll()
	rec.waitRecovered(t, c)
	ev := rec.waitEvent(t, opcua.SubscriptionRecoveryTransferred)
	require.Equal(t, subID, ev.SubscriptionID)
	require.Equal(t, session, c.Session().SessionID().String(), "the session is restored")

	// A message of a type that does not exist is a connection error as
	// well, not just an end of the connection.
	rec.reset()
	var mangled atomic.Bool
	proxy.SetFrameMangle(testutil.ServerToClient, func(msg []byte) [][]byte {
		if string(msg[:3]) == "MSG" && mangled.CompareAndSwap(false, true) {
			copy(msg, "XYZ")
		}
		return [][]byte{msg}
	})
	_, _ = c.ServerStatus(context.Background())
	rec.waitRecovered(t, c)
	require.True(t, mangled.Load())
	proxy.SetFrameMangle(testutil.ServerToClient, nil)
	ss, err := c.ServerStatus(context.Background())
	require.NoError(t, err)
	require.Equal(t, ua.ServerStateRunning, ss.State)
}

// Without auto reconnect a lost connection ends the client.
func TestClientCovMonitorNoAutoReconnect(t *testing.T) {
	proxy := testutil.NewChaosProxy(t, "", 1)
	proxy.SetBackend(newProxiedServer(t, proxy, nil))
	rec := &recorder{}
	opts := append(rec.options(), opcua.AutoReconnect(false))
	c := connectCovClient(t, proxy.EndpointURL(), opts...)

	proxy.DropAll()
	require.Eventually(t, func() bool {
		states, _ := rec.snapshot()
		return slices.Contains(states, opcua.Disconnected) && c.State() == opcua.Closed
	}, recoveryTimeout, 5*time.Millisecond)
	states, _ := rec.snapshot()
	require.NotContains(t, states, opcua.Reconnecting)
}
