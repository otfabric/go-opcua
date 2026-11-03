// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// limitServer starts a server with the given options and returns it with a
// function that creates an activated session and returns its request
// header, or the status CreateSession failed with.
func limitServer(t *testing.T, opts ...Option) (*Server, func() (*ua.RequestHeader, error)) {
	t.Helper()
	srv, err := New(append([]Option{
		EndPoint("localhost", 0),
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })

	sessions := &SessionService{srv: srv}
	return srv, func() (*ua.RequestHeader, error) {
		resp, err := sessions.CreateSession(context.Background(), scNone(), &ua.CreateSessionRequest{
			RequestHeader:           reqHeader(),
			EndpointURL:             "opc.tcp://localhost:4840",
			RequestedSessionTimeout: 60000,
			ClientNonce:             make([]byte, 32),
		}, 1)
		if err != nil {
			return nil, err
		}
		h := reqHeader()
		h.AuthenticationToken = resp.(*ua.CreateSessionResponse).AuthenticationToken
		srv.sb.peek(h.AuthenticationToken).activated.Store(true)
		return h, nil
	}
}

func createSubscription(srv *Server, h *ua.RequestHeader) (uint32, error) {
	resp, err := srv.SubscriptionService.CreateSubscription(context.Background(), scNone(), &ua.CreateSubscriptionRequest{
		RequestHeader:               h,
		RequestedPublishingInterval: 1000,
		RequestedLifetimeCount:      60,
		RequestedMaxKeepAliveCount:  20,
	}, 1)
	if err != nil {
		return 0, err
	}
	return resp.(*ua.CreateSubscriptionResponse).SubscriptionID, nil
}

// TestCreateSession_TooManySessions checks the session limit of
// WithMaxSessions (Part 4 §5.6.2: Bad_TooManySessions) and that a closed or
// timed-out session frees its place.
func TestCreateSession_TooManySessions(t *testing.T) {
	srv, newSession := limitServer(t, WithMaxSessions(2))

	first, err := newSession()
	require.NoError(t, err)
	_, err = newSession()
	require.NoError(t, err)
	_, err = newSession()
	require.ErrorIs(t, err, ua.StatusBadTooManySessions)
	require.Equal(t, 2, srv.sb.count())

	// CloseSession frees a place.
	sessions := &SessionService{srv: srv}
	_, err = sessions.CloseSession(context.Background(), scNone(), &ua.CloseSessionRequest{RequestHeader: first, DeleteSubscriptions: true}, 2)
	require.NoError(t, err)
	_, err = newSession()
	require.NoError(t, err)
	_, err = newSession()
	require.ErrorIs(t, err, ua.StatusBadTooManySessions)

	// So does a session timeout.
	require.Len(t, srv.sb.reapExpired(time.Now().Add(time.Hour)), 2)
	_, err = newSession()
	require.NoError(t, err)
	_, err = newSession()
	require.NoError(t, err)
	_, err = newSession()
	require.ErrorIs(t, err, ua.StatusBadTooManySessions)
}

// TestCreateSubscription_TooManySubscriptions checks the per-session and
// the server-wide subscription limits (Part 4 §5.13.2:
// Bad_TooManySubscriptions) and that a deleted subscription frees its place.
func TestCreateSubscription_TooManySubscriptions(t *testing.T) {
	srv, newSession := limitServer(t, WithMaxSubscriptions(3), WithMaxSubscriptionsPerSession(2))
	a, err := newSession()
	require.NoError(t, err)
	b, err := newSession()
	require.NoError(t, err)

	subA, err := createSubscription(srv, a)
	require.NoError(t, err)
	_, err = createSubscription(srv, a)
	require.NoError(t, err)
	_, err = createSubscription(srv, a)
	require.ErrorIs(t, err, ua.StatusBadTooManySubscriptions, "per session")

	_, err = createSubscription(srv, b)
	require.NoError(t, err)
	_, err = createSubscription(srv, b)
	require.ErrorIs(t, err, ua.StatusBadTooManySubscriptions, "server-wide")

	resp, err := srv.SubscriptionService.DeleteSubscriptions(context.Background(), scNone(), &ua.DeleteSubscriptionsRequest{
		RequestHeader: a, SubscriptionIDs: []uint32{subA},
	}, 2)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, resp.(*ua.DeleteSubscriptionsResponse).Results)
	_, err = createSubscription(srv, b)
	require.NoError(t, err)
}

// TestTransferSubscriptions_PerSessionLimit checks that TransferSubscriptions
// does not move more subscriptions into a session than
// WithMaxSubscriptionsPerSession allows.
func TestTransferSubscriptions_PerSessionLimit(t *testing.T) {
	srv, newSession := limitServer(t, WithMaxSubscriptionsPerSession(2))
	from, err := newSession()
	require.NoError(t, err)
	to, err := newSession()
	require.NoError(t, err)

	s1, err := createSubscription(srv, from)
	require.NoError(t, err)
	s2, err := createSubscription(srv, from)
	require.NoError(t, err)
	own, err := createSubscription(srv, to)
	require.NoError(t, err)

	resp, err := srv.SubscriptionService.TransferSubscriptions(context.Background(), scNone(), &ua.TransferSubscriptionsRequest{
		RequestHeader:   to,
		SubscriptionIDs: []uint32{own, s1, s2},
	}, 3)
	require.NoError(t, err)
	results := resp.(*ua.TransferSubscriptionsResponse).Results
	require.Len(t, results, 3)
	require.Equal(t, ua.StatusOK, results[0].StatusCode, "a subscription the session owns already")
	require.Equal(t, ua.StatusOK, results[1].StatusCode)
	require.Equal(t, ua.StatusBadTooManySubscriptions, results[2].StatusCode)

	srv.SubscriptionService.Mu.Lock()
	sub := srv.SubscriptionService.Subs[s2]
	srv.SubscriptionService.Mu.Unlock()
	owner, _ := sub.sessionChannel()
	require.Same(t, srv.sb.peek(from.AuthenticationToken), owner, "the refused subscription stays where it was")
}

// TestServerCapabilities_SessionLimits checks the MaxSessions,
// MaxSubscriptions and MaxSubscriptionsPerSession variables
// (Part 5 §6.3.2) with the defaults and with configured limits.
func TestServerCapabilities_SessionLimits(t *testing.T) {
	value := func(srv *Server, nid uint32) any {
		t.Helper()
		n := srv.Node(ua.NewNumericNodeID(0, nid))
		require.NotNil(t, n, "i=%d", nid)
		dv := n.Value()
		require.NotNil(t, dv, "i=%d", nid)
		return dv.Value.Value()
	}
	for _, tc := range []struct {
		name                    string
		opts                    []Option
		sessions, subs, perSess uint32
	}{
		{"defaults", nil, 100, 1024, 64},
		{"zero and negative select the defaults", []Option{WithMaxSessions(0), WithMaxSubscriptions(-1), WithMaxSubscriptionsPerSession(0)}, 100, 1024, 64},
		{"configured", []Option{WithMaxSessions(7), WithMaxSubscriptions(70), WithMaxSubscriptionsPerSession(3)}, 7, 70, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(append([]Option{InsecureNoSecurity()}, tc.opts...)...)
			require.NoError(t, err)
			require.Equal(t, tc.sessions, value(srv, id.ServerServerCapabilitiesMaxSessions))
			require.Equal(t, tc.subs, value(srv, id.ServerServerCapabilitiesMaxSubscriptions))
			require.Equal(t, tc.perSess, value(srv, id.ServerServerCapabilitiesMaxSubscriptionsPerSession))
		})
	}
	require.Equal(t, uint32(5), capabilityValue(5))
	require.Equal(t, uint32(math.MaxInt32), capabilityValue(math.MaxInt32))
	if int64(math.MaxInt) > math.MaxUint32 {
		// int64 values so that the file also builds where int is 32 bits.
		for _, big := range []int64{math.MaxUint32, math.MaxUint32 + 1} {
			require.Equal(t, uint32(math.MaxUint32), capabilityValue(int(big)))
		}
	}
}

// TestSessionBroker_ReclaimsAbandoned: a full broker makes room by closing
// the least recently used session whose secure channel is closed, and then
// the least recently used one on a virtual channel (id 0) that has been idle
// for virtualIdleReclaim. Sessions on open channels are never closed for it.
func TestSessionBroker_ReclaimsAbandoned(t *testing.T) {
	var removed []*session
	var reasons []SessionCloseReason
	sb := &sessionBroker{s: map[string]*session{}, removed: func(s *session, r SessionCloseReason) {
		removed = append(removed, s)
		reasons = append(reasons, r)
	}}
	open := map[uint32]bool{1: true, 2: true, 3: true}
	isOpen := func(id uint32) bool { return open[id] }
	add := func(channelID uint32) *session {
		t.Helper()
		s, reclaimed := sb.newSessionWithin(4, isOpen)
		require.NotNil(t, s)
		require.Nil(t, reclaimed)
		s.channelID.Store(channelID)
		return s
	}
	virtual := add(0)
	older := add(1)
	newer := add(2)
	live := add(3)
	now := time.Now()
	virtual.touchAt(now)
	older.touchAt(now.Add(time.Second))
	newer.touchAt(now.Add(2 * time.Second))
	live.touchAt(now.Add(-time.Hour))

	// Every channel open: full.
	s, reclaimed := sb.newSessionWithin(4, isOpen)
	require.Nil(t, s)
	require.Nil(t, reclaimed)

	// Channels 1 and 2 close: the session used least recently goes.
	open[1], open[2] = false, false
	s, reclaimed = sb.newSessionWithin(4, isOpen)
	require.NotNil(t, s)
	require.Same(t, older, reclaimed)
	require.Equal(t, []SessionCloseReason{SessionClosedByServer}, reasons)
	require.Equal(t, []*session{older}, removed)
	s.channelID.Store(4)
	open[4] = true

	s, reclaimed = sb.newSessionWithin(4, isOpen)
	require.NotNil(t, s)
	require.Same(t, newer, reclaimed)
	s.channelID.Store(5)
	open[5] = true

	// Only the virtual session and live ones are left: full again.
	s, reclaimed = sb.newSessionWithin(4, isOpen)
	require.Nil(t, s)
	require.Nil(t, reclaimed)
	require.Equal(t, 4, sb.count())

	// The virtual session has been idle long enough, and its client
	// cannot be told from one that left: it goes, before the live one used
	// even less recently.
	virtual.lastActivity.Store(int64(now.Add(-virtualIdleReclaim - time.Second).Sub(monoEpoch)))
	s, reclaimed = sb.newSessionWithin(4, isOpen)
	require.NotNil(t, s)
	require.Same(t, virtual, reclaimed)
	s.channelID.Store(6)
	open[6] = true

	// A request on a new channel moves the session there.
	sb.touchTokenOn(live.AuthTokenID, 9)
	require.EqualValues(t, 9, live.channelID.Load())
	sb.touchTokenOn(live.AuthTokenID, 0)
	require.EqualValues(t, 9, live.channelID.Load(), "a virtual channel does not move it")
}

// TestCreateSession_ReclaimsSessionOfClosedChannel: the SecureChannelId of a
// session is that of its CreateSession request, also when the channel closed
// before the request was handled. The client of such a session never got the
// response, so the session is never activated; a full server reclaims it.
func TestCreateSession_ReclaimsSessionOfClosedChannel(t *testing.T) {
	srv, _ := limitServer(t, WithMaxSessions(1))
	sessions := &SessionService{srv: srv}
	create := func(channelID uint32) (*ua.CreateSessionResponse, error) {
		ctx := context.WithValue(context.Background(), secureChannelIDKey{}, channelID)
		resp, err := sessions.CreateSession(ctx, scNone(), &ua.CreateSessionRequest{
			RequestHeader:           reqHeader(),
			EndpointURL:             "opc.tcp://localhost:4840",
			RequestedSessionTimeout: 60000,
			ClientNonce:             make([]byte, 32),
		}, 1)
		if err != nil {
			return nil, err
		}
		return resp.(*ua.CreateSessionResponse), nil
	}
	// Channel 4711 is not (any longer) one the server serves.
	first, err := create(4711)
	require.NoError(t, err)
	require.False(t, srv.sb.peek(first.AuthenticationToken).activated.Load())

	second, err := create(4712)
	require.NoError(t, err)
	require.Nil(t, srv.sb.peek(first.AuthenticationToken), "the session of the closed channel was reclaimed")
	require.NotNil(t, srv.sb.peek(second.AuthenticationToken))

	// A virtual channel (0) never closes: its session stays, the server is full.
	srv.sb.peek(second.AuthenticationToken).channelID.Store(0)
	_, err = create(4713)
	require.ErrorIs(t, err, ua.StatusBadTooManySessions)
}
