// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// faultLog records the Publish requests a server answers with a
// ServiceFault.
type faultLog struct {
	mu     sync.Mutex
	ids    []uint32
	status map[uint32]ua.StatusCode
	handle map[uint32]uint32
}

func recordFaults(srv *Server) *faultLog {
	l := &faultLog{status: map[uint32]ua.StatusCode{}, handle: map[uint32]uint32{}}
	srv.publishFaulted = func(pr PubReq, st ua.StatusCode) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.ids = append(l.ids, pr.ID)
		l.status[pr.ID] = st
		if pr.Req != nil && pr.Req.RequestHeader != nil {
			l.handle[pr.ID] = pr.Req.RequestHeader.RequestHandle
		}
	}
	return l
}

func (l *faultLog) faulted() []uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]uint32(nil), l.ids...)
}

func testPubReq(id uint32) PubReq {
	return PubReq{Req: &ua.PublishRequest{RequestHeader: &ua.RequestHeader{RequestHandle: 1000 + id}}, ID: id}
}

// queuedIDs returns the ids of the requests queued on sess, oldest first,
// and leaves the queue as it was.
func queuedIDs(sess *session) []uint32 {
	sess.publishMu.Lock()
	defer sess.publishMu.Unlock()
	var prs []PubReq
	for len(sess.PublishRequests) > 0 {
		prs = append(prs, <-sess.PublishRequests)
	}
	ids := make([]uint32, len(prs))
	for i, pr := range prs {
		ids[i] = pr.ID
		sess.PublishRequests <- pr
	}
	return ids
}

// TestQueuePublishRequest_EvictsOldest: a Publish request that finds the
// queue full is queued, and the oldest queued request is answered with
// Bad_TooManyPublishRequests, with its own RequestHandle (Part 4
// §5.14.5.1: "it shall de-queue the oldest Publish request and return a
// response with the result set to Bad_TooManyPublishRequests"). The order
// of the others is kept and the queue of another session is not touched.
//
// Regression: the new request was refused and the oldest stayed queued.
func TestQueuePublishRequest_EvictsOldest(t *testing.T) {
	srv := newTestServer()
	faults := recordFaults(srv)
	sess := &session{PublishRequests: make(chan PubReq, 3)}
	other := &session{PublishRequests: make(chan PubReq, 3)}
	srv.queuePublishRequest(other, testPubReq(100))

	for id := uint32(1); id <= 3; id++ {
		srv.queuePublishRequest(sess, testPubReq(id))
	}
	require.Empty(t, faults.faulted())

	srv.queuePublishRequest(sess, testPubReq(4))
	require.Equal(t, []uint32{1}, faults.faulted())
	require.Equal(t, ua.StatusBadTooManyPublishRequests, faults.status[1])
	require.Equal(t, uint32(1001), faults.handle[1], "the response carries the handle of the request it answers")
	require.Equal(t, []uint32{2, 3, 4}, queuedIDs(sess))

	srv.queuePublishRequest(sess, testPubReq(5))
	srv.queuePublishRequest(sess, testPubReq(6))
	require.Equal(t, []uint32{1, 2, 3}, faults.faulted())
	require.Equal(t, []uint32{4, 5, 6}, queuedIDs(sess))
	require.Equal(t, []uint32{100}, queuedIDs(other))
}

// TestPublishQueue_Concurrent queues, takes, cancels and releases Publish
// requests of one session at the same time (run with -race): every request
// is answered or taken exactly once, none is lost and none is answered
// twice.
func TestPublishQueue_Concurrent(t *testing.T) {
	srv := newTestServer()
	faults := recordFaults(srv)
	subs := &SubscriptionService{srv: srv}
	sess := &session{PublishRequests: make(chan PubReq, 8)}

	const producers, perProducer = 4, 250
	var (
		takenMu sync.Mutex
		taken   []uint32
		wg      sync.WaitGroup
	)
	stop := make(chan struct{})
	for p := range producers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perProducer {
				srv.queuePublishRequest(sess, testPubReq(uint32(p*perProducer+i+1)))
			}
		}()
	}
	var side sync.WaitGroup
	side.Add(3)
	go func() { // a subscription that answers requests
		defer side.Done()
		for {
			select {
			case pr := <-sess.PublishRequests:
				takenMu.Lock()
				taken = append(taken, pr.ID)
				takenMu.Unlock()
			case <-stop:
				return
			}
		}
	}()
	go func() { // Cancel
		defer side.Done()
		for h := uint32(1000); ; h += 7 {
			select {
			case <-stop:
				return
			default:
				srv.cancelPublishRequests(sess, h, nil)
			}
		}
	}()
	go func() { // a closing session
		defer side.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
				subs.releasePublishRequests(sess, ua.StatusBadSessionClosed)
			}
		}
	}()
	wg.Wait()
	close(stop)
	side.Wait()
	subs.releasePublishRequests(sess, ua.StatusBadSessionClosed)

	seen := map[uint32]int{}
	for _, id := range append(faults.faulted(), taken...) {
		seen[id]++
	}
	require.Len(t, seen, producers*perProducer, "every request is answered")
	for id, n := range seen {
		require.Equal(t, 1, n, "request %d answered %d times", id, n)
	}
}

// TestPublishQueueSize: "a Server shall accept more queued Publish requests
// than created Subscriptions" (Part 4 §5.14.5.1): a session queues at least
// one Publish request more than the subscriptions it may have, and at least
// 100.
func TestPublishQueueSize(t *testing.T) {
	require.Equal(t, 100, publishQueueSize(defaultMaxSubscriptionsPerSession))
	require.Equal(t, 100, publishQueueSize(99))
	require.Equal(t, 101, publishQueueSize(100))
	require.Equal(t, 151, publishQueueSize(150))

	for _, c := range []struct {
		opts []Option
		want int
	}{
		{nil, 100},
		{[]Option{WithMaxSubscriptionsPerSession(150)}, 151},
	} {
		srv, err := New(append([]Option{EndPoint("localhost", 0), InsecureNoSecurity()}, c.opts...)...)
		require.NoError(t, err)
		require.Equal(t, c.want, cap(srv.sb.NewSession().PublishRequests))
		require.Greater(t, c.want, srv.cfg.subscriptionsPerSessionLimit())
	}
}

// TestPublish_FullQueueAnswersOldest over the wire: with the queue of the
// session full, one more Publish request is queued and the client's oldest
// one returns Bad_TooManyPublishRequests; the others stay queued, in their
// order, and the Publish request of another session is not touched.
func TestPublish_FullQueueAnswersOldest(t *testing.T) {
	srv, err := New(EndPoint("localhost", 0), InsecureNoSecurity(), EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connect := func() *opcua.Client {
		c, err := opcua.NewClient(srv.Endpoints()[0].EndpointURL, opcua.InsecureNoSecurity(),
			opcua.AutoReconnect(false), opcua.RequestTimeout(60*time.Second))
		require.NoError(t, err)
		require.NoError(t, c.Connect(ctx))
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		// A subscription that publishes nothing during the test.
		require.NoError(t, c.Send(ctx, &ua.CreateSubscriptionRequest{
			RequestedPublishingInterval: 60000, RequestedLifetimeCount: 3000,
			RequestedMaxKeepAliveCount: 1000, PublishingEnabled: true,
		}, func(ua.Response) error { return nil }))
		return c
	}
	sessionOf := func(c *opcua.Client) *session {
		srv.sb.mu.Lock()
		defer srv.sb.mu.Unlock()
		for _, s := range srv.sb.s {
			if s.ID.Equal(c.Session().SessionID()) {
				return s
			}
		}
		t.Fatal("no server session for the client")
		return nil
	}
	publish := func(c *opcua.Client, done chan<- error) {
		go func() {
			done <- c.Send(ctx, &ua.PublishRequest{SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{}}, func(ua.Response) error { return nil })
		}()
	}

	bystander := connect()
	bystanderDone := make(chan error, 1)
	publish(bystander, bystanderDone)
	bySess := sessionOf(bystander)
	require.Eventually(t, func() bool { return len(bySess.PublishRequests) == 1 }, 10*time.Second, time.Millisecond)

	c := connect()
	sess := sessionOf(c)
	limit := cap(sess.PublishRequests)
	done := make([]chan error, limit+1)
	for i := range done {
		done[i] = make(chan error, 1)
		publish(c, done[i])
		want := min(i+1, limit)
		require.Eventually(t, func() bool { return len(sess.PublishRequests) == want }, 10*time.Second, time.Millisecond)
		if i == limit-1 {
			require.Equal(t, limit, len(queuedIDs(sess)))
		}
	}
	first := queuedIDs(sess)[0]

	select {
	case err := <-done[0]:
		require.ErrorIs(t, err, ua.StatusBadTooManyPublishRequests)
	case <-ctx.Done():
		t.Fatal("the oldest Publish request was not answered")
	}
	before := queuedIDs(sess)
	require.NotContains(t, before, first, "the oldest request left the queue")
	for i := 1; i < len(done); i++ {
		select {
		case err := <-done[i]:
			t.Fatalf("Publish request %d returned %v", i, err)
		default:
		}
	}
	require.Len(t, before, limit)
	for i := 1; i < len(before); i++ {
		require.Less(t, before[i-1], before[i], "the queue keeps the order of the requests")
	}
	require.Len(t, bySess.PublishRequests, 1, "the other session keeps its request")
	select {
	case err := <-bystanderDone:
		t.Fatalf("the Publish request of the other session returned %v", err)
	default:
	}
}

// TestSendStatusChange_PutsRequestBack: a subscription that took a Publish
// request for a StatusChangeNotification another request has sent
// meanwhile queues the request again instead of dropping it.
func TestSendStatusChange_PutsRequestBack(t *testing.T) {
	srv := newTestServer()
	faults := recordFaults(srv)
	sub := NewSubscription()
	sub.srv = srv.SubscriptionService
	sess := &session{PublishRequests: make(chan PubReq, 2)}
	srv.queuePublishRequest(sess, testPubReq(1))

	sub.sendStatusChange(sess, nil)
	require.Equal(t, []uint32{1}, queuedIDs(sess))
	require.Empty(t, faults.faulted())
}
