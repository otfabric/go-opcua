// SPDX-License-Identifier: MIT

package chaos

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
)

// silentLimit bounds how long a subscription of a Connected client may stay
// silent in the tests of this file before that counts as stuck.
const silentLimit = settleLimit

// Bug: a session that the application re-activated after the client had
// replaced it took the subscriptions away without anybody noticing.
//
// The application detaches the session (DetachSession). The client, which
// needs a session, creates a new one and transfers its subscriptions to it.
// The application then activates the old session again: ActivateSession
// closes the session the client has in the meantime, and with it, on the
// server, the subscriptions. The client kept them registered. As long as the
// re-activated session had no subscription at all, the next Publish request
// was answered with BadNoSubscription and everything was recreated; with a
// single subscription created on it in time, the others stayed silent for
// good while the client reported Connected.
//
// This is the "detach session" fault of the monkey right after a connection
// loss (TestChaosMonkeyNetworkFaults, CI seed 1791778880737513190).
// Fix: client.go ActivateSession (the subscriptions follow a session the
// application activates), client.go monitor (silent subscriptions).
func TestRegressionReactivatedSessionKeepsSubscriptions(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	stop := startBumper(e, 0, 1)
	defer stop()

	rec := newStateRecorder("reactivate", true)
	c := e.connect(rec)
	// one bound for the whole script
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := openStream(ctx, e, c, "first", 8, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	delivering := func(st *stream, counter int) bool {
		marker := e.counters[counter].Load()
		return eventually(silentLimit, func() bool { return st.lastValue(counter) > marker })
	}
	if !delivering(st, 0) {
		t.Fatal("the stream does not deliver")
	}

	var others []*stream
	for round := 0; round < 4; round++ {
		old, err := c.DetachSession(ctx)
		if err != nil || old == nil {
			t.Fatalf("round %d: DetachSession: %v %v", round, old, err)
		}
		// The client replaces the session and takes the subscription along.
		if !eventually(settleLimit, func() bool {
			s := c.Session()
			return s != nil && s != old && c.State() == opcua.Connected
		}) {
			t.Fatalf("round %d: the client did not replace the detached session: %v", round, rec.snapshot())
		}
		if !delivering(st, 0) {
			t.Fatalf("round %d: the stream did not follow to the new session", round)
		}

		// The application comes back with the old session and subscribes to
		// something else right away.
		if err := c.ActivateSession(ctx, old); err != nil {
			t.Fatalf("round %d: ActivateSession: %v", round, err)
		}
		// (A call that is under way while the client changes its session
		// may fail with a session error, like during any reconnect.)
		var second *stream
		if !eventually(settleLimit, func() bool {
			second, err = openStream(ctx, e, c, "second", 8, false, 1)
			return err == nil || !isConnectionError(err)
		}) || err != nil {
			t.Fatalf("round %d: second stream: %v", round, err)
		}
		others = append(others, second)

		if !delivering(second, 1) {
			t.Errorf("round %d: the new subscription does not deliver", round)
		}
		if !delivering(st, 0) {
			t.Fatalf("STUCK in round %d: the subscription from before the session was re-activated is silent: last delivered %d, node at %d, client %v, subscriptions %v, server %+v",
				round, st.lastValue(0), e.counters[0].Load(), c.State(), c.SubscriptionIDs(), e.resources())
		}
	}

	for _, s := range append(others, st) {
		if err := s.sub.Cancel(ctx); err != nil {
			t.Errorf("cancel: %v", err)
		}
	}
	closeClient(c, rec)
	for _, s := range append(others, st) {
		s.close()
		s.report(t)
	}
	rec.check(t, true)
}
