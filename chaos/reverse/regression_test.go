// SPDX-License-Identifier: MIT

package reverse

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
)

// TestRegressionLostCreateSubscriptionResponse pins down a leak of
// subscriptions on the server, found by TestChaosSharedReverseListener.
//
// When the connection breaks after a CreateSubscription request reached the
// server but before its response reached the client, the server has a
// subscription the client knows nothing about. The client reconnects and
// takes up its session again, and with the session the subscription lives
// on: every Publish request of the session keeps it alive, and it answers
// them with keep-alive messages that the client used to ignore. Nothing ever
// deleted it. Each lost response left one more behind, for as long as the
// session lasted.
//
// The client must delete a subscription of its session that it does not
// know, and must leave its other subscriptions alone.
func TestRegressionLostCreateSubscriptionResponse(t *testing.T) {
	verifyLeaks := chaoskit.LeakCheck(t)
	n := newNode(t, "server", 0, noneProfile("urn:otfabric:chaos:reverse:regression"), 1).up("")
	rec := chaoskit.NewStateRecorder("client", true)
	c := n.connect(rec, opcua.RequestTimeout(10*time.Second))
	stopFeed := n.feed()
	defer stopFeed()

	// Nothing the server sends arrives any more. The server creates the
	// subscription; then the connection breaks.
	n.fwd.SetBlackhole(testutil.ServerToClient, true)
	failed := make(chan error, 1)
	go func() {
		ctx, cancel := chaoskit.OpCtx()
		defer cancel()
		_, err := c.Subscribe(ctx, streamParams(), make(chan *opcua.PublishNotificationData, 1))
		failed <- err
	}()
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return n.resources().Subscriptions == 1 }) {
		t.Fatalf("the server did not create the subscription: %+v", n.resources())
	}
	n.fwd.SetBlackhole(testutil.ServerToClient, false)
	n.fwd.DropAll()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("Subscribe succeeded although its response was lost")
		}
	case <-time.After(chaoskit.SettleLimit):
		t.Fatalf("Subscribe did not return\n%s", chaoskit.AllStacks())
	}

	// The client is back, in the same session, and subscribes for real.
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return c.State() == opcua.Connected }) {
		t.Fatalf("client did not reconnect: %v", rec.Snapshot())
	}
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	var st *stream
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		var err error
		st, err = openStream(ctx, n, c, "stream")
		return err == nil
	}) {
		t.Fatal("could not subscribe after the reconnect")
	}
	if res := n.resources(); res.Sessions != 1 {
		t.Fatalf("the server has %d sessions, want the one the client took up again", res.Sessions)
	}

	// The subscription nobody knows is deleted as soon as it shows up in a
	// Publish response (its first keep-alive is due after 100ms). The other
	// one keeps delivering.
	if !chaoskit.Eventually(10*time.Second, func() bool { return n.resources().Subscriptions == 1 }) {
		t.Errorf("the server holds %d subscriptions of a client that has 1: %+v", n.resources().Subscriptions, n.resources())
	}
	if ids := c.SubscriptionIDs(); len(ids) != 1 {
		t.Errorf("the client has subscriptions %v, want 1", ids)
	}
	mark := n.counter.Load()
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return st.lastValue() > mark }) {
		t.Errorf("the client's subscription stopped delivering: last value %d, node at %d", st.lastValue(), n.counter.Load())
	}
	if res := n.resources(); res.Subscriptions != 1 || res.MonitoredItems != 1 {
		t.Errorf("the server holds %+v, want the one subscription with its monitored item", res)
	}

	cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := st.sub.Cancel(cctx); err != nil {
		t.Errorf("cancel: %v", err)
	}
	ccancel()
	chaoskit.CloseClient(c, rec)
	st.close()
	st.report(t)
	rec.Check(t, true)
	n.requireDrained()
	stopFeed()
	n.stop()
	n.fwd.Close()
	verifyLeaks()
}
