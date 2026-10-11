// SPDX-License-Identifier: MIT

package chaos

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
)

// emptyResults installs a rewrite of the server's responses on the proxy:
// the next response of the type named by the returned value loses its
// results, as a damaged message or a faulty server would deliver it. It only
// works on channels without security.
func emptyResults(e *env) *atomic.Value {
	var target atomic.Value // name of the response type, e.g. "*ua.ReadResponse"
	target.Store("")
	e.proxy.SetFrameMangle(testutil.ServerToClient, func(m []byte) [][]byte {
		// message header (8), SecureChannelId and TokenId (8), sequence
		// header (8), then the service
		const body = 24
		want := target.Load().(string)
		if want == "" || len(m) < body || string(m[:4]) != "MSGF" {
			return [][]byte{m}
		}
		_, svc, err := ua.DecodeService(m[body:])
		// one response per order
		if err != nil || fmt.Sprintf("%T", svc) != want || !target.CompareAndSwap(want, "") {
			return [][]byte{m}
		}
		results := reflect.ValueOf(svc).Elem().FieldByName("Results")
		results.Set(reflect.Zero(results.Type()))
		typeID, err1 := ua.Encode(ua.NewFourByteExpandedNodeID(0, ua.ServiceTypeID(svc)))
		rest, err2 := ua.Encode(svc)
		if err1 != nil || err2 != nil {
			return [][]byte{m}
		}
		out := append(append(m[:body:body], typeID...), rest...)
		binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
		return [][]byte{out}
	})
	return &target
}

// Bug: the client indexed the results of a response without looking at
// their number. A response with fewer results than the request had operations
// (from a faulty server or, without message security, a damaged message)
// panicked in the application's goroutine: in ReadValue, WriteNodeValue,
// Browse, Subscription.Monitor (there with the lock on the monitored items
// held, so that the next call on the subscription blocked for good) and
// Subscription.Cancel. Found by TestChaosMonkeyCorruption.
// Fix: client.go, node.go, subscription.go: BadUnknownResponse.
func TestRegressionResponseWithoutResults(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	target := emptyResults(e)
	c := e.connect(nil, opcua.AutoReconnect(false))
	ctx, cancel := opCtx()
	defer cancel()

	ch := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, streamParams(), ch)
	if err != nil {
		t.Fatal(err)
	}

	calls := []struct {
		response string
		call     func() error
	}{
		{"*ua.ReadResponse", func() error { _, err := c.ReadValue(ctx, e.scratchID(0)); return err }},
		{"*ua.WriteResponse", func() error { _, err := c.WriteNodeValue(ctx, e.scratchID(0), int32(1)); return err }},
		{"*ua.BrowseResponse", func() error { _, err := c.BrowseAll(ctx, e.folderID()); return err }},
		{"*ua.CreateMonitoredItemsResponse", func() error {
			_, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
				opcua.NewMonitoredItemCreateRequestWithDefaults(e.scratchID(0), ua.AttributeIDValue, 1))
			return err
		}},
		{"*ua.DeleteSubscriptionsResponse", func() error { return sub.Cancel(ctx) }},
	}
	for _, tc := range calls {
		target.Store(tc.response)
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s without results: the client panicked: %v", tc.response, r)
				}
			}()
			err = tc.call()
		}()
		target.Store("")
		if !isStatus(err, ua.StatusBadUnknownResponse) {
			t.Errorf("%s without results: got %v, want BadUnknownResponse", tc.response, err)
		}
	}

	// The client is still usable, and so is a subscription after a Monitor
	// call that got such a response.
	ch2 := make(chan *opcua.PublishNotificationData, 16)
	sub2, err := c.Subscribe(ctx, streamParams(), ch2)
	if err != nil {
		t.Fatal(err)
	}
	item := opcua.NewMonitoredItemCreateRequestWithDefaults(e.scratchID(1), ua.AttributeIDValue, 2)
	target.Store("*ua.CreateMonitoredItemsResponse")
	_, err = sub2.Monitor(ctx, ua.TimestampsToReturnBoth, item)
	target.Store("")
	if !isStatus(err, ua.StatusBadUnknownResponse) {
		t.Errorf("Monitor without results: got %v", err)
	}
	res, err := sub2.Monitor(ctx, ua.TimestampsToReturnBoth, item)
	if err != nil || len(res.Results) != 1 || res.Results[0].StatusCode != ua.StatusOK {
		t.Fatalf("Monitor after the damaged response: %v", err)
	}
	if _, err := c.ReadValue(ctx, e.scratchID(0)); err != nil {
		t.Fatalf("ReadValue after the damaged responses: %v", err)
	}
	if err := sub2.Cancel(ctx); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
}

// Bug: a subscription whose recreation failed was only tried again by the
// next reconnect. When the recreation failed although the connection was
// fine (here: the CreateMonitoredItems request is lost and times out; in the
// chaos scenarios: it timed out on a busy machine), the client reported
// Connected with a subscription that had no monitored items on the server
// and never delivered again. Found by TestChaosMonkeyNetworkFaults under CPU
// pressure.
// Fix: client.go monitor: retry after ReconnectInterval while subscriptions
// are marked for recreation.
func TestRegressionFailedRecreationIsRetried(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1)
	// Lose one CreateMonitoredItems request on its way to the server. The
	// channel has no security, so nobody notices the gap.
	var lose, lost atomic.Bool
	e.proxy.SetFrameMangle(testutil.ClientToServer, func(m []byte) [][]byte {
		const body = 24
		if len(m) < body || string(m[:4]) != "MSGF" || !lose.Load() {
			return [][]byte{m}
		}
		_, svc, err := ua.DecodeService(m[body:])
		if _, ok := svc.(*ua.CreateMonitoredItemsRequest); err != nil || !ok || !lose.CompareAndSwap(true, false) {
			return [][]byte{m}
		}
		lost.Store(true)
		return nil
	})
	stop := startBumper(e, 0)
	defer stop()

	rec := newStateRecorder("retry", true)
	c := e.connect(rec, opcua.RequestTimeout(time.Second))
	ctx, cancel := opCtx()
	defer cancel()
	st, err := openStream(ctx, e, c, "retry", 8, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !eventually(settleLimit, func() bool { return st.lastValue(0) > 0 }) {
		t.Fatal("the stream does not deliver")
	}

	// The server is replaced: the subscription has to be recreated, and the
	// first attempt to create its monitored items fails.
	lose.Store(true)
	e.restartServer(0)
	if !eventually(settleLimit, func() bool { return lost.Load() }) {
		t.Fatal("the monitored items were not recreated")
	}
	marker := e.counters[0].Load()
	if !eventually(settleLimit, func() bool { return st.lastValue(0) > marker }) {
		t.Fatalf("the stream did not resume after a failed recreation: last delivered %d, node at %d, client %v %v, subscriptions %v, server %+v",
			st.lastValue(0), e.counters[0].Load(), c.State(), rec.snapshot(), c.SubscriptionIDs(), e.resources())
	}
	// It resumed without another connection loss.
	if n := countState(rec, opcua.Connected); n != 2 {
		t.Errorf("the client connected %d times, want 2: %v", n, rec.snapshot())
	}
	if err := st.sub.Cancel(ctx); err != nil {
		t.Errorf("cancel: %v", err)
	}
	closeClient(c, rec)
	st.close()
	rec.check(t, true)
}
