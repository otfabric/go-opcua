// SPDX-License-Identifier: MIT

package monitor

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// errorCollector records the asynchronous errors of a NodeMonitor.
type errorCollector struct {
	mu   sync.Mutex
	errs []error
}

func (c *errorCollector) handle(_ *opcua.Client, _ *Subscription, err error) {
	c.mu.Lock()
	c.errs = append(c.errs, err)
	c.mu.Unlock()
}

func (c *errorCollector) wait(t *testing.T, target error) {
	t.Helper()
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, e := range c.errs {
			if stderrors.Is(e, target) {
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond, "no error %v", target)
}

// pumpSub returns a subscription that is not connected to a server, for
// driving pump with hand-made notifications.
func pumpSub(t *testing.T, buf int) (*Subscription, *errorCollector) {
	t.Helper()
	c, err := opcua.NewClient("opc.tcp://localhost:4840")
	require.NoError(t, err)
	m, err := NewNodeMonitor(c)
	require.NoError(t, err)
	col := &errorCollector{}
	m.SetErrorHandler(col.handle)
	s := &Subscription{
		monitor:          m,
		sub:              &opcua.Subscription{SubscriptionID: 7},
		closed:           make(chan struct{}),
		internalNotifyCh: make(chan *opcua.PublishNotificationData, buf),
		handles:          map[uint32]*ua.NodeID{1: ua.NewNumericNodeID(0, 2258)},
		itemLookup:       map[uint32]Item{},
	}
	return s, col
}

func dataChange(subID uint32, handles ...uint32) *opcua.PublishNotificationData {
	items := make([]*ua.MonitoredItemNotification, len(handles))
	for i, h := range handles {
		items[i] = &ua.MonitoredItemNotification{ClientHandle: h, Value: &ua.DataValue{Value: ua.MustVariant(int32(h))}}
	}
	return &opcua.PublishNotificationData{SubscriptionID: subID, Value: &ua.DataChangeNotification{MonitoredItems: items}}
}

func TestPumpErrors(t *testing.T) {
	s, col := pumpSub(t, 4)
	out := make(chan *DataChangeMessage, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.pump(ctx, out, nil); close(done) }()

	// A Publish error is reported, not delivered.
	s.internalNotifyCh <- &opcua.PublishNotificationData{Error: ua.StatusBadTimeout}
	col.wait(t, ua.StatusBadTimeout)

	// A notification of another subscription.
	s.internalNotifyCh <- dataChange(8, 1)
	col.wait(t, errors.ErrInvalidSubscriptionID)

	// A notification type the monitor does not handle.
	s.internalNotifyCh <- &opcua.PublishNotificationData{SubscriptionID: 7, Value: &ua.EventNotificationList{}}
	col.wait(t, errors.ErrInvalidResponseType)

	// An unknown client handle is delivered with an error.
	s.internalNotifyCh <- dataChange(7, 99)
	msg := <-out
	require.ErrorIs(t, msg.Error, errors.ErrMonitoredItemNotFound)

	// A full output channel drops the message and reports a slow consumer.
	s.internalNotifyCh <- dataChange(7, 1, 1)
	col.wait(t, ErrSlowConsumer)
	require.Eventually(t, func() bool { return s.Dropped() == 1 }, 5*time.Second, time.Millisecond)
	msg = <-out
	require.NoError(t, msg.Error)
	require.Equal(t, int32(1), msg.Value.Value())

	cancel()
	<-done
}

func TestPumpCallbackAndClose(t *testing.T) {
	s, col := pumpSub(t, 1)
	got := make(chan *DataChangeMessage, 4)
	done := make(chan struct{})
	go func() {
		s.pump(context.Background(), nil, func(_ *Subscription, m *DataChangeMessage) { got <- m })
		close(done)
	}()
	s.internalNotifyCh <- dataChange(7, 1)
	require.NoError(t, (<-got).Error)
	require.Eventually(t, func() bool { return s.Delivered() == 1 }, 5*time.Second, time.Millisecond)
	_ = col

	// Closing the subscription ends the pump.
	close(s.closed)
	<-done
}

func TestPumpWithoutConsumer(t *testing.T) {
	s, col := pumpSub(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.pump(ctx, nil, nil)
	s.internalNotifyCh <- dataChange(7, 1)
	col.wait(t, errNoConsumerForTest(t, col))
}

// errNoConsumerForTest waits for the internal "neither channel nor callback"
// error and returns it, so that wait can match it.
func errNoConsumerForTest(t *testing.T, col *errorCollector) error {
	t.Helper()
	var found error
	require.Eventually(t, func() bool {
		col.mu.Lock()
		defer col.mu.Unlock()
		for _, e := range col.errs {
			if e != nil && e.Error() == "monitor: internal error: neither channel nor callback is set" {
				found = e
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond)
	return found
}

func TestSubscribeErrors(t *testing.T) {
	// The client is not connected: the subscription cannot be created.
	c, err := opcua.NewClient("opc.tcp://localhost:4840")
	require.NoError(t, err)
	m, err := NewNodeMonitor(c)
	require.NoError(t, err)
	ctx := context.Background()
	_, err = m.Subscribe(ctx, nil, func(*Subscription, *DataChangeMessage) {})
	require.Error(t, err)
	_, err = m.ChanSubscribe(ctx, nil, make(chan *DataChangeMessage))
	require.Error(t, err)

	// Malformed NodeIds are refused before anything is sent.
	s, _ := pumpSub(t, 1)
	require.Error(t, s.AddNodes(ctx, "ns=x;i=1"))
	require.Error(t, s.RemoveNodes(ctx, "ns=x;i=1"))
	require.Error(t, s.SetMonitoringModeForNodes(ctx, ua.MonitoringModeDisabled, "ns=x;i=1"))

	// Nothing to do.
	require.NoError(t, s.RemoveNodeIDs(ctx))
	require.NoError(t, s.SetMonitoringModeForNodeIDs(ctx, ua.MonitoringModeDisabled))
}

// TestServiceFailureKeepsState checks that a failed service call leaves the
// subscription's bookkeeping as it was: AddMonitorItems registers no
// handles, RemoveMonitorItems forgets nothing (regressions: both changed
// their state before the call).
func TestServiceFailureKeepsState(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	f := testutil.AddFixture(t, srv)
	c := testutil.NewTestClient(t, url)
	ctx := context.Background()
	m, err := NewNodeMonitor(c)
	require.NoError(t, err)
	sub, err := m.ChanSubscribe(ctx, nil, make(chan *DataChangeMessage, 8))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Unsubscribe(ctx) })
	items, err := sub.AddMonitorItems(ctx, Request{NodeID: f.Int32}, Request{NodeID: f.Double})
	require.NoError(t, err)
	require.Equal(t, 2, sub.Subscribed())

	// Per-item failures: an id the server does not know.
	bogus := Item{id: 999999, nodeID: f.Int32, handle: 4242}
	require.Error(t, sub.SetMonitoringMode(ctx, ua.MonitoringModeDisabled, bogus), "an id the client does not know")
	require.ErrorIs(t, sub.RemoveMonitorItems(ctx, bogus), errors.ErrMonitoredItemNotFound, "unknown locally")
	require.ErrorIs(t, sub.ModifyMonitorItems(ctx, Request{NodeID: f.String, MonitoringParameters: &ua.MonitoringParameters{}}), errors.ErrMonitoredItemNotFound, "a node that is not monitored")

	sub.mu.RLock()
	handles := len(sub.handles)
	sub.mu.RUnlock()

	require.NoError(t, c.Close(ctx))
	_, err = sub.AddMonitorItems(ctx, Request{NodeID: f.String})
	require.Error(t, err)
	require.Error(t, sub.RemoveMonitorItems(ctx, items...))

	sub.mu.RLock()
	defer sub.mu.RUnlock()
	require.Len(t, sub.handles, handles, "no handle left behind by the failed AddMonitorItems")
	require.Len(t, sub.itemLookup, 2, "the items whose removal failed are still known")
}
