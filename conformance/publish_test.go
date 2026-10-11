// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// The tests in this file drive the Subscription and MonitoredItem service sets
// at protocol level: subscriptions are created with raw requests so the
// client's background publish loop stays idle and every Publish request and
// response is under the control of the test. That makes sequence numbers,
// acknowledgements, keep-alives and queue contents exactly assertable.

// rawSub is a subscription created through a raw CreateSubscription request.
type rawSub struct {
	t  *testing.T
	c  *opcua.Client
	id uint32
	// revised parameters
	interval  float64
	lifetime  uint32
	keepAlive uint32
}

// sendRaw sends req and returns the typed response.
func sendRaw[T any](t *testing.T, c *opcua.Client, req ua.Request) (*T, error) {
	t.Helper()
	var out *T
	err := c.Send(context.Background(), req, func(r ua.Response) error {
		// A ServiceFault is reported through the returned error.
		if v, ok := any(r).(*T); ok {
			out = v
		}
		return nil
	})
	return out, err
}

func mustSendRaw[T any](t *testing.T, c *opcua.Client, req ua.Request) *T {
	t.Helper()
	out, err := sendRaw[T](t, c, req)
	require.NoError(t, err)
	return out
}

type rawSubParams struct {
	interval   float64 // ms; 0 -> 10
	keepAlive  uint32  // 0 -> 1000 (no keep-alives during a test)
	lifetime   uint32  // 0 -> server maximum (the subscription never expires during a test)
	maxNotifs  uint32
	disabled   bool
	priorityHi bool
}

func newRawSub(t *testing.T, c *opcua.Client, p rawSubParams) *rawSub {
	t.Helper()
	if p.interval == 0 {
		p.interval = 10
	}
	if p.keepAlive == 0 {
		p.keepAlive = 1000
	}
	if p.lifetime == 0 {
		// The lifetime counts publishing cycles without a Publish request to
		// answer. These tests issue Publish requests one at a time, so on a
		// slow machine several 10ms cycles can pass between two of them; a
		// short lifetime would let the subscription expire mid-test.
		p.lifetime = 100_000
	}
	var prio uint8
	if p.priorityHi {
		prio = 200
	}
	res := mustSendRaw[ua.CreateSubscriptionResponse](t, c, &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: p.interval,
		RequestedLifetimeCount:      p.lifetime,
		RequestedMaxKeepAliveCount:  p.keepAlive,
		MaxNotificationsPerPublish:  p.maxNotifs,
		PublishingEnabled:           !p.disabled,
		Priority:                    prio,
	})
	require.NotZero(t, res.SubscriptionID)
	return &rawSub{
		t: t, c: c, id: res.SubscriptionID,
		interval: res.RevisedPublishingInterval, lifetime: res.RevisedLifetimeCount, keepAlive: res.RevisedMaxKeepAliveCount,
	}
}

// itemSpec describes one monitored item to create.
type itemSpec struct {
	node    *ua.NodeID
	attr    ua.AttributeID // 0 -> Value
	handle  uint32
	queue   uint32
	discard bool
	mode    ua.MonitoringMode // 0 (Disabled) must be requested via modeSet
	modeSet bool
	filter  *ua.ExtensionObject
	index   string
	// sampling is the requested sampling interval in ms (0 = fastest).
	sampling float64
}

func (s itemSpec) request() *ua.MonitoredItemCreateRequest {
	attr := s.attr
	if attr == 0 {
		attr = ua.AttributeIDValue
	}
	mode := ua.MonitoringModeReporting
	if s.modeSet {
		mode = s.mode
	}
	return &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:       s.node,
			AttributeID:  attr,
			IndexRange:   s.index,
			DataEncoding: &ua.QualifiedName{},
		},
		MonitoringMode: mode,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     s.handle,
			SamplingInterval: s.sampling,
			QueueSize:        s.queue,
			DiscardOldest:    s.discard,
			Filter:           s.filter,
		},
	}
}

func (r *rawSub) createItems(ts ua.TimestampsToReturn, specs ...itemSpec) []*ua.MonitoredItemCreateResult {
	r.t.Helper()
	req := &ua.CreateMonitoredItemsRequest{SubscriptionID: r.id, TimestampsToReturn: ts}
	for _, s := range specs {
		req.ItemsToCreate = append(req.ItemsToCreate, s.request())
	}
	res := mustSendRaw[ua.CreateMonitoredItemsResponse](r.t, r.c, req)
	require.Len(r.t, res.Results, len(specs))
	return res.Results
}

// mustCreateItems creates items and requires every one to succeed; it returns
// the server-assigned monitored item ids.
func (r *rawSub) mustCreateItems(ts ua.TimestampsToReturn, specs ...itemSpec) []uint32 {
	r.t.Helper()
	ids := make([]uint32, len(specs))
	for i, res := range r.createItems(ts, specs...) {
		require.Equal(r.t, ua.StatusOK, res.StatusCode, "item %d", i)
		require.NotZero(r.t, res.MonitoredItemID)
		ids[i] = res.MonitoredItemID
	}
	return ids
}

func (r *rawSub) setPublishing(enabled bool) {
	r.t.Helper()
	res := mustSendRaw[ua.SetPublishingModeResponse](r.t, r.c, &ua.SetPublishingModeRequest{
		PublishingEnabled: enabled,
		SubscriptionIDs:   []uint32{r.id},
	})
	require.Equal(r.t, []ua.StatusCode{ua.StatusOK}, res.Results)
}

func (r *rawSub) setMode(mode ua.MonitoringMode, itemIDs ...uint32) []ua.StatusCode {
	r.t.Helper()
	res := mustSendRaw[ua.SetMonitoringModeResponse](r.t, r.c, &ua.SetMonitoringModeRequest{
		SubscriptionID:   r.id,
		MonitoringMode:   mode,
		MonitoredItemIDs: itemIDs,
	})
	return res.Results
}

func ack(subID, seq uint32) *ua.SubscriptionAcknowledgement {
	return &ua.SubscriptionAcknowledgement{SubscriptionID: subID, SequenceNumber: seq}
}

// publish sends one Publish request and returns the response.
func publish(t *testing.T, c *opcua.Client, acks ...*ua.SubscriptionAcknowledgement) *ua.PublishResponse {
	t.Helper()
	if acks == nil {
		acks = []*ua.SubscriptionAcknowledgement{}
	}
	res := mustSendRaw[ua.PublishResponse](t, c, &ua.PublishRequest{SubscriptionAcknowledgements: acks})
	require.NotNil(t, res.NotificationMessage)
	return res
}

// isKeepAlive reports whether a Publish response carries no notifications.
func isKeepAlive(p *ua.PublishResponse) bool {
	return len(p.NotificationMessage.NotificationData) == 0
}

// dataOf flattens the data-change samples of a Publish response.
func dataOf(t *testing.T, p *ua.PublishResponse) []dataChange {
	t.Helper()
	var out []dataChange
	for _, eo := range p.NotificationMessage.NotificationData {
		dcn, ok := eo.Value.(*ua.DataChangeNotification)
		if !ok {
			continue
		}
		for _, it := range dcn.MonitoredItems {
			out = append(out, dataChange{handle: it.ClientHandle, dv: it.Value})
		}
	}
	return out
}

// eventsOf flattens the events of a Publish response.
func eventsOf(p *ua.PublishResponse) []*ua.EventFieldList {
	var out []*ua.EventFieldList
	for _, eo := range p.NotificationMessage.NotificationData {
		if enl, ok := eo.Value.(*ua.EventNotificationList); ok {
			out = append(out, enl.Events...)
		}
	}
	return out
}

// values extracts the Go values of a list of samples.
func values(samples []dataChange) []any {
	out := make([]any, len(samples))
	for i, s := range samples {
		out[i] = s.dv.Value.Value()
	}
	return out
}

func handles(samples []dataChange) []uint32 {
	out := make([]uint32, len(samples))
	for i, s := range samples {
		out[i] = s.handle
	}
	return out
}

func sorted(in []uint32) []uint32 {
	out := append([]uint32(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// primeItem consumes the initial-value notification of a freshly created
// single-item subscription, so later assertions start from an empty queue. It
// returns the Publish response that carried it.
func (r *rawSub) primeItem(want any) *ua.PublishResponse {
	r.t.Helper()
	p := publish(r.t, r.c)
	require.False(r.t, isKeepAlive(p), "expected the initial value, got a keep-alive")
	samples := dataOf(r.t, p)
	require.Len(r.t, samples, 1)
	require.Equal(r.t, want, samples[0].dv.Value.Value())
	return p
}

func rawSetup(t *testing.T) (*opcua.Client, *testutil.Fixture, string) {
	t.Helper()
	srv, url := newServer(t)
	f := testutil.AddFixture(t, srv)
	return newClient(t, url), f, url
}

// TestPublish_SequenceNumbersAcksAndRepublish walks through the life of the
// retransmission queue: sequence numbering, acknowledgement results, the
// available sequence numbers and Republish for present and absent messages.
func TestPublish_SequenceNumbersAcksAndRepublish(t *testing.T) {
	c, f, _ := rawSetup(t)
	ctx := context.Background()
	sub := newRawSub(t, c, rawSubParams{})
	sub.mustCreateItems(ua.TimestampsToReturnBoth, itemSpec{node: f.Int32, handle: 7, queue: 1, discard: true})

	// First notification: the initial value, sequence number 1.
	p1 := sub.primeItem(int32(42))
	require.Equal(t, sub.id, p1.SubscriptionID)
	require.Equal(t, uint32(1), p1.NotificationMessage.SequenceNumber)
	require.False(t, p1.MoreNotifications)
	require.Equal(t, []uint32{1}, p1.AvailableSequenceNumbers)
	require.Empty(t, p1.Results)
	require.Equal(t, []uint32{7}, handles(dataOf(t, p1)))
	require.WithinDuration(t, time.Now(), p1.NotificationMessage.PublishTime, time.Minute)

	// Acknowledge 1 while receiving 2.
	writeInt32(t, c, f.Int32, 43)
	p2 := publish(t, c, ack(sub.id, 1))
	require.Equal(t, uint32(2), p2.NotificationMessage.SequenceNumber)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, p2.Results)
	require.Equal(t, []uint32{2}, p2.AvailableSequenceNumbers)
	require.Equal(t, []any{int32(43)}, values(dataOf(t, p2)))

	// Bad acknowledgements: already acked, unknown subscription, never sent.
	writeInt32(t, c, f.Int32, 44)
	p3 := publish(t, c, ack(sub.id, 1), ack(sub.id+1000, 1), ack(sub.id, 77))
	require.Equal(t, uint32(3), p3.NotificationMessage.SequenceNumber)
	require.Equal(t, []ua.StatusCode{
		ua.StatusBadSequenceNumberUnknown,
		ua.StatusBadSubscriptionIDInvalid,
		ua.StatusBadSequenceNumberUnknown,
	}, p3.Results)
	require.Equal(t, []uint32{2, 3}, sorted(p3.AvailableSequenceNumbers))

	// Republish returns the unacknowledged message verbatim.
	rp, err := c.Republish(ctx, sub.id, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(2), rp.NotificationMessage.SequenceNumber)
	require.Len(t, rp.NotificationMessage.NotificationData, 1)
	dcn, ok := rp.NotificationMessage.NotificationData[0].Value.(*ua.DataChangeNotification)
	require.True(t, ok)
	require.Len(t, dcn.MonitoredItems, 1)
	require.Equal(t, uint32(7), dcn.MonitoredItems[0].ClientHandle)
	require.Equal(t, int32(43), dcn.MonitoredItems[0].Value.Value.Value())
	require.True(t, p2.NotificationMessage.PublishTime.Equal(rp.NotificationMessage.PublishTime))

	// Republish is idempotent: the message stays until acknowledged.
	rp, err = c.Republish(ctx, sub.id, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(2), rp.NotificationMessage.SequenceNumber)

	// Negative paths.
	_, err = c.Republish(ctx, sub.id, 1)
	require.ErrorIs(t, err, ua.StatusBadMessageNotAvailable, "acknowledged message")
	_, err = c.Republish(ctx, sub.id, 50)
	require.ErrorIs(t, err, ua.StatusBadMessageNotAvailable, "never-sent message")
	_, err = c.Republish(ctx, sub.id+1000, 1)
	require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)

	// Once acknowledged, 2 is gone too.
	writeInt32(t, c, f.Int32, 45)
	p4 := publish(t, c, ack(sub.id, 2), ack(sub.id, 3))
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, p4.Results)
	require.Equal(t, []uint32{4}, p4.AvailableSequenceNumbers)
	_, err = c.Republish(ctx, sub.id, 2)
	require.ErrorIs(t, err, ua.StatusBadMessageNotAvailable)
}

// TestPublish_RetransmissionQueueIsBounded verifies the server keeps only the
// most recent unacknowledged messages.
func TestPublish_RetransmissionQueueIsBounded(t *testing.T) {
	c, f, _ := rawSetup(t)
	ctx := context.Background()
	sub := newRawSub(t, c, rawSubParams{})
	sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 1, discard: true})
	sub.primeItem(int32(42)) // sequence number 1

	const total = 13 // server retains 10
	var last *ua.PublishResponse
	for seq := uint32(2); seq <= total; seq++ {
		writeInt32(t, c, f.Int32, int32(seq))
		last = publish(t, c) // never acknowledge
		require.Equal(t, seq, last.NotificationMessage.SequenceNumber)
	}
	require.Equal(t, []uint32{4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, sorted(last.AvailableSequenceNumbers))

	_, err := c.Republish(ctx, sub.id, 3)
	require.ErrorIs(t, err, ua.StatusBadMessageNotAvailable, "evicted message")
	rp, err := c.Republish(ctx, sub.id, 4)
	require.NoError(t, err)
	dcn := rp.NotificationMessage.NotificationData[0].Value.(*ua.DataChangeNotification)
	require.Equal(t, int32(4), dcn.MonitoredItems[0].Value.Value.Value())
}

// TestPublish_KeepAlive verifies keep-alive responses: no notification data and
// the sequence number of the next message, which is not consumed.
func TestPublish_KeepAlive(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{keepAlive: 1})

	for i := 0; i < 3; i++ {
		p := publish(t, c)
		require.True(t, isKeepAlive(p))
		require.Equal(t, sub.id, p.SubscriptionID)
		require.Equal(t, uint32(1), p.NotificationMessage.SequenceNumber, "keep-alive %d must not consume a sequence number", i)
		require.False(t, p.MoreNotifications)
		require.Empty(t, p.AvailableSequenceNumbers)
	}

	// The first real notification then takes sequence number 1 ...
	sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 1, discard: true})
	var data *ua.PublishResponse
	eventually(t, func() bool {
		data = publish(t, c)
		return !isKeepAlive(data)
	}, "initial value")
	require.Equal(t, uint32(1), data.NotificationMessage.SequenceNumber)
	require.Equal(t, []any{int32(42)}, values(dataOf(t, data)))

	// ... and the following keep-alive announces 2, acknowledging 1 on the way.
	ka := publish(t, c, ack(sub.id, 1))
	require.True(t, isKeepAlive(ka))
	require.Equal(t, uint32(2), ka.NotificationMessage.SequenceNumber)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, ka.Results)
	require.Empty(t, ka.AvailableSequenceNumbers)
}

// TestPublish_MaxNotificationsPerPublish verifies notifications are spread
// over several Publish responses with MoreNotifications set, in monitored-item
// creation order.
func TestPublish_MaxNotificationsPerPublish(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{maxNotifs: 2, disabled: true})

	nodes := []*ua.NodeID{f.Int16, f.Int32, f.Int64, f.Uint16, f.Uint32}
	specs := make([]itemSpec, len(nodes))
	for i, n := range nodes {
		specs[i] = itemSpec{node: n, handle: uint32(100 + i), queue: 1, discard: true}
	}
	sub.mustCreateItems(ua.TimestampsToReturnNeither, specs...)

	// A write is processed synchronously by the server, so after these every
	// item holds exactly its written value (queue size 1).
	ctx := context.Background()
	writes := []any{int16(1), int32(2), int64(3), uint16(4), uint32(5)}
	for i, n := range nodes {
		st, err := c.WriteNodeValue(ctx, n, writes[i])
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)
	}
	sub.setPublishing(true)

	p1 := publish(t, c)
	require.Equal(t, []uint32{100, 101}, handles(dataOf(t, p1)))
	require.Equal(t, []any{int16(1), int32(2)}, values(dataOf(t, p1)))
	require.True(t, p1.MoreNotifications)

	p2 := publish(t, c)
	require.Equal(t, []uint32{102, 103}, handles(dataOf(t, p2)))
	require.Equal(t, []any{int64(3), uint16(4)}, values(dataOf(t, p2)))
	require.True(t, p2.MoreNotifications)

	p3 := publish(t, c)
	require.Equal(t, []uint32{104}, handles(dataOf(t, p3)))
	require.Equal(t, []any{uint32(5)}, values(dataOf(t, p3)))
	require.False(t, p3.MoreNotifications)

	require.Equal(t, []uint32{1, 2, 3}, []uint32{
		p1.NotificationMessage.SequenceNumber, p2.NotificationMessage.SequenceNumber, p3.NotificationMessage.SequenceNumber})
}

// TestPublish_PublishingDisabled verifies a subscription with publishing
// disabled keeps sampling but only sends keep-alives until re-enabled.
func TestPublish_PublishingDisabled(t *testing.T) {
	c, f, url := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{keepAlive: 1})
	sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 1, discard: true})
	var p *ua.PublishResponse
	eventually(t, func() bool { p = publish(t, c); return !isKeepAlive(p) }, "initial value")
	require.Equal(t, []any{int32(42)}, values(dataOf(t, p)))

	sub.setPublishing(false)
	writeInt32(t, c, f.Int32, 99)
	for i := 0; i < 3; i++ {
		require.True(t, isKeepAlive(publish(t, c)), "publishing is disabled: only keep-alives expected")
	}

	sub.setPublishing(true)
	eventually(t, func() bool { p = publish(t, c); return !isKeepAlive(p) }, "queued value after re-enabling")
	require.Equal(t, []any{int32(99)}, values(dataOf(t, p)))

	// Per-subscription results, including foreign and unknown subscriptions.
	other := newRawSub(t, newClient(t, url), rawSubParams{})
	res := mustSendRaw[ua.SetPublishingModeResponse](t, c, &ua.SetPublishingModeRequest{
		PublishingEnabled: true,
		SubscriptionIDs:   []uint32{sub.id, other.id, other.id + 1000},
	})
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadSessionIDInvalid, ua.StatusBadSubscriptionIDInvalid}, res.Results)
}

// TestSubscription_ParameterRevision verifies how the server revises the
// requested subscription parameters on create and on modify.
func TestSubscription_ParameterRevision(t *testing.T) {
	c, _, _ := rawSetup(t)
	ctx := context.Background()

	cases := []struct {
		name                string
		params              opcua.SubscriptionParameters
		interval            time.Duration
		lifetime, keepAlive uint32
	}{
		{name: "InRangeKept",
			params:   opcua.SubscriptionParameters{Interval: 250 * time.Millisecond, LifetimeCount: 60, MaxKeepAliveCount: 20},
			interval: 250 * time.Millisecond, lifetime: 60, keepAlive: 20},
		{name: "IntervalRaisedToMinimum",
			params:   opcua.SubscriptionParameters{Interval: time.Millisecond, LifetimeCount: 60, MaxKeepAliveCount: 20},
			interval: 10 * time.Millisecond, lifetime: 60, keepAlive: 20},
		{name: "IntervalCappedAtMaximum",
			params:   opcua.SubscriptionParameters{Interval: 5 * time.Hour, LifetimeCount: 60, MaxKeepAliveCount: 20},
			interval: time.Hour, lifetime: 60, keepAlive: 20},
		{name: "LifetimeRaisedToThreeKeepAlives",
			params:   opcua.SubscriptionParameters{Interval: 100 * time.Millisecond, LifetimeCount: 4, MaxKeepAliveCount: 50},
			interval: 100 * time.Millisecond, lifetime: 150, keepAlive: 50},
		{name: "CountsCapped",
			params:   opcua.SubscriptionParameters{Interval: 100 * time.Millisecond, LifetimeCount: 4_000_000, MaxKeepAliveCount: 50_000},
			interval: 100 * time.Millisecond, lifetime: 100_000, keepAlive: 10_000},
		{name: "ClientDefaults",
			params:   opcua.SubscriptionParameters{},
			interval: opcua.DefaultSubscriptionInterval, lifetime: opcua.DefaultSubscriptionLifetimeCount, keepAlive: opcua.DefaultSubscriptionMaxKeepAliveCount},
	}
	for _, tc := range cases {
		t.Run("Create/"+tc.name, func(t *testing.T) {
			params := tc.params
			sub, err := c.Subscribe(ctx, &params, make(chan *opcua.PublishNotificationData, 4))
			require.NoError(t, err)
			defer func() { require.NoError(t, sub.Cancel(ctx)) }()
			require.Equal(t, tc.interval, sub.RevisedPublishingInterval)
			require.Equal(t, tc.lifetime, sub.RevisedLifetimeCount)
			require.Equal(t, tc.keepAlive, sub.RevisedMaxKeepAliveCount)
		})
	}

	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Hour}, make(chan *opcua.PublishNotificationData, 4))
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run("Modify/"+tc.name, func(t *testing.T) {
			resp, err := sub.ModifySubscription(ctx, tc.params)
			require.NoError(t, err)
			require.Equal(t, float64(tc.interval/time.Millisecond), resp.RevisedPublishingInterval)
			require.Equal(t, tc.lifetime, resp.RevisedLifetimeCount)
			require.Equal(t, tc.keepAlive, resp.RevisedMaxKeepAliveCount)
			// The client-side handle tracks the revised values.
			require.Equal(t, tc.interval, sub.RevisedPublishingInterval)
			require.Equal(t, tc.lifetime, sub.RevisedLifetimeCount)
			require.Equal(t, tc.keepAlive, sub.RevisedMaxKeepAliveCount)
		})
	}

	// The raw service also revises zero counts, which the client API never sends.
	raw := mustSendRaw[ua.CreateSubscriptionResponse](t, c, &ua.CreateSubscriptionRequest{PublishingEnabled: true})
	require.Equal(t, float64(10), raw.RevisedPublishingInterval)
	require.Equal(t, uint32(1), raw.RevisedMaxKeepAliveCount)
	require.Equal(t, uint32(3), raw.RevisedLifetimeCount)
}

// TestSubscription_ModifyTakesEffect verifies ModifySubscription changes the
// running publishing timer and is refused for unknown or foreign subscriptions.
func TestSubscription_ModifyTakesEffect(t *testing.T) {
	c, f, url := rawSetup(t)
	// One-hour publishing interval: nothing is ever published...
	sub := newRawSub(t, c, rawSubParams{interval: 3_600_000})
	require.Equal(t, float64(3_600_000), sub.interval)
	sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 1, discard: true})

	modify := func(cl *opcua.Client, id uint32) (*ua.ModifySubscriptionResponse, error) {
		return sendRaw[ua.ModifySubscriptionResponse](t, cl, &ua.ModifySubscriptionRequest{
			SubscriptionID:              id,
			RequestedPublishingInterval: 10,
			RequestedLifetimeCount:      3000,
			RequestedMaxKeepAliveCount:  1000,
		})
	}

	_, err := modify(c, sub.id+1000)
	require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)
	_, err = modify(newClient(t, url), sub.id)
	require.ErrorIs(t, err, ua.StatusBadSessionIDInvalid)

	// ...until the interval is modified down to 10ms.
	res, err := modify(c, sub.id)
	require.NoError(t, err)
	require.Equal(t, float64(10), res.RevisedPublishingInterval)
	sub.primeItem(int32(42))
}

// TestSubscription_IDsAreNotReused verifies deleting a subscription never makes
// the server hand out the id of one that is still alive.
func TestSubscription_IDsAreNotReused(t *testing.T) {
	c, f, _ := rawSetup(t)
	ctx := context.Background()

	newSub := func() (*opcua.Subscription, chan *opcua.PublishNotificationData) {
		ch := make(chan *opcua.PublishNotificationData, 64)
		sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
		require.NoError(t, err)
		return sub, ch
	}
	a, _ := newSub()
	b, bch := newSub()
	_, err := b.Monitor(ctx, ua.TimestampsToReturnNeither, opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, 5))
	require.NoError(t, err)
	awaitValue(t, bch, 5, int32(42))

	require.NoError(t, a.Cancel(ctx))
	eventually(t, func() bool {
		res, err := c.SetPublishingMode(ctx, true, a.SubscriptionID)
		return err == nil && res.Results[0] == ua.StatusBadSubscriptionIDInvalid
	}, "subscription a deleted on the server")

	// New subscriptions must get fresh ids, distinct from the surviving b.
	seen := map[uint32]bool{a.SubscriptionID: true, b.SubscriptionID: true}
	for i := 0; i < 3; i++ {
		s, _ := newSub()
		require.False(t, seen[s.SubscriptionID], "subscription id %d handed out twice", s.SubscriptionID)
		seen[s.SubscriptionID] = true
	}
	require.Contains(t, c.SubscriptionIDs(), b.SubscriptionID)

	// b is unharmed and still delivers.
	writeInt32(t, c, f.Int32, 314)
	awaitValue(t, bch, 5, int32(314))
}

// TestSubscription_LifetimeExpiry verifies a subscription that receives no
// Publish requests is deleted once its lifetime count is exhausted, while one
// that is being serviced survives.
func TestSubscription_LifetimeExpiry(t *testing.T) {
	c, _, url := rawSetup(t)
	ctx := context.Background()

	// Raw subscription, never published to: 10ms x small counts.
	orphan := newRawSub(t, c, rawSubParams{interval: 10, keepAlive: 1, lifetime: 3})
	require.Equal(t, uint32(3), orphan.lifetime)

	// A subscription with a one-second lifetime that is serviced by a client
	// publish loop.
	served := newClient(t, url)
	kept, err := served.Subscribe(ctx, &opcua.SubscriptionParameters{
		Interval: 10 * time.Millisecond, MaxKeepAliveCount: 1, LifetimeCount: 100,
	}, make(chan *opcua.PublishNotificationData, 64))
	require.NoError(t, err)
	require.Equal(t, uint32(100), kept.RevisedLifetimeCount)
	created := time.Now()

	eventually(t, func() bool {
		res, err := c.SetPublishingMode(ctx, true, orphan.id)
		return err == nil && res.Results[0] == ua.StatusBadSubscriptionIDInvalid
	}, "orphaned subscription expires")

	// Two lifetimes later the serviced subscription still exists: each
	// keep-alive it gets to send resets its lifetime counter.
	time.Sleep(time.Until(created.Add(2 * time.Second)))
	res, err := served.SetPublishingMode(ctx, true, kept.SubscriptionID)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res.Results)
}

// TestSubscription_DeleteStatuses covers DeleteSubscriptions result codes.
func TestSubscription_DeleteStatuses(t *testing.T) {
	c, f, url := rawSetup(t)
	mine := newRawSub(t, c, rawSubParams{})
	itemIDs := mine.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 1, queue: 1})
	foreign := newRawSub(t, newClient(t, url), rawSubParams{})

	res := mustSendRaw[ua.DeleteSubscriptionsResponse](t, c, &ua.DeleteSubscriptionsRequest{
		SubscriptionIDs: []uint32{mine.id, foreign.id, foreign.id + 1000},
	})
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadSessionIDInvalid, ua.StatusBadSubscriptionIDInvalid}, res.Results)

	// The subscription and its items disappear.
	eventually(t, func() bool {
		r := mustSendRaw[ua.SetPublishingModeResponse](t, c, &ua.SetPublishingModeRequest{SubscriptionIDs: []uint32{mine.id}})
		return r.Results[0] == ua.StatusBadSubscriptionIDInvalid
	}, "subscription deleted")
	eventually(t, func() bool {
		return mine.setMode(ua.MonitoringModeReporting, itemIDs...)[0] == ua.StatusBadMonitoredItemIDInvalid
	}, "monitored items deleted with their subscription")

	// Deleting again reports the subscription as unknown.
	res = mustSendRaw[ua.DeleteSubscriptionsResponse](t, c, &ua.DeleteSubscriptionsRequest{SubscriptionIDs: []uint32{mine.id}})
	require.Equal(t, []ua.StatusCode{ua.StatusBadSubscriptionIDInvalid}, res.Results)

	// Creating items on a deleted subscription is refused.
	_, err := sendRaw[ua.CreateMonitoredItemsResponse](t, c, &ua.CreateMonitoredItemsRequest{
		SubscriptionID:     mine.id,
		TimestampsToReturn: ua.TimestampsToReturnNeither,
		ItemsToCreate:      []*ua.MonitoredItemCreateRequest{itemSpec{node: f.Int32, handle: 1}.request()},
	})
	require.ErrorIs(t, err, ua.StatusBadSubscriptionIDInvalid)
}

// TestSubscription_TransferBetweenSessions moves a subscription to another
// session and verifies ownership and delivery follow it.
func TestSubscription_TransferBetweenSessions(t *testing.T) {
	c1, f, url := rawSetup(t)
	c2 := newClient(t, url)
	ctx := context.Background()

	sub := newRawSub(t, c1, rawSubParams{})
	sub.mustCreateItems(ua.TimestampsToReturnNeither, itemSpec{node: f.Int32, handle: 9, queue: 1, discard: true})
	sub.primeItem(int32(42)) // sequence 1, left unacknowledged

	resp, err := c2.TransferSubscriptions(ctx, []uint32{sub.id, sub.id + 1000}, false)
	require.NoError(t, err)
	require.Len(t, resp.Results, 2)
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	require.Equal(t, []uint32{1}, resp.Results[0].AvailableSequenceNumbers)
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, resp.Results[1].StatusCode)

	// Ownership moved: the old session is refused, the new one accepted.
	old := mustSendRaw[ua.SetPublishingModeResponse](t, c1, &ua.SetPublishingModeRequest{PublishingEnabled: true, SubscriptionIDs: []uint32{sub.id}})
	require.Equal(t, []ua.StatusCode{ua.StatusBadSessionIDInvalid}, old.Results)
	cur := mustSendRaw[ua.SetPublishingModeResponse](t, c2, &ua.SetPublishingModeRequest{PublishingEnabled: true, SubscriptionIDs: []uint32{sub.id}})
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, cur.Results)

	// The unacknowledged message can be recovered through the new session.
	rp, err := c2.Republish(ctx, sub.id, 1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), rp.NotificationMessage.SequenceNumber)

	// New notifications are delivered to the new session's Publish requests,
	// continuing the sequence.
	writeInt32(t, c1, f.Int32, 555)
	p := publish(t, c2, ack(sub.id, 1))
	require.Equal(t, sub.id, p.SubscriptionID)
	require.Equal(t, uint32(2), p.NotificationMessage.SequenceNumber)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, p.Results)
	require.Equal(t, []uint32{9}, handles(dataOf(t, p)))
	require.Equal(t, []any{int32(555)}, values(dataOf(t, p)))

	// Transferring nothing but unknown ids yields per-id errors, not a fault.
	resp, err = c2.TransferSubscriptions(ctx, []uint32{4_000_000}, true)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, resp.Results[0].StatusCode)
}

// TestSubscription_MultiplePerSession verifies several subscriptions in one
// session are serviced independently by the same stream of Publish requests.
func TestSubscription_MultiplePerSession(t *testing.T) {
	c, f, _ := rawSetup(t)
	ctx := context.Background()

	type entry struct {
		sub  *opcua.Subscription
		ch   chan *opcua.PublishNotificationData
		node *ua.NodeID
	}
	nodes := []*ua.NodeID{f.Int16, f.Int32, f.Int64, f.Uint16, f.Uint32, f.Uint64}
	initial := []any{int16(-1234), int32(42), int64(-9_000_000_000), uint16(4321), uint32(4242), uint64(9_000_000_000)}
	updated := []any{int16(1), int32(2), int64(3), uint16(4), uint32(5), uint64(6)}

	subs := make([]entry, len(nodes))
	for i, n := range nodes {
		ch := make(chan *opcua.PublishNotificationData, 64)
		sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, ch)
		require.NoError(t, err)
		_, err = sub.Monitor(ctx, ua.TimestampsToReturnNeither, opcua.NewMonitoredItemCreateRequestWithDefaults(n, ua.AttributeIDValue, uint32(i)))
		require.NoError(t, err)
		subs[i] = entry{sub, ch, n}
	}
	ids := map[uint32]bool{}
	for _, e := range subs {
		ids[e.sub.SubscriptionID] = true
	}
	require.Len(t, ids, len(subs), "subscription ids must be distinct")
	require.ElementsMatch(t, func() []uint32 {
		var out []uint32
		for id := range ids {
			out = append(out, id)
		}
		return out
	}(), c.SubscriptionIDs())

	for i, e := range subs {
		awaitValue(t, e.ch, uint32(i), initial[i])
	}
	for i, e := range subs {
		st, err := c.WriteNodeValue(ctx, e.node, updated[i])
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, st)
	}
	for i, e := range subs {
		// Each channel only ever sees its own subscription's handle.
		dv := awaitValue(t, e.ch, uint32(i), updated[i])
		require.NotNil(t, dv)
	}

	// Cancelling half leaves the others running.
	for i := 0; i < len(subs); i += 2 {
		require.NoError(t, subs[i].sub.Cancel(ctx))
	}
	require.Len(t, c.SubscriptionIDs(), len(subs)/2)
	st, err := c.WriteNodeValue(ctx, subs[1].node, int32(777))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, st)
	awaitValue(t, subs[1].ch, 1, int32(777))
}

// TestPublish_NoSubscription verifies a Publish request on a session without
// subscriptions is answered immediately with BadNoSubscription instead of
// being parked forever.
func TestPublish_NoSubscription(t *testing.T) {
	c, _, _ := rawSetup(t)

	_, err := sendRaw[ua.PublishResponse](t, c, &ua.PublishRequest{SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{}})
	require.ErrorIs(t, err, ua.StatusBadNoSubscription)

	// With a subscription the request is served...
	sub := newRawSub(t, c, rawSubParams{keepAlive: 1})
	require.True(t, isKeepAlive(publish(t, c)))

	// ...and once it is deleted the session is back to BadNoSubscription.
	res := mustSendRaw[ua.DeleteSubscriptionsResponse](t, c, &ua.DeleteSubscriptionsRequest{SubscriptionIDs: []uint32{sub.id}})
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res.Results)
	eventually(t, func() bool {
		r := mustSendRaw[ua.SetPublishingModeResponse](t, c, &ua.SetPublishingModeRequest{SubscriptionIDs: []uint32{sub.id}})
		return r.Results[0] == ua.StatusBadSubscriptionIDInvalid
	}, "subscription deleted")
	_, err = sendRaw[ua.PublishResponse](t, c, &ua.PublishRequest{SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{}})
	require.ErrorIs(t, err, ua.StatusBadNoSubscription)
}

// TestPublish_TooManyPublishRequests verifies the server refuses Publish
// requests beyond its per-session queue instead of dropping them silently.
func TestPublish_TooManyPublishRequests(t *testing.T) {
	c, _, _ := rawSetup(t)
	// An idle subscription that will not answer any Publish during the test.
	newRawSub(t, c, rawSubParams{interval: 3_600_000})

	const queueSize, extra = 100, 15
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, queueSize+extra)
	for i := 0; i < queueSize+extra; i++ {
		go func() {
			results <- c.Send(ctx, &ua.PublishRequest{SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{}}, func(ua.Response) error { return nil })
		}()
	}

	// Exactly the requests that do not fit are refused; the others stay parked.
	for i := 0; i < extra; i++ {
		select {
		case err := <-results:
			require.ErrorIs(t, err, ua.StatusBadTooManyPublishRequests)
		case <-time.After(waitTimeout):
			t.Fatalf("only %d of %d surplus Publish requests were refused", i, extra)
		}
	}
	select {
	case err := <-results:
		t.Fatalf("a queued Publish request completed unexpectedly: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	// Release the parked requests.
	cancel()
	for i := 0; i < queueSize; i++ {
		select {
		case err := <-results:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(waitTimeout):
			t.Fatal("parked Publish requests were not released")
		}
	}
}

// TestSubscription_CreateAndCancelNeverBlock verifies that creating and
// cancelling subscriptions does not stall behind the client's outstanding
// Publish request when no notifications are flowing.
func TestSubscription_CreateAndCancelNeverBlock(t *testing.T) {
	c, _, _ := rawSetup(t)
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		// Idle subscriptions: with the default keep-alive nothing is published
		// for a long time, so the publish loop sits in one Publish request.
		var subs []*opcua.Subscription
		for i := 0; i < 8; i++ {
			sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, make(chan *opcua.PublishNotificationData, 4))
			if err != nil {
				done <- err
				return
			}
			subs = append(subs, sub)
		}
		for _, sub := range subs {
			if err := sub.Cancel(ctx); err != nil {
				done <- err
				return
			}
		}
		// Repeated create/cancel cycles down to zero subscriptions.
		for i := 0; i < 8; i++ {
			sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, make(chan *opcua.PublishNotificationData, 4))
			if err != nil {
				done <- err
				return
			}
			if err := sub.Cancel(ctx); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(waitTimeout):
		t.Fatal("Subscribe/Cancel blocked behind the outstanding Publish request")
	}
	require.Empty(t, c.SubscriptionIDs())

	// The publish loop still works afterwards.
	f2 := c.Node(ua.NewNumericNodeID(0, 2258)) // Server_ServerStatus_CurrentTime
	sub, ch, err := c.NewSubscription().Interval(fastInterval).Monitor(f2.ID).Start(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, sub.Cancel(ctx)) }()
	samples := nextDataChanges(t, ch)
	require.Len(t, samples, 1)
	_, isTime := samples[0].dv.Value.Value().(time.Time)
	require.True(t, isTime, "got %T", samples[0].dv.Value.Value())
}
