//go:build interop

// SPDX-License-Identifier: MIT

// Peer evidence for data-change filtering and sampling.
// COVERAGE.md: subscriptions / monitoreditem.deadband, monitoreditem.trigger,
// monitoreditem.sampling-interval
//
// Go client → peer server: the peers filter Dynamic.Ramp (Double, +1.0 every
// 100 ms, reset at 100) and Dynamic.Counter as the go-opcua client asks.
// Peer client → Go server: the go-opcua server filters and samples as the
// peer client asks. The deadband/trigger half of that direction needs the
// adapter's "deadband" client feature and is skipped on images without it.

package interop

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// ---------------------------------------------------------------------------
// Go client → peer server
// ---------------------------------------------------------------------------

// Client handles of the items of assertPeerDataChangeFilter.
const (
	dcRef            = iota // Ramp, no filter: the reference stream
	dcDeadbandSV            // Ramp, StatusValue + absolute deadband 10
	dcDeadbandSVT           // Ramp, StatusValueTimestamp + absolute deadband 10
	dcDeadbandStatus        // Ramp, Status + absolute deadband 10
	dcDeadbandHuge          // Ramp, StatusValue + absolute deadband 1000
	dcStatus                // Ramp, Status
	dcSVT                   // Ramp, StatusValueTimestamp
	dcCounterSV             // Counter, StatusValue
	dcStaticSV              // Scalar.Int32 (never changes), StatusValue
	dcSlow                  // Ramp, no filter, sampling interval 1 s
	dcItems
)

// peerDataChangeRun is what one subscription against a peer delivered.
type peerDataChangeRun struct {
	samples [dcItems][]*ua.DataValue
	elapsed time.Duration
	revised [dcItems]float64
}

func (r *peerDataChangeRun) floats(h int) []float64 {
	out := make([]float64, 0, len(r.samples[h]))
	for _, dv := range r.samples[h] {
		if dv != nil && dv.Value != nil {
			out = append(out, dv.Value.Float())
		}
	}
	return out
}

// collectPeerDataChanges monitors the fixture's dynamic nodes with every
// filter under test in one subscription and collects until the unfiltered
// reference item has delivered refSamples samples. The reference stream is
// the clock of the test: "the ramp moved this much and the filtered item
// still reported nothing" needs no sleep.
func collectPeerDataChanges(t *testing.T, endpoint string, refSamples int) *peerDataChangeRun {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	ramp := ua.NewStringNodeID(nsIdx, "Dynamic.Ramp")
	counter := ua.NewStringNodeID(nsIdx, "Dynamic.Counter")
	static := ua.NewStringNodeID(nsIdx, "Scalar.Int32")

	item := func(node *ua.NodeID, handle uint32, filter *ua.ExtensionObject) *ua.MonitoredItemCreateRequest {
		req := opcua.NewMonitoredItemCreateRequestWithDefaults(node, ua.AttributeIDValue, handle)
		req.RequestedParameters.QueueSize = 100
		req.RequestedParameters.SamplingInterval = 50
		req.RequestedParameters.Filter = filter
		return req
	}
	abs := func(trigger ua.DataChangeTrigger, v float64) *ua.ExtensionObject {
		return opcua.NewDataChangeFilter(trigger, ua.DeadbandTypeAbsolute, v)
	}
	trig := func(trigger ua.DataChangeTrigger) *ua.ExtensionObject {
		return opcua.NewDataChangeFilter(trigger, ua.DeadbandTypeNone, 0)
	}
	reqs := make([]*ua.MonitoredItemCreateRequest, dcItems)
	reqs[dcRef] = item(ramp, dcRef, nil)
	reqs[dcDeadbandSV] = item(ramp, dcDeadbandSV, abs(ua.DataChangeTriggerStatusValue, 10))
	reqs[dcDeadbandSVT] = item(ramp, dcDeadbandSVT, abs(ua.DataChangeTriggerStatusValueTimestamp, 10))
	reqs[dcDeadbandStatus] = item(ramp, dcDeadbandStatus, abs(ua.DataChangeTriggerStatus, 10))
	reqs[dcDeadbandHuge] = item(ramp, dcDeadbandHuge, abs(ua.DataChangeTriggerStatusValue, 1000))
	reqs[dcStatus] = item(ramp, dcStatus, trig(ua.DataChangeTriggerStatus))
	reqs[dcSVT] = item(ramp, dcSVT, trig(ua.DataChangeTriggerStatusValueTimestamp))
	reqs[dcCounterSV] = item(counter, dcCounterSV, trig(ua.DataChangeTriggerStatusValue))
	reqs[dcStaticSV] = item(static, dcStaticSV, trig(ua.DataChangeTriggerStatusValue))
	reqs[dcSlow] = item(ramp, dcSlow, nil)
	reqs[dcSlow].RequestedParameters.SamplingInterval = 1000

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	notifyCh := make(chan *opcua.PublishNotificationData, 256)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 100 * time.Millisecond}, notifyCh)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Cancel(ctx) }()

	run := &peerDataChangeRun{}
	start := time.Now()
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, reqs...)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	for i, r := range res.Results {
		if r.StatusCode != ua.StatusOK {
			t.Fatalf("item %d: peer rejected the monitored item: %v", i, r.StatusCode)
		}
		run.revised[i] = r.RevisedSamplingInterval
	}

	for len(run.samples[dcRef]) < refSamples {
		select {
		case msg := <-notifyCh:
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, mi := range dcn.MonitoredItems {
				if mi.ClientHandle < dcItems {
					run.samples[mi.ClientHandle] = append(run.samples[mi.ClientHandle], mi.Value)
				}
			}
		case <-ctx.Done():
			t.Fatalf("timed out with %d of %d reference samples", len(run.samples[dcRef]), refSamples)
		}
	}
	run.elapsed = time.Since(start)
	return run
}

// rampStep is the distance between two ramp values; a reset from the top of
// the ramp to 0 counts as a large step.
func rampStep(a, b float64) float64 { return math.Abs(b - a) }

// assertPeerDataChangeFilter is the Go client → peer server check shared by
// both peers.
func assertPeerDataChangeFilter(t *testing.T, endpoint, direction string) {
	t.Helper()
	// 45 reference samples: the ramp advanced by about 45, so a deadband of
	// 10 was exceeded about four times.
	run := collectPeerDataChanges(t, endpoint, 45)
	ref := run.floats(dcRef)
	t.Logf("%s: %d reference samples in %s", direction, len(ref), run.elapsed.Round(time.Millisecond))

	// The reference stream itself moves in small steps: whatever is missing
	// from a filtered stream was removed by the filter.
	small := 0
	for i := 1; i < len(ref); i++ {
		if rampStep(ref[i-1], ref[i]) <= 10 {
			small++
		}
	}
	if small < len(ref)/2 {
		t.Fatalf("reference stream is not a ramp of small steps: %v", ref)
	}

	t.Run("coverage/monitoreditem.deadband/"+direction, func(t *testing.T) {
		for _, h := range []int{dcDeadbandSV, dcDeadbandSVT} {
			vals := run.floats(h)
			t.Logf("handle %d (absolute deadband 10): %v", h, vals)
			// Positive: changes beyond the deadband are reported.
			if len(vals) < 3 {
				t.Errorf("handle %d: want the initial value and at least 2 changes, got %v", h, vals)
			}
			// Negative: nothing within the deadband is.
			for i := 1; i < len(vals); i++ {
				if rampStep(vals[i-1], vals[i]) <= 10 {
					t.Errorf("handle %d: step %v -> %v is within the deadband", h, vals[i-1], vals[i])
				}
			}
			if len(vals)*3 > len(ref) {
				t.Errorf("handle %d: %d samples against %d unfiltered: not filtered", h, len(vals), len(ref))
			}
		}
		// A deadband wider than the ramp: only the initial value.
		if n := len(run.samples[dcDeadbandHuge]); n != 1 {
			t.Errorf("deadband 1000: want only the initial value, got %d samples: %v", n, run.floats(dcDeadbandHuge))
		}
	})

	t.Run("coverage/monitoreditem.trigger/"+direction, func(t *testing.T) {
		// Status: the ramp's status never changes, with or without deadband.
		for _, h := range []int{dcStatus, dcDeadbandStatus} {
			if n := len(run.samples[h]); n != 1 {
				t.Errorf("handle %d (Status trigger): want only the initial value, got %d samples: %v", h, n, run.floats(h))
			}
		}
		// StatusValue: value changes are reported, in order...
		counter := run.samples[dcCounterSV]
		if len(counter) < 3 {
			t.Errorf("StatusValue on Counter: want at least 3 samples, got %d", len(counter))
		}
		for i := 1; i < len(counter); i++ {
			if counter[i].Value.Int() <= counter[i-1].Value.Int() {
				t.Errorf("StatusValue on Counter: not increasing at %d: %v -> %v", i, counter[i-1].Value.Value(), counter[i].Value.Value())
			}
		}
		// ...and an unchanged value is not.
		if n := len(run.samples[dcStaticSV]); n != 1 {
			t.Errorf("StatusValue on a static node: want only the initial value, got %d samples", n)
		}
		// StatusValueTimestamp: every step of the ramp.
		if n := len(run.samples[dcSVT]); n*2 < len(ref) {
			t.Errorf("StatusValueTimestamp on Ramp: %d samples against %d unfiltered", n, len(ref))
		}
	})

	t.Run("coverage/monitoreditem.sampling-interval/"+direction, func(t *testing.T) {
		slow := run.floats(dcSlow)
		t.Logf("sampling interval 1000 ms (revised %v ms): %v", run.revised[dcSlow], slow)
		if run.revised[dcSlow] < 500 {
			t.Errorf("revised sampling interval %v ms for a request of 1000 ms", run.revised[dcSlow])
		}
		// One sample per second at most, however slow the machine: bounded
		// by the time that passed. And clearly fewer than the 50 ms item.
		if limit := int(run.elapsed/time.Second) + 2; len(slow) > limit {
			t.Errorf("%d samples in %s with a 1 s sampling interval", len(slow), run.elapsed)
		}
		if len(slow) < 2 {
			t.Errorf("want at least 2 samples, got %v", slow)
		}
		if len(slow)*3 > len(ref) {
			t.Errorf("%d samples against %d at 50 ms: not throttled", len(slow), len(ref))
		}
	})
}

// assertPeerPercentDeadband is the Go client → peer server check of the
// PercentDeadband (Part 8 §7.2) on the fixture's AnalogItem Analog.Level: a
// Double ramp 0..100 in steps of 2 every 100 ms with EURange [0, 100], so a
// deadband of 10 % is an absolute change of 10.
func assertPeerPercentDeadband(t *testing.T, endpoint string) {
	t.Helper()
	c := dialClient(t, endpoint)
	_, nsIdx := findNS(t, c)
	level := ua.NewStringNodeID(nsIdx, "Analog.Level")
	ramp := ua.NewStringNodeID(nsIdx, "Dynamic.Ramp")

	const hRef, hTen, hFull, hNoRange = 0, 1, 2, 3
	item := func(node *ua.NodeID, handle uint32, percent float64) *ua.MonitoredItemCreateRequest {
		req := opcua.NewMonitoredItemCreateRequestWithDefaults(node, ua.AttributeIDValue, handle)
		req.RequestedParameters.QueueSize = 100
		req.RequestedParameters.SamplingInterval = 50
		if percent >= 0 {
			req.RequestedParameters.Filter = opcua.NewDataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypePercent, percent)
		}
		return req
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	notifyCh := make(chan *opcua.PublishNotificationData, 256)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 100 * time.Millisecond}, notifyCh)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Cancel(ctx) }()

	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		item(level, hRef, -1),
		item(level, hTen, 10),
		item(level, hFull, 100),
		// Dynamic.Ramp is a plain variable without EURange.
		item(ramp, hNoRange, 10),
	)
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if len(res.Results) != 4 {
		t.Fatalf("Monitor: %d results for 4 items", len(res.Results))
	}
	for _, h := range []int{hRef, hTen, hFull} {
		if st := res.Results[h].StatusCode; st != ua.StatusOK {
			t.Fatalf("item %d on Analog.Level: peer rejected the monitored item: %v", h, st)
		}
	}
	// Negative: a PercentDeadband needs an EURange. Part 4 names
	// Bad_MonitoredItemFilterUnsupported; Bad_FilterNotAllowed is the status
	// open62541 uses for a node that is not an AnalogItem.
	switch st := res.Results[hNoRange].StatusCode; st {
	case ua.StatusBadMonitoredItemFilterUnsupported, ua.StatusBadFilterNotAllowed, ua.StatusBadDeadbandFilterInvalid:
		t.Logf("percent deadband on a variable without EURange: %v", st)
	default:
		t.Errorf("percent deadband on a variable without EURange: got %v, want the item rejected", st)
	}

	var samples [3][]float64
	// 60 reference samples: more than one full sweep of the ramp (51 steps).
	for len(samples[hRef]) < 60 {
		select {
		case msg := <-notifyCh:
			if msg.Error != nil {
				t.Fatalf("notification error: %v", msg.Error)
			}
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, mi := range dcn.MonitoredItems {
				if mi.ClientHandle < 3 && mi.Value != nil && mi.Value.Value != nil {
					samples[mi.ClientHandle] = append(samples[mi.ClientHandle], mi.Value.Value.Float())
				}
			}
		case <-ctx.Done():
			t.Fatalf("timed out with %d of 60 reference samples", len(samples[hRef]))
		}
	}
	ref, ten, full := samples[hRef], samples[hTen], samples[hFull]
	t.Logf("reference: %d samples; 10 %%: %v; 100 %%: %v", len(ref), ten, full)

	// Positive: changes beyond 10 % of the range are reported.
	if len(ten) < 4 {
		t.Errorf("10 %% deadband: want the initial value and at least 3 changes, got %v", ten)
	}
	// Negative: nothing within it is.
	for i := 1; i < len(ten); i++ {
		if rampStep(ten[i-1], ten[i]) <= 10 {
			t.Errorf("10 %% deadband: step %v -> %v is within the deadband", ten[i-1], ten[i])
		}
	}
	if len(ten)*3 > len(ref) {
		t.Errorf("10 %% deadband: %d samples against %d unfiltered: not filtered", len(ten), len(ref))
	}
	// 100 % of the range is never exceeded by a value inside the range, the
	// reset from 100 to 0 included.
	if len(full) != 1 {
		t.Errorf("100 %% deadband: want only the initial value, got %v", full)
	}
}

func TestOpen62541Server_DataChangeFilter(t *testing.T) {
	h := startOpen62541Server(t)
	assertPeerDataChangeFilter(t, h.endpoint, "go-client-to-open62541-server")
	t.Run("coverage/monitoreditem.percent-deadband/go-client-to-open62541-server", func(t *testing.T) {
		requireServerFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "percent-deadband")
		assertPeerPercentDeadband(t, h.endpoint)
	})
}

func TestMiloServer_DataChangeFilter(t *testing.T) {
	h := startMiloServer(t)
	assertPeerDataChangeFilter(t, h.endpoint, "go-client-to-milo-server")
	t.Run("coverage/monitoreditem.percent-deadband/go-client-to-milo-server", func(t *testing.T) {
		requireServerFeature(t, "MILO_IMAGE", defaultMiloImage, "percent-deadband")
		assertPeerPercentDeadband(t, h.endpoint)
	})
}

// ---------------------------------------------------------------------------
// Peer client → Go server
// ---------------------------------------------------------------------------

// adapterRun is runOpen62541Client / runMiloClient and friends.
type adapterRun func(t *testing.T, endpoint, subcmd string, args ...string) adapterResult

// filteredSubscribeItem is the first result item of an adapter subscribe; the
// fields after MonitoredItemStatusCode are only present when a
// DataChangeFilter was requested (client contract §4 "subscribe").
type filteredSubscribeItem struct {
	MonitoredItemStatusCode statusCodeObj `json:"monitoredItemStatusCode"`
	Filter                  *struct {
		Trigger       string  `json:"trigger"`
		DeadbandType  string  `json:"deadbandType"`
		DeadbandValue float64 `json:"deadbandValue"`
	} `json:"filter"`
	Notifications []struct {
		Value json.RawMessage `json:"value"`
	} `json:"notifications"`
}

// subscribeItem runs an adapter subscribe on one node and returns the
// notified values of the first item as floats, the item and the raw result.
func subscribeItem(t *testing.T, run adapterRun, endpoint, node string, args ...string) ([]float64, *filteredSubscribeItem, adapterResult) {
	t.Helper()
	all := append([]string{"--node", "nsu=" + interopNamespaceURI + ";s=" + node}, args...)
	result := run(t, endpoint, "subscribe", all...)
	var items []filteredSubscribeItem
	if len(result.Results) == 0 || json.Unmarshal(result.Results, &items) != nil || len(items) == 0 {
		return nil, nil, result
	}
	vals := make([]float64, 0, len(items[0].Notifications))
	for _, n := range items[0].Notifications {
		v, err := strconv.ParseFloat(strings.Trim(string(n.Value), `"`), 64)
		if err != nil {
			t.Fatalf("notification value %s is not a number", n.Value)
		}
		vals = append(vals, v)
	}
	return vals, &items[0], result
}

// subscribeFloats is subscribeItem without the item.
func subscribeFloats(t *testing.T, run adapterRun, endpoint, node string, args ...string) ([]float64, adapterResult) {
	t.Helper()
	vals, _, result := subscribeItem(t, run, endpoint, node, args...)
	return vals, result
}

// requireEchoedFilter asserts that the adapter reports the DataChangeFilter
// it sent: evidence that the filter flag was not silently dropped.
func requireEchoedFilter(t *testing.T, item *filteredSubscribeItem, trigger, deadbandType string, value float64) {
	t.Helper()
	if item == nil || item.Filter == nil {
		t.Fatalf("the adapter reported no filter: the request carried no DataChangeFilter")
	}
	if f := item.Filter; f.Trigger != trigger || f.DeadbandType != deadbandType || f.DeadbandValue != value {
		t.Fatalf("the adapter sent filter %+v, want %s/%s/%v", *f, trigger, deadbandType, value)
	}
}

// assertPeerClientSamplingInterval verifies that the go-opcua server samples
// at the interval the peer client asks for: the ramp moves by 1.0 every
// 100 ms, so samples taken at least a second apart are about 10 apart, where
// a server that reports every change delivers steps of 1.
func assertPeerClientSamplingInterval(t *testing.T, run adapterRun) {
	t.Helper()
	endpoint := startGoServer(t)
	vals, result := subscribeFloats(t, run, endpoint, "Dynamic.Ramp",
		"--notifications", "4",
		"--queue-size", "10",
		"--publishing-interval-ms", "200",
		"--sampling-interval-ms", "1000",
		"--timeout-ms", "20000",
	)
	if !result.Success {
		t.Fatalf("subscribe failed: %s error=%s", result.ServiceResult, result.Error)
	}
	t.Logf("sampling interval 1000 ms: %v", vals)
	if len(vals) < 4 {
		t.Fatalf("want at least 4 notifications, got %v", vals)
	}
	// The interval counts from the initial value on, so every step, the
	// first included, spans about a second of ramp. 5 leaves ample margin.
	for i := 1; i < len(vals); i++ {
		if step := rampStep(vals[i-1], vals[i]); step < 5 {
			t.Errorf("samples %v -> %v are %v apart: sampled faster than once per second", vals[i-1], vals[i], step)
		}
	}
}

func TestGoServer_PeerClient_SamplingInterval(t *testing.T) {
	t.Run("coverage/monitoreditem.sampling-interval/open62541-client-to-go-server", func(t *testing.T) {
		assertPeerClientSamplingInterval(t, runOpen62541Client)
	})
	t.Run("coverage/monitoreditem.sampling-interval/milo-client-to-go-server", func(t *testing.T) {
		assertPeerClientSamplingInterval(t, runMiloClient)
	})
}

// assertPeerClientDeadband verifies that the go-opcua server applies the
// deadband a peer client asks for (subscribe --deadband-absolute /
// --deadband-percent).
func assertPeerClientDeadband(t *testing.T, run, runResult adapterRun) {
	t.Helper()
	endpoint := startGoServer(t)
	common := []string{"--publishing-interval-ms", "200", "--sampling-interval-ms", "50", "--queue-size", "10"}

	// Positive and negative in one: every reported step exceeds the deadband.
	vals, item, result := subscribeItem(t, run, endpoint, "Dynamic.Ramp",
		append([]string{"--deadband-absolute", "10", "--notifications", "4", "--timeout-ms", "20000"}, common...)...)
	if !result.Success {
		t.Fatalf("subscribe --deadband-absolute failed: %s error=%s", result.ServiceResult, result.Error)
	}
	requireEchoedFilter(t, item, "StatusValue", "Absolute", 10)
	t.Logf("absolute deadband 10: %v", vals)
	if len(vals) < 4 {
		t.Fatalf("want at least 4 notifications, got %v", vals)
	}
	for i := 1; i < len(vals); i++ {
		if rampStep(vals[i-1], vals[i]) <= 10 {
			t.Errorf("step %v -> %v is within the deadband", vals[i-1], vals[i])
		}
	}

	// A deadband wider than the ramp: the initial value and nothing else.
	// The adapter waits for a second notification that never comes.
	vals, result = subscribeFloats(t, runResult, endpoint, "Dynamic.Ramp",
		append([]string{"--deadband-absolute", "1000", "--notifications", "2", "--timeout-ms", "3000"}, common...)...)
	if len(vals) > 1 {
		t.Errorf("deadband 1000: want only the initial value, got %v (%s)", vals, result.ServiceResult)
	}

	// Dynamic.Ramp has no EURange: a PercentDeadband cannot be applied and
	// the item is rejected (Bad_MonitoredItemFilterUnsupported).
	vals, item, result = subscribeItem(t, runResult, endpoint, "Dynamic.Ramp",
		append([]string{"--deadband-percent", "10", "--notifications", "1", "--timeout-ms", "3000"}, common...)...)
	if result.Success || len(vals) > 0 {
		t.Errorf("percent deadband without EURange: want a rejected item, got success=%v values=%v", result.Success, vals)
	}
	if item == nil || !statusCodeIs(item.MonitoredItemStatusCode, ua.StatusBadMonitoredItemFilterUnsupported) {
		t.Errorf("percent deadband without EURange: monitored item status %+v, want BadMonitoredItemFilterUnsupported (result: %s)", item, result.Results)
	}
}

// assertPeerClientPercentDeadband verifies that the go-opcua server applies a
// PercentDeadband a peer client asks for on an AnalogItem: Analog.Level ramps
// 0..100 in steps of 2 with EURange [0, 100], so 10 % is a change of 10.
func assertPeerClientPercentDeadband(t *testing.T, run, runResult adapterRun) {
	t.Helper()
	endpoint := startGoServer(t)
	common := []string{"--publishing-interval-ms", "200", "--sampling-interval-ms", "50", "--queue-size", "10"}

	vals, item, result := subscribeItem(t, run, endpoint, "Analog.Level",
		append([]string{"--deadband-percent", "10", "--notifications", "4", "--timeout-ms", "20000"}, common...)...)
	if !result.Success {
		t.Fatalf("subscribe --deadband-percent failed: %s error=%s", result.ServiceResult, result.Error)
	}
	requireEchoedFilter(t, item, "StatusValue", "Percent", 10)
	t.Logf("percent deadband 10 on EURange [0,100]: %v", vals)
	if len(vals) < 4 {
		t.Fatalf("want at least 4 notifications, got %v", vals)
	}
	for i := 1; i < len(vals); i++ {
		if rampStep(vals[i-1], vals[i]) <= 10 {
			t.Errorf("step %v -> %v is within 10 %% of the range", vals[i-1], vals[i])
		}
	}

	// 100 % of the range is never exceeded: the initial value and nothing else.
	vals, item, result = subscribeItem(t, runResult, endpoint, "Analog.Level",
		append([]string{"--deadband-percent", "100", "--notifications", "2", "--timeout-ms", "3000"}, common...)...)
	if item == nil || !statusCodeIs(item.MonitoredItemStatusCode, ua.StatusOK) {
		t.Fatalf("percent deadband 100: the item was not created: %s", result.Results)
	}
	if len(vals) != 1 {
		t.Errorf("percent deadband 100: want only the initial value, got %v (%s)", vals, result.ServiceResult)
	}

	// More than 100 % is not a deadband (Bad_DeadbandFilterInvalid).
	vals, item, result = subscribeItem(t, runResult, endpoint, "Analog.Level",
		append([]string{"--deadband-percent", "150", "--notifications", "1", "--timeout-ms", "3000"}, common...)...)
	if result.Success || len(vals) > 0 {
		t.Errorf("percent deadband 150: want a rejected item, got success=%v values=%v", result.Success, vals)
	}
	if item == nil || !statusCodeIs(item.MonitoredItemStatusCode, ua.StatusBadDeadbandFilterInvalid) {
		t.Errorf("percent deadband 150: monitored item status %+v, want BadDeadbandFilterInvalid (result: %s)", item, result.Results)
	}
}

// assertPeerClientTrigger verifies that the go-opcua server honours the
// DataChangeTrigger a peer client asks for (subscribe --trigger).
func assertPeerClientTrigger(t *testing.T, run, runResult adapterRun) {
	t.Helper()
	endpoint := startGoServer(t)
	common := []string{"--publishing-interval-ms", "200", "--sampling-interval-ms", "50", "--queue-size", "10"}

	// Status: the ramp keeps changing but its status does not.
	vals, item, result := subscribeItem(t, runResult, endpoint, "Dynamic.Ramp",
		append([]string{"--trigger", "Status", "--notifications", "2", "--timeout-ms", "3000"}, common...)...)
	requireEchoedFilter(t, item, "Status", "None", 0)
	if len(vals) != 1 {
		t.Errorf("Status trigger: want only the initial value, got %v (%s)", vals, result.ServiceResult)
	}

	// StatusValue: every change of the counter, in order.
	vals, item, result = subscribeItem(t, run, endpoint, "Dynamic.Counter",
		append([]string{"--trigger", "StatusValue", "--notifications", "3", "--timeout-ms", "20000"}, common...)...)
	if !result.Success || len(vals) < 3 {
		t.Fatalf("StatusValue trigger: success=%v values=%v (%s)", result.Success, vals, result.ServiceResult)
	}
	requireEchoedFilter(t, item, "StatusValue", "None", 0)
	for i := 1; i < len(vals); i++ {
		if vals[i] <= vals[i-1] {
			t.Errorf("StatusValue trigger: not increasing: %v", vals)
		}
	}
	// ...and nothing for a value that does not change.
	vals, result = subscribeFloats(t, runResult, endpoint, "Scalar.Int32",
		append([]string{"--trigger", "StatusValue", "--notifications", "2", "--timeout-ms", "3000"}, common...)...)
	if len(vals) > 1 {
		t.Errorf("StatusValue trigger on a static node: want only the initial value, got %v (%s)", vals, result.ServiceResult)
	}

	// StatusValueTimestamp: every step of the ramp.
	vals, item, result = subscribeItem(t, run, endpoint, "Dynamic.Ramp",
		append([]string{"--trigger", "StatusValueTimestamp", "--notifications", "3", "--timeout-ms", "20000"}, common...)...)
	if !result.Success || len(vals) < 3 {
		t.Fatalf("StatusValueTimestamp trigger: success=%v values=%v (%s)", result.Success, vals, result.ServiceResult)
	}
	requireEchoedFilter(t, item, "StatusValueTimestamp", "None", 0)
}

func TestGoServer_PeerClient_Deadband(t *testing.T) {
	t.Run("coverage/monitoreditem.deadband/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "deadband")
		assertPeerClientDeadband(t, runOpen62541Client, runOpen62541ClientResult)
	})
	t.Run("coverage/monitoreditem.deadband/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, "MILO_IMAGE", defaultMiloImage, "deadband")
		assertPeerClientDeadband(t, runMiloClient, runMiloClientResult)
	})
}

func TestGoServer_PeerClient_PercentDeadband(t *testing.T) {
	t.Run("coverage/monitoreditem.percent-deadband/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "deadband")
		assertPeerClientPercentDeadband(t, runOpen62541Client, runOpen62541ClientResult)
	})
	t.Run("coverage/monitoreditem.percent-deadband/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, "MILO_IMAGE", defaultMiloImage, "deadband")
		assertPeerClientPercentDeadband(t, runMiloClient, runMiloClientResult)
	})
}

func TestGoServer_PeerClient_Trigger(t *testing.T) {
	t.Run("coverage/monitoreditem.trigger/open62541-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "deadband")
		assertPeerClientTrigger(t, runOpen62541Client, runOpen62541ClientResult)
	})
	t.Run("coverage/monitoreditem.trigger/milo-client-to-go-server", func(t *testing.T) {
		requireAdapterClientFeature(t, "MILO_IMAGE", defaultMiloImage, "deadband")
		assertPeerClientTrigger(t, runMiloClient, runMiloClientResult)
	})
}
