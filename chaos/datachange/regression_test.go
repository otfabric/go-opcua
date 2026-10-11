// SPDX-License-Identifier: MIT

package datachange

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// The tests in this file pin down product bugs the suite found that need a
// client and a server to show. The others have their regression test next to
// the code: server/monitored_item_sampler_regress_test.go and
// server/node_value_regress_test.go.

// TestRegressionMonitoringModeSurvivesRecreation: SetMonitoringMode was not
// remembered by the client, so a subscription that was recreated after a
// reconnect brought every item back in the mode it had been created with. An
// item the application had disabled, or set to Sampling, started to report.
func TestRegressionMonitoringModeSurvivesRecreation(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1, 1)
	s := &storm{t: t, e: e}
	c := e.connect(nil, opcua.RequestTimeout(5*time.Second))
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	tr, err := newTracker(ctx, e, c, "sub", stormParams(20*time.Millisecond), true, &s.sink)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	n := e.node(kindDouble, 0)
	witness, err := tr.create(ctx, ua.MonitoringModeReporting, false, itemSpec{n: n, noFilter: true})
	if err != nil {
		t.Fatal(err)
	}
	// One item switched to Sampling, one switched to Disabled, one created
	// Disabled. None of them may deliver anything from here on.
	s.silence(ctx, tr, witness[0])

	delivered := func(w write) bool {
		return chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
			last, ok := witness[0].lastSeen()
			return ok && last.seq >= w.seq
		})
	}
	for round := 0; round < 2; round++ {
		e.restartServer(20 * time.Millisecond)
		// The items are recreated with their initial value; two more changes
		// follow so that an item that samples has something to report.
		for k := 0; k < 3; k++ {
			w, ok := e.set(n, float64(200+10*round+k), ua.StatusOK)
			if !ok || !delivered(w) {
				last, _ := witness[0].lastSeen()
				t.Fatalf("STUCK: the subscription did not deliver write %d after restart %d (state %v, last %v)", w.seq, round+1, c.State(), last.sample)
			}
		}
	}
	chaoskit.CloseClient(c, nil)
	s.sink.Report(t)
}

// TestRegressionModifyRacesUnmonitor: ModifyMonitoredItems looked the item up
// again after the server had answered and dereferenced it without a check.
// When Unmonitor had removed the item in the meantime the client panicked.
func TestRegressionModifyRacesUnmonitor(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1, 1)
	c := e.connect(nil)
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	var sink chaoskit.ErrSink
	tr, err := newTracker(ctx, e, c, "sub", longLived(20*time.Millisecond), false, &sink)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	spec := itemSpec{n: e.node(kindInt32, 0), noFilter: true}

	for round := 0; round < 150; round++ {
		items, err := tr.create(ctx, ua.MonitoringModeReporting, true, spec)
		if err != nil {
			t.Fatal(err)
		}
		it := items[0]
		ep := tr.newEpoch(it, spec, false)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			res, err := tr.sub.ModifyMonitoredItems(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemModifyRequest{
				MonitoredItemID:     it.id,
				RequestedParameters: tr.parameters(spec, ep.handle),
			})
			if goneError(err) {
				return
			}
			if err != nil || len(res.Results) != 1 || !goneOrOK(res.Results[0].StatusCode) {
				t.Errorf("modify: %+v, %v", res, err)
			}
		}()
		go func() {
			defer wg.Done()
			res, err := tr.sub.Unmonitor(ctx, it.id)
			if err != nil || len(res.Results) != 1 || res.Results[0] != ua.StatusOK {
				t.Errorf("delete: %+v, %v", res, err)
			}
		}()
		wg.Wait()
		if t.Failed() {
			return
		}
	}
	// The deletes were synchronous: nothing is left on the server.
	if r := e.resources(); r.MonitoredItems != 0 {
		t.Errorf("server still holds %d monitored items", r.MonitoredItems)
	}
	chaoskit.CloseClient(c, nil)
	sink.Report(t)
}

// TestRegressionWriteRangeIntoUncertainArray: the Write service refused an
// IndexRange on an array whose value had Uncertain quality, with
// BadIndexRangeInvalid. Here the write must succeed and reach a monitored
// item whose own index range covers it.
func TestRegressionWriteRangeIntoUncertainArray(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 1, 1)
	c := e.connect(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var sink chaoskit.ErrSink
	tr, err := newTracker(ctx, e, c, "sub", longLived(20*time.Millisecond), false, &sink)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	n := e.node(kindInt32Array, 0)
	items, err := tr.create(ctx, ua.MonitoringModeReporting, false, itemSpec{n: n, noFilter: true, indexRange: "1:3"})
	if err != nil {
		t.Fatal(err)
	}
	e.set(n, []int32{1, 2, 3, 4, 5, 6}, ua.StatusUncertainLastUsableValue)

	res, err := c.Write(ctx, &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID: n.id, AttributeID: ua.AttributeIDValue, IndexRange: "2:3",
		Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]int32{30, 40})},
	}}})
	if err != nil || len(res.Results) != 1 || res.Results[0] != ua.StatusOK {
		t.Fatalf("write of a range into an Uncertain array: %+v, %v", res, err)
	}
	want := []int32{2, 30, 40}
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last, ok := items[0].lastSeen()
		got, _ := last.value.([]int32)
		return ok && len(got) == 3 && got[0] == want[0] && got[1] == want[1] && got[2] == want[2]
	}) {
		last, _ := items[0].lastSeen()
		t.Fatalf("the item with index range 1:3 delivered %v, want %v", last.sample, want)
	}
	chaoskit.CloseClient(c, nil)
	sink.Report(t)
}
