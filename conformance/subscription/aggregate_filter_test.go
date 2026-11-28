// SPDX-License-Identifier: MIT

package subscription

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestAggregateFilter_Wire creates a MonitoredItem with an AggregateFilter
// over the wire (Part 4 §7.22.4): the AggregateFilterResult holds the
// revised values, and the item reports one Count per completed interval,
// with the Aggregate bits, the start of the interval as SourceTimestamp and
// its end as ServerTimestamp, until every written value is counted.
func TestAggregateFilter_Wire(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{interval: 50})
	before := time.Now().Truncate(time.Millisecond)
	// The value at creation is the first raw value, from before the first
	// interval: it is not counted.
	require.Equal(t, ua.StatusOK, f.NS.SetAttribute(f.Double, ua.AttributeIDValue, dvAt(-1.0, ua.StatusOK, before.Add(-time.Hour))))
	res := sub.createItems(ua.TimestampsToReturnBoth, itemSpec{
		node: f.Double, handle: 1, queue: 50,
		filter: ua.NewExtensionObject(&ua.AggregateFilter{
			AggregateType: ua.NewNumericNodeID(0, id.AggregateFunctionCount), ProcessingInterval: 150,
		}),
	})
	require.Equal(t, ua.StatusOK, res[0].StatusCode)
	afr, ok := res[0].FilterResult.Value.(*ua.AggregateFilterResult)
	require.True(t, ok, "%T", res[0].FilterResult.Value)
	require.Equal(t, 150.0, afr.RevisedProcessingInterval)
	require.False(t, afr.RevisedStartTime.Before(before), "the intervals start when the item is created")
	require.Equal(t, aggregate.DefaultConfig().AggregateConfiguration(), afr.RevisedAggregateConfiguration)

	const writes = 3
	for i := range writes {
		require.Equal(t, ua.StatusOK, f.NS.SetAttribute(f.Double, ua.AttributeIDValue, dvAt(float64(i), ua.StatusOK, time.Now())))
		time.Sleep(time.Millisecond)
	}

	counted := int32(0)
	var last time.Time
	eventually(t, func() bool {
		for _, s := range sub.nextData() {
			require.Equal(t, uint32(1), s.Handle)
			dv := s.DV
			require.Equal(t, 150*time.Millisecond, dv.ServerTimestamp.Sub(dv.SourceTimestamp), "the ServerTimestamp is the end of the interval")
			require.False(t, dv.SourceTimestamp.Before(afr.RevisedStartTime))
			require.True(t, dv.SourceTimestamp.After(last), "one value per interval, in order")
			last = dv.SourceTimestamp
			if dv.Status == ua.StatusBadNoData {
				continue // an interval after the last value (Part 13 §5.4.3.1)
			}
			require.NotZero(t, dv.Status&ua.StatusCodeHistorianCalculated, "%v", dv.Status)
			n, ok := dv.Value.Value().(int32)
			require.True(t, ok, "%T", dv.Value.Value())
			counted += n
		}
		return counted == writes
	}, "the written values counted")

	// The ServerCapabilities list every Aggregate a MonitoredItem can use
	// (Part 5 §6.3.2).
	br := mustSendRaw[ua.BrowseResponse](t, c, &ua.BrowseRequest{
		View: &ua.ViewDescription{ViewID: ua.NewTwoByteNodeID(0)},
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          ua.NewNumericNodeID(0, id.ServerServerCapabilitiesAggregateFunctions),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
	})
	require.Len(t, br.Results, 1)
	require.Len(t, br.Results[0].References, len(aggregate.Functions()))
}

// TestAggregateFilter_Errors: the operation results of an AggregateFilter
// that cannot be used.
func TestAggregateFilter_Errors(t *testing.T) {
	c, f, _ := rawSetup(t)
	sub := newRawSub(t, c, rawSubParams{interval: 50})
	agg := func(fn uint32) *ua.ExtensionObject {
		return ua.NewExtensionObject(&ua.AggregateFilter{AggregateType: ua.NewNumericNodeID(0, fn), ProcessingInterval: 1000})
	}
	res := sub.createItems(ua.TimestampsToReturnSource,
		itemSpec{node: f.Double, handle: 1, filter: agg(id.AggregateFunctionAnnotationCount)},
		itemSpec{node: f.Double, handle: 2, attr: ua.AttributeIDDisplayName, filter: agg(id.AggregateFunctionAverage)},
		itemSpec{node: f.Double, handle: 3, filter: ua.NewExtensionObject(&ua.AggregateFilter{
			AggregateType: ua.NewNumericNodeID(0, id.AggregateFunctionAverage), ProcessingInterval: 1000,
			AggregateConfiguration: &ua.AggregateConfiguration{PercentDataBad: 20, PercentDataGood: 20},
		})},
		itemSpec{node: f.Double, handle: 4, filter: agg(id.AggregateFunctionAverage)},
	)
	require.Equal(t, ua.StatusBadAggregateNotSupported, res[0].StatusCode)
	require.Equal(t, ua.StatusBadFilterNotAllowed, res[1].StatusCode)
	require.Equal(t, ua.StatusBadMonitoredItemFilterInvalid, res[2].StatusCode)
	require.Equal(t, ua.StatusOK, res[3].StatusCode)

	res = sub.createItems(ua.TimestampsToReturnServer, itemSpec{node: f.Double, handle: 5, filter: agg(id.AggregateFunctionAverage)})
	require.Equal(t, ua.StatusBadTimestampsToReturnInvalid, res[0].StatusCode, "Part 13 §5.4.3.1")
}
