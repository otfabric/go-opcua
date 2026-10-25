// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// AlarmMetrics are the values of an AlarmMetricsType object (Part 9 1.05),
// see [Client.ReadAlarmMetrics].
type AlarmMetrics struct {
	AlarmCount          uint32
	StartTime           time.Time
	MaximumActiveState  time.Duration
	MaximumUnAck        time.Duration
	MaximumReAlarmCount uint32
	// The alarm rates, alarms per RateMinutes (the Rate Property of
	// CurrentAlarmRate).
	CurrentAlarmRate, MaximumAlarmRate, AverageAlarmRate float64
	RateMinutes                                          uint16
}

// alarmMetricsPaths are the components ReadAlarmMetrics reads, in the order
// of their use.
var alarmMetricsPaths = [][]string{
	{"AlarmCount"}, {"StartTime"}, {"MaximumActiveState"}, {"MaximumUnAck"}, {"MaximumReAlarmCount"},
	{"CurrentAlarmRate"}, {"MaximumAlarmRate"}, {"AverageAlarmRate"}, {"CurrentAlarmRate", "Rate"},
}

// ReadAlarmMetrics reads the components of an AlarmMetricsType object. A
// component the object does not have (or that cannot be read) keeps its
// zero value; the error reports the first service failure.
func (c *Client) ReadAlarmMetrics(ctx context.Context, metricsID *ua.NodeID) (*AlarmMetrics, error) {
	req := &ua.TranslateBrowsePathsToNodeIDsRequest{}
	for _, p := range alarmMetricsPaths {
		rp := &ua.RelativePath{}
		for _, name := range p {
			rp.Elements = append(rp.Elements, &ua.RelativePathElement{ReferenceTypeID: ua.NewTwoByteNodeID(id.HierarchicalReferences),
				IncludeSubtypes: true, TargetName: &ua.QualifiedName{Name: name}})
		}
		req.BrowsePaths = append(req.BrowsePaths, &ua.BrowsePath{StartingNode: metricsID, RelativePath: rp})
	}
	var tr *ua.TranslateBrowsePathsToNodeIDsResponse
	if err := c.Send(ctx, req, func(r ua.Response) error {
		var ok bool
		if tr, ok = r.(*ua.TranslateBrowsePathsToNodeIDsResponse); !ok {
			return fmt.Errorf("opcua: ReadAlarmMetrics: unexpected %T", r)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(tr.Results) != len(alarmMetricsPaths) {
		return nil, fmt.Errorf("opcua: ReadAlarmMetrics: %d results, want %d", len(tr.Results), len(alarmMetricsPaths))
	}
	read := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	idx := make([]int, 0, len(tr.Results))
	for i, r := range tr.Results {
		if r == nil || r.StatusCode != ua.StatusOK || len(r.Targets) == 0 || r.Targets[0].TargetID == nil {
			continue
		}
		read.NodesToRead = append(read.NodesToRead, &ua.ReadValueID{NodeID: r.Targets[0].TargetID.NodeID, AttributeID: ua.AttributeIDValue})
		idx = append(idx, i)
	}
	if len(idx) == 0 {
		return nil, ua.StatusBadNodeIDUnknown
	}
	res, err := c.Read(ctx, read)
	if err != nil {
		return nil, err
	}
	vals := make([]any, len(alarmMetricsPaths))
	for k, dv := range res.Results {
		if k < len(idx) && dv != nil && dv.Status == ua.StatusOK && dv.Value != nil {
			vals[idx[k]] = dv.Value.Value()
		}
	}
	m := &AlarmMetrics{}
	m.AlarmCount, _ = vals[0].(uint32)
	m.StartTime, _ = vals[1].(time.Time)
	dur := func(v any) time.Duration {
		f, _ := v.(float64)
		return time.Duration(f * float64(time.Millisecond))
	}
	m.MaximumActiveState, m.MaximumUnAck = dur(vals[2]), dur(vals[3])
	m.MaximumReAlarmCount, _ = vals[4].(uint32)
	m.CurrentAlarmRate, _ = vals[5].(float64)
	m.MaximumAlarmRate, _ = vals[6].(float64)
	m.AverageAlarmRate, _ = vals[7].(float64)
	m.RateMinutes, _ = vals[8].(uint16)
	return m, nil
}

// ResetAlarmMetrics calls the Reset method of an AlarmMetricsType object:
// the counters start anew.
func (c *Client) ResetAlarmMetrics(ctx context.Context, metricsID *ua.NodeID) error {
	return c.callStatus(ctx, metricsID, ua.NewNumericNodeID(0, id.AlarmMetricsTypeReset))
}
