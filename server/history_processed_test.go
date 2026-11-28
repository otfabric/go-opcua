// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/aggregate"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

var processedBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// rawProvider is a HistoryProvider with raw reads only, in pages of page
// values (0: one page); the server calculates the Aggregates of its
// processed reads.
type rawProvider struct {
	values    []*ua.DataValue
	page      int
	status    ua.StatusCode
	err       error
	nilRes    bool
	endless   bool
	wrongType bool
	cfg       *aggregate.Config
	reads     int
	released  [][]byte
	from, to  time.Time
}

func (p *rawProvider) ReadRaw(_ *ua.NodeID, start, end time.Time, _ uint32, _ bool, cp []byte) (*ua.HistoryReadResult, error) {
	p.reads++
	p.from, p.to = start, end
	switch {
	case p.err != nil:
		return nil, p.err
	case p.nilRes:
		return nil, nil
	case p.status != ua.StatusOK:
		return &ua.HistoryReadResult{StatusCode: p.status}, nil
	case p.endless:
		return &ua.HistoryReadResult{StatusCode: ua.StatusOK, ContinuationPoint: []byte{1}}, nil
	}
	if p.wrongType {
		return &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryModifiedData{})}, nil
	}
	var in []*ua.DataValue
	for _, v := range p.values {
		if !v.SourceTimestamp.Before(start) && v.SourceTimestamp.Before(end) {
			in = append(in, v)
		}
	}
	// The continuation point is the offset of the next page.
	off := 0
	if len(cp) > 0 {
		off = int(cp[0])
	}
	last := len(in)
	if p.page > 0 && off+p.page < last {
		last = off + p.page
	}
	res := &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: in[off:last]})}
	if last < len(in) {
		res.ContinuationPoint = []byte{byte(last)}
	}
	return res, nil
}

func (p *rawProvider) ReleaseContinuation(cp []byte) { p.released = append(p.released, cp) }

func (p *rawProvider) AggregateConfig(*ua.NodeID) aggregate.Config {
	if p.cfg != nil {
		return *p.cfg
	}
	return aggregate.DefaultConfig()
}

// processedOnly is a ProcessedHistoryReader that does not list its
// Aggregates.
type processedOnly struct{ dataOnlyProvider }

func (processedOnly) ReadProcessed(*ua.NodeID, time.Time, time.Time, float64, *ua.NodeID, *ua.AggregateConfiguration) (*ua.HistoryReadResult, error) {
	return &ua.HistoryReadResult{StatusCode: ua.StatusGoodNoData}, nil
}

func ramp(n int) []*ua.DataValue {
	var out []*ua.DataValue
	for i := range n {
		out = append(out, &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
			Value:           ua.MustVariant(float64(i)),
			SourceTimestamp: processedBase.Add(time.Duration(i) * time.Second),
		})
	}
	return out
}

func historyReadProcessed(t *testing.T, svc *AttributeService, ttr ua.TimestampsToReturn, d *ua.ReadProcessedDetails, nodes ...*ua.NodeID) *ua.HistoryReadResponse {
	t.Helper()
	req := &ua.HistoryReadRequest{
		RequestHeader:      reqHeader(),
		HistoryReadDetails: ua.NewExtensionObject(d),
		TimestampsToReturn: ttr,
	}
	for _, n := range nodes {
		req.NodesToRead = append(req.NodesToRead, &ua.HistoryReadValueID{NodeID: n})
	}
	resp, err := svc.HistoryRead(context.Background(), nil, req, 1)
	require.NoError(t, err)
	return resp.(*ua.HistoryReadResponse)
}

func processedValues(t *testing.T, r *ua.HistoryReadResult) []*ua.DataValue {
	t.Helper()
	require.Equal(t, ua.StatusOK, r.StatusCode)
	return r.HistoryData.Value.(*ua.HistoryData).DataValues
}

func aggType(ids ...uint32) []*ua.NodeID {
	var out []*ua.NodeID
	for _, i := range ids {
		out = append(out, ua.NewNumericNodeID(0, i))
	}
	return out
}

// TestHistoryReadProcessed covers ReadProcessedDetails through the
// HistoryRead service (Part 11 §6.5.4): one Aggregate per node to read,
// source timestamps only, and Aggregates the server calculates from the raw
// values of a provider without processed reads.
func TestHistoryReadProcessed(t *testing.T) {
	a, b := ua.NewStringNodeID(2, "A"), ua.NewStringNodeID(2, "B")
	details := func(aggs ...uint32) *ua.ReadProcessedDetails {
		return &ua.ReadProcessedDetails{
			StartTime:          processedBase,
			EndTime:            processedBase.Add(4 * time.Second),
			ProcessingInterval: 2000,
			AggregateType:      aggType(aggs...),
		}
	}

	t.Run("historian, an Aggregate per node", func(t *testing.T) {
		srv := newTestServer()
		svc := &AttributeService{srv: srv}
		h := NewHistorian()
		h.EnableNode(a, 100)
		for _, v := range ramp(6) {
			h.RecordValue(a, v)
		}
		srv.SetHistorian(h)
		// The same node twice, for Minimum and Maximum (§6.5.4.2).
		resp := historyReadProcessed(t, svc, ua.TimestampsToReturnBoth, details(id.AggregateFunctionMinimum, id.AggregateFunctionMaximum), a, a)
		require.Equal(t, ua.StatusOK, resp.ResponseHeader.ServiceResult)
		mins, maxs := processedValues(t, resp.Results[0]), processedValues(t, resp.Results[1])
		require.Len(t, mins, 2)
		require.Equal(t, []any{0.0, 2.0}, []any{mins[0].Value.Value(), mins[1].Value.Value()})
		require.Equal(t, []any{1.0, 3.0}, []any{maxs[0].Value.Value(), maxs[1].Value.Value()})
	})

	t.Run("aggregate list mismatch", func(t *testing.T) {
		svc := &AttributeService{srv: newTestServer()}
		svc.srv.SetHistorian(NewHistorian())
		resp := historyReadProcessed(t, svc, ua.TimestampsToReturnSource, details(id.AggregateFunctionMinimum), a, b)
		require.Equal(t, ua.StatusBadAggregateListMismatch, resp.ResponseHeader.ServiceResult)
		require.Empty(t, resp.Results)
		resp = historyReadProcessed(t, svc, ua.TimestampsToReturnSource, details(), a)
		require.Equal(t, ua.StatusBadAggregateListMismatch, resp.ResponseHeader.ServiceResult)
	})

	t.Run("timestamps to return", func(t *testing.T) {
		svc := &AttributeService{srv: newTestServer()}
		svc.srv.SetHistorian(&rawProvider{values: ramp(4)})
		for ttr, want := range map[ua.TimestampsToReturn]ua.StatusCode{
			ua.TimestampsToReturnSource:  ua.StatusOK,
			ua.TimestampsToReturnBoth:    ua.StatusOK,
			ua.TimestampsToReturnServer:  ua.StatusBadTimestampsToReturnInvalid,
			ua.TimestampsToReturnNeither: ua.StatusBadTimestampsToReturnInvalid,
		} {
			resp := historyReadProcessed(t, svc, ttr, details(id.AggregateFunctionAverage), a)
			require.Equal(t, want, resp.Results[0].StatusCode, ttr)
		}
	})

	t.Run("nil details", func(t *testing.T) {
		svc := &AttributeService{srv: newTestServer()}
		svc.srv.SetHistorian(NewHistorian())
		res, err := svc.dispatchHistoryRead(NewHistorian(), &ua.HistoryReadRequest{}, 0, (*ua.ReadProcessedDetails)(nil), a, nil)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationInvalid, res.StatusCode)
		res, err = svc.dispatchHistoryRead(NewHistorian(), &ua.HistoryReadRequest{TimestampsToReturn: ua.TimestampsToReturnSource}, 0, *details(id.AggregateFunctionCount), a, nil)
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadHistoryOperationUnsupported, res.StatusCode)
	})

	t.Run("from raw reads", func(t *testing.T) {
		svc := &AttributeService{srv: newTestServer()}
		p := &rawProvider{values: ramp(10), page: 2}
		svc.srv.SetHistorian(p)
		d := details(id.AggregateFunctionCount)
		resp := historyReadProcessed(t, svc, ua.TimestampsToReturnSource, d, a)
		counts := processedValues(t, resp.Results[0])
		require.Len(t, counts, 2)
		require.Equal(t, int32(2), counts[0].Value.Value())
		require.Equal(t, int32(2), counts[1].Value.Value())
		// The window reaches one ProcessingInterval beyond the request on
		// each side, read in pages.
		require.Equal(t, processedBase.Add(-2*time.Second), p.from)
		require.Equal(t, processedBase.Add(6*time.Second), p.to)
		require.Greater(t, p.reads, 1)
	})

	t.Run("configuration of the provider", func(t *testing.T) {
		svc := &AttributeService{srv: newTestServer()}
		values := ramp(4)
		values[1] = &ua.DataValue{EncodingMask: ua.DataValueStatusCode | ua.DataValueSourceTimestamp, Status: ua.StatusBad, SourceTimestamp: values[1].SourceTimestamp}
		cfg := aggregate.Config{PercentDataBad: 50, PercentDataGood: 100}
		svc.srv.SetHistorian(&rawProvider{values: values, cfg: &cfg})
		resp := historyReadProcessed(t, svc, ua.TimestampsToReturnSource, details(id.AggregateFunctionAverage), a)
		got := processedValues(t, resp.Results[0])
		require.Equal(t, ua.StatusBad, got[0].Status&^ua.StatusCodeHistorianBits&^ua.StatusCodeInfoTypeDataValue)
		// The request overrides it.
		d := details(id.AggregateFunctionAverage)
		d.AggregateConfiguration = aggregate.DefaultConfig().AggregateConfiguration()
		resp = historyReadProcessed(t, svc, ua.TimestampsToReturnSource, d, a)
		got = processedValues(t, resp.Results[0])
		require.Equal(t, ua.StatusUncertainDataSubNormal, got[0].Status&^ua.StatusCodeHistorianBits&^ua.StatusCodeInfoTypeDataValue)
	})

	t.Run("errors", func(t *testing.T) {
		for name, tc := range map[string]struct {
			p    *rawProvider
			d    *ua.ReadProcessedDetails
			want ua.StatusCode
		}{
			"unsupported aggregate": {&rawProvider{}, details(99999), ua.StatusBadAggregateNotSupported},
			"start equals end":      {&rawProvider{}, &ua.ReadProcessedDetails{StartTime: processedBase, EndTime: processedBase, AggregateType: aggType(id.AggregateFunctionCount)}, ua.StatusBadInvalidArgument},
			"raw read fails":        {&rawProvider{status: ua.StatusBadNoContinuationPoints}, details(id.AggregateFunctionCount), ua.StatusBadNoContinuationPoints},
			"raw read returns nil":  {&rawProvider{nilRes: true}, details(id.AggregateFunctionCount), ua.StatusBadHistoryOperationUnsupported},
			"raw read of modified":  {&rawProvider{wrongType: true}, details(id.AggregateFunctionCount), ua.StatusOK},
		} {
			svc := &AttributeService{srv: newTestServer()}
			svc.srv.SetHistorian(tc.p)
			resp := historyReadProcessed(t, svc, ua.TimestampsToReturnSource, tc.d, a)
			require.Equal(t, tc.want, resp.Results[0].StatusCode, name)
		}
	})

	t.Run("raw read error", func(t *testing.T) {
		svc := &AttributeService{srv: newTestServer()}
		svc.srv.SetHistorian(&rawProvider{err: errors.New("down")})
		resp := historyReadProcessed(t, svc, ua.TimestampsToReturnSource, details(id.AggregateFunctionCount), a)
		require.Equal(t, ua.StatusBadInternalError, resp.Results[0].StatusCode)
	})

	t.Run("endless continuation points", func(t *testing.T) {
		p := &rawProvider{endless: true}
		raw, st, err := readRawRange(p, a, processedBase, processedBase.Add(time.Second))
		require.NoError(t, err)
		require.Nil(t, raw)
		require.Equal(t, ua.StatusBadInternalError, st)
		require.Equal(t, maxRawPages, p.reads)
		require.Equal(t, [][]byte{{1}}, p.released)
	})

	t.Run("processed reader", func(t *testing.T) {
		svc := &AttributeService{srv: newTestServer()}
		svc.srv.SetHistorian(processedOnly{})
		resp := historyReadProcessed(t, svc, ua.TimestampsToReturnSource, details(id.AggregateFunctionCount), a)
		require.Equal(t, ua.StatusGoodNoData, resp.Results[0].StatusCode)
	})
}

// TestProcessedRequest covers the conversion of the ProcessingInterval in
// milliseconds.
func TestProcessedRequest(t *testing.T) {
	agg := ua.NewNumericNodeID(0, id.AggregateFunctionCount)
	end := processedBase.Add(time.Second)
	r, st := processedRequest(processedBase, end, 1.5, agg, aggregate.DefaultConfig())
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, 1500*time.Microsecond, r.ProcessingInterval)
	r, st = processedRequest(processedBase, end, 1e300, agg, aggregate.DefaultConfig())
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, time.Duration(0), r.ProcessingInterval)
	require.Equal(t, 1, r.Intervals())
	// More than aggregate.MaxIntervals intervals.
	_, st = processedRequest(processedBase, processedBase.Add(time.Hour), 1, agg, aggregate.DefaultConfig())
	require.Equal(t, ua.StatusBadInvalidArgument, st)
}

// TestHistoryAggregateFunctions: the AggregateFunctions folder of the
// HistoryServerCapabilities organizes the Aggregates of the history
// provider (Part 11 §5.7.2), and the AggregateFunction Objects have the
// Description of Part 13 Table 5.
func TestHistoryAggregateFunctions(t *testing.T) {
	s, err := New(InsecureNoSecurity())
	require.NoError(t, err)
	listed := func() []string {
		var out []string
		for _, r := range s.Node(ua.NewNumericNodeID(0, aggregateFunctionsFolder)).refsSnapshot() {
			if r.IsForward && r.ReferenceTypeID.IntID() == id.Organizes {
				out = append(out, r.NodeID.NodeID.String())
			}
		}
		return out
	}
	var all []string
	for _, n := range aggregate.Functions() {
		all = append(all, n.String())
	}
	require.Empty(t, listed())
	s.SetHistorian(NewHistorian())
	require.Equal(t, all, listed())
	// The inverse reference is on the Aggregate.
	avg := s.Node(ua.NewNumericNodeID(0, id.AggregateFunctionAverage))
	require.True(t, avg.hasRefTo(ua.NewNumericNodeID(0, aggregateFunctionsFolder), ua.NewNumericNodeID(0, id.Organizes), false))
	require.Equal(t, "Retrieve the average value of the data over the interval.", avg.Description().Text)
	require.Equal(t, "en", avg.Description().Locale)

	s.SetHistorian(processedOnly{})
	require.Empty(t, listed())
	s.SetHistorian(&rawProvider{})
	require.Equal(t, all, listed())
	s.SetHistorian(nil)
	require.Empty(t, listed())
	require.False(t, avg.hasRefTo(ua.NewNumericNodeID(0, aggregateFunctionsFolder), ua.NewNumericNodeID(0, id.Organizes), false))
}

// TestHistoryAggregateFunctionsWithoutFolder: a server without the folder
// (an address space that does not have it) sets the historian all the same.
func TestHistoryAggregateFunctionsWithoutFolder(t *testing.T) {
	s, err := New(InsecureNoSecurity())
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, s.ns0().(interface {
		DeleteNode(*ua.NodeID) ua.StatusCode
	}).DeleteNode(ua.NewNumericNodeID(0, aggregateFunctionsFolder)))
	s.SetHistorian(NewHistorian())
	require.Nil(t, s.Node(ua.NewNumericNodeID(0, aggregateFunctionsFolder)))
}

// TestHistorianProcessedArrays: the Aggregates that calculate with numbers
// cannot be applied to arrays (Part 11 §6.5.4.2).
func TestHistorianProcessedArrays(t *testing.T) {
	h := NewHistorian()
	n := ua.NewStringNodeID(2, "Arr")
	h.EnableNode(n, 10)
	h.RecordValue(n, &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant([]float64{1, 2}), SourceTimestamp: processedBase})
	res, err := h.ReadProcessed(n, processedBase, processedBase.Add(time.Second), 0, ua.NewNumericNodeID(0, id.AggregateFunctionAverage), nil)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNotSupported, res.StatusCode)
	res, err = h.ReadProcessed(n, processedBase, processedBase.Add(time.Second), 0, ua.NewNumericNodeID(0, id.AggregateFunctionCount), nil)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
}
