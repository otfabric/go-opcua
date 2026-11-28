// SPDX-License-Identifier: MIT

package aggregate

import (
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func at(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }

func good(s float64, v any) *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, Value: ua.MustVariant(v), SourceTimestamp: at(s)}
}

func withStatus(dv *ua.DataValue, st ua.StatusCode) *ua.DataValue {
	dv.Status = st
	dv.EncodingMask |= ua.DataValueStatusCode
	return dv
}

func agg(i uint32) *ua.NodeID { return ua.NewNumericNodeID(0, i) }

// code is the StatusCode without the Aggregate bits and the InfoType.
func code(st ua.StatusCode) ua.StatusCode {
	return st &^ ua.StatusCodeHistorianBits &^ ua.StatusCodeInfoTypeDataValue
}

func TestCheck(t *testing.T) {
	ok := Request{Aggregate: agg(id.AggregateFunctionCount), Start: at(0), End: at(10), ProcessingInterval: time.Second, Config: DefaultConfig()}
	require.Equal(t, ua.StatusOK, ok.Check())
	require.Equal(t, 10, ok.Intervals())
	for name, tc := range map[string]struct {
		mod  func(*Request)
		want ua.StatusCode
	}{
		"no aggregate":       {func(r *Request) { r.Aggregate = nil }, ua.StatusBadAggregateNotSupported},
		"AnnotationCount":    {func(r *Request) { r.Aggregate = agg(id.AggregateFunctionAnnotationCount) }, ua.StatusBadAggregateNotSupported},
		"other namespace":    {func(r *Request) { r.Aggregate = ua.NewNumericNodeID(1, id.AggregateFunctionCount) }, ua.StatusBadAggregateNotSupported},
		"no start":           {func(r *Request) { r.Start = time.Time{} }, ua.StatusBadInvalidArgument},
		"no end":             {func(r *Request) { r.End = time.Time{} }, ua.StatusBadInvalidArgument},
		"start equals end":   {func(r *Request) { r.End = r.Start }, ua.StatusBadInvalidArgument},
		"negative interval":  {func(r *Request) { r.ProcessingInterval = -1 }, ua.StatusBadInvalidArgument},
		"too many intervals": {func(r *Request) { r.ProcessingInterval = time.Nanosecond }, ua.StatusBadInvalidArgument},
		"invalid config":     {func(r *Request) { r.Config = Config{PercentDataBad: 80} }, ua.StatusBadAggregateInvalidInputs},
	} {
		r := ok
		tc.mod(&r)
		require.Equal(t, tc.want, r.Check(), name)
		require.Equal(t, 0, r.Intervals(), name)
		got, st := r.Calculate(nil)
		require.Nil(t, got, name)
		require.Equal(t, tc.want, st, name)
		_, st = r.CalculateIntervals(nil, 0, 1)
		require.Equal(t, tc.want, st, name)
	}
}

// TestIntervals covers Table 49 of Part 13 §5.4.2.2.
func TestIntervals(t *testing.T) {
	type iv struct{ start, end float64 }
	for name, tc := range map[string]struct {
		start, end float64
		pi         time.Duration
		want       []iv
	}{
		"one, interval 0":            {0, 10, 0, []iv{{0, 10}}},
		"one, interval at least":     {0, 10, 10 * time.Second, []iv{{0, 10}}},
		"divides evenly":             {0, 10, 5 * time.Second, []iv{{0, 5}, {5, 10}}},
		"rest":                       {0, 10, 4 * time.Second, []iv{{0, 4}, {4, 8}, {8, 10}}},
		"backwards, one":             {10, 0, 0, []iv{{10, 0}}},
		"backwards, one, at least":   {10, 0, 20 * time.Second, []iv{{10, 0}}},
		"backwards, divides evenly":  {10, 0, 5 * time.Second, []iv{{10, 5}, {5, 0}}},
		"backwards, rest":            {10, 0, 4 * time.Second, []iv{{10, 6}, {6, 2}, {2, 0}}},
		"backwards, rest of a third": {10, 1, 3 * time.Second, []iv{{10, 7}, {7, 4}, {4, 1}}},
	} {
		r := Request{Aggregate: agg(id.AggregateFunctionCount), Start: at(tc.start), End: at(tc.end), ProcessingInterval: tc.pi, Config: DefaultConfig()}
		var got []iv
		for i := range r.Intervals() {
			a, b := r.Interval(i)
			got = append(got, iv{a.Sub(t0).Seconds(), b.Sub(t0).Seconds()})
		}
		require.Equal(t, tc.want, got, name)
	}
}

func TestWindow(t *testing.T) {
	r := Request{Aggregate: agg(id.AggregateFunctionCount), Start: at(0), End: at(10), ProcessingInterval: 2 * time.Second, Config: DefaultConfig()}
	from, to := r.Window(0, r.Intervals())
	require.Equal(t, at(-2), from)
	require.Equal(t, at(12), to)
	from, to = r.Window(1, 2)
	require.Equal(t, at(0), from)
	require.Equal(t, at(6), to)
	// Backwards: the same time range, earliest first.
	r.Start, r.End = at(10), at(0)
	from, to = r.Window(0, r.Intervals())
	require.Equal(t, at(-2), from)
	require.Equal(t, at(12), to)
	// ProcessingInterval 0 reaches the span of the request.
	r.ProcessingInterval = 0
	from, to = r.Window(0, 1)
	require.Equal(t, at(-10), from)
	require.Equal(t, at(20), to)
}

func TestFunctions(t *testing.T) {
	fs := Functions()
	require.Len(t, fs, 36)
	seen := map[uint32]bool{}
	for _, n := range fs {
		require.True(t, Supported(n))
		require.NotEmpty(t, Name(n))
		require.NotEmpty(t, Description(n), Name(n))
		require.False(t, seen[n.IntID()])
		seen[n.IntID()] = true
	}
	require.Equal(t, "TimeAverage2", Name(agg(id.AggregateFunctionTimeAverage2)))
	for _, n := range []*ua.NodeID{nil, agg(id.AggregateFunctionAnnotationCount), ua.NewStringNodeID(0, "Average"), ua.NewNumericNodeID(2, id.AggregateFunctionAverage)} {
		require.False(t, Supported(n))
		require.Empty(t, Name(n))
		require.Empty(t, Description(n))
	}
}

func TestConfig(t *testing.T) {
	d := DefaultConfig()
	require.Equal(t, Config{TreatUncertainAsBad: true, PercentDataBad: 100, PercentDataGood: 100}, d)
	require.True(t, d.Valid())
	for _, tc := range []struct {
		good, bad uint8
		valid     bool
	}{
		{100, 100, true}, {50, 50, true}, {100, 0, true}, {0, 100, true},
		{80, 10, false}, {101, 100, false}, {100, 101, false}, {0, 0, false},
	} {
		require.Equal(t, tc.valid, Config{PercentDataGood: tc.good, PercentDataBad: tc.bad}.Valid(), "%d/%d", tc.good, tc.bad)
	}

	stepped := Config{TreatUncertainAsBad: true, PercentDataBad: 100, PercentDataGood: 100, Stepped: true}
	require.Equal(t, stepped, stepped.Override(nil))
	require.Equal(t, stepped, stepped.Override(&ua.AggregateConfiguration{}))
	require.Equal(t, stepped, stepped.Override(&ua.AggregateConfiguration{UseServerCapabilitiesDefaults: true, PercentDataBad: 1}))
	got := stepped.Override(&ua.AggregateConfiguration{PercentDataBad: 50, PercentDataGood: 60, UseSlopedExtrapolation: true})
	require.Equal(t, Config{PercentDataBad: 50, PercentDataGood: 60, UseSlopedExtrapolation: true, Stepped: true}, got)
	ac := got.AggregateConfiguration()
	require.False(t, ac.UseServerCapabilitiesDefaults)
	require.Equal(t, got, Config{Stepped: true}.Override(ac))
}

func TestNumberAndCast(t *testing.T) {
	for _, v := range []any{int8(-3), uint8(3), int16(-3), uint16(3), int32(-3), uint32(3), int64(-3), uint64(3), float32(3), float64(3), true} {
		f, ok := number(ua.MustVariant(v))
		require.True(t, ok, "%T", v)
		require.NotZero(t, f, "%T", v)
		// A value cast back keeps the type of the source.
		require.IsType(t, v, castLike(f, ua.MustVariant(v)).Value(), "%T", v)
	}
	f, ok := number(ua.MustVariant(false))
	require.True(t, ok)
	require.Zero(t, f)
	_, ok = number(ua.MustVariant("x"))
	require.False(t, ok)

	// Integers are rounded and clamped to their range.
	for _, tc := range []struct {
		f    float64
		src  any
		want any
	}{
		{2.5, int32(0), int32(3)},
		{-1000, int8(0), int8(math.MinInt8)},
		{1000, uint8(0), uint8(math.MaxUint8)},
		{-1, uint16(0), uint16(0)},
		{1e6, int16(0), int16(math.MaxInt16)},
		{1e10, uint32(0), uint32(math.MaxUint32)},
		{1e30, int64(0), int64(math.MaxInt64)},
		{-1e30, int64(0), int64(math.MinInt64)},
		{1e30, uint64(0), uint64(math.MaxUint64)},
		{12, uint64(0), uint64(12)},
		{1.25, float32(0), float32(1.25)},
		{0, true, false},
		{1.5, "text", 1.5},
	} {
		require.Equal(t, tc.want, castLike(tc.f, ua.MustVariant(tc.src)).Value(), "%v as %T", tc.f, tc.src)
	}
	require.Equal(t, 1.5, castLike(1.5, nil).Value())
}

func calc(t *testing.T, r Request, raw []*ua.DataValue) []*ua.DataValue {
	t.Helper()
	got, st := r.Calculate(raw)
	require.Equal(t, ua.StatusOK, st)
	return got
}

// TestReverse: "The calculation of all Aggregates when time flows backwards
// is the same as when time flows forwards with the exception that the
// 'early time' is excluded from the interval and the 'late time' is
// included ... when time flows forward the value at T = n is the same as
// the value at T = n + 1 when time flows backward" (Part 13 §5.4.2.2). With
// no raw value on an interval boundary both directions see the same values.
func TestReverse(t *testing.T) {
	raw := []*ua.DataValue{
		good(0.5, 1.0), good(2.5, 4.0), withStatus(good(4.5, 0.0), ua.StatusBad), good(6.5, 2.0),
		withStatus(good(8.5, 3.0), ua.StatusUncertain), good(10.5, 5.0), good(13.5, 0.0), good(14.5, 1.0),
	}
	cfg := Config{PercentDataBad: 100, PercentDataGood: 100}
	same := []uint32{
		id.AggregateFunctionAverage, id.AggregateFunctionTimeAverage, id.AggregateFunctionTimeAverage2,
		id.AggregateFunctionTotal, id.AggregateFunctionTotal2, id.AggregateFunctionMinimum,
		id.AggregateFunctionMaximum, id.AggregateFunctionRange, id.AggregateFunctionMinimum2,
		id.AggregateFunctionMaximum2, id.AggregateFunctionRange2, id.AggregateFunctionCount,
		id.AggregateFunctionDurationInStateZero, id.AggregateFunctionDurationInStateNonZero,
		id.AggregateFunctionNumberOfTransitions, id.AggregateFunctionDurationGood,
		id.AggregateFunctionDurationBad, id.AggregateFunctionPercentGood, id.AggregateFunctionPercentBad,
		id.AggregateFunctionWorstQuality, id.AggregateFunctionWorstQuality2,
		id.AggregateFunctionStandardDeviationSample, id.AggregateFunctionVarianceSample,
		id.AggregateFunctionStandardDeviationPopulation, id.AggregateFunctionVariancePopulation,
		id.AggregateFunctionMinimumActualTime, id.AggregateFunctionMaximumActualTime,
		id.AggregateFunctionMinimumActualTime2, id.AggregateFunctionMaximumActualTime2,
	}
	actualTime := map[uint32]bool{
		id.AggregateFunctionMinimumActualTime: true, id.AggregateFunctionMaximumActualTime: true,
		id.AggregateFunctionMinimumActualTime2: true, id.AggregateFunctionMaximumActualTime2: true,
	}
	for _, a := range same {
		fwd := calc(t, Request{Aggregate: agg(a), Start: at(0), End: at(16), ProcessingInterval: 4 * time.Second, Config: cfg}, raw)
		back := calc(t, Request{Aggregate: agg(a), Start: at(16), End: at(0), ProcessingInterval: 4 * time.Second, Config: cfg}, raw)
		require.Len(t, back, len(fwd))
		for i := range fwd {
			f, b := fwd[i], back[len(back)-1-i]
			require.Equal(t, f.Value, b.Value, "%s interval %d", Name(agg(a)), i)
			require.Equal(t, code(f.Status), code(b.Status), "%s interval %d", Name(agg(a)), i)
			// The ActualTime Aggregates have the time of their value.
			if !actualTime[a] {
				require.Equal(t, at(float64(4*i+4)), b.SourceTimestamp, "%s interval %d", Name(agg(a)), i)
			}
		}
	}
}

// TestNoData: without raw values every interval is Bad_NoData.
func TestNoData(t *testing.T) {
	for _, a := range Functions() {
		r := Request{Aggregate: a, Start: at(0), End: at(10), ProcessingInterval: 5 * time.Second, Config: DefaultConfig()}
		for _, raw := range [][]*ua.DataValue{nil, {nil, withStatus(&ua.DataValue{SourceTimestamp: at(1)}, ua.StatusBadNoData)}} {
			got := calc(t, r, raw)
			require.Len(t, got, 2)
			for _, dv := range got {
				require.Equal(t, ua.StatusBadNoData, dv.Status, Name(a))
				require.Nil(t, dv.Value, Name(a))
			}
		}
	}
}

// TestInvalidInputs: an Aggregate that calculates with numbers gives
// Bad_AggregateInvalidInputs for values that are not, and Bad_NotSupported
// for arrays (Part 11 §6.5.4.2); the others work on any value.
func TestInvalidInputs(t *testing.T) {
	text := []*ua.DataValue{good(0, "a"), good(2, "b"), good(4, "b"), good(7, "c")}
	arrays := []*ua.DataValue{good(0, []float64{1, 2}), good(2, []float64{3})}
	anyValue := map[uint32]bool{
		id.AggregateFunctionCount: true, id.AggregateFunctionStart: true, id.AggregateFunctionEnd: true,
		id.AggregateFunctionStartBound: true, id.AggregateFunctionEndBound: true,
		id.AggregateFunctionDurationGood: true, id.AggregateFunctionDurationBad: true,
		id.AggregateFunctionPercentGood: true, id.AggregateFunctionPercentBad: true,
		id.AggregateFunctionWorstQuality: true, id.AggregateFunctionWorstQuality2: true,
	}
	for _, a := range Functions() {
		r := Request{Aggregate: a, Start: at(1), End: at(6), ProcessingInterval: 0, Config: DefaultConfig()}
		got := calc(t, r, text)
		require.Len(t, got, 1)
		if anyValue[a.IntID()] {
			require.False(t, isBad(got[0].Status), "%s: %v", Name(a), got[0].Status)
		} else {
			require.Equal(t, ua.StatusBadAggregateInvalidInputs, got[0].Status, Name(a))
		}
		_, st := r.Calculate(arrays)
		if anyValue[a.IntID()] {
			require.Equal(t, ua.StatusOK, st, Name(a))
		} else {
			require.Equal(t, ua.StatusBadNotSupported, st, Name(a))
		}
	}
	// Start and End return the value as it is.
	got := calc(t, Request{Aggregate: agg(id.AggregateFunctionEnd), Start: at(1), End: at(6), Config: DefaultConfig()}, text)
	require.Equal(t, "b", got[0].Value.Value())
}

// TestCalculateIntervals: a part of the intervals, as a provider that pages
// its results calculates them.
func TestCalculateIntervals(t *testing.T) {
	raw := []*ua.DataValue{good(0, 1.0), good(1, 2.0), good(2, 3.0), good(3, 4.0)}
	r := Request{Aggregate: agg(id.AggregateFunctionAverage), Start: at(0), End: at(4), ProcessingInterval: time.Second, Config: DefaultConfig()}
	got, st := r.CalculateIntervals(raw, 1, 3)
	require.Equal(t, ua.StatusOK, st)
	require.Len(t, got, 2)
	require.Equal(t, 2.0, got[0].Value.Value())
	require.Equal(t, 3.0, got[1].Value.Value())
	got, st = r.CalculateIntervals(raw, -1, 100)
	require.Equal(t, ua.StatusOK, st)
	require.Len(t, got, 4)
	got, _ = r.CalculateIntervals(raw, 3, 1)
	require.Empty(t, got)
}

// TestBounds covers bounding values the examples of Annex A do not reach.
func TestBounds(t *testing.T) {
	interp := func(cfg Config, raw []*ua.DataValue, s float64) *ua.DataValue {
		t.Helper()
		got := calc(t, Request{Aggregate: agg(id.AggregateFunctionInterpolative), Start: at(s), End: at(s + 1), Config: cfg}, raw)
		return got[0]
	}
	sloped := Config{PercentDataBad: 100, PercentDataGood: 100, UseSlopedExtrapolation: true}
	// SlopedExtrapolation from the two values before (Part 13 §3.1.8).
	got := interp(sloped, []*ua.DataValue{good(0, 1.0), good(1, 2.0)}, 3)
	require.Equal(t, 4.0, got.Value.Value())
	require.Equal(t, ua.StatusUncertainDataSubNormal, code(got.Status))
	// "If only one non-Bad raw value can be found before the timestamp then
	// SteppedExtrapolation is used".
	got = interp(sloped, []*ua.DataValue{withStatus(good(0, 7.0), ua.StatusBad), good(1, 2.0)}, 3)
	require.Equal(t, 2.0, got.Value.Value())
	// Two values at the same time: the line through them is the first.
	require.Equal(t, 1.0, line(point{t: at(1), f: 1}, point{t: at(1), f: 5}, at(2)))
	// A value that is not a number holds until the next one.
	b := newSeries([]*ua.DataValue{good(0, "a"), good(2, "b")}, DefaultConfig()).interpolated(at(1), false)
	require.Equal(t, "a", b.value().Value())
	b = newSeries([]*ua.DataValue{good(0, "a"), good(2, "b")}, DefaultConfig()).simple(at(1))
	require.Equal(t, "a", b.value().Value())
}

// TestActualTimeReverse: MinimumActualTime2 of an interval read backwards
// whose minimum is the end bound, the bound at the late time as forwards,
// has the time "immediately after endTime", the early time (Part 13
// §5.4.2.4).
func TestActualTimeReverse(t *testing.T) {
	raw := []*ua.DataValue{good(0, 10.0), good(1, 9.0), good(5, 1.0)}
	cfg := Config{PercentDataBad: 100, PercentDataGood: 100}
	got := calc(t, Request{Aggregate: agg(id.AggregateFunctionMinimumActualTime2), Start: at(4), End: at(2), Config: cfg}, raw)
	require.Equal(t, 3.0, got[0].Value.Value())
	require.Equal(t, at(2).Add(Resolution), got[0].SourceTimestamp)
	require.Equal(t, ua.StatusCodeHistorianInterpolated, got[0].Status&ua.StatusCodeHistorianDataLocation)
}

// TestGaps: intervals inside the data without raw values, or with Bad ones
// only.
func TestGaps(t *testing.T) {
	cfg := Config{PercentDataBad: 100, PercentDataGood: 100}
	empty := []*ua.DataValue{good(0, 1.0), good(10, 3.0)}
	badOnly := []*ua.DataValue{withStatus(good(4.5, 0.0), ua.StatusBad), good(8, 1.0)}
	for _, a := range Functions() {
		for name, raw := range map[string][]*ua.DataValue{"empty": empty, "bad only": badOnly} {
			got := calc(t, Request{Aggregate: a, Start: at(4), End: at(6), Config: cfg}, raw)
			require.Len(t, got, 1, "%s %s", Name(a), name)
		}
	}
	for _, tc := range []struct {
		agg  uint32
		raw  []*ua.DataValue
		want ua.StatusCode
	}{
		{id.AggregateFunctionStandardDeviationSample, empty, ua.StatusBadNoData},
		{id.AggregateFunctionStart, empty, ua.StatusBadNoData},
		{id.AggregateFunctionWorstQuality, empty, ua.StatusBadNoData},
		{id.AggregateFunctionTimeAverage, badOnly, ua.StatusBadNoData},
		{id.AggregateFunctionMinimum2, badOnly, ua.StatusBadNoData},
		{id.AggregateFunctionRange2, badOnly, ua.StatusBadNoData},
		{id.AggregateFunctionDurationInStateZero, badOnly, ua.StatusBadNoData},
		{id.AggregateFunctionCount, empty, ua.StatusOK},
	} {
		got := calc(t, Request{Aggregate: agg(tc.agg), Start: at(4), End: at(6), Config: cfg}, tc.raw)
		require.Equal(t, tc.want, code(got[0].Status), Name(agg(tc.agg)))
	}
}

// TestBoundsReverse: StartBound and EndBound of an interval read backwards
// are the bounds at its start and end time in the direction of the request,
// the late and the early time.
func TestBoundsReverse(t *testing.T) {
	raw := []*ua.DataValue{good(0, 0.0), good(10, 10.0)}
	cfg := DefaultConfig()
	start := calc(t, Request{Aggregate: agg(id.AggregateFunctionStartBound), Start: at(6), End: at(2), Config: cfg}, raw)
	end := calc(t, Request{Aggregate: agg(id.AggregateFunctionEndBound), Start: at(6), End: at(2), Config: cfg}, raw)
	require.Equal(t, 6.0, start[0].Value.Value())
	require.Equal(t, 2.0, end[0].Value.Value())
}
