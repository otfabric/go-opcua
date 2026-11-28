// SPDX-License-Identifier: MIT

package aggregate

import (
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// MaxIntervals is the most intervals one Request may have. A request with
// more is Bad_InvalidArgument: a client that needs them reads the range in
// several requests.
const MaxIntervals = 1 << 20

// Request is the time domain and the Aggregate of a processed read (the
// ReadProcessedDetails of Part 11 §6.5.4) or of an AggregateFilter (Part 4
// §7.22.4).
type Request struct {
	// Aggregate is the NodeId of the AggregateFunction Object (Part 13
	// §4.2.2), one of [Functions].
	Aggregate *ua.NodeID
	// Start and End are the startTime and the endTime. An End before Start
	// reads backwards: "If endTime is less than startTime then the data
	// shall be returned in reverse order with the later data coming first"
	// (Part 11 §6.5.4.2).
	Start, End time.Time
	// ProcessingInterval is the length of the intervals; 0 is one interval
	// from Start to End (Part 13 §5.4.3.1).
	ProcessingInterval time.Duration
	// Config is the AggregateConfiguration and the Stepped Property.
	Config Config
}

// Check returns the operation result of a request that cannot be
// calculated, Good otherwise:
//   - Bad_AggregateNotSupported for an Aggregate this package does not
//     calculate: "The requested AggregateFunction is not supported by the
//     Server for the specified Node" (Part 13 §5.3.2, Table 45);
//   - Bad_InvalidArgument when Start or End is not given, Start equals End
//     ("No intervals. Returns a Bad_InvalidArgument StatusCode", Part 13
//     §5.4.2.2, Table 49), the ProcessingInterval is negative, or the
//     request has more than [MaxIntervals] intervals;
//   - Bad_AggregateInvalidInputs for a Config that is not [Config.Valid]
//     (Part 13 §4.2.1.2).
func (r Request) Check() ua.StatusCode {
	if lookup(r.Aggregate) == nil {
		return ua.StatusBadAggregateNotSupported
	}
	if r.Start.IsZero() || r.End.IsZero() || r.Start.Equal(r.End) || r.ProcessingInterval < 0 {
		return ua.StatusBadInvalidArgument
	}
	if r.count() > MaxIntervals {
		return ua.StatusBadInvalidArgument
	}
	if !r.Config.Valid() {
		return ua.StatusBadAggregateInvalidInputs
	}
	return ua.StatusOK
}

// span is |End - Start|.
func (r Request) span() time.Duration {
	d := r.End.Sub(r.Start)
	if d < 0 {
		return -d
	}
	return d
}

func (r Request) reverse() bool { return r.End.Before(r.Start) }

// count is the number of intervals (Part 13 §5.4.2.2, Table 49): one when
// the ProcessingInterval is 0 or not less than the range, else Range/Int
// intervals and one for the rest of the range.
func (r Request) count() int {
	span, pi := r.span(), r.ProcessingInterval
	if pi <= 0 || pi >= span {
		return 1
	}
	n := span / pi
	if span%pi != 0 {
		n++
	}
	if n > MaxIntervals {
		return MaxIntervals + 1
	}
	return int(n)
}

// Intervals returns the number of intervals of the request, 0 when it does
// not pass [Request.Check].
func (r Request) Intervals() int {
	if r.Check() != ua.StatusOK {
		return 0
	}
	return r.count()
}

// Interval returns the start and the end of interval i in the direction of
// the request: [start, end) forwards, and backwards from start to end
// "with the exception that the 'early time' is excluded from the interval
// and the 'late time' is included" (Part 13 §5.4.2.2).
func (r Request) Interval(i int) (start, end time.Time) {
	pi := r.ProcessingInterval
	if pi <= 0 || pi >= r.span() {
		return r.Start, r.End
	}
	off := time.Duration(i) * pi
	if r.reverse() {
		start = r.Start.Add(-off)
		end = start.Add(-pi)
		if end.Before(r.End) {
			end = r.End
		}
		return start, end
	}
	start = r.Start.Add(off)
	end = start.Add(pi)
	if end.After(r.End) {
		end = r.End
	}
	return start, end
}

// Window returns the time range of raw values intervals first to last-1
// need, the values from before the first and after the last interval that
// the bounding values are found with included. A provider that is asked
// for an Aggregate it does not calculate itself reads its raw values of
// that range: "The period of time that is searched to discover the values
// before and after the timestamp is Server dependent ... The Server as a
// minimum should search a time range which is at least the size of the
// ProcessingInterval" (Part 13 §3.1.8, §3.1.9). The window reaches one
// ProcessingInterval, or the span of the request when that is 0 or longer,
// beyond the intervals on each side.
func (r Request) Window(first, last int) (from, to time.Time) {
	reach := r.ProcessingInterval
	if reach <= 0 || reach > r.span() {
		reach = r.span()
	}
	s0, _ := r.Interval(first)
	_, e1 := r.Interval(last - 1)
	from, to = s0, e1
	if to.Before(from) {
		from, to = to, from
	}
	return from.Add(-reach), to.Add(reach)
}

// Calculate returns the processed value of every interval of the request,
// calculated over raw, the raw values of the Variable (any order): the
// values in the time domain of the request and the values before and after
// it that bounding values need, see [Request.Window]. The first and the
// last value of raw are taken as the start and the end of data: an
// interval before the first value is "Before Start of Data", one after the
// last value "After End of Data", and the last value is taken as the latest
// value of a history that is still collecting (Part 13 §5.3.3.2). The
// status is that of [Request.Check].
func (r Request) Calculate(raw []*ua.DataValue) ([]*ua.DataValue, ua.StatusCode) {
	if st := r.Check(); st != ua.StatusOK {
		return nil, st
	}
	return r.CalculateIntervals(raw, 0, r.count())
}

// CalculateIntervals is [Request.Calculate] for the intervals first to
// last-1 only.
func (r Request) CalculateIntervals(raw []*ua.DataValue, first, last int) ([]*ua.DataValue, ua.StatusCode) {
	return r.CalculateIntervalsWithAnnotations(raw, nil, first, last)
}

// CalculateWithAnnotations is [Request.Calculate] with the Annotations of
// the Variable (Part 11 §5.1.2), which the AnnotationCount Aggregate counts
// (Part 13 §5.4.3.20): the DataValues of its Annotation history, each with
// the SourceTimestamp of the value it annotates, any order. An entry with a
// Bad StatusCode is no Annotation. The other Aggregates ignore annotations,
// and [Request.Calculate] is CalculateWithAnnotations without any: its
// AnnotationCount is 0 in every interval with data.
func (r Request) CalculateWithAnnotations(raw, annotations []*ua.DataValue) ([]*ua.DataValue, ua.StatusCode) {
	if st := r.Check(); st != ua.StatusOK {
		return nil, st
	}
	return r.CalculateIntervalsWithAnnotations(raw, annotations, 0, r.count())
}

// CalculateIntervalsWithAnnotations is [Request.CalculateWithAnnotations]
// for the intervals first to last-1 only.
func (r Request) CalculateIntervalsWithAnnotations(raw, annotations []*ua.DataValue, first, last int) ([]*ua.DataValue, ua.StatusCode) {
	if st := r.Check(); st != ua.StatusOK {
		return nil, st
	}
	f := lookup(r.Aggregate)
	s := newSeries(raw, r.Config)
	s.annotations = annotationTimes(annotations)
	if f.numeric {
		// "Not all Aggregates can be applied to arrays ... Any Aggregate
		// that can not be applied to an array, shall report Bad_NotSupported
		// for the operation result" (Part 11 §6.5.4.2).
		for _, p := range s.pts {
			if !p.scalar {
				return nil, ua.StatusBadNotSupported
			}
		}
	}
	first = max(first, 0)
	last = min(last, r.count())
	out := make([]*ua.DataValue, 0, max(last-first, 0))
	for i := first; i < last; i++ {
		iv := r.newInterval(s, i)
		out = append(out, iv.calculate(f))
	}
	return out, ua.StatusOK
}

// interval is one interval of a request, time-ordered: lo < hi.
type interval struct {
	s       *series
	lo, hi  time.Time
	reverse bool
	// ts is the start of the interval in the direction of the request, the
	// timestamp of most Aggregates: "All Aggregates return a timestamp of
	// the start of the interval unless otherwise noted" (Part 13 §5.4.2.2).
	ts time.Time
	// pi is the ProcessingInterval of the request (the whole range for 0).
	pi time.Duration
	// first and last delimit the raw values in the interval, s.pts[first:last].
	first, last int
	// partial: the interval "is not a complete interval" (Part 13
	// §5.3.3.2); beforeData and afterData: it lies wholly before the start
	// or after the end of data.
	partial, beforeData, afterData bool
}

func (r Request) newInterval(s *series, i int) *interval {
	a, b := r.Interval(i)
	iv := &interval{s: s, ts: a, reverse: r.reverse(), pi: r.ProcessingInterval}
	if iv.pi <= 0 || iv.pi > r.span() {
		iv.pi = r.span()
	}
	if iv.reverse {
		iv.lo, iv.hi = b, a
		iv.first, iv.last = s.after(iv.lo), s.after(iv.hi)
	} else {
		iv.lo, iv.hi = a, b
		iv.first, iv.last = s.at(iv.lo), s.at(iv.hi)
	}
	if s.empty() {
		iv.beforeData = true
		return iv
	}
	start, end := s.start(), s.end()
	if iv.reverse {
		iv.beforeData = iv.hi.Before(start)
		iv.afterData = !iv.lo.Before(end)
	} else {
		iv.beforeData = !iv.hi.After(start)
		iv.afterData = iv.lo.After(end)
	}
	// Part 13 §5.3.3.2: "The interval that overlaps the beginning of the
	// history collection" (the data starts inside it), "The interval that
	// overlaps the latest point stored in the history collection" (its end
	// is after the last value), and the last interval of a range the
	// ProcessingInterval does not divide evenly when "there is additional
	// data beyond the end time".
	switch {
	case iv.beforeData || iv.afterData:
	case iv.lo.Before(start) && iv.hi.After(start):
		iv.partial = true
	case !iv.lo.After(end) && iv.hi.After(end):
		iv.partial = true
	case b.Sub(a) != r.ProcessingInterval && r.ProcessingInterval > 0 && r.ProcessingInterval < r.span():
		if (iv.reverse && start.Before(iv.lo)) || (!iv.reverse && end.After(iv.hi)) {
			iv.partial = true
		}
	}
	return iv
}

// in returns the raw values in the interval.
func (iv *interval) in() []point { return iv.s.pts[iv.first:iv.last] }

// calculate returns the processed value of the interval.
func (iv *interval) calculate(f *function) *ua.DataValue {
	if iv.beforeData || (iv.afterData && !f.extrapolates) {
		// "Before Start of Data" and "After End of Data" are Bad_NoData for
		// every Aggregate but those that extrapolate (Part 13 §5.4.3, the
		// tables of each Aggregate).
		return noValue(iv.ts, ua.StatusBadNoData)
	}
	dv := f.calc(iv)
	if f.partial && iv.partial {
		dv.Status |= ua.StatusCodeHistorianPartial
	}
	if dv.Status&ua.StatusCodeHistorianBits != 0 {
		dv.Status |= ua.StatusCodeInfoTypeDataValue
	}
	if isBad(dv.Status) {
		dv.Value = nil
		dv.EncodingMask &^= ua.DataValueValue
	}
	return dv
}

// result returns a processed value with its SourceTimestamp.
func result(ts time.Time, v *ua.Variant, st ua.StatusCode) *ua.DataValue {
	dv := &ua.DataValue{
		EncodingMask:    ua.DataValueSourceTimestamp | ua.DataValueStatusCode,
		Status:          st,
		SourceTimestamp: ts,
	}
	if v != nil && !isBad(st) {
		dv.Value = v
		dv.EncodingMask |= ua.DataValueValue
	}
	return dv
}

func noValue(ts time.Time, st ua.StatusCode) *ua.DataValue { return result(ts, nil, st) }

// valueStatus is the StatusCode of an Aggregate that "operates on raw
// values (e.g. Average) the calculation is done by counting values" (Part
// 13 §5.4.3.2.1), PercentValues: Bad when the share of Bad values is at
// least PercentDataBad, Good when the share of Good values is at least
// PercentDataGood, Uncertain_DataSubNormal otherwise. "If they are equal
// [PercentDataGood = 100 - PercentDataBad] the result of the
// PercentDataGood calculation is used" (§4.2.1.2), so the Good share is
// tested first; with other valid percentages the two cannot both hold.
//
// An Uncertain value is Bad when TreatUncertainAsBad is set, and never
// Good: these Aggregates use "Good Raw data", and "the value is still
// treated as Uncertain when the StatusCode for the result is calculated"
// (§4.2.1.2), as in the examples of Annex A. An interval without values is
// Good.
func (iv *interval) valueStatus(pts []point) ua.StatusCode {
	var good, bad int
	for _, p := range pts {
		switch {
		case isGood(p.st):
			good++
		case iv.s.bad(p.st):
			bad++
		}
	}
	return percent(len(pts), good, bad, iv.s.cfg)
}

func percent[T int | time.Duration](total, good, bad T, cfg Config) ua.StatusCode {
	switch {
	case total == 0:
		return ua.StatusOK
	case float64(good)*100 >= float64(cfg.PercentDataGood)*float64(total):
		return ua.StatusOK
	case float64(bad)*100 >= float64(cfg.PercentDataBad)*float64(total):
		return ua.StatusBad
	}
	return ua.StatusUncertainDataSubNormal
}

// function is an Aggregate.
type function struct {
	id   uint32
	name string
	calc func(*interval) *ua.DataValue
	// partial: the Aggregate sets the Partial bit (Partial "Set Sometimes"
	// in its table); extrapolates: it returns a value after the end of data;
	// numeric: it cannot be applied to arrays; historical: it applies to
	// historical Aggregates only (Part 13 §4.2.2.2, Table 5).
	partial, extrapolates, numeric, historical bool
}

var functions []*function

func init() {
	functions = []*function{
		{id: id.AggregateFunctionInterpolative, name: "Interpolative", calc: interpolative, extrapolates: true, numeric: true},
		{id: id.AggregateFunctionAverage, name: "Average", calc: average, numeric: true},
		{id: id.AggregateFunctionTimeAverage, name: "TimeAverage", calc: timeAverage, partial: true, extrapolates: true, numeric: true},
		{id: id.AggregateFunctionTimeAverage2, name: "TimeAverage2", calc: timeAverage2, partial: true, numeric: true},
		{id: id.AggregateFunctionTotal, name: "Total", calc: total, partial: true, extrapolates: true, numeric: true},
		{id: id.AggregateFunctionTotal2, name: "Total2", calc: total2, partial: true, numeric: true},
		{id: id.AggregateFunctionMinimum, name: "Minimum", calc: minMax(false, false), partial: true, numeric: true},
		{id: id.AggregateFunctionMaximum, name: "Maximum", calc: minMax(true, false), partial: true, numeric: true},
		{id: id.AggregateFunctionMinimumActualTime, name: "MinimumActualTime", calc: minMax(false, true), partial: true, numeric: true},
		{id: id.AggregateFunctionMaximumActualTime, name: "MaximumActualTime", calc: minMax(true, true), partial: true, numeric: true},
		{id: id.AggregateFunctionRange, name: "Range", calc: rangeOf, partial: true, numeric: true},
		{id: id.AggregateFunctionMinimum2, name: "Minimum2", calc: minMax2(false, false), partial: true, numeric: true},
		{id: id.AggregateFunctionMaximum2, name: "Maximum2", calc: minMax2(true, false), partial: true, numeric: true},
		{id: id.AggregateFunctionMinimumActualTime2, name: "MinimumActualTime2", calc: minMax2(false, true), partial: true, numeric: true},
		{id: id.AggregateFunctionMaximumActualTime2, name: "MaximumActualTime2", calc: minMax2(true, true), partial: true, numeric: true},
		{id: id.AggregateFunctionRange2, name: "Range2", calc: range2, partial: true, numeric: true},
		{id: id.AggregateFunctionCount, name: "Count", calc: count, partial: true},
		{id: id.AggregateFunctionAnnotationCount, name: "AnnotationCount", calc: annotationCount, partial: true, historical: true},
		{id: id.AggregateFunctionDurationInStateZero, name: "DurationInStateZero", calc: durationInState(false), partial: true, numeric: true},
		{id: id.AggregateFunctionDurationInStateNonZero, name: "DurationInStateNonZero", calc: durationInState(true), partial: true, numeric: true},
		{id: id.AggregateFunctionNumberOfTransitions, name: "NumberOfTransitions", calc: transitions, partial: true, numeric: true},
		{id: id.AggregateFunctionStart, name: "Start", calc: startEnd(false), partial: true},
		{id: id.AggregateFunctionEnd, name: "End", calc: startEnd(true), partial: true},
		{id: id.AggregateFunctionDelta, name: "Delta", calc: delta, partial: true, numeric: true},
		{id: id.AggregateFunctionStartBound, name: "StartBound", calc: startBound, partial: true},
		{id: id.AggregateFunctionEndBound, name: "EndBound", calc: endBound, partial: true},
		{id: id.AggregateFunctionDeltaBounds, name: "DeltaBounds", calc: deltaBounds, partial: true, numeric: true},
		{id: id.AggregateFunctionDurationGood, name: "DurationGood", calc: durationGood(true, false), partial: true},
		{id: id.AggregateFunctionDurationBad, name: "DurationBad", calc: durationGood(false, false), partial: true},
		{id: id.AggregateFunctionPercentGood, name: "PercentGood", calc: durationGood(true, true), partial: true},
		{id: id.AggregateFunctionPercentBad, name: "PercentBad", calc: durationGood(false, true), partial: true},
		{id: id.AggregateFunctionWorstQuality, name: "WorstQuality", calc: worstQuality(false), partial: true},
		{id: id.AggregateFunctionWorstQuality2, name: "WorstQuality2", calc: worstQuality(true), partial: true},
		{id: id.AggregateFunctionStandardDeviationSample, name: "StandardDeviationSample", calc: deviation(true, true), partial: true, numeric: true},
		{id: id.AggregateFunctionVarianceSample, name: "VarianceSample", calc: deviation(true, false), partial: true, numeric: true},
		{id: id.AggregateFunctionStandardDeviationPopulation, name: "StandardDeviationPopulation", calc: deviation(false, true), partial: true, numeric: true},
		{id: id.AggregateFunctionVariancePopulation, name: "VariancePopulation", calc: deviation(false, false), partial: true, numeric: true},
	}
}

func lookup(n *ua.NodeID) *function {
	if n == nil || n.Namespace() != 0 {
		return nil
	}
	for _, f := range functions {
		if f.id == n.IntID() {
			return f
		}
	}
	return nil
}

// Supported reports whether the package calculates the Aggregate of the
// AggregateFunction Object aggregateType.
func Supported(aggregateType *ua.NodeID) bool { return lookup(aggregateType) != nil }

// Functions returns the NodeIds of the AggregateFunction Objects (Part 13
// §4.2.2) the package calculates, in the order of Part 13 §5.4.3: every
// standard Aggregate.
func Functions() []*ua.NodeID {
	out := make([]*ua.NodeID, len(functions))
	for i, f := range functions {
		out[i] = ua.NewNumericNodeID(0, f.id)
	}
	return out
}

// HistoricalOnly reports whether a supported Aggregate applies to
// historical Aggregates only: AnnotationCount, "Retrieve the number of
// Annotations in the interval (applies to Historical Aggregates only)"
// (Part 13 §4.2.2.2, Table 5). An AggregateFilter of a MonitoredItem (Part
// 4 §7.22.4) cannot use it.
func HistoricalOnly(aggregateType *ua.NodeID) bool {
	f := lookup(aggregateType)
	return f != nil && f.historical
}

// Name returns the BrowseName of a supported AggregateFunction Object
// (Part 13 §4.2.2.2, Table 5), "" for one the package does not calculate.
func Name(aggregateType *ua.NodeID) string {
	if f := lookup(aggregateType); f != nil {
		return f.name
	}
	return ""
}

// descriptions are the Description Attributes of the AggregateFunction
// Objects: "Table 5 specifies the BrowseName and Description Attributes for
// the standard Aggregate Objects. The description is the localized "en"
// text" (Part 13 §4.2.2.2).
var descriptions = map[string]string{
	"Interpolative":               "At the beginning of each interval, retrieve the calculated value from the data points on either side of the requested timestamp.",
	"Average":                     "Retrieve the average value of the data over the interval.",
	"TimeAverage":                 "Retrieve the time weighted average data over the interval using Interpolated Bounding Values.",
	"TimeAverage2":                "Retrieve the time weighted average data over the interval using Simple Bounding Values.",
	"Total":                       "Retrieve the total (time integral) of the data over the interval using Interpolated Bounding Values.",
	"Total2":                      "Retrieve the total (time integral) of the data over the interval using Simple Bounding Values.",
	"Minimum":                     "Retrieve the minimum raw value in the interval with the timestamp of the start of the interval.",
	"Maximum":                     "Retrieve the maximum raw value in the interval with the timestamp of the start of the interval.",
	"MinimumActualTime":           "Retrieve the minimum value in the interval and the timestamp of the minimum value.",
	"MaximumActualTime":           "Retrieve the maximum value in the interval and the timestamp of the maximum value.",
	"Range":                       "Retrieve the difference between the minimum and maximum value over the interval.",
	"Minimum2":                    "Retrieve the minimum value in the interval including the Simple Bounding Values.",
	"Maximum2":                    "Retrieve the maximum value in the interval including the Simple Bounding Values.",
	"MinimumActualTime2":          "Retrieve the minimum value with the actual timestamp including the Simple Bounding Values.",
	"MaximumActualTime2":          "Retrieve the maximum value with the actual timestamp including the Simple Bounding Values.",
	"Range2":                      "Retrieve the difference between the Minimum2 and Maximum2 value over the interval.",
	"Count":                       "Retrieve the number of raw values over the interval.",
	"DurationInStateZero":         "Retrieve the time a Boolean or numeric was in a zero state using Simple Bounding Values.",
	"DurationInStateNonZero":      "Retrieve the time a Boolean or numeric was in a non-zero state using Simple Bounding Values.",
	"NumberOfTransitions":         "Retrieve the number of changes between zero and non-zero that a Boolean or numeric value experienced in the interval.",
	"Start":                       "Retrieve the value at the beginning of the interval.",
	"End":                         "Retrieve the value at the end of the interval.",
	"Delta":                       "Retrieve the difference between the Start and End value in the interval.",
	"StartBound":                  "Retrieve the value at the beginning of the interval using Simple Bounding Values.",
	"EndBound":                    "Retrieve the value at the end of the interval using Simple Bounding Values.",
	"DeltaBounds":                 "Retrieve the difference between the StartBound and EndBound value in the interval using Simple Bounding Values.",
	"DurationGood":                "Retrieve the total duration of time in the interval during which the data is Good.",
	"DurationBad":                 "Retrieve the total duration of time in the interval during which the data is Bad.",
	"PercentGood":                 "Retrieve the percentage of data (0 to 100) in the interval which has Good StatusCode.",
	"PercentBad":                  "Retrieve the percentage of data (0 to 100) in the interval which has Bad StatusCode.",
	"WorstQuality":                "Retrieve the worst StatusCode of data in the interval.",
	"WorstQuality2":               "Retrieve the worst StatusCode of data in the interval including the Simple Bounding Values.",
	"StandardDeviationSample":     "Retrieve the standard deviation for the interval for a sample of the population (n-1).",
	"VarianceSample":              "Retrieve the variance for the interval as calculated by the StandardDeviationSample.",
	"StandardDeviationPopulation": "Retrieve the standard deviation for the interval for a complete population (n) which includes Simple Bounding Values.",
	"VariancePopulation":          "Retrieve the variance for the interval as calculated by the StandardDeviationPopulation which includes Simple Bounding Values.",
	"AnnotationCount":             "Retrieve the number of Annotations in the interval (applies to Historical Aggregates only).",
}

// Description returns the Description of a supported AggregateFunction
// Object, the "en" text of Part 13 Table 5, "" for one the package does not
// calculate.
func Description(aggregateType *ua.NodeID) string {
	if f := lookup(aggregateType); f != nil {
		return descriptions[f.name]
	}
	return ""
}
