// SPDX-License-Identifier: MIT

package aggregate

import (
	"math"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// The Aggregates of Part 13 §5.4.3. Each function calculates one interval
// that lies (partly) within the data; [interval.calculate] answers the
// intervals before the start and after the end of data, sets the Partial
// bit and drops the value of a Bad result.

// interpolative returns the Interpolated Bounding Value at the start of the
// interval (Part 13 §5.4.3.4, Table 52): Interpolated bit unless a raw value
// is at that time, never Partial; after the end of data the value is
// extrapolated and Uncertain_DataSubNormal.
func interpolative(iv *interval) *ua.DataValue {
	b := iv.s.interpolated(iv.ts, iv.s.cfg.Stepped)
	if b.bad() {
		return noValue(iv.ts, ua.StatusBadNoData)
	}
	if !b.num {
		return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
	}
	return result(iv.ts, b.value(), b.st)
}

// goodValues returns the Good raw values of the interval and whether one of
// them is not a number.
func goodValues(pts []point) (vals []point, invalid bool) {
	for _, p := range pts {
		if isGood(p.st) {
			if !p.num {
				invalid = true
			}
			vals = append(vals, p)
		}
	}
	return vals, invalid
}

// average "adds up the values of all Good Raw data for each interval, and
// divides the sum by the number of Good values" (Part 13 §5.4.3.5, Table
// 53): PercentValues, Calculated, never Partial; Bad_NoData without Good
// values.
func average(iv *interval) *ua.DataValue {
	vals, invalid := goodValues(iv.in())
	switch {
	case invalid:
		return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
	case len(vals) == 0:
		return noValue(iv.ts, ua.StatusBadNoData)
	}
	var sum float64
	for _, p := range vals {
		sum += p.f
	}
	return result(iv.ts, ua.MustVariant(sum/float64(len(vals))), iv.valueStatus(iv.in())|ua.StatusCodeHistorianCalculated)
}

// count is "a count of all the raw values within an interval. If one or
// more raw values are non-Good, they are not included in the count ... If
// no Good data exists for an interval, the count is zero" (Part 13
// §5.4.3.21, Table 69): Int32, PercentValues, Calculated.
func count(iv *interval) *ua.DataValue {
	n := int32(0)
	for _, p := range iv.in() {
		if isGood(p.st) {
			n++
		}
	}
	return result(iv.ts, ua.MustVariant(n), iv.valueStatus(iv.in())|ua.StatusCodeHistorianCalculated)
}

// deviation returns the standard deviation or the variance of the Good raw
// values, of a sample (n - 1) or of the population (n) (Part 13 §5.4.3.37
// to §5.4.3.40, Tables 85 to 88): "For every interval where n = 1, a value
// of 0 is returned. If any non-Good values were ignored, the Aggregate
// quality is uncertain/subnormal". Double, Calculated.
func deviation(sample, root bool) func(*interval) *ua.DataValue {
	return func(iv *interval) *ua.DataValue {
		vals, invalid := goodValues(iv.in())
		switch {
		case invalid:
			return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
		case len(vals) == 0:
			return noValue(iv.ts, ua.StatusBadNoData)
		}
		var mean float64
		for _, p := range vals {
			mean += p.f
		}
		mean /= float64(len(vals))
		var ss float64
		for _, p := range vals {
			ss += (p.f - mean) * (p.f - mean)
		}
		v := 0.0
		if n := float64(len(vals)); n > 1 {
			if sample {
				v = ss / (n - 1)
			} else {
				v = ss / n
			}
		}
		if root {
			v = math.Sqrt(v)
		}
		st := ua.StatusOK
		if len(vals) != len(iv.in()) {
			st = ua.StatusUncertainDataSubNormal
		}
		return result(iv.ts, ua.MustVariant(v), st|ua.StatusCodeHistorianCalculated)
	}
}

// extreme finds the minimum (or maximum) of candidates: the index of the
// first (oldest) one and whether another candidate has the same value.
func extreme(vals []point, maximum bool) (best int, multi bool) {
	best = -1
	for i, p := range vals {
		switch {
		case best < 0, maximum && p.f > vals[best].f, !maximum && p.f < vals[best].f:
			best, multi = i, false
		case p.f == vals[best].f:
			multi = true
		}
	}
	return best, multi
}

// minMax is Minimum, Maximum, MinimumActualTime and MaximumActualTime (Part
// 13 §5.4.3.10 to §5.4.3.13, Tables 58 to 61): the minimum (maximum) Good
// raw value, with the timestamp of the start of the interval or, actualTime,
// of the value. "If no Bad values then the Status is Good. If Bad values
// exist then the Status is Uncertain_DataSubNormal. If an Uncertain value is
// less than [greater than] the minimum [maximum] Good value the Status is
// Uncertain_DataSubNormal"; "If only Bad quality values are available then
// the status is returned as Bad_NoData". MultipleValues "If multiple Good
// values exist with the Minimum value", the oldest being returned.
// Minimum and Maximum are Raw when the value is at the start time of the
// interval, Calculated otherwise; the ActualTime Aggregates are Raw, and
// Calculated when the status is Uncertain_DataSubNormal "because of
// non-Good values in the interval".
func minMax(maximum, actualTime bool) func(*interval) *ua.DataValue {
	return func(iv *interval) *ua.DataValue {
		vals, invalid := goodValues(iv.in())
		switch {
		case invalid:
			return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
		case len(vals) == 0:
			return noValue(iv.ts, ua.StatusBadNoData)
		}
		best, multi := extreme(vals, maximum)
		b := vals[best]
		st := ua.StatusOK
		for _, p := range iv.in() {
			switch {
			case iv.s.bad(p.st):
				st = ua.StatusUncertainDataSubNormal
			case isUncertain(p.st) && p.num && ((maximum && p.f > b.f) || (!maximum && p.f < b.f)):
				st = ua.StatusUncertainDataSubNormal
			}
		}
		ts := iv.ts
		if actualTime {
			ts = b.t
			if st != ua.StatusOK {
				st |= ua.StatusCodeHistorianCalculated
			}
		} else if !b.t.Equal(iv.ts) || st != ua.StatusOK {
			st |= ua.StatusCodeHistorianCalculated
		}
		if multi {
			st |= ua.StatusCodeHistorianMultiValue
		}
		return result(ts, b.dv.Value, st)
	}
}

// rangeOf is "the difference between the maximum and minimum Good raw values
// in the interval. If only one Good value exists in the interval, the range
// is zero ... If non-Good values are ignored when finding the minimum or
// maximum values or if Bad values exist then the status is
// Uncertain_DataSubNormal" (Part 13 §5.4.3.14, Table 62). Calculated.
func rangeOf(iv *interval) *ua.DataValue {
	vals, invalid := goodValues(iv.in())
	switch {
	case invalid:
		return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
	case len(vals) == 0:
		return noValue(iv.ts, ua.StatusBadNoData)
	}
	lo, _ := extreme(vals, false)
	hi, _ := extreme(vals, true)
	st := ua.StatusOK
	for _, p := range iv.in() {
		switch {
		case iv.s.bad(p.st):
			st = ua.StatusUncertainDataSubNormal
		case isUncertain(p.st) && p.num && (p.f > vals[hi].f || p.f < vals[lo].f):
			st = ua.StatusUncertainDataSubNormal
		}
	}
	return result(iv.ts, castLike(vals[hi].f-vals[lo].f, vals[hi].dv.Value), st|ua.StatusCodeHistorianCalculated)
}

// startEnd is Start and End (Part 13 §5.4.3.25, §5.4.3.26, Tables 73 and
// 74): the earliest (latest) raw value in the interval, "and returns that
// value and status with the timestamp at which that value occurs. If no
// values are in the interval then the StatusCode is Bad_NoData." Raw.
func startEnd(end bool) func(*interval) *ua.DataValue {
	return func(iv *interval) *ua.DataValue {
		pts := iv.in()
		if len(pts) == 0 {
			return noValue(iv.ts, ua.StatusBadNoData)
		}
		p := pts[0]
		if end {
			p = pts[len(pts)-1]
		}
		var v *ua.Variant
		if !isBad(p.st) {
			v = p.dv.Value
		}
		return result(p.t, v, p.st&^ua.StatusCodeHistorianBits)
	}
}

// delta "retrieves the difference between the earliest and latest Good raw
// values in the interval ... The status is Uncertain_DataSubNormal if
// non-Good values are skipped while looking for the first or last values.
// The status is Good otherwise. The status is Bad_NoData if no Good raw
// values exist" (Part 13 §5.4.3.27, Table 75). Calculated.
func delta(iv *interval) *ua.DataValue {
	pts := iv.in()
	first, last := -1, -1
	for i, p := range pts {
		if isGood(p.st) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if first < 0 {
		return noValue(iv.ts, ua.StatusBadNoData)
	}
	a, b := pts[first], pts[last]
	if !a.num || !b.num {
		return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
	}
	st := ua.StatusOK
	if first > 0 || last < len(pts)-1 {
		st = ua.StatusUncertainDataSubNormal
	}
	return result(iv.ts, castLike(b.f-a.f, b.dv.Value), st|ua.StatusCodeHistorianCalculated)
}

// bounds returns the Simple Bounding Values at the start and at the end of
// the interval in the direction of the request.
func (iv *interval) bounds() (start, end bound) {
	s, e := iv.s.simple(iv.lo), iv.s.simple(iv.hi)
	if iv.reverse {
		return e, s
	}
	return s, e
}

// startBound "returns the value and status at the StartTime for the
// interval by calculating the Simple Bounding Values" (Part 13 §5.4.3.28,
// Table 76): Interpolated when the bound is, Raw when a value exists at the
// start time.
func startBound(iv *interval) *ua.DataValue {
	b, _ := iv.bounds()
	return result(iv.ts, b.value(), b.st)
}

// endBound "returns the value and status at the EndTime for the interval"
// with "The timestamp returned is always the start of the interval and
// Calculated bit is set" (Part 13 §5.4.3.29, Table 77).
func endBound(iv *interval) *ua.DataValue {
	_, b := iv.bounds()
	st := b.st &^ ua.StatusCodeHistorianDataLocation
	if !b.bad() {
		st |= ua.StatusCodeHistorianCalculated
	}
	return result(iv.ts, b.value(), st)
}

// deltaBounds "returns the difference between the StartBound and the
// EndBound Aggregates with the exception that both the start and end shall
// be Good ... If one or both values are Bad the return status will be
// Bad_NoData. If one or both values are Uncertain the status will be
// Uncertain_DataSubNormal" (Part 13 §5.4.3.30, Table 78). Calculated.
func deltaBounds(iv *interval) *ua.DataValue {
	a, b := iv.bounds()
	switch {
	case a.bad() || b.bad():
		return noValue(iv.ts, ua.StatusBadNoData)
	case !a.num || !b.num:
		return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
	}
	st := ua.StatusOK
	if isUncertain(a.st) || isUncertain(b.st) {
		st = ua.StatusUncertainDataSubNormal
	}
	return result(iv.ts, castLike(b.f-a.f, b.src), st|ua.StatusCodeHistorianCalculated)
}

// worstQuality "returns the worst status of the raw values in the interval
// where a Bad status is worse than Uncertain, which is worse than Good ...
// The server shall ignore the TreatUncertainAsBad for this aggregate. If
// multiple values exist with the worst quality the MultipleValues bit is
// set. If multiple values exist with the worst quality but different
// StatusCodes then the StatusCode of the first value is returned" (Part 13
// §5.4.3.35, Table 83). WorstQuality2 includes "The start bound calculated
// using Simple Bounding Values" (§5.4.3.36, Table 84). The value is a
// StatusCode, the status Good, Calculated. MultipleValues is set for
// several values of the worst quality when that quality is not Good, as in
// the examples of Annex A: with only Good values there is no worst value.
func worstQuality(withBound bool) func(*interval) *ua.DataValue {
	return func(iv *interval) *ua.DataValue {
		var sts []ua.StatusCode
		if withBound {
			// TreatUncertainAsBad is ignored for the bound too, which is
			// Uncertain_DataSubNormal after an Uncertain value. The bound
			// is that of the early time of the interval: "The calculation
			// of all Aggregates when time flows backwards is the same as
			// when time flows forwards" (§5.4.2.2).
			s := *iv.s
			s.cfg.TreatUncertainAsBad = false
			sts = append(sts, s.simple(iv.lo).st&^ua.StatusCodeHistorianBits)
		}
		for _, p := range iv.in() {
			sts = append(sts, p.st&^ua.StatusCodeHistorianBits)
		}
		if len(sts) == 0 {
			return noValue(iv.ts, ua.StatusBadNoData)
		}
		worst, multi := sts[0], false
		for _, st := range sts[1:] {
			switch {
			case severity(st) > severity(worst):
				worst, multi = st, false
			case severity(st) == severity(worst):
				multi = true
			}
		}
		st := ua.StatusOK | ua.StatusCodeHistorianCalculated
		if multi && !isGood(worst) {
			st |= ua.StatusCodeHistorianMultiValue
		}
		return result(iv.ts, ua.MustVariant(worst), st)
	}
}

// node is a point of the regions of an interval: a bounding value or a raw
// value.
type node struct {
	t   time.Time
	f   float64
	num bool
	st  ua.StatusCode
	v   *ua.Variant
	// bound is set for a bounding value, raw for a raw value at the time of
	// a bounding value; the time is EffectiveEndTime for the end bound.
	bound, end bool
	src        *ua.Variant
}

func boundNode(b bound, end bool) node {
	return node{t: b.t, f: b.f, num: b.num, st: b.st, v: b.value(), bound: !b.raw, end: end, src: b.src}
}

func pointNode(p point) node {
	return node{t: p.t, f: p.f, num: p.num, st: p.st, v: p.dv.Value, src: p.dv.Value}
}

// region is a part of an interval from one point to the next (Part 13
// §5.4.3.2.1: "each interval shall be divided into regions of Good or Bad
// data").
type region struct {
	from, to node
	d        time.Duration
	// st is the status of the region: that of the point it starts with,
	// and with SlopedInterpolation Uncertain_DataSubNormal when it ends in
	// a Bad or Uncertain value: "A region is Uncertain if a region ends in a
	// Bad or Uncertain value and SlopedInterpolation is used. The end point
	// has no effect on the region if SteppedInterpolation is used" (Part 13
	// §5.4.3.2.2).
	st ua.StatusCode
}

// simpleRegions divides the interval into regions with Simple Bounding
// Values (Part 13 §5.4.3.2.2): from the start bound over the raw values in
// the interval to the end bound. The time before the start of data is a
// Bad region (Bad_NoData). When the interval ends after the last raw value
// the region of that value lasts one unit of [Resolution] and the interval
// ends with it: nothing is known after the latest value of the history, and
// the width of such a partial interval "is the time used when calculating
// the partial interval" (§5.4.3.2.1).
func (iv *interval) simpleRegions() (regs []region, width time.Duration) {
	s := iv.s
	nodes := []node{boundNode(s.simple(iv.lo), false)}
	for _, p := range s.pts[s.after(iv.lo):s.at(iv.hi)] {
		nodes = append(nodes, pointNode(p))
	}
	last := s.pts[len(s.pts)-1]
	if last.t.Before(iv.hi) {
		nodes = append(nodes, node{t: last.t.Add(Resolution), st: ua.StatusBadNoData, end: true})
	} else {
		nodes = append(nodes, boundNode(s.simple(iv.hi), true))
	}
	for i := 0; i+1 < len(nodes); i++ {
		from, to := nodes[i], nodes[i+1]
		r := region{from: from, to: to, d: to.t.Sub(from.t), st: from.st &^ ua.StatusCodeHistorianBits}
		if !s.cfg.Stepped && !s.bad(from.st) && (s.bad(to.st) || isUncertain(to.st)) {
			r.st = ua.StatusUncertainDataSubNormal
		}
		regs = append(regs, r)
		width += r.d
	}
	return regs, width
}

// timeStatus is the StatusCode of a time weighted Aggregate (Part 13
// §5.4.3.2.1), PercentTime: the regions are Bad or Good, "If
// TreatUncertainAsBad = False then Uncertain regions are included with the
// Good regions when calculating the above ratios, if the TreatUncertainAsBad
// = True then the Uncertain regions are included as Bad regions", and the
// shares of their durations are compared as by [interval.valueStatus].
func (iv *interval) timeStatus(regs []region, width time.Duration) ua.StatusCode {
	var bad time.Duration
	for _, r := range regs {
		if iv.s.bad(r.st) {
			bad += r.d
		}
	}
	return percent(width, width-bad, bad, iv.s.cfg)
}

// noData reports whether none of the regions holds a value that is not Bad.
func noDataIn(regs []region) bool {
	for _, r := range regs {
		if !isBad(r.from.st) {
			return false
		}
	}
	return true
}

// timeAverage2 and total2 use Simple Bounding Values and the Stepped
// Property: "If any non-Good data exists in the interval, this data is
// omitted from the calculation and the time interval is reduced by the
// duration of the non-Good data ... If a sub-interval ends at a Bad value
// then only the Good starting value is used to calculate the area of
// sub-interval preceding the Bad value" (Part 13 §5.4.3.7, Table 55);
// "Total2 = TimeAverage2 x ProcessingInterval of Good data (seconds)"
// (§5.4.3.9, Table 57). Non-Good is Bad as TreatUncertainAsBad decides.
// PercentTime, Calculated.
func area2(iv *interval) (area float64, good time.Duration, st ua.StatusCode, ok bool) {
	regs, width := iv.simpleRegions()
	for _, r := range regs {
		if iv.s.bad(r.from.st) || r.d == 0 {
			continue
		}
		if !r.from.num {
			return 0, 0, ua.StatusBadAggregateInvalidInputs, false
		}
		v1 := r.from.f
		if !iv.s.cfg.Stepped && !iv.s.bad(r.to.st) && r.to.num {
			v1 = r.to.f
		}
		area += (r.from.f + v1) / 2 * r.d.Seconds()
		good += r.d
	}
	if noDataIn(regs) {
		return 0, 0, ua.StatusBadNoData, false
	}
	return area, good, iv.timeStatus(regs, width), good > 0
}

func timeAverage2(iv *interval) *ua.DataValue {
	area, good, st, ok := area2(iv)
	if !ok {
		return noValue(iv.ts, st|calculatedIfBad(st))
	}
	return result(iv.ts, ua.MustVariant(area/good.Seconds()), st|ua.StatusCodeHistorianCalculated)
}

func total2(iv *interval) *ua.DataValue {
	area, _, st, ok := area2(iv)
	if !ok {
		return noValue(iv.ts, st|calculatedIfBad(st))
	}
	return result(iv.ts, ua.MustVariant(area), st|ua.StatusCodeHistorianCalculated)
}

// calculatedIfBad is the Calculated bit for a Bad status that is the
// result of the StatusCode calculation, not of missing data.
func calculatedIfBad(st ua.StatusCode) ua.StatusCode {
	if st == ua.StatusBadNoData || st == ua.StatusBadAggregateInvalidInputs {
		return 0
	}
	return ua.StatusCodeHistorianCalculated
}

// area1 is the area of TimeAverage and Total: Interpolated Bounding Values
// and "a straight line is drawn between each value in the interval ending
// at the ending bounding value ... Note that this calculation always uses a
// sloped line between points" (Part 13 §5.4.3.6, Table 54). Bad values are
// omitted and make the result Uncertain_DataSubNormal, as do Uncertain
// values and bounds and an extrapolated end. Without a start bound (the
// data starts in the interval) the partial interval from the first value is
// calculated.
func area1(iv *interval) (area float64, width time.Duration, st ua.StatusCode) {
	s := iv.s
	var nodes []node
	uncertain := false
	if b := s.interpolated(iv.lo, false); !b.bad() {
		nodes = append(nodes, boundNode(b, false))
	} else {
		uncertain = true
	}
	for _, p := range s.pts[s.after(iv.lo):s.at(iv.hi)] {
		if s.bad(p.st) {
			uncertain = true
			continue
		}
		nodes = append(nodes, pointNode(p))
	}
	if b := s.interpolated(iv.hi, false); !b.bad() {
		nodes = append(nodes, boundNode(b, true))
	}
	if len(nodes) < 2 {
		return 0, 0, ua.StatusBadNoData
	}
	for i, n := range nodes {
		if !n.num {
			return 0, 0, ua.StatusBadAggregateInvalidInputs
		}
		if isUncertain(n.st) {
			uncertain = true
		}
		if i > 0 {
			d := n.t.Sub(nodes[i-1].t)
			area += (nodes[i-1].f + n.f) / 2 * d.Seconds()
			width += d
		}
	}
	st = ua.StatusOK
	if uncertain {
		st = ua.StatusUncertainDataSubNormal
	}
	return area, width, st
}

// timeAverage: "The area under the lines is divided by the length of the
// ProcessingInterval to yield the average" (Part 13 §5.4.3.6), of the
// partial interval when there is no start bound. After the end of data the
// value is extrapolated with an Uncertain status (Table 54).
func timeAverage(iv *interval) *ua.DataValue {
	area, width, st := area1(iv)
	if isBad(st) {
		return noValue(iv.ts, st)
	}
	// With two nodes or more the last is the end bound at the end of the
	// interval and the first is before it: the width is not 0.
	return result(iv.ts, ua.MustVariant(area/width.Seconds()), st|ua.StatusCodeHistorianCalculated)
}

// total: "Total = TimeAverage x ProcessingInterval (seconds)" (Part 13
// §5.4.3.8, Table 56), the area of TimeAverage.
func total(iv *interval) *ua.DataValue {
	area, _, st := area1(iv)
	if isBad(st) {
		return noValue(iv.ts, st)
	}
	return result(iv.ts, ua.MustVariant(area), st|ua.StatusCodeHistorianCalculated)
}

// minMax2 is Minimum2, Maximum2, MinimumActualTime2 and MaximumActualTime2
// (Part 13 §5.4.3.15 to §5.4.3.18, Tables 63 to 66): as Minimum, but the
// Simple Bounding Values are included and the status is that of the time
// based StatusCode calculation. "If TreatUncertainAsBad is false and an
// Uncertain raw value is the minimum then that Uncertain value is used.
// Uncertain values are ignored otherwise. If sloped interpolation is used
// and the End bound is the minimum value then End bound is used as the
// Minimum with the timestamp set to the startTime of the interval
// [EffectiveEndTime for the ActualTime Aggregates]. The End bound is
// ignored in all other cases." The start bound gives its own bits
// (Interpolated or Raw). The end bound gives Interpolated; for Minimum2 and
// Maximum2 Calculated when it is a raw value at the end time, whose time is
// not that of the result. The ActualTime Aggregates have no Calculated bit
// (Tables 65 and 66) and report the end bound at the EffectiveEndTime,
// where there is no raw value, so Interpolated, as in Annex A. A raw value
// gives Calculated (Minimum2) or Raw (the ActualTime Aggregates);
// MultipleValues when more than one candidate has the value.
func minMax2(maximum, actualTime bool) func(*interval) *ua.DataValue {
	return func(iv *interval) *ua.DataValue {
		regs, width := iv.simpleRegions()
		var cands []node
		for i, r := range regs {
			if i == 0 || !r.from.bound {
				cands = append(cands, r.from)
			}
		}
		if last := regs[len(regs)-1].to; !iv.s.cfg.Stepped && !iv.s.bad(last.st) {
			cands = append(cands, last)
		}
		best, multi := -1, false
		for i, c := range cands {
			if iv.s.bad(c.st) {
				continue
			}
			if !c.num {
				return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
			}
			switch {
			case best < 0, maximum && c.f > cands[best].f, !maximum && c.f < cands[best].f:
				best, multi = i, false
			case c.f == cands[best].f:
				multi = true
			}
		}
		if best < 0 {
			return noValue(iv.ts, ua.StatusBadNoData)
		}
		b := cands[best]
		st := iv.timeStatus(regs, width)
		ts := iv.ts
		switch {
		case b.end:
			if b.bound || actualTime {
				st |= ua.StatusCodeHistorianInterpolated
			} else {
				st |= ua.StatusCodeHistorianCalculated
			}
			if actualTime {
				ts = iv.hi.Add(-Resolution)
				if iv.reverse {
					ts = iv.lo.Add(Resolution)
				}
			}
		case best == 0:
			if b.bound {
				st |= ua.StatusCodeHistorianInterpolated
			}
		case !actualTime:
			st |= ua.StatusCodeHistorianCalculated
		}
		if actualTime && !b.end {
			ts = b.t
		}
		if multi {
			st |= ua.StatusCodeHistorianMultiValue
		}
		// A candidate is a number that is not Bad: its value is set.
		return result(ts, b.v, st)
	}
}

// range2 is "the difference between the maximum and minimum values in the
// interval as returned by the Minimum2 and Maximum2 Aggregates ... If
// Minimum2 or Maximum2 are Bad then the status is Bad_NoData. If Minimum2
// or Maximum2 are Uncertain then the status is Uncertain_DataSubNormal.
// Good otherwise" (Part 13 §5.4.3.19, Table 67). Calculated.
func range2(iv *interval) *ua.DataValue {
	lo, hi := minMax2(false, false)(iv), minMax2(true, false)(iv)
	switch {
	case lo.Status == ua.StatusBadAggregateInvalidInputs:
		return lo
	case isBad(lo.Status) || isBad(hi.Status):
		return noValue(iv.ts, ua.StatusBadNoData)
	}
	a, _ := number(lo.Value)
	b, _ := number(hi.Value)
	st := ua.StatusOK
	if isUncertain(lo.Status) || isUncertain(hi.Status) {
		st = ua.StatusUncertainDataSubNormal
	}
	return result(iv.ts, castLike(b-a, hi.Value), st|ua.StatusCodeHistorianCalculated)
}

// durationInState is DurationInStateZero and DurationInStateNonZero (Part
// 13 §5.4.3.22, §5.4.3.23, Tables 70 and 71): "the time Duration during the
// interval that the Variable was in the zero [one] state. The Simple
// Bounding Values for the interval are used to determine initial value ...
// If one or more raw values are non-Good, they are not included in the
// Duration, and the Aggregate StatusCode is determined using the StatusCode
// Calculation for time based Aggregates. Duration is in milliseconds."
// A region counts when the value it starts with, a raw value or the start
// bound, is Good: an Uncertain bound is used "as value" (Tables 70 and 71)
// and so is not included either, as in Annex A. Calculated.
func durationInState(nonZero bool) func(*interval) *ua.DataValue {
	return func(iv *interval) *ua.DataValue {
		regs, width := iv.simpleRegions()
		var d time.Duration
		for _, r := range regs {
			if !isGood(r.from.st) {
				continue
			}
			if !r.from.num {
				return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
			}
			if (r.from.f != 0) == nonZero {
				d += r.d
			}
		}
		if noDataIn(regs) {
			return noValue(iv.ts, ua.StatusBadNoData)
		}
		return result(iv.ts, ua.MustVariant(ms(d)), iv.timeStatus(regs, width)|ua.StatusCodeHistorianCalculated)
	}
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// transitions is NumberOfTransitions (Part 13 §5.4.3.24, Table 72): "The
// earliest transition shall be calculated by comparing the earliest
// non-Bad value in the interval to the previous non-Bad value. A
// transition occurred if no previous non-Bad value exists or if the
// earliest non-Bad value is different", and every later non-Bad value that
// differs from the one before it is a transition. Int32, PercentValues,
// Calculated.
func transitions(iv *interval) *ua.DataValue {
	s := iv.s
	var prev *point
	for j := iv.first - 1; j >= 0; j-- {
		if !s.bad(s.pts[j].st) {
			prev = &s.pts[j]
			break
		}
	}
	n := int32(0)
	for i := range iv.in() {
		p := &iv.in()[i]
		if s.bad(p.st) {
			continue
		}
		if !p.num {
			return noValue(iv.ts, ua.StatusBadAggregateInvalidInputs)
		}
		if prev == nil || prev.f != p.f {
			n++
		}
		prev = p
	}
	return result(iv.ts, ua.MustVariant(n), iv.valueStatus(iv.in())|ua.StatusCodeHistorianCalculated)
}

// durationGood is DurationGood, DurationBad, PercentGood and PercentBad
// (Part 13 §5.4.3.31 to §5.4.3.34, Tables 79 to 82): the interval is divided
// into regions that start with a data point, "If that data point is Good
// [Bad] the region is Good [Bad] ... The status of the first region is
// determined by finding the first data point at or before the start of the
// interval. If no value exists, the first region is Bad." The first region
// takes the status of the Simple Bounding Value. Bad is Bad as
// TreatUncertainAsBad decides; an Uncertain region is neither Good nor Bad
// when it is not. "PercentGood = DurationGood / ProcessingInterval x 100 ...
// If the last interval is a partial interval then the duration of the
// partial interval is used". The status is always Good, Calculated.
func durationGood(good, percentOf bool) func(*interval) *ua.DataValue {
	return func(iv *interval) *ua.DataValue {
		regs, width := iv.simpleRegions()
		var d time.Duration
		for _, r := range regs {
			if (good && isGood(r.from.st)) || (!good && iv.s.bad(r.from.st)) {
				d += r.d
			}
		}
		st := ua.StatusOK | ua.StatusCodeHistorianCalculated
		if percentOf {
			p := 0.0
			if width > 0 {
				p = float64(d) / float64(width) * 100
			}
			return result(iv.ts, ua.MustVariant(p), st)
		}
		return result(iv.ts, ua.MustVariant(ms(d)), st)
	}
}
