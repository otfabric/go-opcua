// SPDX-License-Identifier: MIT

package aggregate

import (
	"math"
	"sort"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// Resolution is the time resolution of the calculations: the
// EffectiveEndTime is "the time immediately before endTime where the time
// resolution of the Server determines the exact value", and "If there is
// one data point in the Interval and it falls on the StartTime the time
// duration used in calculations is one unit of the time resolution of the
// Server" (Part 13 §3.1.3, §5.4.2.4). It is one millisecond, the resolution
// of the examples of Annex A.
const Resolution = time.Millisecond

// point is a raw value.
type point struct {
	t  time.Time
	dv *ua.DataValue
	st ua.StatusCode
	// f is the value as a number, num whether it is one (a Boolean is 0 or
	// 1). A Bad value has none: "the value portion of Raw data that has Bad
	// status is set to null" (Part 13 §3.1.7).
	f   float64
	num bool
	// scalar is false for an array or a matrix.
	scalar bool
}

func severity(st ua.StatusCode) uint32 { return uint32(st) >> 30 }

func isGood(st ua.StatusCode) bool      { return severity(st) == 0 }
func isUncertain(st ua.StatusCode) bool { return severity(st) == 1 }
func isBad(st ua.StatusCode) bool       { return severity(st) >= 2 }

// series is the raw history of a Variable an Aggregate is calculated over.
type series struct {
	pts []point
	cfg Config
	// annotations are the times of the Annotations of the Variable, in
	// order (AnnotationCount).
	annotations []time.Time
}

// annotationTimes returns the SourceTimestamps of the Annotations of a
// Variable in order, without the entries that are Bad.
func annotationTimes(annotations []*ua.DataValue) []time.Time {
	var out []time.Time
	for _, dv := range annotations {
		if dv != nil && !isBad(dv.Status) {
			out = append(out, dv.SourceTimestamp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// annotationsIn counts the Annotations from lo to hi: [lo, hi), or (lo, hi]
// for a reverse interval, as the raw values of an interval are taken.
func (s *series) annotationsIn(lo, hi time.Time, reverse bool) int {
	pos := func(t time.Time) int {
		return sort.Search(len(s.annotations), func(i int) bool {
			if reverse {
				return s.annotations[i].After(t)
			}
			return !s.annotations[i].Before(t)
		})
	}
	return pos(hi) - pos(lo)
}

// newSeries sorts the raw values by their SourceTimestamp. Values before the
// first value that is not Bad_NoData are dropped: an entry Bad_NoData, "No
// data exists for the requested time range" (Part 11 §6.2.2, Table 25),
// before any data marks where the history starts and is not data itself;
// the Annex A data sets begin with one ("First archive entry, Point
// created") and treat the history as starting at the next value.
func newSeries(raw []*ua.DataValue, cfg Config) *series {
	pts := make([]point, 0, len(raw))
	for _, dv := range raw {
		if dv == nil {
			continue
		}
		p := point{t: dv.SourceTimestamp, dv: dv, st: dv.Status, scalar: true}
		if !isBad(p.st) && dv.Value != nil {
			p.scalar = dv.Value.ArrayLength() == 0 && len(dv.Value.ArrayDimensions()) == 0
			p.f, p.num = number(dv.Value)
		}
		pts = append(pts, p)
	}
	sort.SliceStable(pts, func(i, j int) bool { return pts[i].t.Before(pts[j].t) })
	first := 0
	for first < len(pts) && ua.StatusCode(uint32(pts[first].st)&0xFFFF0000) == ua.StatusBadNoData {
		first++
	}
	return &series{pts: pts[first:], cfg: cfg}
}

// number returns a scalar numeric or Boolean value as a float64.
func number(v *ua.Variant) (float64, bool) {
	switch n := v.Value().(type) {
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	case int8:
		return float64(n), true
	case uint8:
		return float64(n), true
	case int16:
		return float64(n), true
	case uint16:
		return float64(n), true
	case int32:
		return float64(n), true
	case uint32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// bad reports whether p counts as Bad: Bad, or Uncertain when
// TreatUncertainAsBad is set. "In all cases the TreatUncertainAsBad flag is
// used to determine whether Uncertain values are Bad or non-Bad" (Part 13
// §3.1.7).
func (s *series) bad(st ua.StatusCode) bool {
	return isBad(st) || (s.cfg.TreatUncertainAsBad && isUncertain(st))
}

// empty reports whether the series holds no data.
func (s *series) empty() bool { return len(s.pts) == 0 }

// start and end are the first and the last raw value of the history: the
// start and the end of data of Part 13 §5.3.3.2.
func (s *series) start() time.Time { return s.pts[0].t }
func (s *series) end() time.Time   { return s.pts[len(s.pts)-1].t }

// at returns the index of the first value at or after t.
func (s *series) at(t time.Time) int {
	return sort.Search(len(s.pts), func(i int) bool { return !s.pts[i].t.Before(t) })
}

// after returns the index of the first value after t.
func (s *series) after(t time.Time) int {
	return sort.Search(len(s.pts), func(i int) bool { return s.pts[i].t.After(t) })
}

// bound is a bounding value (Part 13 §3.1.7).
type bound struct {
	t   time.Time
	f   float64
	num bool
	// v is the value of a raw value used as the bound, nil for a computed
	// one; src is the value whose type a computed one has.
	v   *ua.Variant
	src *ua.Variant
	// st is the StatusCode of the bound, with the Interpolated bit when the
	// bound is not a raw value.
	st ua.StatusCode
	// raw is set when the bound is the raw value at t.
	raw bool
	// extrapolated is set when no value was found after t.
	extrapolated bool
}

func noData(t time.Time) bound { return bound{t: t, st: ua.StatusBadNoData} }

func (b bound) bad() bool { return isBad(b.st) }

func rawBound(p point) bound {
	return bound{t: p.t, f: p.f, num: p.num, v: p.dv.Value, src: p.dv.Value, st: p.st, raw: true}
}

// value returns the value of the bound in the type of its source.
func (b bound) value() *ua.Variant {
	if b.bad() {
		return nil
	}
	if b.v != nil {
		return b.v
	}
	return castLike(b.f, b.src)
}

// interpolated returns the Interpolated Bounding Value at t (Part 13
// §3.1.8). Values that count as Bad are skipped; with SlopedInterpolation
// (Stepped false, or always for TimeAverage and Total) the bound lies on the
// line from the first non-Bad value before t to the first one after it,
// and without one after t it is extrapolated, sloped through the two
// non-Bad values before t when UseSlopedExtrapolation is set and stepped
// otherwise.
func (s *series) interpolated(t time.Time, stepped bool) bound {
	i := s.at(t)
	if i < len(s.pts) && s.pts[i].t.Equal(t) && !s.bad(s.pts[i].st) {
		// "if a non-Bad Raw value exists at the timestamp then it is the
		// bounding value"
		return rawBound(s.pts[i])
	}
	// The first non-Bad value before t, and whether a Bad value lies
	// between it and t.
	before, skipped := -1, false
	for j := i - 1; j >= 0; j-- {
		if !s.bad(s.pts[j].st) {
			before = j
			break
		}
		skipped = true
	}
	if i < len(s.pts) && s.pts[i].t.Equal(t) {
		skipped = true // the Bad value at t
	}
	if before < 0 {
		// "If no non-Bad values exist before the timestamp the StatusCode is
		// Bad_NoData."
		return noData(t)
	}
	b := s.pts[before]
	// The first non-Bad value after t.
	after := -1
	for j := s.after(t); j < len(s.pts); j++ {
		if !s.bad(s.pts[j].st) {
			after = j
			break
		}
		if !stepped {
			skipped = true
		}
	}
	// "if the timestamp is after the end of the data then the bounding value
	// is treated as extrapolated and the StatusCode is Uncertain_DataSubNormal"
	// (SteppedInterpolation); "If the after value does not exist the before
	// value shall be extrapolated" (SlopedInterpolation).
	extrapolate := after < 0
	if stepped && !extrapolate {
		extrapolate = s.after(t) == len(s.pts)
	}
	out := bound{t: t, src: b.dv.Value, num: b.num, st: ua.StatusOK}
	switch {
	case !b.num:
		// A value that is not a number holds until the next one.
		out.v, out.f = b.dv.Value, b.f
		stepped = true
	case extrapolate && s.cfg.UseSlopedExtrapolation && !stepped:
		// "find the first non-Bad Raw value before timestamp; find the
		// second non-Bad Raw value before timestamp; draw a line between
		// these two values; extend the line to where it crosses the
		// timestamp". "If only one non-Bad raw value can be found before the
		// timestamp then SteppedExtrapolation is used".
		second := -1
		for j := before - 1; j >= 0; j-- {
			if !s.bad(s.pts[j].st) {
				second = j
				break
			}
		}
		if second >= 0 && s.pts[second].num {
			out.f = line(s.pts[second], b, t)
		} else {
			out.f = b.f
		}
	case extrapolate || stepped:
		out.f = b.f
	default:
		out.f = line(b, s.pts[after], t)
	}
	switch {
	case extrapolate:
		// "The StatusCode is always Uncertain_DataSubNormal" when
		// extrapolating.
		out.st = ua.StatusUncertainDataSubNormal
		out.extrapolated = true
	case skipped, isUncertain(b.st):
		// "The StatusCode is Uncertain_DataSubNormal if any Bad values exist
		// between the before value and after value. If either the before
		// value or the after value are Uncertain the StatusCode is
		// Uncertain_DataSubNormal."
		out.st = ua.StatusUncertainDataSubNormal
	case !stepped && isUncertain(s.pts[after].st):
		out.st = ua.StatusUncertainDataSubNormal
	}
	out.st |= ua.StatusCodeHistorianInterpolated
	return out
}

// simple returns the Simple Bounding Value at t (Part 13 §3.1.9): the raw
// value at t, or one estimated from the raw values immediately before and
// after t, Bad ones included. A bound beyond the last raw value is
// Bad_NoData: "If either bounding time of an interval is beyond the last
// data point then the Server may use extrapolation or return an error"
// (this package returns the error).
func (s *series) simple(t time.Time) bound {
	i := s.at(t)
	if i < len(s.pts) && s.pts[i].t.Equal(t) {
		// "if any Raw value exists at the timestamp then it is the bounding
		// value". "If a Raw value at the timestamp is Bad the StatusCode is
		// Bad_NoData."
		if s.bad(s.pts[i].st) {
			return noData(t)
		}
		return rawBound(s.pts[i])
	}
	if i == 0 || i == len(s.pts) {
		// No value before t, or t beyond the last data point.
		return noData(t)
	}
	b, a := s.pts[i-1], s.pts[i]
	if s.bad(b.st) {
		// "If the value before the timestamp is Bad the StatusCode is
		// Bad_NoData."
		return noData(t)
	}
	out := bound{t: t, src: b.dv.Value, num: b.num, f: b.f, st: ua.StatusOK}
	if !b.num {
		out.v = b.dv.Value
	}
	if isUncertain(b.st) {
		// "If the value before the timestamp is Uncertain the StatusCode is
		// Uncertain_DataSubNormal."
		out.st = ua.StatusUncertainDataSubNormal
	}
	if !s.cfg.Stepped && b.num {
		// "if the value after the timestamp is Bad then the before value is
		// the bounding value"; "If the value after the timestamp is Bad or
		// Uncertain the StatusCode is Uncertain_DataSubNormal."
		if s.bad(a.st) || isUncertain(a.st) {
			out.st = ua.StatusUncertainDataSubNormal
		}
		if !s.bad(a.st) && a.num {
			out.f = line(b, a, t)
		}
	}
	out.st |= ua.StatusCodeHistorianInterpolated
	return out
}

// line returns the value at t on the line through a and b: "Vbound =
// (Tbound - Tbefore)x( Vafter - Vbefore)/( Tafter - Tbefore) + Vbefore"
// (Part 13 §3.1.8).
func line(before, after point, t time.Time) float64 {
	dt := after.t.Sub(before.t)
	if dt == 0 {
		return before.f
	}
	return float64(t.Sub(before.t))*(after.f-before.f)/float64(dt) + before.f
}

// castLike returns f as a Variant of the type of src: the result DataType
// of most Aggregates is "Raw data type" (Part 13 §5.4.2.3, Table 50). An
// integer is rounded to the nearest value and clamped to its range.
func castLike(f float64, src *ua.Variant) *ua.Variant {
	if src == nil {
		return ua.MustVariant(f)
	}
	r := math.Round(f)
	clamp := func(lo, hi float64) float64 { return math.Max(lo, math.Min(hi, r)) }
	switch src.Value().(type) {
	case bool:
		return ua.MustVariant(f != 0)
	case int8:
		return ua.MustVariant(int8(clamp(math.MinInt8, math.MaxInt8)))
	case uint8:
		return ua.MustVariant(uint8(clamp(0, math.MaxUint8)))
	case int16:
		return ua.MustVariant(int16(clamp(math.MinInt16, math.MaxInt16)))
	case uint16:
		return ua.MustVariant(uint16(clamp(0, math.MaxUint16)))
	case int32:
		return ua.MustVariant(int32(clamp(math.MinInt32, math.MaxInt32)))
	case uint32:
		return ua.MustVariant(uint32(clamp(0, math.MaxUint32)))
	case int64:
		if r >= math.MaxInt64 {
			return ua.MustVariant(int64(math.MaxInt64))
		}
		return ua.MustVariant(int64(clamp(math.MinInt64, math.MaxInt64)))
	case uint64:
		if r >= math.MaxUint64 {
			return ua.MustVariant(uint64(math.MaxUint64))
		}
		return ua.MustVariant(uint64(clamp(0, math.MaxUint64)))
	case float32:
		return ua.MustVariant(float32(f))
	}
	return ua.MustVariant(f)
}
