// SPDX-License-Identifier: MIT

// Package aggregate calculates the standard Aggregates of OPC 10000-13
// (Part 13 §5.4) over the raw values of a Variable: every Aggregate of
// Part 13 §5.4.3 but AnnotationCount, with the interval rules of §5.4.2,
// the bounding values of §3.1.8 and §3.1.9, the StatusCode calculation of
// §5.4.3.2 and the Aggregate bits of Part 4 §7.38.1 (Calculated,
// Interpolated, Partial, MultipleValues).
//
// A [Request] holds the time domain, the Aggregate and the [Config]; it is
// the ReadProcessedDetails of a HistoryRead (Part 11 §6.5.4) or the
// AggregateFilter of a MonitoredItem (Part 4 §7.22.4).
// [Request.Calculate] returns one value per interval:
//
//	r := aggregate.Request{
//		Aggregate:          ua.NewNumericNodeID(0, id.AggregateFunctionTimeAverage),
//		Start:              start,
//		End:                end,
//		ProcessingInterval: time.Minute,
//		Config:             aggregate.DefaultConfig(),
//	}
//	from, to := r.Window(0, r.Intervals()) // the raw values to read
//	values, status := r.Calculate(raw)
//
// The server uses the package for the processed reads of its *Historian and
// of any HistoryProvider that does not implement ProcessedHistoryReader: it
// reads the raw values of [Request.Window] with ReadRaw and calculates. A
// custom provider therefore gets the Aggregates by implementing ReadRaw
// only, and their configuration by implementing AggregateConfigProvider.
//
// The tests calculate every example of Annex A (the file
// AggregateExamples.csv of the OPC Foundation, pinned in
// schema/manifest.json) and compare each value, timestamp and StatusCode;
// where the file conflicts with a clause the clause is followed, and
// deviations_test.go lists each such row with the clause.
package aggregate
