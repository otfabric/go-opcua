// SPDX-License-Identifier: MIT

package aggregate

// The reasons of annexDeviations: each names the clause the package follows
// where the file of Annex A gives another result.
const (
	whyExtrapolated = "Tables 54 and 56: After End of Data \"Value extrapolated, Uncertain status\"; " +
		"the file returns Bad_NoData"
	whyTotalSloped = "§5.4.3.8: Total = TimeAverage x ProcessingInterval and \"always uses a SlopedInterpolation\"; " +
		"the file uses SteppedInterpolation for the Stepped Historian3, whose TimeAverage table is sloped"
	whyPercentBad = "§5.4.3.2.1: 3 s of the 5 s interval are Bad (an Uncertain value with TreatUncertainAsBad), " +
		"60 % >= PercentDataBad 50, so the interval is Bad; the file gives Uncertain_DataSubNormal"
	whyUncertainGreater = "Tables 59, 61 and 62: \"If an Uncertain value is greater than the maximum Good value " +
		"the Status is Uncertain_DataSubNormal\" (70 Uncertain at 12:01:17)"
	whyActualTimeCalculated = "Tables 60 and 61: Calculated \"Set Sometimes If the Status was set to " +
		"Uncertain_DataSubNormal because of non-Good values in the interval\"; the file leaves it out"
	whyCalculatedAlways = "Tables 69 and 72: Calculated \"Set Always\"; the file leaves it out when the interval is Bad"
	whyFirstRegion      = "§5.4.3.32: the first region has the status of the data point at or before the start, " +
		"the Uncertain value at 12:01:17, Bad with TreatUncertainAsBad; the file gives 3000 ms for the same " +
		"data and configuration in Historian2"
	whyStartBoundOnly = "§5.4.3.36: the worst status of the raw values and the start bound, TreatUncertainAsBad " +
		"ignored; the file includes the end bound as well"
)

// annexDeviations are the results of Annex A that conflict with a clause of
// Part 13; the package follows the clause. Keyed by Aggregate, data set and
// timestamp of the row; the value and status are those of the clause.
var annexDeviations = map[string]annexDeviation{
	"TimeAverage/Historian1/12:01:35.000":         {"90", "UncertainDataSubNormal, Calculated", whyExtrapolated},
	"TimeAverage/Historian2/12:01:35.000":         {"108.750", "UncertainDataSubNormal, Calculated", whyExtrapolated},
	"TimeAverage/Historian3/12:01:35.000":         {"90", "UncertainDataSubNormal, Calculated", whyExtrapolated},
	"TimeAverage/Historian5/12:01:35.000":         {"70", "UncertainDataSubNormal, Calculated", whyExtrapolated},
	"TimeAverage2/Historian3/12:00:40.000":        {"", "Bad, Calculated", whyPercentBad},
	"TimeAverage2/Historian3/12:00:45.000":        {"", "Bad, Calculated", whyPercentBad},
	"TimeAverage2/Historian3/12:01:15.000":        {"", "Bad, Calculated", whyPercentBad},
	"TimeAverage2/Historian3/12:01:20.000":        {"", "Bad, Calculated", whyPercentBad},
	"Total/Historian1/12:01:35.000":               {"450", "UncertainDataSubNormal, Calculated", whyExtrapolated},
	"Total/Historian2/12:01:35.000":               {"543.750", "UncertainDataSubNormal, Calculated", whyExtrapolated},
	"Total/Historian3/12:00:00.000":               {"31.957", "UncertainDataSubNormal, Calculated, Partial", whyTotalSloped},
	"Total/Historian3/12:00:05.000":               {"61.957", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:10.000":               {"72.826", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:15.000":               {"83.696", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:20.000":               {"94.565", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:25.000":               {"118.409", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:30.000":               {"135.227", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:35.000":               {"146.919", "UncertainDataSubNormal, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:40.000":               {"169.444", "UncertainDataSubNormal, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:45.000":               {"200", "UncertainDataSubNormal, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:50.000":               {"247.250", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:00:55.000":               {"263.750", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:01:00.000":               {"276.250", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:01:05.000":               {"288.750", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:01:10.000":               {"303.091", "UncertainDataSubNormal, Calculated", whyTotalSloped},
	"Total/Historian3/12:01:15.000":               {"325", "UncertainDataSubNormal, Calculated", whyTotalSloped},
	"Total/Historian3/12:01:20.000":               {"352.576", "UncertainDataSubNormal, Calculated", whyTotalSloped},
	"Total/Historian3/12:01:25.000":               {"418.333", "Good, Calculated", whyTotalSloped},
	"Total/Historian3/12:01:35.000":               {"450", "UncertainDataSubNormal, Calculated", whyExtrapolated},
	"Total/Historian5/12:01:35.000":               {"350", "UncertainDataSubNormal, Calculated", whyExtrapolated},
	"Total2/Historian3/12:00:40.000":              {"", "Bad, Calculated", whyPercentBad},
	"Total2/Historian3/12:00:45.000":              {"", "Bad, Calculated", whyPercentBad},
	"Total2/Historian3/12:01:15.000":              {"", "Bad, Calculated", whyPercentBad},
	"Total2/Historian3/12:01:20.000":              {"", "Bad, Calculated", whyPercentBad},
	"Maximum/Historian5/12:01:04.000":             {"30", "UncertainDataSubNormal, Calculated", whyUncertainGreater},
	"MinimumActualTime/Historian2/12:00:39.000":   {"30", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MinimumActualTime/Historian2/12:01:12.000":   {"60", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MinimumActualTime/Historian3/12:00:39.000":   {"30", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MinimumActualTime/Historian3/12:01:12.000":   {"60", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MinimumActualTime/Historian5/12:00:39.000":   {"30", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MaximumActualTime/Historian2/12:00:39.000":   {"30", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MaximumActualTime/Historian2/12:01:12.000":   {"60", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MaximumActualTime/Historian3/12:00:39.000":   {"30", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MaximumActualTime/Historian3/12:01:12.000":   {"60", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MaximumActualTime/Historian5/12:00:39.000":   {"30", "UncertainDataSubNormal, Calculated", whyActualTimeCalculated},
	"MaximumActualTime/Historian5/12:01:12.000":   {"30", "UncertainDataSubNormal, Calculated", whyUncertainGreater},
	"Range/Historian5/12:01:04.000":               {"0", "UncertainDataSubNormal, Calculated", whyUncertainGreater},
	"Count/Historian1/12:00:32.000":               {"", "Bad, Calculated", whyCalculatedAlways},
	"NumberOfTransitions/Historian1/12:00:32.000": {"", "Bad, Calculated", whyCalculatedAlways},
	"DurationBad/Historian3/12:01:20.000":         {"3000", "Good, Calculated, Partial", whyFirstRegion},
	"DurationBad/Historian4/12:01:20.000":         {"3000", "Good, Calculated, Partial", whyFirstRegion},
	"PercentBad/Historian3/12:01:20.000":          {"29.997", "Good, Calculated, Partial", whyFirstRegion},
	"PercentBad/Historian4/12:01:20.000":          {"29.997", "Good, Calculated, Partial", whyFirstRegion},
	"WorstQuality2/Historian1/12:00:16.000":       {"Good", "Good, Calculated", whyStartBoundOnly},
	"WorstQuality2/Historian1/12:00:32.000":       {"Bad", "Good, Calculated", whyStartBoundOnly},
	"WorstQuality2/Historian1/12:01:20.000":       {"Good", "Good, Calculated, Partial", whyStartBoundOnly},
	"WorstQuality2/Historian2/12:01:04.000":       {"Uncertain", "Good, Calculated", whyStartBoundOnly},
	"WorstQuality2/Historian2/12:01:20.000":       {"UncertainDataSubNormal", "Good, Calculated, Partial", whyStartBoundOnly},
	"WorstQuality2/Historian3/12:01:04.000":       {"Uncertain", "Good, Calculated", whyStartBoundOnly},
	"WorstQuality2/Historian3/12:01:20.000":       {"UncertainDataSubNormal", "Good, Calculated, Partial", whyStartBoundOnly},
	"WorstQuality2/Historian4/12:01:04.000":       {"Uncertain", "Good, Calculated", whyStartBoundOnly},
	"WorstQuality2/Historian4/12:01:20.000":       {"UncertainDataSubNormal", "Good, Calculated, Partial", whyStartBoundOnly},
	"WorstQuality2/Historian5/12:01:04.000":       {"Uncertain", "Good, Calculated", whyStartBoundOnly},
	"WorstQuality2/Historian5/12:01:20.000":       {"UncertainDataSubNormal", "Good, Calculated, Partial", whyStartBoundOnly},
}
