package id

import "strings"

// aggregateTypes maps common aggregate function names to their well-known NodeIDs.
var aggregateTypes = map[string]uint32{
	"interpolative":       AggregateFunctionInterpolative,
	"average":             AggregateFunctionAverage,
	"timeaverage":         AggregateFunctionTimeAverage,
	"total":               AggregateFunctionTotal,
	"minimum":             AggregateFunctionMinimum,
	"maximum":             AggregateFunctionMaximum,
	"minimumactualtime":   AggregateFunctionMinimumActualTime,
	"maximumactualtime":   AggregateFunctionMaximumActualTime,
	"range":               AggregateFunctionRange,
	"annotationcount":     AggregateFunctionAnnotationCount,
	"count":               AggregateFunctionCount,
	"numberoftransitions": AggregateFunctionNumberOfTransitions,
	"start":               AggregateFunctionStart,
	"end":                 AggregateFunctionEnd,
	"delta":               AggregateFunctionDelta,
	"durationgood":        AggregateFunctionDurationGood,
	"durationbad":         AggregateFunctionDurationBad,
	"percentgood":         AggregateFunctionPercentGood,
	"percentbad":          AggregateFunctionPercentBad,
	"worstquality":        AggregateFunctionWorstQuality,
}

// AggregateType returns the numeric node ID for a well-known aggregate name
// (e.g. "Average", "Count", "Minimum"). The lookup is case-insensitive.
// Returns (0, false) if the name is not recognized.
func AggregateType(name string) (uint32, bool) {
	v, ok := aggregateTypes[strings.ToLower(name)]
	return v, ok
}
