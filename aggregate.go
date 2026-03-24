package opcua

import (
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// aggregateTypes maps common aggregate function names to their well-known NodeIDs.
var aggregateTypes = map[string]uint32{
	"interpolative":       id.AggregateFunctionInterpolative,
	"average":             id.AggregateFunctionAverage,
	"timeaverage":         id.AggregateFunctionTimeAverage,
	"total":               id.AggregateFunctionTotal,
	"minimum":             id.AggregateFunctionMinimum,
	"maximum":             id.AggregateFunctionMaximum,
	"minimumactualtime":   id.AggregateFunctionMinimumActualTime,
	"maximumactualtime":   id.AggregateFunctionMaximumActualTime,
	"range":               id.AggregateFunctionRange,
	"annotationcount":     id.AggregateFunctionAnnotationCount,
	"count":               id.AggregateFunctionCount,
	"numberoftransitions": id.AggregateFunctionNumberOfTransitions,
	"start":               id.AggregateFunctionStart,
	"end":                 id.AggregateFunctionEnd,
	"delta":               id.AggregateFunctionDelta,
	"durationgood":        id.AggregateFunctionDurationGood,
	"durationbad":         id.AggregateFunctionDurationBad,
	"percentgood":         id.AggregateFunctionPercentGood,
	"percentbad":          id.AggregateFunctionPercentBad,
	"worstquality":        id.AggregateFunctionWorstQuality,
}

// AggregateType maps a human-readable aggregate name (e.g. "Average", "Count",
// "Minimum") to its well-known NodeID. The lookup is case-insensitive.
// Returns nil if the name is not recognized.
func AggregateType(name string) *ua.NodeID {
	v, ok := aggregateTypes[strings.ToLower(name)]
	if !ok {
		return nil
	}
	return ua.NewNumericNodeID(0, v)
}
