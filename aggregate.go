package opcua

import (
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// aggregateTypes maps common aggregate function names to their well-known NodeIDs.
var aggregateTypes = map[string]uint32{
	"interpolative":       id.AggregateFunction_Interpolative,
	"average":             id.AggregateFunction_Average,
	"timeaverage":         id.AggregateFunction_TimeAverage,
	"total":               id.AggregateFunction_Total,
	"minimum":             id.AggregateFunction_Minimum,
	"maximum":             id.AggregateFunction_Maximum,
	"minimumactualtime":   id.AggregateFunction_MinimumActualTime,
	"maximumactualtime":   id.AggregateFunction_MaximumActualTime,
	"range":               id.AggregateFunction_Range,
	"annotationcount":     id.AggregateFunction_AnnotationCount,
	"count":               id.AggregateFunction_Count,
	"numberoftransitions": id.AggregateFunction_NumberOfTransitions,
	"start":               id.AggregateFunction_Start,
	"end":                 id.AggregateFunction_End,
	"delta":               id.AggregateFunction_Delta,
	"durationgood":        id.AggregateFunction_DurationGood,
	"durationbad":         id.AggregateFunction_DurationBad,
	"percentgood":         id.AggregateFunction_PercentGood,
	"percentbad":          id.AggregateFunction_PercentBad,
	"worstquality":        id.AggregateFunction_WorstQuality,
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
