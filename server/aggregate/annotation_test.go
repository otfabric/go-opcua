// SPDX-License-Identifier: MIT

package aggregate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

func annotationAt(s float64) *ua.DataValue {
	return &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(ua.NewExtensionObject(&ua.Annotation{Message: "m"})),
		SourceTimestamp: at(s),
	}
}

// TestAnnotationCount: AnnotationCount counts the Annotations of each
// interval, not the raw values (Part 13 §5.4.3.20, Table 68): Good,
// Calculated, the timestamp of the start of the interval, Partial for the
// interval with the end of data, Bad_NoData after it; Bad entries are no
// Annotations; backwards the late time is included.
func TestAnnotationCount(t *testing.T) {
	raw := []*ua.DataValue{good(0, 1.0), good(2, 2.0), good(4, 3.0), good(6, 4.0), good(8, 5.0)}
	annotations := []*ua.DataValue{
		annotationAt(5), annotationAt(1), annotationAt(1.5), nil,
		withStatus(annotationAt(3), ua.StatusBadNoData), annotationAt(4),
	}
	r := Request{Aggregate: agg(id.AggregateFunctionAnnotationCount), Start: at(0), End: at(12), ProcessingInterval: 4 * time.Second, Config: DefaultConfig()}
	got, st := r.CalculateWithAnnotations(raw, annotations)
	require.Equal(t, ua.StatusOK, st)
	require.Len(t, got, 3)

	require.Equal(t, at(0), got[0].SourceTimestamp)
	require.Equal(t, int32(2), got[0].Value.Value())
	require.Equal(t, ua.StatusOK|ua.StatusCodeHistorianCalculated|ua.StatusCodeInfoTypeDataValue, got[0].Status)

	require.Equal(t, at(4), got[1].SourceTimestamp)
	require.Equal(t, int32(2), got[1].Value.Value())
	require.Equal(t, ua.StatusOK|ua.StatusCodeHistorianCalculated|ua.StatusCodeInfoTypeDataValue, got[1].Status)

	// [8, 12) holds the last raw value: Partial (Part 13 §5.3.3.2).
	require.Equal(t, at(8), got[2].SourceTimestamp)
	require.Equal(t, int32(0), got[2].Value.Value())
	require.Equal(t, ua.StatusOK|ua.StatusCodeHistorianCalculated|ua.StatusCodeHistorianPartial|ua.StatusCodeInfoTypeDataValue, got[2].Status)

	// After the end of data: Bad_NoData.
	r.End = at(16)
	got, st = r.CalculateWithAnnotations(raw, append(annotations, annotationAt(13)))
	require.Equal(t, ua.StatusOK, st)
	require.Len(t, got, 4)
	require.Equal(t, ua.StatusBadNoData, got[3].Status)
	require.Nil(t, got[3].Value)
	r.End = at(12)

	// Before the start of data: Bad_NoData, even with an Annotation.
	r.Start = at(-4)
	got, st = r.CalculateWithAnnotations(raw, append(annotations, annotationAt(-2)))
	require.Equal(t, ua.StatusOK, st)
	require.Equal(t, ua.StatusBadNoData, got[0].Status)
	require.Equal(t, int32(2), got[1].Value.Value())
	r.Start = at(0)

	// Without Annotations: 0 where there is data.
	got = calc(t, r, raw)
	require.Equal(t, int32(0), got[0].Value.Value())

	// Backwards: (4, 8] holds the Annotations at 5, (0, 4] those at 1, 1.5
	// and 4.
	r.Start, r.End = at(8), at(0)
	got, st = r.CalculateWithAnnotations(raw, annotations)
	require.Equal(t, ua.StatusOK, st)
	require.Len(t, got, 2)
	require.Equal(t, int32(1), got[0].Value.Value())
	require.Equal(t, int32(3), got[1].Value.Value())

	// A part of the intervals.
	r.Start, r.End = at(0), at(8)
	got, st = r.CalculateIntervalsWithAnnotations(raw, annotations, 1, 2)
	require.Equal(t, ua.StatusOK, st)
	require.Len(t, got, 1)
	require.Equal(t, int32(2), got[0].Value.Value())

	// An invalid request.
	r.ProcessingInterval = -1
	_, st = r.CalculateWithAnnotations(raw, annotations)
	require.Equal(t, ua.StatusBadInvalidArgument, st)
	_, st = r.CalculateIntervalsWithAnnotations(raw, annotations, 0, 1)
	require.Equal(t, ua.StatusBadInvalidArgument, st)
}

// TestHistoricalOnly: AnnotationCount "applies to Historical Aggregates
// only" (Part 13 §4.2.2.2, Table 5); its BrowseName and Description.
func TestHistoricalOnly(t *testing.T) {
	ac := agg(id.AggregateFunctionAnnotationCount)
	require.True(t, HistoricalOnly(ac))
	require.False(t, HistoricalOnly(agg(id.AggregateFunctionCount)))
	require.False(t, HistoricalOnly(nil))
	require.Equal(t, "AnnotationCount", Name(ac))
	require.Equal(t, "Retrieve the number of Annotations in the interval (applies to Historical Aggregates only).", Description(ac))
}
