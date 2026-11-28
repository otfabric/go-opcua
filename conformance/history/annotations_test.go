// SPDX-License-Identifier: MIT

package history

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// The Annotations of a historized Variable over the wire: the Annotations
// Property (Part 11 §5.1.2), HistoryUpdate UpdateStructureDataDetails
// (§6.9.3), HistoryRead ReadAnnotationDataDetails (§6.5.6) and a raw read
// of the Property, the ExtraData bit of the raw values (Part 4 §7.38.1)
// and the AnnotationCount Aggregate (Part 13 §5.4.3.20).

// annotationSetup is historySetup with the Annotations Property on
// HistoryVar.
func annotationSetup(t *testing.T, n int) (*opcua.Client, *testutil.Fixture) {
	t.Helper()
	c, f, _, _ := setupWith(t, func(srv *server.Server, f *testutil.Fixture) {
		h := server.NewHistorian()
		h.EnableNode(f.HistoryVar, 0)
		for i := range n {
			h.RecordValue(f.HistoryVar, histSample(i, float64(i)))
		}
		srv.SetHistorian(h)
		require.NoError(t, srv.EnableAnnotations(f.HistoryVar))
	})
	return c, f
}

func note(i int, msg string) opcua.HistoryAnnotation {
	return opcua.HistoryAnnotation{Time: histAt(i), Annotation: &ua.Annotation{Message: msg, UserName: "operator", AnnotationTime: histAt(100)}}
}

// annotationsPropertyOf browses the Annotations Property of node.
func annotationsPropertyOf(t *testing.T, c *opcua.Client, node *ua.NodeID) *ua.NodeID {
	t.Helper()
	resp, err := c.Browse(context.Background(), &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: node, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: ua.NewNumericNodeID(0, id.HasProperty),
		IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll),
	}}})
	require.NoError(t, err)
	for _, r := range resp.Results[0].References {
		if r.BrowseName.Name == "Annotations" && r.BrowseName.NamespaceIndex == 0 {
			return r.NodeID.NodeID
		}
	}
	t.Fatalf("no Annotations Property on %s", node)
	return nil
}

func TestAnnotations_Property(t *testing.T) {
	parallel(t)
	c, f := annotationSetup(t, 4)
	p := annotationsPropertyOf(t, c, f.HistoryVar)
	resp, err := c.Read(context.Background(), &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
		{NodeID: p, AttributeID: ua.AttributeIDDataType},
		{NodeID: p, AttributeID: ua.AttributeIDValueRank},
		{NodeID: p, AttributeID: ua.AttributeIDAccessLevel},
	}})
	require.NoError(t, err)
	require.Equal(t, uint32(id.Annotation), resp.Results[0].Value.Value().(*ua.NodeID).IntID())
	require.Equal(t, int32(-2), resp.Results[1].Value.Value())
	al := resp.Results[2].Value.Value().(byte)
	require.NotZero(t, al&byte(ua.AccessLevelTypeHistoryRead))
	require.NotZero(t, al&byte(ua.AccessLevelTypeHistoryWrite))
}

func TestAnnotations_UpdateAndRead(t *testing.T) {
	parallel(t)
	c, f := annotationSetup(t, 4)
	ctx := context.Background()
	p := annotationsPropertyOf(t, c, f.HistoryVar)

	ops, err := c.UpdateAnnotations(ctx, f.HistoryVar, ua.PerformUpdateTypeInsert, note(1, "one"), note(3, "three"))
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted, ua.StatusGoodEntryInserted}, ops)
	// The Property as the node of the update.
	ops, err = c.UpdateAnnotations(ctx, p, ua.PerformUpdateTypeInsert, note(1, "again"), note(2, "two"))
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadEntryExists, ua.StatusGoodEntryInserted}, ops)
	ops, err = c.UpdateAnnotations(ctx, f.HistoryVar, ua.PerformUpdateTypeReplace, note(2, "dos"), note(9, "nine"))
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusBadNoEntryExists}, ops)
	ops, err = c.UpdateAnnotations(ctx, f.HistoryVar, ua.PerformUpdateTypeUpdate, note(3, "tres"), note(0, "cero"))
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryReplaced, ua.StatusGoodEntryInserted}, ops)

	// ReadAnnotationDataDetails: in the order of the reqTimes, of the node
	// and of the Property.
	for _, node := range []*ua.NodeID{f.HistoryVar, p} {
		got, err := c.ReadAnnotations(ctx, node, histAt(3), histAt(5), histAt(1))
		require.NoError(t, err)
		require.Len(t, got, 3)
		require.Equal(t, "tres", got[0].Annotation.Message)
		require.Equal(t, histAt(3), got[0].Time)
		require.Equal(t, ua.StatusBadNoData, got[1].Status)
		require.Equal(t, "one", got[2].Annotation.Message)
		require.Equal(t, "operator", got[2].Annotation.UserName)
	}

	// A raw read of the Property returns the Annotations in time order.
	res := rawHistory(t, c, p, histAt(0), histAt(10), 0, nil)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	var msgs []string
	for _, dv := range res.HistoryData.Value.(*ua.HistoryData).DataValues {
		msgs = append(msgs, dv.Value.Value().(*ua.ExtensionObject).Value.(*ua.Annotation).Message)
	}
	require.Equal(t, []string{"cero", "one", "dos", "tres"}, msgs)

	// The raw values with an Annotation carry the ExtraData bit.
	res = rawHistory(t, c, f.HistoryVar, histAt(0), histAt(10), 0, nil)
	dvs := res.HistoryData.Value.(*ua.HistoryData).DataValues
	require.Len(t, dvs, 4)
	for _, dv := range dvs {
		require.Equal(t, ua.StatusCodeHistorianExtraData, dv.Status&ua.StatusCodeHistorianExtraData, dv.SourceTimestamp)
	}

	// Remove.
	ops, err = c.UpdateAnnotations(ctx, f.HistoryVar, ua.PerformUpdateTypeRemove, opcua.HistoryAnnotation{Time: histAt(0)}, opcua.HistoryAnnotation{Time: histAt(7)})
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadNoEntryExists}, ops)
	res = rawHistory(t, c, f.HistoryVar, histAt(0), histAt(1), 1, nil)
	require.Zero(t, res.HistoryData.Value.(*ua.HistoryData).DataValues[0].Status&ua.StatusCodeHistorianExtraData)
}

// The service calls: several details in one HistoryUpdate, several nodes
// in one HistoryRead, each with its own result.
func TestAnnotations_Services(t *testing.T) {
	parallel(t)
	c, f := annotationSetup(t, 4)
	ctx := context.Background()
	value := func(i int, msg string) *ua.DataValue {
		return &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp, SourceTimestamp: histAt(i),
			Value: ua.MustVariant(ua.NewExtensionObject(&ua.Annotation{Message: msg, AnnotationTime: histAt(50)}))}
	}
	up, err := c.HistoryUpdateStructureData(ctx,
		&ua.UpdateStructureDataDetails{NodeID: f.HistoryVar, PerformInsertReplace: ua.PerformUpdateTypeInsert, UpdateValues: []*ua.DataValue{value(1, "a")}},
		&ua.UpdateStructureDataDetails{NodeID: f.NoHistoryVar, PerformInsertReplace: ua.PerformUpdateTypeInsert, UpdateValues: []*ua.DataValue{value(1, "b")}},
	)
	require.NoError(t, err)
	require.Len(t, up.Results, 2)
	require.Equal(t, ua.StatusOK, up.Results[0].StatusCode)
	require.Equal(t, []ua.StatusCode{ua.StatusGoodEntryInserted}, up.Results[0].OperationResults)
	require.True(t, up.Results[1].StatusCode&ua.StatusBad != 0)

	rd, err := c.HistoryReadAnnotations(ctx, []*ua.HistoryReadValueID{{NodeID: f.HistoryVar}, {NodeID: f.NoHistoryVar}},
		&ua.ReadAnnotationDataDetails{ReqTimes: []time.Time{histAt(1)}})
	require.NoError(t, err)
	require.Len(t, rd.Results, 2)
	require.Equal(t, ua.StatusOK, rd.Results[0].StatusCode)
	dv := rd.Results[0].HistoryData.Value.(*ua.HistoryData).DataValues[0]
	require.Equal(t, "a", dv.Value.Value().(*ua.ExtensionObject).Value.(*ua.Annotation).Message)
	require.True(t, rd.Results[1].StatusCode&ua.StatusBad != 0)
}

func TestAnnotations_Unsupported(t *testing.T) {
	parallel(t)
	c, f := annotationSetup(t, 4)
	ctx := context.Background()
	_, err := c.ReadAnnotations(ctx, f.NoHistoryVar, histAt(1))
	require.Error(t, err)
	_, err = c.UpdateAnnotations(ctx, f.NoHistoryVar, ua.PerformUpdateTypeInsert, note(1, "x"))
	require.Error(t, err)
	// A modified read of the Property is not supported.
	p := annotationsPropertyOf(t, c, f.HistoryVar)
	resp, err := c.HistoryReadRawModified(ctx, []*ua.HistoryReadValueID{{NodeID: p}},
		&ua.ReadRawModifiedDetails{IsReadModified: true, StartTime: histAt(0), EndTime: histAt(10)})
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
}

// AnnotationCount counts the Annotations of each interval (Part 13
// §5.4.3.20): Int32, Calculated; a processed read only, the AggregateFilter
// refuses it as it "applies to Historical Aggregates only" (Table 5).
func TestAnnotations_AnnotationCount(t *testing.T) {
	parallel(t)
	c, f := annotationSetup(t, 8)
	ctx := context.Background()
	_, err := c.UpdateAnnotations(ctx, f.HistoryVar, ua.PerformUpdateTypeInsert, note(0, "a"), note(1, "b"), note(2, "c"), note(5, "d"))
	require.NoError(t, err)
	resp, err := c.HistoryReadProcessed(ctx, []*ua.HistoryReadValueID{{NodeID: f.HistoryVar}}, &ua.ReadProcessedDetails{
		StartTime: histAt(0), EndTime: histAt(8), ProcessingInterval: 4000,
		AggregateType: []*ua.NodeID{ua.NewNumericNodeID(0, id.AggregateFunctionAnnotationCount)},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	dvs := resp.Results[0].HistoryData.Value.(*ua.HistoryData).DataValues
	require.Len(t, dvs, 2)
	require.Equal(t, int32(3), dvs[0].Value.Value())
	require.Equal(t, histAt(0), dvs[0].SourceTimestamp)
	require.Equal(t, ua.StatusCodeHistorianCalculated, dvs[0].Status&ua.StatusCodeHistorianCalculated)
	require.Equal(t, int32(1), dvs[1].Value.Value())

	// The AggregateFilter of a MonitoredItem.
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, make(chan *opcua.PublishNotificationData, 8))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	item := opcua.NewMonitoredItemCreateRequestWithDefaults(f.HistoryVar, ua.AttributeIDValue, 1)
	item.RequestedParameters.Filter = ua.NewExtensionObject(&ua.AggregateFilter{
		StartTime: histAt(0), ProcessingInterval: 1000,
		AggregateType: ua.NewNumericNodeID(0, id.AggregateFunctionAnnotationCount),
	})
	mres, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, item)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadAggregateNotSupported, mres.Results[0].StatusCode)
}
