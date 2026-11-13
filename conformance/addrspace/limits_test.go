// SPDX-License-Identifier: MIT

package addrspace

import (
	"context"
	"errors"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// readCapability reads a UInt32 ServerCapabilities variable.
func readCapability(t *testing.T, c *opcua.Client, n uint32) uint32 {
	t.Helper()
	dvs, err := c.ReadValues(context.Background(), ua.NewNumericNodeID(0, n))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, dvs[0].Status)
	return dvs[0].Value.Value().(uint32)
}

func reads(n int, node *ua.NodeID) []*ua.ReadValueID {
	out := make([]*ua.ReadValueID, n)
	for i := range out {
		out[i] = &ua.ReadValueID{NodeID: node, AttributeID: ua.AttributeIDValue}
	}
	return out
}

// TestOperationLimits_EnforcedAndAdvertised: a request with more operations
// than its OperationLimit fails as a whole with Bad_TooManyOperations (Part 4
// §7.38), and the limit is the one published in ServerCapabilities.
func TestOperationLimits_EnforcedAndAdvertised(t *testing.T) {
	c, f, _, _ := setupWith(t, nil, server.WithOperationLimits(server.OperationalLimits{
		MaxNodesPerRead:   4,
		MaxNodesPerBrowse: 2,
	}))
	ctx := context.Background()

	require.Equal(t, uint32(4), readCapability(t, c, id.ServerServerCapabilitiesOperationLimitsMaxNodesPerRead))
	require.Equal(t, uint32(2), readCapability(t, c, id.ServerServerCapabilitiesOperationLimitsMaxNodesPerBrowse))
	require.Equal(t, uint32(0), readCapability(t, c, id.ServerServerCapabilitiesOperationLimitsMaxNodesPerWrite), "zero: no limit")

	resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: reads(4, f.Int32)})
	require.NoError(t, err)
	require.Len(t, resp.Results, 4)
	_, err = c.Read(ctx, &ua.ReadRequest{NodesToRead: reads(5, f.Int32)})
	require.True(t, errors.Is(err, ua.StatusBadTooManyOperations), "got %v", err)

	desc := &ua.BrowseDescription{NodeID: ua.NewNumericNodeID(0, id.ObjectsFolder), BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)}
	_, err = c.Browse(ctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{desc, desc, desc}})
	require.True(t, errors.Is(err, ua.StatusBadTooManyOperations), "got %v", err)

	// The connection stays usable.
	_, err = c.Read(ctx, &ua.ReadRequest{NodesToRead: reads(1, f.Int32)})
	require.NoError(t, err)
}

// TestOperationLimits_DefaultMonitoredItemsPerCall: the default
// MaxMonitoredItemsPerCall is 32.
func TestOperationLimits_DefaultMonitoredItemsPerCall(t *testing.T) {
	c, f, ctx := setup(t)
	require.Equal(t, uint32(32), readCapability(t, c, id.ServerServerCapabilitiesOperationLimitsMaxMonitoredItemsPerCall))
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, make(chan *opcua.PublishNotificationData, 64))
	require.NoError(t, err)
	reqs := make([]*ua.MonitoredItemCreateRequest, 33)
	for i := range reqs {
		reqs[i] = opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, uint32(i))
	}
	_, err = sub.Monitor(ctx, ua.TimestampsToReturnNeither, reqs...)
	require.True(t, errors.Is(err, ua.StatusBadTooManyOperations), "got %v", err)
	resp, err := sub.Monitor(ctx, ua.TimestampsToReturnNeither, reqs[:32]...)
	require.NoError(t, err)
	require.Len(t, resp.Results, 32)
}

// TestMonitoredItemLimits: CreateMonitoredItems answers
// Bad_TooManyMonitoredItems for the items beyond a limit (Part 4 §5.12.2).
func TestMonitoredItemLimits(t *testing.T) {
	c, f, _, _ := setupWith(t, nil,
		server.WithMaxMonitoredItemsPerSubscription(3),
		server.WithMaxMonitoredItemsPerSession(4),
		server.WithMaxMonitoredItems(100))
	ctx := context.Background()
	require.Equal(t, uint32(3), readCapability(t, c, id.ServerServerCapabilitiesMaxMonitoredItemsPerSubscription))
	require.Equal(t, uint32(100), readCapability(t, c, id.ServerServerCapabilitiesMaxMonitoredItems))

	create := func(sub *opcua.Subscription, n int) []ua.StatusCode {
		reqs := make([]*ua.MonitoredItemCreateRequest, n)
		for i := range reqs {
			reqs[i] = opcua.NewMonitoredItemCreateRequestWithDefaults(f.Int32, ua.AttributeIDValue, uint32(i))
		}
		resp, err := sub.Monitor(ctx, ua.TimestampsToReturnNeither, reqs...)
		require.NoError(t, err)
		out := make([]ua.StatusCode, n)
		for i, r := range resp.Results {
			out[i] = r.StatusCode
		}
		return out
	}
	sub1, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, make(chan *opcua.PublishNotificationData, 16))
	require.NoError(t, err)
	sub2, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: fastInterval}, make(chan *opcua.PublishNotificationData, 16))
	require.NoError(t, err)

	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK, ua.StatusOK, ua.StatusBadTooManyMonitoredItems}, create(sub1, 4))
	require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusBadTooManyMonitoredItems}, create(sub2, 2), "the session limit")
}

// TestBrowseContinuationPoints_SessionBound: Browse continuation points are
// limited per session (Bad_NoContinuationPoints) and belong to their session
// (Part 4 §7.9).
func TestBrowseContinuationPoints_SessionBound(t *testing.T) {
	c, _, _, url := setupWith(t, nil, server.WithMaxBrowseContinuationPoints(1))
	other := testutil.NewTestClient(t, url)
	ctx := context.Background()
	require.Equal(t, uint32(1), readCapability(t, c, id.ServerServerCapabilitiesMaxBrowseContinuationPoints))

	browse := func(c *opcua.Client) *ua.BrowseResult {
		resp, err := c.Browse(ctx, &ua.BrowseRequest{
			RequestedMaxReferencesPerNode: 1,
			NodesToBrowse: []*ua.BrowseDescription{{NodeID: ua.NewNumericNodeID(0, id.Server), BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences), IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll)}},
		})
		require.NoError(t, err)
		return resp.Results[0]
	}
	first := browse(c)
	require.Equal(t, ua.StatusOK, first.StatusCode)
	require.NotEmpty(t, first.ContinuationPoint)
	require.Equal(t, ua.StatusBadNoContinuationPoints, browse(c).StatusCode)

	next := func(c *opcua.Client) ua.StatusCode {
		resp, err := c.BrowseNext(ctx, &ua.BrowseNextRequest{ContinuationPoints: [][]byte{first.ContinuationPoint}})
		require.NoError(t, err)
		return resp.Results[0].StatusCode
	}
	require.Equal(t, ua.StatusBadContinuationPointInvalid, next(other))
	require.Equal(t, ua.StatusOK, next(c))
	require.Equal(t, ua.StatusOK, browse(c).StatusCode, "a used point frees its place")
}

// TestQuery_ContinuationPointsSessionBound: QueryFirst continuation points
// are limited per session and belong to their session.
func TestQuery_ContinuationPointsSessionBound(t *testing.T) {
	c, f, _, url := setupWith(t, nil, server.WithQuery(true), server.WithMaxQueryContinuationPoints(1))
	other := testutil.NewTestClient(t, url)
	ctx := context.Background()
	require.Equal(t, uint32(1), readCapability(t, c, id.ServerServerCapabilitiesMaxQueryContinuationPoints))

	resp, err := queryByType(ctx, c, f.CustomVarType, true, nil, 1)
	require.NoError(t, err)
	require.NotEmpty(t, resp.ContinuationPoint)
	_, err = queryByType(ctx, c, f.CustomVarType, true, nil, 1)
	require.True(t, errors.Is(err, ua.StatusBadNoContinuationPoints), "got %v", err)

	_, err = other.QueryNext(ctx, &ua.QueryNextRequest{ContinuationPoint: resp.ContinuationPoint})
	require.True(t, errors.Is(err, ua.StatusBadContinuationPointInvalid), "got %v", err)
	next, err := c.QueryNext(ctx, &ua.QueryNextRequest{ContinuationPoint: resp.ContinuationPoint})
	require.NoError(t, err)
	require.NotEmpty(t, next.QueryDataSets)
}

// TestQuery_DisabledByDefault: without server.WithQuery the Query service
// set is not served.
func TestQuery_DisabledByDefault(t *testing.T) {
	c, f, ctx := setup(t)
	_, err := queryByType(ctx, c, f.CustomVarType, true, nil, 0)
	require.True(t, errors.Is(err, ua.StatusBadServiceUnsupported), "got %v", err)
}
