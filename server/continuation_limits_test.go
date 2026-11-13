// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// browseOverflow is a Browse of the Server object with room for one
// reference, so that it needs a continuation point.
func browseOverflow(hdr *ua.RequestHeader) *ua.BrowseRequest {
	return &ua.BrowseRequest{
		RequestHeader:                 hdr,
		RequestedMaxReferencesPerNode: 1,
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          ua.NewNumericNodeID(0, id.Server),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
	}
}

func browseCP(t *testing.T, svc *ViewService, hdr *ua.RequestHeader) (ua.StatusCode, []byte) {
	t.Helper()
	resp, err := svc.Browse(context.Background(), nil, browseOverflow(hdr), 1)
	require.NoError(t, err)
	r := resp.(*ua.BrowseResponse).Results[0]
	return r.StatusCode, r.ContinuationPoint
}

func browseNext(t *testing.T, svc *ViewService, hdr *ua.RequestHeader, cp []byte, release bool) ua.StatusCode {
	t.Helper()
	resp, err := svc.BrowseNext(context.Background(), nil, &ua.BrowseNextRequest{
		RequestHeader: hdr, ContinuationPoints: [][]byte{cp}, ReleaseContinuationPoints: release}, 1)
	require.NoError(t, err)
	return resp.(*ua.BrowseNextResponse).Results[0].StatusCode
}

func TestBrowseContinuationPointsSessionOwned(t *testing.T) {
	srv := newTestServer()
	srv.cfg.maxBrowseContinuationPoints = 2
	svc := &ViewService{srv: srv, cps: newCPStore[[]*ua.ReferenceDescription]()}
	srv.view = svc
	sess, hdr := activatedSession(t, srv)
	_, other := activatedSession(t, srv)

	st, cp1 := browseCP(t, svc, hdr)
	require.Equal(t, ua.StatusOK, st)
	require.NotEmpty(t, cp1)
	_, cp2 := browseCP(t, svc, hdr)
	require.NotEmpty(t, cp2)

	// Part 4 §7.9: the session holds all it may.
	st, cp := browseCP(t, svc, hdr)
	require.Equal(t, ua.StatusBadNoContinuationPoints, st)
	require.Empty(t, cp)
	// Another session has its own.
	st, cpOther := browseCP(t, svc, other)
	require.Equal(t, ua.StatusOK, st)

	// Another session cannot use or release them.
	require.Equal(t, ua.StatusBadContinuationPointInvalid, browseNext(t, svc, other, cp1, true))
	require.Equal(t, ua.StatusGood, browseNext(t, svc, hdr, cp1, false))
	require.Equal(t, ua.StatusBadContinuationPointInvalid, browseNext(t, svc, hdr, cp1, false), "a used point is gone")
	st, _ = browseCP(t, svc, hdr)
	require.Equal(t, ua.StatusOK, st, "a used point frees its place")

	// Closing the session releases its points.
	require.Equal(t, 3, svc.cps.len())
	srv.sessionRemoved(sess, SessionClosedByClient)
	require.Equal(t, 1, svc.cps.len())
	require.Equal(t, ua.StatusGood, browseNext(t, svc, other, cpOther, true))
	require.Equal(t, 0, svc.cps.len())
}

func TestContinuationPointsExpire(t *testing.T) {
	c := newCPStore[int]()
	now := time.Now()
	c.now = func() time.Time { return now }
	tok, ok := c.store("a", 1, 1)
	require.True(t, ok)
	_, ok = c.store("a", 1, 2)
	require.False(t, ok)

	now = now.Add(continuationPointTTL + time.Second)
	_, ok = c.take("a", tok)
	require.False(t, ok, "expired")
	tok2, ok := c.store("a", 1, 3)
	require.True(t, ok)
	_, ok = c.store("a", 1, 4)
	require.False(t, ok)
	now = now.Add(continuationPointTTL + time.Second)
	_, ok = c.store("a", 1, 5)
	require.True(t, ok, "an expired point frees its place")
	_, ok = c.take("a", tok2)
	require.False(t, ok)
	c.releaseSession("nobody")
}

func TestContinuationPointCapabilities(t *testing.T) {
	srv, err := New(WithMaxBrowseContinuationPoints(3), WithMaxQueryContinuationPoints(2))
	require.NoError(t, err)
	val := func(n uint32) uint32 {
		return srv.Node(ua.NewNumericNodeID(0, n)).Value().Value.Value().(uint32)
	}
	require.Equal(t, uint32(3), val(id.ServerServerCapabilitiesMaxBrowseContinuationPoints))
	require.Equal(t, uint32(2), val(id.ServerServerCapabilitiesMaxQueryContinuationPoints))
}

// denyController denies reading and browsing one node.
type denyController struct {
	DefaultAccessController
	read, browse *ua.NodeID
}

func (d denyController) CheckRead(_ context.Context, _ *Session, n *ua.NodeID) ua.StatusCode {
	if d.read != nil && n.Equal(d.read) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

func (d denyController) CheckBrowse(_ context.Context, _ *Session, n *ua.NodeID) ua.StatusCode {
	if d.browse != nil && n.Equal(d.browse) {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

func propertyQuery(hdr *ua.RequestHeader, max uint32) *ua.QueryFirstRequest {
	return &ua.QueryFirstRequest{
		RequestHeader:       hdr,
		MaxDataSetsToReturn: max,
		NodeTypes: []*ua.NodeTypeDescription{{
			TypeDefinitionNode: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, id.PropertyType), "", 0),
			DataToReturn:       []*ua.QueryDataDescription{{AttributeID: ua.AttributeIDBrowseName}},
		}},
	}
}

func TestQueryDisabledByDefault(t *testing.T) {
	srv := newTestServer()
	require.False(t, srv.cfg.query)
	svc := &QueryService{srv: srv}
	_, hdr := activatedSession(t, srv)
	_, err := svc.QueryFirst(context.Background(), nil, propertyQuery(hdr, 1), 1)
	require.Equal(t, ua.StatusBadServiceUnsupported, err)
	_, err = svc.QueryNext(context.Background(), nil, &ua.QueryNextRequest{RequestHeader: hdr, ContinuationPoint: []byte("x")}, 1)
	require.Equal(t, ua.StatusBadServiceUnsupported, err)

	on, err := newServerNoNS(WithQuery(true))
	require.NoError(t, err)
	require.True(t, on.cfg.query)
}

func TestQueryRespectsAccessControl(t *testing.T) {
	srv := newTestServer()
	srv.cfg.query = true
	svc := &QueryService{srv: srv}
	_, hdr := activatedSession(t, srv)

	resp, err := svc.QueryFirst(context.Background(), nil, propertyQuery(hdr, 0), 1)
	require.NoError(t, err)
	sets := resp.(*ua.QueryFirstResponse).QueryDataSets
	require.Greater(t, len(sets), 2)
	baseline := map[string]any{}
	var readable []*ua.NodeID
	for _, ds := range sets {
		v := ds.Values[0].Value()
		baseline[ds.NodeID.NodeID.String()] = v
		if _, st := v.(ua.StatusCode); !st {
			readable = append(readable, ds.NodeID.NodeID)
		}
	}
	require.Greater(t, len(readable), 2)
	hidden, unreadable := readable[0], readable[1]

	srv.cfg.accessController = denyController{read: unreadable, browse: hidden}
	resp, err = svc.QueryFirst(context.Background(), nil, propertyQuery(hdr, 0), 2)
	require.NoError(t, err)
	got := resp.(*ua.QueryFirstResponse).QueryDataSets
	require.Len(t, got, len(sets)-1, "a node the session may not browse is left out")
	seen := false
	for _, ds := range got {
		require.False(t, ds.NodeID.NodeID.Equal(hidden))
		if ds.NodeID.NodeID.Equal(unreadable) {
			seen = true
			require.Equal(t, ua.StatusBadUserAccessDenied, ds.Values[0].Value())
		} else {
			require.Equal(t, baseline[ds.NodeID.NodeID.String()], ds.Values[0].Value())
		}
	}
	require.True(t, seen)

	// The filter cannot read what the session may not: the attribute is
	// NULL, so an IsNull filter matches the unreadable node and not the
	// readable ones.
	q := propertyQuery(hdr, 0)
	q.Filter = &ua.ContentFilter{Elements: []*ua.ContentFilterElement{{
		FilterOperator: ua.FilterOperatorIsNull,
		FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.AttributeOperand{AttributeID: ua.AttributeIDBrowseName})},
	}}}
	resp, err = svc.QueryFirst(context.Background(), nil, q, 3)
	require.NoError(t, err)
	got = resp.(*ua.QueryFirstResponse).QueryDataSets
	matched := map[string]bool{}
	for _, ds := range got {
		matched[ds.NodeID.NodeID.String()] = true
	}
	require.True(t, matched[unreadable.String()])
	for _, n := range readable[2:] {
		require.False(t, matched[n.String()], n.String())
	}
}

func TestQueryContinuationPointsSessionOwned(t *testing.T) {
	srv := newTestServer()
	srv.cfg.query = true
	srv.cfg.maxQueryContinuationPoints = 1
	svc := &QueryService{srv: srv}
	srv.query = svc
	sess, hdr := activatedSession(t, srv)
	_, other := activatedSession(t, srv)

	resp, err := svc.QueryFirst(context.Background(), nil, propertyQuery(hdr, 1), 1)
	require.NoError(t, err)
	cp := resp.(*ua.QueryFirstResponse).ContinuationPoint
	require.NotEmpty(t, cp)

	_, err = svc.QueryFirst(context.Background(), nil, propertyQuery(hdr, 1), 2)
	require.Equal(t, ua.StatusBadNoContinuationPoints, err)

	_, err = svc.QueryNext(context.Background(), nil, &ua.QueryNextRequest{RequestHeader: other, ContinuationPoint: cp}, 3)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, err)

	srv.sessionRemoved(sess, SessionTimedOut)
	require.Equal(t, 0, svc.store().len())
	_, err = svc.QueryNext(context.Background(), nil, &ua.QueryNextRequest{RequestHeader: hdr, ContinuationPoint: cp}, 4)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, err)
}

// TestQueryRejectsOversizedFilter: a Query ContentFilter with more than
// maxFilterElements elements is Bad_ContentFilterInvalid.
func TestQueryRejectsOversizedFilter(t *testing.T) {
	srv := newTestServer()
	big := sharedChildFilter(maxFilterElements + 1)

	svc := &QueryService{srv: srv}
	srv.cfg.query = true
	_, hdr := activatedSession(t, srv)
	q := propertyQuery(hdr, 1)
	q.Filter = big
	resp, err := svc.QueryFirst(context.Background(), nil, q, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadContentFilterInvalid, resp.(*ua.QueryFirstResponse).ResponseHeader.ServiceResult)
}
