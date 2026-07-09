// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestQueryService_EmptyNodeTypes(t *testing.T) {
	srv := newTestServer()
	svc := &QueryService{srv: srv, cps: make(map[string]*queryContinuation)}

	_, err := svc.QueryFirst(context.Background(), nil, &ua.QueryFirstRequest{
		RequestHeader: reqHeader(),
	}, 1)
	require.Equal(t, ua.StatusBadNothingToDo, err)
}

func TestQueryService_UnknownView(t *testing.T) {
	srv := newTestServer()
	svc := &QueryService{srv: srv, cps: make(map[string]*queryContinuation)}

	_, err := svc.QueryFirst(context.Background(), nil, &ua.QueryFirstRequest{
		RequestHeader: reqHeader(),
		View:          &ua.ViewDescription{ViewID: ua.NewNumericNodeID(0, 9999)},
		NodeTypes: []*ua.NodeTypeDescription{{
			TypeDefinitionNode: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 63), "", 0),
		}},
	}, 1)
	require.Equal(t, ua.StatusBadViewIDUnknown, err)
}

func TestQueryService_InvalidFilter(t *testing.T) {
	srv := newTestServer()
	svc := &QueryService{srv: srv, cps: make(map[string]*queryContinuation)}

	resp, err := svc.QueryFirst(context.Background(), nil, &ua.QueryFirstRequest{
		RequestHeader: reqHeader(),
		NodeTypes: []*ua.NodeTypeDescription{{
			TypeDefinitionNode: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 63), "", 0),
		}},
		Filter: &ua.ContentFilter{
			Elements: []*ua.ContentFilterElement{{FilterOperator: ua.FilterOperator(99)}},
		},
	}, 1)
	require.NoError(t, err)
	qf := resp.(*ua.QueryFirstResponse)
	require.Equal(t, ua.StatusBadContentFilterInvalid, qf.ResponseHeader.ServiceResult)
}

func TestQueryService_QueryNextUnknownToken(t *testing.T) {
	srv := newTestServer()
	svc := &QueryService{srv: srv, cps: make(map[string]*queryContinuation)}

	_, err := svc.QueryNext(context.Background(), nil, &ua.QueryNextRequest{
		RequestHeader:     reqHeader(),
		ContinuationPoint: []byte("missing"),
	}, 1)
	require.Equal(t, ua.StatusBadContinuationPointInvalid, err)
}

func TestQueryService_ScanFindsNodes(t *testing.T) {
	srv := newTestServer()
	svc := &QueryService{srv: srv, cps: make(map[string]*queryContinuation)}

	// Query for PropertyType (id=68) — a leaf type in ns-0 with no subtypes.
	// Limiting MaxDataSetsToReturn avoids walking the entire address space.
	resp, err := svc.QueryFirst(context.Background(), nil, &ua.QueryFirstRequest{
		RequestHeader:       reqHeader(),
		MaxDataSetsToReturn: 5,
		NodeTypes: []*ua.NodeTypeDescription{{
			TypeDefinitionNode: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 68), "", 0),
			IncludeSubTypes:    false,
		}},
	}, 1)
	require.NoError(t, err)
	qfr := resp.(*ua.QueryFirstResponse)
	// ns-0 has many Property nodes; at least one should be returned.
	require.NotEmpty(t, qfr.QueryDataSets)
}

func TestQueryService_ContinuationPoint(t *testing.T) {
	srv := newTestServer()
	svc := &QueryService{srv: srv, cps: make(map[string]*queryContinuation)}

	// Limit to 1 result so we get a continuation point.
	// Use PropertyType (id=68, leaf type) with no subtype expansion to keep it fast.
	resp, err := svc.QueryFirst(context.Background(), nil, &ua.QueryFirstRequest{
		RequestHeader:       reqHeader(),
		MaxDataSetsToReturn: 1,
		NodeTypes: []*ua.NodeTypeDescription{{
			TypeDefinitionNode: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 68), "", 0),
			IncludeSubTypes:    false,
		}},
	}, 1)
	require.NoError(t, err)
	qfr := resp.(*ua.QueryFirstResponse)
	require.Len(t, qfr.QueryDataSets, 1)
	// Continuation point should be set.
	require.NotEmpty(t, qfr.ContinuationPoint)

	// Retrieve the next page.
	resp2, err := svc.QueryNext(context.Background(), nil, &ua.QueryNextRequest{
		RequestHeader:     reqHeader(),
		ContinuationPoint: qfr.ContinuationPoint,
	}, 2)
	require.NoError(t, err)
	qnr := resp2.(*ua.QueryNextResponse)
	require.NotEmpty(t, qnr.QueryDataSets)
}
