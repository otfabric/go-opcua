package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestViewService_Browse(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	svc := &ViewService{srv: srv}

	t.Run("browse objects folder returns references", func(t *testing.T) {
		req := &ua.BrowseRequest{
			RequestHeader: reqHeader(),
			NodesToBrowse: []*ua.BrowseDescription{
				{
					NodeID:          ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
					BrowseDirection: ua.BrowseDirectionForward,
					ReferenceTypeID: ua.NewNumericNodeID(0, 0), // all types
					IncludeSubtypes: true,
					NodeClassMask:   0, // all classes
					ResultMask:      uint32(ua.BrowseResultMaskAll),
				},
			},
		}
		resp, err := svc.Browse(context.Background(), nil, req, 1)
		require.NoError(t, err)

		browseResp := resp.(*ua.BrowseResponse)
		require.Len(t, browseResp.Results, 1)
		assert.Equal(t, ua.StatusGood, browseResp.Results[0].StatusCode)
		assert.NotEmpty(t, browseResp.Results[0].References, "should have child references")
	})

	t.Run("browse with forward direction filters correctly", func(t *testing.T) {
		req := &ua.BrowseRequest{
			RequestHeader: reqHeader(),
			NodesToBrowse: []*ua.BrowseDescription{
				{
					NodeID:          ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
					BrowseDirection: ua.BrowseDirectionForward,
					ReferenceTypeID: ua.NewNumericNodeID(0, 0),
					IncludeSubtypes: true,
					NodeClassMask:   0,
					ResultMask:      uint32(ua.BrowseResultMaskAll),
				},
			},
		}
		resp, err := svc.Browse(context.Background(), nil, req, 1)
		require.NoError(t, err)

		browseResp := resp.(*ua.BrowseResponse)
		for _, ref := range browseResp.Results[0].References {
			assert.True(t, ref.IsForward, "all references should be forward when BrowseDirectionForward")
		}
	})

	t.Run("browse unknown node returns bad status", func(t *testing.T) {
		req := &ua.BrowseRequest{
			RequestHeader: reqHeader(),
			NodesToBrowse: []*ua.BrowseDescription{
				{
					NodeID:          ua.NewStringNodeID(ns.ID(), "nonexistent"),
					BrowseDirection: ua.BrowseDirectionBoth,
					ReferenceTypeID: ua.NewNumericNodeID(0, 0),
					IncludeSubtypes: true,
					NodeClassMask:   0,
					ResultMask:      uint32(ua.BrowseResultMaskAll),
				},
			},
		}
		resp, err := svc.Browse(context.Background(), nil, req, 1)
		require.NoError(t, err)

		browseResp := resp.(*ua.BrowseResponse)
		require.Len(t, browseResp.Results, 1)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, browseResp.Results[0].StatusCode)
	})

	t.Run("browse unknown namespace returns bad status", func(t *testing.T) {
		req := &ua.BrowseRequest{
			RequestHeader: reqHeader(),
			NodesToBrowse: []*ua.BrowseDescription{
				{
					NodeID:          ua.NewNumericNodeID(99, id.ObjectsFolder),
					BrowseDirection: ua.BrowseDirectionBoth,
					ReferenceTypeID: ua.NewNumericNodeID(0, 0),
					IncludeSubtypes: true,
					ResultMask:      uint32(ua.BrowseResultMaskAll),
				},
			},
		}
		resp, err := svc.Browse(context.Background(), nil, req, 1)
		require.NoError(t, err)

		browseResp := resp.(*ua.BrowseResponse)
		require.Len(t, browseResp.Results, 1)
		assert.Equal(t, ua.StatusBad, browseResp.Results[0].StatusCode)
	})

	t.Run("browse multiple nodes", func(t *testing.T) {
		req := &ua.BrowseRequest{
			RequestHeader: reqHeader(),
			NodesToBrowse: []*ua.BrowseDescription{
				{
					NodeID:          ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
					BrowseDirection: ua.BrowseDirectionBoth,
					ReferenceTypeID: ua.NewNumericNodeID(0, 0),
					IncludeSubtypes: true,
					ResultMask:      uint32(ua.BrowseResultMaskAll),
				},
				{
					NodeID:          ua.NewStringNodeID(ns.ID(), "nonexistent"),
					BrowseDirection: ua.BrowseDirectionBoth,
					ReferenceTypeID: ua.NewNumericNodeID(0, 0),
					IncludeSubtypes: true,
					ResultMask:      uint32(ua.BrowseResultMaskAll),
				},
			},
		}
		resp, err := svc.Browse(context.Background(), nil, req, 1)
		require.NoError(t, err)

		browseResp := resp.(*ua.BrowseResponse)
		require.Len(t, browseResp.Results, 2)
		assert.Equal(t, ua.StatusGood, browseResp.Results[0].StatusCode)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, browseResp.Results[1].StatusCode)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.Browse(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestViewService_BrowseDirection(t *testing.T) {
	tests := []struct {
		name      string
		direction ua.BrowseDirection
		isForward bool
		want      bool
	}{
		{"both + forward", ua.BrowseDirectionBoth, true, true},
		{"both + inverse", ua.BrowseDirectionBoth, false, true},
		{"forward + forward", ua.BrowseDirectionForward, true, true},
		{"forward + inverse", ua.BrowseDirectionForward, false, false},
		{"inverse + forward", ua.BrowseDirectionInverse, true, false},
		{"inverse + inverse", ua.BrowseDirectionInverse, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := suitableDirection(tt.direction, tt.isForward)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestViewService_UnsupportedMethods(t *testing.T) {
	srv := newTestServer()
	svc := &ViewService{srv: srv, cps: make(map[string]*continuationPoint)}

	t.Run("BrowseNext empty", func(t *testing.T) {
		resp, err := svc.BrowseNext(context.Background(), nil, &ua.BrowseNextRequest{RequestHeader: reqHeader()}, 1)
		require.NoError(t, err)
		browseResp := resp.(*ua.BrowseNextResponse)
		assert.Empty(t, browseResp.Results)
	})

	t.Run("TranslateBrowsePathsToNodeIDs empty", func(t *testing.T) {
		resp, err := svc.TranslateBrowsePathsToNodeIDs(context.Background(), nil, &ua.TranslateBrowsePathsToNodeIDsRequest{RequestHeader: reqHeader()}, 1)
		require.NoError(t, err)
		transResp := resp.(*ua.TranslateBrowsePathsToNodeIDsResponse)
		assert.Empty(t, transResp.Results)
	})

	t.Run("RegisterNodes", func(t *testing.T) {
		resp, err := svc.RegisterNodes(context.Background(), nil, &ua.RegisterNodesRequest{RequestHeader: reqHeader()}, 1)
		require.NoError(t, err)
		regResp := resp.(*ua.RegisterNodesResponse)
		assert.Equal(t, ua.StatusOK, regResp.ResponseHeader.ServiceResult)
	})

	t.Run("UnregisterNodes", func(t *testing.T) {
		resp, err := svc.UnregisterNodes(context.Background(), nil, &ua.UnregisterNodesRequest{RequestHeader: reqHeader()}, 1)
		require.NoError(t, err)
		unregResp := resp.(*ua.UnregisterNodesResponse)
		assert.Equal(t, ua.StatusOK, unregResp.ResponseHeader.ServiceResult)
	})
}

func TestViewService_BrowseNext(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &ViewService{srv: srv, cps: make(map[string]*continuationPoint)}

	// Add enough children to produce a continuation point.
	for i := 0; i < 5; i++ {
		n := ns.AddNewVariableStringNode("child_"+string(rune('a'+i)), int32(i))
		obj.AddRef(n, id.HasComponent, true)
	}

	t.Run("browse with max refs produces continuation point", func(t *testing.T) {
		req := &ua.BrowseRequest{
			RequestHeader:                 reqHeader(),
			RequestedMaxReferencesPerNode: 2,
			NodesToBrowse: []*ua.BrowseDescription{{
				NodeID:          ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, 0),
				IncludeSubtypes: true,
				ResultMask:      uint32(ua.BrowseResultMaskAll),
			}},
		}
		resp, err := svc.Browse(context.Background(), nil, req, 1)
		require.NoError(t, err)

		browseResp := resp.(*ua.BrowseResponse)
		require.Len(t, browseResp.Results, 1)
		result := browseResp.Results[0]
		assert.Equal(t, ua.StatusGood, result.StatusCode)
		assert.Len(t, result.References, 2)
		assert.NotEmpty(t, result.ContinuationPoint, "should have a continuation point")

		// BrowseNext to get remaining references.
		nextReq := &ua.BrowseNextRequest{
			RequestHeader:             reqHeader(),
			ReleaseContinuationPoints: false,
			ContinuationPoints:        [][]byte{result.ContinuationPoint},
		}
		nextResp, err := svc.BrowseNext(context.Background(), nil, nextReq, 2)
		require.NoError(t, err)

		browseNextResp := nextResp.(*ua.BrowseNextResponse)
		require.Len(t, browseNextResp.Results, 1)
		assert.Equal(t, ua.StatusGood, browseNextResp.Results[0].StatusCode)
		assert.NotEmpty(t, browseNextResp.Results[0].References)
	})

	t.Run("release continuation point", func(t *testing.T) {
		// Create a continuation point first.
		req := &ua.BrowseRequest{
			RequestHeader:                 reqHeader(),
			RequestedMaxReferencesPerNode: 2,
			NodesToBrowse: []*ua.BrowseDescription{{
				NodeID:          ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.NewNumericNodeID(0, 0),
				IncludeSubtypes: true,
				ResultMask:      uint32(ua.BrowseResultMaskAll),
			}},
		}
		resp, err := svc.Browse(context.Background(), nil, req, 1)
		require.NoError(t, err)
		cp := resp.(*ua.BrowseResponse).Results[0].ContinuationPoint
		require.NotEmpty(t, cp)

		// Release it.
		releaseReq := &ua.BrowseNextRequest{
			RequestHeader:             reqHeader(),
			ReleaseContinuationPoints: true,
			ContinuationPoints:        [][]byte{cp},
		}
		releaseResp, err := svc.BrowseNext(context.Background(), nil, releaseReq, 3)
		require.NoError(t, err)
		browseRelease := releaseResp.(*ua.BrowseNextResponse)
		require.Len(t, browseRelease.Results, 1)
		assert.Equal(t, ua.StatusGood, browseRelease.Results[0].StatusCode)

		// Using the same continuation point again should fail.
		nextReq := &ua.BrowseNextRequest{
			RequestHeader:             reqHeader(),
			ReleaseContinuationPoints: false,
			ContinuationPoints:        [][]byte{cp},
		}
		nextResp, err := svc.BrowseNext(context.Background(), nil, nextReq, 4)
		require.NoError(t, err)
		browseNext := nextResp.(*ua.BrowseNextResponse)
		require.Len(t, browseNext.Results, 1)
		assert.Equal(t, ua.StatusBadContinuationPointInvalid, browseNext.Results[0].StatusCode)
	})

	t.Run("invalid continuation point", func(t *testing.T) {
		nextReq := &ua.BrowseNextRequest{
			RequestHeader:             reqHeader(),
			ReleaseContinuationPoints: false,
			ContinuationPoints:        [][]byte{[]byte("nonexistent")},
		}
		nextResp, err := svc.BrowseNext(context.Background(), nil, nextReq, 5)
		require.NoError(t, err)
		browseNext := nextResp.(*ua.BrowseNextResponse)
		require.Len(t, browseNext.Results, 1)
		assert.Equal(t, ua.StatusBadContinuationPointInvalid, browseNext.Results[0].StatusCode)
	})
}

func TestViewService_TranslateBrowsePathsToNodeIDs(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &ViewService{srv: srv, cps: make(map[string]*continuationPoint)}

	// Create a child node with a known browse name.
	child := ns.AddNewVariableStringNode("target_node", int32(100))
	obj.AddRef(child, id.HasComponent, true)

	t.Run("translate valid path", func(t *testing.T) {
		req := &ua.TranslateBrowsePathsToNodeIDsRequest{
			RequestHeader: reqHeader(),
			BrowsePaths: []*ua.BrowsePath{{
				StartingNode: ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
				RelativePath: &ua.RelativePath{
					Elements: []*ua.RelativePathElement{{
						ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
						IsInverse:       false,
						IncludeSubtypes: true,
						TargetName:      &ua.QualifiedName{Name: "target_node"},
					}},
				},
			}},
		}
		resp, err := svc.TranslateBrowsePathsToNodeIDs(context.Background(), nil, req, 1)
		require.NoError(t, err)

		transResp := resp.(*ua.TranslateBrowsePathsToNodeIDsResponse)
		require.Len(t, transResp.Results, 1)
		result := transResp.Results[0]
		assert.Equal(t, ua.StatusGood, result.StatusCode)
		require.Len(t, result.Targets, 1)
		assert.Equal(t, child.ID().String(), result.Targets[0].TargetID.NodeID.String())
	})

	t.Run("translate path with no match", func(t *testing.T) {
		req := &ua.TranslateBrowsePathsToNodeIDsRequest{
			RequestHeader: reqHeader(),
			BrowsePaths: []*ua.BrowsePath{{
				StartingNode: ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
				RelativePath: &ua.RelativePath{
					Elements: []*ua.RelativePathElement{{
						ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
						IsInverse:       false,
						IncludeSubtypes: true,
						TargetName:      &ua.QualifiedName{Name: "nonexistent"},
					}},
				},
			}},
		}
		resp, err := svc.TranslateBrowsePathsToNodeIDs(context.Background(), nil, req, 2)
		require.NoError(t, err)

		transResp := resp.(*ua.TranslateBrowsePathsToNodeIDsResponse)
		require.Len(t, transResp.Results, 1)
		assert.Equal(t, ua.StatusBadNoMatch, transResp.Results[0].StatusCode)
	})

	t.Run("translate path with nil target name", func(t *testing.T) {
		req := &ua.TranslateBrowsePathsToNodeIDsRequest{
			RequestHeader: reqHeader(),
			BrowsePaths: []*ua.BrowsePath{{
				StartingNode: ua.NewNumericNodeID(ns.ID(), id.ObjectsFolder),
				RelativePath: &ua.RelativePath{
					Elements: []*ua.RelativePathElement{{
						ReferenceTypeID: ua.NewNumericNodeID(0, id.HasComponent),
						IsInverse:       false,
						IncludeSubtypes: true,
						TargetName:      nil,
					}},
				},
			}},
		}
		resp, err := svc.TranslateBrowsePathsToNodeIDs(context.Background(), nil, req, 3)
		require.NoError(t, err)

		transResp := resp.(*ua.TranslateBrowsePathsToNodeIDsResponse)
		require.Len(t, transResp.Results, 1)
		assert.Equal(t, ua.StatusBadBrowseNameInvalid, transResp.Results[0].StatusCode)
	})
}

func TestViewService_RegisterNodes(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	svc := &ViewService{srv: srv}

	t.Run("register existing nodes returns same IDs", func(t *testing.T) {
		nodeIDs := []*ua.NodeID{
			ua.NewStringNodeID(ns.ID(), "rw_int32"),
			ua.NewStringNodeID(ns.ID(), "rw_float64"),
		}
		req := &ua.RegisterNodesRequest{
			RequestHeader:   reqHeader(),
			NodesToRegister: nodeIDs,
		}
		resp, err := svc.RegisterNodes(context.Background(), nil, req, 1)
		require.NoError(t, err)

		regResp := resp.(*ua.RegisterNodesResponse)
		assert.Equal(t, ua.StatusOK, regResp.ResponseHeader.ServiceResult)
		require.Len(t, regResp.RegisteredNodeIDs, 2)
		assert.Equal(t, nodeIDs[0].String(), regResp.RegisteredNodeIDs[0].String())
		assert.Equal(t, nodeIDs[1].String(), regResp.RegisteredNodeIDs[1].String())
	})

	t.Run("register nonexistent node returns nil entry", func(t *testing.T) {
		req := &ua.RegisterNodesRequest{
			RequestHeader: reqHeader(),
			NodesToRegister: []*ua.NodeID{
				ua.NewStringNodeID(ns.ID(), "nonexistent"),
			},
		}
		resp, err := svc.RegisterNodes(context.Background(), nil, req, 2)
		require.NoError(t, err)

		regResp := resp.(*ua.RegisterNodesResponse)
		require.Len(t, regResp.RegisteredNodeIDs, 1)
		assert.Nil(t, regResp.RegisteredNodeIDs[0])
	})

	t.Run("register empty list", func(t *testing.T) {
		req := &ua.RegisterNodesRequest{
			RequestHeader:   reqHeader(),
			NodesToRegister: []*ua.NodeID{},
		}
		resp, err := svc.RegisterNodes(context.Background(), nil, req, 3)
		require.NoError(t, err)

		regResp := resp.(*ua.RegisterNodesResponse)
		assert.Empty(t, regResp.RegisteredNodeIDs)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.RegisterNodes(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}

func TestViewService_UnregisterNodes(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	svc := &ViewService{srv: srv}

	t.Run("unregister nodes succeeds", func(t *testing.T) {
		req := &ua.UnregisterNodesRequest{
			RequestHeader: reqHeader(),
			NodesToUnregister: []*ua.NodeID{
				ua.NewStringNodeID(ns.ID(), "rw_int32"),
			},
		}
		resp, err := svc.UnregisterNodes(context.Background(), nil, req, 1)
		require.NoError(t, err)

		unregResp := resp.(*ua.UnregisterNodesResponse)
		assert.Equal(t, ua.StatusOK, unregResp.ResponseHeader.ServiceResult)
	})

	t.Run("unregister empty list", func(t *testing.T) {
		req := &ua.UnregisterNodesRequest{
			RequestHeader:     reqHeader(),
			NodesToUnregister: []*ua.NodeID{},
		}
		resp, err := svc.UnregisterNodes(context.Background(), nil, req, 2)
		require.NoError(t, err)

		unregResp := resp.(*ua.UnregisterNodesResponse)
		assert.Equal(t, ua.StatusOK, unregResp.ResponseHeader.ServiceResult)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.UnregisterNodes(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}
