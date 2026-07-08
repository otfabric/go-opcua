// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nodeSpecificController allows read/write/browse/call for a specific node
// and denies everything else.
type nodeSpecificController struct {
	allowedNodeID string
}

func (c nodeSpecificController) CheckRead(_ context.Context, _ *session, nodeID *ua.NodeID) ua.StatusCode {
	if nodeID != nil && nodeID.String() == c.allowedNodeID {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

func (c nodeSpecificController) CheckWrite(_ context.Context, _ *session, nodeID *ua.NodeID) ua.StatusCode {
	if nodeID != nil && nodeID.String() == c.allowedNodeID {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

func (c nodeSpecificController) CheckBrowse(_ context.Context, _ *session, nodeID *ua.NodeID) ua.StatusCode {
	if nodeID != nil && nodeID.String() == c.allowedNodeID {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

func (c nodeSpecificController) CheckCall(_ context.Context, _ *session, nodeID *ua.NodeID) ua.StatusCode {
	if nodeID != nil && nodeID.String() == c.allowedNodeID {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

// readOnlyController allows reads but denies writes, browse, and calls.
type readOnlyController struct{}

func (readOnlyController) CheckRead(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}
func (readOnlyController) CheckWrite(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}
func (readOnlyController) CheckBrowse(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}
func (readOnlyController) CheckCall(_ context.Context, _ *session, _ *ua.NodeID) ua.StatusCode {
	return ua.StatusBadUserAccessDenied
}

func TestAccessControl_NodeSpecific_ReadAllowed(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	allowedNodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")
	srv.cfg.accessController = nodeSpecificController{allowedNodeID: allowedNodeID.String()}
	svc := &AttributeService{srv: srv}

	req := &ua.ReadRequest{
		RequestHeader: reqHeader(),
		NodesToRead: []*ua.ReadValueID{
			{NodeID: allowedNodeID, AttributeID: ua.AttributeIDValue},
		},
	}
	resp, err := svc.Read(context.Background(), nil, req, 1)
	require.NoError(t, err)

	readResp := resp.(*ua.ReadResponse)
	require.Len(t, readResp.Results, 1)
	assert.NotEqual(t, ua.StatusBadUserAccessDenied, readResp.Results[0].Status)
}

func TestAccessControl_NodeSpecific_ReadDenied(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	allowedNodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")
	deniedNodeID := ua.NewStringNodeID(ns.ID(), "rw_float64")
	srv.cfg.accessController = nodeSpecificController{allowedNodeID: allowedNodeID.String()}
	svc := &AttributeService{srv: srv}

	req := &ua.ReadRequest{
		RequestHeader: reqHeader(),
		NodesToRead: []*ua.ReadValueID{
			{NodeID: deniedNodeID, AttributeID: ua.AttributeIDValue},
		},
	}
	resp, err := svc.Read(context.Background(), nil, req, 1)
	require.NoError(t, err)

	readResp := resp.(*ua.ReadResponse)
	require.Len(t, readResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, readResp.Results[0].Status)
}

func TestAccessControl_NodeSpecific_MixedReadResults(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	allowedNodeID := ua.NewStringNodeID(ns.ID(), "rw_int32")
	deniedNodeID := ua.NewStringNodeID(ns.ID(), "rw_float64")
	srv.cfg.accessController = nodeSpecificController{allowedNodeID: allowedNodeID.String()}
	svc := &AttributeService{srv: srv}

	req := &ua.ReadRequest{
		RequestHeader: reqHeader(),
		NodesToRead: []*ua.ReadValueID{
			{NodeID: allowedNodeID, AttributeID: ua.AttributeIDValue},
			{NodeID: deniedNodeID, AttributeID: ua.AttributeIDValue},
		},
	}
	resp, err := svc.Read(context.Background(), nil, req, 1)
	require.NoError(t, err)

	readResp := resp.(*ua.ReadResponse)
	require.Len(t, readResp.Results, 2)
	assert.NotEqual(t, ua.StatusBadUserAccessDenied, readResp.Results[0].Status, "allowed node should succeed")
	assert.Equal(t, ua.StatusBadUserAccessDenied, readResp.Results[1].Status, "denied node should fail")
}

func TestAccessControl_ReadOnly_WriteBlocked(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	srv.cfg.accessController = readOnlyController{}
	svc := &AttributeService{srv: srv}

	req := &ua.WriteRequest{
		RequestHeader: reqHeader(),
		NodesToWrite: []*ua.WriteValue{
			{
				NodeID:      ua.NewStringNodeID(ns.ID(), "rw_int32"),
				AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        ua.MustVariant(int32(99)),
				},
			},
		},
	}
	resp, err := svc.Write(context.Background(), nil, req, 1)
	require.NoError(t, err)

	writeResp := resp.(*ua.WriteResponse)
	require.Len(t, writeResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, writeResp.Results[0])
}

func TestAccessControl_ReadOnly_ReadAllowed(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	srv.cfg.accessController = readOnlyController{}
	svc := &AttributeService{srv: srv}

	req := &ua.ReadRequest{
		RequestHeader: reqHeader(),
		NodesToRead: []*ua.ReadValueID{
			{NodeID: ua.NewStringNodeID(ns.ID(), "rw_int32"), AttributeID: ua.AttributeIDValue},
		},
	}
	resp, err := svc.Read(context.Background(), nil, req, 1)
	require.NoError(t, err)

	readResp := resp.(*ua.ReadResponse)
	require.Len(t, readResp.Results, 1)
	assert.NotEqual(t, ua.StatusBadUserAccessDenied, readResp.Results[0].Status)
}

func TestAccessControl_ReadOnly_BrowseAllowed(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	srv.cfg.accessController = readOnlyController{}
	svc := &ViewService{srv: srv, cps: make(map[string]*continuationPoint)}

	req := &ua.BrowseRequest{
		RequestHeader: reqHeader(),
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
	assert.Equal(t, ua.StatusGood, browseResp.Results[0].StatusCode)
}

func TestAccessControl_ReadOnly_CallBlocked(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	srv.cfg.accessController = readOnlyController{}
	svc := &MethodService{srv: srv}

	methodID := ua.NewStringNodeID(ns.ID(), "ro_method")
	methodNode := NewFolderNode(methodID, "ro_method")
	methodNode.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(methodNode)
	obj.AddRef(methodNode, RefType(id.HasComponent), true)

	srv.RegisterMethod(obj.ID(), methodID, func(ctx context.Context, oID, mID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return nil, ua.StatusOK
	})

	req := &ua.CallRequest{
		RequestHeader: reqHeader(),
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID: obj.ID(),
			MethodID: methodID,
		}},
	}
	resp, err := svc.Call(context.Background(), nil, req, 1)
	require.NoError(t, err)

	callResp := resp.(*ua.CallResponse)
	require.Len(t, callResp.Results, 1)
	assert.Equal(t, ua.StatusBadUserAccessDenied, callResp.Results[0].StatusCode)
}
