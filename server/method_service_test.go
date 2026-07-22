// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMethodService_Call(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	svc := &MethodService{srv: srv}

	objID := obj.ID()
	methodID := ua.NewStringNodeID(ns.ID(), "test_method")

	// Create a method node with a declared Int32 InputArguments property.
	methodNode := NewFolderNode(methodID, "test_method")
	methodNode.SetNodeClass(ua.NodeClassMethod)
	ns.AddNode(methodNode)
	obj.AddRef(methodNode, RefType(id.HasComponent), true)

	arg := &ua.Argument{
		Name: "value", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1,
		Description: ua.NewLocalizedText("echo input"),
	}
	argValue := &ua.DataValue{
		EncodingMask: ua.DataValueValue,
		Value:        ua.MustVariant([]*ua.ExtensionObject{ua.NewExtensionObject(arg)}),
	}
	argNode := NewNode(
		ua.NewStringNodeID(ns.ID(), "test_method.InputArguments"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: DataValueFromValue(attrs.BrowseName("InputArguments")),
		},
		nil,
		func() *ua.DataValue { return argValue },
	)
	ns.AddNode(argNode)
	methodNode.AddRef(argNode, RefType(id.HasProperty), true)

	srv.RegisterMethod(objID, methodID, func(ctx context.Context, oID, mID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return args, ua.StatusOK
	})

	t.Run("call registered method", func(t *testing.T) {
		req := &ua.CallRequest{
			RequestHeader: reqHeader(),
			MethodsToCall: []*ua.CallMethodRequest{{
				ObjectID:       objID,
				MethodID:       methodID,
				InputArguments: []*ua.Variant{ua.MustVariant(int32(42))},
			}},
		}
		resp, err := svc.Call(context.Background(), nil, req, 1)
		require.NoError(t, err)

		callResp := resp.(*ua.CallResponse)
		require.Len(t, callResp.Results, 1)
		assert.Equal(t, ua.StatusOK, callResp.Results[0].StatusCode)
		require.Len(t, callResp.Results[0].OutputArguments, 1)
		assert.Equal(t, int32(42), callResp.Results[0].OutputArguments[0].Value())
	})

	t.Run("too few arguments", func(t *testing.T) {
		req := &ua.CallRequest{
			RequestHeader: reqHeader(),
			MethodsToCall: []*ua.CallMethodRequest{{
				ObjectID: objID, MethodID: methodID,
			}},
		}
		resp, err := svc.Call(context.Background(), nil, req, 2)
		require.NoError(t, err)
		callResp := resp.(*ua.CallResponse)
		assert.Equal(t, ua.StatusBadArgumentsMissing, callResp.Results[0].StatusCode)
	})

	t.Run("wrong argument type", func(t *testing.T) {
		req := &ua.CallRequest{
			RequestHeader: reqHeader(),
			MethodsToCall: []*ua.CallMethodRequest{{
				ObjectID:       objID,
				MethodID:       methodID,
				InputArguments: []*ua.Variant{ua.MustVariant("not-an-int")},
			}},
		}
		resp, err := svc.Call(context.Background(), nil, req, 3)
		require.NoError(t, err)
		callResp := resp.(*ua.CallResponse)
		assert.Equal(t, ua.StatusBadTypeMismatch, callResp.Results[0].StatusCode)
		require.Len(t, callResp.Results[0].InputArgumentResults, 1)
		assert.Equal(t, ua.StatusBadTypeMismatch, callResp.Results[0].InputArgumentResults[0])
	})

	t.Run("call unregistered method", func(t *testing.T) {
		req := &ua.CallRequest{
			RequestHeader: reqHeader(),
			MethodsToCall: []*ua.CallMethodRequest{{
				ObjectID: objID,
				MethodID: ua.NewStringNodeID(ns.ID(), "nonexistent_method"),
			}},
		}
		resp, err := svc.Call(context.Background(), nil, req, 4)
		require.NoError(t, err)

		callResp := resp.(*ua.CallResponse)
		require.Len(t, callResp.Results, 1)
		assert.Equal(t, ua.StatusBadMethodInvalid, callResp.Results[0].StatusCode)
	})

	t.Run("call with unknown object node", func(t *testing.T) {
		req := &ua.CallRequest{
			RequestHeader: reqHeader(),
			MethodsToCall: []*ua.CallMethodRequest{{
				ObjectID: ua.NewStringNodeID(ns.ID(), "nonexistent_object"),
				MethodID: methodID,
			}},
		}
		resp, err := svc.Call(context.Background(), nil, req, 5)
		require.NoError(t, err)

		callResp := resp.(*ua.CallResponse)
		require.Len(t, callResp.Results, 1)
		assert.Equal(t, ua.StatusBadNodeIDUnknown, callResp.Results[0].StatusCode)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.Call(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}
