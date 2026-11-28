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
		assert.Equal(t, ua.StatusBadInvalidArgument, callResp.Results[0].StatusCode)
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

// TestMethodService_CallArgumentEncodings: the DataType of an Argument is
// checked whatever DataEncoding its NUMERIC NodeId has (OPC 10000-6
// §5.2.2.9): the InputArguments of a NodeSet give the DataTypes of
// namespace 0 as Two Byte or Four Byte NodeIds. An empty Variant is taken
// for an array and a nullable built-in type, and refused for the others
// (§5.1.2 Table 1, §5.1.9, §5.1.11).
func TestMethodService_CallArgumentEncodings(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dt        *ua.NodeID
		rank      int32
		good      any
		wrong     any
		nullTaken bool
	}{
		{"TwoByte Int32", ua.NewTwoByteNodeID(id.Int32), -1, int32(1), "x", false},
		{"FourByte Int32", ua.NewFourByteNodeID(0, id.Int32), -1, int32(1), "x", false},
		{"Numeric Int32", ua.NewNumericNodeID(0, id.Int32), -1, int32(1), "x", false},
		// Duration is a subtype of Double.
		{"FourByte Duration", ua.NewFourByteNodeID(0, id.Duration), -1, float64(1), int32(1), false},
		{"TwoByte String", ua.NewTwoByteNodeID(id.String), -1, "x", int32(1), true},
		{"TwoByte ByteString array", ua.NewTwoByteNodeID(id.ByteString), 1, [][]byte{{1}}, []string{"x"}, true},
		{"TwoByte Int32 array", ua.NewTwoByteNodeID(id.Int32), 1, []int32{1}, int32(1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer()
			ns, obj := addTestNamespace(srv)
			methodID := ua.NewStringNodeID(ns.ID(), "m")
			m := NewFolderNode(methodID, "m")
			m.SetNodeClass(ua.NodeClassMethod)
			ns.AddNode(m)
			obj.AddRef(m, RefType(id.HasComponent), true)
			args := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]*ua.ExtensionObject{
				ua.NewExtensionObject(&ua.Argument{Name: "v", DataType: tc.dt, ValueRank: tc.rank}),
			})}
			argNode := NewNode(ua.NewStringNodeID(ns.ID(), "m.InputArguments"),
				map[ua.AttributeID]*ua.DataValue{
					ua.AttributeIDNodeClass:  DataValueFromValue(uint32(ua.NodeClassVariable)),
					ua.AttributeIDBrowseName: DataValueFromValue(attrs.BrowseName("InputArguments")),
				}, nil, func() *ua.DataValue { return args })
			ns.AddNode(argNode)
			m.AddRef(argNode, RefType(id.HasProperty), true)
			srv.RegisterMethod(obj.ID(), methodID, func(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
				return nil, ua.StatusOK
			})
			call := func(v *ua.Variant) *ua.CallMethodResult {
				resp, err := (&MethodService{srv: srv}).Call(context.Background(), nil, &ua.CallRequest{
					RequestHeader: reqHeader(),
					MethodsToCall: []*ua.CallMethodRequest{{ObjectID: obj.ID(), MethodID: methodID, InputArguments: []*ua.Variant{v}}},
				}, 1)
				require.NoError(t, err)
				return resp.(*ua.CallResponse).Results[0]
			}
			assert.Equal(t, ua.StatusOK, call(ua.MustVariant(tc.good)).StatusCode)
			r := call(ua.MustVariant(tc.wrong))
			assert.Equal(t, ua.StatusBadInvalidArgument, r.StatusCode)
			assert.Equal(t, []ua.StatusCode{ua.StatusBadTypeMismatch}, r.InputArgumentResults)
			for _, null := range []*ua.Variant{{}, nil} {
				r = call(null)
				if tc.nullTaken {
					assert.Equal(t, ua.StatusOK, r.StatusCode, "an empty Variant is a null value")
				} else {
					assert.Equal(t, ua.StatusBadInvalidArgument, r.StatusCode, "the type has no null value")
					assert.Equal(t, []ua.StatusCode{ua.StatusBadTypeMismatch}, r.InputArgumentResults)
				}
			}
		})
	}
}

// TestNullableBuiltin: the Nullable column of OPC 10000-6 §5.1.2 Table 1.
func TestNullableBuiltin(t *testing.T) {
	for typ := ua.TypeIDBoolean; typ <= ua.TypeIDDiagnosticInfo; typ++ {
		want := typ > ua.TypeIDDouble && typ != ua.TypeIDStatusCode
		assert.Equal(t, want, nullableBuiltin(typ), typ.String())
	}
	assert.True(t, nullableBuiltin(ua.TypeIDNull))
	assert.True(t, nullableBuiltin(ua.TypeID(99)), "not a built-in type: not refused here")
}

// TestBuiltinTypeOfNodeIDs: a DataType of namespace 0 is a built-in type in
// any DataEncoding of its NUMERIC NodeId (OPC 10000-6 §5.2.2.9); nil, other
// namespaces and other identifier types are not.
func TestBuiltinTypeOfNodeIDs(t *testing.T) {
	for _, dt := range []*ua.NodeID{ua.NewTwoByteNodeID(id.Int32), ua.NewFourByteNodeID(0, id.Int32), ua.NewNumericNodeID(0, id.Int32)} {
		typ, ok := builtinTypeOf(nil, dt)
		assert.True(t, ok, dt.String())
		assert.Equal(t, ua.TypeIDInt32, typ, dt.String())
	}
	for _, dt := range []*ua.NodeID{nil, ua.NewNumericNodeID(1, id.Int32), ua.NewFourByteNodeID(1, id.Int32), ua.NewStringNodeID(0, "Int32")} {
		_, ok := builtinTypeOf(nil, dt)
		assert.False(t, ok, "%v", dt)
	}
}
