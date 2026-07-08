// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// queryByType issues a QueryFirst for the given type, optionally including
// subtypes, returning the Value attribute of every matching node.
func queryByType(ctx context.Context, c *opcua.Client, typeID *ua.NodeID, subtypes bool, filter *ua.ContentFilter, max uint32) (*ua.QueryFirstResponse, error) {
	return c.QueryFirst(ctx, &ua.QueryFirstRequest{
		NodeTypes: []*ua.NodeTypeDescription{
			{
				TypeDefinitionNode: ua.NewExpandedNodeID(typeID, "", 0),
				IncludeSubTypes:    subtypes,
				DataToReturn: []*ua.QueryDataDescription{
					{AttributeID: ua.AttributeIDValue},
				},
			},
		},
		Filter:              filter,
		MaxDataSetsToReturn: max,
	})
}

func TestQuery_ByType(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := queryByType(ctx, c, f.CustomVarType, false, nil, 0)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.ResponseHeader.ServiceResult)
	require.Len(t, resp.QueryDataSets, 2, "exact type match should return CustomVarA and CustomVarB")

	values := map[int32]bool{}
	for _, ds := range resp.QueryDataSets {
		require.Len(t, ds.Values, 1)
		v, ok := ds.Values[0].Value().(int32)
		require.True(t, ok)
		values[v] = true
	}
	require.True(t, values[10])
	require.True(t, values[20])
}

func TestQuery_IncludeSubTypes(t *testing.T) {
	c, f, ctx := setup(t)

	without, err := queryByType(ctx, c, f.CustomVarType, false, nil, 0)
	require.NoError(t, err)
	require.Len(t, without.QueryDataSets, 2)

	with, err := queryByType(ctx, c, f.CustomVarType, true, nil, 0)
	require.NoError(t, err)
	require.Len(t, with.QueryDataSets, 3, "subtype match should also return CustomSubVar")
}

func TestQuery_Filter(t *testing.T) {
	c, f, ctx := setup(t)

	// WHERE Value == 30 -> only CustomSubVar matches.
	filter := &ua.ContentFilter{
		Elements: []*ua.ContentFilterElement{
			{
				FilterOperator: ua.FilterOperatorEquals,
				FilterOperands: []*ua.ExtensionObject{
					attributeOperand(ua.AttributeIDValue),
					literalOperand(ua.MustVariant(int32(30))),
				},
			},
		},
	}

	resp, err := queryByType(ctx, c, f.CustomVarType, true, filter, 0)
	require.NoError(t, err)
	require.Len(t, resp.QueryDataSets, 1)
	require.Equal(t, int32(30), resp.QueryDataSets[0].Values[0].Value())
}

func TestQuery_FilterGreaterThan(t *testing.T) {
	c, f, ctx := setup(t)

	// WHERE Value > 15 -> CustomVarB (20) and CustomSubVar (30).
	filter := &ua.ContentFilter{
		Elements: []*ua.ContentFilterElement{
			{
				FilterOperator: ua.FilterOperatorGreaterThan,
				FilterOperands: []*ua.ExtensionObject{
					attributeOperand(ua.AttributeIDValue),
					literalOperand(ua.MustVariant(int32(15))),
				},
			},
		},
	}

	resp, err := queryByType(ctx, c, f.CustomVarType, true, filter, 0)
	require.NoError(t, err)
	require.Len(t, resp.QueryDataSets, 2)
}

func TestQuery_DataToReturn_MultipleAttributes(t *testing.T) {
	c, f, ctx := setup(t)

	resp, err := c.QueryFirst(ctx, &ua.QueryFirstRequest{
		NodeTypes: []*ua.NodeTypeDescription{
			{
				TypeDefinitionNode: ua.NewExpandedNodeID(f.CustomVarType, "", 0),
				DataToReturn: []*ua.QueryDataDescription{
					{AttributeID: ua.AttributeIDValue},
					{AttributeID: ua.AttributeIDBrowseName},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, resp.QueryDataSets, 2)
	for _, ds := range resp.QueryDataSets {
		require.Len(t, ds.Values, 2)
		_, ok := ds.Values[0].Value().(int32)
		require.True(t, ok, "first value should be the Value attribute")
		qn, ok := ds.Values[1].Value().(*ua.QualifiedName)
		require.True(t, ok, "second value should be the BrowseName attribute")
		require.Contains(t, qn.Name, "CustomVar")
	}
}

func TestQuery_Pagination(t *testing.T) {
	c, f, ctx := setup(t)

	first, err := queryByType(ctx, c, f.CustomVarType, true, nil, 1)
	require.NoError(t, err)
	require.Len(t, first.QueryDataSets, 1)
	require.NotEmpty(t, first.ContinuationPoint, "overflow must produce a continuation point")

	next, err := c.QueryNext(ctx, &ua.QueryNextRequest{
		ContinuationPoint: first.ContinuationPoint,
	})
	require.NoError(t, err)
	require.Len(t, next.QueryDataSets, 2, "remaining datasets returned")

	// The continuation point is retired after use.
	_, err = c.QueryNext(ctx, &ua.QueryNextRequest{
		ContinuationPoint: first.ContinuationPoint,
	})
	require.Error(t, err)
}

func TestQuery_ReleaseContinuationPoint(t *testing.T) {
	c, f, ctx := setup(t)

	first, err := queryByType(ctx, c, f.CustomVarType, true, nil, 1)
	require.NoError(t, err)
	require.NotEmpty(t, first.ContinuationPoint)

	released, err := c.QueryNext(ctx, &ua.QueryNextRequest{
		ReleaseContinuationPoint: true,
		ContinuationPoint:        first.ContinuationPoint,
	})
	require.NoError(t, err)
	require.Empty(t, released.QueryDataSets)

	// After release the token is gone.
	_, err = c.QueryNext(ctx, &ua.QueryNextRequest{
		ContinuationPoint: first.ContinuationPoint,
	})
	require.Error(t, err)
}

// TestQuery_Errors exercises the fault paths. All subtests share one client:
// an operation-level ServiceFault must not tear down the connection, so the
// subsequent calls on the same client keep working.
func TestQuery_Errors(t *testing.T) {
	c, f, ctx := setup(t)

	t.Run("empty node types", func(t *testing.T) {
		_, err := c.QueryFirst(ctx, &ua.QueryFirstRequest{})
		require.Error(t, err)
	})

	t.Run("null type definition", func(t *testing.T) {
		// A null TypeDefinition is reported per-NodeType in ParsingResults; the
		// overall service call still succeeds and returns no data sets.
		resp, err := c.QueryFirst(ctx, &ua.QueryFirstRequest{
			NodeTypes: []*ua.NodeTypeDescription{
				{TypeDefinitionNode: ua.NewTwoByteExpandedNodeID(0)},
			},
		})
		require.NoError(t, err)
		require.Empty(t, resp.QueryDataSets)
		require.Len(t, resp.ParsingResults, 1)
		require.Equal(t, ua.StatusBadTypeDefinitionInvalid, resp.ParsingResults[0].StatusCode)
	})

	t.Run("invalid filter operator", func(t *testing.T) {
		_, err := c.QueryFirst(ctx, &ua.QueryFirstRequest{
			NodeTypes: []*ua.NodeTypeDescription{
				{TypeDefinitionNode: ua.NewExpandedNodeID(f.CustomVarType, "", 0)},
			},
			Filter: &ua.ContentFilter{
				Elements: []*ua.ContentFilterElement{
					{FilterOperator: ua.FilterOperator(99)},
				},
			},
		})
		require.Error(t, err)
	})

	t.Run("unknown continuation point", func(t *testing.T) {
		_, err := c.QueryNext(ctx, &ua.QueryNextRequest{
			ContinuationPoint: []byte("does-not-exist"),
		})
		require.Error(t, err)
	})

	t.Run("unknown view", func(t *testing.T) {
		_, err := c.QueryFirst(ctx, &ua.QueryFirstRequest{
			View: &ua.ViewDescription{ViewID: ua.NewNumericNodeID(0, 9999)},
			NodeTypes: []*ua.NodeTypeDescription{
				{TypeDefinitionNode: ua.NewExpandedNodeID(f.CustomVarType, "", 0)},
			},
		})
		require.Error(t, err)
	})

	// The connection survived every fault above.
	t.Run("connection still usable", func(t *testing.T) {
		resp, err := queryByType(ctx, c, f.CustomVarType, false, nil, 0)
		require.NoError(t, err)
		require.Len(t, resp.QueryDataSets, 2)
	})
}

// --- operand builders -----------------------------------------------------

func literalOperand(v *ua.Variant) *ua.ExtensionObject {
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.LiteralOperandEncodingDefaultBinary),
		Value:        ua.LiteralOperand{Value: v},
	}
}

func attributeOperand(attr ua.AttributeID) *ua.ExtensionObject {
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.AttributeOperandEncodingDefaultBinary),
		Value: ua.AttributeOperand{
			NodeID:      ua.NewTwoByteNodeID(0),
			AttributeID: attr,
		},
	}
}
