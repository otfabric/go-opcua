// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func lit(v *ua.Variant) *ua.ExtensionObject {
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.LiteralOperandEncodingDefaultBinary),
		Value:        &ua.LiteralOperand{Value: v},
	}
}

func elemOp(i uint32) *ua.ExtensionObject {
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.ElementOperandEncodingDefaultBinary),
		Value:        &ua.ElementOperand{Index: i},
	}
}

func cfe(op ua.FilterOperator, operands ...*ua.ExtensionObject) *ua.ContentFilterElement {
	return &ua.ContentFilterElement{FilterOperator: op, FilterOperands: operands}
}

// evalRoot builds a single-element (or multi-element) filter and evaluates it
// against an anonymous node.
func evalRoot(t *testing.T, elements ...*ua.ContentFilterElement) tvl {
	t.Helper()
	srv := newTestServer()
	node := NewNode(ua.NewStringNodeID(0, "anon"), nil, nil, nil)
	return evalFilter(srv, node, &ua.ContentFilter{Elements: elements})
}

func TestFilter_NilMatchesAll(t *testing.T) {
	srv := newTestServer()
	node := NewNode(ua.NewStringNodeID(0, "anon"), nil, nil, nil)
	require.Equal(t, tvlTrue, evalFilter(srv, node, nil))
	require.Equal(t, tvlTrue, evalFilter(srv, node, &ua.ContentFilter{}))
}

func TestFilter_ThreeValuedLogic(t *testing.T) {
	cases := []struct {
		a, b, and, or tvl
	}{
		{tvlTrue, tvlTrue, tvlTrue, tvlTrue},
		{tvlTrue, tvlFalse, tvlFalse, tvlTrue},
		{tvlFalse, tvlFalse, tvlFalse, tvlFalse},
		{tvlTrue, tvlNull, tvlNull, tvlTrue},
		{tvlFalse, tvlNull, tvlFalse, tvlNull},
		{tvlNull, tvlNull, tvlNull, tvlNull},
	}
	for _, c := range cases {
		require.Equal(t, c.and, andTVL(c.a, c.b))
		require.Equal(t, c.and, andTVL(c.b, c.a))
		require.Equal(t, c.or, orTVL(c.a, c.b))
		require.Equal(t, c.or, orTVL(c.b, c.a))
	}
	require.Equal(t, tvlFalse, notTVL(tvlTrue))
	require.Equal(t, tvlTrue, notTVL(tvlFalse))
	require.Equal(t, tvlNull, notTVL(tvlNull))
}

func TestFilter_Equals(t *testing.T) {
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(1))))))
	require.Equal(t, tvlFalse, evalRoot(t, cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(2))))))
	// implicit numeric conversion across integer/float
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(float64(1))))))
	// strings
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorEquals, lit(ua.MustVariant("x")), lit(ua.MustVariant("x")))))
	// null operand -> null
	require.Equal(t, tvlNull, evalRoot(t, cfe(ua.FilterOperatorEquals, lit(nil), lit(ua.MustVariant(int32(1))))))
}

func TestFilter_Ordering(t *testing.T) {
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorGreaterThan, lit(ua.MustVariant(int32(2))), lit(ua.MustVariant(int32(1))))))
	require.Equal(t, tvlFalse, evalRoot(t, cfe(ua.FilterOperatorLessThan, lit(ua.MustVariant(int32(2))), lit(ua.MustVariant(int32(1))))))
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorGreaterThanOrEqual, lit(ua.MustVariant(int32(2))), lit(ua.MustVariant(int32(2))))))
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorLessThanOrEqual, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(2))))))
}

func TestFilter_Between(t *testing.T) {
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorBetween,
		lit(ua.MustVariant(int32(5))), lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(10))))))
	require.Equal(t, tvlFalse, evalRoot(t, cfe(ua.FilterOperatorBetween,
		lit(ua.MustVariant(int32(20))), lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(10))))))
}

func TestFilter_InList(t *testing.T) {
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorInList,
		lit(ua.MustVariant(int32(2))), lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(2))))))
	require.Equal(t, tvlFalse, evalRoot(t, cfe(ua.FilterOperatorInList,
		lit(ua.MustVariant(int32(9))), lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(2))))))
}

func TestFilter_IsNull(t *testing.T) {
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorIsNull, lit(nil))))
	require.Equal(t, tvlFalse, evalRoot(t, cfe(ua.FilterOperatorIsNull, lit(ua.MustVariant(int32(5))))))
}

func TestFilter_Not(t *testing.T) {
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorNot,
		lit(ua.MustVariant(false)))))
	require.Equal(t, tvlFalse, evalRoot(t, cfe(ua.FilterOperatorNot,
		lit(ua.MustVariant(true)))))
}

func TestFilter_AndOrElements(t *testing.T) {
	// element0 = element1 AND element2; element1 = 1==1 (true); element2 = 1==2 (false)
	tv := evalRoot(t,
		cfe(ua.FilterOperatorAnd, elemOp(1), elemOp(2)),
		cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(1)))),
		cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(2)))),
	)
	require.Equal(t, tvlFalse, tv)

	tv = evalRoot(t,
		cfe(ua.FilterOperatorOr, elemOp(1), elemOp(2)),
		cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(1)))),
		cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(2)))),
	)
	require.Equal(t, tvlTrue, tv)
}

func TestFilter_ElementCycleIsInvalid(t *testing.T) {
	// element0 references element0 -> cycle -> NULL result.
	tv := evalRoot(t, cfe(ua.FilterOperatorNot, elemOp(0)))
	require.Equal(t, tvlNull, tv)
}

func TestFilter_Bitwise(t *testing.T) {
	srv := newTestServer()
	node := NewNode(ua.NewStringNodeID(0, "anon"), nil, nil, nil)
	// (0b1100 & 0b1010) == 0b1000 -> 8
	f := &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorEquals, elemOp(1), lit(ua.MustVariant(int64(8)))),
		cfe(ua.FilterOperatorBitwiseAnd, lit(ua.MustVariant(int64(12))), lit(ua.MustVariant(int64(10)))),
	}}
	require.Equal(t, tvlTrue, evalFilter(srv, node, f))
}

func TestFilter_Like(t *testing.T) {
	cases := []struct {
		s, pat string
		want   bool
	}{
		{"abc", "a%c", true},
		{"abbbc", "a%c", true},
		{"abc", "a_c", true},
		{"abbc", "a_c", false},
		{"abc", "a[bx]c", true},
		{"axc", "a[bx]c", true},
		{"azc", "a[^b]c", true},
		{"abc", "a[^b]c", false},
		{"a%c", "a\\%c", true},
		{"abc", "a\\%c", false},
	}
	for _, c := range cases {
		re, err := likeToRegexp(c.pat)
		require.NoError(t, err, c.pat)
		require.Equal(t, c.want, re.MatchString(c.s), "%q like %q", c.s, c.pat)
	}
}

func TestFilter_Cast(t *testing.T) {
	require.Equal(t, "5", castVariant(ua.MustVariant(int32(5)), 12).Value())
	require.Equal(t, int32(3), castVariant(ua.MustVariant(float64(3.7)), 6).Value())
	require.Equal(t, float64(2), castVariant(ua.MustVariant(int32(2)), 11).Value())
	require.Equal(t, true, castVariant(ua.MustVariant(int32(1)), 1).Value())
	require.Nil(t, castVariant(ua.MustVariant("x"), 6))
}

func TestFilter_LikeEval(t *testing.T) {
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorLike,
		lit(ua.MustVariant("abc")), lit(ua.MustVariant("a%c")))))
	require.Equal(t, tvlFalse, evalRoot(t, cfe(ua.FilterOperatorLike,
		lit(ua.MustVariant("xyz")), lit(ua.MustVariant("a%c")))))
}

func TestFilter_CastEval(t *testing.T) {
	tv := evalRoot(t,
		cfe(ua.FilterOperatorEquals, lit(ua.MustVariant("5")), elemOp(1)),
		cfe(ua.FilterOperatorCast, lit(ua.MustVariant(int32(5))), lit(ua.MustVariant(ua.NewNumericNodeID(0, id.String)))),
	)
	require.Equal(t, tvlTrue, tv)
}

func TestFilter_InView(t *testing.T) {
	require.Equal(t, tvlTrue, evalRoot(t, cfe(ua.FilterOperatorInView, lit(nil))))
	require.Equal(t, tvlFalse, evalRoot(t, cfe(ua.FilterOperatorInView,
		lit(ua.MustVariant(ua.NewNumericNodeID(0, id.ObjectsFolder))))))
}

func TestFilter_OfType(t *testing.T) {
	srv := newTestServer()
	ns := NewNodeNameSpace(srv, "http://example.com/filter")
	v := ns.AddNewVariableStringNode("v", int32(1))
	typedef := srv.Node(ua.NewNumericNodeID(0, id.BaseDataVariableType))
	require.NotNil(t, typedef)
	v.AddRef(typedef, id.HasTypeDefinition, true)

	f := &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorOfType, lit(ua.MustVariant(ua.NewNumericNodeID(0, id.BaseDataVariableType)))),
	}}
	require.Equal(t, tvlTrue, evalFilter(srv, v, f))
}

func TestFilter_BitwiseOr(t *testing.T) {
	tv := evalRoot(t,
		cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int64(14))), elemOp(1)),
		cfe(ua.FilterOperatorBitwiseOr, lit(ua.MustVariant(int64(12))), lit(ua.MustVariant(int64(10)))),
	)
	require.Equal(t, tvlTrue, tv)
}

func TestFilter_Validate(t *testing.T) {
	// unknown operator
	res, ok := validateFilter(&ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperator(99)),
	}})
	require.False(t, ok)
	require.Equal(t, ua.StatusBadFilterOperatorInvalid, res.ElementResults[0].StatusCode)

	// operand count mismatch
	res, ok = validateFilter(&ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1)))),
	}})
	require.False(t, ok)
	require.Equal(t, ua.StatusBadFilterOperandCountMismatch, res.ElementResults[0].StatusCode)

	// valid filter
	res, ok = validateFilter(&ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(int32(1))), lit(ua.MustVariant(int32(1)))),
	}})
	require.True(t, ok)
	require.Equal(t, ua.StatusGood, res.ElementResults[0].StatusCode)
}

func saoOp(attr ua.AttributeID, path ...*ua.QualifiedName) *ua.ExtensionObject {
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(0, id.SimpleAttributeOperandEncodingDefaultBinary),
		Value: &ua.SimpleAttributeOperand{
			AttributeID: attr,
			BrowsePath:  path,
		},
	}
}

func TestFilter_SimpleAttributeOperand(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)
	node := srv.Node(ua.NewStringNodeID(ns.ID(), "rw_int32"))
	require.NotNil(t, node)

	tv := evalFilter(srv, node, &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorEquals, saoOp(ua.AttributeIDValue), lit(ua.MustVariant(int32(42)))),
	}})
	require.Equal(t, tvlTrue, tv)
}

func TestFilter_RelatedTo(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)

	parent := NewNode(
		ua.NewStringNodeID(ns.ID(), "parent"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:   DataValueFromValue(uint32(ua.NodeClassObject)),
			ua.AttributeIDBrowseName:  DataValueFromValue(attrs.BrowseName("parent")),
			ua.AttributeIDDisplayName: DataValueFromValue(attrs.DisplayName("parent", "parent")),
		},
		nil,
		nil,
	)
	ns.AddNode(parent)
	parentType := srv.Node(ua.NewNumericNodeID(0, id.BaseObjectType))
	require.NotNil(t, parentType)
	parent.AddRef(parentType, id.HasTypeDefinition, true)
	obj.AddRef(parent, id.HasComponent, true)

	child := ns.AddNewVariableStringNode("relchild", int32(7))
	parent.AddRef(child, id.HasComponent, true)
	childType := srv.Node(ua.NewNumericNodeID(0, id.BaseDataVariableType))
	require.NotNil(t, childType)
	child.AddRef(childType, id.HasTypeDefinition, true)

	f := &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorRelatedTo,
			lit(ua.MustVariant(ua.NewNumericNodeID(0, id.BaseObjectType))),
			lit(ua.MustVariant(ua.NewNumericNodeID(0, id.HasComponent))),
			lit(ua.MustVariant(ua.NewNumericNodeID(0, id.BaseDataVariableType))),
		),
	}}
	require.Equal(t, tvlTrue, evalFilter(srv, parent, f))
	require.Equal(t, tvlFalse, evalFilter(srv, child, f))
}

func TestFloatOf(t *testing.T) {
	tests := []struct {
		v      *ua.Variant
		want   float64
		wantOk bool
	}{
		{ua.MustVariant(int8(1)), 1, true},
		{ua.MustVariant(int16(2)), 2, true},
		{ua.MustVariant(int32(3)), 3, true},
		{ua.MustVariant(int64(4)), 4, true},
		{ua.MustVariant(uint8(5)), 5, true},
		{ua.MustVariant(uint16(6)), 6, true},
		{ua.MustVariant(uint32(7)), 7, true},
		{ua.MustVariant(uint64(8)), 8, true},
		{ua.MustVariant(float32(1.5)), 1.5, true},
		{ua.MustVariant(float64(2.5)), 2.5, true},
		{ua.MustVariant("str"), 0, false},
	}
	for _, tt := range tests {
		got, ok := floatOf(tt.v)
		if ok != tt.wantOk || (ok && got != tt.want) {
			t.Errorf("floatOf(%v) = (%v, %v), want (%v, %v)", tt.v, got, ok, tt.want, tt.wantOk)
		}
	}
}

func TestIntOf(t *testing.T) {
	tests := []struct {
		v      *ua.Variant
		want   int64
		wantOk bool
	}{
		{ua.MustVariant(int8(1)), 1, true},
		{ua.MustVariant(int16(2)), 2, true},
		{ua.MustVariant(int32(3)), 3, true},
		{ua.MustVariant(int64(4)), 4, true},
		{ua.MustVariant(uint8(5)), 5, true},
		{ua.MustVariant(uint16(6)), 6, true},
		{ua.MustVariant(uint32(7)), 7, true},
		{ua.MustVariant(uint64(8)), 8, true},
		{ua.MustVariant("str"), 0, false},
	}
	for _, tt := range tests {
		got, ok := intOf(tt.v)
		if ok != tt.wantOk || (ok && got != tt.want) {
			t.Errorf("intOf(%v) = (%v, %v), want (%v, %v)", tt.v, got, ok, tt.want, tt.wantOk)
		}
	}
}

func TestNodeIDOperand(t *testing.T) {
	// nil variant
	if nodeIDOperand(nil) != nil {
		t.Error("expected nil for nil variant")
	}
	// NodeID variant
	nid := ua.NewStringNodeID(0, "test")
	v := ua.MustVariant(nid)
	got := nodeIDOperand(v)
	require.NotNil(t, got)
	require.Equal(t, nid, got)
	// string (non-NodeID) variant
	if nodeIDOperand(ua.MustVariant("string")) != nil {
		t.Error("expected nil for string variant")
	}
}

func TestCastVariant(t *testing.T) {
	tests := []struct {
		src      *ua.Variant
		dataType uint32
		wantNil  bool
	}{
		{ua.MustVariant(int32(1)), 1, false},  // to bool
		{ua.MustVariant("str"), 1, true},      // string can't cast to bool
		{ua.MustVariant(int32(5)), 6, false},  // to int32
		{ua.MustVariant(int32(5)), 8, false},  // to int64
		{ua.MustVariant(int32(5)), 7, false},  // to uint32
		{ua.MustVariant(int32(5)), 9, false},  // to uint64
		{ua.MustVariant(int32(5)), 10, false}, // to float32
		{ua.MustVariant(int32(5)), 11, false}, // to float64
		{ua.MustVariant(int32(5)), 99, true},  // unknown type
	}
	for _, tt := range tests {
		got := castVariant(tt.src, tt.dataType)
		if tt.wantNil && got != nil {
			t.Errorf("castVariant(_, %d) = %v, want nil", tt.dataType, got)
		} else if !tt.wantNil && got == nil {
			t.Errorf("castVariant(_, %d) = nil, want non-nil", tt.dataType)
		}
	}
}
