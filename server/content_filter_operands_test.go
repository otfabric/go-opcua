// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func attrOp(nodeID *ua.NodeID, attr ua.AttributeID, path ...*ua.QualifiedName) *ua.ExtensionObject {
	op := &ua.AttributeOperand{NodeID: nodeID, AttributeID: attr}
	if len(path) > 0 {
		op.BrowsePath = &ua.RelativePath{}
		for _, qn := range path {
			op.BrowsePath.Elements = append(op.BrowsePath.Elements, &ua.RelativePathElement{TargetName: qn})
		}
	}
	return &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, Value: op}
}

func rawOp(v interface{}) *ua.ExtensionObject {
	return &ua.ExtensionObject{EncodingMask: ua.ExtensionObjectBinary, Value: v}
}

// evalWithStatus evaluates element 0 of the filter against node and returns
// both the resulting value and the evaluation status.
func evalWithStatus(srv *Server, node *Node, elements ...*ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	ev := &filterEvaluator{
		srv:      srv,
		node:     node,
		nodeID:   node.ID(),
		typeDef:  nodeTypeDefinition(node),
		elements: elements,
		visiting: make([]bool, len(elements)),
	}
	return ev.evalElement(0)
}

func anonNode() *Node { return NewNode(ua.NewStringNodeID(0, "anon"), nil, nil, nil) }

func i32(v int32) *ua.ExtensionObject  { return lit(ua.MustVariant(v)) }
func str(s string) *ua.ExtensionObject { return lit(ua.MustVariant(s)) }

func TestFilter_ValidateOperands(t *testing.T) {
	good := i32(1)
	filter := &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		cfe(ua.FilterOperatorEquals, nil, good),                                                                                  // 0: nil operand
		cfe(ua.FilterOperatorEquals, &ua.ExtensionObject{}, good),                                                                // 1: operand without body
		cfe(ua.FilterOperatorEquals, lit(nil), good),                                                                             // 2: literal without value
		cfe(ua.FilterOperatorEquals, elemOp(99), good),                                                                           // 3: element out of range
		cfe(ua.FilterOperatorEquals, elemOp(4), good),                                                                            // 4: element referencing itself
		cfe(ua.FilterOperatorEquals, elemOp(2), good),                                                                            // 5: element referencing backwards
		cfe(ua.FilterOperatorEquals, elemOp(7), good),                                                                            // 6: valid forward reference
		cfe(ua.FilterOperatorEquals, attrOp(nil, ua.AttributeIDValue), saoOp(ua.AttributeIDValue)),                               // 7: attribute operands
		cfe(ua.FilterOperatorEquals, rawOp(&ua.ReadValueID{}), good),                                                             // 8: not an operand type
		cfe(ua.FilterOperatorEquals, rawOp(ua.LiteralOperand{Value: ua.MustVariant(true)}), rawOp(ua.ElementOperand{Index: 99})), // 9: value forms
		cfe(ua.FilterOperatorEquals, rawOp(ua.AttributeOperand{}), rawOp(ua.SimpleAttributeOperand{})),                           // 10: value forms
	}}
	res, ok := validateFilter(filter)
	require.False(t, ok)
	require.Len(t, res.ElementResults, len(filter.Elements))

	want := []struct {
		elem ua.StatusCode
		ops  []ua.StatusCode
	}{
		{ua.StatusBadFilterOperandInvalid, []ua.StatusCode{ua.StatusBadFilterOperandInvalid, ua.StatusGood}},
		{ua.StatusBadFilterOperandInvalid, []ua.StatusCode{ua.StatusBadFilterOperandInvalid, ua.StatusGood}},
		{ua.StatusBadFilterOperandInvalid, []ua.StatusCode{ua.StatusBadFilterLiteralInvalid, ua.StatusGood}},
		{ua.StatusBadFilterOperandInvalid, []ua.StatusCode{ua.StatusBadFilterElementInvalid, ua.StatusGood}},
		{ua.StatusBadFilterOperandInvalid, []ua.StatusCode{ua.StatusBadFilterElementInvalid, ua.StatusGood}},
		{ua.StatusBadFilterOperandInvalid, []ua.StatusCode{ua.StatusBadFilterElementInvalid, ua.StatusGood}},
		{ua.StatusGood, []ua.StatusCode{ua.StatusGood, ua.StatusGood}},
		{ua.StatusGood, []ua.StatusCode{ua.StatusGood, ua.StatusGood}},
		{ua.StatusBadFilterOperandInvalid, []ua.StatusCode{ua.StatusBadFilterOperandInvalid, ua.StatusGood}},
		{ua.StatusBadFilterOperandInvalid, []ua.StatusCode{ua.StatusGood, ua.StatusBadFilterElementInvalid}},
		{ua.StatusGood, []ua.StatusCode{ua.StatusGood, ua.StatusGood}},
	}
	for i, w := range want {
		assert.Equal(t, w.elem, res.ElementResults[i].StatusCode, "element %d", i)
		assert.Equal(t, w.ops, res.ElementResults[i].OperandStatusCodes, "element %d operands", i)
	}

	// An empty filter is valid and yields no result structure.
	res, ok = validateFilter(nil)
	require.True(t, ok)
	require.Nil(t, res)
}

func TestFilter_EvalElementStatus(t *testing.T) {
	srv := newTestServer()
	node := anonNode()

	// An element operand pointing past the end of the filter.
	v, st := evalWithStatus(srv, node, cfe(ua.FilterOperatorNot, elemOp(5)))
	require.Equal(t, ua.StatusGood, st)
	require.Nil(t, v, "NOT of an unresolvable element is NULL")

	ev := &filterEvaluator{srv: srv, node: node, nodeID: node.ID(), elements: nil, visiting: nil}
	_, st = ev.evalElement(0)
	require.Equal(t, ua.StatusBadFilterElementInvalid, st)
	_, st = ev.evalElement(-1)
	require.Equal(t, ua.StatusBadFilterElementInvalid, st)

	// Wrong number of operands.
	_, st = evalWithStatus(srv, node, cfe(ua.FilterOperatorEquals, i32(1)))
	require.Equal(t, ua.StatusBadFilterOperandCountMismatch, st)
	_, st = evalWithStatus(srv, node, cfe(ua.FilterOperatorInList, i32(1)))
	require.Equal(t, ua.StatusBadFilterOperandCountMismatch, st)

	// An operator the evaluator does not know.
	_, st = evalWithStatus(srv, node, cfe(ua.FilterOperator(99)))
	require.Equal(t, ua.StatusBadFilterOperatorUnsupported, st)

	// A self-referencing element is rejected instead of recursing forever.
	v, st = evalWithStatus(srv, node, cfe(ua.FilterOperatorIsNull, elemOp(0)))
	require.Equal(t, ua.StatusGood, st)
	require.Equal(t, true, v.Value(), "the cyclic operand resolves to NULL")
}

func TestFilter_UnresolvableOperandsAreNull(t *testing.T) {
	srv := newTestServer()
	node := anonNode()
	isNull := func(op *ua.ExtensionObject) tvl {
		return evalFilter(srv, node, &ua.ContentFilter{Elements: []*ua.ContentFilterElement{cfe(ua.FilterOperatorIsNull, op)}})
	}
	require.Equal(t, tvlTrue, isNull(nil))
	require.Equal(t, tvlTrue, isNull(rawOp(&ua.ReadValueID{})))
	require.Equal(t, tvlTrue, isNull(lit(nil)))
	require.Equal(t, tvlFalse, isNull(rawOp(ua.LiteralOperand{Value: ua.MustVariant(int32(1))})))
}

func TestFilter_AttributeOperand(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	rw := srv.Node(ua.NewStringNodeID(ns.ID(), "rw_int32"))
	require.NotNil(t, rw)
	rwName := rw.BrowseName()
	require.NotNil(t, rwName)

	eq42 := func(node *Node, op *ua.ExtensionObject) tvl {
		return evalFilter(srv, node, &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
			cfe(ua.FilterOperatorEquals, op, i32(42)),
		}})
	}

	// No node id: the candidate node itself is read.
	require.Equal(t, tvlTrue, eq42(rw, attrOp(nil, ua.AttributeIDValue)))
	require.Equal(t, tvlTrue, eq42(rw, attrOp(ua.NewTwoByteNodeID(0), ua.AttributeIDValue)))
	// Explicit node id overrides the candidate node.
	require.Equal(t, tvlTrue, eq42(anonNode(), attrOp(rw.ID(), ua.AttributeIDValue)))
	// Explicit node id plus browse path.
	require.Equal(t, tvlTrue, eq42(anonNode(), attrOp(obj.ID(), ua.AttributeIDValue, rwName)))
	// Value form of the operand.
	require.Equal(t, tvlTrue, eq42(rw, rawOp(ua.AttributeOperand{AttributeID: ua.AttributeIDValue})))

	// Unresolvable inputs evaluate to NULL rather than failing.
	missing := &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "does_not_exist"}
	require.Equal(t, tvlNull, eq42(anonNode(), attrOp(obj.ID(), ua.AttributeIDValue, missing)))
	require.Equal(t, tvlNull, eq42(rw, attrOp(ua.NewStringNodeID(99, "x"), ua.AttributeIDValue)), "unknown namespace")
	require.Equal(t, tvlNull, eq42(rw, attrOp(ua.NewStringNodeID(ns.ID(), "nope"), ua.AttributeIDValue)), "unknown node")
	require.Equal(t, tvlNull, eq42(NewNode(nil, nil, nil, nil), attrOp(nil, ua.AttributeIDValue)), "candidate without node id")
}

func TestFilter_SimpleAttributeOperandPath(t *testing.T) {
	srv := newTestServer()
	ns, obj := addTestNamespace(srv)
	rw := srv.Node(ua.NewStringNodeID(ns.ID(), "rw_int32"))
	require.NotNil(t, rw)

	eq42 := func(node *Node, op *ua.ExtensionObject) tvl {
		return evalFilter(srv, node, &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
			cfe(ua.FilterOperatorEquals, op, i32(42)),
		}})
	}
	require.Equal(t, tvlTrue, eq42(obj, saoOp(ua.AttributeIDValue, rw.BrowseName())))
	// AttributeID 0 defaults to Value.
	require.Equal(t, tvlTrue, eq42(obj, saoOp(0, rw.BrowseName())))
	require.Equal(t, tvlTrue, eq42(rw, rawOp(ua.SimpleAttributeOperand{})))
	require.Equal(t, tvlNull, eq42(obj, saoOp(ua.AttributeIDValue, &ua.QualifiedName{NamespaceIndex: ns.ID(), Name: "missing"})))
}

func TestFilter_NullPropagation(t *testing.T) {
	srv := newTestServer()
	node := anonNode()
	null := lit(nil)
	nodeID := lit(ua.MustVariant(ua.NewNumericNodeID(0, id.Int32)))

	tests := []struct {
		name string
		el   *ua.ContentFilterElement
		want interface{} // nil = NULL
	}{
		{"ordering of booleans is undefined", cfe(ua.FilterOperatorGreaterThan, lit(ua.MustVariant(true)), lit(ua.MustVariant(false))), nil},
		{"ordering against null", cfe(ua.FilterOperatorLessThan, null, i32(1)), nil},
		{"ordering of strings", cfe(ua.FilterOperatorLessThan, str("abc"), str("abd")), true},
		{"between with null bound", cfe(ua.FilterOperatorBetween, i32(5), null, i32(9)), nil},
		{"in list with null value", cfe(ua.FilterOperatorInList, null, i32(1)), nil},
		{"in list miss with null member", cfe(ua.FilterOperatorInList, i32(1), null, i32(2)), nil},
		{"in list hit despite null member", cfe(ua.FilterOperatorInList, i32(2), null, i32(2)), true},
		{"in list miss", cfe(ua.FilterOperatorInList, i32(1), i32(2), i32(3)), false},
		{"like with null value", cfe(ua.FilterOperatorLike, null, str("%")), nil},
		{"like with null pattern", cfe(ua.FilterOperatorLike, str("a"), null), nil},
		{"like on a number", cfe(ua.FilterOperatorLike, i32(1), str("%")), nil},
		{"like with numeric pattern", cfe(ua.FilterOperatorLike, str("a"), i32(1)), nil},
		{"like with invalid character class", cfe(ua.FilterOperatorLike, str("a"), str("[z-a]")), nil},
		{"cast of null", cfe(ua.FilterOperatorCast, null, nodeID), nil},
		{"cast to null type", cfe(ua.FilterOperatorCast, i32(1), null), nil},
		{"cast to non node id type", cfe(ua.FilterOperatorCast, i32(1), i32(6)), nil},
		{"cast of string to int32 is undefined", cfe(ua.FilterOperatorCast, str("x"), nodeID), nil},
		{"oftype null", cfe(ua.FilterOperatorOfType, null), false},
		{"oftype non node id", cfe(ua.FilterOperatorOfType, i32(1)), false},
		{"oftype on untyped node", cfe(ua.FilterOperatorOfType, nodeID), false},
		{"inview null node id", cfe(ua.FilterOperatorInView, lit(ua.MustVariant(ua.NewTwoByteNodeID(0)))), true},
		{"inview non node id", cfe(ua.FilterOperatorInView, i32(1)), true},
		{"relatedto with null operand", cfe(ua.FilterOperatorRelatedTo, nodeID, null, nodeID), nil},
		{"relatedto on untyped node", cfe(ua.FilterOperatorRelatedTo, nodeID, nodeID, nodeID), false},
		{"bitwise and with null", cfe(ua.FilterOperatorBitwiseAnd, null, i32(1)), nil},
		{"bitwise or with string", cfe(ua.FilterOperatorBitwiseOr, str("a"), i32(1)), nil},
		{"bitwise and", cfe(ua.FilterOperatorBitwiseAnd, i32(12), i32(10)), int64(8)},
		{"and with non boolean operand", cfe(ua.FilterOperatorAnd, i32(1), lit(ua.MustVariant(true))), nil},
		{"or short circuits non boolean operand", cfe(ua.FilterOperatorOr, i32(1), lit(ua.MustVariant(true))), true},
		{"equal booleans", cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(true)), lit(ua.MustVariant(true))), true},
		{"unequal booleans", cfe(ua.FilterOperatorEquals, lit(ua.MustVariant(true)), lit(ua.MustVariant(false))), false},
		{"equal node ids", cfe(ua.FilterOperatorEquals, nodeID, lit(ua.MustVariant(ua.NewNumericNodeID(0, id.Int32)))), true},
		{"unequal node ids", cfe(ua.FilterOperatorEquals, nodeID, lit(ua.MustVariant(ua.NewNumericNodeID(0, id.Int64)))), false},
		{"string never equals number", cfe(ua.FilterOperatorEquals, str("1"), i32(1)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, st := evalWithStatus(srv, node, tt.el)
			require.Equal(t, ua.StatusGood, st)
			if tt.want == nil {
				require.Nil(t, v)
				return
			}
			require.NotNil(t, v)
			require.Equal(t, tt.want, v.Value())
		})
	}
}

func TestFilter_CastAndNodeIDHelpers(t *testing.T) {
	require.Equal(t, true, castVariant(ua.MustVariant(true), id.Boolean).Value())
	require.Equal(t, false, castVariant(ua.MustVariant(int32(0)), id.Boolean).Value())
	require.Nil(t, castVariant(ua.MustVariant("yes"), id.Boolean))
	require.Nil(t, castVariant(ua.MustVariant(int32(1)), id.DateTime), "unsupported target type")

	nid := ua.NewNumericNodeID(2, 77)
	require.Equal(t, nid, nodeIDOperand(ua.MustVariant(&ua.ExpandedNodeID{NodeID: nid})))
	require.Nil(t, nodeIDOperand(ua.MustVariant(int32(1))))
	require.Nil(t, nodeIDOperand(nil))

	_, ok := variantOrder(nil, ua.MustVariant(int32(1)))
	require.False(t, ok)
	_, ok = variantOrder(ua.MustVariant(int32(1)), ua.MustVariant("a"))
	require.False(t, ok)
}

func TestLikeToRegexp_EscapesAndClasses(t *testing.T) {
	tests := []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{`50\%`, []string{"50%"}, []string{"500", "50"}},
		{`a\_b`, []string{"a_b"}, []string{"axb"}},
		{`tail\`, []string{`tail\`}, []string{"tail", "tailx"}},
		{`[\]x]y`, []string{"]y", "xy"}, []string{"zy"}},
		{`[^ab]c`, []string{"xc"}, []string{"ac", "bc"}},
		{`a.c`, []string{"a.c"}, []string{"abc"}},
		{`_%z`, []string{"az", "abcz"}, []string{"z"}},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			re, err := likeToRegexp(tt.pattern)
			require.NoError(t, err)
			for _, s := range tt.match {
				assert.True(t, re.MatchString(s), "%q should match %q", tt.pattern, s)
			}
			for _, s := range tt.noMatch {
				assert.False(t, re.MatchString(s), "%q should not match %q", tt.pattern, s)
			}
		})
	}

	_, err := likeToRegexp("[z-a]")
	require.Error(t, err)
}

func TestFilter_RelatedToHops(t *testing.T) {
	srv := newTestServer()
	ns, _ := addTestNamespace(srv)

	objectType := srv.Node(ua.NewNumericNodeID(0, id.BaseObjectType))
	variableType := srv.Node(ua.NewNumericNodeID(0, id.BaseDataVariableType))
	require.NotNil(t, objectType)
	require.NotNil(t, variableType)

	newObject := func(name string) *Node {
		n := NewNode(
			ua.NewStringNodeID(ns.ID(), name),
			map[ua.AttributeID]*ua.DataValue{
				ua.AttributeIDNodeClass:   DataValueFromValue(uint32(ua.NodeClassObject)),
				ua.AttributeIDBrowseName:  DataValueFromValue(attrs.BrowseName(name)),
				ua.AttributeIDDisplayName: DataValueFromValue(attrs.DisplayName(name, name)),
			}, nil, nil)
		n.AddRef(objectType, id.HasTypeDefinition, true)
		return n
	}

	// top -> mid -> leaf(variable), with a back edge mid -> top, an inverse
	// reference and a reference to a node that is not in the address space.
	top, mid := newObject("hop_top"), newObject("hop_mid")
	ns.AddNode(top)
	ns.AddNode(mid)
	ghost := newObject("hop_ghost") // never added to the namespace
	leaf := ns.AddNewVariableStringNode("hop_leaf", int32(1))
	leaf.AddRef(variableType, id.HasTypeDefinition, true)

	top.AddRef(ghost, id.HasComponent, true)
	top.AddRef(mid, id.HasComponent, true)
	mid.AddRef(top, id.HasComponent, false)
	mid.AddRef(top, id.HasComponent, true)
	mid.AddRef(leaf, id.Organizes, true) // wrong reference type for the query below
	mid.AddRef(leaf, id.HasComponent, true)

	related := func(node *Node, hops ...*ua.ExtensionObject) tvl {
		ops := append([]*ua.ExtensionObject{
			lit(ua.MustVariant(ua.NewNumericNodeID(0, id.BaseObjectType))),
			lit(ua.MustVariant(ua.NewNumericNodeID(0, id.HasComponent))),
			lit(ua.MustVariant(ua.NewNumericNodeID(0, id.BaseDataVariableType))),
		}, hops...)
		return evalFilter(srv, node, &ua.ContentFilter{Elements: []*ua.ContentFilterElement{cfe(ua.FilterOperatorRelatedTo, ops...)}})
	}

	require.Equal(t, tvlFalse, related(top), "leaf is two hops away, default is one")
	require.Equal(t, tvlFalse, related(top, lit(ua.MustVariant(uint32(1)))))
	require.Equal(t, tvlTrue, related(top, lit(ua.MustVariant(uint32(2)))))
	require.Equal(t, tvlTrue, related(top, lit(ua.MustVariant(int32(5)))))
	require.Equal(t, tvlFalse, related(top, lit(ua.MustVariant(int32(0)))), "non-positive hop count falls back to one")
	require.Equal(t, tvlFalse, related(top, lit(nil)), "null hop count falls back to one")
	require.Equal(t, tvlTrue, related(mid))
	require.Equal(t, tvlFalse, related(leaf), "source type does not match")

	// Without the leaf the top<->mid cycle must terminate.
	require.True(t, mid.RemoveRef(ua.NewExpandedNodeID(leaf.ID(), "", 0), ua.NewNumericNodeID(0, id.HasComponent), true))
	require.Equal(t, tvlFalse, related(top, lit(ua.MustVariant(uint32(50)))))
}
