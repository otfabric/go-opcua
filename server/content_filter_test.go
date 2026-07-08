// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
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
