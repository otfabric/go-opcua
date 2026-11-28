// SPDX-License-Identifier: MIT

package uamethod

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// testMethod has an argument of each kind the generator emits a helper
// for, and of each ValueRank of Part 3 §5.6.2.
var testMethod = &Method{
	Name: "M", ObjectType: "T", Namespace: "urn:test", ID: 1, ObjectTypeID: 2,
	in: []argument{
		{name: "Scalar", dataType: id.Int32, valueRank: rankScalar, builtin: ua.TypeIDInt32},
		{name: "Array", dataType: id.Int32, valueRank: rankOneDimension, builtin: ua.TypeIDInt32},
		{name: "Any", dataType: id.BaseDataType, valueRank: rankAny},
		{name: "ScalarOrArray", dataType: id.Int32, valueRank: rankScalarOrOneDimension, builtin: ua.TypeIDInt32},
		{name: "OneOrMore", dataType: id.Int32, valueRank: rankOneOrMoreDimensions, builtin: ua.TypeIDInt32},
		{name: "Matrix", dataType: id.Int32, valueRank: 2, builtin: ua.TypeIDInt32},
		{name: "Structure", dataType: id.Range, valueRank: rankScalar, builtin: ua.TypeIDExtensionObject},
		{name: "Structures", dataType: id.Range, valueRank: rankOneDimension, builtin: ua.TypeIDExtensionObject},
		{name: "Node", dataType: id.NodeID, valueRank: rankScalar, builtin: ua.TypeIDNodeID},
	},
}

func TestShapeValueRanks(t *testing.T) {
	vs := make([]*ua.Variant, len(testMethod.in))
	shape := func(i int, v *ua.Variant) error {
		vs[i] = v
		return testMethod.shape(false, vs, i)
	}
	matrix, err := ua.NewVariant([][]int32{{1, 2}, {3, 4}})
	require.NoError(t, err)
	cube, err := ua.NewVariant([][][]int32{{{1}}})
	require.NoError(t, err)
	scalar, array := ua.MustVariant(int32(1)), ua.MustVariant([]int32{1})

	require.NoError(t, shape(0, scalar))
	require.ErrorIs(t, shape(0, array), ua.StatusBadTypeMismatch)
	require.NoError(t, shape(1, array))
	require.ErrorIs(t, shape(1, scalar), ua.StatusBadTypeMismatch)
	require.ErrorIs(t, shape(1, matrix), ua.StatusBadTypeMismatch)
	require.NoError(t, shape(2, ua.MustVariant("anything")))
	require.NoError(t, shape(2, nil))
	require.NoError(t, shape(3, scalar))
	require.NoError(t, shape(3, array))
	require.ErrorIs(t, shape(3, matrix), ua.StatusBadTypeMismatch)
	require.NoError(t, shape(4, array))
	require.NoError(t, shape(4, matrix))
	require.ErrorIs(t, shape(4, scalar), ua.StatusBadTypeMismatch)
	require.NoError(t, shape(5, matrix))
	require.ErrorIs(t, shape(5, cube), ua.StatusBadTypeMismatch)
	err = shape(5, array)
	require.ErrorContains(t, err, "want ValueRank 2")
	require.ErrorContains(t, err, "input argument 5 (Matrix)")
}

func TestHelpers(t *testing.T) {
	m := testMethod
	r := &ua.Range{Low: 1, High: 2}

	// array: a value, the null array, and a Variant of the type whose value
	// is not of the Go type.
	xs, err := array[int32](m, false, []*ua.Variant{nil, ua.MustVariant([]int32{1, 2})}, 1)
	require.NoError(t, err)
	require.Equal(t, []int32{1, 2}, xs)
	_, err = array[int32](m, false, []*ua.Variant{nil, ua.MustVariant(int32(1))}, 1)
	require.ErrorIs(t, err, ua.StatusBadTypeMismatch)
	_, err = array[int64](m, false, []*ua.Variant{nil, ua.MustVariant([]int32{1})}, 1)
	require.ErrorContains(t, err, "want []int64")
	// A null array, as it decodes (Part 6 §5.2.5).
	nullArray := new(ua.Variant)
	_, err = nullArray.Decode([]byte{0x86, 0xff, 0xff, 0xff, 0xff})
	require.NoError(t, err)
	xs, err = array[int32](m, false, []*ua.Variant{nil, nullArray}, 1)
	require.NoError(t, err)
	require.Nil(t, xs)

	// variant: as it is.
	v := ua.MustVariant("x")
	args := []*ua.Variant{nil, nil, v}
	got, err := variant(m, false, args, 2)
	require.NoError(t, err)
	require.Same(t, v, got)
	_, err = variant(m, false, []*ua.Variant{nil, nil, nil, nil, nil, ua.MustVariant(int32(1))}, 5)
	require.Error(t, err)

	// scalar: a Variant of the type with another Go type.
	_, err = scalar[int64](m, false, []*ua.Variant{ua.MustVariant(int32(1))}, 0)
	require.ErrorContains(t, err, "a value of int32, want int64")

	// structure.
	at := func(i int, v *ua.Variant) []*ua.Variant {
		a := make([]*ua.Variant, len(m.in))
		a[i] = v
		return a
	}
	s, err := structure[ua.Range](m, false, at(6, ua.MustVariant(ua.NewExtensionObject(r))), 6)
	require.NoError(t, err)
	require.Equal(t, r, s)
	s, err = structure[ua.Range](m, false, at(6, ua.MustVariant(ua.NewExtensionObject(nil))), 6)
	require.NoError(t, err)
	require.Nil(t, s)
	_, err = structure[ua.Range](m, false, at(6, ua.MustVariant(ua.NewExtensionObject(&ua.EUInformation{}))), 6)
	require.ErrorContains(t, err, "an ExtensionObject of *ua.EUInformation, want *ua.Range")
	_, err = structure[ua.Range](m, false, at(6, ua.MustVariant(int32(1))), 6)
	require.ErrorIs(t, err, ua.StatusBadTypeMismatch)

	// structures and packStructures.
	ss, err := structures[ua.Range](m, false, at(7, packStructures([]*ua.Range{r, nil})), 7)
	require.NoError(t, err)
	require.Equal(t, []*ua.Range{r, nil}, ss)
	ss, err = structures[ua.Range](m, false, at(7, packStructures[ua.Range](nil)), 7)
	require.NoError(t, err)
	require.Nil(t, ss)
	_, err = structures[ua.Range](m, false, at(7, ua.MustVariant([]*ua.ExtensionObject{ua.NewExtensionObject(&ua.EUInformation{})})), 7)
	require.ErrorContains(t, err, "element 0")
	_, err = structures[ua.Range](m, false, at(7, ua.MustVariant(int32(1))), 7)
	require.ErrorIs(t, err, ua.StatusBadTypeMismatch)

	// pointer: the null NodeId is a value, not nil.
	n, err := pointer[ua.NodeID](m, false, at(8, ua.MustVariant(ua.NewTwoByteNodeID(0))), 8)
	require.NoError(t, err)
	require.NotNil(t, n)
	_, err = pointer[ua.NodeID](m, false, at(8, ua.MustVariant(int32(0))), 8)
	require.ErrorIs(t, err, ua.StatusBadTypeMismatch)

	require.Equal(t, &ua.Variant{}, orNull(nil))
	require.Same(t, v, orNull(v))
	require.Equal(t, ua.NewExtensionObject(nil), orNullObject(nil))
	eo := ua.NewExtensionObject(r)
	require.Same(t, eo, orNullObject(eo))
	require.Equal(t, ua.NewTwoByteNodeID(0), nodeID(nil))
}

func TestCallOutsideNamespaceZero(t *testing.T) {
	_, err := testMethod.Call(context.Background(), nil, ua.NewNumericNodeID(1, 1), nil, nil)
	require.ErrorContains(t, err, "the NodeId of the Method is required outside namespace 0")
	require.Equal(t, "T.M", testMethod.String())
	require.Nil(t, (&Method{}).InputArguments())
}
