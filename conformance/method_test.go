// SPDX-License-Identifier: MIT

package conformance

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestMethod_CallSquare(t *testing.T) {
	c, f, ctx := setup(t)

	result, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, int32(9))
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, result.StatusCode)
	require.Len(t, result.OutputArguments, 1)
	require.Equal(t, int32(81), result.OutputArguments[0].Value())
}

func TestMethod_Arguments(t *testing.T) {
	c, f, ctx := setup(t)

	inputs, outputs, err := c.MethodArguments(ctx, f.MethodObject, f.SquareMethod)
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.Equal(t, "n", inputs[0].Name)
	require.Len(t, outputs, 1)
	require.Equal(t, "result", outputs[0].Name)
}

func TestMethod_CallRaw(t *testing.T) {
	c, f, ctx := setup(t)

	res, err := c.Call(ctx, &ua.CallMethodRequest{
		ObjectID:       f.MethodObject,
		MethodID:       f.SquareMethod,
		InputArguments: []*ua.Variant{ua.MustVariant(int32(6))},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, int32(36), res.OutputArguments[0].Value())
}

func TestMethod_Errors(t *testing.T) {
	c, f, ctx := setup(t)

	t.Run("unknown method", func(t *testing.T) {
		res, err := c.CallMethod(ctx, f.MethodObject, ua.NewStringNodeID(f.NSIndex, "DoesNotExist"), int32(1))
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadMethodInvalid, res.StatusCode)
	})

	t.Run("unknown object", func(t *testing.T) {
		res, err := c.CallMethod(ctx, ua.NewStringNodeID(f.NSIndex, "NoObject"), f.SquareMethod, int32(1))
		require.NoError(t, err)
		require.Equal(t, ua.StatusBadNodeIDUnknown, res.StatusCode)
	})

	t.Run("wrong argument type", func(t *testing.T) {
		res, err := c.CallMethod(ctx, f.MethodObject, f.SquareMethod, "not-an-int")
		require.NoError(t, err)
		require.NotEqual(t, ua.StatusOK, res.StatusCode)
	})
}
