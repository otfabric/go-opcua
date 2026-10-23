// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestMethodCallerFromContext(t *testing.T) {
	_, ok := MethodCallerFromContext(context.Background())
	require.False(t, ok)

	c, ok := MethodCallerFromContext(withMethodCaller(context.Background(), nil, nil))
	require.True(t, ok)
	require.Equal(t, ua.MessageSecurityModeNone, c.SecurityMode)
	require.Nil(t, c.SessionID)

	sess := &session{ID: ua.NewNumericNodeID(1, 5), identityToken: &ua.AnonymousIdentityToken{}, roles: []*ua.NodeID{ua.RoleAnonymous.NodeID()}}
	c, ok = MethodCallerFromContext(withMethodCaller(context.Background(), sess, nil))
	require.True(t, ok)
	require.Equal(t, sess.ID, c.SessionID)
	require.Equal(t, sess.identityToken, c.Identity)
	require.Equal(t, sess.roles, c.Roles)
	c.Roles[0] = nil
	require.NotNil(t, sess.roles[0], "roles are copied")
}

// TestVariantMatchesArgumentSubtypes checks that arguments declared with a
// subtype of a built-in type (IntegerId, Duration) accept the built-in
// encoding, and that an empty array matches ValueRank 1.
func TestVariantMatchesArgumentSubtypes(t *testing.T) {
	srv := newTestServer()
	arg := func(dt uint32, rank int32) *ua.Argument {
		return &ua.Argument{DataType: ua.NewNumericNodeID(0, dt), ValueRank: rank}
	}
	cases := []struct {
		name string
		v    any
		a    *ua.Argument
		want bool
	}{
		{"IntegerId as UInt32", uint32(1), arg(id.IntegerID, -1), true},
		{"IntegerId as Int32", int32(1), arg(id.IntegerID, -1), false},
		{"Duration as Double", 1.5, arg(id.Duration, -1), true},
		{"Duration as Float", float32(1.5), arg(id.Duration, -1), false},
		{"UtcTime", time.Now(), arg(id.UtcTime, -1), true},
		{"BaseDataType any", "x", arg(id.BaseDataType, -1), true},
		{"Number any", "x", arg(id.Number, -1), true},
		{"empty ByteString array", [][]byte{}, arg(id.ByteString, 1), true},
		{"ByteString array", [][]byte{{1}}, arg(id.ByteString, 1), true},
		{"scalar for array", []byte{1}, arg(id.ByteString, 1), false},
		{"array for scalar", []string{"a"}, arg(id.String, -1), false},
		{"any rank", []string{"a"}, arg(id.String, -2), true},
		{"custom namespace", "x", &ua.Argument{DataType: ua.NewNumericNodeID(2, 5)}, true},
		{"string type id", "x", &ua.Argument{DataType: ua.NewStringNodeID(0, "x")}, true},
		{"unknown type", "x", arg(999999, -1), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, variantMatchesArgument(srv, ua.MustVariant(c.v), c.a))
		})
	}
	require.True(t, variantMatchesArgument(srv, nil, arg(id.String, -1)))
	require.True(t, variantMatchesArgument(nil, ua.MustVariant("x"), arg(123456, -1)))
}

func TestSKSHelpers(t *testing.T) {
	_, ok := msDuration(math.NaN())
	require.False(t, ok)
	_, ok = msDuration(math.Inf(1))
	require.False(t, ok)
	d, ok := msDuration(1.5)
	require.True(t, ok)
	require.Equal(t, 1500*time.Microsecond, d)
	require.Equal(t, 1.5, durationMS(d))
	require.Equal(t, ua.StatusBadTypeMismatch, checkArgs([]*ua.Variant{nil}, ua.TypeIDString))
	require.Equal(t, ua.StatusBadTooManyArguments, checkArgs([]*ua.Variant{ua.MustVariant("a"), ua.MustVariant("b")}, ua.TypeIDString))
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, requireEncryption(nil))
	require.Nil(t, sksCaller(context.Background()))
}
