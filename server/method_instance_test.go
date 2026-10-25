// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// TestInstanceMethod: the Method of an ObjectType (or a supertype) called
// on an instance is the Method of the instance with its BrowseName.
func TestInstanceMethod(t *testing.T) {
	s := newPushServer(t, PushManagement{})
	obj := ua.NewNumericNodeID(0, tlObj)
	call := func(o *ua.NodeID, m uint32) *ua.NodeID {
		t.Helper()
		r := s.instanceMethod(&ua.CallMethodRequest{ObjectID: o, MethodID: ua.NewNumericNodeID(0, m)})
		return r.MethodID
	}
	require.True(t, call(obj, id.FileTypeOpen).Equal(ua.NewNumericNodeID(0, mOpen)), "a method of the supertype FileType")
	require.True(t, call(obj, id.FileTypeClose).Equal(ua.NewNumericNodeID(0, mClose)))
	require.True(t, call(obj, id.TrustListTypeOpenWithMasks).Equal(ua.NewNumericNodeID(0, mOpenMasks)), "a method of TrustListType")
	require.True(t, call(obj, mOpen).Equal(ua.NewNumericNodeID(0, mOpen)), "the method of the instance")
	require.True(t, call(obj, id.ServerTypeGetMonitoredItems).Equal(ua.NewNumericNodeID(0, id.ServerTypeGetMonitoredItems)), "not of the type")
	require.True(t, call(obj, id.Server).Equal(ua.NewNumericNodeID(0, id.Server)), "not a method")
	require.True(t, call(ua.NewNumericNodeID(0, id.ObjectsFolder), id.FileTypeOpen).Equal(ua.NewNumericNodeID(0, id.FileTypeOpen)), "the object is no file")
	require.True(t, call(ua.NewNumericNodeID(9, 1), id.FileTypeOpen).Equal(ua.NewNumericNodeID(0, id.FileTypeOpen)), "unknown object")
	require.Nil(t, s.instanceMethod(nil))
	r := &ua.CallMethodRequest{ObjectID: obj}
	require.Same(t, r, s.instanceMethod(r))
}
