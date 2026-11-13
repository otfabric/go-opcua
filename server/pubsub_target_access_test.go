// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestPubSubTargetVariables_NonValueAttributeRespectsWriteMask(t *testing.T) {
	s := newTestServer()
	ns, _ := addTestNamespace(s)
	n := ns.AddNewVariableStringNode("target", int32(1))
	require.NoError(t, n.SetAttribute(ua.AttributeIDAccessLevel, DataValueFromValue(byte(ua.AccessLevelTypeCurrentRead))))
	write := func(attr ua.AttributeID, v any) ua.StatusCode {
		return s.writeTarget(&ua.FieldTargetDataType{TargetNodeID: n.ID(), AttributeID: attr}, DataValueFromValue(v))
	}
	// No WriteMask: neither AccessLevel nor DisplayName can be written.
	require.Equal(t, ua.StatusBadNotWritable, write(ua.AttributeIDAccessLevel, byte(3)))
	require.Equal(t, ua.StatusBadNotWritable, write(ua.AttributeIDDisplayName, byte(3)))
	require.Equal(t, ua.StatusBadNotWritable, write(ua.AttributeIDValue, int32(5)), "AccessLevel CurrentRead")
	al, err := n.Attribute(ua.AttributeIDAccessLevel)
	require.NoError(t, err)
	require.Equal(t, byte(ua.AccessLevelTypeCurrentRead), al.Value.Value.Value())

	// With the WriteMask bit, a value of the Attribute's DataType only.
	require.NoError(t, n.SetAttribute(ua.AttributeIDWriteMask, DataValueFromValue(uint32(ua.AttributeWriteMaskDisplayName))))
	require.Equal(t, ua.StatusBadTypeMismatch, write(ua.AttributeIDDisplayName, byte(3)))
	require.Equal(t, ua.StatusOK, write(ua.AttributeIDDisplayName, ua.NewLocalizedText("x")))
}

func TestPubSubConfigMethodsHaveRolePermissions(t *testing.T) {
	s := newTestServer()
	s.restrictPubSubMethods()
	want := DefaultNodePermissions[id.PublishSubscribeAddConnection].RolePermissions
	require.NotEmpty(t, want)
	for _, mid := range pubsubConfigMethods {
		n := s.ownNode(mid)
		if n == nil {
			continue
		}
		n.mu.RLock()
		got := len(n.rolePermissions)
		n.mu.RUnlock()
		require.NotZero(t, got, "i=%d", mid)
	}
	// Methods that have RolePermissions keep theirs.
	open := s.ownNode(id.PublishSubscribePubSubConfigurationOpen)
	require.NotNil(t, open)
	require.Len(t, open.rolePermissions, len(DefaultNodePermissions[id.PublishSubscribePubSubConfigurationOpen].RolePermissions))
}

func TestPubSubReaderTargetsChecks(t *testing.T) {
	s := newTestServer()
	m := &pubsubModel{s: s}
	ctx := context.Background()
	// Not a client call: the operator decides.
	require.Equal(t, ua.StatusOK, m.checkReaderTargets(ctx, &ua.DataSetReaderDataType{}))
	require.Equal(t, ua.StatusOK, m.checkPublishedRead(ctx, &ua.PublishedVariableDataType{PublishedVariable: ua.NewStringNodeID(1, "x")}))

	// A client call whose session is gone: no session, as for the services.
	cctx := context.WithValue(ctx, methodCallerKey{}, &MethodCaller{SessionID: ua.NewStringNodeID(1, "gone")})
	sess, client := m.callerSession(cctx)
	require.True(t, client)
	require.Nil(t, sess)
	s.cfg.accessController = noReads{}
	mirror := &ua.DataSetReaderDataType{SubscribedDataSet: ua.NewExtensionObject(&ua.SubscribedDataSetMirrorDataType{})}
	require.Equal(t, ua.StatusOK, m.checkConnectionTargets(cctx, nil, &ua.PubSubConnectionDataType{ReaderGroups: []*ua.ReaderGroupDataType{nil,
		{DataSetReaders: []*ua.DataSetReaderDataType{nil, {}, mirror}}}}))
	target := &ua.DataSetReaderDataType{SubscribedDataSet: ua.NewExtensionObject(&ua.TargetVariablesDataType{
		TargetVariables: []*ua.FieldTargetDataType{nil, {}, {TargetNodeID: ua.NewStringNodeID(1, "x")}}})}
	require.Equal(t, ua.StatusBadUserAccessDenied, m.checkGroupTargets(cctx, &ua.ReaderGroupDataType{DataSetReaders: []*ua.DataSetReaderDataType{target}}))
	require.Equal(t, ua.StatusBadUserAccessDenied, m.checkPublishedRead(cctx, &ua.PublishedVariableDataType{PublishedVariable: ua.NewStringNodeID(1, "x")}))

	// A target in a namespace that does not exist.
	s.cfg.accessController = DefaultAccessController{}
	require.Equal(t, ua.StatusOK, s.checkTargetWrite(ctx, nil, &ua.FieldTargetDataType{TargetNodeID: ua.NewStringNodeID(99, "x"), AttributeID: ua.AttributeIDDisplayName}))
	require.Equal(t, ua.StatusBadNotWritable, s.checkTargetWrite(ctx, nil, &ua.FieldTargetDataType{TargetNodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDNodeID}))
}
