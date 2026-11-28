// SPDX-License-Identifier: MIT

package uamethod_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// The contracts of push certificate management (ServerConfigurationType,
// OPC 10000-12 §7.10), of the SecurityGroup folders and key push targets of
// an SKS (OPC 10000-14 §8.5, §8.6, §8.7) and of the PublishSubscribe Object
// (§9.1.3), with the clauses of the NodeSet.
func TestServerConfigurationAndSecurityGroupContracts(t *testing.T) {
	for _, c := range []struct {
		m         *uamethod.Method
		id, typID uint32
		clause    string
		mandatory bool
		in, out   int
	}{
		{uamethod.ServerConfigurationTypeUpdateCertificate, id.ServerConfigurationTypeUpdateCertificate, id.ServerConfigurationType, "OPC 10000-12 §7.10.5", true, 6, 1},
		{uamethod.ServerConfigurationTypeCreateSelfSignedCertificate, id.ServerConfigurationTypeCreateSelfSignedCertificate, id.ServerConfigurationType, "OPC 10000-12 §7.10.6", false, 7, 1},
		{uamethod.ServerConfigurationTypeDeleteCertificate, id.ServerConfigurationTypeDeleteCertificate, id.ServerConfigurationType, "OPC 10000-12 §7.10.7", false, 2, 0},
		{uamethod.ServerConfigurationTypeGetCertificates, id.ServerConfigurationTypeGetCertificates, id.ServerConfigurationType, "OPC 10000-12 §7.10.8", false, 1, 2},
		{uamethod.ServerConfigurationTypeApplyChanges, id.ServerConfigurationTypeApplyChanges, id.ServerConfigurationType, "OPC 10000-12 §7.10.9", true, 0, 0},
		{uamethod.ServerConfigurationTypeCreateSigningRequest, id.ServerConfigurationTypeCreateSigningRequest, id.ServerConfigurationType, "OPC 10000-12 §7.10.10", true, 5, 1},
		{uamethod.ServerConfigurationTypeCancelChanges, id.ServerConfigurationTypeCancelChanges, id.ServerConfigurationType, "OPC 10000-12 §7.10.11", false, 0, 0},
		{uamethod.ServerConfigurationTypeGetRejectedList, id.ServerConfigurationTypeGetRejectedList, id.ServerConfigurationType, "OPC 10000-12 §7.10.12", true, 0, 1},
		{uamethod.ServerConfigurationTypeResetToServerDefaults, id.ServerConfigurationTypeResetToServerDefaults, id.ServerConfigurationType, "OPC 10000-12 §7.10.13", false, 0, 0},
		{uamethod.SecurityGroupFolderTypeAddSecurityGroup, id.SecurityGroupFolderTypeAddSecurityGroup, id.SecurityGroupFolderType, "OPC 10000-14 §8.5.2", true, 5, 2},
		{uamethod.SecurityGroupFolderTypeRemoveSecurityGroup, id.SecurityGroupFolderTypeRemoveSecurityGroup, id.SecurityGroupFolderType, "OPC 10000-14 §8.5.3", true, 1, 0},
		{uamethod.SecurityGroupFolderTypeAddSecurityGroupFolder, id.SecurityGroupFolderTypeAddSecurityGroupFolder, id.SecurityGroupFolderType, "OPC 10000-14 §8.5.4", false, 1, 1},
		{uamethod.SecurityGroupFolderTypeRemoveSecurityGroupFolder, id.SecurityGroupFolderTypeRemoveSecurityGroupFolder, id.SecurityGroupFolderType, "OPC 10000-14 §8.5.5", false, 1, 0},
		{uamethod.PubSubKeyPushTargetTypeConnectSecurityGroups, id.PubSubKeyPushTargetTypeConnectSecurityGroups, id.PubSubKeyPushTargetType, "OPC 10000-14 §8.6.3", true, 1, 1},
		{uamethod.PubSubKeyPushTargetTypeDisconnectSecurityGroups, id.PubSubKeyPushTargetTypeDisconnectSecurityGroups, id.PubSubKeyPushTargetType, "OPC 10000-14 §8.6.4", true, 1, 1},
		{uamethod.PubSubKeyPushTargetTypeTriggerKeyUpdate, id.PubSubKeyPushTargetTypeTriggerKeyUpdate, id.PubSubKeyPushTargetType, "OPC 10000-14 §8.6.6", true, 0, 0},
		{uamethod.PubSubKeyPushTargetFolderTypeAddPushTarget, id.PubSubKeyPushTargetFolderTypeAddPushTarget, id.PubSubKeyPushTargetFolderType, "OPC 10000-14 §8.7.2", true, 6, 1},
		{uamethod.PubSubKeyPushTargetFolderTypeRemovePushTarget, id.PubSubKeyPushTargetFolderTypeRemovePushTarget, id.PubSubKeyPushTargetFolderType, "OPC 10000-14 §8.7.3", true, 1, 0},
		{uamethod.PubSubKeyPushTargetFolderTypeAddPushTargetFolder, id.PubSubKeyPushTargetFolderTypeAddPushTargetFolder, id.PubSubKeyPushTargetFolderType, "OPC 10000-14 §8.7.4", false, 1, 1},
		{uamethod.PubSubKeyPushTargetFolderTypeRemovePushTargetFolder, id.PubSubKeyPushTargetFolderTypeRemovePushTargetFolder, id.PubSubKeyPushTargetFolderType, "OPC 10000-14 §8.7.5", false, 1, 0},
		{uamethod.PublishSubscribeTypeSetSecurityKeys, id.PublishSubscribeTypeSetSecurityKeys, id.PublishSubscribeType, "OPC 10000-14 §9.1.3.3", false, 7, 0},
		{uamethod.PublishSubscribeTypeAddConnection, id.PublishSubscribeTypeAddConnection, id.PublishSubscribeType, "OPC 10000-14 §9.1.3.4", false, 1, 1},
		{uamethod.PublishSubscribeTypeRemoveConnection, id.PublishSubscribeTypeRemoveConnection, id.PublishSubscribeType, "OPC 10000-14 §9.1.3.5", false, 1, 0},
	} {
		require.Equal(t, c.id, c.m.ID, c.m.String())
		require.Equal(t, c.typID, c.m.ObjectTypeID, c.m.String())
		require.Equal(t, c.clause, c.m.Clause, c.m.String())
		require.Equal(t, c.mandatory, c.m.Mandatory, c.m.String())
		require.Len(t, c.m.InputArguments(), c.in, c.m.String())
		require.Len(t, c.m.OutputArguments(), c.out, c.m.String())
	}
	// Subtypes of built-in types keep their DataType (Duration, IntegerId),
	// a structure is its own (UserTokenPolicy), an array is ValueRank 1.
	keys := uamethod.PublishSubscribeTypeSetSecurityKeys.InputArguments()
	require.Equal(t, ua.NewNumericNodeID(0, id.IntegerID), keys[2].DataType)
	require.Equal(t, int32(1), keys[4].ValueRank)
	require.Equal(t, ua.NewNumericNodeID(0, id.Duration), keys[5].DataType)
	require.Equal(t, ua.NewNumericNodeID(0, id.UserTokenPolicy), uamethod.PubSubKeyPushTargetFolderTypeAddPushTarget.InputArguments()[3].DataType)
	require.Equal(t, "IpAddresses", uamethod.ServerConfigurationTypeCreateSelfSignedCertificate.InputArguments()[4].Name)

	// A nil CertificateTypeId is the null NodeId, nil arrays the null array.
	in := (&uamethod.ServerConfigurationTypeUpdateCertificateInput{}).Pack()
	require.Equal(t, ua.NewTwoByteNodeID(0), in[1].Value())
	require.Equal(t, [][]byte(nil), in[3].Value())
}

// TestCallServerConfigurationAndSecurityGroup calls each Method of the
// families: its outputs, a Bad result and outputs of the wrong count.
func TestCallServerConfigurationAndSecurityGroup(t *testing.T) {
	ctx := context.Background()
	obj := ua.NewNumericNodeID(1, 5)
	n := ua.NewNumericNodeID(1, 6)
	c := &caller{}
	ok := func(out ...any) {
		c.res = &ua.CallMethodResult{}
		for _, o := range out {
			c.res.OutputArguments = append(c.res.OutputArguments, ua.MustVariant(o))
		}
	}

	ok(true)
	u, err := uamethod.CallServerConfigurationTypeUpdateCertificate(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.True(t, u.ApplyChangesRequired)
	require.Equal(t, ua.NewNumericNodeID(0, id.ServerConfigurationTypeUpdateCertificate), c.req.MethodID)
	ok([]byte{1})
	s, err := uamethod.CallServerConfigurationTypeCreateSelfSignedCertificate(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []byte{1}, s.Certificate)
	csr, err := uamethod.CallServerConfigurationTypeCreateSigningRequest(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []byte{1}, csr.CertificateRequest)
	ok([]*ua.NodeID{n}, [][]byte{{2}})
	g, err := uamethod.CallServerConfigurationTypeGetCertificates(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{n}, g.CertificateTypeIDs)
	ok([][]byte{{3}})
	r, err := uamethod.CallServerConfigurationTypeGetRejectedList(ctx, c, obj, nil)
	require.NoError(t, err)
	require.Equal(t, [][]byte{{3}}, r.Certificates)
	ok("sg", n)
	a, err := uamethod.CallSecurityGroupFolderTypeAddSecurityGroup(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "sg", a.SecurityGroupID)
	require.Equal(t, n, a.SecurityGroupNodeID)
	ok(n)
	f, err := uamethod.CallSecurityGroupFolderTypeAddSecurityGroupFolder(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, n, f.SecurityGroupFolderNodeID)
	pt, err := uamethod.CallPubSubKeyPushTargetFolderTypeAddPushTarget(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, n, pt.PushTargetID)
	ptf, err := uamethod.CallPubSubKeyPushTargetFolderTypeAddPushTargetFolder(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, n, ptf.PushTargetFolderNodeID)
	ac, err := uamethod.CallPublishSubscribeTypeAddConnection(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, n, ac.ConnectionID)
	ok([]ua.StatusCode{ua.StatusOK})
	cs, err := uamethod.CallPubSubKeyPushTargetTypeConnectSecurityGroups(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, cs.ConnectResults)
	ds, err := uamethod.CallPubSubKeyPushTargetTypeDisconnectSecurityGroups(ctx, c, obj, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, ds.DisconnectResults)
	ok()
	in := &uamethod.PublishSubscribeTypeSetSecurityKeysInput{SecurityGroupID: "sg", CurrentTokenID: 2, FutureKeys: [][]byte{}}
	require.NoError(t, uamethod.CallPublishSubscribeTypeSetSecurityKeys(ctx, c, obj, nil, in))
	require.Equal(t, in.Pack(), c.req.InputArguments)

	calls := []func() error{
		func() error {
			_, err := uamethod.CallServerConfigurationTypeUpdateCertificate(ctx, c, obj, nil, nil)
			return err
		},
		func() error {
			_, err := uamethod.CallServerConfigurationTypeCreateSelfSignedCertificate(ctx, c, obj, nil, nil)
			return err
		},
		func() error { return uamethod.CallServerConfigurationTypeDeleteCertificate(ctx, c, obj, nil, nil) },
		func() error {
			_, err := uamethod.CallServerConfigurationTypeGetCertificates(ctx, c, obj, nil, nil)
			return err
		},
		func() error { return uamethod.CallServerConfigurationTypeApplyChanges(ctx, c, obj, nil) },
		func() error {
			_, err := uamethod.CallServerConfigurationTypeCreateSigningRequest(ctx, c, obj, nil, nil)
			return err
		},
		func() error { return uamethod.CallServerConfigurationTypeCancelChanges(ctx, c, obj, nil) },
		func() error {
			_, err := uamethod.CallServerConfigurationTypeGetRejectedList(ctx, c, obj, nil)
			return err
		},
		func() error { return uamethod.CallServerConfigurationTypeResetToServerDefaults(ctx, c, obj, nil) },
		func() error {
			_, err := uamethod.CallSecurityGroupFolderTypeAddSecurityGroup(ctx, c, obj, nil, nil)
			return err
		},
		func() error { return uamethod.CallSecurityGroupFolderTypeRemoveSecurityGroup(ctx, c, obj, nil, nil) },
		func() error {
			_, err := uamethod.CallSecurityGroupFolderTypeAddSecurityGroupFolder(ctx, c, obj, nil, nil)
			return err
		},
		func() error {
			return uamethod.CallSecurityGroupFolderTypeRemoveSecurityGroupFolder(ctx, c, obj, nil, nil)
		},
		func() error {
			_, err := uamethod.CallPubSubKeyPushTargetTypeConnectSecurityGroups(ctx, c, obj, nil, nil)
			return err
		},
		func() error {
			_, err := uamethod.CallPubSubKeyPushTargetTypeDisconnectSecurityGroups(ctx, c, obj, nil, nil)
			return err
		},
		func() error { return uamethod.CallPubSubKeyPushTargetTypeTriggerKeyUpdate(ctx, c, obj, nil) },
		func() error {
			_, err := uamethod.CallPubSubKeyPushTargetFolderTypeAddPushTarget(ctx, c, obj, nil, nil)
			return err
		},
		func() error {
			return uamethod.CallPubSubKeyPushTargetFolderTypeRemovePushTarget(ctx, c, obj, nil, nil)
		},
		func() error {
			_, err := uamethod.CallPubSubKeyPushTargetFolderTypeAddPushTargetFolder(ctx, c, obj, nil, nil)
			return err
		},
		func() error {
			return uamethod.CallPubSubKeyPushTargetFolderTypeRemovePushTargetFolder(ctx, c, obj, nil, nil)
		},
		func() error { return uamethod.CallPublishSubscribeTypeSetSecurityKeys(ctx, c, obj, nil, nil) },
		func() error {
			_, err := uamethod.CallPublishSubscribeTypeAddConnection(ctx, c, obj, nil, nil)
			return err
		},
		func() error { return uamethod.CallPublishSubscribeTypeRemoveConnection(ctx, c, obj, nil, nil) },
	}
	c.res = &ua.CallMethodResult{StatusCode: ua.StatusBadUserAccessDenied}
	for i, call := range calls {
		require.ErrorIs(t, call(), ua.StatusBadUserAccessDenied, "call %d", i)
	}
	ok(int32(1), int32(2), int32(3))
	for i, call := range calls {
		require.ErrorIs(t, call(), ua.StatusBadTooManyArguments, "call %d", i)
	}
}
