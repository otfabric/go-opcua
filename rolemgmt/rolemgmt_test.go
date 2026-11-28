// SPDX-License-Identifier: MIT

package rolemgmt

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// newServer starts a server with the managed RoleSet whose SecurityAdmin
// role has the user alice; bob is another user.
func newServer(t *testing.T) string {
	t.Helper()
	_, url := conformkit.NewServerPrepared(t, func(srv *server.Server) {
		require.NoError(t, srv.RoleSet().AddIdentity(ua.RoleSecurityAdmin.NodeID(),
			&ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "alice"}))
	}, conformkit.SecureServerOpts(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == "bob" && pass == "builder" {
				return nil
			}
			return conformkit.UserValidator(user, pass)
		}),
		server.WithRoleManagement(server.RoleManagement{}))...)
	return url
}

func connect(t *testing.T, url, user, pass string) *opcua.Client {
	t.Helper()
	ep := conformkit.EndpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	return conformkit.NewClient(t, url, append(conformkit.SecureClientOpts(t, ep, ua.UserTokenTypeUserName),
		opcua.AuthUsername(user, pass))...)
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	cleanup.Register(t, cancel)
	return ctx
}

func TestRoleSet(t *testing.T) {
	url := newServer(t)
	ctx := testCtx(t)
	c := connect(t, url, "alice", "wonderland")
	rs := New(c)
	require.True(t, rs.NodeID().Equal(ua.NewNumericNodeID(0, id.ServerServerCapabilitiesRoleSet)))

	roles, err := rs.Roles(ctx)
	require.NoError(t, err)
	require.Len(t, roles, 12)
	require.Equal(t, "Anonymous", roles[0].BrowseName.Name)

	role, err := rs.AddRole(ctx, "Maintainer", "")
	require.NoError(t, err)
	require.NotNil(t, role.NodeID)
	_, err = rs.AddRole(ctx, "Maintainer", "")
	require.ErrorIs(t, err, ua.StatusBadAlreadyExists)

	rule := &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "bob"}
	ep := &ua.EndpointType{EndpointURL: "opc.tcp://host:4840"}
	require.NoError(t, role.AddIdentity(ctx, rule))
	require.NoError(t, role.AddApplication(ctx, "urn:app"))
	require.NoError(t, role.AddEndpoint(ctx, ep))
	require.NoError(t, role.SetApplicationsExclude(ctx, false))
	require.NoError(t, role.SetEndpointsExclude(ctx, false))
	cfg, err := role.Config(ctx)
	require.NoError(t, err)
	require.Equal(t, &Config{
		Identities:   []*ua.IdentityMappingRuleType{rule},
		Applications: []string{"urn:app"},
		Endpoints:    []*ua.EndpointType{ep},
	}, cfg)

	require.NoError(t, role.RemoveIdentity(ctx, rule))
	require.NoError(t, role.RemoveApplication(ctx, "urn:app"))
	require.NoError(t, role.RemoveEndpoint(ctx, ep))
	require.ErrorIs(t, role.RemoveEndpoint(ctx, ep), ua.StatusBadNotFound)
	cfg, err = role.Config(ctx)
	require.NoError(t, err)
	require.Empty(t, cfg.Identities)
	require.Empty(t, cfg.Applications)
	require.Empty(t, cfg.Endpoints)

	require.NoError(t, rs.RemoveRole(ctx, role.NodeID))
	require.ErrorIs(t, rs.RemoveRole(ctx, role.NodeID), ua.StatusBadNodeIDUnknown)

	// Roles of another Object: none of its components is a role.
	other, err := NewRoleSet(c, ua.NewNumericNodeID(0, id.Server)).Roles(ctx)
	require.NoError(t, err)
	require.Empty(t, other)
}

func TestRoleErrors(t *testing.T) {
	url := newServer(t)
	ctx := testCtx(t)
	alice := connect(t, url, "alice", "wonderland")
	rs := New(alice)

	// A role without the Exclude Properties (§4.3), an Object without the
	// Properties of RoleType.
	require.ErrorIs(t, rs.Role(ua.RoleAnonymous.NodeID()).SetApplicationsExclude(ctx, false), ua.StatusBadNotFound)
	_, err := rs.Role(ua.NewNumericNodeID(0, id.ObjectsFolder)).Config(ctx)
	require.ErrorIs(t, err, ua.StatusBadNotFound)

	// A user without SecurityAdmin.
	bob := connect(t, url, "bob", "builder")
	require.ErrorIs(t, New(bob).Role(ua.RoleObserver.NodeID()).SetEndpointsExclude(ctx, false), ua.StatusBadUserAccessDenied)

	// A client that is gone.
	gone := connect(t, url, "alice", "wonderland")
	require.NoError(t, gone.Close(ctx))
	g := New(gone)
	_, err = g.Roles(ctx)
	require.Error(t, err)
	_, err = g.AddRole(ctx, "X", "")
	require.Error(t, err)
	observer := g.Role(ua.RoleObserver.NodeID())
	_, err = observer.Config(ctx)
	require.Error(t, err)
	require.Error(t, observer.SetApplicationsExclude(ctx, true))
	require.Error(t, observer.AddApplication(ctx, "urn:x"))
}

// A Read or Write the server refuses.
func TestRoleReadWriteRefused(t *testing.T) {
	url := newServer(t)
	ctx := testCtx(t)
	alice := connect(t, url, "alice", "wonderland")
	observer := New(alice).Role(ua.RoleObserver.NodeID())
	_, err := observer.Config(ctx) // browses the Properties
	require.NoError(t, err)
	require.NoError(t, alice.Close(ctx))
	require.Error(t, observer.SetEndpointsExclude(ctx, true), "the Write fails")
	_, err = observer.Config(ctx)
	require.Error(t, err, "the Read fails")
}

func TestConfigOf(t *testing.T) {
	t.Parallel()
	rule := &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeAnonymous}
	dv := func(v any) *ua.DataValue { return &ua.DataValue{Value: ua.MustVariant(v)} }
	cfg, err := configOf(
		[]string{propIdentities, propApplications, propApplicationsExclude, propEndpoints, propEndpointsExclude, propCustomConfiguration, "Other", propApplications},
		[]*ua.DataValue{
			dv([]*ua.ExtensionObject{nil, ua.NewExtensionObject(rule), ua.NewExtensionObject(&ua.EndpointType{})}),
			nil,
			dv(true),
			dv("not endpoints"),
			{Status: ua.StatusUncertain},
			dv(true),
			dv(int32(1)),
			{},
		})
	require.NoError(t, err)
	require.Equal(t, &Config{Identities: []*ua.IdentityMappingRuleType{rule}, ApplicationsExclude: true, CustomConfiguration: true}, cfg)

	_, err = configOf([]string{propIdentities}, []*ua.DataValue{{Status: ua.StatusBadUserAccessDenied}})
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
}

func TestIsRole(t *testing.T) {
	t.Parallel()
	nid := ua.NewExpandedNodeID(ua.NewNumericNodeID(0, 1), "", 0)
	require.False(t, isRole(nil))
	require.False(t, isRole(&ua.ReferenceDescription{NodeID: nid}))
	require.False(t, isRole(&ua.ReferenceDescription{NodeID: nid, TypeDefinition: ua.NewExpandedNodeID(ua.NewNumericNodeID(1, id.RoleType), "", 0)}))
	require.True(t, isRole(&ua.ReferenceDescription{NodeID: nid, TypeDefinition: ua.NewExpandedNodeID(ua.NewNumericNodeID(0, id.RoleType), "", 0)}))
}
