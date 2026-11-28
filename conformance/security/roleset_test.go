// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/rolemgmt"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
	"github.com/stretchr/testify/require"
)

// The managed RoleSet of OPC 10000-18 over the wire: the RoleSet and Role
// Methods (§4.2.2, §4.2.3, §4.4.5 to §4.4.10), the Properties of the roles
// (§4.4.1) and the roles a session gets from them, at ActivateSession and
// again when a role changes (§4.4.1).

const rolesTestNS = "urn:conformance:roleset"

// roleSetServer is a server with the managed RoleSet whose SecurityAdmin
// role has the user alice, the user bob as another AuthenticatedUser, RBAC
// and a variable v in the namespace rolesTestNS.
type roleSetServer struct {
	srv *server.Server
	url string
	v   *ua.NodeID
}

func newRoleSetServer(t *testing.T, opts ...server.Option) *roleSetServer {
	t.Helper()
	var v *ua.NodeID
	srv, url := newServerPrepared(t, func(srv *server.Server) {
		ns := server.NewNodeNameSpace(srv, rolesTestNS)
		n := ns.AddNewVariableStringNode("v", int32(7))
		ns.Objects().AddRef(n, id.HasComponent, true)
		v = n.ID()
		require.NoError(t, srv.RoleSet().AddIdentity(ua.RoleSecurityAdmin.NodeID(),
			&ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "alice"}))
	}, secureServerOpts(t, append([]server.Option{
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == "bob" && pass == "builder" {
				return nil
			}
			return userValidator(user, pass)
		}),
		server.WithRoleManagement(server.RoleManagement{}),
		server.WithAccessController(server.NewRBACAccessController(nil)),
		server.WithClientCertificateValidator(func([]byte) error { return nil }),
	}, opts...)...)...)
	return &roleSetServer{srv: srv, url: url, v: v}
}

// client connects user (with the password of the validator) over the
// Basic256Sha256 Endpoint with mode.
func (r *roleSetServer) client(t *testing.T, mode ua.MessageSecurityMode, user string) *opcua.Client {
	t.Helper()
	pass := map[string]string{"alice": "wonderland", "bob": "builder"}[user]
	ep := endpointFor(t, r.url, ua.SecurityPolicyURIBasic256Sha256, mode)
	return newClient(t, r.url, append(secureClientOpts(t, ep, ua.UserTokenTypeUserName), opcua.AuthUsername(user, pass))...)
}

// readStatus returns the status of a Read of the Value of nid.
func readStatus(ctx context.Context, t *testing.T, c *opcua.Client, nid *ua.NodeID) ua.StatusCode {
	t.Helper()
	dv, err := c.ReadValue(ctx, nid)
	require.NoError(t, err)
	return dv.Status
}

func roleSetCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// TestRoleSet_AddRoleAndReevaluation: a role AddRole adds, whose Identities
// grant it to the active session of bob without a new ActivateSession, and
// RemoveRole, which removes it with its RolePermissions (§4.2.2, §4.2.3,
// §4.4.1, §4.4.5, §4.4.6).
func TestRoleSet_AddRoleAndReevaluation(t *testing.T) {
	r := newRoleSetServer(t)
	ctx := roleSetCtx(t)
	alice := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")
	bob := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "bob")
	rs := rolemgmt.New(alice)

	role, err := rs.AddRole(ctx, "Maintainer", "")
	require.NoError(t, err)
	roles, err := rs.Roles(ctx)
	require.NoError(t, err)
	var names []string
	for _, x := range roles {
		names = append(names, x.BrowseName.Name)
	}
	require.Contains(t, names, "Maintainer")
	require.Contains(t, names, "SecurityAdmin")

	// "the initial values of ApplicationsExclude and EndpointsExclude shall
	// be TRUE" (§4.2.2).
	cfg, err := role.Config(ctx)
	require.NoError(t, err)
	require.Empty(t, cfg.Identities)
	require.True(t, cfg.ApplicationsExclude)
	require.True(t, cfg.EndpointsExclude)
	require.False(t, cfg.CustomConfiguration)

	require.NoError(t, r.srv.SetNamespaceDefaults(rolesTestNS, server.NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{
		{RoleID: role.NodeID, Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead},
	}}))
	require.Equal(t, ua.StatusBadUserAccessDenied, readStatus(ctx, t, bob, r.v))

	rule := &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "bob"}
	require.NoError(t, role.AddIdentity(ctx, rule))
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r.v), "re-evaluated for the active session")
	cfg, err = role.Config(ctx)
	require.NoError(t, err)
	require.Len(t, cfg.Identities, 1)
	require.Equal(t, rule.Criteria, cfg.Identities[0].Criteria)

	// A new session gets it at ActivateSession.
	bob2 := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "bob")
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob2, r.v))

	require.NoError(t, role.RemoveIdentity(ctx, rule))
	require.Equal(t, ua.StatusBadUserAccessDenied, readStatus(ctx, t, bob, r.v))
	require.NoError(t, role.AddIdentity(ctx, rule))
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r.v))

	// "If a Role is removed all Permissions associated with the Role shall
	// be deleted" (§4.2.3): the defaults grant nothing any more.
	require.NoError(t, rs.RemoveRole(ctx, role.NodeID))
	require.Equal(t, ua.StatusBadUserAccessDenied, readStatus(ctx, t, bob, r.v))
	dv, err := alice.ReadValue(ctx, role.NodeID)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadNodeIDUnknown, dv.Status)
	require.ErrorIs(t, rs.RemoveRole(ctx, role.NodeID), ua.StatusBadNodeIDUnknown)
}

// TestRoleSet_MethodErrors: the results of §4.2.2, §4.2.3 and §4.4.5 to
// §4.4.10 for the calls the server refuses.
func TestRoleSet_MethodErrors(t *testing.T) {
	r := newRoleSetServer(t)
	ctx := roleSetCtx(t)
	alice := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")
	rs := rolemgmt.New(alice)

	role, err := rs.AddRole(ctx, "Auditor", "")
	require.NoError(t, err)
	_, err = rs.AddRole(ctx, "Auditor", server.RolesNamespaceURI)
	require.ErrorIs(t, err, ua.StatusBadAlreadyExists)
	_, err = rs.AddRole(ctx, "Observer", "http://opcfoundation.org/UA/")
	require.ErrorIs(t, err, ua.StatusBadAlreadyExists, "a well-known role")
	_, err = rs.AddRole(ctx, "NotWellKnown", "http://opcfoundation.org/UA/")
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = rs.AddRole(ctx, "", "")
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = rs.AddRole(ctx, "Other", "urn:not:in:the:namespace:array")
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	// A role of the application's namespace.
	nsRole, err := rs.AddRole(ctx, "Auditor", rolesTestNS)
	require.NoError(t, err)
	require.False(t, nsRole.NodeID.Equal(role.NodeID))

	require.ErrorIs(t, rs.RemoveRole(ctx, ua.RoleObserver.NodeID()), ua.StatusBadRequestNotAllowed)
	require.ErrorIs(t, rs.RemoveRole(ctx, ua.NewStringNodeID(1, "nope")), ua.StatusBadNodeIDUnknown)

	// §4.3: Anonymous, AuthenticatedUser and TrustedApplication cannot be
	// changed; their Objects have no Methods (the NodeSet of namespace 0).
	anon := rs.Role(ua.RoleAnonymous.NodeID())
	user := &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "carol"}
	require.ErrorIs(t, anon.AddIdentity(ctx, user), ua.StatusBadMethodInvalid)
	cfg, err := anon.Config(ctx)
	require.NoError(t, err)
	require.Len(t, cfg.Identities, 2, "Anonymous and AuthenticatedUser (§4.3)")

	// No Anonymous rule for a role with administrator rights (§4.4.1).
	admin := rs.Role(ua.RoleSecurityAdmin.NodeID())
	require.ErrorIs(t, admin.AddIdentity(ctx, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeAnonymous}),
		ua.StatusBadRequestNotAllowed)

	for name, rule := range map[string]*ua.IdentityMappingRuleType{
		"thumbprint lower case": {CriteriaType: ua.IdentityCriteriaTypeThumbprint, Criteria: "abcdef0123456789abcdef0123456789abcdef01"},
		"criteria on Anonymous": {CriteriaType: ua.IdentityCriteriaTypeAnonymous, Criteria: "x"},
		"subject order":         {CriteriaType: ua.IdentityCriteriaTypeX509Subject, Criteria: `O="A"/CN="B"`},
		"criteria type":         {CriteriaType: ua.IdentityCriteriaType(42)},
	} {
		require.ErrorIs(t, role.AddIdentity(ctx, rule), ua.StatusBadInvalidArgument, name)
	}
	// Role and GroupId need JWTs (§4.4.3).
	require.ErrorIs(t, role.AddIdentity(ctx, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeRole, Criteria: "admins"}),
		ua.StatusBadNotSupported)

	require.NoError(t, role.AddIdentity(ctx, user))
	require.ErrorIs(t, role.AddIdentity(ctx, user), ua.StatusBadAlreadyExists)
	require.ErrorIs(t, role.RemoveIdentity(ctx, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "dave"}),
		ua.StatusBadNotFound)

	require.ErrorIs(t, role.AddApplication(ctx, "no scheme"), ua.StatusBadInvalidArgument)
	require.NoError(t, role.AddApplication(ctx, "urn:app"))
	require.ErrorIs(t, role.AddApplication(ctx, "urn:app"), ua.StatusBadAlreadyExists)
	require.ErrorIs(t, role.RemoveApplication(ctx, "urn:other"), ua.StatusBadNotFound)
	require.NoError(t, role.RemoveApplication(ctx, "urn:app"))

	ep := &ua.EndpointType{EndpointURL: "opc.tcp://host:4840", SecurityMode: ua.MessageSecurityModeSignAndEncrypt}
	require.ErrorIs(t, role.AddEndpoint(ctx, &ua.EndpointType{EndpointURL: "http://host:80"}), ua.StatusBadInvalidArgument)
	require.NoError(t, role.AddEndpoint(ctx, ep))
	require.ErrorIs(t, role.AddEndpoint(ctx, ep), ua.StatusBadAlreadyExists)
	require.ErrorIs(t, role.RemoveEndpoint(ctx, &ua.EndpointType{EndpointURL: "opc.tcp://other:4840"}), ua.StatusBadNotFound)
	require.NoError(t, role.RemoveEndpoint(ctx, ep))

	// A role that is gone.
	require.NoError(t, rs.RemoveRole(ctx, nsRole.NodeID))
	err = uamethod.CallRoleTypeAddApplication(ctx, alice, nsRole.NodeID, ua.NewNumericNodeID(0, id.RoleTypeAddApplication),
		&uamethod.RoleTypeAddApplicationInput{ApplicationURI: "urn:app"})
	require.Error(t, err)
}

// TestRoleSet_Authorization: "The Client shall use an encrypted channel and
// shall provide user credentials with administrator rights like
// SecurityAdmin Role" (§4.2.2 and the other Methods).
func TestRoleSet_Authorization(t *testing.T) {
	r := newRoleSetServer(t)
	ctx := roleSetCtx(t)
	bob := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "bob")
	_, err := rolemgmt.New(bob).AddRole(ctx, "Intruder", "")
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	observer := rolemgmt.New(bob).Role(ua.RoleObserver.NodeID())
	require.ErrorIs(t, observer.AddApplication(ctx, "urn:x"), ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, observer.SetApplicationsExclude(ctx, false), ua.StatusBadUserAccessDenied)
	_, err = observer.Config(ctx)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied, "the Properties are for administrators")

	signed := r.client(t, ua.MessageSecurityModeSign, "alice")
	_, err = rolemgmt.New(signed).AddRole(ctx, "Unencrypted", "")
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)
	require.ErrorIs(t, rolemgmt.New(signed).Role(ua.RoleObserver.NodeID()).SetEndpointsExclude(ctx, false),
		ua.StatusBadSecurityModeInsufficient)

	alice := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")
	require.NoError(t, rolemgmt.New(alice).Role(ua.RoleObserver.NodeID()).SetEndpointsExclude(ctx, false))
}

// TestRoleSet_ApplicationsAndEndpoints: the Applications and Endpoints of a
// role and their exclude flags decide whether the role is granted
// (§4.4.1).
func TestRoleSet_ApplicationsAndEndpoints(t *testing.T) {
	r := newRoleSetServer(t)
	ctx := roleSetCtx(t)
	alice := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")
	bob := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "bob")
	rs := rolemgmt.New(alice)
	role, err := rs.AddRole(ctx, "Station", "")
	require.NoError(t, err)
	require.NoError(t, r.srv.SetNamespaceDefaults(rolesTestNS, server.NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{
		{RoleID: role.NodeID, Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead},
	}}))
	require.NoError(t, role.AddIdentity(ctx, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeAuthenticatedUser}))
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r.v))

	// Applications: include list with the client, exclude list with it.
	require.NoError(t, role.AddApplication(ctx, clientAppURI))
	require.Equal(t, ua.StatusBadUserAccessDenied, readStatus(ctx, t, bob, r.v), "excluded")
	require.NoError(t, role.SetApplicationsExclude(ctx, false))
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r.v), "included")
	require.NoError(t, role.RemoveApplication(ctx, clientAppURI))
	require.NoError(t, role.AddApplication(ctx, "urn:another:client"))
	require.Equal(t, ua.StatusBadUserAccessDenied, readStatus(ctx, t, bob, r.v), "not included")
	require.NoError(t, role.SetApplicationsExclude(ctx, true))
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r.v), "not excluded")
	cfg, err := role.Config(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"urn:another:client"}, cfg.Applications)

	// Endpoints: the Endpoint of the session, then another one.
	ep := endpointFor(t, r.url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	mine := &ua.EndpointType{EndpointURL: ep.EndpointURL, SecurityMode: ep.SecurityMode, SecurityPolicyURI: ep.SecurityPolicyURI}
	require.NoError(t, role.AddEndpoint(ctx, mine))
	require.Equal(t, ua.StatusBadUserAccessDenied, readStatus(ctx, t, bob, r.v), "excluded")
	require.NoError(t, role.SetEndpointsExclude(ctx, false))
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r.v), "included")
	// The default fields are ignored (§4.4.2): the URL alone matches.
	require.NoError(t, role.RemoveEndpoint(ctx, mine))
	require.NoError(t, role.AddEndpoint(ctx, &ua.EndpointType{EndpointURL: ep.EndpointURL}))
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r.v), "included by URL")
	cfg, err = role.Config(ctx)
	require.NoError(t, err)
	require.Len(t, cfg.Endpoints, 1)
	require.False(t, cfg.EndpointsExclude)

	// A Sign session uses another Endpoint than mine.
	require.NoError(t, role.RemoveEndpoint(ctx, &ua.EndpointType{EndpointURL: ep.EndpointURL}))
	require.NoError(t, role.AddEndpoint(ctx, mine))
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r.v))
	bobSigned := r.client(t, ua.MessageSecurityModeSign, "bob")
	require.Equal(t, ua.StatusBadUserAccessDenied, readStatus(ctx, t, bobSigned, r.v))
}

// TestRoleSet_Disabled: without WithRoleManagement the RoleSet Methods are
// not served and the roles are those of the RoleMapper, as before.
func TestRoleSet_Disabled(t *testing.T) {
	srv, url := newServer(t, secureServerOpts(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(userValidator))...)
	require.Nil(t, srv.RoleSet())
	ep := endpointFor(t, url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	c := newClient(t, url, append(secureClientOpts(t, ep, ua.UserTokenTypeUserName), opcua.AuthUsername("alice", "wonderland"))...)
	_, err := rolemgmt.New(c).AddRole(roleSetCtx(t), "Maintainer", "")
	require.Error(t, err)
	var ce *uamethod.CallError
	require.ErrorAs(t, err, &ce)
}

// TestRoleSet_AuditEvents: with auditing on, a change of a role by one of
// its Methods reports a RoleMappingRuleChangedAuditEventType event (§4.5),
// AddRole and a refused call an AuditUpdateMethodEventType event (Part 5
// §6.4.27).
func TestRoleSet_AuditEvents(t *testing.T) {
	r := newRoleSetServer(t, server.WithAuditing(true))
	ctx := roleSetCtx(t)
	alice := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")
	f := ua.NewEventFilter().TypeDefinition(ua.NewNumericNodeID(0, id.BaseEventType)).Select("EventType", "SourceName", "Status")
	sub, ch, err := alice.NewSubscription().Interval(20*time.Millisecond).
		MonitorEvents(f.Build(), ua.NewNumericNodeID(0, id.Server)).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	// next returns the next event whose SourceName is a RoleSet Method.
	next := func() []*ua.Variant {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for {
			select {
			case msg := <-ch:
				require.NoError(t, msg.Error)
				if enl, ok := msg.Value.(*ua.EventNotificationList); ok {
					for _, ev := range enl.Events {
						if name, _ := ev.EventFields[1].Value().(string); strings.HasPrefix(name, "Method/") {
							return ev.EventFields
						}
					}
				}
			case <-deadline:
				t.Fatal("no audit event")
			}
		}
	}
	isType := func(ev []*ua.Variant, typ uint32) bool {
		return ev[0].Value().(*ua.NodeID).Equal(ua.NewNumericNodeID(0, typ))
	}

	role, err := rolemgmt.New(alice).AddRole(ctx, "Audited", "")
	require.NoError(t, err)
	ev := next()
	require.True(t, isType(ev, id.AuditUpdateMethodEventType))
	require.Equal(t, "Method/AddRole", ev[1].Value())
	require.Equal(t, true, ev[2].Value())

	require.NoError(t, role.AddApplication(ctx, "urn:audited"))
	ev = next()
	require.True(t, isType(ev, id.RoleMappingRuleChangedAuditEventType))
	require.Equal(t, "Method/AddApplication", ev[1].Value())

	require.ErrorIs(t, role.AddApplication(ctx, "urn:audited"), ua.StatusBadAlreadyExists)
	ev = next()
	require.True(t, isType(ev, id.AuditUpdateMethodEventType))
	require.Equal(t, false, ev[2].Value())
}
