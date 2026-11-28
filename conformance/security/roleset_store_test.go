// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/rolemgmt"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/rolestore"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
)

// The managed RoleSet with the file store of package server/rolestore
// (server.WithRoleSetStore): the RoleSet and Role Methods of OPC 10000-18
// (§4.2.2, §4.2.3, §4.4.5 to §4.4.10) and a Write of ApplicationsExclude
// (§4.4.1) over the wire, a restart, failed commits and concurrent
// changes.

const roleStoreOwner = "urn:otfabric:test:roleset"

func openRoleStore(t *testing.T, dir string) *rolestore.Store {
	t.Helper()
	st, err := rolestore.OpenDir(context.Background(), dir, rolestore.Options{Owner: roleStoreOwner})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// newStoredRoleSetServer is newRoleSetServer on the store st, with the
// namespaces pad before rolesTestNS. The SecurityAdmin rule of alice is
// added at each start: a restored store has it already.
func newStoredRoleSetServer(t *testing.T, st server.RoleSetStore, pad ...string) *roleSetServer {
	t.Helper()
	var v *ua.NodeID
	srv, url := newServerPrepared(t, func(srv *server.Server) {
		for _, uri := range pad {
			server.NewNodeNameSpace(srv, uri)
		}
		ns := server.NewNodeNameSpace(srv, rolesTestNS)
		n := ns.AddNewVariableStringNode("v", int32(7))
		ns.Objects().AddRef(n, id.HasComponent, true)
		v = n.ID()
		err := srv.RoleSet().AddIdentity(ua.RoleSecurityAdmin.NodeID(),
			&ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "alice"})
		if !errors.Is(err, ua.StatusBadAlreadyExists) {
			require.NoError(t, err)
		}
	}, secureServerOpts(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == "bob" && pass == "builder" {
				return nil
			}
			return userValidator(user, pass)
		}),
		server.WithRoleManagement(server.RoleManagement{}),
		server.WithRoleSetStore(st),
		server.WithAccessController(server.NewRBACAccessController(nil)),
		server.WithClientCertificateValidator(func([]byte) error { return nil }),
	)...)
	return &roleSetServer{srv: srv, url: url, v: v}
}

// grantRead lets role read the variables of rolesTestNS: the
// DefaultRolePermissions are the application's, not the store's.
func grantRead(t *testing.T, srv *server.Server, role *ua.NodeID) {
	t.Helper()
	require.NoError(t, srv.SetNamespaceDefaults(rolesTestNS, server.NamespaceDefaults{RolePermissions: []*ua.RolePermissionType{
		{RoleID: role, Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead},
	}}))
}

// roleByName returns the role of the RoleSet of srv with the BrowseName
// name.
func roleByName(t *testing.T, srv *server.Server, name string) server.Role {
	t.Helper()
	for _, r := range srv.RoleSet().Roles() {
		if r.BrowseName.Name == name {
			return r
		}
	}
	t.Fatalf("no role %s", name)
	return server.Role{}
}

// roleNames returns the BrowseNames of the roles of srv.
func roleNames(srv *server.Server) []string {
	var out []string
	for _, r := range srv.RoleSet().Roles() {
		out = append(out, r.BrowseName.Name)
	}
	return out
}

// TestRoleSet_StoreRestart: the roles AddRole added, with their Identities,
// Applications and Endpoints, and the configuration of a well-known role,
// each changed by a Method or a Write over the wire, are in the store; a
// server started again on the directory, with the namespaces at other
// indexes, has them with the same NodeIds (Part 3 §5.2.2) and grants them
// to the sessions; RemoveRole stays removed.
func TestRoleSet_StoreRestart(t *testing.T) {
	ctx := roleSetCtx(t)
	dir := t.TempDir()

	st := openRoleStore(t, dir)
	r1 := newStoredRoleSetServer(t, st)
	alice := r1.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")
	rs := rolemgmt.New(alice)
	maint, err := rs.AddRole(ctx, "Maintainer", "")
	require.NoError(t, err)
	require.NoError(t, maint.AddIdentity(ctx, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "bob"}))
	require.NoError(t, maint.AddApplication(ctx, "urn:another:client"))
	require.NoError(t, maint.SetApplicationsExclude(ctx, true))
	plant, err := rs.AddRole(ctx, "Plant", rolesTestNS)
	require.NoError(t, err)
	ep := endpointFor(t, r1.url, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	require.NoError(t, plant.AddEndpoint(ctx, &ua.EndpointType{EndpointURL: ep.EndpointURL}))
	gone, err := rs.AddRole(ctx, "Gone", "")
	require.NoError(t, err)
	require.NoError(t, rs.RemoveRole(ctx, gone.NodeID))
	op := rs.Role(ua.RoleOperator.NodeID())
	require.NoError(t, op.AddIdentity(ctx, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "bob"}))
	require.NoError(t, op.SetEndpointsExclude(ctx, false))
	before := r1.srv.RoleSet().Roles()
	nsArray := r1.srv.Namespaces()
	maintURI := nsArray[maint.NodeID.Namespace()].Name()

	grantRead(t, r1.srv, maint.NodeID)
	bob := r1.client(t, ua.MessageSecurityModeSignAndEncrypt, "bob")
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob, r1.v))

	// Restart, rolesTestNS and the roles namespace one index further.
	require.NoError(t, r1.srv.Close())
	require.NoError(t, st.Close())
	st2 := openRoleStore(t, dir)
	r2 := newStoredRoleSetServer(t, st2, "urn:conformance:roleset:pad1", "urn:conformance:roleset:pad2")
	require.Len(t, r2.srv.RoleSet().Roles(), len(before))
	maint2 := roleByName(t, r2.srv, "Maintainer")
	require.Equal(t, maint.NodeID.StringID(), maint2.NodeID.StringID(), "the identifier of the NodeId is kept")
	require.NotEqual(t, maint.NodeID.Namespace(), maint2.NodeID.Namespace(), "the namespace index moved")
	require.Equal(t, maintURI, r2.srv.Namespaces()[maint2.NodeID.Namespace()].Name())
	require.Len(t, maint2.Identities, 1)
	require.Equal(t, []string{"urn:another:client"}, maint2.Applications)
	require.True(t, maint2.ApplicationsExclude)
	require.True(t, maint2.Removable)
	plant2 := roleByName(t, r2.srv, "Plant")
	nsIdx, err := r2.srv.Namespace(int(plant2.BrowseName.NamespaceIndex))
	require.NoError(t, err)
	require.Equal(t, rolesTestNS, nsIdx.Name(), "the BrowseName is remapped by URI")
	require.Len(t, plant2.Endpoints, 1)
	require.NotContains(t, roleNames(r2.srv), "Gone")
	op2 := roleByName(t, r2.srv, "Operator")
	require.Len(t, op2.Identities, 1)
	require.False(t, op2.EndpointsExclude)

	// Over the wire: the restored roles, their Properties and their
	// Methods, and the roles of a new session.
	alice2 := r2.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")
	rs2 := rolemgmt.New(alice2)
	cfg, err := rs2.Role(maint2.NodeID).Config(ctx)
	require.NoError(t, err)
	require.Equal(t, "bob", cfg.Identities[0].Criteria)
	require.True(t, cfg.ApplicationsExclude)
	grantRead(t, r2.srv, maint2.NodeID)
	bob2 := r2.client(t, ua.MessageSecurityModeSignAndEncrypt, "bob")
	require.Equal(t, ua.StatusOK, readStatus(ctx, t, bob2, r2.v), "the restored role is granted")
	require.NoError(t, rs2.Role(maint2.NodeID).RemoveIdentity(ctx, &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "bob"}))
	require.Equal(t, ua.StatusBadUserAccessDenied, readStatus(ctx, t, bob2, r2.v))
	_, err = rs2.AddRole(ctx, "Maintainer", "")
	require.ErrorIs(t, err, ua.StatusBadAlreadyExists)
}

// TestRoleSet_StoreFailedCommit: a change whose write fails, or has an
// unknown outcome, is Bad_InternalError and changes nothing; the next
// change settles the store, and a restart starts with what was applied
// only.
func TestRoleSet_StoreFailedCommit(t *testing.T) {
	ctx := roleSetCtx(t)
	dir := t.TempDir()
	fs, err := fxstore.OpenFile(dir, fxstore.Limits{})
	require.NoError(t, err)
	faulty := storetest.NewFaulty(fs)
	st, err := rolestore.Open(ctx, faulty, rolestore.Options{Owner: roleStoreOwner})
	require.NoError(t, err)
	r := newStoredRoleSetServer(t, st)
	alice := r.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")
	rs := rolemgmt.New(alice)
	op := rs.Role(ua.RoleOperator.NodeID())
	rule := &ua.IdentityMappingRuleType{CriteriaType: ua.IdentityCriteriaTypeUserName, Criteria: "bob"}

	for _, fault := range []storetest.Fault{storetest.FailNotCommitted, storetest.FailLost, storetest.FailApplied} {
		for name, change := range map[string]func() error{
			"AddIdentity": func() error { return op.AddIdentity(ctx, rule) },
			"AddRole":     func() error { _, err := rs.AddRole(ctx, "Maintainer", ""); return err },
			"Write":       func() error { return op.SetApplicationsExclude(ctx, false) },
		} {
			faulty.FailApply(fault)
			require.ErrorIs(t, change(), ua.StatusBadInternalError, "%s, fault %d", name, fault)
			cfg, err := op.Config(ctx)
			require.NoError(t, err)
			require.Empty(t, cfg.Identities, name)
			require.True(t, cfg.ApplicationsExclude, name)
			require.NotContains(t, roleNames(r.srv), "Maintainer", name)
			ok, err := st.Settle(ctx)
			require.NoError(t, err)
			require.True(t, ok)
		}
	}
	// Fenced by an unknown outcome; the next change settles and applies.
	faulty.FailApply(storetest.FailLost)
	require.ErrorIs(t, op.AddIdentity(ctx, rule), ua.StatusBadInternalError)
	require.True(t, st.Status().Fenced)
	require.NoError(t, op.AddIdentity(ctx, rule))
	require.False(t, st.Status().Fenced)

	// A write that landed with an unknown outcome and is then settled
	// leaves the state that was applied.
	faulty.FailApply(storetest.FailApplied)
	require.ErrorIs(t, op.RemoveIdentity(ctx, rule), ua.StatusBadInternalError)
	ok, err := st.Settle(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, r.srv.Close())
	require.NoError(t, st.Close())
	require.NoError(t, fs.Close())

	r2 := newStoredRoleSetServer(t, openRoleStore(t, dir))
	got := roleByName(t, r2.srv, "Operator")
	require.Len(t, got.Identities, 1)
	require.Equal(t, "bob", got.Identities[0].Criteria)
}

// TestRoleSet_StoreConcurrent: concurrent changes over the wire from two
// administrators are each written once; a restart has them all.
func TestRoleSet_StoreConcurrent(t *testing.T) {
	ctx := roleSetCtx(t)
	dir := t.TempDir()
	st := openRoleStore(t, dir)
	r := newStoredRoleSetServer(t, st)
	rev := st.Status().Revision
	roles := []*ua.NodeID{ua.RoleObserver.NodeID(), ua.RoleOperator.NodeID(), ua.RoleEngineer.NodeID(), ua.RoleSupervisor.NodeID()}
	clients := []*rolemgmt.RoleSet{
		rolemgmt.New(r.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")),
		rolemgmt.New(r.client(t, ua.MessageSecurityModeSignAndEncrypt, "alice")),
	}
	const n = 5
	var wg sync.WaitGroup
	for i, role := range roles {
		rs := clients[i%2]
		wg.Go(func() {
			for j := range n {
				require.NoError(t, rs.Role(role).AddApplication(ctx, "urn:app:"+string(rune('a'+j))))
			}
		})
	}
	wg.Go(func() {
		_, err := clients[0].AddRole(ctx, "Maintainer", "")
		require.NoError(t, err)
	})
	wg.Wait()
	require.Equal(t, rev+uint64(len(roles)*n+1), st.Status().Revision, "one write per change")
	want := portableRoles(r.srv)
	require.NoError(t, r.srv.Close())
	require.NoError(t, st.Close())

	r2 := newStoredRoleSetServer(t, openRoleStore(t, dir))
	require.Equal(t, want, portableRoles(r2.srv))
}

// portableRoles returns the roles of srv with the namespace URIs in place
// of the namespace indexes, which the diagnostics namespace of the first
// session may shift.
func portableRoles(srv *server.Server) []server.Role {
	ns := srv.Namespaces()
	out := srv.RoleSet().Roles()
	for i, r := range out {
		out[i].NodeID = ua.NewStringNodeID(0, ns[r.NodeID.Namespace()].Name()+"|"+strconv.Itoa(int(r.NodeID.IntID()))+"|"+r.NodeID.StringID())
		out[i].BrowseName = &ua.QualifiedName{Name: ns[r.BrowseName.NamespaceIndex].Name() + "|" + r.BrowseName.Name}
	}
	return out
}
