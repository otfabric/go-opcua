// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// memRoleStore is a RoleSetStore in memory: it keeps the roles with the
// namespace URIs of their NodeIds and BrowseNames, as package
// server/rolestore does, and fails as told.
type memRoleStore struct {
	mu       sync.Mutex
	roles    []Role
	ns       []string
	writes   int
	failLoad error
	failNext error
	// loaded are the namespaces of the last load.
	loaded []string
}

func (m *memRoleStore) LoadRoleSet(_ context.Context, namespaces []string) ([]Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loaded = slices.Clone(namespaces)
	if m.failLoad != nil {
		return nil, m.failLoad
	}
	if m.roles == nil {
		return nil, nil
	}
	idx := func(i uint16) uint16 {
		if int(i) >= len(m.ns) {
			return 0xffff
		}
		j := slices.Index(namespaces, m.ns[i])
		if j < 0 {
			return 0xffff
		}
		return uint16(j)
	}
	out := make([]Role, len(m.roles))
	for i, r := range m.roles {
		c := r
		if r.NodeID != nil {
			c.NodeID = ua.NewStringNodeID(0, "")
			if r.NodeID.Type() == ua.NodeIDTypeString {
				c.NodeID = ua.NewStringNodeID(idx(r.NodeID.Namespace()), r.NodeID.StringID())
			} else {
				c.NodeID = ua.NewNumericNodeID(idx(r.NodeID.Namespace()), r.NodeID.IntID())
			}
		}
		if r.BrowseName != nil {
			c.BrowseName = &ua.QualifiedName{NamespaceIndex: idx(r.BrowseName.NamespaceIndex), Name: r.BrowseName.Name}
		}
		out[i] = c
	}
	return out, nil
}

func (m *memRoleStore) StoreRoleSet(_ context.Context, roles []Role, namespaces []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failNext; err != nil {
		m.failNext = nil
		return err
	}
	m.writes++
	m.roles, m.ns = slices.Clone(roles), slices.Clone(namespaces)
	return nil
}

func (m *memRoleStore) state() ([]Role, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.roles), m.writes
}

func (m *memRoleStore) fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNext = err
}

// roleNames returns the BrowseNames of the roles.
func roleNames(rs []Role) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.BrowseName.Name)
	}
	return out
}

func TestRoleSetStoreOption(t *testing.T) {
	t.Parallel()
	_, err := New(WithRoleSetStore(nil))
	require.ErrorContains(t, err, "nil store")
	_, err = New(InsecureNoSecurity(), EndPoint("localhost", 0), WithRoleSetStore(&memRoleStore{}))
	require.ErrorContains(t, err, "needs WithRoleManagement")
}

// Each change writes the RoleSet once, after it succeeded, without the
// fixed roles; a write that fails changes nothing and is Bad_InternalError,
// over the wire too.
func TestRoleSetStoreWrites(t *testing.T) {
	t.Parallel()
	st := &memRoleStore{}
	s := newRoleSetTestServer(t, RoleManagement{}, WithRoleSetStore(st))
	rs := s.RoleSet()
	obs := ua.RoleObserver.NodeID()
	ep := &ua.EndpointType{EndpointURL: "opc.tcp://h:1"}
	sess := s.sb.NewSession()
	s.grantRoles(nil, sess, &ua.UserNameIdentityToken{UserName: "alice"})

	var nid *ua.NodeID
	for _, c := range []struct {
		name   string
		change func() error
	}{
		{"AddIdentity", func() error { return rs.AddIdentity(obs, userRule("alice")) }},
		{"RemoveIdentity", func() error { return rs.RemoveIdentity(obs, userRule("alice")) }},
		{"AddApplication", func() error { return rs.AddApplication(obs, "urn:a") }},
		{"RemoveApplication", func() error { return rs.RemoveApplication(obs, "urn:a") }},
		{"AddEndpoint", func() error { return rs.AddEndpoint(obs, ep) }},
		{"RemoveEndpoint", func() error { return rs.RemoveEndpoint(obs, ep) }},
		{"SetApplicationsExclude", func() error { return rs.SetApplicationsExclude(obs, false) }},
		{"SetEndpointsExclude", func() error { return rs.SetEndpointsExclude(obs, false) }},
		{"AddRole", func() (err error) { nid, err = rs.AddRole("Maintainer", ""); return err }},
		{"RemoveRole", func() error { return rs.RemoveRole(nid) }},
	} {
		before := rs.Roles()
		_, n := st.state()
		fail := errors.New("disk full")
		st.fail(fail)
		err := c.change()
		require.ErrorIs(t, err, ua.StatusBadInternalError, c.name)
		require.ErrorIs(t, err, fail, c.name)
		require.Equal(t, before, rs.Roles(), "%s: a refused write changes nothing", c.name)
		require.NoError(t, c.change(), c.name)
		got, n2 := st.state()
		require.Equal(t, n+1, n2, "%s: one write", c.name)
		var want []Role
		for _, r := range rs.Roles() {
			if !r.Fixed {
				want = append(want, r)
			}
		}
		require.Equal(t, want, got, c.name)
	}
	require.NotContains(t, roleNames(rs.Roles()), "Maintainer")
	require.Nil(t, s.Node(nid))

	// A failed AddRole adds no nodes; a failed RemoveRole removes none.
	st.fail(errors.New("no"))
	_, err := rs.AddRole("Other", "")
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	rolesNS, _ := s.namespaceLookup(RolesNamespaceURI)
	require.Nil(t, s.Node(ua.NewStringNodeID(rolesNS, itoa(int(rolesNS))+":Other")))
	nid, err = rs.AddRole("Other", "")
	require.NoError(t, err)
	st.fail(errors.New("no"))
	require.ErrorIs(t, rs.RemoveRole(nid), ua.StatusBadInternalError)
	require.NotNil(t, s.Node(nid))
	r, ok := rs.Role(nid)
	require.True(t, ok)
	require.True(t, r.Removable)

	// Over the wire: the Method and the Write of an Exclude Property.
	ctx := roleAdminCtx(s)
	st.fail(errors.New("no"))
	_, sc := callRole(t, s, ctx, obs, s.childNamed(s.Node(obs), id.HasComponent, "AddApplication").ID(), ua.MustVariant("urn:b"))
	require.Equal(t, ua.StatusBadInternalError, sc)
	st.fail(errors.New("no"))
	_, sc = callRole(t, s, ctx, roleSetNodeID, roleSetAddRoleID, ua.MustVariant("X"), ua.MustVariant(""))
	require.Equal(t, ua.StatusBadInternalError, sc)
	w := s.childNamed(s.Node(obs), id.HasProperty, "ApplicationsExclude").ValueWriter()
	admin := s.sb.NewSession()
	admin.setRoles([]*ua.NodeID{ua.RoleSecurityAdmin.NodeID()})
	admin.channel.Store(uasc.NewCryptoChannel(&uasc.Config{SecurityMode: ua.MessageSecurityModeSignAndEncrypt,
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256}))
	st.fail(errors.New("no"))
	sc = w(ctx, &ValueWrite{Session: admin.handle(), Value: &ua.DataValue{Value: ua.MustVariant(true)}})
	require.Equal(t, ua.StatusBadInternalError, sc)
	r, _ = rs.Role(obs)
	require.False(t, r.ApplicationsExclude)
}

// Without a store nothing is written and the NodeIds of AddRole are those
// of v1.43.0 before the store.
func TestRoleSetStoreNone(t *testing.T) {
	t.Parallel()
	s := newRoleSetTestServer(t, RoleManagement{})
	rs := s.RoleSet()
	require.NoError(t, rs.restore())
	require.False(t, rs.restored)
	require.NoError(t, rs.persistLocked(rs.roles))
	nid, err := rs.AddRole("Maintainer", "")
	require.NoError(t, err)
	require.Equal(t, itoa(int(nid.Namespace()))+":Maintainer", nid.StringID())
}

// restartedRoleSet returns a server on st with the namespace urn:app
// registered first, so that the roles namespace has another index than in
// the server that wrote st.
func restartedRoleSet(t *testing.T, st *memRoleStore) *Server {
	t.Helper()
	s := newRoleSetTestServer(t, RoleManagement{}, WithRoleSetStore(st))
	NewNodeNameSpace(s, "urn:pad")
	NewNodeNameSpace(s, "urn:app")
	return s
}

// The roles of the store come back at the first change or restore: the
// configuration of the well-known roles, the added roles with their
// NodeIds (Part 3 §5.2.2) and BrowseNames remapped by URI, and the roles of
// the sessions.
func TestRoleSetStoreRestore(t *testing.T) {
	t.Parallel()
	st := &memRoleStore{}
	s1 := newRoleSetTestServer(t, RoleManagement{}, WithRoleSetStore(st))
	NewNodeNameSpace(s1, "urn:app")
	rs1 := s1.RoleSet()
	require.NoError(t, rs1.AddIdentity(ua.RoleOperator.NodeID(), userRule("alice")))
	require.NoError(t, rs1.AddApplication(ua.RoleOperator.NodeID(), "urn:client"))
	require.NoError(t, rs1.SetApplicationsExclude(ua.RoleOperator.NodeID(), true))
	m, err := rs1.AddRole("Maintainer", "")
	require.NoError(t, err)
	require.NoError(t, rs1.AddIdentity(m, userRule("bob")))
	a, err := rs1.AddRole("Plant", "urn:app")
	require.NoError(t, err)
	require.NoError(t, rs1.AddEndpoint(a, &ua.EndpointType{EndpointURL: "opc.tcp://h:1"}))

	s2 := restartedRoleSet(t, st)
	rs2 := s2.RoleSet()
	require.NotContains(t, roleNames(rs2.Roles()), "Maintainer", "not restored before Start or a change")
	require.NoError(t, rs2.restore())
	require.NoError(t, rs2.restore(), "once")
	rolesNS, ok := s2.namespaceLookup(RolesNamespaceURI)
	require.True(t, ok)
	appNS, _ := s2.namespaceLookup("urn:app")
	require.NotEqual(t, m.Namespace(), rolesNS, "the roles namespace moved")

	m2, ok := rs2.Role(ua.NewStringNodeID(rolesNS, m.StringID()))
	require.True(t, ok, "the NodeId keeps its identifier")
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: rolesNS, Name: "Maintainer"}, m2.BrowseName)
	require.Equal(t, []*ua.IdentityMappingRuleType{userRule("bob")}, m2.Identities)
	require.True(t, m2.Removable)
	require.NotNil(t, s2.Node(m2.NodeID), "with its nodes")
	a2, ok := rs2.Role(ua.NewStringNodeID(rolesNS, a.StringID()))
	require.True(t, ok)
	require.Equal(t, &ua.QualifiedName{NamespaceIndex: appNS, Name: "Plant"}, a2.BrowseName)
	require.Len(t, a2.Endpoints, 1)
	op, _ := rs2.Role(ua.RoleOperator.NodeID())
	require.Equal(t, []string{"urn:client"}, op.Applications)
	require.True(t, op.ApplicationsExclude)
	require.Len(t, op.Identities, 1)

	sess := s2.sb.NewSession()
	s2.grantRoles(nil, sess, &ua.UserNameIdentityToken{UserName: "bob"})
	require.Contains(t, nodeStrings(sess.currentRoles()), m2.NodeID.String())

	// An AddRole of a name whose NodeId a restored role has: another
	// NodeId. Plant of urn:app is "1:Plant", the index urn:app had; a role
	// Plant of urn:pad, now at 1, gets a suffix.
	require.Equal(t, "1:Plant", a.StringID())
	pad, _ := s2.namespaceLookup("urn:pad")
	require.Equal(t, uint16(1), pad)
	p, err := rs2.AddRole("Plant", "urn:pad")
	require.NoError(t, err)
	require.Equal(t, "1:Plant#2", p.StringID())
	p3, err := rs2.AddRole("Plant", "urn:app")
	require.ErrorIs(t, err, ua.StatusBadAlreadyExists, "the restored role has the BrowseName")
	require.Nil(t, p3)
}

// The first change before Start restores, and is made on the restored
// roles; a session active then gets its roles again.
func TestRoleSetStoreRestoreOnChange(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		change func(rs *RoleSet) error
	}{
		{"update", func(rs *RoleSet) error { return rs.AddIdentity(ua.RoleOperator.NodeID(), userRule("alice")) }},
		{"failed update", func(rs *RoleSet) error { return rs.AddIdentity(ua.NewNumericNodeID(0, 1), userRule("alice")) }},
		{"AddRole", func(rs *RoleSet) error { _, err := rs.AddRole("X", ""); return err }},
		{"RemoveRole", func(rs *RoleSet) error { return rs.RemoveRole(ua.NewNumericNodeID(0, 1)) }},
	} {
		st := &memRoleStore{}
		s1 := newRoleSetTestServer(t, RoleManagement{}, WithRoleSetStore(st))
		require.NoError(t, s1.RoleSet().AddIdentity(ua.RoleEngineer.NodeID(), userRule("bob")))

		s2 := restartedRoleSet(t, st)
		sess := s2.sb.NewSession()
		s2.grantRoles(nil, sess, &ua.UserNameIdentityToken{UserName: "bob"})
		require.NotContains(t, sess.currentRoles(), ua.RoleEngineer.NodeID())
		_ = c.change(s2.RoleSet())
		require.True(t, s2.RoleSet().restored, c.name)
		require.Contains(t, nodeStrings(sess.currentRoles()), ua.RoleEngineer.NodeID().String(), c.name)
	}
}

// A store that cannot be loaded fails Start and every change, and is tried
// again; the RoleSet keeps the roles it had.
func TestRoleSetStoreLoadError(t *testing.T) {
	t.Parallel()
	fail := errors.New("unreadable")
	st := &memRoleStore{failLoad: fail}
	s := newRoleSetTestServer(t, RoleManagement{}, WithRoleSetStore(st))
	rs := s.RoleSet()
	before := rs.Roles()
	require.ErrorIs(t, s.Start(context.Background()), fail)
	require.ErrorIs(t, rs.AddIdentity(ua.RoleOperator.NodeID(), userRule("alice")), fail)
	_, err := rs.AddRole("X", "")
	require.ErrorIs(t, err, fail)
	require.ErrorIs(t, rs.RemoveRole(ua.RoleOperator.NodeID()), fail)
	require.Equal(t, before, rs.Roles())
	_, n := st.state()
	require.Zero(t, n)

	st.mu.Lock()
	st.failLoad = nil
	st.mu.Unlock()
	require.NoError(t, rs.AddIdentity(ua.RoleOperator.NodeID(), userRule("alice")))
	require.True(t, rs.restored)
}

// Stored roles the RoleSet cannot take fail the restore and change
// nothing.
func TestRoleSetStoreInvalid(t *testing.T) {
	t.Parallel()
	rolesIdx := uint16(3) // urn:pad, urn:app and the roles namespace follow namespace 0
	added := func(name string) Role {
		return Role{
			NodeID: ua.NewStringNodeID(rolesIdx, "x:"+name), BrowseName: &ua.QualifiedName{NamespaceIndex: rolesIdx, Name: name},
			Removable: true, ApplicationsExclude: true, EndpointsExclude: true,
		}
	}
	op := func(edit func(r *Role)) Role {
		r := Role{NodeID: ua.RoleOperator.NodeID(), BrowseName: &ua.QualifiedName{Name: "Operator"}}
		edit(&r)
		return r
	}
	for name, roles := range map[string][]Role{
		"no NodeId":     {{BrowseName: &ua.QualifiedName{Name: "x"}}},
		"no BrowseName": {{NodeID: ua.RoleOperator.NodeID()}},
		"twice":         {op(func(*Role) {}), op(func(*Role) {})},
		"unknown role":  {op(func(r *Role) { r.NodeID = ua.NewNumericNodeID(0, 1) })},
		"fixed role":    {op(func(r *Role) { r.NodeID = ua.RoleAnonymous.NodeID() })},
		"invalid rule":  {op(func(r *Role) { r.Identities = []*ua.IdentityMappingRuleType{userRule("")} })},
		"anonymous admin": {op(func(r *Role) {
			r.NodeID = ua.RoleSecurityAdmin.NodeID()
			r.Identities = []*ua.IdentityMappingRuleType{{CriteriaType: ua.IdentityCriteriaTypeAnonymous}}
		})},
		"invalid application": {op(func(r *Role) { r.Applications = []string{"no scheme"} })},
		"invalid endpoint":    {op(func(r *Role) { r.Endpoints = []*ua.EndpointType{{EndpointURL: "http://h"}} })},
		"added elsewhere":     {func() Role { r := added("A"); r.NodeID = ua.NewStringNodeID(0, "x"); return r }()},
		"added numeric":       {func() Role { r := added("A"); r.NodeID = ua.NewNumericNodeID(rolesIdx, 1); return r }()},
		"added unknown ns":    {func() Role { r := added("A"); r.NodeID = ua.NewStringNodeID(99, "x"); return r }()},
		"added name ns":       {func() Role { r := added("A"); r.BrowseName.NamespaceIndex = 99; return r }()},
		"added no name":       {added("")},
		"added well-known":    {func() Role { r := added("Operator"); r.BrowseName.NamespaceIndex = 0; return r }()},
		"added twice":         {added("A"), func() Role { r := added("A"); r.NodeID = ua.NewStringNodeID(rolesIdx, "y"); return r }()},
	} {
		st := &memRoleStore{}
		s := restartedRoleSet(t, st)
		st.roles, st.ns = roles, append(s.namespaceURIs(), RolesNamespaceURI)
		rs := s.RoleSet()
		before := rs.Roles()
		err := rs.restore()
		require.ErrorContains(t, err, "the stored roles", name)
		require.False(t, rs.restored, name)
		require.Equal(t, before, rs.Roles(), name)
	}

	// The roles namespace cannot hold the added roles.
	st := &memRoleStore{}
	s := restartedRoleSet(t, st)
	require.Positive(t, s.AddNamespace(blindNameSpace{NewNameSpace(RolesNamespaceURI)}))
	st.roles, st.ns = []Role{added("A")}, s.namespaceURIs()
	require.ErrorIs(t, s.RoleSet().restore(), ua.StatusBadNotSupported)
	require.Equal(t, s.namespaceURIs(), st.loaded, "the roles namespace is in the NamespaceArray")
}

// Concurrent changes through the Methods and the Go API: each is written
// once, and the store ends with the RoleSet.
func TestRoleSetStoreConcurrent(t *testing.T) {
	t.Parallel()
	st := &memRoleStore{}
	s := newRoleSetTestServer(t, RoleManagement{}, WithRoleSetStore(st))
	rs := s.RoleSet()
	ctx := roleAdminCtx(s)
	roles := []*ua.NodeID{ua.RoleObserver.NodeID(), ua.RoleOperator.NodeID(), ua.RoleEngineer.NodeID(), ua.RoleSupervisor.NodeID()}
	var wg sync.WaitGroup
	for i, r := range roles {
		wg.Go(func() {
			for j := range 10 {
				require.NoError(t, rs.AddApplication(r, "urn:app:"+itoa(j)))
				_, sc := callRole(t, s, ctx, r, s.childNamed(s.Node(r), id.HasComponent, "AddIdentity").ID(),
					ua.MustVariant(ua.NewExtensionObject(userRule("u"+itoa(i*100+j)))))
				require.Equal(t, ua.StatusOK, sc)
			}
		})
		wg.Go(func() {
			for range 20 {
				_ = rs.Roles()
				sess := s.sb.NewSession()
				s.grantRoles(nil, sess, &ua.UserNameIdentityToken{UserName: "u1"})
			}
		})
	}
	wg.Go(func() {
		for i := range 5 {
			nid, err := rs.AddRole("R"+itoa(i), "")
			require.NoError(t, err)
			if i%2 == 0 {
				require.NoError(t, rs.RemoveRole(nid))
			}
		}
	})
	wg.Wait()
	got, n := st.state()
	require.Equal(t, len(roles)*20+5+3, n)
	var want []Role
	for _, r := range rs.Roles() {
		if !r.Fixed {
			want = append(want, r)
		}
	}
	require.Equal(t, want, got)
}
