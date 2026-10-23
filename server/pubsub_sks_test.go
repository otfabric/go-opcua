// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	pubsubsec "github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

var (
	pubSubID        = ua.NewNumericNodeID(0, id.PublishSubscribe)
	getKeysID       = ua.NewNumericNodeID(0, id.PublishSubscribeGetSecurityKeys)
	setKeysID       = ua.NewNumericNodeID(0, id.PublishSubscribeSetSecurityKeys)
	getGroupID      = ua.NewNumericNodeID(0, id.PublishSubscribeGetSecurityGroup)
	groupsID        = ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroups)
	addGroupID      = ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroupsAddSecurityGroup)
	removeGroupID   = ua.NewNumericNodeID(0, id.PublishSubscribeSecurityGroupsRemoveSecurityGroup)
	folderAddID     = ua.NewNumericNodeID(0, id.SecurityGroupFolderTypeAddSecurityGroup)
	folderRemoveID  = ua.NewNumericNodeID(0, id.SecurityGroupFolderTypeRemoveSecurityGroup)
	basic256Sha256  = ua.SecurityPolicyURIBasic256Sha256
	signAndEncrypt  = ua.MessageSecurityModeSignAndEncrypt
	testUsers       = map[string]string{"alice": "alice-pw", "bob": "bob-pw"}
	errUnknownLogin = errors.New("unknown user")
)

type sksServer struct {
	srv   *server.Server
	url   string
	sks   *server.SecurityKeyService
	rings *pubsubsec.KeyRings
}

// startSKS starts a server with None, Basic256Sha256 Sign and SignAndEncrypt
// endpoints, anonymous and user name login, the KeyService ks and a push
// target for the rings.
func startSKS(t *testing.T, ks *pubsubsec.KeyService, pushOpts ...server.SKSOption) *sksServer {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity(basic256Sha256, ua.MessageSecurityModeSign),
		server.EnableSecurity(basic256Sha256, signAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(user, pass string) error {
			if want, ok := testUsers[user]; ok && want == pass {
				return nil
			}
			return errUnknownLogin
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if u, ok := tok.(*ua.UserNameIdentityToken); ok && u.UserName == "alice" {
				return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), ua.RoleSecurityAdmin.NodeID()}
			}
			return server.DefaultRoleMapper(tok)
		}),
	)
	require.NoError(t, err)
	h, err := srv.EnableSecurityKeyService(ks)
	require.NoError(t, err)
	rings := &pubsubsec.KeyRings{}
	require.NoError(t, srv.EnableSecurityKeyPush(rings, pushOpts...))
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	return &sksServer{srv: srv, url: fmt.Sprintf("opc.tcp://localhost:%d", srv.Port()), sks: h, rings: rings}
}

// connect opens a session with the given policy, mode and user ("" for
// anonymous).
func connect(t *testing.T, url, policy string, mode ua.MessageSecurityMode, user string) *opcua.Client {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)
	var ep *ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityPolicyURI == policy && e.SecurityMode == mode {
			ep = e
		}
	}
	require.NotNil(t, ep, "no endpoint %s %s", policy, mode)
	auth := ua.UserTokenTypeAnonymous
	opts := []opcua.Option{opcua.AutoReconnect(false)}
	if user != "" {
		auth = ua.UserTokenTypeUserName
		opts = append(opts, opcua.AuthUsername(user, testUsers[user]))
	} else {
		opts = append(opts, opcua.AuthAnonymous())
	}
	opts = append(opts, opcua.SecurityFromEndpoint(ep, auth))
	if policy != ua.SecurityPolicyURINone {
		opts = append(opts, opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey), opcua.TrustedCertificates(p.ServerCertX509))
	}
	c, err := opcua.NewClient(url, opts...)
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func call(t *testing.T, c *opcua.Client, obj, method *ua.NodeID, args ...any) *ua.CallMethodResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := c.CallMethod(ctx, obj, method, args...)
	require.NoError(t, err)
	return res
}

func newKeyService(t *testing.T, opts ...pubsubsec.Option) *pubsubsec.KeyService {
	t.Helper()
	ks := pubsubsec.NewKeyService(opts...)
	require.NoError(t, ks.AddSecurityGroup(pubsubsec.SecurityGroupConfig{
		SecurityGroupID:   "sg1",
		SecurityPolicyURI: pubsubsec.PolicyURIAes256CTR,
		KeyLifetime:       time.Hour,
		MaxFutureKeyCount: 2,
		MaxPastKeyCount:   1,
	}))
	return ks
}

func TestSKS_GetSecurityKeys(t *testing.T) {
	ks := newKeyService(t)
	s := startSKS(t, ks)
	alice := connect(t, s.url, basic256Sha256, signAndEncrypt, "alice")

	res := call(t, alice, pubSubID, getKeysID, "sg1", uint32(0), uint32(5))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Len(t, res.OutputArguments, 5)
	require.Equal(t, pubsubsec.PolicyURIAes256CTR, res.OutputArguments[0].Value())
	require.Equal(t, uint32(1), res.OutputArguments[1].Value())
	keys, ok := res.OutputArguments[2].Value().([][]byte)
	require.True(t, ok, "%T", res.OutputArguments[2].Value())
	require.Len(t, keys, 3)
	for _, k := range keys {
		require.Len(t, k, 68)
	}
	ttnk, ok := res.OutputArguments[3].Value().(float64)
	require.True(t, ok)
	require.InDelta(t, float64(time.Hour/time.Millisecond), ttnk, 60_000)
	require.Equal(t, float64(time.Hour/time.Millisecond), res.OutputArguments[4].Value())

	want, err := ks.GetSecurityKeys("sg1", 0, 2)
	require.NoError(t, err)
	require.Equal(t, want.Keys, keys)

	res = call(t, alice, pubSubID, getKeysID, "sg1", uint32(2), uint32(0))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, uint32(2), res.OutputArguments[1].Value())

	res = call(t, alice, pubSubID, getKeysID, "nope", uint32(0), uint32(0))
	require.Equal(t, ua.StatusBadNotFound, res.StatusCode)
	res = call(t, alice, pubSubID, getKeysID, "sg1", "x", uint32(0))
	require.Equal(t, ua.StatusBadTypeMismatch, res.StatusCode)
	res = call(t, alice, pubSubID, getKeysID, "sg1")
	require.Equal(t, ua.StatusBadArgumentsMissing, res.StatusCode)

	t.Run("rejected without encryption", func(t *testing.T) {
		for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSign} {
			policy := basic256Sha256
			if mode == ua.MessageSecurityModeNone {
				policy = ua.SecurityPolicyURINone
			}
			c := connect(t, s.url, policy, mode, "alice")
			res := call(t, c, pubSubID, getKeysID, "sg1", uint32(0), uint32(0))
			require.Equal(t, ua.StatusBadSecurityModeInsufficient, res.StatusCode, mode.String())
			require.Empty(t, res.OutputArguments)
		}
	})
	t.Run("rejected for anonymous", func(t *testing.T) {
		c := connect(t, s.url, basic256Sha256, signAndEncrypt, "")
		res := call(t, c, pubSubID, getKeysID, "sg1", uint32(0), uint32(0))
		require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	})
}

func TestSKS_Authorizer(t *testing.T) {
	ks := newKeyService(t, pubsubsec.WithAuthorizer(func(_ context.Context, c *pubsubsec.Caller, op pubsubsec.Operation, gid string) error {
		if op == pubsubsec.OpGetSecurityKeys && c.UserName() == "bob" && gid == "sg1" {
			return nil
		}
		return pubsubsec.RequireRoles(ua.RoleSecurityAdmin.NodeID())(context.Background(), c, op, gid)
	}))
	s := startSKS(t, ks)
	bob := connect(t, s.url, basic256Sha256, signAndEncrypt, "bob")
	require.Equal(t, ua.StatusOK, call(t, bob, pubSubID, getKeysID, "sg1", uint32(0), uint32(0)).StatusCode)
	res := call(t, bob, groupsID, addGroupID, "sg2", 1000.0, pubsubsec.PolicyURIAes128CTR, uint32(1), uint32(1))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	res = call(t, bob, pubSubID, getGroupID, "sg1")
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)

	alice := connect(t, s.url, basic256Sha256, signAndEncrypt, "alice")
	res = call(t, alice, groupsID, addGroupID, "sg2", 1000.0, pubsubsec.PolicyURIAes128CTR, uint32(1), uint32(1))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	res = call(t, bob, pubSubID, getKeysID, "sg2", uint32(0), uint32(0))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	nid, _ := s.sks.SecurityGroupNodeID("sg2")
	res = call(t, bob, groupsID, removeGroupID, nid)
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
}

func TestSKS_AddRemoveSecurityGroup(t *testing.T) {
	ks := newKeyService(t)
	require.NoError(t, ks.AddSecurityGroup(pubsubsec.SecurityGroupConfig{
		SecurityGroupID:     "nested",
		SecurityPolicyURI:   pubsubsec.PolicyURIAes128CTR,
		KeyLifetime:         time.Minute,
		SecurityGroupFolder: []string{"plant", "line 1"},
	}))
	s := startSKS(t, ks)
	alice := connect(t, s.url, basic256Sha256, signAndEncrypt, "alice")
	ctx := context.Background()

	res := call(t, alice, groupsID, addGroupID, "sg2", 1500.0, pubsubsec.PolicyURIAes128CTR, uint32(3), uint32(2))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, "sg2", res.OutputArguments[0].Value())
	nid, ok := res.OutputArguments[1].Value().(*ua.NodeID)
	require.True(t, ok)
	cfg, ok := ks.SecurityGroup("sg2")
	require.True(t, ok)
	require.Equal(t, 1500*time.Millisecond, cfg.KeyLifetime)
	require.Equal(t, uint32(3), cfg.MaxFutureKeyCount)
	require.Equal(t, uint32(2), cfg.MaxPastKeyCount)

	// The node is a SecurityGroupType below SecurityGroups with the
	// properties of the group.
	refs, err := alice.Node(groupsID).ReferencedNodes(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassObject, false)
	require.NoError(t, err)
	var found bool
	for _, r := range refs {
		found = found || r.ID.Equal(nid)
	}
	require.True(t, found, "SecurityGroups has the group")
	td, err := alice.Node(nid).ReferencedNodes(ctx, id.HasTypeDefinition, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	require.Len(t, td, 1)
	require.Equal(t, uint32(id.SecurityGroupType), td[0].ID.IntID())
	props := map[string]any{}
	pnodes, err := alice.Node(nid).ReferencedNodes(ctx, id.HasProperty, ua.BrowseDirectionForward, ua.NodeClassVariable, false)
	require.NoError(t, err)
	for _, pn := range pnodes {
		bn, err := pn.BrowseName(ctx)
		require.NoError(t, err)
		v, err := pn.Value(ctx)
		require.NoError(t, err)
		props[bn.Name] = v.Value()
	}
	require.Equal(t, map[string]any{
		"SecurityGroupId":   "sg2",
		"KeyLifetime":       1500.0,
		"SecurityPolicyUri": pubsubsec.PolicyURIAes128CTR,
		"MaxFutureKeyCount": uint32(3),
		"MaxPastKeyCount":   uint32(2),
	}, props)

	res = call(t, alice, pubSubID, getGroupID, "sg2")
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, nid, res.OutputArguments[0].Value())
	require.Equal(t, ua.StatusBadNotFound, call(t, alice, pubSubID, getGroupID, "nope").StatusCode)

	cases := []struct {
		name string
		args []any
		want ua.StatusCode
	}{
		{"exists", []any{"sg2", 1000.0, pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0)}, ua.StatusBadNodeIDExists},
		{"policy", []any{"sg3", 1000.0, "urn:none", uint32(0), uint32(0)}, ua.StatusBadSecurityPolicyRejected},
		{"lifetime", []any{"sg3", 0.0, pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0)}, ua.StatusBadInvalidArgument},
		{"negative lifetime", []any{"sg3", -1.0, pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0)}, ua.StatusBadInvalidArgument},
		{"name", []any{"", 1000.0, pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0)}, ua.StatusBadInvalidArgument},
		{"types", []any{"sg3", "1000", pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0)}, ua.StatusBadTypeMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, call(t, alice, groupsID, addGroupID, c.args...).StatusCode)
		})
	}

	// A group in a SecurityGroupFolder, added through the folder.
	folder, ok := s.sks.SecurityGroupFolderNodeID("plant", "line 1")
	require.True(t, ok)
	nestedID, ok := s.sks.SecurityGroupNodeID("nested")
	require.True(t, ok)
	fr, err := alice.Node(folder).ReferencedNodes(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	require.NoError(t, err)
	var hasNested, hasAdd bool
	for _, r := range fr {
		hasNested = hasNested || r.ID.Equal(nestedID)
		hasAdd = hasAdd || r.ID.Equal(folderAddID)
	}
	require.True(t, hasNested)
	require.True(t, hasAdd)
	res = call(t, alice, folder, folderAddID, "in-folder", 1000.0, pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	cfg, _ = ks.SecurityGroup("in-folder")
	require.Equal(t, []string{"plant", "line 1"}, cfg.SecurityGroupFolder)
	require.Equal(t, ua.StatusOK, call(t, alice, folder, folderRemoveID, res.OutputArguments[1].Value()).StatusCode)
	_, ok = ks.SecurityGroup("in-folder")
	require.False(t, ok)
	plant, ok := s.sks.SecurityGroupFolderNodeID("plant")
	require.True(t, ok)
	require.Equal(t, ua.StatusOK, call(t, alice, plant, folderAddID, "in-plant", 1000.0, pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0)).StatusCode)
	cfg, _ = ks.SecurityGroup("in-plant")
	require.Equal(t, []string{"plant"}, cfg.SecurityGroupFolder)

	// Remove the group: the node goes away.
	require.Equal(t, ua.StatusOK, call(t, alice, groupsID, removeGroupID, nid).StatusCode)
	_, ok = ks.SecurityGroup("sg2")
	require.False(t, ok)
	_, ok = s.sks.SecurityGroupNodeID("sg2")
	require.False(t, ok)
	require.Nil(t, s.srv.Node(nid))
	refs, err = alice.Node(groupsID).ReferencedNodes(ctx, id.HasComponent, ua.BrowseDirectionForward, ua.NodeClassObject, false)
	require.NoError(t, err)
	for _, r := range refs {
		require.False(t, r.ID.Equal(nid))
	}
	require.Equal(t, ua.StatusBadNodeIDUnknown, call(t, alice, groupsID, removeGroupID, nid).StatusCode)
	require.Equal(t, ua.StatusBadNodeIDUnknown, call(t, alice, groupsID, removeGroupID, ua.NewNumericNodeID(0, 1)).StatusCode)

	// Groups added through the Go API get nodes too; Close detaches.
	require.NoError(t, ks.AddSecurityGroup(pubsubsec.SecurityGroupConfig{SecurityGroupID: "api", SecurityPolicyURI: pubsubsec.PolicyURIAes128CTR, KeyLifetime: time.Second}))
	_, ok = s.sks.SecurityGroupNodeID("api")
	require.True(t, ok)
	require.Same(t, ks, s.sks.KeyService())
	s.sks.Close()
	require.NoError(t, ks.AddSecurityGroup(pubsubsec.SecurityGroupConfig{SecurityGroupID: "late", SecurityPolicyURI: pubsubsec.PolicyURIAes128CTR, KeyLifetime: time.Second}))
	_, ok = s.sks.SecurityGroupNodeID("late")
	require.False(t, ok)
	res = call(t, alice, groupsID, addGroupID, "late2", 1000.0, pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0))
	require.Equal(t, ua.StatusBadInternalError, res.StatusCode)
	_, ok = s.sks.SecurityGroupFolderNodeID("nope")
	require.False(t, ok)

	t.Run("rejected without encryption", func(t *testing.T) {
		c := connect(t, s.url, basic256Sha256, ua.MessageSecurityModeSign, "alice")
		require.Equal(t, ua.StatusBadSecurityModeInsufficient, call(t, c, groupsID, addGroupID, "x", 1000.0, pubsubsec.PolicyURIAes128CTR, uint32(0), uint32(0)).StatusCode)
		require.Equal(t, ua.StatusBadSecurityModeInsufficient, call(t, c, groupsID, removeGroupID, nestedID).StatusCode)
		require.Equal(t, ua.StatusBadSecurityModeInsufficient, call(t, c, pubSubID, getGroupID, "nested").StatusCode)
	})
}

func TestSKS_SetSecurityKeys(t *testing.T) {
	ks := newKeyService(t)
	s := startSKS(t, ks)
	p := pubsubsec.Aes128CTR()
	ring := pubsubsec.NewKeyRing("pushed", p)
	s.rings.Add(ring)
	alice := connect(t, s.url, basic256Sha256, signAndEncrypt, "alice")

	key := func(b byte) []byte {
		k := make([]byte, p.KeyLength())
		k[0] = b
		return k
	}
	res := call(t, alice, pubSubID, setKeysID, "pushed", p.URI(), uint32(7), key(7), [][]byte{key(8), key(9)}, 60_000.0, 120_000.0)
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, []uint32{7, 8, 9}, ring.TokenIDs())
	require.Equal(t, 2*time.Minute, ring.KeyLifetime())
	k, err := ring.CurrentKeys()
	require.NoError(t, err)
	require.Equal(t, byte(7), k.SigningKey[0])

	// No future keys: an empty array.
	res = call(t, alice, pubSubID, setKeysID, "pushed", p.URI(), uint32(8), key(8), [][]byte{}, 0.0, 1000.0)
	require.Equal(t, ua.StatusOK, res.StatusCode, res.StatusCode.Error())
	require.Equal(t, uint32(8), ring.CurrentTokenID())

	cases := []struct {
		name string
		args []any
		want ua.StatusCode
	}{
		{"unknown group", []any{"nope", p.URI(), uint32(1), key(1), [][]byte{}, 0.0, 1000.0}, ua.StatusBadNotFound},
		{"policy", []any{"pushed", pubsubsec.PolicyURIAes256CTR, uint32(1), key(1), [][]byte{}, 0.0, 1000.0}, ua.StatusBadSecurityPolicyRejected},
		{"key length", []any{"pushed", p.URI(), uint32(1), []byte{1, 2}, [][]byte{}, 0.0, 1000.0}, ua.StatusBadSecurityChecksFailed},
		{"token 0", []any{"pushed", p.URI(), uint32(0), key(1), [][]byte{}, 0.0, 1000.0}, ua.StatusBadInvalidArgument},
		{"lifetime", []any{"pushed", p.URI(), uint32(1), key(1), [][]byte{}, 0.0, -5.0}, ua.StatusBadInvalidArgument},
		{"scalar future keys", []any{"pushed", p.URI(), uint32(1), key(1), key(2), 0.0, 1000.0}, ua.StatusBadTypeMismatch},
		{"missing", []any{"pushed", p.URI()}, ua.StatusBadArgumentsMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, call(t, alice, pubSubID, setKeysID, c.args...).StatusCode)
		})
	}

	anon := connect(t, s.url, basic256Sha256, signAndEncrypt, "")
	require.Equal(t, ua.StatusBadUserAccessDenied, call(t, anon, pubSubID, setKeysID, "pushed", p.URI(), uint32(1), key(1), [][]byte{}, 0.0, 1000.0).StatusCode)
	sign := connect(t, s.url, basic256Sha256, ua.MessageSecurityModeSign, "alice")
	require.Equal(t, ua.StatusBadSecurityModeInsufficient, call(t, sign, pubSubID, setKeysID, "pushed", p.URI(), uint32(1), key(1), [][]byte{}, 0.0, 1000.0).StatusCode)
	require.Equal(t, uint32(8), ring.CurrentTokenID())
}

func TestSKS_EnableErrors(t *testing.T) {
	srv, err := server.New(server.EndPoint("localhost", 0))
	require.NoError(t, err)
	_, err = srv.EnableSecurityKeyService(nil)
	require.Error(t, err)
	require.Error(t, srv.EnableSecurityKeyPush(nil))

	// A namespace of the caller's choice, and the default one is reused.
	ns := server.NewNodeNameSpace(srv, "urn:test:sks")
	ks := newKeyService(t)
	h, err := srv.EnableSecurityKeyService(ks, server.SKSNamespace(ns), nil)
	require.NoError(t, err)
	nid, ok := h.SecurityGroupNodeID("sg1")
	require.True(t, ok)
	require.Equal(t, ns.ID(), nid.Namespace())
	require.NoError(t, srv.EnableSecurityKeyPush(&pubsubsec.KeyRings{}, server.SKSAuthorizer(pubsubsec.AllowAll)))
	require.NoError(t, srv.EnableSecurityKeyPush(&pubsubsec.KeyRings{}))
	n := len(srv.Namespaces())
	require.NoError(t, srv.EnableSecurityKeyPush(&pubsubsec.KeyRings{}))
	require.Len(t, srv.Namespaces(), n)

	// The method nodes require encryption.
	av, err := srv.Node(getKeysID).Attribute(ua.AttributeIDAccessRestrictions)
	require.NoError(t, err)
	require.Equal(t, uint16(ua.AccessRestrictionTypeEncryptionRequired), av.Value.Value.Value())
}
