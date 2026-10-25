// SPDX-License-Identifier: MIT

package addrspace

import (
	"context"
	"sync"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// userController is an AccessController written outside package server: it
// lets only olivia read the guarded node, and records the sessions it saw.
type userController struct {
	server.DefaultAccessController

	mu      sync.Mutex
	guarded *ua.NodeID
	seen    map[string][]*ua.NodeID // SessionId -> roles
	certs   int
}

var (
	_ server.AccessController      = (*userController)(nil)
	_ server.EventAccessController = (*userController)(nil)
)

func (c *userController) CheckRead(_ context.Context, sess *server.Session, nodeID *ua.NodeID) ua.StatusCode {
	c.mu.Lock()
	guarded := c.guarded
	if sess != nil {
		c.seen[sess.ID().String()] = sess.Roles()
		if sess.ClientCertificate() != nil {
			c.certs++
		}
	}
	c.mu.Unlock()
	if guarded == nil || nodeID.String() != guarded.String() {
		return ua.StatusOK
	}
	if u, ok := sess.Identity().(*ua.UserNameIdentityToken); ok && u.UserName == "olivia" {
		return ua.StatusOK
	}
	return ua.StatusBadUserAccessDenied
}

func (c *userController) CheckReceiveEvents(context.Context, *server.Session, *ua.NodeID) ua.StatusCode {
	return ua.StatusOK
}

// TestAccessControl_CustomController: an AccessController of another package
// gets the session of the request: its SessionId, its identity and its roles.
func TestAccessControl_CustomController(t *testing.T) {
	ac := &userController{seen: map[string][]*ua.NodeID{}}
	srv, url := newServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(user, pass string) error {
			if pass == user+"-pw" {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if u, ok := tok.(*ua.UserNameIdentityToken); ok && u.UserName == "olivia" {
				return []*ua.NodeID{ua.RoleOperator.NodeID()}
			}
			return server.DefaultRoleMapper(tok)
		}),
		server.WithAccessController(ac),
	)
	f := testutil.AddFixture(t, srv)
	ac.mu.Lock()
	ac.guarded = f.Int32
	ac.mu.Unlock()
	ctx := context.Background()

	ep := endpointFor(t, url, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
	read := func(c *opcua.Client) ua.StatusCode {
		t.Helper()
		resp, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: f.Int32, AttributeID: ua.AttributeIDValue}}})
		require.NoError(t, err)
		return resp.Results[0].Status
	}

	olivia := newClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("olivia", "olivia-pw"))
	require.Equal(t, ua.StatusOK, read(olivia))
	bob := newClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("bob", "bob-pw"))
	require.Equal(t, ua.StatusBadUserAccessDenied, read(bob))
	require.Equal(t, ua.StatusBadUserAccessDenied, read(newClient(t, url)))

	ac.mu.Lock()
	defer ac.mu.Unlock()
	roles, ok := ac.seen[olivia.Session().SessionID().String()]
	require.True(t, ok, "the controller saw olivia's SessionId")
	require.Len(t, roles, 1)
	require.Equal(t, ua.RoleOperator.NodeID().String(), roles[0].String())
	_, ok = ac.seen[bob.Session().SessionID().String()]
	require.True(t, ok, "the controller saw bob's SessionId")
	require.Zero(t, ac.certs, "no client certificate over SecurityPolicy None")
}
