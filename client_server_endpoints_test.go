// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestCreateSessionVerifiesServerEndpoints checks that the client compares
// the endpoint it selected from GetEndpoints with the endpoints of the
// CreateSession response and does not activate the session when they
// differ (Part 4 §5.7.2).
func TestCreateSessionVerifiesServerEndpoints(t *testing.T) {
	t.Parallel()
	p, err := testpki.Get()
	require.NoError(t, err)
	var logons atomic.Int32
	_, url := newScriptedServer(t, nil,
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			logons.Add(1)
			return nil
		}),
	)
	ctx := context.Background()
	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)
	var ep *ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityMode == ua.MessageSecurityModeSign {
			ep = e
		}
	}
	require.NotNil(t, ep)

	opts := func(ep *ua.EndpointDescription) []opcua.Option {
		return []opcua.Option{
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
			opcua.Certificate(p.ClientCert),
			opcua.PrivateKey(p.ClientKey),
			opcua.TrustedCertificates(p.ServerCertX509),
			opcua.AuthUsername("user", "secret"),
		}
	}

	// The endpoint as the server describes it.
	c := connectCovClient(t, url, opts(ep)...)
	_, err = c.ServerStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), logons.Load())

	// An endpoint whose user token policy differs from the server's.
	changed := *ep
	changed.UserIdentityTokens = nil
	for _, utp := range ep.UserIdentityTokens {
		u := *utp
		u.SecurityPolicyURI = ua.SecurityPolicyURINone
		changed.UserIdentityTokens = append(changed.UserIdentityTokens, &u)
	}
	c2 := newCovClient(t, url, opts(&changed)...)
	require.ErrorIs(t, c2.Connect(ctx), ua.StatusBadSecurityChecksFailed)
	require.Equal(t, int32(1), logons.Load(), "no ActivateSession after the mismatch")
}
