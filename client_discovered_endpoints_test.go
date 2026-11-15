// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// TestCreateSessionComparesDiscoveredEndpoints checks that the client
// compares the endpoint list it selected from with the ServerEndpoints of
// CreateSession (Part 4 §5.6.2): the list given with DiscoveredEndpoints,
// and by default the GetEndpoints answer an endpoint given to
// SecurityFromEndpoint came in. When they differ, Connect closes the
// session before ActivateSession and fails with Bad_SecurityChecksFailed;
// InsecureSkipDiscoveredEndpointsCheck turns the comparison off.
func TestCreateSessionComparesDiscoveredEndpoints(t *testing.T) {
	t.Parallel()
	p, err := testpki.Get()
	require.NoError(t, err)
	ctx := context.Background()

	var logons, closes atomic.Int32
	// start starts a server with Sign and SignAndEncrypt endpoints. With
	// withoutEncrypt its GetEndpoints answer leaves the SignAndEncrypt
	// endpoints out; CreateSession returns all of them.
	start := func(withoutEncrypt bool) string {
		var srv *server.Server
		handlers := map[uint16]server.Handler{
			// Counts the sessions the client closes, and closes none: the
			// client sees the response it expects.
			id.CloseSessionRequestEncodingDefaultBinary: func(_ context.Context, _ *uasc.SecureChannel, r ua.Request, _ uint32) (ua.Response, error) {
				closes.Add(1)
				return &ua.CloseSessionResponse{ResponseHeader: okHeader(r)}, nil
			},
		}
		if withoutEncrypt {
			handlers[id.GetEndpointsRequestEncodingDefaultBinary] = respond(func(r ua.Request) ua.Response {
				res := &ua.GetEndpointsResponse{ResponseHeader: okHeader(r)}
				for _, ep := range srv.Endpoints() {
					if ep.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
						res.Endpoints = append(res.Endpoints, ep)
					}
				}
				return res
			})
		}
		var url string
		srv, url = newScriptedServer(t, handlers,
			server.Certificate(p.ServerCert),
			server.PrivateKey(p.ServerKey),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
			server.EnableAuthMode(ua.UserTokenTypeUserName),
			server.WithUsernameValidator(func(user, pass string) error {
				logons.Add(1)
				return nil
			}),
		)
		return url
	}
	full := start(false)
	partial := start(true)

	opts := func(ep *ua.EndpointDescription, more ...opcua.Option) []opcua.Option {
		return append([]opcua.Option{
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
			opcua.Certificate(p.ClientCert),
			opcua.PrivateKey(p.ClientKey),
			opcua.TrustedCertificates(p.ServerCertX509),
			opcua.AuthUsername("user", "secret"),
		}, more...)
	}
	// refused checks that Connect fails with Bad_SecurityChecksFailed after
	// CreateSession: the session is closed and never activated.
	refused := func(name, url string, opt ...opcua.Option) {
		t.Helper()
		l, cl := logons.Load(), closes.Load()
		c := newCovClient(t, url, opt...)
		require.ErrorIs(t, c.Connect(ctx), ua.StatusBadSecurityChecksFailed, name)
		require.Equal(t, l, logons.Load(), "%s: no ActivateSession", name)
		require.Equal(t, cl+1, closes.Load(), "%s: the session is closed", name)
	}
	connected := func(name, url string, mode ua.MessageSecurityMode, opt ...opcua.Option) {
		t.Helper()
		l := logons.Load()
		c := newCovClient(t, url, opt...)
		require.NoError(t, c.Connect(ctx), name)
		require.Equal(t, mode, c.SecurityMode(), name)
		require.Equal(t, l+1, logons.Load(), name)
		require.NoError(t, c.Close(ctx), name)
	}

	all, err := opcua.GetEndpoints(ctx, full)
	require.NoError(t, err)
	var sign *ua.EndpointDescription
	var withoutEncrypt []*ua.EndpointDescription
	for _, ep := range all {
		if ep.SecurityMode == ua.MessageSecurityModeSign {
			sign = ep
		}
		if ep.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
			withoutEncrypt = append(withoutEncrypt, ep)
		}
	}
	require.NotNil(t, sign)
	require.Len(t, withoutEncrypt, len(all)-1)
	// A copy of the endpoint, so that only the option gives the list.
	signCopy := *sign

	// The list given with DiscoveredEndpoints.
	connected("full list given", full, ua.MessageSecurityModeSign, opts(&signCopy, opcua.DiscoveredEndpoints(all))...)
	refused("list without SignAndEncrypt given", full, opts(&signCopy, opcua.DiscoveredEndpoints(withoutEncrypt))...)
	connected("list without SignAndEncrypt given, comparison off", full, ua.MessageSecurityModeSign,
		opts(&signCopy, opcua.DiscoveredEndpoints(withoutEncrypt), opcua.InsecureSkipDiscoveredEndpointsCheck())...)

	// The GetEndpoints answer the selected endpoint came in.
	ep, err := opcua.SelectEndpoint(all, "", ua.MessageSecurityModeInvalid, p.ClientCert)
	require.NoError(t, err)
	require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, ep.SecurityMode)
	connected("selected from the full answer", full, ua.MessageSecurityModeSignAndEncrypt, opts(ep)...)

	answer, err := opcua.GetEndpoints(ctx, partial)
	require.NoError(t, err)
	require.Len(t, answer, len(all)-1)
	ep, err = opcua.SelectEndpoint(answer, "", ua.MessageSecurityModeInvalid, p.ClientCert)
	require.NoError(t, err)
	require.Equal(t, ua.MessageSecurityModeSign, ep.SecurityMode)
	refused("selected from an answer without SignAndEncrypt", partial, opts(ep)...)
	connected("selected from an answer without SignAndEncrypt, comparison off", partial, ua.MessageSecurityModeSign,
		opts(ep, opcua.InsecureSkipDiscoveredEndpointsCheck())...)
	// The list given with the option replaces the answer. (The endpoints of
	// the two servers differ only in their URLs, which are not compared.)
	connected("selected from an answer without SignAndEncrypt, full list given", partial, ua.MessageSecurityModeSign,
		opts(ep, opcua.DiscoveredEndpoints(all))...)
}
