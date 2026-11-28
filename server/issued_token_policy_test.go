// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// tokenPolicies returns the user token policies of the endpoints of srv by
// token type.
func tokenPolicies(t *testing.T, srv *Server) map[ua.UserTokenType][]*ua.UserTokenPolicy {
	t.Helper()
	out := map[ua.UserTokenType][]*ua.UserTokenPolicy{}
	for _, ep := range srv.Endpoints() {
		for _, p := range ep.UserIdentityTokens {
			out[p.TokenType] = append(out[p.TokenType], p)
		}
	}
	return out
}

// TestWithIssuedTokenPolicy: the IssuedToken UserTokenPolicy advertises the
// IssuedTokenType and IssuerEndpointUrl of WithIssuedTokenPolicy; the other
// policies carry neither, as IssuedTokenType "may only be specified if
// TokenType is ISSUEDTOKEN" (Part 4 §7.41).
func TestWithIssuedTokenPolicy(t *testing.T) {
	const issuer = `{"ua:resourceId":"urn:test:server","ua:authorityUrl":"https://auth.example"}`
	newServer := func(t *testing.T, opts ...Option) *Server {
		t.Helper()
		srv, err := New(append([]Option{
			EndPoint("localhost", 0),
			InsecureNoSecurity(),
			AllowUsernameOnNone(),
			EnableAuthMode(ua.UserTokenTypeAnonymous),
			EnableAuthMode(ua.UserTokenTypeUserName),
			EnableAuthMode(ua.UserTokenTypeIssuedToken),
		}, opts...)...)
		require.NoError(t, err)
		srv.initEndpoints() // Start builds them
		return srv
	}

	t.Run("configured", func(t *testing.T) {
		pols := tokenPolicies(t, newServer(t, WithIssuedTokenPolicy(IssuedTokenTypeJWT, issuer)))
		require.NotEmpty(t, pols[ua.UserTokenTypeIssuedToken])
		for _, p := range pols[ua.UserTokenTypeIssuedToken] {
			require.Equal(t, "http://opcfoundation.org/UA/UserToken#JWT", p.IssuedTokenType)
			require.Equal(t, issuer, p.IssuerEndpointURL)
		}
		for _, tt := range []ua.UserTokenType{ua.UserTokenTypeAnonymous, ua.UserTokenTypeUserName} {
			require.NotEmpty(t, pols[tt])
			for _, p := range pols[tt] {
				require.Empty(t, p.IssuedTokenType, "%v", tt)
				require.Empty(t, p.IssuerEndpointURL, "%v", tt)
			}
		}
	})

	t.Run("default", func(t *testing.T) {
		pols := tokenPolicies(t, newServer(t))
		require.NotEmpty(t, pols[ua.UserTokenTypeIssuedToken])
		for _, p := range pols[ua.UserTokenTypeIssuedToken] {
			require.Empty(t, p.IssuedTokenType)
			require.Empty(t, p.IssuerEndpointURL)
		}
	})
}
