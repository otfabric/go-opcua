// SPDX-License-Identifier: MIT

package opcua

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

func TestVerifyServerEndpoints(t *testing.T) {
	sc := uasc.NewCryptoChannel(&uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
		SecurityMode:      ua.MessageSecurityModeSign,
	})
	ep := func() *ua.EndpointDescription {
		return &ua.EndpointDescription{
			EndpointURL:         "opc.tcp://a:4840",
			Server:              &ua.ApplicationDescription{ApplicationURI: "urn:s"},
			SecurityPolicyURI:   ua.SecurityPolicyURIBasic256Sha256,
			SecurityMode:        ua.MessageSecurityModeSign,
			SecurityLevel:       3,
			TransportProfileURI: ua.TransportProfileUATCP,
			UserIdentityTokens: []*ua.UserTokenPolicy{
				{PolicyID: "anonymous", TokenType: ua.UserTokenTypeAnonymous},
				{PolicyID: "username", TokenType: ua.UserTokenTypeUserName},
			},
		}
	}
	srv := ep()
	srv.EndpointURL = "opc.tcp://b:4840" // the URL is not compared
	srv.UserIdentityTokens = []*ua.UserTokenPolicy{srv.UserIdentityTokens[1], srv.UserIdentityTokens[0]}
	other := ep()
	other.SecurityMode = ua.MessageSecurityModeSignAndEncrypt
	servers := []*ua.EndpointDescription{nil, other, srv}

	require.NoError(t, verifyServerEndpoints(nil, sc, servers), "no endpoint selected")
	require.NoError(t, verifyServerEndpoints(ep(), nil, servers), "no channel")
	require.NoError(t, verifyServerEndpoints(ep(), sc, servers))
	require.NoError(t, verifyServerEndpoints(other, sc, nil), "channel uses other security than the endpoint")

	for name, change := range map[string]func(*ua.EndpointDescription){
		"application uri": func(e *ua.EndpointDescription) { e.Server.ApplicationURI = "urn:x" },
		"security level":  func(e *ua.EndpointDescription) { e.SecurityLevel = 9 },
		"transport":       func(e *ua.EndpointDescription) { e.TransportProfileURI = ua.TransportProfileHTTPS },
		"token count":     func(e *ua.EndpointDescription) { e.UserIdentityTokens = e.UserIdentityTokens[:1] },
		"token policy uri": func(e *ua.EndpointDescription) {
			e.UserIdentityTokens[1] = &ua.UserTokenPolicy{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURINone}
		},
		"nil token": func(e *ua.EndpointDescription) { e.UserIdentityTokens[1] = nil },
	} {
		e := ep()
		change(e)
		require.ErrorIs(t, verifyServerEndpoints(e, sc, servers), ua.StatusBadSecurityChecksFailed, name)
	}
	require.ErrorIs(t, verifyServerEndpoints(ep(), sc, nil), ua.StatusBadSecurityChecksFailed, "empty list")
}
