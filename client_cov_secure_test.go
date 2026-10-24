// SPDX-License-Identifier: MIT

package opcua_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// secureCovServer starts a server with a Basic256Sha256 SignAndEncrypt
// endpoint that accepts user "user"/"secret" and the PKI's user certificate.
func secureCovServer(t *testing.T) (*testpki.PKI, *ua.EndpointDescription, string) {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	_, url := newScriptedServer(t, nil,
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.EnableAuthMode(ua.UserTokenTypeIssuedToken),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == "user" && pass == "secret" {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithX509UserValidator(func(der []byte) error {
			if bytes.Equal(der, p.UserCert) {
				return nil
			}
			return ua.StatusBadIdentityTokenRejected
		}),
	)
	eps, err := opcua.GetEndpoints(context.Background(), url)
	require.NoError(t, err)
	for _, ep := range eps {
		if ep.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && ep.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
			return p, ep, url
		}
	}
	t.Fatal("no Basic256Sha256 endpoint")
	return nil, nil, ""
}

func secureCovOpts(p *testpki.PKI, ep *ua.EndpointDescription, auth ua.UserTokenType, extra ...opcua.Option) []opcua.Option {
	return append([]opcua.Option{
		opcua.SecurityFromEndpoint(ep, auth),
		opcua.Certificate(p.ClientCert),
		opcua.PrivateKey(p.ClientKey),
		opcua.TrustedCertificates(p.ServerCertX509),
	}, extra...)
}

func TestClientCovSecureUserTokens(t *testing.T) {
	p, ep, url := secureCovServer(t)
	ctx := context.Background()

	t.Run("user name", func(t *testing.T) {
		c := connectCovClient(t, url, secureCovOpts(p, ep, ua.UserTokenTypeUserName, opcua.AuthUsername("user", "secret"))...)
		require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, c.SecurityPolicy())
		require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, c.SecurityMode())
		_, err := c.ServerStatus(ctx)
		require.NoError(t, err)

		// the configured token is not changed by encrypting the password
		tok, ok := c.TestingConfiguredUserToken().(*ua.UserNameIdentityToken)
		require.True(t, ok)
		require.Empty(t, tok.EncryptionAlgorithm)
	})

	t.Run("wrong password", func(t *testing.T) {
		c := newCovClient(t, url, secureCovOpts(p, ep, ua.UserTokenTypeUserName, opcua.AuthUsername("user", "wrong"))...)
		require.ErrorIs(t, c.Connect(ctx), ua.StatusBadUserAccessDenied)
		require.Equal(t, opcua.Closed, c.State())
	})

	t.Run("user certificate", func(t *testing.T) {
		c := connectCovClient(t, url, secureCovOpts(p, ep, ua.UserTokenTypeCertificate,
			opcua.AuthCertificate(p.UserCert), opcua.AuthPrivateKey(p.UserKey))...)
		_, err := c.ServerStatus(ctx)
		require.NoError(t, err)
	})

	t.Run("untrusted user certificate", func(t *testing.T) {
		c := newCovClient(t, url, secureCovOpts(p, ep, ua.UserTokenTypeCertificate,
			opcua.AuthCertificate(p.StrangerCert), opcua.AuthPrivateKey(p.StrangerKey))...)
		require.ErrorIs(t, c.Connect(ctx), ua.StatusBadIdentityTokenRejected)
	})

	t.Run("issued token", func(t *testing.T) {
		// the server has no validator for issued tokens and rejects them
		c := newCovClient(t, url, secureCovOpts(p, ep, ua.UserTokenTypeIssuedToken, opcua.AuthIssuedToken([]byte("token")))...)
		err := c.Connect(ctx)
		require.Error(t, err)
		var sc ua.StatusCode
		require.ErrorAs(t, err, &sc)
		require.Equal(t, opcua.Closed, c.State())
	})
}

func TestClientCovSecureChannelFailures(t *testing.T) {
	p, ep, url := secureCovServer(t)
	ctx := context.Background()

	t.Run("server certificate not trusted", func(t *testing.T) {
		c := newCovClient(t, url,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.Certificate(p.ClientCert),
			opcua.PrivateKey(p.ClientKey),
		)
		err := c.Connect(ctx)
		require.ErrorContains(t, err, "server certificate validation failed")
		require.Nil(t, c.SecureChannel())
		require.Equal(t, opcua.Closed, c.State())
	})

	t.Run("server without the policy", func(t *testing.T) {
		// a server that only speaks None cannot open the secure channel
		_, plain := newScriptedServer(t, nil)
		c := newCovClient(t, plain, secureCovOpts(p, ep, ua.UserTokenTypeAnonymous)...)
		require.Error(t, c.Connect(ctx))
		require.Nil(t, c.SecureChannel())
		require.Equal(t, opcua.Closed, c.State())
	})
}
