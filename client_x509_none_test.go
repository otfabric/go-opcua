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

// TestX509UserTokenOnNoneEndpointNamesPolicy checks that a None endpoint
// offers the X.509 user token under a real SecurityPolicy (Part 4 §7.40.5),
// so the client signs it, and that a client logs on with the certificate.
func TestX509UserTokenOnNoneEndpointNamesPolicy(t *testing.T) {
	t.Parallel()
	p, err := testpki.Get()
	require.NoError(t, err)
	_, url := newScriptedServer(t, nil,
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.AllowUsernameOnNone(),
		server.EnableAuthMode(ua.UserTokenTypeCertificate),
		server.WithX509UserValidator(func(der []byte) error {
			if bytes.Equal(der, p.UserCert) {
				return nil
			}
			return ua.StatusBadIdentityTokenRejected
		}),
	)
	ctx := context.Background()
	eps, err := opcua.GetEndpoints(ctx, url)
	require.NoError(t, err)

	var none *ua.EndpointDescription
	for _, ep := range eps {
		if ep.SecurityPolicyURI == ua.SecurityPolicyURINone {
			none = ep
		}
	}
	require.NotNil(t, none)
	var cert *ua.UserTokenPolicy
	for _, utp := range none.UserIdentityTokens {
		if utp.TokenType == ua.UserTokenTypeCertificate {
			cert = utp
		}
	}
	require.NotNil(t, cert)
	require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, cert.SecurityPolicyURI)

	c := connectCovClient(t, url,
		opcua.SecurityFromEndpoint(none, ua.UserTokenTypeCertificate),
		opcua.AuthCertificate(p.UserCert), opcua.AuthPrivateKey(p.UserKey))
	_, err = c.ServerStatus(ctx)
	require.NoError(t, err)

	// Without the key of the certificate the client cannot log on.
	c2 := newCovClient(t, url,
		opcua.SecurityFromEndpoint(none, ua.UserTokenTypeCertificate),
		opcua.AuthCertificate(p.UserCert), opcua.AuthPrivateKey(p.ClientKey))
	require.ErrorIs(t, c2.Connect(ctx), ua.StatusBadUserSignatureInvalid)
}
