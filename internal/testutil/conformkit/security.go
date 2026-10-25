// SPDX-License-Identifier: MIT

package conformkit

import (
	"strings"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// The application URIs of the certificates of the shared test PKI.
const (
	ServerAppURI = testpki.ServerAppURI
	ClientAppURI = testpki.ClientAppURI
)

// PKI returns the in-memory PKI shared by all security tests of the test
// binary. RSA key generation is expensive (more so under the race detector),
// so it is built once per test binary; the certificates come from
// internal/testutil/testpki, which the chaos suites share.
func PKI(t *testing.T) *testpki.PKI {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	return p
}

// SecurePolicies lists every non-None RSA security policy the library
// supports.
var SecurePolicies = []string{
	ua.SecurityPolicyURIBasic128Rsa15,
	ua.SecurityPolicyURIBasic256,
	ua.SecurityPolicyURIBasic256Sha256,
	ua.SecurityPolicyURIAes128Sha256RsaOaep,
	ua.SecurityPolicyURIAes256Sha256RsaPss,
}

// SecureModes lists the secure message security modes.
var SecureModes = []ua.MessageSecurityMode{
	ua.MessageSecurityModeSign,
	ua.MessageSecurityModeSignAndEncrypt,
}

// SecureServerOpts returns server options enabling the server certificate and
// every policy x mode combination, plus any extra options.
func SecureServerOpts(t *testing.T, extra ...server.Option) []server.Option {
	t.Helper()
	p := PKI(t)
	opts := []server.Option{
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
	}
	for _, pol := range SecurePolicies {
		for _, mode := range SecureModes {
			opts = append(opts, server.EnableSecurity(pol, mode))
		}
	}
	return append(opts, extra...)
}

// SecureServer starts a server with the fixture and all secure endpoints.
func SecureServer(t *testing.T, extra ...server.Option) (*testutil.Fixture, string) {
	t.Helper()
	srv, url := NewServer(t, SecureServerOpts(t, extra...)...)
	f := testutil.AddFixture(t, srv)
	return f, url
}

// SecureClientOpts returns the client options for a fully validated secure
// connection to ep using the shared client application certificate.
func SecureClientOpts(t *testing.T, ep *ua.EndpointDescription, auth ua.UserTokenType) []opcua.Option {
	t.Helper()
	p := PKI(t)
	return []opcua.Option{
		opcua.SecurityFromEndpoint(ep, auth),
		opcua.Certificate(p.ClientCert),
		opcua.PrivateKey(p.ClientKey),
		opcua.TrustedCertificates(p.ServerCertX509),
	}
}

// ShortPolicy returns the name of a security policy URI without its prefix.
func ShortPolicy(uri string) string {
	return strings.TrimPrefix(uri, "http://opcfoundation.org/UA/SecurityPolicy#")
}

// UserValidator accepts the user alice with the password wonderland.
func UserValidator(user, pass string) error {
	if user == "alice" && pass == "wonderland" {
		return nil
	}
	return ua.StatusBadUserAccessDenied
}
