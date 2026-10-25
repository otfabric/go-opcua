// SPDX-License-Identifier: MIT

package eccext

import (
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// Copies of the helpers of the conformance package that the tests here use
// (security_test.go, security_ecc_test.go): see doc.go for why these tests
// are a package of their own.

// securePolicies lists every non-None security policy the library supports.
var securePolicies = []string{
	ua.SecurityPolicyURIBasic128Rsa15,
	ua.SecurityPolicyURIBasic256,
	ua.SecurityPolicyURIBasic256Sha256,
	ua.SecurityPolicyURIAes128Sha256RsaOaep,
	ua.SecurityPolicyURIAes256Sha256RsaPss,
}

var secureModes = []ua.MessageSecurityMode{
	ua.MessageSecurityModeSign,
	ua.MessageSecurityModeSignAndEncrypt,
}

// secureServerOpts returns server options enabling the server certificate and
// every policy x mode combination, plus any extra options.
func secureServerOpts(t *testing.T, extra ...server.Option) []server.Option {
	t.Helper()
	p := pki(t)
	opts := []server.Option{
		server.Certificate(p.serverCert),
		server.PrivateKey(p.serverKey),
	}
	for _, pol := range securePolicies {
		for _, mode := range secureModes {
			opts = append(opts, server.EnableSecurity(pol, mode))
		}
	}
	return append(opts, extra...)
}

func shortPolicy(uri string) string {
	return strings.TrimPrefix(uri, "http://opcfoundation.org/UA/SecurityPolicy#")
}

// userValidator accepts exactly alice/wonderland.
func userValidator(user, pass string) error {
	if user == "alice" && pass == "wonderland" {
		return nil
	}
	return ua.StatusBadUserAccessDenied
}

// awaitInt32Change waits until the subscription behind ch reports want.
func awaitInt32Change(t *testing.T, ch <-chan *opcua.PublishNotificationData, want int32) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		for _, dc := range nextDataChanges(t, ch) {
			if dc.dv != nil && dc.dv.Value != nil && dc.dv.Value.Value() == want {
				return
			}
		}
	}
	t.Fatalf("no data change with value %d", want)
}
