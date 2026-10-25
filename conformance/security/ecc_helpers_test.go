// SPDX-License-Identifier: MIT

package security

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// eccIdentity is an ECC certificate with its private key: an ECDSA key or,
// for the curve Ed25519, an EdDSA key.
type eccIdentity struct {
	cert []byte
	key  crypto.Signer
	x509 *x509.Certificate
}

// eccPKI is the ECC half of the shared test PKI: application instance and
// user certificates on the curves of the ECC security policies. It lives next
// to the RSA certificates of testPKI, the way a server that offers both
// families has one certificate per key type.
type eccPKI struct {
	// Self-signed application instance certificates, by curve.
	server map[string]*eccIdentity
	client map[string]*eccIdentity

	// user is a self-signed X.509 user identity certificate, stranger a
	// certificate nobody trusts (both P-256).
	user     *eccIdentity
	stranger *eccIdentity

	// edUser is an Ed25519 X.509 user identity certificate.
	edUser *eccIdentity

	// A P-256 CA and a client certificate issued by it, for trust lists.
	caCert []byte
	issued *eccIdentity

	// By curve: user identity certificates, CAs and client certificates
	// issued by them.
	users      map[string]*eccIdentity
	cas        map[string]*eccIdentity
	issuedByCA map[string]*eccIdentity
}

const (
	curveP256    = testpki.CurveP256
	curveP384    = testpki.CurveP384
	curveEd25519 = testpki.CurveEd25519

	curveBrainpoolP256r1 = testpki.CurveBrainpoolP256r1
	curveBrainpoolP384r1 = testpki.CurveBrainpoolP384r1
	curveEd448           = testpki.CurveEd448
)

// aeadPolicies lists the ECC security policies of OPC UA 1.05.07 with
// authenticated encryption, with the key type of the application instance
// certificates the tests use with them.
var aeadPolicies = []struct {
	uri   string
	curve string
}{
	{ua.SecurityPolicyURIECCNistP256AesGcm, curveP256},
	{ua.SecurityPolicyURIECCNistP256ChaChaPoly, curveP256},
	{ua.SecurityPolicyURIECCCurve25519, curveEd25519},
}

// eccPolicies lists the ECC security policies with the curve of the
// application instance certificates the tests use with them.
var eccPolicies = []struct {
	uri   string
	curve string
}{
	{ua.SecurityPolicyURIECCNistP256, curveP256},
	{ua.SecurityPolicyURIECCNistP384, curveP384},
}

// adaptECC converts the ECC half of the shared test PKI.
func adaptECC(src *testpki.ECC) *eccPKI {
	conv := func(id *testpki.Identity) *eccIdentity {
		return &eccIdentity{cert: id.Cert, key: id.Key, x509: id.X509}
	}
	p := &eccPKI{
		server:   map[string]*eccIdentity{},
		client:   map[string]*eccIdentity{},
		user:     conv(src.User),
		stranger: conv(src.Stranger),
		edUser:   conv(src.EdUser),
		caCert:   src.CACert,
		issued:   conv(src.Issued),

		users:      map[string]*eccIdentity{},
		cas:        map[string]*eccIdentity{},
		issuedByCA: map[string]*eccIdentity{},
	}
	for dst, from := range map[*map[string]*eccIdentity]map[string]*testpki.Identity{
		&p.server: src.Server, &p.client: src.Client, &p.users: src.Users,
		&p.cas: src.CAs, &p.issuedByCA: src.IssuedByCA,
	} {
		for curve, id := range from {
			(*dst)[curve] = conv(id)
		}
	}
	return p
}

// mixedServerOpts returns the options of a server that offers every RSA and
// every ECC security policy in both secure modes. It has three application
// instance certificates: RSA, ECC P-256 and ECC P-384.
func mixedServerOpts(t *testing.T, extra ...server.Option) []server.Option {
	t.Helper()
	ecc := pki(t).ecc
	opts := secureServerOpts(t,
		server.ApplicationIdentity(ecc.server[curveP256].cert, ecc.server[curveP256].key),
		server.ApplicationIdentity(ecc.server[curveP384].cert, ecc.server[curveP384].key),
	)
	for _, pol := range eccPolicies {
		for _, mode := range secureModes {
			opts = append(opts, server.EnableSecurity(pol.uri, mode))
		}
	}
	return append(opts, extra...)
}

// aeadServerOpts returns the options of a server that offers what
// mixedServerOpts does and the ECC policies with authenticated encryption. It
// has a fourth application instance certificate, with an Ed25519 key.
func aeadServerOpts(t *testing.T, extra ...server.Option) []server.Option {
	t.Helper()
	ed := pki(t).ecc.server[curveEd25519]
	opts := mixedServerOpts(t, server.ApplicationIdentity(ed.cert, ed.key))
	for _, pol := range aeadPolicies {
		for _, mode := range secureModes {
			opts = append(opts, server.EnableSecurity(pol.uri, mode))
		}
	}
	return append(opts, extra...)
}

// aeadServer starts a server with the fixture and every RSA and ECC endpoint,
// those of the policies with authenticated encryption included.
func aeadServer(t *testing.T, extra ...server.Option) (*testutil.Fixture, string) {
	t.Helper()
	srv, url := newServer(t, aeadServerOpts(t, extra...)...)
	return testutil.AddFixture(t, srv), url
}

// mixedServer starts a server with the fixture and all RSA and ECC endpoints.
func mixedServer(t *testing.T, extra ...server.Option) (*testutil.Fixture, string) {
	t.Helper()
	srv, url := newServer(t, mixedServerOpts(t, extra...)...)
	return testutil.AddFixture(t, srv), url
}

// eccClientOpts returns the client options for a fully validated connection to
// the ECC endpoint ep, with the client application certificate on the given
// curve.
func eccClientOpts(t *testing.T, ep *ua.EndpointDescription, curve string, auth ua.UserTokenType) []opcua.Option {
	t.Helper()
	ecc := pki(t).ecc
	return []opcua.Option{
		opcua.SecurityFromEndpoint(ep, auth),
		opcua.Certificate(ecc.client[curve].cert),
		opcua.PrivateKeySigner(ecc.client[curve].key),
		opcua.TrustedCertificates(ecc.server[curveP256].x509, ecc.server[curveP384].x509, ecc.server[curveEd25519].x509),
	}
}
