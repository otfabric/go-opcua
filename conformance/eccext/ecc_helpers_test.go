// SPDX-License-Identifier: MIT

package eccext

import (
	"crypto"
	"crypto/x509"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
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
