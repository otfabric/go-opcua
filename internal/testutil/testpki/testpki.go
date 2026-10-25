// SPDX-License-Identifier: MIT

// Package testpki is a small in-memory PKI shared by the test suites of this
// module: self-signed RSA, ECDSA (P-256, P-384) and Ed25519 application
// instance certificates for a server and a client, ECDSA on the Brainpool
// curves and Ed448 for the policies crypto/x509 has no keys for, user identity
// certificates, certificates nobody trusts and a CA with an issued leaf per
// key family.
//
// Key generation is expensive (RSA under the race detector in particular), so
// the PKI is built once per test binary.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"

	"github.com/otfabric/go-opcua/uapolicy"
)

// Application URIs of the application instance certificates.
const (
	ServerAppURI = "urn:otfabric:conformance:server"
	ClientAppURI = "urn:otfabric:conformance:client"
)

// Curve names, the keys of the ECC certificate maps.
const (
	CurveP256    = "P-256"
	CurveP384    = "P-384"
	CurveEd25519 = "Ed25519"

	CurveBrainpoolP256r1 = "brainpoolP256r1"
	CurveBrainpoolP384r1 = "brainpoolP384r1"
	CurveEd448           = "Ed448"
)

// Curves lists every curve of the ECC certificate maps.
var Curves = []string{CurveP256, CurveP384, CurveEd25519, CurveBrainpoolP256r1, CurveBrainpoolP384r1, CurveEd448}

// Identity is an ECC certificate with its private key: an ECDSA key or, for
// the curves Ed25519 and Ed448, an EdDSA key.
type Identity struct {
	Cert []byte
	Key  crypto.Signer
	X509 *x509.Certificate
}

// ECC is the ECC half of the PKI: application instance and user certificates
// on the curves of the ECC security policies.
type ECC struct {
	// Self-signed application instance certificates, by curve.
	Server map[string]*Identity
	Client map[string]*Identity

	// User is a self-signed X.509 user identity certificate, Stranger a
	// certificate nobody trusts (both P-256).
	User     *Identity
	Stranger *Identity

	// EdUser is an Ed25519 X.509 user identity certificate.
	EdUser *Identity

	// Users are X.509 user identity certificates by curve, for the curves of
	// Curves.
	Users map[string]*Identity

	// Per curve of Curves: a CA on that curve and a client certificate
	// issued by it (on the same curve), for trust lists.
	CAs        map[string]*Identity
	IssuedByCA map[string]*Identity

	// A P-256 CA and a client certificate issued by it, for trust lists.
	CACert []byte
	Issued *Identity
}

// PKI holds the RSA certificates and, in ECC, the ECC ones.
type PKI struct {
	// Self-signed application instance certificates.
	ServerCert []byte
	ServerKey  *rsa.PrivateKey
	ClientCert []byte
	ClientKey  *rsa.PrivateKey

	// A CA plus a client certificate issued by it, for trust-list tests.
	CACert         []byte
	CAKey          *rsa.PrivateKey
	IssuedCert     []byte
	IssuedKey      *rsa.PrivateKey
	UserCert       []byte // self-signed X.509 user identity certificate
	UserKey        *rsa.PrivateKey
	StrangerCert   []byte // a second self-signed cert nobody trusts
	StrangerKey    *rsa.PrivateKey
	ServerCertX509 *x509.Certificate

	// ECC holds the certificates for the ECC security policies.
	ECC *ECC
}

var (
	once   sync.Once
	pkiVal *PKI
	pkiErr error
)

// Get returns the PKI of this test binary, building it on first use.
func Get() (*PKI, error) {
	once.Do(func() { pkiVal, pkiErr = build() })
	return pkiVal, pkiErr
}

func build() (*PKI, error) {
	p := &PKI{}
	var err error
	if p.ServerCert, p.ServerKey, err = SelfSigned("conformance server", ServerAppURI); err != nil {
		return nil, err
	}
	if p.ClientCert, p.ClientKey, err = SelfSigned("conformance client", ClientAppURI); err != nil {
		return nil, err
	}
	if p.UserCert, p.UserKey, err = SelfSigned("conformance user", "urn:otfabric:conformance:user"); err != nil {
		return nil, err
	}
	if p.StrangerCert, p.StrangerKey, err = SelfSigned("conformance stranger", "urn:otfabric:conformance:stranger"); err != nil {
		return nil, err
	}
	if p.ServerCertX509, err = x509.ParseCertificate(p.ServerCert); err != nil {
		return nil, err
	}
	if p.ECC, err = buildECC(); err != nil {
		return nil, err
	}

	// CA and a leaf issued by it.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	caTmpl := CertTemplate("conformance CA", "")
	caTmpl.IsCA = true
	caTmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if p.CACert, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey); err != nil {
		return nil, err
	}
	caX509, err := x509.ParseCertificate(p.CACert)
	if err != nil {
		return nil, err
	}
	p.CAKey = caKey
	if p.IssuedKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, err
	}
	leaf := CertTemplate("conformance issued client", ClientAppURI)
	if p.IssuedCert, err = x509.CreateCertificate(rand.Reader, leaf, caX509, &p.IssuedKey.PublicKey, caKey); err != nil {
		return nil, err
	}
	return p, nil
}

// CertTemplate returns the template of an application instance certificate
// for localhost with the given common name and, unless empty, application
// URI.
func CertTemplate(cn, appURI string) *x509.Certificate {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"otfabric conformance"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	if appURI != "" {
		if u, err := url.Parse(appURI); err == nil {
			tmpl.URIs = []*url.URL{u}
		}
	}
	return tmpl
}

// SelfSigned creates a self-signed RSA-2048 certificate.
func SelfSigned(cn, appURI string) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := CertTemplate(cn, appURI)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

func eccCurve(name string) elliptic.Curve {
	switch name {
	case CurveP384:
		return elliptic.P384()
	case CurveBrainpoolP256r1:
		return brainpool.P256r1()
	case CurveBrainpoolP384r1:
		return brainpool.P384r1()
	}
	return elliptic.P256()
}

// NewKey creates a new key on the curve: an ECDSA key on a NIST or Brainpool
// curve, an Ed25519 or an Ed448 key.
func NewKey(curve string) (crypto.Signer, error) {
	switch curve {
	case CurveEd25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	case CurveEd448:
		_, key, err := ed448.GenerateKey(rand.Reader)
		return key, err
	}
	return ecdsa.GenerateKey(eccCurve(curve), rand.Reader)
}

// NewIdentity creates a certificate for a new key on the curve (see NewKey).
// A nil issuer makes it self-signed.
func NewIdentity(curve, cn, appURI string, issuer *x509.Certificate, issuerKey crypto.Signer) (*Identity, error) {
	key, err := NewKey(curve)
	if err != nil {
		return nil, err
	}
	tmpl := CertTemplate(cn, appURI)
	// An ECC key signs; it neither enciphers keys nor data.
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	return issue(tmpl, key, issuer, issuerKey)
}

// NewCA creates a self-signed CA certificate for a new key on the curve.
func NewCA(curve, cn string) (*Identity, error) {
	key, err := NewKey(curve)
	if err != nil {
		return nil, err
	}
	tmpl := CertTemplate(cn, "")
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return issue(tmpl, key, nil, nil)
}

func issue(tmpl *x509.Certificate, key crypto.Signer, issuer *x509.Certificate, issuerKey crypto.Signer) (*Identity, error) {
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer, issuerKey
	}
	// uapolicy.CreateCertificate is x509.CreateCertificate with Brainpool and
	// Ed448 keys in addition.
	der, err := uapolicy.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		return nil, err
	}
	parsed, err := uapolicy.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Identity{Cert: der, Key: key, X509: parsed}, nil
}

// IssueFromCSR issues an application instance certificate for a PKCS #10
// certificate signing request (DER): its subject, alternative names and key,
// signed by issuer, valid from an hour ago for a day.
func IssueFromCSR(csrDER []byte, issuer *x509.Certificate, issuerKey crypto.Signer) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	tmpl := CertTemplate(csr.Subject.CommonName, "")
	tmpl.Subject = csr.Subject
	tmpl.DNSNames, tmpl.IPAddresses, tmpl.URIs = csr.DNSNames, csr.IPAddresses, csr.URIs
	if _, ok := csr.PublicKey.(*rsa.PublicKey); !ok {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	}
	return uapolicy.CreateCertificate(rand.Reader, tmpl, issuer, csr.PublicKey, issuerKey)
}

func buildECC() (*ECC, error) {
	p := &ECC{
		Server:     map[string]*Identity{},
		Client:     map[string]*Identity{},
		Users:      map[string]*Identity{},
		CAs:        map[string]*Identity{},
		IssuedByCA: map[string]*Identity{},
	}
	var err error
	for _, curve := range Curves {
		if p.Server[curve], err = NewIdentity(curve, "conformance server "+curve, ServerAppURI, nil, nil); err != nil {
			return nil, err
		}
		if p.Client[curve], err = NewIdentity(curve, "conformance client "+curve, ClientAppURI, nil, nil); err != nil {
			return nil, err
		}
		if p.Users[curve], err = NewIdentity(curve, "conformance user "+curve, "urn:otfabric:conformance:user", nil, nil); err != nil {
			return nil, err
		}
		ca, err := NewCA(curve, "conformance CA "+curve)
		if err != nil {
			return nil, err
		}
		p.CAs[curve] = ca
		if p.IssuedByCA[curve], err = NewIdentity(curve, "conformance issued client "+curve, ClientAppURI, ca.X509, ca.Key); err != nil {
			return nil, err
		}
	}
	if p.User, err = NewIdentity(CurveP256, "conformance ecc user", "urn:otfabric:conformance:user", nil, nil); err != nil {
		return nil, err
	}
	if p.Stranger, err = NewIdentity(CurveP256, "conformance ecc stranger", "urn:otfabric:conformance:stranger", nil, nil); err != nil {
		return nil, err
	}
	if p.EdUser, err = NewIdentity(CurveEd25519, "conformance ed25519 user", "urn:otfabric:conformance:user", nil, nil); err != nil {
		return nil, err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := CertTemplate("conformance ECC CA", "")
	caTmpl.IsCA = true
	caTmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if p.CACert, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey); err != nil {
		return nil, err
	}
	caX509, err := x509.ParseCertificate(p.CACert)
	if err != nil {
		return nil, err
	}
	if p.Issued, err = NewIdentity(CurveP256, "conformance issued ecc client", ClientAppURI, caX509, caKey); err != nil {
		return nil, err
	}
	return p, nil
}
