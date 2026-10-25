// SPDX-License-Identifier: MIT

package gdsserver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the key identifier of RFC 5280 §4.2.1.2 method 1 is SHA-1
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/uapolicy"
)

// certType describes a certificate type of Part 12 §7.8.4 that the GDS
// issues.
type certType struct {
	id uint32
	// issuer is the Issuer.Name of the CA that signs it; "" for a type
	// whose CA follows the key (see issuerFor).
	issuer string
	// generate makes a new key of the type.
	generate func(rsaBits int) (crypto.Signer, error)
	// accepts reports whether a public key fits the type.
	accepts func(pub crypto.PublicKey) bool
}

func isCurve(pub crypto.PublicKey, c elliptic.Curve) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	return ok && k.Curve == c
}

func rsaBits(pub crypto.PublicKey, minBits, maxBits int) bool {
	k, ok := pub.(*rsa.PublicKey)
	return ok && k.N.BitLen() >= minBits && k.N.BitLen() <= maxBits
}

func genECDSA(c elliptic.Curve) func(int) (crypto.Signer, error) {
	return func(int) (crypto.Signer, error) { return ecdsa.GenerateKey(c, rand.Reader) }
}

func genRSA(bits int) (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, bits) }

// issuerFor returns the name of the CA that signs a certificate of the type
// for the public key pub.
func (t *certType) issuerFor(pub crypto.PublicKey) string {
	if t.issuer != "" {
		return t.issuer
	}
	switch {
	case isCurve(pub, elliptic.P256()):
		return "NistP256"
	case isCurve(pub, elliptic.P384()):
		return "NistP384"
	}
	return "RSA"
}

// httpsIssuers are the CAs that may sign the certificates of the
// HttpsCertificateType, by the key of the certificate.
var httpsIssuers = []string{"RSA", "NistP256", "NistP384"}

// certTypes are the certificate types the GDS can issue. Each application
// certificate type has a CA of its own key type; the HttpsCertificateType
// (the TLS certificates of the DefaultHttpsGroup, RSA or ECDSA on the NIST
// curves) is signed by the CA of its key.
var certTypes = map[uint32]*certType{
	id.RsaSha256ApplicationCertificateType: {
		id: id.RsaSha256ApplicationCertificateType, issuer: "RSA", generate: genRSA,
		accepts: func(pub crypto.PublicKey) bool { return rsaBits(pub, 2048, 4096) },
	},
	id.RsaMinApplicationCertificateType: {
		id: id.RsaMinApplicationCertificateType, issuer: "RSA",
		generate: func(int) (crypto.Signer, error) { return genRSA(2048) },
		accepts:  func(pub crypto.PublicKey) bool { return rsaBits(pub, 2048, 2048) },
	},
	id.EccNistP256ApplicationCertificateType: {
		id: id.EccNistP256ApplicationCertificateType, issuer: "NistP256", generate: genECDSA(elliptic.P256()),
		accepts: func(pub crypto.PublicKey) bool { return isCurve(pub, elliptic.P256()) },
	},
	id.EccNistP384ApplicationCertificateType: {
		id: id.EccNistP384ApplicationCertificateType, issuer: "NistP384", generate: genECDSA(elliptic.P384()),
		accepts: func(pub crypto.PublicKey) bool { return isCurve(pub, elliptic.P384()) },
	},
	id.EccBrainpoolP256r1ApplicationCertificateType: {
		id: id.EccBrainpoolP256r1ApplicationCertificateType, issuer: "BrainpoolP256r1", generate: genECDSA(brainpool.P256r1()),
		accepts: func(pub crypto.PublicKey) bool { return isCurve(pub, brainpool.P256r1()) },
	},
	id.EccBrainpoolP384r1ApplicationCertificateType: {
		id: id.EccBrainpoolP384r1ApplicationCertificateType, issuer: "BrainpoolP384r1", generate: genECDSA(brainpool.P384r1()),
		accepts: func(pub crypto.PublicKey) bool { return isCurve(pub, brainpool.P384r1()) },
	},
	id.EccCurve25519ApplicationCertificateType: {
		id: id.EccCurve25519ApplicationCertificateType, issuer: "Curve25519",
		generate: func(int) (crypto.Signer, error) {
			_, k, err := ed25519.GenerateKey(rand.Reader)
			return k, err
		},
		accepts: func(pub crypto.PublicKey) bool { _, ok := pub.(ed25519.PublicKey); return ok },
	},
	id.EccCurve448ApplicationCertificateType: {
		id: id.EccCurve448ApplicationCertificateType, issuer: "Curve448",
		generate: func(int) (crypto.Signer, error) {
			_, k, err := ed448.GenerateKey(rand.Reader)
			return k, err
		},
		accepts: func(pub crypto.PublicKey) bool { _, ok := pub.(ed448.PublicKey); return ok },
	},
	id.HTTPSCertificateType: {
		id: id.HTTPSCertificateType, generate: genRSA,
		accepts: func(pub crypto.PublicKey) bool {
			return rsaBits(pub, 2048, 4096) || isCurve(pub, elliptic.P256()) || isCurve(pub, elliptic.P384())
		},
	},
}

// newIssuerKey makes the key of a new CA.
func newIssuerKey(name string, rsaBits int) (crypto.Signer, error) {
	switch name {
	case "RSA":
		return genRSA(rsaBits)
	case "NistP256":
		return genECDSA(elliptic.P256())(0)
	case "NistP384":
		return genECDSA(elliptic.P384())(0)
	case "BrainpoolP256r1":
		return genECDSA(brainpool.P256r1())(0)
	case "BrainpoolP384r1":
		return genECDSA(brainpool.P384r1())(0)
	case "Curve25519":
		return certTypes[id.EccCurve25519ApplicationCertificateType].generate(0)
	case "Curve448":
		return certTypes[id.EccCurve448ApplicationCertificateType].generate(0)
	}
	return nil, fmt.Errorf("gdsserver: unknown issuer %q", name)
}

// ca is a certificate authority with what signing needs of it.
type ca struct {
	rec     *Issuer
	cert    *x509.Certificate
	key     crypto.Signer
	revoked map[string]bool // the serial numbers (hex) it revoked
	crl     *x509.RevocationList
}

// keyID returns the key identifier of RFC 5280 §4.2.1.2 method 1: the SHA-1
// of the subjectPublicKey bits.
func keyID(pub crypto.PublicKey) []byte {
	var bits []byte
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits = x509.MarshalPKCS1PublicKey(k)
	case *ecdsa.PublicKey:
		n := (k.Curve.Params().BitSize + 7) / 8
		bits = append([]byte{4}, k.X.FillBytes(make([]byte, n))...) //nolint:staticcheck // SA1019: Brainpool keys have no crypto/ecdh form
		bits = append(bits, k.Y.FillBytes(make([]byte, n))...)      //nolint:staticcheck // SA1019: see above
	case ed25519.PublicKey:
		bits = k
	case ed448.PublicKey:
		bits = k
	}
	sum := sha1.Sum(bits) //nolint:gosec // see the import
	return sum[:]
}

func randomSerial() (*big.Int, error) {
	// 159 bits: positive and at most 20 octets (RFC 5280 §4.1.2.2).
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
}

// newCA creates a self-signed CA.
func newCA(name, commonName string, now time.Time, lifetime time.Duration, rsaBits int) (*Issuer, error) {
	key, err := newIssuerKey(name, rsaBits)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyID(key.Public()),
	}
	der, err := uapolicy.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	pk, err := uapolicy.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Issuer{Name: name, Certificate: der, PrivateKey: pk}, nil
}

// loadCA checks an Issuer and prepares it for signing.
func loadCA(rec *Issuer) (*ca, error) {
	cert, err := uapolicy.ParseCertificate(rec.Certificate)
	if err != nil {
		return nil, fmt.Errorf("gdsserver: issuer %s: %w", rec.Name, err)
	}
	key, err := uapolicy.ParsePrivateKey(rec.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("gdsserver: issuer %s: %w", rec.Name, err)
	}
	if !uapolicy.KeyMatchesCertificate(key, rec.Certificate) {
		return nil, fmt.Errorf("gdsserver: issuer %s: the key does not belong to the certificate", rec.Name)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&x509.KeyUsageCRLSign == 0 || len(cert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("gdsserver: issuer %s: not a CA certificate with keyCertSign, cRLSign and a subject key identifier", rec.Name)
	}
	c := &ca{rec: rec, cert: cert, key: key, revoked: map[string]bool{}}
	for _, r := range rec.Revoked {
		c.revoked[serialKey(new(big.Int).SetBytes(r.SerialNumber))] = true
	}
	if len(rec.CRL) > 0 {
		if crl, err := uapolicy.ParseRevocationList(rec.CRL); err == nil {
			c.crl = crl
		}
	}
	return c, nil
}

func serialKey(n *big.Int) string { return n.Text(16) }

// issues reports whether the CA signed cert: the issuer name matches and
// the signature checks. The validity period is not checked.
func (c *ca) issues(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, c.cert.RawSubject) {
		return false
	}
	if pub, ok := c.cert.PublicKey.(ed448.PublicKey); ok {
		return ed448.Verify(pub, cert.RawTBSCertificate, cert.Signature, "")
	}
	return cert.CheckSignatureFrom(c.cert) == nil
}

// isRevoked reports whether the CA revoked the certificate.
func (c *ca) isRevoked(cert *x509.Certificate) bool {
	return cert.SerialNumber != nil && c.revoked[serialKey(cert.SerialNumber)]
}

// leaf describes a certificate to issue.
type leaf struct {
	pub       crypto.PublicKey
	subject   pkix.Name
	uri       string
	dns       []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
}

// issue signs an application instance certificate (Part 6 §6.2.2).
func (c *ca) issue(l *leaf) ([]byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	var uris []*url.URL
	if l.uri != "" {
		u, err := url.Parse(l.uri)
		if err != nil {
			return nil, err
		}
		uris = []*url.URL{u}
	}
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	if _, ok := l.pub.(*rsa.PublicKey); ok {
		usage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	}
	notAfter := l.notAfter
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               l.subject,
		NotBefore:             l.notBefore,
		NotAfter:              notAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  uris,
		DNSNames:              l.dns,
		IPAddresses:           l.ips,
		SubjectKeyId:          keyID(l.pub),
		AuthorityKeyId:        c.cert.SubjectKeyId,
	}
	return uapolicy.CreateCertificate(rand.Reader, tmpl, c.cert, l.pub, c.key)
}

// makeCRL signs a new CRL of the revoked certificates.
func (c *ca) makeCRL(now time.Time, validity time.Duration) error {
	tmpl := &x509.RevocationList{
		Number:     new(big.Int).SetUint64(c.rec.CRLNumber + 1),
		ThisUpdate: now,
		NextUpdate: now.Add(validity),
	}
	for _, r := range c.rec.Revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   new(big.Int).SetBytes(r.SerialNumber),
			RevocationTime: r.RevokedAt,
		})
	}
	der, err := uapolicy.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		return err
	}
	crl, err := uapolicy.ParseRevocationList(der)
	if err != nil {
		return err
	}
	c.rec.CRL = der
	c.rec.CRLNumber++
	c.crl = crl
	return nil
}

// parseSubjectName parses a SubjectName of Part 12 §7.9.4: X.500 name
// value pairs separated by '/' or ',' ("CN=App/O=Company/DC=host"). It
// knows CN, O, OU, C, ST, L, STREET and DC.
func parseSubjectName(s string) (pkix.Name, error) {
	var name pkix.Name
	sep := ","
	if strings.HasPrefix(strings.TrimSpace(s), "/") || (strings.Contains(s, "/") && !strings.Contains(s, ",")) {
		sep = "/"
	}
	n := 0
	for _, part := range strings.Split(s, sep) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k, v = strings.ToUpper(strings.TrimSpace(k)), strings.Trim(strings.TrimSpace(v), `"`)
		if !ok || v == "" {
			return name, fmt.Errorf("gdsserver: invalid subject name element %q", part)
		}
		switch k {
		case "CN":
			name.CommonName = v
		case "O":
			name.Organization = append(name.Organization, v)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, v)
		case "C":
			name.Country = append(name.Country, v)
		case "ST", "S":
			name.Province = append(name.Province, v)
		case "L":
			name.Locality = append(name.Locality, v)
		case "STREET":
			name.StreetAddress = append(name.StreetAddress, v)
		case "DC":
			name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: oidDomainComponent, Value: v})
		default:
			return name, fmt.Errorf("gdsserver: unknown subject name attribute %q", k)
		}
		n++
	}
	if n == 0 {
		return name, errors.New("gdsserver: empty subject name")
	}
	return name, nil
}

var oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}

// hostsOf returns the host names and IP addresses of URLs, each once.
func hostsOf(urls []string) (dns []string, ips []net.IP) {
	seen := map[string]bool{}
	for _, s := range urls {
		u, err := url.Parse(strings.TrimPrefix(s, "rcp+"))
		if err != nil {
			continue
		}
		h := u.Hostname()
		if h == "" || seen[strings.ToLower(h)] {
			continue
		}
		seen[strings.ToLower(h)] = true
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, h)
		}
	}
	return dns, ips
}
