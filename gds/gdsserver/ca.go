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
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/uapolicy"
)

// certType describes a certificate type of Part 12 §7.8.4 that the GDS
// issues.
type certType struct {
	id     uint32
	issuer string // the Issuer.Name of the CA that signs it
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

// certTypes are the certificate types the GDS can issue. The Brainpool
// types are issued by the NIST CA with the same hash (ecdsa-with-SHA256,
// ecdsa-with-SHA384, the CertificateSignatureAlgorithm of their security
// policies): crypto/x509 cannot check the signature of a CRL a Brainpool CA
// signed, so its revocations would not be enforced by the servers of this
// module.
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
		id: id.EccBrainpoolP256r1ApplicationCertificateType, issuer: "NistP256", generate: genECDSA(brainpool.P256r1()),
		accepts: func(pub crypto.PublicKey) bool { return isCurve(pub, brainpool.P256r1()) },
	},
	id.EccBrainpoolP384r1ApplicationCertificateType: {
		id: id.EccBrainpoolP384r1ApplicationCertificateType, issuer: "NistP384", generate: genECDSA(brainpool.P384r1()),
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
		if crl, err := x509.ParseRevocationList(rec.CRL); err == nil {
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
	u, err := url.Parse(l.uri)
	if err != nil {
		return nil, err
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
		URIs:                  []*url.URL{u},
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
	der, err := signCRL(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		return err
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return err
	}
	c.rec.CRL = der
	c.rec.CRLNumber++
	c.crl = crl
	return nil
}

var oidSignatureEd448 = asn1.ObjectIdentifier{1, 3, 101, 113}

// signCRL creates a CRL like x509.CreateRevocationList, also for an Ed448
// issuer, which crypto/x509 cannot sign with: the CRL is built with a
// throwaway Ed25519 key, and the TBSCertList is signed again with Ed448
// after its signature algorithm was replaced.
func signCRL(rnd io.Reader, tmpl *x509.RevocationList, issuer *x509.Certificate, key crypto.Signer) ([]byte, error) {
	if _, ok := key.(ed448.PrivateKey); !ok {
		return x509.CreateRevocationList(rnd, tmpl, issuer, key)
	}
	_, placeholder, err := ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	iss := *issuer
	iss.PublicKey = placeholder.Public()
	der, err := x509.CreateRevocationList(rnd, tmpl, &iss, placeholder)
	if err != nil {
		return nil, err
	}
	in := cryptobyte.String(der)
	var list, tbs cryptobyte.String
	if !in.ReadASN1(&list, cbasn1.SEQUENCE) || !list.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, errors.New("gdsserver: malformed CRL")
	}
	var version, alg cryptobyte.String
	hasVersion := tbs.PeekASN1Tag(cbasn1.INTEGER)
	if hasVersion && !tbs.ReadASN1Element(&version, cbasn1.INTEGER) {
		return nil, errors.New("gdsserver: malformed CRL version")
	}
	if !tbs.ReadASN1Element(&alg, cbasn1.SEQUENCE) {
		return nil, errors.New("gdsserver: malformed CRL signature algorithm")
	}
	algID := func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidSignatureEd448) })
	}
	var tb cryptobyte.Builder
	tb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(version)
		algID(b)
		b.AddBytes(tbs)
	})
	newTBS, err := tb.Bytes()
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(rnd, newTBS, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	var out cryptobyte.Builder
	out.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(newTBS)
		algID(b)
		b.AddASN1BitString(sig)
	})
	return out.Bytes()
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
