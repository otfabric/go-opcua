// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/sign/ed448"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// minCSRNonce is the least entropy a client gives CreateSigningRequest
// when the key is regenerated (Part 12 §7.10.7).
const minCSRNonce = 32

// The certificate types of application instance certificates (Part 12
// §7.8.4), the most specific first: certTypeOf picks the first that fits.
var certTypePolicies = []struct {
	certType uint32
	policy   string
}{
	{id.EccNistP384ApplicationCertificateType, ua.SecurityPolicyURIECCNistP384},
	{id.EccNistP256ApplicationCertificateType, ua.SecurityPolicyURIECCNistP256},
	{id.EccBrainpoolP384r1ApplicationCertificateType, ua.SecurityPolicyURIECCBrainpoolP384r1},
	{id.EccBrainpoolP256r1ApplicationCertificateType, ua.SecurityPolicyURIECCBrainpoolP256r1},
	{id.EccCurve25519ApplicationCertificateType, ua.SecurityPolicyURIECCCurve25519},
	{id.EccCurve448ApplicationCertificateType, ua.SecurityPolicyURIECCCurve448},
}

// certTypeOf returns the certificate type of an application instance
// certificate: RsaSha256ApplicationCertificateType for an RSA key of at
// least 2048 bits (RsaMinApplicationCertificateType below), else the ECC
// type of its curve.
func certTypeOf(cert []byte) (uint32, bool) {
	pub, err := uapolicy.CertificatePublicKey(cert)
	if err != nil {
		return 0, false
	}
	if k, ok := pub.(*rsa.PublicKey); ok {
		if k.N.BitLen() < 2048 {
			return id.RsaMinApplicationCertificateType, true
		}
		return id.RsaSha256ApplicationCertificateType, true
	}
	for _, t := range certTypePolicies {
		if uapolicy.CheckPublicKey(t.policy, pub) == nil {
			return t.certType, true
		}
	}
	return 0, false
}

func isRSAType(t uint32) bool {
	return t == id.RsaMinApplicationCertificateType || t == id.RsaSha256ApplicationCertificateType
}

// typeMatches reports whether a certificate of type have serves the
// requested certificate type: the type itself, an abstract supertype, or
// the other RSA type.
func typeMatches(want, have uint32) bool {
	switch {
	case want == have, want == 0, want == id.ApplicationCertificateType, want == id.CertificateType:
		return true
	case isRSAType(want):
		return isRSAType(have)
	case want == id.EccApplicationCertificateType:
		return !isRSAType(have)
	}
	return false
}

// httpsTypeMatches reports whether a certificate type requested for the
// DefaultHttpsGroup is the one of its certificate (HttpsCertificateType)
// or a supertype of it.
func httpsTypeMatches(want uint32) bool {
	switch want {
	case 0, id.CertificateType, id.HTTPSCertificateType, id.TLSCertificateType, id.TLSServerCertificateType:
		return true
	}
	return false
}

// certificateTypes returns the CertificateTypes of the
// DefaultApplicationGroup: the types of the server's certificates.
func (s *serverConfig) certificateTypes() []*ua.NodeID {
	var out []*ua.NodeID
	for _, x := range s.identityCerts() {
		if t, ok := certTypeOf(x.certificate); ok && !slices.ContainsFunc(out, func(n *ua.NodeID) bool { return n.IntID() == t }) {
			out = append(out, ua.NewNumericNodeID(0, t))
		}
	}
	return out
}

// groupTypes returns the CertificateTypes of a group.
func (m *pushManager) groupTypes(g *certGroup) []*ua.NodeID {
	switch g.kind {
	case groupApplication:
		return m.s.cfg.certificateTypes()
	case groupHTTPS:
		return []*ua.NodeID{ua.NewNumericNodeID(0, id.HTTPSCertificateType)}
	case groupUserToken, numGroups:
	}
	return []*ua.NodeID{}
}

// groupCerts returns the certificates of a group with their types.
func (m *pushManager) groupCerts(g *certGroup) ([]uint32, []applicationIdentity) {
	var types []uint32
	var out []applicationIdentity
	switch g.kind {
	case groupApplication:
		for _, x := range m.s.cfg.identityCerts() {
			if t, ok := certTypeOf(x.certificate); ok {
				types = append(types, t)
				out = append(out, x)
			}
		}
	case groupHTTPS:
		if x := m.https.Load(); x != nil {
			types = append(types, id.HTTPSCertificateType)
			out = append(out, applicationIdentity{certificate: x.cert, key: x.key})
		}
	case groupUserToken, numGroups:
	}
	return types, out
}

// certOfType returns the certificate of the group and type arguments with
// its concrete type: argument i is the CertificateGroupId (null is the
// DefaultApplicationGroup) and i+1 the CertificateTypeId. The certificate
// of a DefaultHttpsGroup without one is empty.
func (m *pushManager) certOfType(args []*ua.Variant, i int) (*certGroup, applicationIdentity, uint32, ua.StatusCode) {
	gid, ok1 := argValue[*ua.NodeID](args, i)
	typ, ok2 := argValue[*ua.NodeID](args, i+1)
	if !ok1 || !ok2 {
		return nil, applicationIdentity{}, 0, ua.StatusBadTypeMismatch
	}
	g, ok := m.group(gid)
	if !ok {
		return nil, applicationIdentity{}, 0, ua.StatusBadInvalidArgument
	}
	var want uint32
	if !isNullNodeID(typ) {
		if typ.Namespace() != 0 || !isNumericNodeID(typ) {
			return nil, applicationIdentity{}, 0, ua.StatusBadInvalidArgument
		}
		want = typ.IntID()
	}
	switch g.kind {
	case groupApplication:
		for _, x := range m.s.cfg.identityCerts() {
			if t, ok := certTypeOf(x.certificate); ok && typeMatches(want, t) {
				return g, x, t, ua.StatusOK
			}
		}
	case groupHTTPS:
		if httpsTypeMatches(want) {
			var cur applicationIdentity
			if x := m.https.Load(); x != nil {
				cur = applicationIdentity{certificate: x.cert, key: x.key}
			}
			return g, cur, id.HTTPSCertificateType, ua.StatusOK
		}
	case groupUserToken, numGroups:
		// The DefaultUserTokenGroup has a trust list only.
	}
	return nil, applicationIdentity{}, 0, ua.StatusBadInvalidArgument
}

func isNumericNodeID(n *ua.NodeID) bool {
	switch n.Type() {
	case ua.NodeIDTypeTwoByte, ua.NodeIDTypeFourByte, ua.NodeIDTypeNumeric:
		return true
	case ua.NodeIDTypeString, ua.NodeIDTypeGUID, ua.NodeIDTypeByteString:
		return false
	}
	return false
}

func isNullNodeID(n *ua.NodeID) bool {
	return n == nil || isNumericNodeID(n) && n.Namespace() == 0 && n.IntID() == 0
}

// checkNewCert checks a certificate for a group: its type, the key the
// group can use, the ApplicationUri of an application instance
// certificate and the validity period.
func (m *pushManager) checkNewCert(g *certGroup, certType uint32, der []byte) (*x509.Certificate, ua.StatusCode) {
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil || !bytes.Equal(cert.Raw, der) {
		return nil, ua.StatusBadCertificateInvalid
	}
	if g.kind == groupHTTPS {
		if !tlsKeySupported(cert.PublicKey) {
			return nil, ua.StatusBadCertificateInvalid
		}
	} else {
		if t, ok := certTypeOf(der); !ok || !typeMatches(certType, t) {
			return nil, ua.StatusBadCertificateInvalid
		}
		if uri := m.s.cfg.applicationURI; uri != "" && (len(cert.URIs) == 0 || cert.URIs[0].String() != uri) {
			return nil, ua.StatusBadCertificateURIInvalid
		}
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, ua.StatusBadCertificateTimeInvalid
	}
	return cert, ua.StatusOK
}

// updateCertificate is UpdateCertificate (Part 12 §7.10.4): a new
// certificate of a group, with its issuers and, if the server did not make
// the key, its private key (PEM or PFX). It replaces the certificate of the
// type for new channels or TLS connections when the changes are applied.
func (m *pushManager) updateCertificate(ctx context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	g, cur, certType, sc := m.certOfType(args, 0)
	if sc != ua.StatusOK {
		return nil, sc
	}
	der, ok1 := argValue[[]byte](args, 2)
	var issuers [][]byte
	ok2 := true
	if len(args) > 3 && args[3] != nil && args[3].Value() != nil {
		issuers, ok2 = args[3].Value().([][]byte)
	}
	format, ok3 := argValue[string](args, 4)
	var keyData []byte
	if len(args) > 5 && args[5] != nil && args[5].Value() != nil {
		keyData, ok3 = args[5].Value().([]byte)
	}
	if !ok1 || !ok2 || !ok3 {
		return nil, ua.StatusBadTypeMismatch
	}
	cert, sc := m.checkNewCert(g, certType, der)
	if sc != ua.StatusOK {
		return nil, sc
	}
	var parsedIssuers []*x509.Certificate
	for _, b := range issuers {
		ic, err := uapolicy.ParseCertificate(b)
		if err != nil || !bytes.Equal(ic.Raw, b) {
			return nil, ua.StatusBadCertificateInvalid
		}
		parsedIssuers = append(parsedIssuers, ic)
	}
	if !issuedByOneOf(cert, parsedIssuers) {
		return nil, ua.StatusBadSecurityChecksFailed
	}

	key := certKey{g.kind, certType}
	var priv crypto.Signer
	switch strings.ToUpper(format) {
	case "":
		if len(keyData) > 0 {
			return nil, ua.StatusBadInvalidArgument
		}
	case "PEM":
		k, err := uapolicy.ParsePrivateKey(keyData)
		if err != nil {
			return nil, ua.StatusBadSecurityChecksFailed
		}
		priv = k
	case "PFX":
		var password string
		if f := m.cfg.PFXPassword; f != nil {
			p, err := f(ctx, g.nodeID(), ua.NewNumericNodeID(0, certType))
			if err != nil {
				m.logger().Warn("push management: no PFX password", "error", err)
				return nil, ua.StatusBadSecurityChecksFailed
			}
			password = p
		}
		k, _, err := uapolicy.ParsePFX(keyData, password)
		if err != nil {
			m.logger().Info("push management: PFX private key rejected", "error", err)
			return nil, ua.StatusBadSecurityChecksFailed
		}
		priv = k
	default:
		return nil, ua.StatusBadNotSupported
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if priv == nil {
		// The key of the last CreateSigningRequest that regenerated it, or
		// the key the server has.
		for _, k := range []crypto.Signer{m.csrKeys[key], cur.key} {
			if k != nil && uapolicy.KeyMatchesCertificate(k, der) {
				priv = k
				break
			}
		}
	}
	if priv == nil || !uapolicy.KeyMatchesCertificate(priv, der) {
		return nil, ua.StatusBadSecurityChecksFailed
	}
	if _, isRSA := priv.(*rsa.PrivateKey); isRSAType(certType) && !isRSA {
		return nil, ua.StatusBadSecurityChecksFailed
	}
	required, sc := m.addCertLocked(ctx, c.SessionID, g, &pendingCert{key: key, old: cur.certificate, cert: slices.Clone(der), issuers: issuers, priv: priv})
	if sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(required)}, ua.StatusOK
}

// issuedByOneOf reports whether cert is self-signed or signed by one of the
// issuers. Without issuers any certificate passes: its CA may be known to
// the clients only.
func issuedByOneOf(cert *x509.Certificate, issuers []*x509.Certificate) bool {
	if len(issuers) == 0 || bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return true
	}
	for _, ic := range issuers {
		if !bytes.Equal(ic.RawSubject, cert.RawIssuer) {
			continue
		}
		// A signature crypto/x509 cannot check (Ed448) is not held against
		// the certificate.
		err := cert.CheckSignatureFrom(ic)
		if err == nil || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
			return true
		}
	}
	return false
}

// createSigningRequest is CreateSigningRequest (Part 12 §7.10.7): a PKCS #10
// certificate request for the certificate of the group and type, with the
// key the server has or a new one (RegeneratePrivateKey), which
// UpdateCertificate then takes with the certificate issued for it. RSA,
// ECDSA (NIST and Brainpool), Ed25519 and Ed448 keys are supported.
func (m *pushManager) createSigningRequest(_ context.Context, _ *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	g, cur, certType, sc := m.certOfType(args, 0)
	if sc != ua.StatusOK {
		return nil, sc
	}
	subject, ok1 := argValue[string](args, 2)
	regenerate, ok2 := argValue[bool](args, 3)
	var nonce []byte
	ok3 := true
	if len(args) > 4 && args[4] != nil && args[4].Value() != nil {
		nonce, ok3 = args[4].Value().([]byte)
	}
	if !ok1 || !ok2 || !ok3 {
		return nil, ua.StatusBadTypeMismatch
	}
	tmpl := &x509.CertificateRequest{}
	if cur.certificate != nil {
		curCert, err := uapolicy.ParseCertificate(cur.certificate)
		if err != nil {
			return nil, ua.StatusBadInternalError
		}
		tmpl.Subject, tmpl.DNSNames, tmpl.IPAddresses, tmpl.URIs = curCert.Subject, curCert.DNSNames, curCert.IPAddresses, curCert.URIs
	} else if subject == "" || !regenerate {
		// A DefaultHttpsGroup without a certificate has neither a subject
		// nor a key to sign the request with.
		return nil, ua.StatusBadInvalidArgument
	}
	if subject != "" {
		name, err := parseSubjectName(subject)
		if err != nil {
			return nil, ua.StatusBadInvalidArgument
		}
		tmpl.Subject = name
	}
	key := cur.key
	if regenerate {
		if len(nonce) < minCSRNonce {
			return nil, ua.StatusBadInvalidArgument
		}
		var err error
		if key, err = generateKey(g.kind, certType, cur.key, 0); err != nil {
			return nil, ua.StatusBadNotSupported
		}
	}
	csr, err := uapolicy.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		m.logger().Warn("push management: creating the signing request failed", "error", err)
		return nil, ua.StatusBadInternalError
	}
	if regenerate {
		m.mu.Lock()
		m.csrKeys[certKey{g.kind, certType}] = key
		m.mu.Unlock()
	}
	return []*ua.Variant{ua.MustVariant(csr)}, ua.StatusOK
}

// keyBits is the size of the key of a certificate type for
// CreateSelfSignedCertificate's KeySizeInBits.
var keyBits = map[uint32][]int{
	id.EccNistP256ApplicationCertificateType:        {256},
	id.EccNistP384ApplicationCertificateType:        {384},
	id.EccBrainpoolP256r1ApplicationCertificateType: {256},
	id.EccBrainpoolP384r1ApplicationCertificateType: {384},
	id.EccCurve25519ApplicationCertificateType:      {255, 256},
	id.EccCurve448ApplicationCertificateType:        {448, 456},
}

var errKeySize = errors.New("server: key size not supported")

// generateKey returns a new key for a certificate of the group and type:
// the curve of an ECC type, RSA of bits (0: the size of the current key,
// at least 2048), and for the DefaultHttpsGroup a key of the kind of the
// current one (RSA without one).
func generateKey(g groupKind, certType uint32, cur crypto.Signer, bits int) (crypto.Signer, error) {
	if g == groupHTTPS {
		switch k := cur.(type) {
		case *ecdsa.PrivateKey:
			if bits != 0 && bits != k.Curve.Params().BitSize {
				return nil, errKeySize
			}
			return ecdsa.GenerateKey(k.Curve, rand.Reader)
		case ed25519.PrivateKey:
			if bits != 0 && bits != 255 && bits != 256 {
				return nil, errKeySize
			}
			_, nk, err := ed25519.GenerateKey(rand.Reader)
			return nk, err
		}
		return generateRSA(cur, bits, false)
	}
	if isRSAType(certType) {
		return generateRSA(cur, bits, certType == id.RsaMinApplicationCertificateType)
	}
	if sizes := keyBits[certType]; bits != 0 && !slices.Contains(sizes, bits) {
		return nil, errKeySize
	}
	switch certType {
	case id.EccNistP256ApplicationCertificateType:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case id.EccNistP384ApplicationCertificateType:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case id.EccBrainpoolP256r1ApplicationCertificateType:
		return ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	case id.EccBrainpoolP384r1ApplicationCertificateType:
		return ecdsa.GenerateKey(brainpool.P384r1(), rand.Reader)
	case id.EccCurve25519ApplicationCertificateType:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case id.EccCurve448ApplicationCertificateType:
		_, k, err := ed448.GenerateKey(rand.Reader)
		return k, err
	}
	return nil, x509.ErrUnsupportedAlgorithm
}

// generateRSA returns a new RSA key of bits: 2048, 3072 or 4096 (2048 only
// for RsaMinApplicationCertificateType); 0 keeps the size of the current
// RSA key, at least 2048.
func generateRSA(cur crypto.Signer, bits int, minType bool) (*rsa.PrivateKey, error) {
	if bits == 0 {
		bits = 2048
		if k, ok := cur.(*rsa.PrivateKey); ok && !minType {
			bits = max(k.N.BitLen(), 2048)
		}
	}
	switch {
	case minType && bits != 2048:
		return nil, errKeySize
	case bits != 2048 && bits != 3072 && bits != 4096:
		return nil, errKeySize
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

var oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}

// parseSubjectName parses the SubjectName of CreateSigningRequest and
// CreateSelfSignedCertificate: X.500 name value pairs separated by '/'
// (Part 12 §7.10.7, CN=App/O=Company) or by ','.
func parseSubjectName(s string) (pkix.Name, error) {
	var n pkix.Name
	sep := ","
	if strings.Contains(s, "/") {
		sep = "/"
	}
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(s), "/"), sep)
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		k, v = strings.ToUpper(strings.TrimSpace(k)), strings.Trim(strings.TrimSpace(v), `"`)
		if !ok || k == "" || v == "" {
			return n, x509.ErrUnsupportedAlgorithm
		}
		switch k {
		case "CN":
			n.CommonName = v
		case "O":
			n.Organization = append(n.Organization, v)
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, v)
		case "L":
			n.Locality = append(n.Locality, v)
		case "S", "ST":
			n.Province = append(n.Province, v)
		case "C":
			n.Country = append(n.Country, v)
		case "STREET":
			n.StreetAddress = append(n.StreetAddress, v)
		case "DC":
			n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{Type: oidDomainComponent, Value: v})
		default:
			return n, x509.ErrUnsupportedAlgorithm
		}
	}
	return n, nil
}

// defaultCertLifetime is the lifetime of a self-signed certificate when
// LifetimeInDays is 0.
const defaultCertLifetime = 365

// createSelfSignedCertificate is CreateSelfSignedCertificate (Part 12
// §7.10.5): a new key and a self-signed certificate of the group and type,
// which replaces the current one when the changes are applied. It returns
// the certificate.
func (m *pushManager) createSelfSignedCertificate(ctx context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	g, cur, certType, sc := m.certOfType(args, 0)
	if sc != ua.StatusOK {
		return nil, sc
	}
	subject, ok1 := argValue[string](args, 2)
	dnsNames, ok2 := stringsArg(args, 3)
	ipNames, ok3 := stringsArg(args, 4)
	days, ok4 := argValue[uint16](args, 5)
	bits, ok5 := argValue[uint16](args, 6)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return nil, ua.StatusBadTypeMismatch
	}
	tmpl := &x509.Certificate{}
	if cur.certificate != nil {
		curCert, err := uapolicy.ParseCertificate(cur.certificate)
		if err != nil {
			return nil, ua.StatusBadInternalError
		}
		tmpl.Subject, tmpl.DNSNames, tmpl.IPAddresses = curCert.Subject, curCert.DNSNames, curCert.IPAddresses
	} else if subject == "" {
		return nil, ua.StatusBadInvalidArgument
	}
	if subject != "" {
		name, err := parseSubjectName(subject)
		if err != nil {
			return nil, ua.StatusBadInvalidArgument
		}
		tmpl.Subject = name
	}
	if len(dnsNames) > 0 || len(ipNames) > 0 {
		tmpl.DNSNames, tmpl.IPAddresses = nil, nil
		for _, d := range dnsNames {
			if d = strings.TrimSpace(d); d == "" || strings.ContainsAny(d, " /\\@") {
				return nil, ua.StatusBadInvalidArgument
			}
			tmpl.DNSNames = append(tmpl.DNSNames, d)
		}
		for _, s := range ipNames {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip == nil {
				return nil, ua.StatusBadInvalidArgument
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	if uri := m.s.cfg.applicationURI; uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, ua.StatusBadInternalError
		}
		tmpl.URIs = []*url.URL{u}
	}
	if days == 0 {
		days = defaultCertLifetime
	}
	key, err := generateKey(g.kind, certType, cur.key, int(bits))
	if err != nil {
		return nil, ua.StatusBadInvalidArgument
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, ua.StatusBadInternalError
	}
	now := time.Now()
	tmpl.SerialNumber = serial
	tmpl.NotBefore = now.Add(-5 * time.Minute)
	tmpl.NotAfter = now.Add(time.Duration(days) * 24 * time.Hour)
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign
	if _, ok := key.(*rsa.PrivateKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	der, err := uapolicy.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		m.logger().Warn("push management: creating the self-signed certificate failed", "error", err)
		return nil, ua.StatusBadInternalError
	}
	if _, sc := m.checkNewCert(g, certType, der); sc != ua.StatusOK {
		return nil, sc
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, sc := m.addCertLocked(ctx, c.SessionID, g, &pendingCert{key: certKey{g.kind, certType}, old: cur.certificate, cert: der, priv: key}); sc != ua.StatusOK {
		return nil, sc
	}
	return []*ua.Variant{ua.MustVariant(der)}, ua.StatusOK
}

// stringsArg returns a String array argument; null is an empty array.
func stringsArg(args []*ua.Variant, i int) ([]string, bool) {
	if i >= len(args) || args[i] == nil || args[i].Value() == nil {
		return nil, i < len(args)
	}
	v, ok := args[i].Value().([]string)
	return v, ok
}

// getCertificates is GetCertificates (Part 12 §7.10.8): the certificate
// types and the certificates of a group that are in use.
func (m *pushManager) getCertificates(_ context.Context, _ *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	gid, ok := argValue[*ua.NodeID](args, 0)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	g, ok := m.group(gid)
	if !ok {
		return nil, ua.StatusBadInvalidArgument
	}
	types, certs := m.groupCerts(g)
	tids := make([]*ua.NodeID, len(types))
	ders := make([][]byte, len(certs))
	for i := range types {
		tids[i] = ua.NewNumericNodeID(0, types[i])
		ders[i] = slices.Clone(certs[i].certificate)
	}
	return []*ua.Variant{ua.MustVariant(tids), ua.MustVariant(ders)}, ua.StatusOK
}

// getRejectedList is GetRejectedList (Part 12 §7.10.9).
func (m *pushManager) getRejectedList(_ context.Context, _ *MethodCaller, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	certs := m.rejectedList()
	if certs == nil {
		certs = [][]byte{}
	}
	return []*ua.Variant{ua.MustVariant(certs)}, ua.StatusOK
}

// applyChanges is ApplyChanges (Part 12 §7.10.6): applies the transaction
// of the session.
func (m *pushManager) applyChanges(ctx context.Context, c *MethodCaller, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tx == nil {
		return nil, ua.StatusOK
	}
	if _, sc := m.txLocked(c.SessionID); sc != ua.StatusOK {
		return nil, sc
	}
	return nil, m.applyLocked(ctx)
}

// cancelChanges is CancelChanges (Part 12 §7.10.10): drops the
// transaction of the session.
func (m *pushManager) cancelChanges(_ context.Context, c *MethodCaller, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tx == nil {
		return nil, ua.StatusOK
	}
	if m.otherTxLocked(c.SessionID) {
		return nil, ua.StatusBadTransactionPending
	}
	if m.tx != nil && m.tx.session.Equal(c.SessionID) {
		m.tx = nil
		m.endDiagnostics(ua.StatusBadRequestCancelledByClient)
	} else {
		m.tx = nil // of a closed session
		m.endDiagnostics(ua.StatusBadSessionClosed)
	}
	return nil, ua.StatusOK
}

// resetToServerDefaults is ResetToServerDefaults (Part 12 §7.10.13): the
// trust lists and certificates the server was configured with take effect
// again, for new channels and connections. Pending changes, keys of
// signing requests and open TrustList handles are dropped.
func (m *pushManager) resetToServerDefaults(ctx context.Context, c *MethodCaller, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.otherTxLocked(c.SessionID) {
		return nil, ua.StatusBadTransactionPending
	}
	initial := [numGroups]*ua.TrustListDataType{m.cfg.TrustList, m.cfg.HTTPSTrustList, m.cfg.UserTokenTrustList}
	trust := map[groupKind]*trustList{}
	for k := range numGroups {
		tl, _ := newTrustList(initial[k], m.cfg.MaxTrustListSize) // checked by the option
		trust[k] = tl
	}
	var certs []*pendingCert
	for _, x := range m.initial.certs() {
		if t, ok := certTypeOf(x.certificate); ok {
			certs = append(certs, &pendingCert{key: certKey{groupApplication, t}, cert: x.certificate, priv: x.key})
		}
	}
	if x := m.initial.https; x != nil {
		certs = append(certs, &pendingCert{key: certKey{groupHTTPS, id.HTTPSCertificateType}, cert: x.cert, issuers: x.issuers, priv: x.key})
	}
	if sc := m.storeLocked(ctx, trust, certs); sc != ua.StatusOK {
		return nil, sc
	}
	if m.tx != nil {
		m.tx = nil
		m.endDiagnostics(ua.StatusBadRequestCancelledByClient)
	}
	now := time.Now().UnixNano()
	for k, tl := range trust {
		g := m.groups[k]
		g.trust.Store(tl)
		g.lastUpdate.Store(now)
		for h := range g.handles {
			delete(g.handles, h)
			g.openCount.Add(-1)
		}
	}
	clear(m.csrKeys)
	m.s.cfg.restoreIdentities(m.initial)
	m.https.Store(m.initial.https)
	m.s.initEndpoints()
	m.evaluateAlarms()
	go m.changed()
	return nil, ua.StatusOK
}
