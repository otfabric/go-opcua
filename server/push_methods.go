// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"slices"
	"strings"
	"time"

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
	case want == have, want == 0, want == id.ApplicationCertificateType:
		return true
	case isRSAType(want):
		return isRSAType(have)
	case want == id.EccApplicationCertificateType:
		return !isRSAType(have)
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

// identityOfType returns the application instance certificate of the
// group and type arguments with its concrete type: argument i is the
// CertificateGroupId (null or the DefaultApplicationGroup) and i+1 the
// CertificateTypeId.
func (m *pushManager) identityOfType(args []*ua.Variant, i int) (applicationIdentity, uint32, ua.StatusCode) {
	group, ok1 := argValue[*ua.NodeID](args, i)
	typ, ok2 := argValue[*ua.NodeID](args, i+1)
	if !ok1 || !ok2 {
		return applicationIdentity{}, 0, ua.StatusBadTypeMismatch
	}
	if !isNullNodeID(group) && !group.Equal(ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroup)) {
		return applicationIdentity{}, 0, ua.StatusBadInvalidArgument
	}
	var want uint32
	if !isNullNodeID(typ) {
		if typ.Namespace() != 0 || !isNumericNodeID(typ) {
			return applicationIdentity{}, 0, ua.StatusBadInvalidArgument
		}
		want = typ.IntID()
	}
	for _, x := range m.s.cfg.identityCerts() {
		if t, ok := certTypeOf(x.certificate); ok && typeMatches(want, t) {
			return x, t, ua.StatusOK
		}
	}
	return applicationIdentity{}, 0, ua.StatusBadInvalidArgument
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

// updateCertificate is UpdateCertificate (Part 12 §7.10.4): a new
// application instance certificate, with its issuers and, if the server
// did not make the key, its private key. It replaces the certificate of the
// type for new channels when the changes are applied.
func (m *pushManager) updateCertificate(ctx context.Context, c *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	cur, certType, sc := m.identityOfType(args, 0)
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
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil || !bytes.Equal(cert.Raw, der) {
		return nil, ua.StatusBadCertificateInvalid
	}
	if t, ok := certTypeOf(der); !ok || !typeMatches(certType, t) {
		return nil, ua.StatusBadCertificateInvalid
	}
	if uri := m.s.cfg.applicationURI; uri != "" && (len(cert.URIs) == 0 || cert.URIs[0].String() != uri) {
		return nil, ua.StatusBadCertificateURIInvalid
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, ua.StatusBadCertificateTimeInvalid
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

	m.mu.Lock()
	defer m.mu.Unlock()
	var key crypto.Signer
	switch strings.ToUpper(format) {
	case "":
		if len(keyData) > 0 {
			return nil, ua.StatusBadInvalidArgument
		}
		// The key of the last CreateSigningRequest that regenerated it, or
		// the key the server has.
		for _, k := range []crypto.Signer{m.csrKeys[certType], cur.key} {
			if k != nil && uapolicy.KeyMatchesCertificate(k, der) {
				key = k
				break
			}
		}
	case "PEM":
		k, err := uapolicy.ParsePrivateKey(keyData)
		if err != nil {
			return nil, ua.StatusBadSecurityChecksFailed
		}
		key = k
	default:
		return nil, ua.StatusBadNotSupported // PFX
	}
	if key == nil || !uapolicy.KeyMatchesCertificate(key, der) {
		return nil, ua.StatusBadSecurityChecksFailed
	}
	if _, isRSA := key.(*rsa.PrivateKey); isRSAType(certType) && !isRSA {
		return nil, ua.StatusBadSecurityChecksFailed
	}
	tx, sc := m.txLocked(c.SessionID)
	if sc != ua.StatusOK {
		return nil, sc
	}
	tx.certs[certType] = &pendingCert{certType: certType, old: cur.certificate, cert: slices.Clone(der), issuers: issuers, key: key}
	if m.cfg.ApplyImmediately {
		if sc := m.applyLocked(ctx); sc != ua.StatusOK {
			return nil, sc
		}
		return []*ua.Variant{ua.MustVariant(false)}, ua.StatusOK
	}
	return []*ua.Variant{ua.MustVariant(true)}, ua.StatusOK
}

// issuedByOneOf reports whether cert is self-signed or signed by one of the
// issuers. Without issuers any certificate passes: its CA may be known to
// the clients only. A signature crypto/x509 cannot check (Brainpool, Ed448)
// is not held against the certificate.
func issuedByOneOf(cert *x509.Certificate, issuers []*x509.Certificate) bool {
	if len(issuers) == 0 || bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return true
	}
	for _, ic := range issuers {
		if !bytes.Equal(ic.RawSubject, cert.RawIssuer) {
			continue
		}
		err := cert.CheckSignatureFrom(ic)
		if err == nil || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
			return true
		}
	}
	return false
}

// createSigningRequest is CreateSigningRequest (Part 12 §7.10.7): a PKCS #10
// certificate request for the certificate of the type, with the key the
// server has or a new one (RegeneratePrivateKey), which UpdateCertificate
// then takes with the certificate issued for it.
func (m *pushManager) createSigningRequest(_ context.Context, _ *MethodCaller, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	cur, certType, sc := m.identityOfType(args, 0)
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
	curCert, err := uapolicy.ParseCertificate(cur.certificate)
	if err != nil {
		return nil, ua.StatusBadInternalError
	}
	name := curCert.Subject
	if subject != "" {
		if name, err = parseSubjectName(subject); err != nil {
			return nil, ua.StatusBadInvalidArgument
		}
	}
	key := cur.key
	if regenerate {
		if len(nonce) < minCSRNonce {
			return nil, ua.StatusBadInvalidArgument
		}
		if key, err = generateKeyLike(cur.key); err != nil {
			return nil, ua.StatusBadNotSupported
		}
	}
	tmpl := &x509.CertificateRequest{
		Subject:     name,
		DNSNames:    curCert.DNSNames,
		IPAddresses: curCert.IPAddresses,
		URIs:        curCert.URIs,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		// crypto/x509 makes no requests for Brainpool and Ed448 keys.
		return nil, ua.StatusBadNotSupported
	}
	if regenerate {
		m.mu.Lock()
		m.csrKeys[certType] = key
		m.mu.Unlock()
	}
	return []*ua.Variant{ua.MustVariant(csr)}, ua.StatusOK
}

// generateKeyLike returns a new key of the type and size of key: RSA (at
// least 2048 bits), ECDSA on the NIST curves or Ed25519.
func generateKeyLike(key crypto.Signer) (crypto.Signer, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return rsa.GenerateKey(rand.Reader, max(k.N.BitLen(), 2048))
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256", "P-384":
			return ecdsa.GenerateKey(k.Curve, rand.Reader)
		}
	case ed25519.PrivateKey:
		_, nk, err := ed25519.GenerateKey(rand.Reader)
		return nk, err
	}
	return nil, x509.ErrUnsupportedAlgorithm
}

var oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}

// parseSubjectName parses the SubjectName of CreateSigningRequest: X.500
// name value pairs separated by '/' (Part 12 §7.10.7, CN=App/O=Company) or
// by ','.
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
	if _, sc := m.txLocked(c.SessionID); sc != ua.StatusOK {
		return nil, sc
	}
	m.tx = nil
	return nil, ua.StatusOK
}
