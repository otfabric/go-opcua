// SPDX-License-Identifier: MIT

package gdsserver

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

func newKey(t *testing.T, curve string) crypto.Signer {
	t.Helper()
	k, err := testpki.NewKey(curve)
	require.NoError(t, err)
	return k
}

func csrFor(t *testing.T, key crypto.Signer, uri string) []byte {
	t.Helper()
	csr, err := gds.NewCertificateRequest(key, uri, "CN=Test/O=otfabric", []string{"ignored.example", "192.0.2.1"})
	require.NoError(t, err)
	return csr
}

// registerClient registers the test client application.
func (e *env) registerClient() *ua.NodeID {
	e.t.Helper()
	appID, err := e.admin().RegisterApplication(ctxT(e.t), clientRecord())
	require.NoError(e.t, err)
	return appID
}

func TestCertificates_SigningRequestApproval(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	key := newKey(t, testpki.CurveP256)

	reqID, err := self.StartSigningRequest(ctx, appID, nil, nil, csrFor(t, key, testClientURI))
	require.NoError(t, err)
	_, err = self.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadNothingToDo)

	reqs := e.gds.Requests()
	require.Len(t, reqs, 1)
	require.Equal(t, testClientURI, reqs[0].ApplicationURI)
	require.Equal(t, RequestPending, reqs[0].State)
	require.False(t, reqs[0].NewKeyPair)
	require.Equal(t, reqs[0].ID, e.gds.RequestID(reqID))
	require.NoError(t, e.gds.ApproveRequest(ctx, reqs[0].ID, true))
	require.Error(t, e.gds.ApproveRequest(ctx, reqs[0].ID, true))
	require.ErrorIs(t, e.gds.ApproveRequest(ctx, "nope", true), ErrUnknownRequest)

	res, err := self.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	require.Nil(t, res.PrivateKey)
	require.Len(t, res.IssuerCertificates, 1)
	cert, err := x509.ParseCertificate(res.Certificate)
	require.NoError(t, err)
	require.True(t, uapolicy.KeyMatchesCertificate(key, res.Certificate))
	require.Equal(t, testClientURI, cert.URIs[0].String())
	require.Equal(t, "Test", cert.Subject.CommonName)
	require.Empty(t, cert.DNSNames, "the host names of the request are not taken from a client without discovery URLs")
	ca, err := x509.ParseCertificate(res.IssuerCertificates[0])
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err)

	// Completed: the request is gone.
	_, err = self.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	require.Empty(t, e.gds.Requests())

	// A rejected request.
	reqID, err = self.StartSigningRequest(ctx, appID, nil, p256Type, csrFor(t, key, testClientURI))
	require.NoError(t, err)
	require.NoError(t, e.gds.ApproveRequest(ctx, e.gds.RequestID(reqID), false))
	_, err = self.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadRequestNotAllowed)

	types, certs, err := self.GetCertificates(ctx, appID, nil)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.True(t, types[0].Equal(p256Type))
	require.Equal(t, res.Certificate, certs[0])
}

func TestCertificates_SigningRequestErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, MaxRequests: 2})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	key := newKey(t, testpki.CurveP256)
	good := csrFor(t, key, testClientURI)

	_, err := self.StartSigningRequest(ctx, appID, nil, nil, csrFor(t, key, "urn:other"))
	require.ErrorIs(t, err, ua.StatusBadCertificateURIInvalid)
	_, err = self.StartSigningRequest(ctx, appID, nil, nil, csrFor(t, newKey(t, testpki.CurveP384), testClientURI))
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument, "a P-384 key for a P-256 certificate")
	_, err = self.StartSigningRequest(ctx, appID, nil, nil, []byte("garbage"))
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-5] ^= 0xff
	_, err = self.StartSigningRequest(ctx, appID, nil, nil, tampered)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)

	// A well-formed request crypto/x509 cannot read.
	unsupported, err := asn1.Marshal(struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		Info:      asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{0x02, 0x01, 0x00}},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 113}},
		Signature: asn1.BitString{Bytes: []byte{1, 2, 3}, BitLength: 24},
	})
	require.NoError(t, err)
	_, err = self.StartSigningRequest(ctx, appID, nil, nil, unsupported)
	require.ErrorIs(t, err, ua.StatusBadNotSupported)

	_, err = self.StartSigningRequest(ctx, appID, ua.NewNumericNodeID(e.gds.Namespace(), gdsid.DirectoryCertificateGroupsDefaultHTTPSGroup), nil, good)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = self.StartSigningRequest(ctx, appID, nil, ua.NewNumericNodeID(0, id.RsaSha256ApplicationCertificateType), good)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument, "a type the group does not issue")
	_, err = self.StartSigningRequest(ctx, appID, nil, ua.NewNumericNodeID(3, id.EccNistP256ApplicationCertificateType), good)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)

	// Unknown and foreign applications.
	_, err = e.caAdmin().StartSigningRequest(ctx, ua.NewGUIDNodeID(e.gds.Namespace(), "00000000-0000-0000-0000-000000000003"), nil, nil, good)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
	otherID, err := e.admin().RegisterApplication(ctx, record("urn:test:other"))
	require.NoError(t, err)
	_, err = self.StartSigningRequest(ctx, otherID, nil, nil, good)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	// Sign only: the methods need encryption.
	_, err = e.pull(dialOpts{mode: ua.MessageSecurityModeSign}).StartSigningRequest(ctx, appID, nil, nil, good)
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)
	_, err = e.pull(dialOpts{mode: ua.MessageSecurityModeSign}).StartNewKeyPairRequest(ctx, appID, nil)
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)
	_, err = e.pull(dialOpts{mode: ua.MessageSecurityModeSign}).FinishRequest(ctx, appID, appID)
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)

	// At most MaxRequests open requests.
	for range 2 {
		_, err = self.StartSigningRequest(ctx, appID, nil, nil, good)
		require.NoError(t, err)
	}
	_, err = self.StartSigningRequest(ctx, appID, nil, nil, good)
	require.ErrorIs(t, err, ua.StatusBadTooManyOperations)

	// FinishRequest with a request of another application or none.
	_, err = e.caAdmin().FinishRequest(ctx, otherID, ua.NewGUIDNodeID(e.gds.Namespace(), e.gds.Requests()[0].ID))
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)

	c := e.dial(dialOpts{})
	for _, m := range []uint32{gdsid.DirectoryStartSigningRequest, gdsid.DirectoryStartNewKeyPairRequest, gdsid.DirectoryFinishRequest} {
		_, sc := e.rawCall(c, m, ua.MustVariant(uint32(1)), ua.MustVariant(uint32(1)), ua.MustVariant(uint32(1)),
			ua.MustVariant(uint32(1)), ua.MustVariant(uint32(1)), ua.MustVariant(uint32(1)), ua.MustVariant(uint32(1)))
		require.Contains(t, []ua.StatusCode{ua.StatusBadTypeMismatch, ua.StatusBadInvalidArgument, ua.StatusBadTooManyArguments}, sc)
	}
}

func TestCertificates_RequestLifetime(t *testing.T) {
	t.Parallel()
	var clk clock
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, AutoApprove: true, Now: clk.now, RequestLifetime: time.Hour})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	reqID, err := self.StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	clk.advance(2 * time.Hour)
	_, err = self.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	require.Empty(t, e.gds.Requests())
}

func TestCertificates_NewKeyPair(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, AutoApprove: true})
	ctx := ctxT(t)
	rec := record(testClientURI, "opc.tcp://host.example:4840", "opc.tcp://192.0.2.7:4840")
	appID, err := e.admin().RegisterApplication(ctx, rec)
	require.NoError(t, err)
	self := e.anonymous()

	reqID, err := self.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{
		SubjectName:        "CN=Box/O=otfabric/DC=host.example",
		DomainNames:        []string{"host.example", "192.0.2.7"},
		PrivateKeyPassword: "secret",
	})
	require.NoError(t, err)
	res, err := self.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	_, err = gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, res.PrivateKey, "wrong")
	require.Error(t, err)
	key, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, res.PrivateKey, "secret")
	require.NoError(t, err)
	require.True(t, uapolicy.KeyMatchesCertificate(key, res.Certificate))
	cert, err := x509.ParseCertificate(res.Certificate)
	require.NoError(t, err)
	require.Equal(t, "Box", cert.Subject.CommonName)
	require.Equal(t, []string{"host.example"}, cert.DNSNames)
	require.Len(t, cert.IPAddresses, 1)

	// Without names: those of the discovery URLs and the application name.
	reqID, err = self.StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	res, err = self.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(res.Certificate)
	require.NoError(t, err)
	require.Equal(t, "App "+testClientURI, cert.Subject.CommonName)
	require.Equal(t, []string{"host.example"}, cert.DNSNames)

	// The application may not ask for other names; an administrator may.
	_, err = self.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{DomainNames: []string{"evil.example"}})
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	reqID, err = e.caAdmin().StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{DomainNames: []string{"other.example"}})
	require.NoError(t, err)
	_, err = e.caAdmin().FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)

	for name, r := range map[string]*gds.NewKeyPairRequest{
		"format":  {PrivateKeyFormat: gds.PrivateKeyFormatPFX},
		"subject": {SubjectName: "XX=1"},
		"domain":  {DomainNames: []string{"a b"}},
		"empty":   {DomainNames: []string{""}},
		"many":    {DomainNames: make([]string, maxDomainNames+1)},
	} {
		_, err := self.StartNewKeyPairRequest(ctx, appID, r)
		require.ErrorIs(t, err, ua.StatusBadInvalidArgument, name)
	}
}

// TestCertificates_AllTypes issues a certificate of every type with a key
// the GDS generates and one from a request where crypto/x509 can make it.
func TestCertificates_AllTypes(t *testing.T) {
	t.Parallel()
	p := pkiOf(t)
	caKey, err := uapolicy.MarshalPrivateKey(p.CAKey)
	require.NoError(t, err)
	e := newEnv(t, Config{
		SelfAdmin:        selfAdminAll,
		AutoApprove:      true,
		CertificateTypes: DefaultCertificateTypes,
		Issuers:          []*Issuer{{Name: "RSA", Certificate: p.CACert, PrivateKey: caKey}},
	})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	for _, typ := range DefaultCertificateTypes {
		reqID, err := self.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{CertificateType: typ})
		require.NoError(t, err, typ)
		res, err := self.FinishRequest(ctx, appID, reqID)
		require.NoError(t, err, typ)
		key, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, res.PrivateKey, "")
		require.NoError(t, err)
		require.True(t, uapolicy.KeyMatchesCertificate(key, res.Certificate), typ)
		cert, err := uapolicy.ParseCertificate(res.Certificate)
		require.NoError(t, err)
		issuer, err := uapolicy.ParseCertificate(res.IssuerCertificates[0])
		require.NoError(t, err)
		require.Equal(t, issuer.RawSubject, cert.RawIssuer)
		e.gds.mu.Lock()
		ok := slices_any(e.gds.cas, func(c *ca) bool { return c.issues(cert) })
		e.gds.mu.Unlock()
		require.True(t, ok, typ)
		status, _, err := self.CheckRevocationStatus(ctx, res.Certificate)
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, status, typ)
	}
	require.Equal(t, p.CACert, e.gds.IssuerCertificates()[len(e.gds.IssuerCertificates())-1], "the RSA CA is the one configured")

	for _, curve := range []string{testpki.CurveP256, testpki.CurveP384, testpki.CurveEd25519} {
		typ := map[string]*ua.NodeID{
			testpki.CurveP256: gds.EccNistP256ApplicationCertificateType, testpki.CurveP384: gds.EccNistP384ApplicationCertificateType,
			testpki.CurveEd25519: gds.EccCurve25519ApplicationCertificateType,
		}[curve]
		reqID, err := self.StartSigningRequest(ctx, appID, nil, typ, csrFor(t, newKey(t, curve), testClientURI))
		require.NoError(t, err, curve)
		_, err = self.FinishRequest(ctx, appID, reqID)
		require.NoError(t, err, curve)
	}
	reqID, err := self.StartSigningRequest(ctx, appID, nil, gds.RsaSha256ApplicationCertificateType, csrFor(t, p.ClientKey, testClientURI))
	require.NoError(t, err)
	_, err = self.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)

	update, err := self.GetCertificateStatus(ctx, appID, nil, nil)
	require.NoError(t, err)
	require.False(t, update, "a fresh certificate of every type")
}

func slices_any(m map[string]*ca, f func(*ca) bool) bool { //nolint:revive // test helper
	for _, c := range m {
		if f(c) {
			return true
		}
	}
	return false
}

// TestCertificates_SelfAdminByIssuedCertificate: without Config.SelfAdmin
// the application manages itself only with a certificate the GDS issued.
func TestCertificates_SelfAdminByIssuedCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{AutoApprove: true})
	ctx := ctxT(t)
	appID := e.registerClient()

	// Its self-signed certificate does not do.
	_, err := e.anonymous().StartNewKeyPairRequest(ctx, appID, nil)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	ca := e.caAdmin()
	reqID, err := ca.StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	res, err := ca.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	key, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, res.PrivateKey, "")
	require.NoError(t, err)

	self := e.pull(dialOpts{cert: res.Certificate, key: key})
	groups, err := self.GetCertificateGroups(ctx, appID)
	require.NoError(t, err)
	require.Equal(t, []*ua.NodeID{e.gds.DefaultApplicationGroup()}, groups)
	update, err := self.GetCertificateStatus(ctx, appID, nil, p256Type)
	require.NoError(t, err)
	require.False(t, update)
	tl, err := self.ReadTrustList(ctx, appID, nil)
	require.NoError(t, err)
	require.Len(t, tl.TrustedCertificates, 1)
	require.Len(t, tl.TrustedCrls, 1)

	// Revoked, it no longer does.
	require.NoError(t, ca.RevokeCertificate(ctx, appID, res.Certificate))
	_, err = e.pull(dialOpts{cert: res.Certificate, key: key}).GetCertificateGroups(ctx, appID)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
}

func TestCertificates_Revocation(t *testing.T) {
	t.Parallel()
	var clk clock
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, AutoApprove: true, Now: clk.now, CertificateLifetime: 30 * 24 * time.Hour})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	issue := func() []byte {
		t.Helper()
		reqID, err := self.StartNewKeyPairRequest(ctx, appID, nil)
		require.NoError(t, err)
		res, err := self.FinishRequest(ctx, appID, reqID)
		require.NoError(t, err)
		return res.Certificate
	}
	cert := issue()

	status, until, err := self.CheckRevocationStatus(ctx, cert)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)
	require.True(t, until.After(clk.now()))

	require.ErrorIs(t, self.RevokeCertificate(ctx, appID, cert), ua.StatusBadUserAccessDenied)
	ca := e.caAdmin()
	require.ErrorIs(t, ca.RevokeCertificate(ctx, appID, pkiOf(t).ClientCert), ua.StatusBadInvalidArgument)
	require.NoError(t, ca.RevokeCertificate(ctx, appID, cert))
	require.NoError(t, ca.RevokeCertificate(ctx, appID, cert), "again")

	status, _, err = self.CheckRevocationStatus(ctx, cert)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateRevoked, status)
	parsed, err := x509.ParseCertificate(cert)
	require.NoError(t, err)
	tl := e.gds.TrustList()
	crl, err := x509.ParseRevocationList(tl.TrustedCrls[0])
	require.NoError(t, err)
	require.Len(t, crl.RevokedCertificateEntries, 1)
	require.Zero(t, crl.RevokedCertificateEntries[0].SerialNumber.Cmp(parsed.SerialNumber))

	update, err := self.GetCertificateStatus(ctx, appID, nil, nil)
	require.NoError(t, err)
	require.True(t, update, "the only certificate is revoked")
	types, certs, err := self.GetCertificates(ctx, appID, nil)
	require.NoError(t, err)
	require.Empty(t, types)
	require.Empty(t, certs)

	// Renewal is due after two thirds of the lifetime; then it expires.
	cert = issue()
	update, err = self.GetCertificateStatus(ctx, appID, nil, nil)
	require.NoError(t, err)
	require.False(t, update)
	clk.advance(21 * 24 * time.Hour)
	update, err = self.GetCertificateStatus(ctx, appID, nil, nil)
	require.NoError(t, err)
	require.True(t, update)
	clk.advance(10 * 24 * time.Hour)
	status, _, err = self.CheckRevocationStatus(ctx, cert)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateTimeInvalid, status)

	// Certificates of no CA of the GDS, and no certificates.
	status, _, err = self.CheckRevocationStatus(ctx, pkiOf(t).ClientCert)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateUntrusted, status)
	status, _, err = self.CheckRevocationStatus(ctx, []byte("junk"))
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateInvalid, status)
	_, _, err = e.pull(dialOpts{mode: ua.MessageSecurityModeNone}).CheckRevocationStatus(ctx, cert)
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)

	// UnregisterApplication revokes what is left.
	require.NoError(t, e.admin().UnregisterApplication(ctx, appID))
	status, _, err = self.CheckRevocationStatus(ctx, cert)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateRevoked, status)
	require.ErrorIs(t, ca.RevokeCertificate(ctx, appID, cert), ua.StatusBadNotFound)
	require.ErrorIs(t, e.pull(dialOpts{mode: ua.MessageSecurityModeNone, user: userCAAdmin}).RevokeCertificate(ctx, appID, cert), ua.StatusBadSecurityModeInsufficient)
}

func TestCertificates_GroupsAndStatusArguments(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	bad := ua.NewNumericNodeID(e.gds.Namespace(), gdsid.DirectoryCertificateGroupsDefaultUserTokenGroup)
	_, err := self.GetTrustList(ctx, appID, bad)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, _, err = self.GetCertificates(ctx, appID, bad)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = self.GetCertificateStatus(ctx, appID, bad, nil)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	_, err = self.GetCertificateStatus(ctx, appID, nil, gds.RsaMinApplicationCertificateType)
	require.ErrorIs(t, err, ua.StatusBadInvalidArgument)
	tl, err := self.GetTrustList(ctx, appID, nil)
	require.NoError(t, err)
	require.True(t, tl.Equal(e.gds.node(gdsid.DirectoryCertificateGroupsDefaultApplicationGroupTrustList)))
	update, err := self.GetCertificateStatus(ctx, appID, e.gds.DefaultApplicationGroup(), p256Type)
	require.NoError(t, err)
	require.True(t, update, "no certificate yet")

	unknown := ua.NewGUIDNodeID(e.gds.Namespace(), "00000000-0000-0000-0000-000000000004")
	_, err = self.GetCertificateGroups(ctx, unknown)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, err = self.GetTrustList(ctx, unknown, nil)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, _, err = self.GetCertificates(ctx, unknown, nil)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, err = self.GetCertificateStatus(ctx, unknown, nil, nil)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)

	c := e.dial(dialOpts{})
	for _, m := range []uint32{gdsid.DirectoryGetCertificateGroups, gdsid.DirectoryGetCertificates, gdsid.DirectoryGetTrustList,
		gdsid.DirectoryGetCertificateStatus, gdsid.DirectoryCheckRevocationStatus, gdsid.DirectoryRevokeCertificate,
		gdsid.DirectoryGetApplication, gdsid.DirectoryFindApplications} {
		args := []*ua.Variant{ua.MustVariant(uint32(1)), ua.MustVariant(uint32(1)), ua.MustVariant(uint32(1))}
		_, sc := e.rawCall(c, m, args...)
		require.True(t, errors.Is(sc, ua.StatusBadTypeMismatch) || errors.Is(sc, ua.StatusBadTooManyArguments) || errors.Is(sc, ua.StatusBadInvalidArgument), "%d: %v", m, sc)
	}
}
