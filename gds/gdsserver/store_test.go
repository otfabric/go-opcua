// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsid"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

var errStore = errors.New("store down")

// failOn makes the store fail the named operations.
func failOn(m *MemoryStore, ops ...string) {
	m.failWith(func(op string) error {
		for _, o := range ops {
			if o == op {
				return errStore
			}
		}
		return nil
	})
}

func TestMemoryStore_Copies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemoryStore()
	app := &Application{ID: "a", RecordID: 2, Record: clientRecord(), EndpointIDs: []uint32{3},
		Certificates: []*IssuedCertificate{{CertificateType: 1, Certificate: []byte{1}}}}
	require.NoError(t, m.PutApplication(ctx, app))
	app.Record.ApplicationURI = "changed"
	app.Certificates[0].Certificate[0] = 9
	req := &Request{ID: "r", ApplicationID: "a", DomainNames: []string{"x"}, CertificateRequest: []byte{1}}
	require.NoError(t, m.PutRequest(ctx, req))
	req.DomainNames[0] = "y"
	iss := &Issuer{Name: "RSA", Certificate: []byte{1}, Revoked: []*RevokedCertificate{{SerialNumber: []byte{1}}}}
	require.NoError(t, m.PutIssuer(ctx, iss))
	iss.Revoked[0].SerialNumber[0] = 9
	meta := &Meta{NextRecordID: 5, TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{{1}}}}
	require.NoError(t, m.PutMeta(ctx, meta))
	meta.TrustList.TrustedCertificates[0][0] = 9

	st, err := m.Load(ctx)
	require.NoError(t, err)
	require.Equal(t, testClientURI, st.Applications[0].Record.ApplicationURI)
	require.Equal(t, []byte{1}, st.Applications[0].Certificates[0].Certificate)
	require.Equal(t, []string{"x"}, st.Requests[0].DomainNames)
	require.Equal(t, []byte{1}, st.Issuers[0].Revoked[0].SerialNumber)
	require.Equal(t, []byte{1}, st.Meta.TrustList.TrustedCertificates[0])

	require.NoError(t, m.DeleteApplication(ctx, "a"))
	require.NoError(t, m.DeleteRequest(ctx, "r"))
	st, err = m.Load(ctx)
	require.NoError(t, err)
	require.Empty(t, st.Applications)
	require.Empty(t, st.Requests)

	failOn(m, "Load", "PutApplication", "DeleteApplication", "PutRequest", "DeleteRequest", "PutIssuer", "PutMeta")
	_, err = m.Load(ctx)
	require.ErrorIs(t, err, errStore)
	require.ErrorIs(t, m.PutApplication(ctx, app), errStore)
	require.ErrorIs(t, m.DeleteApplication(ctx, "a"), errStore)
	require.ErrorIs(t, m.PutRequest(ctx, req), errStore)
	require.ErrorIs(t, m.DeleteRequest(ctx, "r"), errStore)
	require.ErrorIs(t, m.PutIssuer(ctx, iss), errStore)
	require.ErrorIs(t, m.PutMeta(ctx, meta), errStore)

	require.Equal(t, "Pending", RequestPending.String())
	require.Equal(t, "Approved", RequestApproved.String())
	require.Equal(t, "Rejected", RequestRejected.String())
	require.Equal(t, "Unknown", RequestState(7).String())
}

// TestStore_Failures: a failing write fails the call with
// Bad_InternalError and changes nothing.
func TestStore_Failures(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll})
	ctx := ctxT(t)
	admin, ca, self := e.admin(), e.caAdmin(), e.anonymous()
	appID := e.registerClient()
	key := newKey(t, testpki.CurveP256)

	failOn(e.store, "PutMeta")
	_, err := admin.RegisterApplication(ctx, record("urn:test:x"))
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	failOn(e.store, "PutApplication")
	_, err = admin.RegisterApplication(ctx, record("urn:test:x"))
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	found, err := admin.FindApplications(ctx, "urn:test:x")
	require.NoError(t, err)
	require.Empty(t, found)
	rec, err := admin.GetApplication(ctx, appID)
	require.NoError(t, err)
	require.ErrorIs(t, admin.UpdateApplication(ctx, rec), ua.StatusBadInternalError)

	failOn(e.store, "PutRequest")
	_, err = self.StartSigningRequest(ctx, appID, nil, nil, csrFor(t, key, testClientURI))
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	require.Empty(t, e.gds.Requests())
	e.store.failWith(nil)
	reqID, err := self.StartSigningRequest(ctx, appID, nil, nil, csrFor(t, key, testClientURI))
	require.NoError(t, err)
	failOn(e.store, "PutRequest")
	require.ErrorIs(t, e.gds.ApproveRequest(ctx, e.gds.RequestID(reqID), true), errStore)
	e.store.failWith(nil)
	require.NoError(t, e.gds.ApproveRequest(ctx, e.gds.RequestID(reqID), true))

	// FinishRequest: the certificate is not recorded, the request stays.
	failOn(e.store, "PutApplication")
	_, err = self.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	failOn(e.store, "DeleteRequest")
	_, err = self.FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	e.store.failWith(nil)
	res, err := self.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)

	failOn(e.store, "PutIssuer")
	require.ErrorIs(t, ca.RevokeCertificate(ctx, appID, res.Certificate), ua.StatusBadInternalError)
	status, _, err := self.CheckRevocationStatus(ctx, res.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status, "not revoked")
	failOn(e.store, "PutApplication")
	require.ErrorIs(t, ca.RevokeCertificate(ctx, appID, res.Certificate), ua.StatusBadInternalError)

	failOn(e.store, "PutIssuer")
	require.ErrorIs(t, admin.UnregisterApplication(ctx, appID), ua.StatusBadInternalError)
	failOn(e.store, "DeleteApplication")
	require.ErrorIs(t, admin.UnregisterApplication(ctx, appID), ua.StatusBadInternalError)
	e.store.failWith(nil)
	_, err = self.StartSigningRequest(ctx, appID, nil, nil, csrFor(t, key, testClientURI))
	require.NoError(t, err)
	failOn(e.store, "DeleteRequest")
	require.ErrorIs(t, admin.UnregisterApplication(ctx, appID), ua.StatusBadInternalError)
	e.store.failWith(nil)
	require.NoError(t, admin.UnregisterApplication(ctx, appID))
	require.Empty(t, e.gds.Requests())

	// The trust list.
	failOn(e.store, "PutMeta")
	push := gds.New(e.dial(dialOpts{user: userCAAdmin}))
	push.TrustList = e.gds.node(gdsid.DirectoryCertificateGroupsDefaultApplicationGroupTrustList)
	require.Error(t, push.AddCertificate(ctx, pkiOf(t).CACert, true))
}

func TestAttach_Errors(t *testing.T) {
	t.Parallel()
	newSrv := func() *server.Server {
		srv, err := server.New(server.InsecureNoSecurity(), server.EndPoint("localhost", 0))
		require.NoError(t, err)
		return srv
	}
	_, err := Attach(newSrv(), Config{CertificateTypes: []*ua.NodeID{ua.NewNumericNodeID(0, 1)}})
	require.Error(t, err)
	_, err = Attach(newSrv(), Config{CertificateTypes: []*ua.NodeID{nil}})
	require.Error(t, err)

	srv := newSrv()
	_, err = Attach(srv, Config{CertificateTypes: []*ua.NodeID{p256Type}})
	require.NoError(t, err)
	_, err = Attach(srv, Config{CertificateTypes: []*ua.NodeID{p256Type}})
	require.Error(t, err, "twice")

	for _, op := range []string{"Load", "PutMeta", "PutIssuer"} {
		m := NewMemoryStore()
		failOn(m, op)
		_, err = Attach(newSrv(), Config{Store: m, CertificateTypes: []*ua.NodeID{p256Type}})
		require.ErrorIs(t, err, errStore, op)
	}

	p := pkiOf(t)
	_, err = Attach(newSrv(), Config{CertificateTypes: []*ua.NodeID{gds.RsaSha256ApplicationCertificateType},
		Issuers: []*Issuer{{Name: "RSA", Certificate: p.CACert, PrivateKey: []byte("junk")}}})
	require.Error(t, err)
	_, err = Attach(newSrv(), Config{CertificateTypes: []*ua.NodeID{gds.RsaSha256ApplicationCertificateType},
		Issuers: []*Issuer{nil, {Name: "RSA", Certificate: p.ClientCert, PrivateKey: mustKey(t, p.ClientKey)}}})
	require.Error(t, err, "not a CA")
	_, err = Attach(newSrv(), Config{CertificateTypes: []*ua.NodeID{gds.RsaSha256ApplicationCertificateType},
		Issuers: []*Issuer{{Name: "RSA", Certificate: p.CACert, PrivateKey: mustKey(t, p.ClientKey)}}})
	require.Error(t, err, "key of another certificate")
	_, err = Attach(newSrv(), Config{CertificateTypes: []*ua.NodeID{gds.RsaSha256ApplicationCertificateType},
		Issuers: []*Issuer{{Name: "RSA", Certificate: []byte("junk"), PrivateKey: mustKey(t, p.ClientKey)}}})
	require.Error(t, err)
}

// TestRestart: the state survives a restart of the GDS with the same
// Store, a request in flight included.
func TestRestart(t *testing.T) {
	t.Parallel()
	for name, store := range map[string]func(t *testing.T) Store{
		"memory": func(*testing.T) Store { return NewMemoryStore() },
		"file": func(t *testing.T) Store {
			s, err := NewFileStore(t.TempDir())
			require.NoError(t, err)
			return s
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testRestart(t, store(t))
		})
	}
}

func testRestart(t *testing.T, store Store) {
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, Store: store})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	reqID, err := self.StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	reqID2, err := self.StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	require.NoError(t, e.gds.ApproveRequest(ctx, e.gds.RequestID(reqID2), true))
	res2, err := self.FinishRequest(ctx, appID, reqID2)
	require.NoError(t, err)
	require.NoError(t, e.caAdmin().RevokeCertificate(ctx, appID, res2.Certificate))
	push := gds.New(e.dial(dialOpts{user: userCAAdmin}))
	push.TrustList = e.gds.node(gdsid.DirectoryCertificateGroupsDefaultApplicationGroupTrustList)
	require.NoError(t, push.AddCertificate(ctx, pkiOf(t).CACert, false))
	caBefore := e.gds.IssuerCertificates()

	e.restart()
	self = e.anonymous()
	require.Equal(t, caBefore, e.gds.IssuerCertificates())
	reqs := e.gds.Requests()
	require.Len(t, reqs, 1)
	require.NoError(t, e.gds.ApproveRequest(ctx, reqs[0].ID, true))
	res, err := self.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	status, _, err := self.CheckRevocationStatus(ctx, res2.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateRevoked, status)
	status, _, err = self.CheckRevocationStatus(ctx, res.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, status)
	tl := e.gds.TrustList()
	require.Contains(t, tl.IssuerCertificates, pkiOf(t).CACert)

	// Record ids continue.
	id2, err := e.admin().RegisterApplication(ctx, record("urn:test:after"))
	require.NoError(t, err)
	q, err := self.QueryApplications(ctx, nil)
	require.NoError(t, err)
	require.Len(t, q.Applications, 2)
	require.NotNil(t, id2)
}

// TestIssuers: an issuer of the Config replaces the stored one; the stored
// revocations are kept only for the same certificate.
func TestIssuers(t *testing.T) {
	t.Parallel()
	p := pkiOf(t)
	ecc := p.ECC
	caKey := mustKey(t, ecc.CAs[testpki.CurveP256].Key)
	iss := []*Issuer{{Name: "NistP256", Certificate: ecc.CAs[testpki.CurveP256].Cert, PrivateKey: caKey}}
	store := NewMemoryStore()
	e := newEnv(t, Config{Store: store, Issuers: iss, AutoApprove: true, SelfAdmin: selfAdminAll})
	ctx := ctxT(t)
	require.Equal(t, [][]byte{ecc.CAs[testpki.CurveP256].Cert}, e.gds.IssuerCertificates())
	appID := e.registerClient()
	self := e.anonymous()
	reqID, err := self.StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	res, err := self.FinishRequest(ctx, appID, reqID)
	require.NoError(t, err)
	require.NoError(t, e.caAdmin().RevokeCertificate(ctx, appID, res.Certificate))

	e.restart()
	status, _, err := e.anonymous().CheckRevocationStatus(ctx, res.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateRevoked, status, "same CA: the revocation is kept")

	// Another CA: its CRL starts empty, the old certificates are no longer
	// of the GDS.
	other, err := testpki.NewCA(testpki.CurveP256, "other CA")
	require.NoError(t, err)
	e.cfg.Issuers = []*Issuer{{Name: "NistP256", Certificate: other.Cert, PrivateKey: mustKey(t, other.Key)}}
	e.restart()
	status, _, err = e.anonymous().CheckRevocationStatus(ctx, res.Certificate)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadCertificateUntrusted, status)
	update, err := e.anonymous().GetCertificateStatus(ctx, appID, nil, nil)
	require.NoError(t, err)
	require.True(t, update)
}

func mustKey(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	return der
}

// TestCRLRefresh: a CRL past half its lifetime is renewed when the trust
// list is read.
func TestCRLRefresh(t *testing.T) {
	t.Parallel()
	var clk clock
	e := newEnv(t, Config{Now: clk.now, CRLLifetime: 10 * time.Hour})
	crl := func() *x509.RevocationList {
		t.Helper()
		c, err := x509.ParseRevocationList(e.gds.TrustList().TrustedCrls[0])
		require.NoError(t, err)
		return c
	}
	first := crl()
	clk.advance(4 * time.Hour)
	require.Zero(t, crl().Number.Cmp(first.Number))
	clk.advance(2 * time.Hour)
	require.Equal(t, 1, crl().Number.Cmp(first.Number))

	// A failing store keeps the old CRL.
	before := crl()
	clk.advance(6 * time.Hour)
	failOn(e.store, "PutIssuer")
	require.Zero(t, crl().Number.Cmp(before.Number))
}

// TestTrustListObject: reading and changing the trust list of the
// DefaultApplicationGroup.
func TestTrustListObject(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, AutoApprove: true})
	ctx := ctxT(t)
	appID := e.registerClient()
	tlNode := e.gds.node(gdsid.DirectoryCertificateGroupsDefaultApplicationGroupTrustList)
	client := func(o dialOpts) *gds.Client {
		c := gds.New(e.dial(o))
		c.TrustList = tlNode
		return c
	}
	ca := client(dialOpts{user: userCAAdmin})
	extra := pkiOf(t).ECC.CAs[testpki.CurveP384].Cert
	require.NoError(t, ca.AddCertificate(ctx, extra, true))
	tl, err := client(dialOpts{user: userSecurityAdmin}).ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	require.Contains(t, tl.TrustedCertificates, extra)
	require.Len(t, tl.TrustedCertificates, 2)

	// The application reads it.
	tl2, err := e.anonymous().ReadTrustList(ctx, appID, nil)
	require.NoError(t, err)
	require.Equal(t, tl.TrustedCertificates, tl2.TrustedCertificates)

	// Others may not, and only the CertificateAuthorityAdmin writes.
	_, err = client(dialOpts{user: userPlain, cert: pkiOf(t).ECC.Users[testpki.CurveP256].Cert, key: pkiOf(t).ECC.Users[testpki.CurveP256].Key}).ReadTrustList(ctx, ua.TrustListMasksAll)
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	require.ErrorIs(t, client(dialOpts{user: userSecurityAdmin}).AddCertificate(ctx, extra, true), ua.StatusBadUserAccessDenied)
	_, err = client(dialOpts{mode: ua.MessageSecurityModeNone, user: userCAAdmin}).ReadTrustList(ctx, ua.TrustListMasksAll)
	require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)
	require.ErrorIs(t, client(dialOpts{mode: ua.MessageSecurityModeSign, user: userCAAdmin}).AddCertificate(ctx, extra, false), ua.StatusBadSecurityModeInsufficient)

	// The CA entries stay whatever is written.
	thumb := gds.Thumbprint(extra)
	require.NoError(t, ca.RemoveCertificate(ctx, thumb, true))
	tl, err = ca.ReadTrustList(ctx, ua.TrustListMasksAll)
	require.NoError(t, err)
	require.Equal(t, e.gds.IssuerCertificates(), tl.TrustedCertificates)
}

// TestConcurrentFinish: of concurrent FinishRequest calls for one request
// exactly one gets the certificate.
func TestConcurrentFinish(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, AutoApprove: true})
	ctx := ctxT(t)
	appID := e.registerClient()
	clients := make([]*gds.PullClient, 4)
	for i := range clients {
		clients[i] = e.anonymous()
	}
	for range 3 {
		reqID, err := clients[0].StartNewKeyPairRequest(ctx, appID, nil)
		require.NoError(t, err)
		var wg sync.WaitGroup
		results := make([]error, len(clients))
		for i, c := range clients {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, results[i] = c.FinishRequest(ctx, appID, reqID)
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range results {
			if err == nil {
				ok++
				continue
			}
			require.True(t, errors.Is(err, ua.StatusBadNothingToDo) || errors.Is(err, ua.StatusBadInvalidArgument), err)
		}
		require.Equal(t, 1, ok)
	}
	_, certs, err := clients[0].GetCertificates(ctx, appID, nil)
	require.NoError(t, err)
	require.Len(t, certs, 3)

	// Concurrent registrations of one URI: one wins.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	admins := []*gds.PullClient{e.admin(), e.admin(), e.admin(), e.admin()}
	for i, a := range admins {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = a.RegisterApplication(ctx, record("urn:test:race"))
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else {
			require.ErrorIs(t, err, ua.StatusBadEntryExists)
		}
	}
	require.Equal(t, 1, ok)
}

// TestUnregisterWhileIssuing: an application unregistered while its
// certificate is being issued gets none.
func TestUnregisterWhileIssuing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, AutoApprove: true})
	ctx := ctxT(t)
	appID := e.registerClient()
	reqID, err := e.anonymous().StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	rid := e.gds.RequestID(reqID)

	// Mark the request as being issued, as FinishRequest does without the
	// lock, and unregister meanwhile.
	e.gds.mu.Lock()
	e.gds.issuing[rid] = true
	e.gds.mu.Unlock()
	_, err = e.anonymous().FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadNothingToDo, "issuing")
	e.gds.mu.Lock()
	delete(e.gds.issuing, rid)
	e.gds.mu.Unlock()
	require.NoError(t, e.admin().UnregisterApplication(ctx, appID))
	_, err = e.caAdmin().FinishRequest(ctx, appID, reqID)
	require.ErrorIs(t, err, ua.StatusBadNotFound)
}

// TestClose: a closed GDS answers Bad_ShutDown and writes nothing.
func TestClose(t *testing.T) {
	t.Parallel()
	var clk clock
	e := newEnv(t, Config{SelfAdmin: selfAdminAll, Now: clk.now, CRLLifetime: time.Hour})
	ctx := ctxT(t)
	appID := e.registerClient()
	self := e.anonymous()
	reqID, err := self.StartNewKeyPairRequest(ctx, appID, nil)
	require.NoError(t, err)
	push := gds.New(e.dial(dialOpts{user: userCAAdmin}))
	push.TrustList = e.gds.node(gdsid.DirectoryCertificateGroupsDefaultApplicationGroupTrustList)
	before := e.gds.TrustList()

	e.gds.Close()
	e.gds.Close()
	_, err = self.FindApplications(ctx, testClientURI)
	require.ErrorIs(t, err, ua.StatusBadShutdown)
	require.ErrorIs(t, e.gds.ApproveRequest(ctx, e.gds.RequestID(reqID), true), ErrClosed)
	require.ErrorIs(t, push.AddCertificate(ctx, pkiOf(t).CACert, true), ua.StatusBadShutdown)
	clk.advance(2 * time.Hour)
	require.Equal(t, before.TrustedCrls, e.gds.TrustList().TrustedCrls, "no CRL is renewed")
}
