// SPDX-License-Identifier: MIT

package certmgmt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

const (
	adminUser = "admin"
	adminPass = "admin-pw"
)

var tlsClientType = ua.NewNumericNodeID(0, id.TLSClientCertificateType)

// fixture is the PKI of the scenario.
type fixture struct {
	p *testpki.PKI

	// The trust lists: listA trusts the CA and revokes the issued client by
	// a CRL, listB does not trust the CA, listC trusts the CA without the
	// CRL. Both A and B reject the issued client; a list with the CA of A
	// and the CRLs of B would accept it.
	listA, listB, listC *ua.TrustListDataType
	crl                 []byte

	// The application instance certificates the admins install, with their
	// PEM keys.
	certs [][]byte
	keys  [][]byte

	// partners and partnersTL are the certificate group of the application
	// "Partners" (a TLS client certificate and a trust list) and its
	// TrustList.
	partners, partnersTL *ua.NodeID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	p, err := testpki.Get()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(p.CACert)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := x509.ParseCertificate(p.IssuedCert)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.CreateRevocationList(nil, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: issued.SerialNumber, RevocationTime: time.Now()}},
	}, ca, p.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		p:     p,
		crl:   crl,
		listA: &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksAll), TrustedCertificates: [][]byte{p.ClientCert, p.CACert}, TrustedCrls: [][]byte{crl}},
		listB: &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksAll), TrustedCertificates: [][]byte{p.ClientCert}},
		listC: &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksAll), TrustedCertificates: [][]byte{p.ClientCert, p.CACert}},
	}

	// The server certificate itself, one issued by the CA for its key, and
	// one for another key (the stranger's: no client uses it as server).
	pemKey := func(k *rsa.PrivateKey) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	}
	csr, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{Subject: p.ServerCertX509.Subject, URIs: p.ServerCertX509.URIs, DNSNames: p.ServerCertX509.DNSNames}, p.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	byCA, err := testpki.IssueFromCSR(csr, ca, p.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := testpki.CertTemplate("rekeyed server", testpki.ServerAppURI)
	rekeyed, err := x509.CreateCertificate(nil, tmpl, tmpl, &p.StrangerKey.PublicKey, p.StrangerKey)
	if err != nil {
		t.Fatal(err)
	}
	f.certs = [][]byte{p.ServerCert, byCA, rekeyed}
	f.keys = [][]byte{pemKey(p.ServerKey), pemKey(p.ServerKey), pemKey(p.StrangerKey)}
	return f
}

func (f *fixture) installed(cert []byte) bool {
	for _, c := range f.certs {
		if bytes.Equal(c, cert) {
			return true
		}
	}
	return false
}

func startServer(t *testing.T, f *fixture, wd *chaoskit.Watchdog) (*server.Server, string) {
	t.Helper()
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(f.p.ServerCert),
		server.PrivateKey(f.p.ServerKey),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(u, p string) error {
			if u == adminUser && p == adminPass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if _, ok := tok.(*ua.UserNameIdentityToken); ok {
				return []*ua.NodeID{ua.RoleSecurityAdmin.NodeID()}
			}
			return server.DefaultRoleMapper(tok)
		}),
		server.WithPushManagement(server.PushManagement{
			TrustList: f.listB,
			CertificateGroups: []server.CertificateGroup{{
				Name:             "Partners",
				CertificateTypes: []*ua.NodeID{tlsClientType},
				TrustList:        f.listB,
			}},
			// The alarms are evaluated all the time, during the changes.
			Alarms: &server.CertificateAlarms{ExpirationLimit: 48 * time.Hour, CheckInterval: 2 * time.Millisecond},
		}),
		server.SetLogger(chaoskit.Logger()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := wd.Do("Start", func() error { return srv.Start(context.Background()) }); err != nil {
		t.Fatal(err)
	}
	f.partners = srv.CertificateGroupID("Partners")
	f.partnersTL = ua.NewStringNodeID(f.partners.Namespace(), f.partners.StringID()+".TrustList")
	return srv, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
}

// dial connects over Basic256Sha256 SignAndEncrypt with the application
// certificate; admin selects the SecurityAdmin user.
func dial(url string, cert []byte, key *rsa.PrivateKey, admin bool) (*opcua.Client, []byte, error) {
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	var ep *ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && e.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
			ep = e
		}
	}
	if ep == nil {
		return nil, nil, errors.New("no Basic256Sha256 endpoint")
	}
	tok := ua.UserTokenTypeAnonymous
	if admin {
		tok = ua.UserTokenTypeUserName
	}
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(ep, tok),
		opcua.Certificate(cert),
		opcua.PrivateKey(key),
		opcua.InsecureSkipVerify(),
		opcua.AutoReconnect(false),
		opcua.DialTimeout(30 * time.Second),
		opcua.RequestTimeout(30 * time.Second),
	}
	if admin {
		opts = append(opts, opcua.AuthUsername(adminUser, adminPass))
	}
	c, err := opcua.NewClient(url, opts...)
	if err != nil {
		return nil, ep.ServerCertificate, err
	}
	if err := c.Connect(ctx); err != nil {
		_ = c.Close(context.Background())
		return nil, ep.ServerCertificate, err
	}
	return c, ep.ServerCertificate, nil
}

// certRejection reports whether err is the rejection of the client
// certificate.
func certRejection(err error) bool {
	for _, sc := range []ua.StatusCode{ua.StatusBadCertificateUntrusted, ua.StatusBadCertificateRevoked,
		ua.StatusBadCertificateIssuerRevoked, ua.StatusBadCertificateInvalid} {
		if errors.Is(err, sc) {
			return true
		}
	}
	return false
}

// TestPushChurn: admins change the trust list and the server certificate
// while clients connect; see the package documentation for the invariants.
func TestPushChurn(t *testing.T) {
	seed := chaoskit.Seed(t)
	dur := chaoskit.Duration(t, 3*time.Second)
	wd := chaoskit.NewWatchdog(t)
	f := newFixture(t)
	verifyLeaks := chaoskit.LeakCheck(t)
	srv, url := startServer(t, f, wd)
	p := f.p

	var errs chaoskit.ErrSink
	var tally chaoskit.ErrorTally
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var strangerTried atomic.Bool

	// A long-lived client: its channel and session survive every change.
	reader, _, err := dial(url, p.ClientCert, p.ClientKey, false)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			err := wd.Do("reader Read", func() error {
				ctx, cancel := chaoskit.OpCtx()
				defer cancel()
				_, err := reader.ReadValue(ctx, ua.NewNumericNodeID(0, id.ServerServerStatusState))
				return err
			})
			if err != nil {
				errs.Addf("the long-lived client failed to read: %v", err)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Clients that connect and disconnect: always trusted, never trusted,
	// and rejected by every list of the churn for one reason or another.
	type dialer struct {
		name  string
		cert  []byte
		key   *rsa.PrivateKey
		check func(err error)
	}
	dialers := []dialer{
		{"trusted", p.ClientCert, p.ClientKey, func(err error) {
			if certRejection(err) {
				errs.Addf("a certificate every trust list trusts was rejected: %v", err)
			}
		}},
		{"stranger", p.StrangerCert, p.StrangerKey, func(err error) {
			strangerTried.Store(true)
			if err == nil {
				errs.Addf("a certificate no trust list trusts was accepted")
			}
		}},
		{"revoked", p.IssuedCert, p.IssuedKey, func(err error) {
			if err == nil {
				errs.Addf("the issued client was accepted: validated against a mix of two trust lists")
			}
		}},
	}
	for i := 0; i < 2*len(dialers); i++ {
		d := dialers[i%len(dialers)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				var c *opcua.Client
				var advertised []byte
				err := wd.Do("dial "+d.name, func() error {
					var err error
					c, advertised, err = dial(url, d.cert, d.key, false)
					return err
				})
				tally.Add(err)
				if advertised != nil && !f.installed(advertised) {
					errs.Addf("an endpoint advertises a certificate nobody installed")
				}
				d.check(err)
				if err != nil {
					continue
				}
				if got := c.SecureChannel().RemoteCertificate(); !f.installed(got) {
					errs.Addf("a channel presents a certificate nobody installed")
				}
				_ = wd.Do("close "+d.name, func() error { return c.Close(context.Background()) })
			}
		}()
	}

	// The admins.
	for a := 0; a < 2; a++ {
		rng := rand.New(rand.NewSource(seed + int64(a)))
		wg.Add(1)
		go func() {
			defer wg.Done()
			var c *opcua.Client
			defer func() {
				if c != nil {
					_ = c.Close(context.Background())
				}
			}()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if c == nil || rng.Intn(20) == 0 {
					// Drop the session, perhaps in the middle of a
					// transaction.
					if c != nil {
						_ = wd.Do("admin close", func() error { return c.Close(context.Background()) })
						c = nil
					}
					err := wd.Do("admin dial", func() error {
						var err error
						c, _, err = dial(url, p.ClientCert, p.ClientKey, true)
						return err
					})
					if certRejection(err) {
						errs.Addf("the admin certificate was rejected: %v", err)
					}
					if err != nil {
						continue
					}
				}
				g := gds.New(c)
				err := wd.Do("admin op", func() error { return adminOp(rng, g, f) })
				switch {
				case err == nil, chaoskit.IsConnectionError(err):
				case errors.Is(err, ua.StatusBadTransactionPending), errors.Is(err, ua.StatusBadInvalidArgument),
					errors.Is(err, ua.StatusBadInvalidState), errors.Is(err, ua.StatusBadNotWritable), errors.Is(err, ua.StatusBadNotReadable):
					// another admin's transaction or open file
				default:
					errs.Addf("admin: %v", err)
				}
			}
		}()
	}

	time.Sleep(dur)
	close(stop)
	wd.Wait("the workers", &wg)
	_ = wd.Do("reader close", func() error { return reader.Close(context.Background()) })
	t.Logf("dials: %s", tally.String())

	// A final, deterministic round: the changes take effect.
	c, _, err := dial(url, p.ClientCert, p.ClientKey, true)
	if err != nil {
		t.Fatalf("final admin: %v", err)
	}
	g := gds.New(c)
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	if _, err := g.WriteTrustList(ctx, f.listC); err != nil {
		t.Fatalf("WriteTrustList: %v", err)
	}
	if _, err := g.UpdateCertificate(ctx, &gds.CertificateUpdate{CertificateType: gds.RsaSha256ApplicationCertificateType,
		Certificate: f.certs[0], PrivateKeyFormat: "PEM", PrivateKey: f.keys[0]}); err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}
	if err := g.ApplyChanges(ctx); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	issued, _, err := dial(url, p.IssuedCert, p.IssuedKey, false)
	if err != nil {
		t.Fatalf("the issued client is trusted now: %v", err)
	}
	if got := issued.SecureChannel().RemoteCertificate(); !bytes.Equal(got, f.certs[0]) {
		t.Error("a new channel does not present the certificate applied last")
	}
	_ = issued.Close(ctx)
	if _, _, err := dial(url, p.StrangerCert, p.StrangerKey, false); err == nil {
		t.Error("the stranger was accepted")
	}
	rejected, err := g.GetRejectedList(ctx)
	if err != nil {
		t.Fatalf("GetRejectedList: %v", err)
	}
	if strangerTried.Load() && !containsCert(rejected, p.StrangerCert) {
		t.Error("the rejected list does not report the stranger")
	}
	if !containsCert(srv.TrustList().TrustedCertificates, p.CACert) {
		t.Error("the trust list applied last is not the server's")
	}
	// The group of the application: its trust list and certificate take
	// effect too.
	if _, err := g.WithTrustList(f.partnersTL).WriteTrustList(ctx, f.listC); err != nil {
		t.Fatalf("WriteTrustList of the group: %v", err)
	}
	partnerCert, err := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{CertificateGroup: f.partners, SubjectName: "CN=partners"})
	if err != nil {
		t.Fatalf("CreateSelfSignedCertificate of the group: %v", err)
	}
	if err := g.ApplyChanges(ctx); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if err := srv.VerifyGroupCertificate(f.partners, p.IssuedCert); err != nil {
		t.Errorf("the trust list of the group applied last does not trust the issued client: %v", err)
	}
	if got, _, _ := srv.GroupCertificate(f.partners, nil); !bytes.Equal(got, partnerCert) {
		t.Error("the certificate of the group is not the one applied last")
	}
	_ = c.Close(ctx)
	_ = wd.Do("Close", srv.Close)
	errs.Report(t)
	verifyLeaks()
}

func containsCert(list [][]byte, cert []byte) bool {
	for _, c := range list {
		if bytes.Equal(c, cert) {
			return true
		}
	}
	return false
}

// adminOp makes one change, then applies, cancels or keeps the transaction.
func adminOp(rng *rand.Rand, g *gds.Client, f *fixture) error {
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	p := f.p
	var err error
	switch rng.Intn(22) {
	case 0:
		_, err = g.WriteTrustList(ctx, f.listA)
	case 1:
		_, err = g.WriteTrustList(ctx, f.listB)
	case 2:
		// Partial updates that keep the issued client rejected: add the
		// CRL, or drop the CA.
		_, err = g.WriteTrustList(ctx, &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksTrustedCrls), TrustedCrls: [][]byte{f.crl}})
	case 3:
		_, err = g.WriteTrustList(ctx, &ua.TrustListDataType{SpecifiedLists: uint32(ua.TrustListMasksTrustedCertificates), TrustedCertificates: [][]byte{p.ClientCert}})
	case 4:
		err = g.AddCertificate(ctx, p.UserCert, rng.Intn(2) == 0)
	case 5:
		err = g.RemoveCertificate(ctx, gds.Thumbprint(p.UserCert), rng.Intn(2) == 0)
	case 6:
		i := rng.Intn(len(f.certs))
		_, err = g.UpdateCertificate(ctx, &gds.CertificateUpdate{CertificateType: gds.RsaSha256ApplicationCertificateType,
			Certificate: f.certs[i], PrivateKeyFormat: "PEM", PrivateKey: f.keys[i]})
	case 7:
		var csr []byte
		if csr, err = g.CreateSigningRequest(ctx, &gds.SigningRequest{CertificateType: gds.RsaSha256ApplicationCertificateType}); err == nil {
			var req *x509.CertificateRequest
			if req, err = x509.ParseCertificateRequest(csr); err == nil && !isServerKey(req.PublicKey, f) {
				err = errors.New("the CSR is not for a key of the installed certificates")
			}
		}
	case 8:
		_, err = g.GetRejectedList(ctx)
	case 9:
		var tl *ua.TrustListDataType
		if tl, err = g.ReadTrustList(ctx, ua.TrustListMasksAll); err == nil && !containsCert(tl.TrustedCertificates, p.ClientCert) {
			err = errors.New("the trust list read does not trust the admin")
		}
	case 10:
		// Back to the trust list (listB) and certificate (certs[0]) the
		// server started with.
		return g.ResetToServerDefaults(ctx)
	case 11:
		var certs [][]byte
		if _, certs, err = g.GetCertificates(ctx, nil); err == nil && (len(certs) != 1 || !f.installed(certs[0])) {
			err = errors.New("GetCertificates returns a certificate nobody installed")
		}
	case 12:
		var d *gds.TransactionDiagnostics
		if d, err = g.TransactionDiagnostics(ctx); err == nil && d.StartTime.IsZero() && (len(d.AffectedTrustLists) > 0 || len(d.AffectedCertificateGroups) > 0) {
			err = errors.New("TransactionDiagnostics: affected nodes without a transaction")
		}
	case 13:
		// The HTTPS certificate (no HTTPS listener: it changes only the
		// group's certificate).
		_, err = g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{CertificateGroup: gds.DefaultHTTPSGroup, LifetimeInDays: 1})
	case 14:
		err = g.WithTrustList(gds.UserTokenTrustList).AddCertificate(ctx, p.UserCert, true)
	case 15:
		_, err = g.WithTrustList(gds.HTTPSTrustList).WriteTrustList(ctx, f.listA)
	case 16:
		// The HTTPS certificate goes (Bad_InvalidState once it is gone).
		err = g.DeleteCertificate(ctx, gds.DefaultHTTPSGroup, nil)
	case 17:
		// The group of the application: a new TLS client certificate, its
		// deletion, its trust list.
		_, err = g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{CertificateGroup: f.partners, SubjectName: "CN=partners", LifetimeInDays: 1})
	case 18:
		err = g.DeleteCertificate(ctx, f.partners, tlsClientType)
	case 19:
		_, err = g.WithTrustList(f.partnersTL).WriteTrustList(ctx, f.listA)
	case 20:
		var types []*ua.NodeID
		if types, _, err = g.GetCertificates(ctx, f.partners); err == nil && (len(types) > 1 || len(types) == 1 && !types[0].Equal(tlsClientType)) {
			err = fmt.Errorf("GetCertificates of the group of the application returns the types %v", types)
		}
	case 21:
		// The certificate the endpoints advertise is never deleted:
		// ApplyChanges refuses it, and the admin cancels.
		if err = g.DeleteCertificate(ctx, nil, gds.RsaSha256ApplicationCertificateType); err != nil {
			return err
		}
		if err = g.ApplyChanges(ctx); err == nil {
			return errors.New("ApplyChanges deleted the certificate of the endpoints")
		}
		if !errors.Is(err, ua.StatusBadInvalidState) {
			return err
		}
		return g.CancelChanges(ctx)
	}
	if err != nil {
		return err
	}
	switch r := rng.Intn(10); {
	case r < 7:
		return g.ApplyChanges(ctx)
	case r < 9:
		return g.CancelChanges(ctx)
	}
	return nil
}

func isServerKey(pub crypto.PublicKey, f *fixture) bool {
	k, ok := pub.(*rsa.PublicKey)
	return ok && (k.Equal(&f.p.ServerKey.PublicKey) || k.Equal(&f.p.StrangerKey.PublicKey))
}
