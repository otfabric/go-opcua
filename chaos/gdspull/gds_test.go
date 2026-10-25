// SPDX-License-Identifier: MIT

package gdspull

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsserver"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

const (
	adminUser = "admin"
	adminPass = "admin-pw"
)

// gdsEnv is a GDS that restarts on the same Store.
type gdsEnv struct {
	t     *testing.T
	p     *testpki.PKI
	store *gdsserver.MemoryStore
	cfg   gdsserver.Config

	// mu is held for reading by who uses the current GDS (ApproveRequest)
	// and for writing by a restart.
	mu  sync.RWMutex
	srv *server.Server
	g   *gdsserver.GDS
	url string
	gen int // incremented by every restart
}

func newGDSEnv(t *testing.T) *gdsEnv {
	t.Helper()
	p, err := testpki.Get()
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := x509.MarshalPKCS8PrivateKey(p.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	e := &gdsEnv{t: t, p: p, store: gdsserver.NewMemoryStore()}
	e.cfg = gdsserver.Config{
		Store:            e.store,
		CertificateTypes: []*ua.NodeID{gds.EccNistP256ApplicationCertificateType, gds.RsaSha256ApplicationCertificateType},
		Issuers:          []*gdsserver.Issuer{{Name: "RSA", Certificate: p.CACert, PrivateKey: caKey}},
		Logger:           slog.New(slog.DiscardHandler),
		MaxRequests:      64,
	}
	if err := e.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.g.Close()
		_ = e.srv.Close()
	})
	return e
}

// start starts a server with a GDS on the Store; e.mu is held or not yet
// shared.
func (e *gdsEnv) start() error {
	var g atomic.Pointer[gdsserver.GDS]
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(e.p.ServerCert),
		server.PrivateKey(e.p.ServerKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == adminUser && pass == adminPass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(ua.IdentityToken) []*ua.NodeID {
			return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), g.Load().DiscoveryAdminRole(), g.Load().CertificateAuthorityAdminRole()}
		}),
		server.SetLogger(chaoskit.Logger()),
	)
	if err != nil {
		return err
	}
	gd, err := gdsserver.Attach(srv, e.cfg)
	if err != nil {
		return err
	}
	g.Store(gd)
	if err := srv.Start(context.Background()); err != nil {
		return err
	}
	e.srv, e.g, e.url = srv, gd, fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
	return nil
}

// restart stops the GDS (waiting for the calls in flight), closes the
// server and starts a new one on the Store.
func (e *gdsEnv) restart() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.g.Close()
	_ = e.srv.Close()
	e.gen++
	return e.start()
}

func (e *gdsEnv) current() (*gdsserver.GDS, string, int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.g, e.url, e.gen
}

// approve approves or rejects a request with the current GDS.
func (e *gdsEnv) approve(ctx context.Context, reqID *ua.NodeID, ok bool) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.g.ApproveRequest(ctx, e.g.RequestID(reqID), ok)
}

// dial connects an admin client to the current server.
func (e *gdsEnv) dial() (*opcua.Client, *gds.PullClient, error) {
	_, url, _ := e.current()
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	var ep *ua.EndpointDescription
	for _, x := range eps {
		if x.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
			ep = x
		}
	}
	if ep == nil {
		return nil, nil, errors.New("no endpoint")
	}
	c, err := opcua.NewClient(url,
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
		opcua.Certificate(e.p.ClientCert),
		opcua.PrivateKey(e.p.ClientKey),
		opcua.InsecureSkipVerify(),
		opcua.AuthUsername(adminUser, adminPass),
		opcua.AutoReconnect(false),
		opcua.DialTimeout(10*time.Second),
		opcua.RequestTimeout(10*time.Second),
	)
	if err != nil {
		return nil, nil, err
	}
	if err := c.Connect(ctx); err != nil {
		_ = c.Close(context.Background())
		return nil, nil, err
	}
	return c, gds.NewPullClient(c), nil
}

// ledger records what the clients did, for the invariants.
type ledger struct {
	mu        sync.Mutex
	issued    map[string]string // request id → certificate (DER)
	serials   map[string]bool
	revoked   [][]byte
	apps      map[string]bool // URI → registered and not unregistered
	uncertain map[string]bool // URIs whose last operation has no known outcome
}

func newLedger() *ledger {
	return &ledger{issued: map[string]string{}, serials: map[string]bool{}, apps: map[string]bool{}, uncertain: map[string]bool{}}
}

// checkCert checks an issued certificate.
func checkCert(errs *chaoskit.ErrSink, cas [][]byte, uri string, der []byte) {
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil {
		errs.Addf("an issued certificate does not parse: %v", err)
		return
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != uri {
		errs.Addf("certificate for %s carries %v", uri, cert.URIs)
	}
	for _, c := range cas {
		ca, err := x509.ParseCertificate(c)
		if err == nil && cert.CheckSignatureFrom(ca) == nil {
			return
		}
	}
	errs.Addf("certificate for %s is signed by no CA of the GDS", uri)
}

// TestGDSRestartMidRequest: requests in every state survive a restart of
// the GDS, also one whose FinishRequest was in flight.
func TestGDSRestartMidRequest(t *testing.T) {
	wd := chaoskit.NewWatchdog(t)
	verifyLeaks := chaoskit.LeakCheck(t)
	e := newGDSEnv(t)
	ctx := context.Background()
	c, pc, err := e.dial()
	if err != nil {
		t.Fatal(err)
	}
	rec := &gds.ApplicationRecord{
		ApplicationURI:   "urn:chaos:restart",
		ApplicationType:  ua.ApplicationTypeServer,
		ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedText("restart")},
		ProductURI:       "urn:chaos",
		DiscoveryURLs:    []string{"opc.tcp://localhost:4840"},
	}
	appID, err := pc.RegisterApplication(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	var pending, approved, rejected, racing []*ua.NodeID
	for i := range 4 {
		ids := []*[]*ua.NodeID{&pending, &approved, &rejected, &racing}
		for range 2 {
			id, err := pc.StartNewKeyPairRequest(ctx, appID, nil)
			if err != nil {
				t.Fatal(err)
			}
			*ids[i] = append(*ids[i], id)
		}
	}
	for _, id := range append(approved, racing...) {
		if err := e.approve(ctx, id, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range rejected {
		if err := e.approve(ctx, id, false); err != nil {
			t.Fatal(err)
		}
	}

	// FinishRequest calls race with the restart: each completes before the
	// GDS stops, or fails with a connection error and is repeated after.
	type result struct {
		id  *ua.NodeID
		res *gds.IssuedCertificate
		err error
	}
	results := make(chan result, len(racing))
	var wg sync.WaitGroup
	for _, id := range racing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var r *gds.IssuedCertificate
			err := wd.Do("FinishRequest", func() error {
				var err error
				r, err = pc.FinishRequest(ctx, appID, id)
				return err
			})
			results <- result{id, r, err}
		}()
	}
	if err := wd.Do("restart", e.restart); err != nil {
		t.Fatal(err)
	}
	wd.Wait("FinishRequest", &wg)
	close(results)
	_ = c.Close(ctx)

	c, pc, err = e.dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	g, _, _ := e.current()
	cas := g.IssuerCertificates()
	issued := 0
	for r := range results {
		switch {
		case r.err == nil:
			issued++
			checkCert(new(chaoskit.ErrSink), cas, rec.ApplicationURI, r.res.Certificate)
			if _, err := pc.FinishRequest(ctx, appID, r.id); !errors.Is(err, ua.StatusBadInvalidArgument) {
				t.Errorf("a completed request is finished again: %v", err)
			}
		case chaoskit.IsConnectionError(r.err):
			// Completed by the old GDS before it stopped, or not at all:
			// the new one has the outcome.
			res, err := pc.FinishRequest(ctx, appID, r.id)
			switch {
			case err == nil:
				issued++
				checkCert(new(chaoskit.ErrSink), cas, rec.ApplicationURI, res.Certificate)
			case errors.Is(err, ua.StatusBadInvalidArgument):
				issued++ // the old GDS issued it; the response was lost
			default:
				t.Errorf("FinishRequest after the restart: %v", err)
			}
		default:
			t.Errorf("FinishRequest during the restart: %v", r.err)
		}
	}
	if issued != len(racing) {
		t.Errorf("%d of %d racing requests issued", issued, len(racing))
	}
	for _, id := range pending {
		if _, err := pc.FinishRequest(ctx, appID, id); !errors.Is(err, ua.StatusBadNothingToDo) {
			t.Errorf("pending request after the restart: %v", err)
		}
	}
	for _, id := range rejected {
		if _, err := pc.FinishRequest(ctx, appID, id); !errors.Is(err, ua.StatusBadRequestNotAllowed) {
			t.Errorf("rejected request after the restart: %v", err)
		}
	}
	for _, id := range approved {
		res, err := pc.FinishRequest(ctx, appID, id)
		if err != nil {
			t.Fatalf("approved request after the restart: %v", err)
		}
		checkCert(new(chaoskit.ErrSink), cas, rec.ApplicationURI, res.Certificate)
	}
	_, certs, err := pc.GetCertificates(ctx, appID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != len(racing)+len(approved) {
		t.Errorf("%d certificates recorded, want %d", len(certs), len(racing)+len(approved))
	}
	_ = c.Close(ctx)
	e.mu.Lock()
	e.g.Close()
	_ = e.srv.Close()
	e.mu.Unlock()
	verifyLeaks()
}

// TestGDSChurn: see the package documentation.
func TestGDSChurn(t *testing.T) {
	seed := chaoskit.Seed(t)
	dur := chaoskit.Duration(t, 3*time.Second)
	wd := chaoskit.NewWatchdog(t)
	verifyLeaks := chaoskit.LeakCheck(t)
	e := newGDSEnv(t)
	led := newLedger()
	var errs chaoskit.ErrSink
	var tally chaoskit.ErrorTally

	deadline := time.Now().Add(dur)
	approvals := make(chan *ua.NodeID, 256)
	restarts := make(chan struct{}, 1)
	var ops atomic.Int64
	var wg, aux sync.WaitGroup

	// The approver approves two of three requests and rejects the rest.
	aux.Add(1)
	go func() {
		defer aux.Done()
		r := rand.New(rand.NewSource(seed))
		for id := range approvals {
			err := e.approve(context.Background(), id, r.Intn(3) != 0)
			if err != nil && !errors.Is(err, gdsserver.ErrUnknownRequest) {
				errs.Addf("ApproveRequest: %v", err)
			}
		}
	}()
	// The restarter restarts the GDS when asked.
	aux.Add(1)
	go func() {
		defer aux.Done()
		for range restarts {
			if err := wd.Do("restart", e.restart); err != nil {
				errs.Addf("restart: %v", err)
				return
			}
		}
	}()

	worker := func(w int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(seed + int64(w)))
		var c *opcua.Client
		var pc *gds.PullClient
		defer func() {
			if c != nil {
				_ = c.Close(context.Background())
			}
		}()
		type app struct {
			id    *ua.NodeID
			uri   string
			reqs  []*ua.NodeID
			certs [][]byte
		}
		var apps []*app
		for n := 0; time.Now().Before(deadline); n++ {
			if c == nil {
				var err error
				if c, pc, err = e.dial(); err != nil {
					tally.Add(err)
					c = nil
					continue
				}
			}
			if ops.Add(1)%40 == 0 {
				select {
				case restarts <- struct{}{}:
				default:
				}
			}
			ctx, cancel := chaoskit.OpCtx()
			var err error
			uri := ""
			switch op := r.Intn(10); {
			case op == 0 || len(apps) == 0:
				uri = fmt.Sprintf("urn:chaos:w%d:a%d", w, n)
				rec := &gds.ApplicationRecord{
					ApplicationURI:   uri,
					ApplicationType:  ua.ApplicationTypeServer,
					ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedText(uri)},
					ProductURI:       "urn:chaos",
					DiscoveryURLs:    []string{fmt.Sprintf("opc.tcp://w%d.example:%d", w, 4840+n)},
				}
				var id *ua.NodeID
				err = wd.Do("RegisterApplication", func() error { id, err = pc.RegisterApplication(ctx, rec); return err })
				led.mu.Lock()
				if err == nil {
					led.apps[uri] = true
					apps = append(apps, &app{id: id, uri: uri})
				} else if chaoskit.IsConnectionError(err) {
					led.uncertain[uri] = true
				}
				led.mu.Unlock()
			case op <= 3:
				a := apps[r.Intn(len(apps))]
				var id *ua.NodeID
				if r.Intn(2) == 0 {
					err = wd.Do("StartNewKeyPairRequest", func() error {
						id, err = pc.StartNewKeyPairRequest(ctx, a.id, &gds.NewKeyPairRequest{CertificateType: gds.EccNistP256ApplicationCertificateType})
						return err
					})
				} else {
					key, kerr := testpki.NewKey(testpki.CurveP256)
					if kerr != nil {
						errs.Addf("key: %v", kerr)
						cancel()
						return
					}
					csr, cerr := gds.NewCertificateRequest(key, a.uri, "CN=chaos", nil)
					if cerr != nil {
						errs.Addf("csr: %v", cerr)
						cancel()
						return
					}
					err = wd.Do("StartSigningRequest", func() error {
						id, err = pc.StartSigningRequest(ctx, a.id, nil, gds.EccNistP256ApplicationCertificateType, csr)
						return err
					})
				}
				if err == nil {
					a.reqs = append(a.reqs, id)
					approvals <- id
				}
			case op <= 6:
				a := apps[r.Intn(len(apps))]
				if len(a.reqs) == 0 {
					break
				}
				i := r.Intn(len(a.reqs))
				id := a.reqs[i]
				var res *gds.IssuedCertificate
				err = wd.Do("FinishRequest", func() error { res, err = pc.FinishRequest(ctx, a.id, id); return err })
				switch {
				case err == nil:
					checkCert(&errs, e.issuers(), a.uri, res.Certificate)
					cert, perr := x509.ParseCertificate(res.Certificate)
					led.mu.Lock()
					if prev, dup := led.issued[id.String()]; dup {
						errs.Addf("request %v issued twice (%d bytes before)", id, len(prev))
					}
					led.issued[id.String()] = string(res.Certificate)
					if perr == nil {
						if led.serials[cert.SerialNumber.String()] {
							errs.Addf("serial number %v issued twice", cert.SerialNumber)
						}
						led.serials[cert.SerialNumber.String()] = true
					}
					led.mu.Unlock()
					a.certs = append(a.certs, res.Certificate)
					a.reqs = append(a.reqs[:i], a.reqs[i+1:]...)
				case errors.Is(err, ua.StatusBadRequestNotAllowed), errors.Is(err, ua.StatusBadInvalidArgument):
					a.reqs = append(a.reqs[:i], a.reqs[i+1:]...)
				}
			case op == 7:
				a := apps[r.Intn(len(apps))]
				if len(a.certs) == 0 {
					break
				}
				cert := a.certs[0]
				err = wd.Do("RevokeCertificate", func() error { return pc.RevokeCertificate(ctx, a.id, cert) })
				if err == nil {
					led.mu.Lock()
					led.revoked = append(led.revoked, cert)
					led.mu.Unlock()
					a.certs = a.certs[1:]
				}
			case op == 8:
				err = wd.Do("QueryServers", func() error {
					_, err := pc.QueryServers(ctx, &gds.ServerQuery{MaxRecordsToReturn: 10})
					return err
				})
			default:
				i := r.Intn(len(apps))
				a := apps[i]
				err = wd.Do("UnregisterApplication", func() error { return pc.UnregisterApplication(ctx, a.id) })
				led.mu.Lock()
				switch {
				case err == nil:
					delete(led.apps, a.uri)
					apps = append(apps[:i], apps[i+1:]...)
				case chaoskit.IsConnectionError(err):
					led.uncertain[a.uri] = true
					apps = append(apps[:i], apps[i+1:]...)
				}
				led.mu.Unlock()
			}
			cancel()
			tally.Add(err)
			if err != nil && chaoskit.IsConnectionError(err) {
				_ = c.Close(context.Background())
				c = nil
				continue
			}
			if err != nil && !errors.Is(err, ua.StatusBadNothingToDo) && !errors.Is(err, ua.StatusBadRequestNotAllowed) &&
				!errors.Is(err, ua.StatusBadInvalidArgument) && !errors.Is(err, ua.StatusBadTooManyOperations) {
				errs.Addf("unexpected error: %v", err)
			}
		}
	}
	for w := range 4 {
		wg.Add(1)
		go worker(w)
	}
	wd.Wait("workers", &wg)
	close(approvals)
	close(restarts)
	wd.Wait("approver and restarter", &aux)

	// A last restart, then the invariants.
	if err := e.restart(); err != nil {
		t.Fatal(err)
	}
	c, pc, err := e.dial()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	led.mu.Lock()
	for uri, ok := range led.apps {
		if !ok || led.uncertain[uri] {
			continue
		}
		found, err := pc.FindApplications(ctx, uri)
		if err != nil || len(found) != 1 {
			errs.Addf("registered application %s not found after the restart: %v", uri, err)
		}
	}
	for _, cert := range led.revoked {
		status, _, err := pc.CheckRevocationStatus(ctx, cert)
		if err != nil || status != ua.StatusBadCertificateRevoked {
			errs.Addf("revoked certificate reported as %v (%v)", status, err)
		}
	}
	led.mu.Unlock()
	_ = c.Close(ctx)
	t.Logf("operations: %s", tally.String())
	errs.Report(t)
	e.mu.Lock()
	e.g.Close()
	_ = e.srv.Close()
	e.mu.Unlock()
	verifyLeaks()
}

// issuers returns the CA certificates of the current GDS.
func (e *gdsEnv) issuers() [][]byte {
	g, _, _ := e.current()
	return g.IssuerCertificates()
}
