//go:build interop

// SPDX-License-Identifier: MIT

// The GDS pull model (Part 12 §6, §7.9) against UA-.NETStandard: the
// opcua-interop adapter dotnet-gds (opcua-interop v0.15.0, CLIENT_CONTRACT
// §16) runs the stack's Global Discovery Server and GDS client on
// OPCFoundation.NetStandard.Opc.Ua.Gds.Server / .Gds.Client 2.0.1.
//
//	go-client-to-dotnet-server   gds.PullClient → GlobalDiscoverySampleServer
//	dotnet-client-to-go-server   GlobalDiscoveryServerClient (`client gds-pull`) → gdsserver
//
//	DOTNET_GDS_IMAGE   Docker image of the dotnet-gds adapter (default:
//	                   defaultDotnetGDSImage; an opt-in peer, see
//	                   optional_peers_test.go)
//
// The ledger rows are those of the dotnet peer (testdata/ledger-dotnet.json).

package interop

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsserver"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

const (
	dotnetGDSEnv = "DOTNET_GDS_IMAGE"
	// defaultDotnetGDSImage is the dotnet-gds adapter of opcua-interop
	// v0.15.0, by digest; an opt-in peer until it moves to the pinned peers.
	defaultDotnetGDSImage = "ghcr.io/otfabric/opcua-interop-dotnet-gds@sha256:c8f5b05d58a955840aaf819bcd9aeb1af62db8500c5bad360e6c4081ec9f176d"

	// The GDS administrator of the fixture (opcua-interop
	// fixtures/gds/fixture.json) and of the go GDS.
	gdsAdminUser = "gds-admin"
	gdsAdminPass = "gds-admin-password"
)

func init() {
	optionalPeerImageEnv[dotnetGDSEnv] = true
	peerInteropVersion[dotnetGDSEnv] = "v0.15.0"
}

// requireDotnetGDS skips (or fails with OPCUA_INTEROP_REQUIRE_CAPABILITIES=1)
// unless the dotnet-gds image declares gds-pull in list ("serverFeatures" or
// "clientOperations").
func requireDotnetGDS(t *testing.T, list string) {
	t.Helper()
	caps, image := imageCapabilities(t, dotnetGDSEnv, defaultDotnetGDSImage)
	requirePinnedVersion(t, dotnetGDSEnv, caps, image)
	have := caps.ServerFeatures
	if list == "clientOperations" {
		have = caps.ClientOperations
	}
	if !slices.Contains(have, "gds-pull") {
		capabilityUnavailable(t, "adapter %s (version %s) has no %s gds-pull (opcua-interop v0.15.0 dotnet-gds)", image, caps.Adapter.Version, list)
	}
}

// TestDotnetGDSPull_GoClient_DotnetServer: gds.PullClient against the
// Global Discovery Server of UA-.NETStandard 2.0.1.
func TestDotnetGDSPull_GoClient_DotnetServer(t *testing.T) {
	requireDotnetGDS(t, "serverFeatures")
	h := startSecureAdapterServerIn(t, dotnetGDSEnv, defaultDotnetGDSImage, "dotnet-server",
		fixtureDirWithUser(t, gdsAdminUser, gdsAdminPass, "AuthenticatedUser", "DiscoveryAdmin", "CertificateAuthorityAdmin", "SecurityAdmin"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin := func(t *testing.T) *gds.PullClient {
		t.Helper()
		c, err := connectSecureClient(t, h.endpoint, "Basic256Sha256", "SignAndEncrypt", ua.UserTokenTypeUserName,
			opcua.AuthUsername(gdsAdminUser, gdsAdminPass))
		if err != nil {
			t.Fatalf("connect as %s: %v", gdsAdminUser, err)
		}
		return gds.NewPullClient(c)
	}
	p := admin(t)
	uri := "urn:otfabric:interop:gds-pull:go-client"
	rec := &gds.ApplicationRecord{
		ApplicationURI:     uri,
		ApplicationType:    ua.ApplicationTypeServer,
		ApplicationNames:   []*ua.LocalizedText{ua.NewLocalizedTextWithLocale("go-opcua interop", "en-US")},
		ProductURI:         "urn:otfabric:go-opcua",
		DiscoveryURLs:      []string{"opc.tcp://localhost:4851"},
		ServerCapabilities: []string{"NA"},
	}
	var appID *ua.NodeID

	t.Run("coverage/gds.pull.directory/"+dirGoClientToDotnetServer, func(t *testing.T) {
		var err error
		if appID, err = p.RegisterApplication(ctx, rec); err != nil {
			t.Fatalf("RegisterApplication: %v", err)
		}
		found, err := p.FindApplications(ctx, uri)
		if err != nil || len(found) != 1 || !found[0].ApplicationID.Equal(appID) {
			t.Fatalf("FindApplications: %v %+v", err, found)
		}
		got, err := p.GetApplication(ctx, appID)
		if err != nil || got.ApplicationURI != uri || got.ApplicationType != ua.ApplicationTypeServer {
			t.Fatalf("GetApplication: %v %+v", err, got)
		}
		upd := *got
		upd.ApplicationNames = []*ua.LocalizedText{ua.NewLocalizedTextWithLocale("go-opcua interop updated", "en-US")}
		if err := p.UpdateApplication(ctx, &upd); err != nil {
			t.Fatalf("UpdateApplication: %v", err)
		}
		if got, err = p.GetApplication(ctx, appID); err != nil || got.ApplicationNames[0].Text != "go-opcua interop updated" {
			t.Fatalf("GetApplication after UpdateApplication: %v %+v", err, got)
		}
		servers, err := p.QueryServers(ctx, &gds.ServerQuery{ApplicationURI: uri})
		if err != nil {
			t.Fatalf("QueryServers: %v", err)
		}
		t.Logf("QueryServers: %d servers", len(servers.Servers))
		apps, err := p.QueryApplications(ctx, &gds.ApplicationQuery{ApplicationURI: uri})
		if err != nil || len(apps.Applications) != 1 {
			t.Fatalf("QueryApplications: %v %+v", err, apps)
		}
	})
	if appID == nil {
		t.Fatal("no application")
	}

	var issued []byte
	t.Run("coverage/gds.pull.certificate-request/"+dirGoClientToDotnetServer, func(t *testing.T) {
		key, err := testpki.NewKey(testpki.CurveP256)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := gds.NewCertificateRequest(key, uri, "CN=go-opcua interop/O=otfabric", []string{"localhost"})
		if err != nil {
			t.Fatal(err)
		}
		reqID, err := p.StartSigningRequest(ctx, appID, nil, gds.EccNistP256ApplicationCertificateType, csr)
		if err != nil {
			t.Fatalf("StartSigningRequest: %v", err)
		}
		res, err := p.WaitForCertificate(ctx, appID, reqID, 200*time.Millisecond)
		if err != nil {
			t.Fatalf("FinishRequest: %v", err)
		}
		if !uapolicy.KeyMatchesCertificate(key, res.Certificate) {
			t.Fatal("the certificate is not for the key of the request")
		}
		checkIssued(t, res, uri)

		// A key pair the GDS generates, delivered as PFX with a password.
		reqID, err = p.StartNewKeyPairRequest(ctx, appID, &gds.NewKeyPairRequest{
			CertificateType: gds.EccNistP256ApplicationCertificateType, SubjectName: "CN=go-opcua interop pfx",
			DomainNames: []string{"localhost"}, PrivateKeyFormat: gds.PrivateKeyFormatPFX, PrivateKeyPassword: "pfx-password"})
		if err != nil {
			t.Fatalf("StartNewKeyPairRequest: %v", err)
		}
		res, err = p.WaitForCertificate(ctx, appID, reqID, 200*time.Millisecond)
		if err != nil {
			t.Fatalf("FinishRequest (new key pair): %v", err)
		}
		k, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPFX, res.PrivateKey, "pfx-password")
		if err != nil {
			t.Fatalf("the PFX of UA-.NETStandard: %v", err)
		}
		if !uapolicy.KeyMatchesCertificate(k, res.Certificate) {
			t.Fatal("the PFX key is not that of the certificate")
		}
		checkIssued(t, res, uri)
		issued = res.Certificate
	})

	t.Run("coverage/gds.pull.trust-list/"+dirGoClientToDotnetServer, func(t *testing.T) {
		groups, err := p.GetCertificateGroups(ctx, appID)
		if err != nil || len(groups) == 0 {
			t.Fatalf("GetCertificateGroups: %v %v", err, groups)
		}
		def, err := p.DefaultApplicationGroup(ctx)
		if err != nil || !slices.ContainsFunc(groups, def.Equal) {
			t.Fatalf("DefaultApplicationGroup %v not in %v (%v)", def, groups, err)
		}
		if _, err := p.GetTrustList(ctx, appID, nil); err != nil {
			t.Fatalf("GetTrustList: %v", err)
		}
		tl, err := p.ReadTrustList(ctx, appID, nil)
		if err != nil {
			t.Fatalf("reading the TrustList: %v", err)
		}
		if len(tl.TrustedCertificates) == 0 || len(tl.TrustedCrls) == 0 {
			t.Fatalf("trust list without CAs or CRLs: %d certificates, %d CRLs", len(tl.TrustedCertificates), len(tl.TrustedCrls))
		}
		if issued != nil {
			cert, _ := x509.ParseCertificate(issued)
			if !slices.ContainsFunc(tl.TrustedCertificates, func(c []byte) bool {
				ca, err := x509.ParseCertificate(c)
				return err == nil && cert.CheckSignatureFrom(ca) == nil
			}) {
				t.Fatal("the CA of the issued certificate is not in the trust list")
			}
		}
		update, err := p.GetCertificateStatus(ctx, appID, nil, gds.EccNistP256ApplicationCertificateType)
		if err != nil {
			t.Fatalf("GetCertificateStatus: %v", err)
		}
		t.Logf("GetCertificateStatus: updateRequired %v", update)
	})

	t.Run("coverage/gds.pull.revocation/"+dirGoClientToDotnetServer, func(t *testing.T) {
		if issued == nil {
			t.Skip("no certificate issued")
		}
		cert, err := x509.ParseCertificate(issued)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.RevokeCertificate(ctx, appID, issued); err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}
		// The CRL of the trust list lists the certificate.
		tl, err := admin(t).ReadTrustList(ctx, appID, nil)
		if err != nil {
			t.Fatalf("reading the TrustList: %v", err)
		}
		if !crlsRevoke(tl.TrustedCrls, cert) {
			t.Fatalf("no CRL of the trust list revokes the certificate of %s serial %x", cert.Issuer, cert.SerialNumber)
		}
		// UA-.NETStandard 2.0.1 reads its CRL (1.5.378 checked online only and
		// answered BadCertificateRevocationUnknown).
		status, _, err := p.CheckRevocationStatus(ctx, issued)
		if err != nil {
			t.Fatalf("CheckRevocationStatus: %v", err)
		}
		if status != ua.StatusBadCertificateRevoked {
			t.Fatalf("CheckRevocationStatus of a revoked certificate: %v", status)
		}
		if err := p.UnregisterApplication(ctx, appID); err != nil {
			t.Fatalf("UnregisterApplication: %v", err)
		}
		if found, err := p.FindApplications(ctx, uri); err != nil || len(found) != 0 {
			t.Fatalf("FindApplications after UnregisterApplication: %v %d", err, len(found))
		}
	})
}

// checkIssued checks an issued certificate: the URI of the application and
// the issuer chain FinishRequest returned.
func checkIssued(t *testing.T, res *gds.IssuedCertificate, uri string) {
	t.Helper()
	cert, err := x509.ParseCertificate(res.Certificate)
	if err != nil {
		t.Fatalf("issued certificate: %v", err)
	}
	if len(cert.URIs) == 0 || cert.URIs[0].String() != uri {
		t.Fatalf("issued certificate URIs %v, want %s", cert.URIs, uri)
	}
	if len(res.IssuerCertificates) == 0 {
		t.Fatal("no issuer certificates")
	}
	ca, err := x509.ParseCertificate(res.IssuerCertificates[0])
	if err != nil {
		t.Fatalf("issuer certificate: %v", err)
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("the issued certificate is not signed by the returned issuer: %v", err)
	}
}

// crlsRevoke reports whether one of the CRLs revokes cert.
func crlsRevoke(crls [][]byte, cert *x509.Certificate) bool {
	for _, b := range crls {
		crl, err := x509.ParseRevocationList(b)
		if err != nil || !bytes.Equal(crl.RawIssuer, cert.RawIssuer) {
			continue
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return true
			}
		}
	}
	return false
}

// startGDSGoServer starts a go-opcua server with gdsserver: the RSA CA is
// that of the test PKI, the user gds-admin has the DiscoveryAdmin and
// CertificateAuthorityAdmin roles.
func startGDSGoServer(t *testing.T) (string, *gdsserver.GDS) {
	t.Helper()
	caCert, caKey := loadTestCA(t)
	keyDER, err := uapolicy.MarshalPrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	var g *gdsserver.GDS
	s, err := server.New(
		server.ListenOn("0.0.0.0:0"),
		server.EndPoint("host.docker.internal", 0),
		server.Certificate(loadGoServerCert(t)),
		server.PrivateKey(loadGoServerKey(t)),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == gdsAdminUser && pass == gdsAdminPass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if _, ok := tok.(*ua.UserNameIdentityToken); ok {
				return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), g.DiscoveryAdminRole(), g.CertificateAuthorityAdminRole()}
			}
			return server.DefaultRoleMapper(tok)
		}),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	g, err = gdsserver.Attach(s, gdsserver.Config{
		CertificateTypes: []*ua.NodeID{gds.RsaSha256ApplicationCertificateType, gds.EccNistP256ApplicationCertificateType},
		Issuers:          []*gdsserver.Issuer{{Name: "RSA", Certificate: caCert.Raw, PrivateKey: keyDER}},
		AutoApprove:      true,
		Logger:           slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("gdsserver.Attach: %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() {
		g.Close()
		_ = s.Close()
	})
	return fmt.Sprintf("opc.tcp://localhost:%d", s.Port()), g
}

// gdsPullResult is the result of the adapter's `client gds-pull` (CLIENT_CONTRACT §16.2).
type gdsPullResult struct {
	FindApplications   []string      `json:"findApplications"`
	Registered         bool          `json:"registered"`
	ApplicationID      string        `json:"applicationId"`
	RequestKind        string        `json:"requestKind"`
	RequestID          string        `json:"requestId"`
	Certificate        string        `json:"certificate"`
	PrivateKeyFormat   string        `json:"privateKeyFormat"`
	PrivateKey         string        `json:"privateKey"`
	IssuerCertificates []string      `json:"issuerCertificates"`
	CertificateGroups  []string      `json:"certificateGroups"`
	TrustListID        string        `json:"trustListId"`
	TrustList          trustListJSON `json:"trustList"`
	UpdateRequired     *bool         `json:"updateRequired"`
	RevokeStatus       statusCodeObj `json:"revokeStatus"`
	CertificateStatus  statusCodeObj `json:"certificateStatus"`
	UnregisterStatus   statusCodeObj `json:"unregisterStatus"`
}

// gdsPullClient is an adapter with `client gds-pull` (CLIENT_CONTRACT
// §16.2); the GDS pull tests against the go server run once per such
// adapter.
type gdsPullClient struct {
	name         string // adapter name, in the ApplicationUris
	env          string // image env variable
	defaultImage string
	pki          string // client identity in the test PKI
	direction    string // ledger direction
}

// runGDSPull runs `client gds-pull` of c against endpoint as gds-admin over
// Basic256Sha256 SignAndEncrypt.
func runGDSPull(t *testing.T, c gdsPullClient, endpoint string, args ...string) gdsPullResult {
	t.Helper()
	res := runSecureAdapterClient(t, c.env, c.defaultImage, c.pki, endpoint, "gds-pull",
		"Basic256Sha256", "SignAndEncrypt", append([]string{"--username", gdsAdminUser, "--password", gdsAdminPass}, args...)...)
	if !res.Success {
		t.Fatalf("client gds-pull %v: %s %s\n%s", args, res.ServiceResult.Name, res.Error, res.Results)
	}
	var items []gdsPullResult
	if err := json.Unmarshal(res.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("gds-pull results %s: %v", res.Results, err)
	}
	return items[0]
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}

// TestDotnetGDSPull_DotnetClient_GoServer: GlobalDiscoveryServerClient of
// UA-.NETStandard 2.0.1 against gdsserver.
func TestDotnetGDSPull_DotnetClient_GoServer(t *testing.T) {
	requireDotnetGDS(t, "clientOperations")
	testGDSPullGoServer(t, dotnetGDSPullClient)
}

// dotnetGDSPullClient is the dotnet-gds adapter's `client gds-pull`.
var dotnetGDSPullClient = gdsPullClient{
	name: "dotnet", env: dotnetGDSEnv, defaultImage: defaultDotnetGDSImage, pki: "dotnet-client",
	direction: dirDotnetClientToGoServer,
}

// testGDSPullGoServer runs the `client gds-pull` of c against gdsserver.
func testGDSPullGoServer(t *testing.T, c gdsPullClient) {
	endpoint, g := startGDSGoServer(t)
	ca := loadCACertDER(t)
	group := g.DefaultApplicationGroup().String()
	uri := "urn:otfabric:interop:gds-pull:" + c.name + "-client"
	dir := c.direction

	var csr gdsPullResult
	t.Run("coverage/gds.pull.directory/"+dir, func(t *testing.T) {
		csr = runGDSPull(t, c, endpoint, "--app-uri", uri, "--request", "csr", "--certificate-type", "RsaSha256")
		if !csr.Registered || len(csr.FindApplications) != 0 || csr.ApplicationID == "" {
			t.Fatalf("FindApplications / RegisterApplication: %+v", csr)
		}
		// A second run finds the record.
		again := runGDSPull(t, c, endpoint, "--app-uri", uri, "--request", "csr", "--certificate-type", "NistP256")
		if again.Registered || !slices.Equal(again.FindApplications, []string{csr.ApplicationID}) || again.ApplicationID != csr.ApplicationID {
			t.Fatalf("the second run did not find the record: %+v", again)
		}
	})

	t.Run("coverage/gds.pull.certificate-request/"+dir, func(t *testing.T) {
		if csr.Certificate == "" {
			t.Fatal("no certificate from the CSR run")
		}
		cert, err := x509.ParseCertificate(decodeB64(t, csr.Certificate))
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.URIs) == 0 || cert.URIs[0].String() != uri {
			t.Fatalf("certificate URIs %v", cert.URIs)
		}
		if len(csr.IssuerCertificates) == 0 || !bytes.Equal(decodeB64(t, csr.IssuerCertificates[0]), ca) {
			t.Fatal("the issuer is not the RSA CA of the go GDS")
		}
		nk := runGDSPull(t, c, endpoint, "--app-uri", uri+":nk", "--request", "new-key-pair", "--certificate-type", "NistP256")
		if nk.PrivateKeyFormat != "PEM" {
			t.Fatalf("privateKeyFormat %q", nk.PrivateKeyFormat)
		}
		key, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, decodeB64(t, nk.PrivateKey), "")
		if err != nil {
			t.Fatalf("the private key gdsserver delivered: %v", err)
		}
		if !uapolicy.KeyMatchesCertificate(key, decodeB64(t, nk.Certificate)) {
			t.Fatal("the private key is not that of the certificate")
		}
	})

	t.Run("coverage/gds.pull.trust-list/"+dir, func(t *testing.T) {
		if !slices.Contains(csr.CertificateGroups, group) {
			t.Fatalf("certificateGroups %v, want %s", csr.CertificateGroups, group)
		}
		if csr.TrustListID == "" || !csr.TrustList.has(ca) {
			t.Fatalf("trust list %s: %+v", csr.TrustListID, csr.TrustList)
		}
		if csr.UpdateRequired == nil || *csr.UpdateRequired {
			t.Fatalf("updateRequired %v after issuing", csr.UpdateRequired)
		}
	})

	t.Run("coverage/gds.pull.revocation/"+dir, func(t *testing.T) {
		res := runGDSPull(t, c, endpoint, "--app-uri", uri+":revoke", "--request", "new-key-pair",
			"--certificate-type", "NistP256", "--revoke", "--unregister")
		if res.RevokeStatus.Code != 0 || res.UnregisterStatus.Code != 0 {
			t.Fatalf("revoke %+v unregister %+v", res.RevokeStatus, res.UnregisterStatus)
		}
		if !statusCodeIs(res.CertificateStatus, ua.StatusBadCertificateRevoked) {
			t.Fatalf("certificateStatus %+v, want BadCertificateRevoked", res.CertificateStatus)
		}
		cert, err := x509.ParseCertificate(decodeB64(t, res.Certificate))
		if err != nil {
			t.Fatal(err)
		}
		if !crlsRevoke(g.TrustList().TrustedCrls, cert) {
			t.Fatal("the CRL of the go GDS does not revoke the certificate")
		}
		for _, a := range g.Requests() {
			if a.ApplicationURI == uri+":revoke" {
				t.Fatalf("a request of the unregistered application is left: %+v", a)
			}
		}
	})
}
