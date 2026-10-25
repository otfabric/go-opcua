//go:build interop

// SPDX-License-Identifier: MIT

// Push certificate management (Part 12 §7) across stacks:
//
//	go-client-to-<peer>-server    package gds against the ServerConfiguration
//	                              object of open62541 (UA_ENABLE_GDS_PUSHMANAGEMENT),
//	                              UA-.NETStandard (ConfigurationNodeManager) and
//	                              node-opcua (node-opcua-server-configuration)
//	node-opcua-client-to-go-server  node-opcua's ClientPushCertificateManagement
//	                              (adapter `client push`) against server.WithPushManagement
//
// The adapters declare serverFeatures "push-management" and, for node-opcua,
// the client operation "push" (opcua-interop feat/gds). An image without them
// skips — also with OPCUA_INTEROP_REQUIRE_CAPABILITIES=1: the ledger rows stay
// unverified until an opcua-interop release with feat/gds is pinned.

package interop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// The SecurityAdmin user of the push fixture (baseline + this user).
const (
	pushAdminUser = "sec-admin"
	pushAdminPass = "sec-admin-password"
)

// requirePushFeature skips when the adapter image does not declare the push
// management feature. It never fails: the rows are unverified until the
// opcua-interop release with it is pinned.
func requirePushFeature(t *testing.T, imageEnv, defaultImage, list, feature string) {
	t.Helper()
	caps, image := imageCapabilities(t, imageEnv, defaultImage)
	have := caps.ServerFeatures
	if list == "clientOperations" {
		have = caps.ClientOperations
	}
	if !slices.Contains(have, feature) {
		t.Skipf("adapter %s (version %s) has no %s %q (opcua-interop feat/gds; set %s to such an image)",
			image, caps.Adapter.Version, list, feature, imageEnv)
	}
}

// pushFixtureDir writes the baseline fixture with the SecurityAdmin user
// added into a directory the containers can read and returns it.
func pushFixtureDir(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(interopFixtureDir(t), "baseline.json"))
	if err != nil {
		t.Fatalf("read the baseline fixture: %v", err)
	}
	var fx map[string]any
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode the baseline fixture: %v", err)
	}
	users, _ := fx["users"].([]any)
	fx["users"] = append(users, map[string]any{
		"username": pushAdminUser,
		"password": pushAdminPass,
		"roles":    []string{"AuthenticatedUser", "SecurityAdmin"},
	})
	out, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := containerScratchDir(t)
	if err := os.WriteFile(filepath.Join(dir, "baseline.json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := shareWithContainers(dir); err != nil {
		t.Fatalf("share the fixture with the containers: %v", err)
	}
	return dir
}

// pushPeer is a peer server with push certificate management.
type pushPeer struct {
	name      string // ledger name
	env       string
	image     string
	pki       string // test PKI identity of the server
	direction string
	// roles: the peer grants SecurityAdmin by the fixture roles and refuses
	// the methods to others; open62541 v1.5.9 has no roles and serves any
	// session on a SignAndEncrypt channel.
	roles bool
	// closesChannels: ApplyChanges closes the channels (open62541 v1.5.9
	// shuts them down after the response), so the test reconnects.
	closesChannels bool
	// applyIdle: the status of ApplyChanges without a pending change.
	applyIdle ua.StatusCode
}

var pushPeers = []pushPeer{
	{name: "open62541", env: "OPEN62541_IMAGE", image: defaultOpen62541Image, pki: "open62541-server",
		direction: "go-client-to-open62541-server", closesChannels: true, applyIdle: ua.StatusBadNothingToDo},
	{name: "dotnet", env: dotnetEnv, image: defaultDotnetImage, pki: "dotnet-server",
		direction: dirGoClientToDotnetServer, roles: true},
	{name: "node-opcua", env: nodeOpcuaEnv, image: defaultNodeOpcuaImage, pki: "node-opcua-server",
		direction: "go-client-to-node-opcua-server", roles: true, applyIdle: ua.StatusBadNothingToDo},
}

// pushClient connects to the peer over Basic256Sha256 SignAndEncrypt, as the
// SecurityAdmin user or anonymously.
func pushClient(t *testing.T, endpoint string, admin bool) *opcua.Client {
	t.Helper()
	tok := ua.UserTokenTypeAnonymous
	var opts []opcua.Option
	if admin {
		tok = ua.UserTokenTypeUserName
		opts = append(opts, opcua.AuthUsername(pushAdminUser, pushAdminPass))
	}
	c, err := connectSecureClient(t, endpoint, "Basic256Sha256", "SignAndEncrypt", tok, opts...)
	if err != nil {
		t.Fatalf("connect (admin %v): %v", admin, err)
	}
	return c
}

// applyChanges calls ApplyChanges and accepts the peer's status for "nothing
// pending" when idle is set.
func applyChanges(t *testing.T, ctx context.Context, g *gds.Client, p pushPeer, idle bool) {
	t.Helper()
	err := g.ApplyChanges(ctx)
	if err == nil || (idle && p.applyIdle != 0 && errors.Is(err, p.applyIdle)) {
		return
	}
	t.Fatalf("ApplyChanges: %v", err)
}

// readTrustList reads the whole trust list on a fresh admin session (the
// peer may close channels after ApplyChanges).
func readTrustList(t *testing.T, ctx context.Context, endpoint string) *ua.TrustListDataType {
	t.Helper()
	tl, err := gds.New(pushClient(t, endpoint, true)).ReadTrustList(ctx, ua.TrustListMasksAll)
	if err != nil {
		t.Fatalf("ReadTrustList: %v", err)
	}
	return tl
}

func containsCert(list [][]byte, c []byte) bool {
	return slices.ContainsFunc(list, func(x []byte) bool { return bytes.Equal(x, c) })
}

// TestCertMgmtPush_GoClient_PeerServers: package gds pushes to the
// ServerConfiguration object of each peer server.
func TestCertMgmtPush_GoClient_PeerServers(t *testing.T) {
	for _, p := range pushPeers {
		t.Run(p.name, func(t *testing.T) {
			requirePushFeature(t, p.env, p.image, "serverFeatures", "push-management")
			h := startSecureAdapterServerIn(t, p.env, p.image, p.pki, pushFixtureDir(t))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			t.Run("coverage/certmgmt.push.access/"+p.direction, func(t *testing.T) {
				props, err := gds.New(pushClient(t, h.endpoint, true)).Properties(ctx)
				if err != nil {
					t.Fatalf("Properties: %v", err)
				}
				t.Logf("%s: SupportedPrivateKeyFormats %v, MaxTrustListSize %d, CertificateTypes %v",
					p.name, props.SupportedPrivateKeyFormats, props.MaxTrustListSize, props.CertificateTypes)
				if !p.roles {
					return
				}
				anon := gds.New(pushClient(t, h.endpoint, false))
				if _, err := anon.ReadTrustList(ctx, ua.TrustListMasksAll); !errors.Is(err, ua.StatusBadUserAccessDenied) {
					t.Errorf("anonymous ReadTrustList: %v, want Bad_UserAccessDenied", err)
				}
				if _, err := anon.GetRejectedList(ctx); !errors.Is(err, ua.StatusBadUserAccessDenied) {
					t.Errorf("anonymous GetRejectedList: %v, want Bad_UserAccessDenied", err)
				}
			})

			t.Run("coverage/certmgmt.push.trust-list/"+p.direction, func(t *testing.T) {
				extra, _, err := testpki.SelfSigned("go-opcua interop push "+p.name, "urn:otfabric:interop:push")
				if err != nil {
					t.Fatal(err)
				}
				before := readTrustList(t, ctx, h.endpoint)
				if containsCert(before.TrustedCertificates, extra) {
					t.Fatal("the new certificate is trusted before AddCertificate")
				}
				g := gds.New(pushClient(t, h.endpoint, true))
				if err := g.AddCertificate(ctx, extra, true); err != nil {
					t.Fatalf("AddCertificate: %v", err)
				}
				applyChanges(t, ctx, g, p, true)
				after := readTrustList(t, ctx, h.endpoint)
				if !containsCert(after.TrustedCertificates, extra) {
					t.Fatalf("trusted certificates after AddCertificate + ApplyChanges: %d, the new one is missing",
						len(after.TrustedCertificates))
				}

				g = gds.New(pushClient(t, h.endpoint, true))
				if err := g.RemoveCertificate(ctx, gds.Thumbprint(extra), true); err != nil {
					t.Fatalf("RemoveCertificate: %v", err)
				}
				applyChanges(t, ctx, g, p, true)
				if containsCert(readTrustList(t, ctx, h.endpoint).TrustedCertificates, extra) {
					t.Fatal("the certificate is still trusted after RemoveCertificate + ApplyChanges")
				}

				// The whole list written back with the file methods.
				g = gds.New(pushClient(t, h.endpoint, true))
				cur, err := g.ReadTrustList(ctx, ua.TrustListMasksAll)
				if err != nil {
					t.Fatalf("ReadTrustList: %v", err)
				}
				cur.TrustedCertificates = append(cur.TrustedCertificates, extra)
				if _, err := g.WriteTrustList(ctx, cur); err != nil {
					t.Fatalf("WriteTrustList: %v", err)
				}
				applyChanges(t, ctx, g, p, true)
				if !containsCert(readTrustList(t, ctx, h.endpoint).TrustedCertificates, extra) {
					t.Fatal("the certificate written with Open / Write / CloseAndUpdate is not trusted")
				}
				// The go-opcua client (consumer, issued by the test CA) still connects.
				pushClient(t, h.endpoint, false)
			})

			t.Run("coverage/certmgmt.push.rejected-list/"+p.direction, func(t *testing.T) {
				rej, err := gds.New(pushClient(t, h.endpoint, true)).GetRejectedList(ctx)
				if err != nil {
					t.Fatalf("GetRejectedList: %v", err)
				}
				for i, c := range rej {
					if _, err := x509.ParseCertificate(c); err != nil {
						t.Errorf("rejected certificate %d does not parse: %v", i, err)
					}
				}
			})

			t.Run("coverage/certmgmt.push.certificate-update/"+p.direction, func(t *testing.T) {
				pushCertificateUpdate(t, ctx, h.endpoint, p)
			})
		})
	}
}

// pushCertificateUpdate: CreateSigningRequest for the existing key, the test
// CA signs it, UpdateCertificate (+ ApplyChanges) installs it and the
// endpoints present it.
func pushCertificateUpdate(t *testing.T, ctx context.Context, endpoint string, p pushPeer) {
	t.Helper()
	eps, err := opcua.GetEndpoints(ctx, endpoint)
	if err != nil {
		t.Fatalf("GetEndpoints: %v", err)
	}
	var old []byte
	for _, ep := range eps {
		if ep.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 {
			old = ep.ServerCertificate
		}
	}
	// The endpoint may carry the chain (Part 6 §6.2.3): the leaf comes first.
	chain, err := x509.ParseCertificates(old)
	if err != nil || len(chain) == 0 {
		t.Fatalf("server certificate: %v", err)
	}
	oldCert := chain[0]

	g := gds.New(pushClient(t, endpoint, true))
	csrDER, err := g.CreateSigningRequest(ctx, &gds.SigningRequest{
		CertificateGroup: gds.DefaultApplicationGroup,
		CertificateType:  gds.RsaSha256ApplicationCertificateType,
	})
	if err != nil {
		t.Fatalf("CreateSigningRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("the CSR does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if !publicKeysEqual(csr.PublicKey, oldCert.PublicKey) {
		t.Fatal("the CSR (RegeneratePrivateKey false) is not for the key of the server certificate")
	}
	if len(csr.URIs) == 0 {
		// The peer leaves the ApplicationUri out: take it over from the
		// current certificate, as a CA would from the application record.
		csr.URIs = oldCert.URIs
		csr.DNSNames = oldCert.DNSNames
	}

	caCert, caKey := loadTestCA(t)
	tmpl := testpki.CertTemplate(oldCert.Subject.CommonName, "")
	tmpl.Subject = oldCert.Subject
	tmpl.URIs, tmpl.DNSNames, tmpl.IPAddresses = csr.URIs, csr.DNSNames, csr.IPAddresses
	newDER, err := uapolicy.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issue the certificate: %v", err)
	}
	required, err := g.UpdateCertificate(ctx, &gds.CertificateUpdate{
		CertificateGroup:   gds.DefaultApplicationGroup,
		CertificateType:    gds.RsaSha256ApplicationCertificateType,
		Certificate:        newDER,
		IssuerCertificates: [][]byte{caCert.Raw},
	})
	if err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}
	if required {
		applyChanges(t, ctx, g, p, false)
	}

	// The endpoints advertise the new certificate, alone or followed by its
	// issuer (a chain, Part 6 §6.2.3); the peer may take a moment to rebuild
	// them after the ApplyChanges response.
	deadline := time.Now().Add(20 * time.Second)
	for {
		eps, err := opcua.GetEndpoints(ctx, endpoint)
		if err == nil && slices.ContainsFunc(eps, func(ep *ua.EndpointDescription) bool {
			return ep.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && bytes.HasPrefix(ep.ServerCertificate, newDER)
		}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Basic256Sha256 endpoints do not present the updated certificate (applyChangesRequired %v, err %v)", required, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	// A new secure channel validates it against the test CA.
	pushClient(t, endpoint, false)
}

func publicKeysEqual(a, b any) bool {
	ka, err1 := x509.MarshalPKIXPublicKey(a)
	kb, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(ka, kb)
}

// loadTestCA returns the CA of the test PKI with its key.
func loadTestCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	pki := pkiDir(t)
	ca := loadCACert(t, filepath.Join(pki, "ca", "ca.crt"))
	raw, err := os.ReadFile(filepath.Join(pki, "ca", "ca.key"))
	if err != nil {
		capabilityUnavailable(t, "test PKI has no CA key: %v", err)
	}
	key, err := uapolicy.ParsePrivateKey(raw)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	return ca, key
}

// startPushGoServer starts a go-opcua server with push management: the
// trust list trusts the test CA, the user sec-admin has the SecurityAdmin
// role.
func startPushGoServer(t *testing.T) (string, *server.Server) {
	t.Helper()
	ca := loadCACertDER(t)
	return startGoServerWithOptions(t,
		server.Certificate(loadGoServerCert(t)),
		server.PrivateKey(loadGoServerKey(t)),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == pushAdminUser && pass == pushAdminPass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if _, ok := tok.(*ua.UserNameIdentityToken); ok {
				return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), ua.RoleSecurityAdmin.NodeID()}
			}
			return server.DefaultRoleMapper(tok)
		}),
		server.WithPushManagement(server.PushManagement{
			TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{ca}},
		}),
	)
}

// pushClientResult is the result of the adapter's `client push`.
type pushClientResult struct {
	TrustList                 trustListJSON `json:"trustList"`
	TrustListAfter            trustListJSON `json:"trustListAfter"`
	CertificateSigningRequest string        `json:"certificateSigningRequest"`
	RejectedCertificates      []string      `json:"rejectedCertificates"`
}

type trustListJSON struct {
	SpecifiedLists      uint32   `json:"specifiedLists"`
	TrustedCertificates []string `json:"trustedCertificates"`
}

func (l trustListJSON) has(der []byte) bool {
	return slices.Contains(l.TrustedCertificates, base64.StdEncoding.EncodeToString(der))
}

// runNodeOpcuaPush runs the node-opcua adapter's `client push` against the go
// server as the SecurityAdmin user, with certificate (DER) mounted at
// /certs/add.der.
func runNodeOpcuaPush(t *testing.T, endpoint string, certificate []byte, args ...string) (adapterResult, pushClientResult) {
	t.Helper()
	pki := pkiDir(t)
	dir := containerScratchDir(t)
	add := filepath.Join(dir, "add.der")
	if err := os.WriteFile(add, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := shareWithContainers(dir); err != nil {
		t.Fatal(err)
	}
	cmdArgs := []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", filepath.Join(pki, "node-opcua-client", "cert.crt") + ":/certs/cert.crt:ro",
		"-v", filepath.Join(pki, "node-opcua-client", "cert.key") + ":/certs/cert.key:ro",
		"-v", filepath.Join(pki, "ca", "ca.crt") + ":/certs/ca.crt:ro",
		"-v", add + ":/certs/add.der:ro",
		getEnvOr(nodeOpcuaEnv, defaultNodeOpcuaImage),
		"client", "push",
		"--endpoint", strings.ReplaceAll(endpoint, "localhost", "host.docker.internal"),
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--trust-list", "/certs/ca.crt",
		"--security-policy", "Basic256Sha256",
		"--security-mode", "SignAndEncrypt",
		"--username", pushAdminUser,
		"--password", pushAdminPass,
		"--add-certificate", "/certs/add.der",
	}
	raw, _ := runClientContainer(t, append(cmdArgs, args...))
	res, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse the push result: %v\nraw: %s", err, raw)
	}
	var items []pushClientResult
	if err := json.Unmarshal(res.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("push results %s: %v", res.Results, err)
	}
	return res, items[0]
}

// TestCertMgmtPush_NodeOpcuaClient_GoServer: node-opcua's
// ClientPushCertificateManagement (node-opcua-server-configuration) pushes to
// server.WithPushManagement.
func TestCertMgmtPush_NodeOpcuaClient_GoServer(t *testing.T) {
	requireNodeOpcuaImage(t)
	requirePushFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "clientOperations", "push")
	const dir = "node-opcua-client-to-go-server"

	t.Run("coverage/certmgmt.push.trust-list/"+dir, func(t *testing.T) {
		endpoint, srv := startPushGoServer(t)
		extra, _, err := testpki.SelfSigned("go-opcua interop push node-opcua", "urn:otfabric:interop:push")
		if err != nil {
			t.Fatal(err)
		}
		res, out := runNodeOpcuaPush(t, endpoint, extra, "--apply")
		if !res.Success {
			t.Fatalf("client push failed: %s %s", res.ServiceResult.Name, res.Error)
		}
		if !out.TrustList.has(loadCACertDER(t)) || out.TrustList.has(extra) {
			t.Fatalf("the trust list read before AddCertificate: %+v", out.TrustList)
		}
		if !out.TrustListAfter.has(extra) {
			t.Fatalf("the trust list read after ApplyChanges lacks the added certificate: %+v", out.TrustListAfter)
		}
		if !containsCert(srv.TrustList().TrustedCertificates, extra) {
			t.Fatal("the go server does not trust the certificate node-opcua added")
		}

		// RemoveCertificate by thumbprint, applied.
		res, out = runNodeOpcuaPush(t, endpoint, extra, "--remove-certificate", gds.Thumbprint(extra), "--apply")
		if res.Success {
			// AddCertificate of a trusted certificate replaces it; then it is removed.
			if containsCert(srv.TrustList().TrustedCertificates, extra) {
				t.Fatalf("the certificate is still trusted after RemoveCertificate: %+v", out.TrustListAfter)
			}
		} else {
			t.Fatalf("client push --remove-certificate failed: %s %s", res.ServiceResult.Name, res.Error)
		}
	})

	t.Run("coverage/certmgmt.push.certificate-update/"+dir, func(t *testing.T) {
		endpoint, _ := startPushGoServer(t)
		extra, _, err := testpki.SelfSigned("go-opcua interop push csr", "urn:otfabric:interop:push")
		if err != nil {
			t.Fatal(err)
		}
		res, out := runNodeOpcuaPush(t, endpoint, extra, "--csr")
		if !res.Success {
			t.Fatalf("client push --csr failed: %s %s", res.ServiceResult.Name, res.Error)
		}
		der, err := base64.StdEncoding.DecodeString(out.CertificateSigningRequest)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatalf("the CSR does not parse: %v", err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("CSR signature: %v", err)
		}
		cert, err := x509.ParseCertificate(loadGoServerCert(t))
		if err != nil {
			t.Fatal(err)
		}
		if !publicKeysEqual(csr.PublicKey, cert.PublicKey) {
			t.Fatal("the CSR is not for the key of the go server certificate")
		}
	})

	t.Run("coverage/certmgmt.push.rejected-list/"+dir, func(t *testing.T) {
		endpoint, _ := startPushGoServer(t)
		// A client the go server does not trust is rejected and reported.
		untrusted := filepath.Join(pkiDir(t), "untrusted", "cert.crt")
		if _, err := os.Stat(untrusted); err != nil {
			capabilityUnavailable(t, "test PKI has no untrusted identity: %v", err)
		}
		r := runSecureAdapterClientResult(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "untrusted", endpoint,
			"read", "Basic256Sha256", "SignAndEncrypt", "--node", "i=2259")
		if r.Success {
			t.Fatal("the untrusted client was accepted")
		}
		untrustedDER := readCertDER(t, untrusted)
		extra, _, err := testpki.SelfSigned("go-opcua interop push rejected", "urn:otfabric:interop:push")
		if err != nil {
			t.Fatal(err)
		}
		res, out := runNodeOpcuaPush(t, endpoint, extra)
		if !res.Success {
			t.Fatalf("client push failed: %s %s", res.ServiceResult.Name, res.Error)
		}
		if !slices.Contains(out.RejectedCertificates, base64.StdEncoding.EncodeToString(untrustedDER)) {
			t.Fatalf("GetRejectedList (%d certificates) lacks the untrusted client", len(out.RejectedCertificates))
		}
	})

	t.Run("coverage/certmgmt.push.access/"+dir, func(t *testing.T) {
		endpoint, _ := startPushGoServer(t)
		extra, _, err := testpki.SelfSigned("go-opcua interop push access", "urn:otfabric:interop:push")
		if err != nil {
			t.Fatal(err)
		}
		// Wrong password: no session. The SecurityAdmin user over
		// SignAndEncrypt is covered by the subtests above; here an
		// anonymous push is refused.
		res, _ := runNodeOpcuaPushAnonymous(t, endpoint, extra)
		if res.Success || !statusCodeNameHas(res.ServiceResult, "UserAccessDenied") {
			t.Fatalf("anonymous push: success %v, %s; want Bad_UserAccessDenied", res.Success, res.ServiceResult.Name)
		}
	})
}

// runNodeOpcuaPushAnonymous is `client push --add-certificate` without a user.
func runNodeOpcuaPushAnonymous(t *testing.T, endpoint string, certificate []byte) (adapterResult, string) {
	t.Helper()
	pki := pkiDir(t)
	dir := containerScratchDir(t)
	add := filepath.Join(dir, "add.der")
	if err := os.WriteFile(add, certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := shareWithContainers(dir); err != nil {
		t.Fatal(err)
	}
	raw, _ := runClientContainer(t, []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", filepath.Join(pki, "node-opcua-client", "cert.crt") + ":/certs/cert.crt:ro",
		"-v", filepath.Join(pki, "node-opcua-client", "cert.key") + ":/certs/cert.key:ro",
		"-v", filepath.Join(pki, "ca", "ca.crt") + ":/certs/ca.crt:ro",
		"-v", add + ":/certs/add.der:ro",
		getEnvOr(nodeOpcuaEnv, defaultNodeOpcuaImage),
		"client", "push",
		"--endpoint", strings.ReplaceAll(endpoint, "localhost", "host.docker.internal"),
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--trust-list", "/certs/ca.crt",
		"--security-policy", "Basic256Sha256",
		"--security-mode", "SignAndEncrypt",
		"--add-certificate", "/certs/add.der",
	})
	res, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse the push result: %v\nraw: %s", err, raw)
	}
	return res, string(raw)
}

func readCertDER(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := pem.Decode(raw); b != nil {
		return b.Bytes
	}
	return raw
}
