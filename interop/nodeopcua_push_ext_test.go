//go:build interop

// SPDX-License-Identifier: MIT

// The node-opcua adapter features of opcua-interop v0.15.0 (unreleased when
// these tests were written; built from the opcua-interop branch
// feat/push-ext):
//
//	node-opcua-client-to-go-server   `client push` with --group,
//	                                 --get-certificates, --create-self-signed,
//	                                 --delete-certificate, --update-certificate
//	                                 (PEM / PFX key), --reset-to-defaults and
//	                                 --transaction-diagnostics against
//	                                 server.WithPushManagement; `client query`
//	                                 (QueryFirst / QueryNext) against the
//	                                 go-opcua Query service set
//	go-client-to-node-opcua-server   the alarm fixture's condition branches
//	                                 (s=Alarms.Clear) and AudibleEnabled /
//	                                 AudibleSound
//
// The features are gated on the capabilities the adapter advertises
// (clientFeatures push-groups / push-certificates /
// push-transaction-diagnostics, clientOperations query, serverFeatures
// alarms-branches / alarms-audible). Until the pinned image has them the
// tests skip, also under OPCUA_INTEROP_REQUIRE_CAPABILITIES=1; run them
// against a local build with
//
//	NODE_OPCUA_IMAGE=opcua-interop-node-opcua:push-ext go test -tags=interop -run 'PushExt|NodeOpcuaClient_Query|AlarmBranches|AlarmAudible' ./interop/
//
// COVERAGE: testdata/ledger-node-opcua.json certmgmt.push.get-certificates,
// certmgmt.push.create-self-signed, certmgmt.push.delete-certificate,
// certmgmt.push.https-group, certmgmt.push.usertoken-group,
// certmgmt.push.pfx, certmgmt.push.transaction-diagnostics,
// certmgmt.push.reset-to-defaults, query.first, query.next, alarms.branches,
// alarms.audible-sound

package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// pushExtClient is an adapter whose `client push` has the flags of
// opcua-interop v0.15.0 (CLIENT_CONTRACT §1 "push flags"); the push tests
// against the go server run once per such adapter.
type pushExtClient struct {
	name         string // adapter name, in subjects and certificate names
	env          string // image env variable
	defaultImage string
	pki          string // client identity in the test PKI
	direction    string // ledger direction
	// require skips (or fails) unless the adapter image is usable.
	require func(t *testing.T) *adapterCaps
	// coreRows: the adapter's certmgmt.push.trust-list and
	// certmgmt.push.certificate-update rows are verified here too (node-opcua
	// has them from TestCertMgmtPush_NodeOpcuaClient_GoServer).
	coreRows bool
}

// requireV015 skips (or fails when REQUIRE_CAPABILITIES=1) when the adapter
// image of pc does not advertise a capability of opcua-interop v0.15.0
// (list: clientOperations, clientFeatures or serverFeatures).
func requireV015(t *testing.T, pc pushExtClient, list, capability string) {
	t.Helper()
	caps := pc.require(t)
	requirePinnedVersion(t, pc.env, caps, pc.defaultImage)
	have := map[string][]string{
		"clientOperations": caps.ClientOperations,
		"clientFeatures":   caps.ClientFeatures,
		"serverFeatures":   caps.ServerFeatures,
	}[list]
	if !slices.Contains(have, capability) {
		capabilityUnavailable(t, "the %s adapter (version %s) has no %s %q: need opcua-interop v0.15.0; "+
			"set %s to such an image", pc.name, caps.Adapter.Version, list, capability, pc.env)
	}
}

// requireNodeOpcuaV015 is requireV015 for the node-opcua adapter.
func requireNodeOpcuaV015(t *testing.T, list, capability string) {
	t.Helper()
	requireV015(t, nodeOpcuaPushClient, list, capability)
}

// pushExtResult is the result of `client push` with the v0.15.0 keys
// (CLIENT_CONTRACT §4 "push").
type pushExtResult struct {
	CertificateGroupID                string             `json:"certificateGroupId"`
	TrustList                         trustListJSON      `json:"trustList"`
	TrustListAfter                    *trustListJSON     `json:"trustListAfter"`
	AddCertificateStatus              *statusCodeObj     `json:"addCertificateStatus"`
	RemoveCertificateStatus           *statusCodeObj     `json:"removeCertificateStatus"`
	GetCertificatesStatus             *statusCodeObj     `json:"getCertificatesStatus"`
	CertificateTypeIDs                []string           `json:"certificateTypeIds"`
	Certificates                      []string           `json:"certificates"`
	CreateSelfSignedCertificateStatus *statusCodeObj     `json:"createSelfSignedCertificateStatus"`
	SelfSignedCertificate             string             `json:"selfSignedCertificate"`
	DeleteCertificateStatus           *statusCodeObj     `json:"deleteCertificateStatus"`
	UpdateCertificateStatus           *statusCodeObj     `json:"updateCertificateStatus"`
	ApplyChangesRequired              *bool              `json:"applyChangesRequired"`
	CertificateSigningRequest         string             `json:"certificateSigningRequest"`
	ResetToServerDefaultsStatus       *statusCodeObj     `json:"resetToServerDefaultsStatus"`
	ApplyChangesStatus                *statusCodeObj     `json:"applyChangesStatus"`
	CancelChangesStatus               *statusCodeObj     `json:"cancelChangesStatus"`
	TransactionDiagnosticsStatus      *statusCodeObj     `json:"transactionDiagnosticsStatus"`
	TransactionDiagnostics            *txDiagnosticsJSON `json:"transactionDiagnostics"`
}

type txDiagnosticsJSON struct {
	StartTime                 *time.Time    `json:"startTime"`
	EndTime                   *time.Time    `json:"endTime"`
	Result                    statusCodeObj `json:"result"`
	AffectedTrustLists        []string      `json:"affectedTrustLists"`
	AffectedCertificateGroups []string      `json:"affectedCertificateGroups"`
	Errors                    []struct {
		TargetID string        `json:"targetId"`
		Error    statusCodeObj `json:"error"`
		Message  *string       `json:"message"`
	} `json:"errors"`
}

// good reports whether a step status is present and Good.
func good(s *statusCodeObj) bool { return s != nil && s.Code == 0 }

// runPushExt runs the `client push` of pc against the go server as the
// SecurityAdmin user over Basic256Sha256 SignAndEncrypt. files are written
// to a directory mounted at /work, so args can name them as /work/<name>.
func runPushExt(t *testing.T, pc pushExtClient, endpoint string, files map[string][]byte, args ...string) (adapterResult, pushExtResult) {
	t.Helper()
	pki := pkiDir(t)
	dir := containerScratchDir(t)
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := shareWithContainers(dir); err != nil {
		t.Fatal(err)
	}
	cmdArgs := []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", filepath.Join(pki, pc.pki, "cert.crt") + ":/certs/cert.crt:ro",
		"-v", filepath.Join(pki, pc.pki, "cert.key") + ":/certs/cert.key:ro",
		"-v", filepath.Join(pki, "ca", "ca.crt") + ":/certs/ca.crt:ro",
		"-v", dir + ":/work:ro",
		getEnvOr(pc.env, pc.defaultImage),
		"client", "push",
		"--endpoint", strings.ReplaceAll(endpoint, "localhost", "host.docker.internal"),
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--trust-list", "/certs/ca.crt",
		"--security-policy", "Basic256Sha256",
		"--security-mode", "SignAndEncrypt",
		"--username", pushAdminUser,
		"--password", pushAdminPass,
	}
	raw, _ := runClientContainer(t, append(cmdArgs, args...))
	res, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse the push result: %v\nraw: %s", err, raw)
	}
	var items []pushExtResult
	if err := json.Unmarshal(res.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("push results %s: %v (success %v, %s, error %s)", res.Results, err, res.Success, res.ServiceResult, res.Error)
	}
	return res, items[0]
}

// mustPush is runPushExt that fails the test unless the command succeeded.
func mustPush(t *testing.T, pc pushExtClient, endpoint string, files map[string][]byte, args ...string) pushExtResult {
	t.Helper()
	res, out := runPushExt(t, pc, endpoint, files, args...)
	if !res.Success {
		t.Fatalf("client push %v: %s %s", args, res.ServiceResult, res.Error)
	}
	return out
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// groupCertificate returns the certificate of the go server's
// DefaultApplicationGroup / RsaSha256ApplicationCertificateType.
func groupCertificate(t *testing.T, srv *server.Server) []byte {
	t.Helper()
	cert, _, _ := srv.GroupCertificate(gds.DefaultApplicationGroup, gds.RsaSha256ApplicationCertificateType)
	if cert == nil {
		t.Fatal("the go server has no RsaSha256 application certificate")
	}
	return cert
}

// waitEndpointCertificate waits until the Basic256Sha256 endpoints of the go
// server present der (alone or followed by its issuers).
func waitEndpointCertificate(t *testing.T, endpoint string, der []byte) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		eps, err := opcua.GetEndpoints(ctx, endpoint)
		cancel()
		if err == nil && slices.ContainsFunc(eps, func(ep *ua.EndpointDescription) bool {
			return ep.SecurityPolicyURI == ua.SecurityPolicyURIBasic256Sha256 && bytes.HasPrefix(ep.ServerCertificate, der)
		}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Basic256Sha256 endpoints do not present the new certificate (GetEndpoints: %v)", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// caSignedServerCertificate returns a certificate for the go server's
// identity (subject, URIs, DNS names, IP addresses of its current
// certificate) for publicKey, issued by the test CA, and the CA certificate.
func caSignedServerCertificate(t *testing.T, cur *x509.Certificate, publicKey any) ([]byte, []byte) {
	t.Helper()
	caCert, caKey := loadTestCA(t)
	tmpl := testpki.CertTemplate(cur.Subject.CommonName, "")
	tmpl.Subject = cur.Subject
	tmpl.URIs, tmpl.DNSNames, tmpl.IPAddresses = cur.URIs, cur.DNSNames, cur.IPAddresses
	der, err := uapolicy.CreateCertificate(rand.Reader, tmpl, caCert, publicKey, caKey)
	if err != nil {
		t.Fatalf("issue the certificate: %v", err)
	}
	return der, caCert.Raw
}

// TestCertMgmtPushExt_NodeOpcuaClient_GoServer: the Part 12 1.05 push
// methods from node-opcua's `client push` (node-opcua-server-configuration
// ClientPushCertificateManagement plus plain Calls) against
// server.WithPushManagement.
func TestCertMgmtPushExt_NodeOpcuaClient_GoServer(t *testing.T) {
	testCertMgmtPushExt(t, nodeOpcuaPushClient)
}

// nodeOpcuaPushClient is the node-opcua adapter's `client push`.
var nodeOpcuaPushClient = pushExtClient{
	name: "node-opcua", env: nodeOpcuaEnv, defaultImage: defaultNodeOpcuaImage, pki: "node-opcua-client",
	direction: dirNodeOpcuaClientToGoServer, require: requireNodeOpcuaImage,
}

// testCertMgmtPushExt runs the `client push` of pc with the v0.15.0 flags
// against server.WithPushManagement; with pc.coreRows also the trust list
// and certificate update rows.
func testCertMgmtPushExt(t *testing.T, pc pushExtClient) {
	pc.require(t)
	appType := fmt.Sprintf("i=%d", id.RsaSha256ApplicationCertificateType)
	dir := pc.direction
	push := func(t *testing.T, endpoint string, files map[string][]byte, args ...string) pushExtResult {
		t.Helper()
		return mustPush(t, pc, endpoint, files, args...)
	}
	selfSigned := func(t *testing.T, what string) []byte {
		t.Helper()
		der, _, err := testpki.SelfSigned("go-opcua interop "+what+" "+pc.name, "urn:otfabric:interop:"+strings.ToLower(what))
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	if pc.coreRows {
		t.Run("coverage/certmgmt.push.trust-list/"+dir, func(t *testing.T) {
			requireV015(t, pc, "clientOperations", "push")
			endpoint, srv := startPushGoServer(t)
			extra := selfSigned(t, "push")
			out := push(t, endpoint, map[string][]byte{"add.der": extra}, "--add-certificate", "/work/add.der", "--apply")
			if !good(out.AddCertificateStatus) || !good(out.ApplyChangesStatus) {
				t.Fatalf("AddCertificate %+v, ApplyChanges %+v", out.AddCertificateStatus, out.ApplyChangesStatus)
			}
			if !out.TrustList.has(loadCACertDER(t)) || out.TrustList.has(extra) {
				t.Fatalf("the trust list read before AddCertificate: %+v", out.TrustList)
			}
			if out.TrustListAfter == nil || !out.TrustListAfter.has(extra) {
				t.Fatalf("the trust list read after ApplyChanges lacks the added certificate: %+v", out.TrustListAfter)
			}
			if !containsCert(srv.TrustList().TrustedCertificates, extra) {
				t.Fatalf("the go server does not trust the certificate %s added", pc.name)
			}
			// RemoveCertificate by thumbprint, applied.
			out = push(t, endpoint, nil, "--remove-certificate", gds.Thumbprint(extra), "--apply")
			if !good(out.RemoveCertificateStatus) || !good(out.ApplyChangesStatus) {
				t.Fatalf("RemoveCertificate %+v, ApplyChanges %+v", out.RemoveCertificateStatus, out.ApplyChangesStatus)
			}
			if containsCert(srv.TrustList().TrustedCertificates, extra) || out.TrustListAfter == nil || out.TrustListAfter.has(extra) {
				t.Fatal("the certificate is still trusted after RemoveCertificate")
			}
			// --issuer: AddCertificate to the issuer list.
			issuer := selfSigned(t, "issuer")
			out = push(t, endpoint, map[string][]byte{"issuer.der": issuer}, "--add-certificate", "/work/issuer.der", "--issuer", "--apply")
			if !good(out.AddCertificateStatus) || !containsCert(srv.TrustList().IssuerCertificates, issuer) ||
				containsCert(srv.TrustList().TrustedCertificates, issuer) {
				t.Fatalf("AddCertificate --issuer %+v: not (only) in the issuer list of the go server", out.AddCertificateStatus)
			}
		})
	}

	t.Run("coverage/certmgmt.push.get-certificates/"+dir, func(t *testing.T) {
		requireV015(t, pc, "clientFeatures", "push-certificates")
		endpoint, _ := startPushGoServer(t)
		out := push(t, endpoint, nil, "--get-certificates")
		if !good(out.GetCertificatesStatus) {
			t.Fatalf("GetCertificates: %+v", out.GetCertificatesStatus)
		}
		if len(out.CertificateTypeIDs) != len(out.Certificates) {
			t.Fatalf("GetCertificates: %d types, %d certificates", len(out.CertificateTypeIDs), len(out.Certificates))
		}
		i := slices.Index(out.CertificateTypeIDs, appType)
		if i < 0 {
			t.Fatalf("GetCertificates types %v lack RsaSha256ApplicationCertificateType", out.CertificateTypeIDs)
		}
		if !bytes.Equal(decodeB64(t, out.Certificates[i]), loadGoServerCert(t)) {
			t.Fatal("GetCertificates does not return the certificate of the go server for RsaSha256ApplicationCertificateType")
		}
	})

	t.Run("coverage/certmgmt.push.create-self-signed/"+dir, func(t *testing.T) {
		requireV015(t, pc, "clientFeatures", "push-certificates")
		endpoint, srv := startPushGoServer(t)
		before := groupCertificate(t, srv)
		cn := pc.name + " self-signed"
		out := push(t, endpoint, nil, "--create-self-signed",
			"--certificate-type-id", appType,
			"--subject", "CN="+cn+"/O=otfabric",
			"--dns", "interop.example", "--ip", "192.0.2.7",
			"--lifetime-days", "2", "--key-size", "2048")
		if !good(out.CreateSelfSignedCertificateStatus) || !good(out.CancelChangesStatus) || out.ApplyChangesStatus != nil {
			t.Fatalf("create %+v, cancel %+v, apply %+v; want Good, Good and no ApplyChanges",
				out.CreateSelfSignedCertificateStatus, out.CancelChangesStatus, out.ApplyChangesStatus)
		}
		x, err := x509.ParseCertificate(decodeB64(t, out.SelfSignedCertificate))
		if err != nil {
			t.Fatalf("the self-signed certificate does not parse: %v", err)
		}
		// Self-signed: issued by its own subject, signed by its own key (an
		// application certificate need not be a CA, so not CheckSignatureFrom).
		if !bytes.Equal(x.RawIssuer, x.RawSubject) {
			t.Fatalf("issuer %v is not the subject %v", x.Issuer, x.Subject)
		}
		if err := x.CheckSignature(x.SignatureAlgorithm, x.RawTBSCertificate, x.Signature); err != nil {
			t.Fatalf("not signed by its own key: %v", err)
		}
		if x.Subject.CommonName != cn || !slices.Equal(x.Subject.Organization, []string{"otfabric"}) {
			t.Errorf("subject %v, want CN=%s, O=otfabric", x.Subject, cn)
		}
		if !slices.Equal(x.DNSNames, []string{"interop.example"}) || len(x.IPAddresses) != 1 || x.IPAddresses[0].String() != "192.0.2.7" {
			t.Errorf("SANs DNS %v IP %v, want interop.example / 192.0.2.7", x.DNSNames, x.IPAddresses)
		}
		if k, ok := x.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 2048 {
			t.Errorf("public key %T, want RSA 2048", x.PublicKey)
		}
		if lifetime := x.NotAfter.Sub(x.NotBefore); lifetime < 47*time.Hour || lifetime > 49*time.Hour {
			t.Errorf("lifetime %v, want about 2 days", lifetime)
		}
		// CancelChanges: the go server keeps its certificate.
		if !bytes.Equal(groupCertificate(t, srv), before) {
			t.Fatal("the go server installed the cancelled self-signed certificate")
		}
	})

	t.Run("coverage/certmgmt.push.delete-certificate/"+dir, func(t *testing.T) {
		requireV015(t, pc, "clientFeatures", "push-certificates")
		endpoint, srv := startPushGoServer(t)
		before := groupCertificate(t, srv)
		// Accepted, then cancelled.
		out := push(t, endpoint, nil, "--delete-certificate", appType)
		if !good(out.DeleteCertificateStatus) || !good(out.CancelChangesStatus) {
			t.Fatalf("delete %+v, cancel %+v; want Good", out.DeleteCertificateStatus, out.CancelChangesStatus)
		}
		// Applied: the certificate the endpoints use "shall not be
		// deleted. This determination happens when ApplyChanges is called"
		// (Part 12 1.05 §7.10): Bad_InvalidState.
		res, out := runPushExt(t, pc, endpoint, nil, "--delete-certificate", appType, "--apply")
		if !good(out.DeleteCertificateStatus) {
			t.Fatalf("DeleteCertificate: %+v", out.DeleteCertificateStatus)
		}
		if res.Success || out.ApplyChangesStatus == nil || out.ApplyChangesStatus.Code != uint32(ua.StatusBadInvalidState) {
			t.Fatalf("ApplyChanges of the deletion: success %v, %+v; want Bad_InvalidState", res.Success, out.ApplyChangesStatus)
		}
		if !bytes.Equal(groupCertificate(t, srv), before) {
			t.Fatal("the go server deleted the certificate of its endpoints")
		}
		// A type the go server has no certificate of (it has an RSA one) is
		// refused at once.
		res, out = runPushExt(t, pc, endpoint, nil, "--delete-certificate", fmt.Sprintf("i=%d", id.EccNistP256ApplicationCertificateType))
		if res.Success || out.DeleteCertificateStatus == nil || out.DeleteCertificateStatus.Code == 0 {
			t.Fatalf("DeleteCertificate of an ECC type: success %v, %+v; want a Bad status", res.Success, out.DeleteCertificateStatus)
		}
	})

	groupTrustList := func(t *testing.T, group string, groupID *ua.NodeID) {
		requireV015(t, pc, "clientFeatures", "push-groups")
		endpoint, srv := startPushGoServer(t)
		extra := selfSigned(t, group)
		out := push(t, endpoint, map[string][]byte{"add.der": extra}, "--group", group, "--add-certificate", "/work/add.der", "--apply")
		if out.CertificateGroupID != groupID.String() {
			t.Errorf("certificateGroupId %q, want %v", out.CertificateGroupID, groupID)
		}
		if out.TrustList.has(extra) || out.TrustListAfter == nil || !out.TrustListAfter.has(extra) {
			t.Fatalf("the %s trust list before / after AddCertificate + ApplyChanges: %+v / %+v", group, out.TrustList, out.TrustListAfter)
		}
		if !containsCert(srv.GroupTrustList(groupID).TrustedCertificates, extra) {
			t.Fatalf("the go server's %s trust list does not trust the certificate %s added", group, pc.name)
		}
		if containsCert(srv.TrustList().TrustedCertificates, extra) {
			t.Fatalf("the certificate added to the %s group is in the application trust list", group)
		}
	}
	t.Run("coverage/certmgmt.push.https-group/"+dir, func(t *testing.T) {
		groupTrustList(t, "Https", gds.DefaultHTTPSGroup)
	})
	t.Run("coverage/certmgmt.push.usertoken-group/"+dir, func(t *testing.T) {
		groupTrustList(t, "UserToken", gds.DefaultUserTokenGroup)
	})

	t.Run("coverage/certmgmt.push.pfx/"+dir, func(t *testing.T) {
		requireV015(t, pc, "clientFeatures", "push-certificates")
		endpoint, srv := startPushGoServer(t)
		cur := mustParse(t, groupCertificate(t, srv))
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		newDER, caDER := caSignedServerCertificate(t, cur, &key.PublicKey)
		pfx, err := uapolicy.EncodePFX(key, [][]byte{newDER}, "")
		if err != nil {
			t.Fatal(err)
		}
		out := push(t, endpoint, map[string][]byte{"new.der": newDER, "new.pfx": pfx, "ca.der": caDER},
			"--update-certificate", "/work/new.der", "--update-private-key", "/work/new.pfx",
			"--issuer-certificate", "/work/ca.der", "--apply")
		if !good(out.UpdateCertificateStatus) || !good(out.ApplyChangesStatus) {
			t.Fatalf("UpdateCertificate %+v, ApplyChanges %+v", out.UpdateCertificateStatus, out.ApplyChangesStatus)
		}
		if got, _, k := srv.GroupCertificate(gds.DefaultApplicationGroup, gds.RsaSha256ApplicationCertificateType); !bytes.Equal(got, newDER) {
			t.Fatal("the go server did not install the certificate with the PFX key")
		} else if pub, ok := k.Public().(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
			t.Fatal("the go server does not use the private key of the PFX")
		}
		waitEndpointCertificate(t, endpoint, newDER)
		// A new secure channel works with the new key.
		pushClient(t, endpoint, false)
	})

	t.Run("coverage/certmgmt.push.transaction-diagnostics/"+dir, func(t *testing.T) {
		requireV015(t, pc, "clientFeatures", "push-transaction-diagnostics")
		endpoint, _ := startPushGoServer(t)
		extra := selfSigned(t, "diagnostics")
		out := push(t, endpoint, map[string][]byte{"add.der": extra}, "--add-certificate", "/work/add.der", "--apply", "--transaction-diagnostics")
		d := out.TransactionDiagnostics
		if !good(out.TransactionDiagnosticsStatus) || d == nil {
			t.Fatalf("TransactionDiagnostics: %+v", out.TransactionDiagnosticsStatus)
		}
		if d.StartTime == nil || d.EndTime == nil || d.EndTime.Before(*d.StartTime) || d.Result.Code != 0 || len(d.Errors) != 0 {
			t.Fatalf("TransactionDiagnostics of the applied transaction: %+v", d)
		}
		appTrustList := fmt.Sprintf("i=%d", id.ServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList)
		if !slices.Contains(d.AffectedTrustLists, appTrustList) {
			t.Fatalf("AffectedTrustLists %v lack %s", d.AffectedTrustLists, appTrustList)
		}

		// A failed ApplyChanges: its status and an error entry.
		res, out := runPushExt(t, pc, endpoint, nil, "--delete-certificate", appType, "--apply", "--transaction-diagnostics")
		d = out.TransactionDiagnostics
		if res.Success || !good(out.TransactionDiagnosticsStatus) || d == nil {
			t.Fatalf("the failed transaction: success %v, diagnostics %+v %+v", res.Success, out.TransactionDiagnosticsStatus, d)
		}
		if d.Result.Code != uint32(ua.StatusBadInvalidState) || len(d.Errors) == 0 || d.Errors[0].Error.Code != uint32(ua.StatusBadInvalidState) {
			t.Fatalf("TransactionDiagnostics of the refused deletion: %+v", d)
		}
		appGroup := fmt.Sprintf("i=%d", id.ServerConfigurationCertificateGroupsDefaultApplicationGroup)
		if d.Errors[0].TargetID != appGroup {
			t.Errorf("error target %s, want %s", d.Errors[0].TargetID, appGroup)
		}
	})

	t.Run("coverage/certmgmt.push.reset-to-defaults/"+dir, func(t *testing.T) {
		requireV015(t, pc, "clientFeatures", "push-certificates")
		endpoint, srv := startPushGoServer(t)
		extra := selfSigned(t, "reset")
		push(t, endpoint, map[string][]byte{"add.der": extra}, "--add-certificate", "/work/add.der", "--apply")
		if !containsCert(srv.TrustList().TrustedCertificates, extra) {
			t.Fatal("the added certificate is not trusted")
		}
		out := push(t, endpoint, nil, "--reset-to-defaults")
		if !good(out.ResetToServerDefaultsStatus) {
			t.Fatalf("ResetToServerDefaults: %+v", out.ResetToServerDefaultsStatus)
		}
		tl := srv.TrustList()
		if containsCert(tl.TrustedCertificates, extra) || !containsCert(tl.TrustedCertificates, loadCACertDER(t)) {
			t.Fatalf("the trust list after ResetToServerDefaults (%d trusted) is not the configured one", len(tl.TrustedCertificates))
		}
		if out.TrustListAfter == nil || out.TrustListAfter.has(extra) {
			t.Fatalf("the trust list %s reads after ResetToServerDefaults: %+v", pc.name, out.TrustListAfter)
		}
	})

	// CreateSigningRequest, then UpdateCertificate without a private key (the
	// server keeps the key of its signing request) with a PEM issuer. For
	// node-opcua the certmgmt.push.certificate-update row is verified by
	// TestCertMgmtPush_NodeOpcuaClient_GoServer (--csr), so the subtest is
	// not a coverage case there.
	updateCase := "update-certificate/" + dir
	if pc.coreRows {
		updateCase = "coverage/certmgmt.push.certificate-update/" + dir
	}
	t.Run(updateCase, func(t *testing.T) {
		requireV015(t, pc, "clientFeatures", "push-certificates")
		endpoint, srv := startPushGoServer(t)
		out := push(t, endpoint, nil, "--csr")
		csr, err := x509.ParseCertificateRequest(decodeB64(t, out.CertificateSigningRequest))
		if err != nil {
			t.Fatalf("the CSR does not parse: %v", err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("CSR signature: %v", err)
		}
		cur := mustParse(t, groupCertificate(t, srv))
		if !publicKeysEqual(csr.PublicKey, cur.PublicKey) {
			t.Fatal("the CSR is not for the key of the go server certificate")
		}
		newDER, caDER := caSignedServerCertificate(t, cur, csr.PublicKey)
		caPEM := pemEncodeCert(caDER)
		out = push(t, endpoint, map[string][]byte{"new.der": newDER, "ca.pem": caPEM},
			"--update-certificate", "/work/new.der", "--issuer-certificate", "/work/ca.pem", "--apply")
		if !good(out.UpdateCertificateStatus) || !good(out.ApplyChangesStatus) || out.ApplyChangesRequired == nil {
			t.Fatalf("UpdateCertificate %+v (applyChangesRequired %v), ApplyChanges %+v",
				out.UpdateCertificateStatus, out.ApplyChangesRequired, out.ApplyChangesStatus)
		}
		if !bytes.Equal(groupCertificate(t, srv), newDER) {
			t.Fatal("the go server did not install the updated certificate")
		}
		waitEndpointCertificate(t, endpoint, newDER)
	})
}

// ---------------------------------------------------------------------------
// Query (Part 4 §5.9): node-opcua `client query` → go server
// ---------------------------------------------------------------------------

const queryObjects = 5

// startQueryGoServer is the baseline go server with an ObjectType
// s=QueryType and queryObjects instances s=Query.<i> (BrowseName Query.<i>),
// each with a property Serial = "A-<i>".
func startQueryGoServer(t *testing.T) (string, uint16) {
	t.Helper()
	endpoint, srv := startGoServerWithOptions(t)
	_, nsIdx := findNSFromServer(t, srv)
	nsAny, err := srv.Namespace(int(nsIdx))
	if err != nil {
		t.Fatal(err)
	}
	ns, ok := nsAny.(*server.NodeNameSpace)
	if !ok {
		t.Fatalf("namespace %d is a %T", nsIdx, nsAny)
	}
	typeNode := ns.AddNode(server.NewNode(
		ua.NewStringNodeID(nsIdx, "QueryType"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:   server.DataValueFromValue(uint32(ua.NodeClassObjectType)),
			ua.AttributeIDBrowseName:  server.DataValueFromValue(attrs.BrowseName("QueryType")),
			ua.AttributeIDDisplayName: server.DataValueFromValue(attrs.DisplayName("QueryType", "en")),
			ua.AttributeIDIsAbstract:  server.DataValueFromValue(false),
		},
		nil, nil,
	))
	if base := srv.Node(ua.NewNumericNodeID(0, id.BaseObjectType)); base != nil {
		base.AddRef(typeNode, server.RefType(id.HasSubtype), true)
	}
	objs := ns.Objects()
	for i := 1; i <= queryObjects; i++ {
		name := fmt.Sprintf("Query.%d", i)
		obj := ns.AddNode(server.NewNode(
			ua.NewStringNodeID(nsIdx, name),
			map[ua.AttributeID]*ua.DataValue{
				ua.AttributeIDNodeClass:     server.DataValueFromValue(uint32(ua.NodeClassObject)),
				ua.AttributeIDBrowseName:    server.DataValueFromValue(attrs.BrowseName(name)),
				ua.AttributeIDDisplayName:   server.DataValueFromValue(attrs.DisplayName(name, "en")),
				ua.AttributeIDEventNotifier: server.DataValueFromValue(byte(0)),
			},
			nil, nil,
		))
		serial := ns.AddNode(server.NewVariableNode(ua.NewStringNodeID(nsIdx, name+".Serial"), "Serial", fmt.Sprintf("A-%d", i)))
		obj.AddRef(typeNode, server.RefType(id.HasTypeDefinition), true)
		obj.AddRef(serial, server.RefType(id.HasProperty), true)
		objs.AddRef(obj, server.RefTypeIDOrganizes, true)
	}
	return endpoint, nsIdx
}

// queryResult is the result of `client query` (CLIENT_CONTRACT §4 "query").
type queryResult struct {
	TypeDefinitionNode string `json:"typeDefinitionNode"`
	QueryFirst         struct {
		StatusCode        statusCodeObj `json:"statusCode"`
		ContinuationPoint *string       `json:"continuationPoint"`
		ParsingResults    []struct {
			StatusCode      statusCodeObj   `json:"statusCode"`
			DataStatusCodes []statusCodeObj `json:"dataStatusCodes"`
		} `json:"parsingResults"`
		QueryDataSets []queryDataSetJSON `json:"queryDataSets"`
	} `json:"queryFirst"`
	QueryNext []struct {
		StatusCode               statusCodeObj      `json:"statusCode"`
		ReleaseContinuationPoint bool               `json:"releaseContinuationPoint"`
		RevisedContinuationPoint *string            `json:"revisedContinuationPoint"`
		QueryDataSets            []queryDataSetJSON `json:"queryDataSets"`
	} `json:"queryNext"`
	QueryDataSets []queryDataSetJSON `json:"queryDataSets"`
}

type queryDataSetJSON struct {
	NodeID             string `json:"nodeId"`
	TypeDefinitionNode string `json:"typeDefinitionNode"`
	Values             []struct {
		DataType string          `json:"dataType"`
		Value    json.RawMessage `json:"value"`
	} `json:"values"`
}

func runNodeOpcuaQuery(t *testing.T, endpoint string, args ...string) (adapterResult, queryResult) {
	t.Helper()
	base := []string{"--type-definition", "nsu=" + interopNamespaceURI + ";s=QueryType",
		"--data-to-return", ".Serial", "--data-to-return", "#BrowseName"}
	res := runNodeOpcuaClientResult(t, endpoint, "query", append(base, args...)...)
	var items []queryResult
	if err := json.Unmarshal(res.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("query results %s: %v (success %v, %s, error %s)", res.Results, err, res.Success, res.ServiceResult, res.Error)
	}
	return res, items[0]
}

// assertQueryDataSets checks that sets are exactly the queryObjects
// instances of QueryType with their Serial and BrowseName, in any order.
func assertQueryDataSets(t *testing.T, sets []queryDataSetJSON, nsIdx uint16) {
	t.Helper()
	typeID := fmt.Sprintf("ns=%d;s=QueryType", nsIdx)
	seen := map[string]bool{}
	for _, ds := range sets {
		var i int
		if _, err := fmt.Sscanf(ds.NodeID, fmt.Sprintf("ns=%d;s=Query.%%d", nsIdx), &i); err != nil || i < 1 || i > queryObjects {
			t.Fatalf("unexpected data set node %s", ds.NodeID)
		}
		if seen[ds.NodeID] {
			t.Fatalf("data set %s returned twice", ds.NodeID)
		}
		seen[ds.NodeID] = true
		if ds.TypeDefinitionNode != typeID {
			t.Errorf("%s: TypeDefinitionNode %s, want %s", ds.NodeID, ds.TypeDefinitionNode, typeID)
		}
		if len(ds.Values) != 2 {
			t.Fatalf("%s: %d values, want 2", ds.NodeID, len(ds.Values))
		}
		var serial string
		if err := json.Unmarshal(ds.Values[0].Value, &serial); err != nil || serial != fmt.Sprintf("A-%d", i) {
			t.Errorf("%s: Serial %s (%s), want A-%d", ds.NodeID, ds.Values[0].Value, ds.Values[0].DataType, i)
		}
		if ds.Values[1].DataType != "QualifiedName" || !strings.Contains(string(ds.Values[1].Value), fmt.Sprintf("%q", fmt.Sprintf("Query.%d", i))) {
			t.Errorf("%s: BrowseName %s (%s), want Query.%d", ds.NodeID, ds.Values[1].Value, ds.Values[1].DataType, i)
		}
	}
	if len(seen) != queryObjects {
		t.Fatalf("%d data sets, want %d", len(seen), queryObjects)
	}
}

// TestGoServer_NodeOpcuaClient_Query: node-opcua's QueryFirst / QueryNext
// against the go-opcua Query service set.
func TestGoServer_NodeOpcuaClient_Query(t *testing.T) {
	requireNodeOpcuaImage(t)
	requireNodeOpcuaV015(t, "clientOperations", "query")
	endpoint, nsIdx := startQueryGoServer(t)

	t.Run("coverage/query.first/node-opcua-client-to-go-server", func(t *testing.T) {
		res, out := runNodeOpcuaQuery(t, endpoint)
		if !res.Success {
			t.Fatalf("client query: %s %s", res.ServiceResult, res.Error)
		}
		if out.QueryFirst.StatusCode.Code != 0 || out.QueryFirst.ContinuationPoint != nil || len(out.QueryNext) != 0 {
			t.Fatalf("QueryFirst %s, continuation point %v, %d QueryNext; want Good, none, 0",
				out.QueryFirst.StatusCode, out.QueryFirst.ContinuationPoint, len(out.QueryNext))
		}
		if len(out.QueryFirst.ParsingResults) != 1 || out.QueryFirst.ParsingResults[0].StatusCode.Code != 0 ||
			len(out.QueryFirst.ParsingResults[0].DataStatusCodes) != 2 {
			t.Fatalf("ParsingResults %+v, want one Good with two data status codes", out.QueryFirst.ParsingResults)
		}
		assertQueryDataSets(t, out.QueryFirst.QueryDataSets, nsIdx)
	})

	t.Run("coverage/query.next/node-opcua-client-to-go-server", func(t *testing.T) {
		res, out := runNodeOpcuaQuery(t, endpoint, "--max-data-sets", "2")
		if !res.Success {
			t.Fatalf("client query --max-data-sets 2: %s %s", res.ServiceResult, res.Error)
		}
		if len(out.QueryFirst.QueryDataSets) != 2 || out.QueryFirst.ContinuationPoint == nil {
			t.Fatalf("QueryFirst: %d data sets, continuation point %v; want 2 and one", len(out.QueryFirst.QueryDataSets), out.QueryFirst.ContinuationPoint)
		}
		if len(out.QueryNext) == 0 {
			t.Fatal("no QueryNext")
		}
		for i, n := range out.QueryNext {
			if n.StatusCode.Code != 0 || n.ReleaseContinuationPoint {
				t.Fatalf("QueryNext %d: %s (release %v)", i, n.StatusCode, n.ReleaseContinuationPoint)
			}
		}
		if last := out.QueryNext[len(out.QueryNext)-1]; last.RevisedContinuationPoint != nil {
			t.Fatalf("the last QueryNext returned a continuation point")
		}
		assertQueryDataSets(t, out.QueryDataSets, nsIdx)

		// ReleaseContinuationPoint: Good and no data.
		res, out = runNodeOpcuaQuery(t, endpoint, "--max-data-sets", "2", "--release-continuation-point")
		if !res.Success || len(out.QueryNext) != 1 {
			t.Fatalf("client query --release-continuation-point: %s %s, %d QueryNext", res.ServiceResult, res.Error, len(out.QueryNext))
		}
		if n := out.QueryNext[0]; !n.ReleaseContinuationPoint || n.StatusCode.Code != 0 || len(n.QueryDataSets) != 0 || n.RevisedContinuationPoint != nil {
			t.Fatalf("the releasing QueryNext: %+v", n)
		}
	})
}

// ---------------------------------------------------------------------------
// Alarms (Part 9): go client → node-opcua alarm fixture
// ---------------------------------------------------------------------------

func isNullNodeID(n *ua.NodeID) bool { return n == nil || n.String() == "i=0" }

// TestNodeOpcuaServer_AlarmBranches: s=Alarms.Clear on the node-opcua alarm
// fixture keeps the unacknowledged state in a condition branch; the go
// client acknowledges and confirms the branch by its EventId.
func TestNodeOpcuaServer_AlarmBranches(t *testing.T) {
	requireNodeOpcuaImage(t)
	requireServerFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "alarms")
	requireNodeOpcuaV015(t, "serverFeatures", "alarms-branches")
	s := newPeerAlarmSession(t, startNodeOpcuaServer(t).endpoint)

	t.Run("coverage/alarms.branches/go-client-to-node-opcua-server", func(t *testing.T) {
		cond := s.refresh(t)
		if cond == nil || !isNullNodeID(cond.BranchID) || cond.Active == nil || !*cond.Active || cond.Acked == nil || *cond.Acked {
			t.Fatalf("the refreshed alarm after Reset: %+v; want branch zero, active, unacknowledged", cond)
		}
		condID := cond.ConditionID
		clear := ua.NewStringNodeID(s.source.Namespace(), "Alarms.Clear")
		call := func() ua.StatusCode {
			res, err := s.c.Call(s.ctx, &ua.CallMethodRequest{ObjectID: s.source, MethodID: clear})
			if err != nil {
				t.Fatalf("Call Alarms.Clear: %v", err)
			}
			return res.StatusCode
		}
		if sc := call(); sc != ua.StatusOK {
			t.Fatalf("Alarms.Clear: %v", sc)
		}
		isCond := func(ev *opcua.ConditionEvent) bool { return ev.ConditionID != nil && ev.ConditionID.Equal(condID) }
		branch := s.next(t, "the event of the new branch", func(ev *opcua.ConditionEvent) bool {
			return isCond(ev) && !isNullNodeID(ev.BranchID)
		})
		if branch.Active == nil || !*branch.Active || branch.Acked == nil || *branch.Acked || !branch.Retain {
			t.Fatalf("the branch: active %v acked %v retain %v; want the active unacknowledged state, retained",
				branch.Active, branch.Acked, branch.Retain)
		}
		normal := s.next(t, "the event of the condition back to normal", func(ev *opcua.ConditionEvent) bool {
			return isCond(ev) && isNullNodeID(ev.BranchID)
		})
		if normal.Active == nil || *normal.Active || normal.Acked == nil || !*normal.Acked {
			t.Fatalf("branch zero after Clear: active %v acked %v; want inactive, acknowledged", normal.Active, normal.Acked)
		}
		if sc := call(); sc != ua.StatusBadInvalidState {
			t.Errorf("Alarms.Clear of a normal alarm: %v, want Bad_InvalidState", sc)
		}

		isBranch := func(ev *opcua.ConditionEvent) bool {
			return isCond(ev) && ev.BranchID != nil && ev.BranchID.Equal(branch.BranchID)
		}
		if err := s.c.Acknowledge(s.ctx, condID, branch.EventID, "go-branch-ack"); err != nil {
			t.Fatalf("Acknowledge of the branch: %v", err)
		}
		acked := s.next(t, "the acknowledged branch", func(ev *opcua.ConditionEvent) bool {
			return isBranch(ev) && ev.Acked != nil && *ev.Acked
		})
		if acked.Comment == nil || acked.Comment.Text != "go-branch-ack" {
			t.Errorf("branch Comment after Acknowledge = %v, want go-branch-ack", acked.Comment)
		}
		if err := s.c.Confirm(s.ctx, condID, acked.EventID, "go-branch-confirm"); err != nil {
			t.Fatalf("Confirm of the branch: %v", err)
		}
		confirmed := s.next(t, "the confirmed branch", func(ev *opcua.ConditionEvent) bool {
			return isBranch(ev) && ev.Confirmed != nil && *ev.Confirmed
		})
		if confirmed.Retain {
			t.Error("the confirmed branch is still retained")
		}
		// The branch is gone: its EventId is unknown now.
		if err := s.c.Acknowledge(s.ctx, condID, confirmed.EventID, "late"); err == nil {
			t.Error("Acknowledge with the EventId of the deleted branch succeeded")
		}
	})
}

// TestNodeOpcuaServer_AlarmAudible: AudibleEnabled / AudibleSound of the
// node-opcua alarm fixture (Part 9 §5.8.2, AudioVariableType §8.3).
func TestNodeOpcuaServer_AlarmAudible(t *testing.T) {
	requireNodeOpcuaImage(t)
	requireServerFeature(t, nodeOpcuaEnv, defaultNodeOpcuaImage, "alarms")
	requireNodeOpcuaV015(t, "serverFeatures", "alarms-audible")
	h := startNodeOpcuaServer(t)

	t.Run("coverage/alarms.audible-sound/go-client-to-node-opcua-server", func(t *testing.T) {
		c := dialClient(t, h.endpoint)
		ctx, nsIdx := findNS(t, c)
		alarm := c.Node(ua.NewStringNodeID(nsIdx, "Alarms.InteropAlarm"))
		path := func(names ...string) *ua.NodeID {
			qn := make([]*ua.QualifiedName, len(names))
			for i, n := range names {
				qn[i] = &ua.QualifiedName{Name: n}
			}
			nid, err := alarm.TranslateBrowsePathsToNodeIDs(ctx, qn)
			if err != nil {
				t.Fatalf("%v: %v", names, err)
			}
			return nid
		}
		enabled, sound, listID := path("AudibleEnabled"), path("AudibleSound"), path("AudibleSound", "ListId")
		read := func(nid *ua.NodeID, attr ua.AttributeID) any {
			res, err := c.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: nid, AttributeID: attr}}})
			if err != nil || len(res.Results) != 1 || res.Results[0].Status != ua.StatusOK || res.Results[0].Value == nil {
				t.Fatalf("read %v attribute %d: %v %+v", nid, attr, err, res)
			}
			return res.Results[0].Value.Value()
		}
		if v, ok := read(enabled, ua.AttributeIDValue).(bool); !ok || !v {
			t.Errorf("AudibleEnabled = %v, want true", v)
		}
		want := []byte("RIFF\x24\x00\x00\x00WAVEfmt interop-alarm-sound")
		if v, ok := read(sound, ua.AttributeIDValue).([]byte); !ok || !bytes.Equal(v, want) {
			t.Errorf("AudibleSound = %q, want %q", v, want)
		}
		if dt, ok := read(sound, ua.AttributeIDDataType).(*ua.NodeID); !ok || dt.Namespace() != 0 || dt.IntID() != id.AudioDataType {
			t.Errorf("AudibleSound DataType = %v, want AudioDataType", dt)
		}
		if v, ok := read(listID, ua.AttributeIDValue).(string); !ok || v != "urn:otfabric:opcua-interop:sounds" {
			t.Errorf("AudibleSound/ListId = %q", v)
		}
		refs, err := c.Node(sound).ReferencedNodes(ctx, id.HasTypeDefinition, ua.BrowseDirectionForward, ua.NodeClassAll, false)
		if err != nil || len(refs) != 1 || refs[0].ID.IntID() != id.AudioVariableType {
			t.Errorf("AudibleSound TypeDefinition: %v %v, want AudioVariableType", refs, err)
		}
	})
}
