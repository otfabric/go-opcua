//go:build interop

// SPDX-License-Identifier: MIT

// The async-opcua adapter client operations of opcua-interop v0.15.0
// (unreleased when these tests were written; built from the opcua-interop
// branch feat/async-opcua-push), against the go server:
//
//	async-opcua-client-to-go-server   `client push` (Part 12 §7: the
//	                                  group's trust list, AddCertificate /
//	                                  RemoveCertificate, CreateSigningRequest,
//	                                  UpdateCertificate with a PEM / PFX key,
//	                                  GetCertificates, CreateSelfSignedCertificate,
//	                                  DeleteCertificate, ResetToServerDefaults,
//	                                  CancelChanges, TransactionDiagnostics, the
//	                                  Https / UserToken groups) against
//	                                  server.WithPushManagement; `client
//	                                  gds-pull` (Part 12 §6, §7.9) against
//	                                  gdsserver; `client query` (QueryFirst /
//	                                  QueryNext) against the go-opcua Query
//	                                  service set
//
// async-opcua 0.19.0 has no push, GDS or Query client API: the adapter sends
// plain Call requests on the standard NodeIds (ServerConfiguration, the
// TrustList of the group, the GDS Directory), encodes the GDS
// ApplicationRecordDataType itself, and sends QueryFirst / QueryNext on the
// session's secure channel with the session's request header.
//
// The tests are gated on the capabilities the adapter advertises
// (clientOperations push / query / gds-pull, clientFeatures push-groups /
// push-certificates / push-transaction-diagnostics). Until the pinned image
// has them they skip, also under OPCUA_INTEROP_REQUIRE_CAPABILITIES=1; run
// them against a local build with
//
//	ASYNC_OPCUA_IMAGE=opcua-interop-async-opcua:push-ext go test -tags=interop -run 'AsyncOpcuaClient_(Push|GDSPull|Query)' ./interop/
//
// COVERAGE: testdata/ledger-async-opcua.json certmgmt.push.trust-list,
// certmgmt.push.certificate-update, certmgmt.push.create-self-signed,
// certmgmt.push.delete-certificate, certmgmt.push.https-group,
// certmgmt.push.usertoken-group, certmgmt.push.pfx,
// certmgmt.push.transaction-diagnostics, gds.pull.directory,
// gds.pull.certificate-request, gds.pull.trust-list, gds.pull.revocation,
// query.first, query.next

package interop

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// requireAsyncOpcuaV015 skips (or fails when REQUIRE_CAPABILITIES=1) when
// the async-opcua adapter image does not advertise a capability of
// opcua-interop v0.15.0 (list: clientOperations or clientFeatures).
func requireAsyncOpcuaV015(t *testing.T, list, capability string) {
	t.Helper()
	caps := requireAsyncOpcuaImage(t)
	requirePinnedVersion(t, asyncOpcuaEnv, caps, defaultAsyncOpcuaImage)
	have := map[string][]string{
		"clientOperations": caps.ClientOperations,
		"clientFeatures":   caps.ClientFeatures,
	}[list]
	if !slices.Contains(have, capability) {
		capabilityUnavailable(t, "the async-opcua adapter (version %s) has no %s %q: need opcua-interop v0.15.0; "+
			"set %s to such an image", caps.Adapter.Version, list, capability, asyncOpcuaEnv)
	}
}

// asyncOpcuaPushResult is the result of `client push` (CLIENT_CONTRACT §4
// "push") with the keys pushExtResult does not decode.
type asyncOpcuaPushResult struct {
	pushExtResult
	RemoveCertificateStatus    *statusCodeObj `json:"removeCertificateStatus"`
	CreateSigningRequestStatus *statusCodeObj `json:"createSigningRequestStatus"`
	GetRejectedListStatus      *statusCodeObj `json:"getRejectedListStatus"`
	RejectedCertificates       []string       `json:"rejectedCertificates"`
}

// runAsyncOpcuaPush runs the async-opcua adapter's `client push` against the
// go server over Basic256Sha256 SignAndEncrypt, as the SecurityAdmin user
// unless anonymous. files are written to a directory mounted at /work, so
// args can name them as /work/<name>.
func runAsyncOpcuaPush(t *testing.T, endpoint string, anonymous bool, files map[string][]byte, args ...string) (adapterResult, asyncOpcuaPushResult) {
	t.Helper()
	requireAsyncOpcuaImage(t)
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
		"-v", filepath.Join(pki, "async-opcua-client", "cert.crt") + ":/certs/cert.crt:ro",
		"-v", filepath.Join(pki, "async-opcua-client", "cert.key") + ":/certs/cert.key:ro",
		"-v", filepath.Join(pki, "ca", "ca.crt") + ":/certs/ca.crt:ro",
		"-v", dir + ":/work:ro",
		getEnvOr(asyncOpcuaEnv, defaultAsyncOpcuaImage),
		"client", "push",
		"--endpoint", strings.ReplaceAll(endpoint, "localhost", "host.docker.internal"),
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--trust-list", "/certs/ca.crt",
		"--security-policy", "Basic256Sha256",
		"--security-mode", "SignAndEncrypt",
	}
	if !anonymous {
		cmdArgs = append(cmdArgs, "--username", pushAdminUser, "--password", pushAdminPass)
	}
	raw, _ := runClientContainer(t, append(cmdArgs, args...))
	res, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse the push result: %v\nraw: %s", err, raw)
	}
	if anonymous && !res.Success {
		return res, asyncOpcuaPushResult{}
	}
	var items []asyncOpcuaPushResult
	if err := json.Unmarshal(res.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("push results %s: %v (success %v, %s, error %s)", res.Results, err, res.Success, res.ServiceResult, res.Error)
	}
	return res, items[0]
}

// mustAsyncOpcuaPush is runAsyncOpcuaPush as the SecurityAdmin user that
// fails the test unless the command succeeded.
func mustAsyncOpcuaPush(t *testing.T, endpoint string, files map[string][]byte, args ...string) asyncOpcuaPushResult {
	t.Helper()
	res, out := runAsyncOpcuaPush(t, endpoint, false, files, args...)
	if !res.Success {
		t.Fatalf("client push %v: %s %s", args, res.ServiceResult, res.Error)
	}
	return out
}

// TestCertMgmtPush_AsyncOpcuaClient_GoServer: push certificate management
// from the async-opcua adapter's `client push` (plain Calls of async-opcua
// 0.19.0) against server.WithPushManagement.
func TestCertMgmtPush_AsyncOpcuaClient_GoServer(t *testing.T) {
	requireAsyncOpcuaImage(t)
	requireAsyncOpcuaV015(t, "clientOperations", "push")
	appType := fmt.Sprintf("i=%d", id.RsaSha256ApplicationCertificateType)

	t.Run("coverage/certmgmt.push.trust-list/async-opcua-client-to-go-server", func(t *testing.T) {
		endpoint, srv := startPushGoServer(t)
		extra, _, err := testpki.SelfSigned("go-opcua interop push async-opcua", "urn:otfabric:interop:push")
		if err != nil {
			t.Fatal(err)
		}
		out := mustAsyncOpcuaPush(t, endpoint, map[string][]byte{"add.der": extra}, "--add-certificate", "/work/add.der", "--apply")
		if out.CertificateGroupID != fmt.Sprintf("i=%d", id.ServerConfigurationCertificateGroupsDefaultApplicationGroup) {
			t.Errorf("certificateGroupId %q", out.CertificateGroupID)
		}
		if !good(out.AddCertificateStatus) || !good(out.ApplyChangesStatus) {
			t.Fatalf("AddCertificate %+v, ApplyChanges %+v", out.AddCertificateStatus, out.ApplyChangesStatus)
		}
		if out.TrustList.SpecifiedLists != 15 || !out.TrustList.has(loadCACertDER(t)) || out.TrustList.has(extra) {
			t.Fatalf("the trust list read before AddCertificate: %+v", out.TrustList)
		}
		if out.TrustListAfter == nil || !out.TrustListAfter.has(extra) {
			t.Fatalf("the trust list read after ApplyChanges lacks the added certificate: %+v", out.TrustListAfter)
		}
		if !containsCert(srv.TrustList().TrustedCertificates, extra) {
			t.Fatal("the go server does not trust the certificate async-opcua added")
		}

		// RemoveCertificate by thumbprint, applied.
		out = mustAsyncOpcuaPush(t, endpoint, nil, "--remove-certificate", gds.Thumbprint(extra), "--apply")
		if !good(out.RemoveCertificateStatus) || !good(out.ApplyChangesStatus) {
			t.Fatalf("RemoveCertificate %+v, ApplyChanges %+v", out.RemoveCertificateStatus, out.ApplyChangesStatus)
		}
		if containsCert(srv.TrustList().TrustedCertificates, extra) || out.TrustListAfter == nil || out.TrustListAfter.has(extra) {
			t.Fatal("the certificate is still trusted after RemoveCertificate")
		}

		// An issuer certificate goes to the issuer list.
		out = mustAsyncOpcuaPush(t, endpoint, map[string][]byte{"add.der": extra}, "--add-certificate", "/work/add.der", "--issuer", "--apply")
		if !good(out.AddCertificateStatus) || !containsCert(srv.TrustList().IssuerCertificates, extra) || containsCert(srv.TrustList().TrustedCertificates, extra) {
			t.Fatalf("AddCertificate --issuer %+v: not (only) in the issuer list", out.AddCertificateStatus)
		}
	})

	t.Run("coverage/certmgmt.push.certificate-update/async-opcua-client-to-go-server", func(t *testing.T) {
		endpoint, srv := startPushGoServer(t)
		out := mustAsyncOpcuaPush(t, endpoint, nil, "--csr")
		if !good(out.CreateSigningRequestStatus) || !good(out.GetRejectedListStatus) {
			t.Fatalf("CreateSigningRequest %+v, GetRejectedList %+v", out.CreateSigningRequestStatus, out.GetRejectedListStatus)
		}
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
		// UpdateCertificate without a private key (the server keeps the key
		// of its signing request), with a PEM issuer.
		newDER, caDER := caSignedServerCertificate(t, cur, csr.PublicKey)
		out = mustAsyncOpcuaPush(t, endpoint, map[string][]byte{"new.der": newDER, "ca.pem": pemEncodeCert(caDER)},
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

	t.Run("coverage/certmgmt.push.create-self-signed/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAsyncOpcuaV015(t, "clientFeatures", "push-certificates")
		endpoint, srv := startPushGoServer(t)
		before := groupCertificate(t, srv)
		out := mustAsyncOpcuaPush(t, endpoint, nil, "--create-self-signed",
			"--certificate-type-id", appType,
			"--subject", "CN=async-opcua self-signed/O=otfabric",
			"--dns", "interop.example", "--ip", "192.0.2.9",
			"--lifetime-days", "3", "--key-size", "2048")
		if !good(out.CreateSelfSignedCertificateStatus) || !good(out.CancelChangesStatus) || out.ApplyChangesStatus != nil {
			t.Fatalf("create %+v, cancel %+v, apply %+v; want Good, Good and no ApplyChanges",
				out.CreateSelfSignedCertificateStatus, out.CancelChangesStatus, out.ApplyChangesStatus)
		}
		x, err := x509.ParseCertificate(decodeB64(t, out.SelfSignedCertificate))
		if err != nil {
			t.Fatalf("the self-signed certificate does not parse: %v", err)
		}
		if !bytes.Equal(x.RawIssuer, x.RawSubject) {
			t.Fatalf("issuer %v is not the subject %v", x.Issuer, x.Subject)
		}
		if err := x.CheckSignature(x.SignatureAlgorithm, x.RawTBSCertificate, x.Signature); err != nil {
			t.Fatalf("not signed by its own key: %v", err)
		}
		if x.Subject.CommonName != "async-opcua self-signed" || !slices.Equal(x.Subject.Organization, []string{"otfabric"}) {
			t.Errorf("subject %v, want CN=async-opcua self-signed, O=otfabric", x.Subject)
		}
		if !slices.Equal(x.DNSNames, []string{"interop.example"}) || len(x.IPAddresses) != 1 || x.IPAddresses[0].String() != "192.0.2.9" {
			t.Errorf("SANs DNS %v IP %v, want interop.example / 192.0.2.9", x.DNSNames, x.IPAddresses)
		}
		if k, ok := x.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 2048 {
			t.Errorf("public key %T, want RSA 2048", x.PublicKey)
		}
		if lifetime := x.NotAfter.Sub(x.NotBefore); lifetime < 71*time.Hour || lifetime > 73*time.Hour {
			t.Errorf("lifetime %v, want about 3 days", lifetime)
		}
		if !bytes.Equal(groupCertificate(t, srv), before) {
			t.Fatal("the go server installed the cancelled self-signed certificate")
		}
	})

	t.Run("coverage/certmgmt.push.delete-certificate/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAsyncOpcuaV015(t, "clientFeatures", "push-certificates")
		endpoint, srv := startPushGoServer(t)
		before := groupCertificate(t, srv)
		out := mustAsyncOpcuaPush(t, endpoint, nil, "--delete-certificate", appType)
		if !good(out.DeleteCertificateStatus) || !good(out.CancelChangesStatus) {
			t.Fatalf("delete %+v, cancel %+v; want Good", out.DeleteCertificateStatus, out.CancelChangesStatus)
		}
		// Applied: the certificate of the endpoints is not deleted
		// (Part 12 1.05 §7.10): Bad_InvalidState at ApplyChanges.
		res, out := runAsyncOpcuaPush(t, endpoint, false, nil, "--delete-certificate", appType, "--apply")
		if !good(out.DeleteCertificateStatus) {
			t.Fatalf("DeleteCertificate: %+v", out.DeleteCertificateStatus)
		}
		if res.Success || out.ApplyChangesStatus == nil || out.ApplyChangesStatus.Code != uint32(ua.StatusBadInvalidState) ||
			res.ServiceResult.Code != uint32(ua.StatusBadInvalidState) {
			t.Fatalf("ApplyChanges of the deletion: success %v, %+v (serviceResult %s); want Bad_InvalidState", res.Success, out.ApplyChangesStatus, res.ServiceResult)
		}
		if out.TrustListAfter != nil {
			t.Error("trustListAfter present after a failed step")
		}
		if !bytes.Equal(groupCertificate(t, srv), before) {
			t.Fatal("the go server deleted the certificate of its endpoints")
		}
		res, out = runAsyncOpcuaPush(t, endpoint, false, nil, "--delete-certificate", fmt.Sprintf("i=%d", id.EccNistP256ApplicationCertificateType))
		if res.Success || out.DeleteCertificateStatus == nil || out.DeleteCertificateStatus.Code == 0 {
			t.Fatalf("DeleteCertificate of an ECC type: success %v, %+v; want a Bad status", res.Success, out.DeleteCertificateStatus)
		}
	})

	groupTrustList := func(t *testing.T, group string, groupID *ua.NodeID) {
		requireAsyncOpcuaV015(t, "clientFeatures", "push-groups")
		endpoint, srv := startPushGoServer(t)
		extra, _, err := testpki.SelfSigned("go-opcua interop "+group+" async-opcua", "urn:otfabric:interop:"+strings.ToLower(group))
		if err != nil {
			t.Fatal(err)
		}
		out := mustAsyncOpcuaPush(t, endpoint, map[string][]byte{"add.der": extra}, "--group", group, "--add-certificate", "/work/add.der", "--apply")
		if out.CertificateGroupID != groupID.String() {
			t.Errorf("certificateGroupId %q, want %v", out.CertificateGroupID, groupID)
		}
		if out.TrustList.has(extra) || out.TrustListAfter == nil || !out.TrustListAfter.has(extra) {
			t.Fatalf("the %s trust list before / after AddCertificate + ApplyChanges: %+v / %+v", group, out.TrustList, out.TrustListAfter)
		}
		if !containsCert(srv.GroupTrustList(groupID).TrustedCertificates, extra) {
			t.Fatalf("the go server's %s trust list does not trust the certificate async-opcua added", group)
		}
		if containsCert(srv.TrustList().TrustedCertificates, extra) {
			t.Fatalf("the certificate added to the %s group is in the application trust list", group)
		}
	}
	t.Run("coverage/certmgmt.push.https-group/async-opcua-client-to-go-server", func(t *testing.T) {
		groupTrustList(t, "Https", gds.DefaultHTTPSGroup)
	})
	t.Run("coverage/certmgmt.push.usertoken-group/async-opcua-client-to-go-server", func(t *testing.T) {
		groupTrustList(t, "UserToken", gds.DefaultUserTokenGroup)
	})

	t.Run("coverage/certmgmt.push.pfx/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAsyncOpcuaV015(t, "clientFeatures", "push-certificates")
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
		out := mustAsyncOpcuaPush(t, endpoint, map[string][]byte{"new.der": newDER, "new.pfx": pfx, "ca.der": caDER},
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
		pushClient(t, endpoint, false)
	})

	t.Run("coverage/certmgmt.push.transaction-diagnostics/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAsyncOpcuaV015(t, "clientFeatures", "push-transaction-diagnostics")
		endpoint, _ := startPushGoServer(t)
		extra, _, err := testpki.SelfSigned("go-opcua interop diagnostics async-opcua", "urn:otfabric:interop:diagnostics")
		if err != nil {
			t.Fatal(err)
		}
		out := mustAsyncOpcuaPush(t, endpoint, map[string][]byte{"add.der": extra}, "--add-certificate", "/work/add.der", "--apply", "--transaction-diagnostics")
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
		res, out := runAsyncOpcuaPush(t, endpoint, false, nil, "--delete-certificate", appType, "--apply", "--transaction-diagnostics")
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

	// GetCertificates and ResetToServerDefaults: the rows are verified with
	// `client call` (certmgmt_call_peer_test.go); these exercise the flags.
	t.Run("get-certificates/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAsyncOpcuaV015(t, "clientFeatures", "push-certificates")
		endpoint, _ := startPushGoServer(t)
		out := mustAsyncOpcuaPush(t, endpoint, nil, "--get-certificates")
		if !good(out.GetCertificatesStatus) || len(out.CertificateTypeIDs) != len(out.Certificates) {
			t.Fatalf("GetCertificates %+v: %d types, %d certificates", out.GetCertificatesStatus, len(out.CertificateTypeIDs), len(out.Certificates))
		}
		i := slices.Index(out.CertificateTypeIDs, appType)
		if i < 0 || !bytes.Equal(decodeB64(t, out.Certificates[i]), loadGoServerCert(t)) {
			t.Fatalf("GetCertificates types %v: no RsaSha256 application certificate of the go server", out.CertificateTypeIDs)
		}
	})
	t.Run("reset-to-defaults/async-opcua-client-to-go-server", func(t *testing.T) {
		requireAsyncOpcuaV015(t, "clientFeatures", "push-certificates")
		endpoint, srv := startPushGoServer(t)
		extra, _, err := testpki.SelfSigned("go-opcua interop reset async-opcua", "urn:otfabric:interop:reset")
		if err != nil {
			t.Fatal(err)
		}
		mustAsyncOpcuaPush(t, endpoint, map[string][]byte{"add.der": extra}, "--add-certificate", "/work/add.der", "--apply")
		out := mustAsyncOpcuaPush(t, endpoint, nil, "--reset-to-defaults")
		if !good(out.ResetToServerDefaultsStatus) || containsCert(srv.TrustList().TrustedCertificates, extra) {
			t.Fatalf("ResetToServerDefaults %+v: the added certificate is still trusted", out.ResetToServerDefaultsStatus)
		}
		if out.TrustListAfter == nil || out.TrustListAfter.has(extra) {
			t.Fatalf("the trust list read after ResetToServerDefaults: %+v", out.TrustListAfter)
		}
	})
	t.Run("anonymous/async-opcua-client-to-go-server", func(t *testing.T) {
		endpoint, _ := startPushGoServer(t)
		res, _ := runAsyncOpcuaPush(t, endpoint, true, nil)
		if res.Success || !statusCodeNameHas(res.ServiceResult, "UserAccessDenied") {
			t.Fatalf("anonymous push: success %v, %s; want Bad_UserAccessDenied", res.Success, res.ServiceResult.Name)
		}
	})
}

// runAsyncOpcuaGDSPull runs `client gds-pull` of the async-opcua adapter
// against endpoint as gds-admin over Basic256Sha256 SignAndEncrypt.
func runAsyncOpcuaGDSPull(t *testing.T, endpoint string, args ...string) gdsPullResult {
	t.Helper()
	requireAsyncOpcuaImage(t)
	res := runSecureAdapterClient(t, asyncOpcuaEnv, defaultAsyncOpcuaImage, "async-opcua-client", endpoint, "gds-pull",
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

// TestGDSPull_AsyncOpcuaClient_GoServer: the GDS pull model from the
// async-opcua adapter's `client gds-pull` (plain Calls of async-opcua 0.19.0
// on the Directory) against gdsserver.
func TestGDSPull_AsyncOpcuaClient_GoServer(t *testing.T) {
	requireAsyncOpcuaImage(t)
	requireAsyncOpcuaV015(t, "clientOperations", "gds-pull")
	endpoint, g := startGDSGoServer(t)
	ca := loadCACertDER(t)
	group := g.DefaultApplicationGroup().String()
	const uri = "urn:otfabric:interop:gds-pull:async-opcua-client"

	var csr gdsPullResult
	t.Run("coverage/gds.pull.directory/async-opcua-client-to-go-server", func(t *testing.T) {
		csr = runAsyncOpcuaGDSPull(t, endpoint, "--app-uri", uri, "--request", "csr", "--certificate-type", "RsaSha256")
		if !csr.Registered || len(csr.FindApplications) != 0 || csr.ApplicationID == "" {
			t.Fatalf("FindApplications / RegisterApplication: %+v", csr)
		}
		// A second run finds the record.
		again := runAsyncOpcuaGDSPull(t, endpoint, "--app-uri", uri, "--request", "csr", "--certificate-type", "NistP256")
		if again.Registered || !slices.Equal(again.FindApplications, []string{csr.ApplicationID}) || again.ApplicationID != csr.ApplicationID {
			t.Fatalf("the second run did not find the record: %+v", again)
		}
		cert, err := x509.ParseCertificate(decodeB64(t, again.Certificate))
		if err != nil {
			t.Fatal(err)
		}
		if cert.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("the NistP256 request issued a %v certificate", cert.PublicKeyAlgorithm)
		}
	})

	t.Run("coverage/gds.pull.certificate-request/async-opcua-client-to-go-server", func(t *testing.T) {
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
		if cert.Subject.CommonName != "async-opcua-client" || !slices.Contains(cert.DNSNames, "localhost") {
			t.Errorf("certificate subject %v, DNS %v; want CN=async-opcua-client and localhost", cert.Subject, cert.DNSNames)
		}
		if len(csr.IssuerCertificates) == 0 || !bytes.Equal(decodeB64(t, csr.IssuerCertificates[0]), ca) {
			t.Fatal("the issuer is not the RSA CA of the go GDS")
		}
		nk := runAsyncOpcuaGDSPull(t, endpoint, "--app-uri", uri+":nk", "--request", "new-key-pair", "--certificate-type", "NistP256")
		if nk.RequestKind != "new-key-pair" || nk.PrivateKeyFormat != "PEM" {
			t.Fatalf("requestKind %q privateKeyFormat %q", nk.RequestKind, nk.PrivateKeyFormat)
		}
		key, err := gds.DecodePrivateKey(gds.PrivateKeyFormatPEM, decodeB64(t, nk.PrivateKey), "")
		if err != nil {
			t.Fatalf("the private key gdsserver delivered: %v", err)
		}
		if !uapolicy.KeyMatchesCertificate(key, decodeB64(t, nk.Certificate)) {
			t.Fatal("the private key is not that of the certificate")
		}
	})

	t.Run("coverage/gds.pull.trust-list/async-opcua-client-to-go-server", func(t *testing.T) {
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

	t.Run("coverage/gds.pull.revocation/async-opcua-client-to-go-server", func(t *testing.T) {
		res := runAsyncOpcuaGDSPull(t, endpoint, "--app-uri", uri+":revoke", "--request", "new-key-pair",
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

// runAsyncOpcuaQuery runs `client query` for the QueryType instances of
// startQueryGoServer with their Serial and BrowseName.
func runAsyncOpcuaQuery(t *testing.T, endpoint string, args ...string) (adapterResult, queryResult) {
	t.Helper()
	base := []string{"--type-definition", "nsu=" + interopNamespaceURI + ";s=QueryType",
		"--data-to-return", ".Serial", "--data-to-return", "#BrowseName"}
	res := runAsyncOpcuaClientResult(t, endpoint, "query", append(base, args...)...)
	var items []queryResult
	if err := json.Unmarshal(res.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("query results %s: %v (success %v, %s, error %s)", res.Results, err, res.Success, res.ServiceResult, res.Error)
	}
	return res, items[0]
}

// TestGoServer_AsyncOpcuaClient_Query: QueryFirst / QueryNext of the
// async-opcua adapter (raw requests on the session's channel) against the
// go-opcua Query service set.
func TestGoServer_AsyncOpcuaClient_Query(t *testing.T) {
	requireAsyncOpcuaImage(t)
	requireAsyncOpcuaV015(t, "clientOperations", "query")
	endpoint, nsIdx := startQueryGoServer(t)

	t.Run("coverage/query.first/async-opcua-client-to-go-server", func(t *testing.T) {
		res, out := runAsyncOpcuaQuery(t, endpoint)
		if !res.Success {
			t.Fatalf("client query: %s %s", res.ServiceResult, res.Error)
		}
		if out.TypeDefinitionNode != fmt.Sprintf("ns=%d;s=QueryType", nsIdx) {
			t.Errorf("typeDefinitionNode %s", out.TypeDefinitionNode)
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
		assertQueryDataSets(t, out.QueryDataSets, nsIdx)

		// An unknown type: no data sets, or a Bad status of QueryFirst.
		res = runAsyncOpcuaClientResult(t, endpoint, "query", "--type-definition", "nsu="+interopNamespaceURI+";s=NoSuchType")
		var items []queryResult
		if err := json.Unmarshal(res.Results, &items); err != nil || len(items) != 1 {
			t.Fatalf("query of an unknown type: %s %v", res.Results, err)
		}
		if res.Success && len(items[0].QueryDataSets) != 0 {
			t.Fatalf("query of an unknown type returned %d data sets", len(items[0].QueryDataSets))
		}
		t.Logf("QueryFirst of an unknown type: %s", items[0].QueryFirst.StatusCode)
	})

	t.Run("coverage/query.next/async-opcua-client-to-go-server", func(t *testing.T) {
		res, out := runAsyncOpcuaQuery(t, endpoint, "--max-data-sets", "2")
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
		res, out = runAsyncOpcuaQuery(t, endpoint, "--max-data-sets", "2", "--release-continuation-point")
		if !res.Success || len(out.QueryNext) != 1 {
			t.Fatalf("client query --release-continuation-point: %s %s, %d QueryNext", res.ServiceResult, res.Error, len(out.QueryNext))
		}
		if n := out.QueryNext[0]; !n.ReleaseContinuationPoint || n.StatusCode.Code != 0 || len(n.QueryDataSets) != 0 || n.RevisedContinuationPoint != nil {
			t.Fatalf("the releasing QueryNext: %+v", n)
		}
	})
}
