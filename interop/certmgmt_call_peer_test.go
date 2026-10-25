//go:build interop

// SPDX-License-Identifier: MIT

// Push certificate management (Part 12 §7) of the go-opcua server driven by
// the generic operations of the peer clients (CLIENT_CONTRACT §1 "call
// flags", "translate flags", "read flags"), for the adapters that have no
// `client push` or whose `client push` does not cover the method:
//
//	certmgmt.push.rejected-list      GetRejectedList (§7.10.9) returns the
//	                                 certificate of a client the server refused
//	certmgmt.push.get-certificates   GetCertificates (§7.10.8) of the
//	                                 DefaultApplicationGroup
//	certmgmt.push.reset-to-defaults  ResetToServerDefaults (§7.10.13) restores
//	                                 the configured trust list
//	certmgmt.push.access             the methods are refused to an anonymous
//	                                 session and on a Sign-only channel
//	certmgmt.push.alarms             CertificateExpired / TrustListOutOfDate
//	                                 (§7.8.5, §7.8.6) of the
//	                                 DefaultApplicationGroup, read by browse path
//
// The peer client connects over Basic256Sha256 SignAndEncrypt as the
// SecurityAdmin user of startPushGoServer unless a check says otherwise.

package interop

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// callPeer is a peer client driven through its generic operations.
type callPeer struct {
	name      string
	env       string
	image     string
	pki       string // test PKI identity of the client
	direction string
	// caps are the capabilities this test verifies for the peer; the others
	// are verified elsewhere (node-opcua's `client push`).
	caps []string
}

const (
	capRejectedList    = "certmgmt.push.rejected-list"
	capGetCertificates = "certmgmt.push.get-certificates"
	capResetToDefaults = "certmgmt.push.reset-to-defaults"
	capPushAccess      = "certmgmt.push.access"
	capPushAlarms      = "certmgmt.push.alarms"
)

var allCallCaps = []string{capRejectedList, capGetCertificates, capResetToDefaults, capPushAccess, capPushAlarms}

func TestCertMgmtPush_Open62541ClientCall_GoServer(t *testing.T) {
	runCertMgmtCallPeer(t, callPeer{name: "open62541", env: "OPEN62541_IMAGE", image: defaultOpen62541Image,
		pki: "open62541-client", direction: "open62541-client-to-go-server", caps: allCallCaps})
}

func TestCertMgmtPush_MiloClientCall_GoServer(t *testing.T) {
	runCertMgmtCallPeer(t, callPeer{name: "milo", env: "MILO_IMAGE", image: defaultMiloImage,
		pki: "milo-client", direction: "milo-client-to-go-server", caps: allCallCaps})
}

func TestCertMgmtPush_AsyncuaClientCall_GoServer(t *testing.T) {
	runCertMgmtCallPeer(t, callPeer{name: "asyncua", env: asyncuaEnv, image: defaultAsyncuaImage,
		pki: "asyncua-client", direction: "asyncua-client-to-go-server", caps: allCallCaps})
}

func TestCertMgmtPush_AsyncOpcuaClientCall_GoServer(t *testing.T) {
	runCertMgmtCallPeer(t, callPeer{name: "async-opcua", env: asyncOpcuaEnv, image: defaultAsyncOpcuaImage,
		pki: "async-opcua-client", direction: "async-opcua-client-to-go-server", caps: allCallCaps})
}

func TestCertMgmtPush_DotnetClientCall_GoServer(t *testing.T) {
	runCertMgmtCallPeer(t, callPeer{name: "dotnet", env: dotnetEnv, image: defaultDotnetImage,
		pki: "dotnet-client", direction: dirDotnetClientToGoServer, caps: allCallCaps})
}

// TestCertMgmtPush_NodeOpcuaClientCall_GoServer: rejected-list and access of
// node-opcua are verified with its `client push`
// (TestCertMgmtPush_NodeOpcuaClient_GoServer).
func TestCertMgmtPush_NodeOpcuaClientCall_GoServer(t *testing.T) {
	runCertMgmtCallPeer(t, callPeer{name: "node-opcua", env: nodeOpcuaEnv, image: defaultNodeOpcuaImage,
		pki: "node-opcua-client", direction: "node-opcua-client-to-go-server",
		caps: []string{capGetCertificates, capResetToDefaults, capPushAlarms}})
}

func runCertMgmtCallPeer(t *testing.T, p callPeer) {
	requireAdapterOp(t, p.env, p.image, "call")
	for _, c := range p.caps {
		t.Run("coverage/"+c+"/"+p.direction, func(t *testing.T) {
			switch c {
			case capRejectedList:
				p.assertRejectedList(t)
			case capGetCertificates:
				p.assertGetCertificates(t)
			case capResetToDefaults:
				p.assertResetToDefaults(t)
			case capPushAccess:
				p.assertAccess(t)
			case capPushAlarms:
				p.assertAlarms(t)
			}
		})
	}
}

// run runs a peer client operation over Basic256Sha256 in mode, as the
// SecurityAdmin user when admin is set.
func (p callPeer) run(t *testing.T, endpoint, mode string, admin bool, subcmd string, args ...string) adapterResult {
	t.Helper()
	if admin {
		args = append(args, "--username", pushAdminUser, "--password", pushAdminPass)
	}
	return runSecureAdapterClientResult(t, p.env, p.image, p.pki, endpoint, subcmd, "Basic256Sha256", mode, args...)
}

// call calls a method of ServerConfiguration and returns the status of the
// method (the service result when the adapter reports no method result)
// and its output arguments.
func (p callPeer) call(t *testing.T, endpoint, mode string, admin bool, method uint32, inputs ...string) (statusCodeObj, []json.RawMessage) {
	t.Helper()
	args := []string{"--object", ua.NewNumericNodeID(0, id.ServerConfiguration).String(),
		"--method", ua.NewNumericNodeID(0, method).String()}
	for _, in := range inputs {
		args = append(args, "--input", in)
	}
	r := p.run(t, endpoint, mode, admin, "call", args...)
	var items []alarms105CallResult
	if err := json.Unmarshal(r.Results, &items); err != nil || len(items) == 0 {
		if r.Adapter == "" {
			t.Fatalf("call i=%d: no adapter result", method)
		}
		return r.ServiceResult, nil
	}
	var outs []json.RawMessage
	if len(items[0].OutputArguments) > 0 && string(items[0].OutputArguments) != "null" {
		if err := json.Unmarshal(items[0].OutputArguments, &outs); err != nil {
			t.Fatalf("call i=%d: outputArguments %s: %v", method, items[0].OutputArguments, err)
		}
	}
	return items[0].StatusCode, outs
}

// mustCallGood is call as the SecurityAdmin over SignAndEncrypt that expects Good.
func (p callPeer) mustCallGood(t *testing.T, endpoint string, method uint32, inputs ...string) []json.RawMessage {
	t.Helper()
	sc, outs := p.call(t, endpoint, "SignAndEncrypt", true, method, inputs...)
	if sc.Code != uint32(ua.StatusOK) {
		t.Fatalf("call i=%d: %s, want Good", method, sc)
	}
	return outs
}

// byteStrings decodes a ByteString[] output argument: Base64 strings (§7),
// or the Java object {"bytes": <Base64>, ...} the Milo adapter prints for a
// ByteString of an array.
func byteStrings(t *testing.T, raw json.RawMessage) [][]byte {
	t.Helper()
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		t.Fatalf("ByteString[] output %s: %v", raw, err)
	}
	out := make([][]byte, len(elems))
	for i, e := range elems {
		var s string
		var obj struct {
			Bytes *string `json:"bytes"`
		}
		switch {
		case json.Unmarshal(e, &s) == nil:
		case json.Unmarshal(e, &obj) == nil && obj.Bytes != nil:
			s = *obj.Bytes
		default:
			t.Fatalf("ByteString[] output element %d: %.80s", i, e)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("ByteString[] output element %d: %v", i, err)
		}
		out[i] = b
	}
	return out
}

// nodeIDs decodes a NodeId[] output argument: canonical strings (§6), or
// the Java object (namespaceIndex, identifier) the Milo adapter prints for
// a NodeId of an array.
func nodeIDs(t *testing.T, raw json.RawMessage) []*ua.NodeID {
	t.Helper()
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		t.Fatalf("NodeId[] output %s: %v", raw, err)
	}
	out := make([]*ua.NodeID, len(elems))
	for i, e := range elems {
		var s string
		var obj struct {
			NamespaceIndex json.Number `json:"namespaceIndex"`
			Identifier     any         `json:"identifier"`
		}
		switch {
		case json.Unmarshal(e, &s) == nil:
			n, err := ua.ParseNodeID(s)
			if err != nil {
				t.Fatalf("NodeId[] output element %s: %v", e, err)
			}
			out[i] = n
		case json.Unmarshal(e, &obj) == nil && obj.Identifier != nil:
			ns, _ := obj.NamespaceIndex.Int64()
			n, err := ua.ParseNodeID(fmt.Sprintf("ns=%d;i=%v", ns, obj.Identifier))
			if err != nil {
				t.Fatalf("NodeId[] output element %s: %v", e, err)
			}
			out[i] = n
		default:
			t.Fatalf("NodeId[] output element %s", e)
		}
	}
	return out
}

// assertRejectedList: the go server refuses a client with a self-signed
// application certificate it does not trust, then GetRejectedList returns
// that certificate. The certificate is made here: UA-.NETStandard cannot use
// the key of the "untrusted" identity of the test PKI (a CA certificate), so
// it would fail before it opens a channel.
func (p callPeer) assertRejectedList(t *testing.T) {
	endpoint, _ := startPushGoServer(t)
	untrustedDER, r := p.runUntrusted(t, endpoint)
	if r.Success {
		t.Fatal("the untrusted client was accepted")
	}

	outs := p.mustCallGood(t, endpoint, id.ServerConfigurationGetRejectedList)
	if len(outs) != 1 {
		t.Fatalf("GetRejectedList: %d output arguments, want 1", len(outs))
	}
	rej := byteStrings(t, outs[0])
	if !containsCert(rej, untrustedDER) {
		t.Fatalf("GetRejectedList (%d certificates) lacks the untrusted client (its read: %s %s)", len(rej), r.ServiceResult, r.Error)
	}
}

// runUntrusted runs the peer's read over Basic256Sha256 SignAndEncrypt with
// a new self-signed application certificate and returns that certificate.
func (p callPeer) runUntrusted(t *testing.T, endpoint string) ([]byte, adapterResult) {
	t.Helper()
	requireOptionalPeer(t, p.env, p.image)
	appURI := "urn:otfabric:interop:untrusted:" + p.name
	der, key, err := testpki.SelfSigned("go-opcua interop untrusted "+p.name, appURI)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := containerScratchDir(t)
	certFile, keyFile := filepath.Join(dir, "cert.crt"), filepath.Join(dir, "cert.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := shareWithContainers(dir); err != nil {
		t.Fatal(err)
	}
	raw, _ := runClientContainer(t, []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", certFile + ":/certs/cert.crt:ro",
		"-v", keyFile + ":/certs/cert.key:ro",
		"-v", filepath.Join(pkiDir(t), "ca", "ca.crt") + ":/certs/ca.crt:ro",
		getEnvOr(p.env, p.image),
		"client", "read",
		"--endpoint", strings.ReplaceAll(endpoint, "localhost", "host.docker.internal"),
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--trust-list", "/certs/ca.crt",
		"--security-policy", "Basic256Sha256",
		"--security-mode", "SignAndEncrypt",
		"--node", "i=2259",
	})
	r, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse the result of the untrusted read: %v\nraw: %s", err, raw)
	}
	return der, r
}

// assertGetCertificates: GetCertificates of the DefaultApplicationGroup
// returns the application certificate of the go server and its type.
func (p callPeer) assertGetCertificates(t *testing.T) {
	endpoint, _ := startPushGoServer(t)
	group := ua.NewNumericNodeID(0, id.ServerConfigurationCertificateGroupsDefaultApplicationGroup)
	if !group.Equal(gds.DefaultApplicationGroup) {
		t.Fatalf("DefaultApplicationGroup %s != %s", group, gds.DefaultApplicationGroup)
	}
	outs := p.mustCallGood(t, endpoint, id.ServerConfigurationGetCertificates, "NodeId:"+group.String())
	if len(outs) != 2 {
		t.Fatalf("GetCertificates: %d output arguments, want 2 (%s)", len(outs), outs)
	}
	types := nodeIDs(t, outs[0])
	certs := byteStrings(t, outs[1])
	if len(types) != 1 || len(certs) != 1 {
		t.Fatalf("GetCertificates: CertificateTypeIds %v, %d certificates; want one of each", types, len(certs))
	}
	if want := ua.NewNumericNodeID(0, id.RsaSha256ApplicationCertificateType); !types[0].Equal(want) {
		t.Errorf("CertificateTypeIds[0] = %s, want %s (RsaSha256ApplicationCertificateType)", types[0], want)
	}
	if !bytes.Equal(certs[0], loadGoServerCert(t)) {
		t.Error("Certificates[0] is not the application certificate of the go server")
	}
}

// assertResetToDefaults: a certificate the go-opcua gds client added to the
// trust list is gone after ResetToServerDefaults; the trust list is the
// configured one (the test CA) again.
func (p callPeer) assertResetToDefaults(t *testing.T) {
	endpoint, srv := startPushGoServer(t)
	ca := loadCACertDER(t)
	extra, _, err := testpki.SelfSigned("go-opcua interop reset "+p.name, "urn:otfabric:interop:push")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	g := gds.New(pushClient(t, endpoint, true))
	if err := g.AddCertificate(ctx, extra, true); err != nil {
		t.Fatalf("AddCertificate: %v", err)
	}
	if err := g.ApplyChanges(ctx); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if !containsCert(srv.TrustList().TrustedCertificates, extra) {
		t.Fatal("the added certificate is not trusted before the reset")
	}

	if outs := p.mustCallGood(t, endpoint, id.ServerConfigurationResetToServerDefaults); len(outs) != 0 {
		t.Fatalf("ResetToServerDefaults: output arguments %s, want none", outs)
	}
	tl := srv.TrustList()
	if len(tl.TrustedCertificates) != 1 || !bytes.Equal(tl.TrustedCertificates[0], ca) ||
		len(tl.TrustedCrls) != 0 || len(tl.IssuerCertificates) != 0 || len(tl.IssuerCrls) != 0 {
		t.Fatalf("trust list after ResetToServerDefaults: %d trusted (CA %v, added %v), %d CRLs, %d issuers, %d issuer CRLs; want the test CA only",
			len(tl.TrustedCertificates), containsCert(tl.TrustedCertificates, ca), containsCert(tl.TrustedCertificates, extra),
			len(tl.TrustedCrls), len(tl.IssuerCertificates), len(tl.IssuerCrls))
	}
}

// assertAccess: GetRejectedList is refused to an anonymous session
// (Bad_UserAccessDenied) and to the SecurityAdmin on a Sign-only channel
// (Bad_SecurityModeInsufficient).
func (p callPeer) assertAccess(t *testing.T) {
	endpoint, _ := startPushGoServerWith(t, server.PushManagement{},
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign))
	if sc, _ := p.call(t, endpoint, "SignAndEncrypt", false, id.ServerConfigurationGetRejectedList); sc.Code != uint32(ua.StatusBadUserAccessDenied) {
		t.Errorf("anonymous GetRejectedList: %s, want Bad_UserAccessDenied", sc)
	}
	if sc, _ := p.call(t, endpoint, "Sign", true, id.ServerConfigurationGetRejectedList); sc.Code != uint32(ua.StatusBadSecurityModeInsufficient) {
		t.Errorf("GetRejectedList over Sign: %s, want Bad_SecurityModeInsufficient", sc)
	}
	// The same call as the SecurityAdmin over SignAndEncrypt is allowed.
	p.mustCallGood(t, endpoint, id.ServerConfigurationGetRejectedList)
}

// translateRead resolves the browse path below ServerConfiguration with the
// peer's translate and reads the target with the peer's read.
func (p callPeer) translateRead(t *testing.T, endpoint string, path ...string) json.RawMessage {
	t.Helper()
	r := p.run(t, endpoint, "SignAndEncrypt", true, "translate",
		"--starting-node", ua.NewNumericNodeID(0, id.ServerConfiguration).String(),
		"--path", strings.Join(path, "."))
	var tr []struct {
		StatusCode statusCodeObj `json:"statusCode"`
		Targets    []string      `json:"targets"`
	}
	if err := json.Unmarshal(r.Results, &tr); err != nil || len(tr) != 1 || len(tr[0].Targets) != 1 {
		t.Fatalf("translate %v: %v; success %v %s results %s", path, err, r.Success, r.ServiceResult, r.Results)
	}
	r = p.run(t, endpoint, "SignAndEncrypt", true, "read", "--node", tr[0].Targets[0])
	var rr []struct {
		StatusCode statusCodeObj   `json:"statusCode"`
		Value      json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(r.Results, &rr); err != nil || len(rr) != 1 {
		t.Fatalf("read %s (%v): %v; results %s", tr[0].Targets[0], path, err, r.Results)
	}
	if rr[0].StatusCode.Code != uint32(ua.StatusOK) {
		t.Fatalf("read %s (%v): %s", tr[0].Targets[0], path, rr[0].StatusCode)
	}
	return rr[0].Value
}

// assertAlarms: the CertificateExpired alarm of the DefaultApplicationGroup
// is active (an ExpirationLimit longer than the life of the certificate) and
// reports the certificate; TrustListOutOfDate is inactive (the trust list
// is due for an update only after an hour).
func (p callPeer) assertAlarms(t *testing.T) {
	requireAdapterOp(t, p.env, p.image, "translate")
	requireAdapterOp(t, p.env, p.image, "read")
	endpoint, _ := startPushGoServerWith(t, server.PushManagement{
		TrustListUpdateFrequency: time.Hour,
		Alarms:                   &server.CertificateAlarms{ExpirationLimit: 100 * 365 * 24 * time.Hour},
	})
	group := []string{"CertificateGroups", "DefaultApplicationGroup"}
	boolAt := func(path ...string) bool {
		t.Helper()
		raw := p.translateRead(t, endpoint, append(slices.Clone(group), path...)...)
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatalf("%v: value %s is not a Boolean", path, raw)
		}
		return b
	}
	if !boolAt("CertificateExpired", "ActiveState", "Id") {
		t.Error("CertificateExpired.ActiveState.Id = false, want true")
	}
	if boolAt("TrustListOutOfDate", "ActiveState", "Id") {
		t.Error("TrustListOutOfDate.ActiveState.Id = true, want false")
	}
	raw := p.translateRead(t, endpoint, append(slices.Clone(group), "CertificateExpired", "Certificate")...)
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("CertificateExpired.Certificate value %s: %v", raw, err)
	}
	if der, err := base64.StdEncoding.DecodeString(s); err != nil || !bytes.Equal(der, loadGoServerCert(t)) {
		t.Errorf("CertificateExpired.Certificate is not the application certificate of the go server (%v)", err)
	}
}
