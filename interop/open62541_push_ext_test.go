//go:build interop

// SPDX-License-Identifier: MIT

// The open62541 adapter's `client push` (CLIENT_CONTRACT §1 "push flags",
// §15) and `client gds-pull` (§16.2) of opcua-interop v0.15.0 (unreleased
// when these tests were written; built from the opcua-interop branch
// feat/open62541-push). open62541 v1.5.9 has neither a push nor a GDS client
// API, so the adapter builds both on UA_Client_call:
//
//	open62541-client-to-go-server   `client push` (all the v0.15.0 flags)
//	                                against server.WithPushManagement;
//	                                `client gds-pull` against gdsserver
//
// The tests are the shared ones of the node-opcua push client
// (testCertMgmtPushExt) and the dotnet-gds pull client
// (testGDSPullGoServer). They are gated on the capabilities the adapter
// advertises (clientOperations push / gds-pull, clientFeatures push-groups,
// push-certificates, push-transaction-diagnostics); until the pinned image
// has them they skip, also under OPCUA_INTEROP_REQUIRE_CAPABILITIES=1. Run
// them against a local build with
//
//	OPEN62541_IMAGE=opcua-interop-open62541:push-ext go test -tags=interop -run 'Open62541Client_GoServer' ./interop/
//
// COVERAGE: coverage.json certmgmt.push.trust-list,
// certmgmt.push.certificate-update, certmgmt.push.create-self-signed,
// certmgmt.push.delete-certificate, certmgmt.push.https-group,
// certmgmt.push.usertoken-group, certmgmt.push.pfx,
// certmgmt.push.transaction-diagnostics, gds.pull.directory,
// gds.pull.certificate-request, gds.pull.trust-list, gds.pull.revocation

package interop

import "testing"

const (
	open62541Env                 = "OPEN62541_IMAGE"
	dirOpen62541ClientToGoServer = "open62541-client-to-go-server"
)

// requireOpen62541Image returns the capabilities of the open62541 image; the
// default image must be the pinned release.
func requireOpen62541Image(t *testing.T) *adapterCaps {
	t.Helper()
	caps, image := imageCapabilities(t, open62541Env, defaultOpen62541Image)
	requirePinnedVersion(t, open62541Env, caps, image)
	return caps
}

// open62541PushClient is the open62541 adapter's `client push`.
var open62541PushClient = pushExtClient{
	name: "open62541", env: open62541Env, defaultImage: defaultOpen62541Image, pki: "open62541-client",
	direction: dirOpen62541ClientToGoServer, require: requireOpen62541Image, coreRows: true,
}

// TestCertMgmtPushExt_Open62541Client_GoServer: the open62541 adapter's
// `client push` against server.WithPushManagement, with the trust list and
// certificate update rows.
func TestCertMgmtPushExt_Open62541Client_GoServer(t *testing.T) {
	testCertMgmtPushExt(t, open62541PushClient)
}

// TestGDSPull_Open62541Client_GoServer: the open62541 adapter's `client
// gds-pull` against gdsserver.
func TestGDSPull_Open62541Client_GoServer(t *testing.T) {
	requireV015(t, open62541PushClient, "clientOperations", "gds-pull")
	testGDSPullGoServer(t, gdsPullClient{
		name: "open62541", env: open62541Env, defaultImage: defaultOpen62541Image, pki: "open62541-client",
		direction: dirOpen62541ClientToGoServer,
	})
}
