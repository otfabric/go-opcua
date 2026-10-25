//go:build interop

// SPDX-License-Identifier: MIT

// The Eclipse Milo adapter's `client push` (CLIENT_CONTRACT §1 "push flags",
// §15) and `client gds-pull` (§16.2) of opcua-interop v0.15.0 (unreleased
// when these tests were written; built from the opcua-interop branch
// feat/milo-push). Milo 1.1.8 has neither a push nor a GDS client, so the
// adapter builds both on plain Calls (OpcUaClient.call):
//
//	milo-client-to-go-server   `client push` (all the v0.15.0 flags)
//	                           against server.WithPushManagement;
//	                           `client gds-pull` against gdsserver
//
// The tests are the shared ones of the node-opcua push client
// (testCertMgmtPushExt) and the dotnet-gds pull client
// (testGDSPullGoServer). They are gated on the capabilities the adapter
// advertises (clientOperations push / gds-pull, clientFeatures push-groups,
// push-certificates, push-transaction-diagnostics); until the pinned image
// has them they skip, also under OPCUA_INTEROP_REQUIRE_CAPABILITIES=1. Run
// them against a local build with
//
//	MILO_IMAGE=opcua-interop-milo:push-ext go test -tags=interop -run 'Milo.*_GoServer' ./interop/
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
	miloEnv                 = "MILO_IMAGE"
	miloClientPKI           = "milo-client"
	dirMiloClientToGoServer = "milo-client-to-go-server"
)

// requireMiloImage skips (or fails with OPCUA_INTEROP_REQUIRE_CAPABILITIES=1
// when MILO_IMAGE is set) when the Milo adapter image cannot report its
// capabilities, and fails when the default image is not the release this
// suite is written against.
func requireMiloImage(t *testing.T) *adapterCaps {
	t.Helper()
	caps, image := imageCapabilities(t, miloEnv, defaultMiloImage)
	requirePinnedVersion(t, miloEnv, caps, image)
	return caps
}

// miloPushClient is the Milo adapter's `client push`.
var miloPushClient = pushExtClient{
	name: "milo", env: miloEnv, defaultImage: defaultMiloImage, pki: miloClientPKI,
	direction: dirMiloClientToGoServer, require: requireMiloImage, coreRows: true,
}

// TestCertMgmtPushExt_MiloClient_GoServer: the Milo adapter's `client push`
// against server.WithPushManagement, with the trust list and certificate
// update rows.
func TestCertMgmtPushExt_MiloClient_GoServer(t *testing.T) {
	testCertMgmtPushExt(t, miloPushClient)
}

// TestGDSPull_MiloClient_GoServer: the Milo adapter's `client gds-pull`
// against gdsserver.
func TestGDSPull_MiloClient_GoServer(t *testing.T) {
	requireV015(t, miloPushClient, "clientOperations", "gds-pull")
	testGDSPullGoServer(t, gdsPullClient{
		name: "milo", env: miloEnv, defaultImage: defaultMiloImage, pki: miloClientPKI,
		direction: dirMiloClientToGoServer,
	})
}
