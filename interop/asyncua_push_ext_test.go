//go:build interop

// SPDX-License-Identifier: MIT

// The asyncua adapter's `client push` (CLIENT_CONTRACT §1 "push flags", §15)
// and `client gds-pull` (§16.2) of opcua-interop v0.15.0 (unreleased when
// these tests were written; built from the opcua-interop branch
// feat/asyncua-push). opcua-asyncio 2.1.0 has neither a push nor a GDS
// client, so the adapter builds both on plain Calls:
//
//	asyncua-client-to-go-server   `client push` (all the v0.15.0 flags)
//	                              against server.WithPushManagement;
//	                              `client gds-pull` against gdsserver
//
// The tests are the shared ones of the node-opcua push client
// (testCertMgmtPushExt) and the dotnet-gds pull client
// (testGDSPullGoServer). They are gated on the capabilities the adapter
// advertises (clientOperations push / gds-pull, clientFeatures push-groups,
// push-certificates, push-transaction-diagnostics); until the pinned image
// has them they skip, also under OPCUA_INTEROP_REQUIRE_CAPABILITIES=1. Run
// them against a local build with
//
//	ASYNCUA_IMAGE=opcua-interop-asyncua:push-ext go test -tags=interop -run 'Asyncua.*_GoServer' ./interop/
//
// COVERAGE: testdata/ledger-asyncua.json certmgmt.push.trust-list,
// certmgmt.push.certificate-update, certmgmt.push.create-self-signed,
// certmgmt.push.delete-certificate, certmgmt.push.https-group,
// certmgmt.push.usertoken-group, certmgmt.push.pfx,
// certmgmt.push.transaction-diagnostics, gds.pull.directory,
// gds.pull.certificate-request, gds.pull.trust-list, gds.pull.revocation

package interop

import "testing"

// TestCertMgmtPushExt_AsyncuaClient_GoServer: the asyncua adapter's
// `client push` against server.WithPushManagement, with the trust list and
// certificate update rows (node-opcua has those in
// TestCertMgmtPush_NodeOpcuaClient_GoServer).
func TestCertMgmtPushExt_AsyncuaClient_GoServer(t *testing.T) {
	testCertMgmtPushExt(t, pushExtClient{
		name: "asyncua", env: asyncuaEnv, defaultImage: defaultAsyncuaImage, pki: asyncuaClientPKI,
		direction: dirAsyncuaClientToGoServer, require: requireAsyncuaImage, coreRows: true,
	})
}

// TestGDSPull_AsyncuaClient_GoServer: the asyncua adapter's `client
// gds-pull` against gdsserver.
func TestGDSPull_AsyncuaClient_GoServer(t *testing.T) {
	c := pushExtClient{name: "asyncua", env: asyncuaEnv, require: requireAsyncuaImage}
	requireV015(t, c, "clientOperations", "gds-pull")
	testGDSPullGoServer(t, gdsPullClient{
		name: "asyncua", env: asyncuaEnv, defaultImage: defaultAsyncuaImage, pki: asyncuaClientPKI,
		direction: dirAsyncuaClientToGoServer,
	})
}
