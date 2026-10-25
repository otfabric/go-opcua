//go:build interop

// SPDX-License-Identifier: MIT

// The UA-.NETStandard (dotnet) adapter's `client push` (CLIENT_CONTRACT §1
// "push flags", §15) and `client gds-pull` (§16.2) of opcua-interop v0.15.0
// (unreleased when these tests were written; built from the opcua-interop
// branch feat/dotnet-push). The push client is plain Calls on the
// ServerConfiguration NodeIds over the adapter's one session (the
// ServerPushConfigurationClient of Opc.Ua.Gds.Client 2.0.1 opens a session
// of its own and has no Part 12 1.05 methods); the pull client is the
// stack's GlobalDiscoveryServerClient, as in the dotnet-gds adapter:
//
//	dotnet-client-to-go-server   `client push` (all the v0.15.0 flags)
//	                             against server.WithPushManagement;
//	                             `client gds-pull` against gdsserver
//
// The tests are the shared ones of the node-opcua push client
// (testCertMgmtPushExt) and the dotnet-gds pull client
// (testGDSPullGoServer). They are gated on the capabilities the adapter
// advertises (clientOperations push / gds-pull, clientFeatures push-groups,
// push-certificates, push-transaction-diagnostics); until the pinned image
// has them they skip, also under OPCUA_INTEROP_REQUIRE_CAPABILITIES=1. Run
// them against a local build with
//
//	DOTNET_IMAGE=opcua-interop-dotnet:dotnet-push go test -tags=interop -run 'Dotnet.*_GoServer' ./interop/
//
// The gds.pull.* dotnet-client-to-go-server rows stay with the dotnet-gds
// adapter's TestDotnetGDSPull_DotnetClient_GoServer; TestGDSPull_DotnetClient_GoServer
// runs the same cases with the dotnet adapter's `client gds-pull`.
//
// COVERAGE: testdata/ledger-dotnet.json certmgmt.push.trust-list,
// certmgmt.push.certificate-update, certmgmt.push.get-certificates,
// certmgmt.push.create-self-signed, certmgmt.push.delete-certificate,
// certmgmt.push.reset-to-defaults, certmgmt.push.https-group,
// certmgmt.push.usertoken-group, certmgmt.push.pfx,
// certmgmt.push.transaction-diagnostics

package interop

import "testing"

// TestCertMgmtPushExt_DotnetClient_GoServer: the dotnet adapter's `client
// push` against server.WithPushManagement, with the trust list and
// certificate update rows.
func TestCertMgmtPushExt_DotnetClient_GoServer(t *testing.T) {
	testCertMgmtPushExt(t, pushExtClient{
		name: "dotnet", env: dotnetEnv, defaultImage: defaultDotnetImage, pki: "dotnet-client",
		direction: dirDotnetClientToGoServer, require: requireDotnetImage, coreRows: true,
	})
}

// TestGDSPull_DotnetClient_GoServer: the dotnet adapter's `client
// gds-pull` against gdsserver.
func TestGDSPull_DotnetClient_GoServer(t *testing.T) {
	c := pushExtClient{name: "dotnet", env: dotnetEnv, require: requireDotnetImage}
	requireV015(t, c, "clientOperations", "gds-pull")
	testGDSPullGoServer(t, gdsPullClient{
		name: "dotnet", env: dotnetEnv, defaultImage: defaultDotnetImage, pki: "dotnet-client",
		direction: dirDotnetClientToGoServer,
	})
}
