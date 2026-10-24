//go:build interop

// SPDX-License-Identifier: MIT

// Harness for the third reference stack: the opcua-interop "dotnet" adapter,
// built on the OPC Foundation UA-.NETStandard stack (NuGet
// OPCFoundation.NetStandard.Opc.Ua.* 2.0.1, .NET 10).
//
//	DOTNET_IMAGE   Docker image of the dotnet adapter (default: defaultDotnetImage)
//
// The dotnet adapter is new in opcua-interop v0.9.0, and the dotnet peer is
// opt-in: with DOTNET_IMAGE unset its tests run only when defaultDotnetImage
// is already present locally (it is never pulled) and skip otherwise, also
// with OPCUA_INTEROP_REQUIRE_CAPABILITIES=1, so the open62541 / Milo suite
// pinned to interopVersion is unaffected. With DOTNET_IMAGE set the usual
// capability gating applies (missing operations or features fail under
// OPCUA_INTEROP_REQUIRE_CAPABILITIES=1).
//
//	DOTNET_IMAGE=ghcr.io/otfabric/opcua-interop-dotnet:dev \
//	    go test -tags=interop -run Dotnet ./interop/
//
// Ledger: testdata/ledger-dotnet.json, validated without Docker by
// TestDotnetLedgerValid. Directions:
//
//	go-client-to-dotnet-server   go-opcua client → dotnet adapter server
//	dotnet-client-to-go-server   dotnet adapter client → go-opcua server
//	dotnet-server-to-go-lds      dotnet server registers with a go-opcua LDS
//	dotnet-client-to-go-lds      dotnet client registers a server with a go-opcua LDS
//
// The secure tests use the dotnet-server / dotnet-client identities of the
// test PKI (opcua-interop v0.9.0 certs/generate.sh, or --add-dotnet on an
// older PKI): a PKI without them skips.

package interop

import (
	"testing"
)

// defaultDotnetImage is the v0.9.0 tag until the release is published; then
// pin its multi-arch digest here (and in INTEROP.md), as for the other peers.
const defaultDotnetImage = "ghcr.io/otfabric/opcua-interop-dotnet:v0.9.0"

// dotnetInteropVersion is the opcua-interop release the dotnet tests and
// testdata/ledger-dotnet.json are written against.
const dotnetInteropVersion = "v0.9.0"

// dotnetEnv is the image env variable of the dotnet peer, an opt-in peer
// (optional_peers_test.go).
const dotnetEnv = "DOTNET_IMAGE"

const (
	dirGoClientToDotnetServer = "go-client-to-dotnet-server"
	dirDotnetClientToGoServer = "dotnet-client-to-go-server"
)

// requireDotnetImage skips (or fails with OPCUA_INTEROP_REQUIRE_CAPABILITIES=1)
// when the dotnet adapter image cannot report its capabilities.
func requireDotnetImage(t *testing.T) *adapterCaps {
	t.Helper()
	caps, _ := imageCapabilities(t, dotnetEnv, defaultDotnetImage)
	return caps
}

// startDotnetServer starts the dotnet adapter container in server mode.
func startDotnetServer(t *testing.T) *serverHandle {
	t.Helper()
	requireDotnetImage(t)
	return startAdapterServer(t, dotnetEnv, defaultDotnetImage)
}

// startDotnetSecureServer starts the dotnet adapter with its certificate
// (test PKI identity dotnet-server) and the fixture's RSA security profiles.
func startDotnetSecureServer(t *testing.T) *serverHandle {
	t.Helper()
	requireDotnetImage(t)
	return startSecureAdapterServer(t, dotnetEnv, defaultDotnetImage, "dotnet-server")
}

// runDotnetClient runs the dotnet adapter in client mode (fails on a non-zero exit).
func runDotnetClient(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireDotnetImage(t)
	return runAdapterClient(t, dotnetEnv, defaultDotnetImage, endpoint, subcmd, args...)
}

// runDotnetClientResult runs the dotnet adapter in client mode and returns
// the parsed result even when the container exits non-zero.
func runDotnetClientResult(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireDotnetImage(t)
	return runAdapterClientResult(t, dotnetEnv, defaultDotnetImage, endpoint, subcmd, args...)
}
