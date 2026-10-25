//go:build interop

// SPDX-License-Identifier: MIT

// Harness for the third reference stack: the opcua-interop "dotnet" adapter,
// built on the OPC Foundation UA-.NETStandard stack (NuGet
// OPCFoundation.NetStandard.Opc.Ua.* 2.0.1, .NET 10).
//
//	DOTNET_IMAGE   Docker image of the dotnet adapter (default: defaultDotnetImage)
//
// The dotnet peer runs with every interop run against the image pinned by
// digest below (opcua-interop interopVersion); set DOTNET_IMAGE to test another
// build. The usual capability gating applies.
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
// test PKI (opcua-interop v0.17.0 certs/generate.sh, or --add-dotnet on an
// older PKI): a PKI without them skips.

package interop

import (
	"testing"
)

// defaultDotnetImage is the dotnet adapter of the opcua-interop release
// named by interopVersion (multi-arch index digest; see harness_test.go).
const defaultDotnetImage = "ghcr.io/otfabric/opcua-interop-dotnet@sha256:aae1a636b3321c96678f4da972ba0e003ba3666f9d01293c42e0f912883c4728"

// dotnetEnv is the image env variable of the dotnet peer, see harness_test.go.
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
