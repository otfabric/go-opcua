//go:build interop

// SPDX-License-Identifier: MIT

// Harness for the opcua-asyncio (Python, PyPI "asyncua",
// https://github.com/FreeOpcUa/opcua-asyncio) adapter of opcua-interop, new
// in opcua-interop v0.9.0 (asyncua 2.1.0).
//
//	ASYNCUA_IMAGE   Docker image of the asyncua adapter (default: defaultAsyncuaImage)
//
// The asyncua peer runs with every interop run against the image pinned by
// digest below (opcua-interop interopVersion); set ASYNCUA_IMAGE to test another
// build. The usual capability gating applies.
//
//	ASYNCUA_IMAGE=ghcr.io/otfabric/opcua-interop-asyncua:dev \
//	    go test -tags=interop -run Asyncua ./interop/
//
// Ledger: testdata/ledger-asyncua.json, validated without Docker by
// TestAsyncuaLedgerValid. Directions:
//
//	go-client-to-asyncua-server   go-opcua client → asyncua adapter server
//	asyncua-client-to-go-server   asyncua adapter client → go-opcua server
//	asyncua-server-to-go-lds      asyncua server registers with a go-opcua LDS
//	asyncua-client-to-go-lds      asyncua client registers a server with a go-opcua LDS
//
// The secure tests use the asyncua-server / asyncua-client identities of the
// test PKI (opcua-interop v0.10.0 certs/generate.sh, or --add-asyncua on an
// older PKI): a PKI without them skips. Stack deviations skip with
// asyncuaDeviation and are unsupported rows of the ledger.

package interop

import (
	"testing"
)

// defaultAsyncuaImage is the asyncua adapter of the opcua-interop release
// named by interopVersion (multi-arch index digest; see harness_test.go).
const defaultAsyncuaImage = "ghcr.io/otfabric/opcua-interop-asyncua@sha256:758ec9ff91ae81c904a568df9e7891dc90f38e0461264cf330219f7ab34e13e9"

// asyncuaEnv is the image env variable of the asyncua peer, see harness_test.go.
const asyncuaEnv = "ASYNCUA_IMAGE"

const (
	dirGoClientToAsyncuaServer = "go-client-to-asyncua-server"
	dirAsyncuaClientToGoServer = "asyncua-client-to-go-server"
)

// The asyncua identities of the test PKI.
const (
	asyncuaServerPKI = "asyncua-server"
	asyncuaClientPKI = "asyncua-client"
)

// requireAsyncuaImage skips (or fails with OPCUA_INTEROP_REQUIRE_CAPABILITIES=1
// when ASYNCUA_IMAGE is set) when the asyncua adapter image cannot report its
// capabilities, and fails when the default image is not the release this
// suite is written against.
func requireAsyncuaImage(t *testing.T) *adapterCaps {
	t.Helper()
	caps, image := imageCapabilities(t, asyncuaEnv, defaultAsyncuaImage)
	requirePinnedVersion(t, asyncuaEnv, caps, image)
	return caps
}

// startAsyncuaServer starts the asyncua adapter container in server mode.
func startAsyncuaServer(t *testing.T) *serverHandle {
	t.Helper()
	requireAsyncuaImage(t)
	return startAdapterServer(t, asyncuaEnv, defaultAsyncuaImage)
}

// startAsyncuaSecureServer starts the asyncua adapter with its certificate
// (test PKI identity asyncua-server) and the fixture's RSA security profiles.
func startAsyncuaSecureServer(t *testing.T) *serverHandle {
	t.Helper()
	requireAsyncuaImage(t)
	return startSecureAdapterServer(t, asyncuaEnv, defaultAsyncuaImage, asyncuaServerPKI)
}

// runAsyncuaClient runs the asyncua adapter in client mode (fails on a non-zero exit).
func runAsyncuaClient(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireAsyncuaImage(t)
	return runAdapterClient(t, asyncuaEnv, defaultAsyncuaImage, endpoint, subcmd, args...)
}

// runAsyncuaClientResult runs the asyncua adapter in client mode and returns
// the parsed result even when the container exits non-zero.
func runAsyncuaClientResult(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireAsyncuaImage(t)
	return runAdapterClientResult(t, asyncuaEnv, defaultAsyncuaImage, endpoint, subcmd, args...)
}

// asyncuaDeviation skips a test whose capability asyncua 2.1.0 implements in
// a way that does not conform to OPC UA (opcua-interop asyncua/README.md,
// testdata/ledger-asyncua.json). It is a skip, not a pass: the ledger records
// these rows as unsupported, never verified.
func asyncuaDeviation(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("asyncua 2.1.0 deviation: "+format, args...)
}
