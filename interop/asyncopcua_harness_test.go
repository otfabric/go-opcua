//go:build interop

// SPDX-License-Identifier: MIT

// Harness for the async-opcua (Rust, https://github.com/FreeOpcUa/async-opcua)
// adapter of opcua-interop, new in opcua-interop v0.9.0 (async-opcua 0.19.0).
//
//	ASYNC_OPCUA_IMAGE   Docker image of the async-opcua adapter (default: defaultAsyncOpcuaImage)
//
// The async-opcua peer runs with every interop run against the image pinned by
// digest below (opcua-interop interopVersion); set ASYNC_OPCUA_IMAGE to test another
// build. The usual capability gating applies.
//
//	ASYNC_OPCUA_IMAGE=ghcr.io/otfabric/opcua-interop-async-opcua:dev \
//	    go test -tags=interop -run AsyncOpcua ./interop/
//
// Ledger: testdata/ledger-async-opcua.json, validated without Docker by
// TestAsyncOpcuaLedgerValid. Directions:
//
//	go-client-to-async-opcua-server   go-opcua client → async-opcua adapter server
//	async-opcua-client-to-go-server   async-opcua adapter client → go-opcua server
//	async-opcua-server-to-go-lds      async-opcua server registers with a go-opcua LDS
//	async-opcua-client-to-go-lds      async-opcua client registers a server with a go-opcua LDS
//
// async-opcua 0.19 trusts peer certificates by exact certificate only (no CA
// chain validation in its CertificateStore), so the adapter server trusts the
// certificates listed in <pki>/trusted/certs — the test PKI of opcua-interop
// v0.15.0 lists the consumer certificate there for the async-opcua-server
// identity. The adapter client validates the server certificate against
// --trust-list itself (exact match or CA-signed). The secure tests need the
// async-opcua-server / async-opcua-client identities of that PKI.
package interop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// defaultAsyncOpcuaImage is the async-opcua adapter of the opcua-interop release
// named by interopVersion (multi-arch index digest; see harness_test.go).
const defaultAsyncOpcuaImage = "ghcr.io/otfabric/opcua-interop-async-opcua@sha256:6e16bdba99e51ce2e3057ad8e9c74578222c2cfdd796664064df83468b103793"

// requireAsyncOpcuaImage skips (or fails with
// OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 when ASYNC_OPCUA_IMAGE is set) when
// the async-opcua adapter image cannot report its capabilities.
func requireAsyncOpcuaImage(t *testing.T) *adapterCaps {
	t.Helper()
	caps, image := imageCapabilities(t, asyncOpcuaEnv, defaultAsyncOpcuaImage)
	requirePinnedVersion(t, asyncOpcuaEnv, caps, image)
	return caps
}

// startAsyncOpcuaServer starts the async-opcua adapter container in server mode.
func startAsyncOpcuaServer(t *testing.T) *serverHandle {
	t.Helper()
	requireAsyncOpcuaImage(t)
	return startAdapterServer(t, "ASYNC_OPCUA_IMAGE", defaultAsyncOpcuaImage)
}

// startAsyncOpcuaSecureServer starts the async-opcua adapter with its
// certificate and the secure endpoints of the fixture.
func startAsyncOpcuaSecureServer(t *testing.T) *serverHandle {
	t.Helper()
	requireAsyncOpcuaImage(t)
	return startSecureAdapterServer(t, "ASYNC_OPCUA_IMAGE", defaultAsyncOpcuaImage, "async-opcua-server")
}

// runAsyncOpcuaClient runs the async-opcua adapter in client mode.
func runAsyncOpcuaClient(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireAsyncOpcuaImage(t)
	return runAdapterClient(t, "ASYNC_OPCUA_IMAGE", defaultAsyncOpcuaImage, endpoint, subcmd, args...)
}

// runAsyncOpcuaClientResult runs the async-opcua adapter in client mode and
// returns the parsed result even when the container exits non-zero.
func runAsyncOpcuaClientResult(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireAsyncOpcuaImage(t)
	return runAdapterClientResult(t, "ASYNC_OPCUA_IMAGE", defaultAsyncOpcuaImage, endpoint, subcmd, args...)
}

// startAsyncOpcuaSecureReverseServer starts the async-opcua adapter with its
// certificate, the secure endpoints and a reverse connect target; no port is
// published, the server is only reachable through the connections it opens.
func startAsyncOpcuaSecureReverseServer(t *testing.T, clientPort int) {
	t.Helper()
	requireAsyncOpcuaImage(t)
	pki := pkiDir(t)
	certFile := filepath.Join(pki, "async-opcua-server", "cert.crt")
	keyFile := filepath.Join(pki, "async-opcua-server", "cert.key")
	adapterPKI := filepath.Join(pki, "async-opcua-server", "pki")
	for _, f := range []string{certFile, keyFile, adapterPKI} {
		if _, err := os.Stat(f); err != nil {
			capabilityUnavailable(t, "test PKI file missing (%s): %v — run certs/generate.sh first", f, err)
		}
	}
	runtimePKI := filepath.Join(containerScratchDir(t), "pki")
	if err := copyDir(adapterPKI, runtimePKI); err != nil {
		t.Fatalf("copy PKI to temp dir: %v", err)
	}
	if err := shareWithContainers(runtimePKI); err != nil {
		t.Fatalf("share PKI with the container: %v", err)
	}
	fixtureDir := getEnvOr("OPCUA_INTEROP_FIXTURE_DIR", defaultFixtureDir)
	if !strings.HasPrefix(fixtureDir, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		fixtureDir = cwd + "/" + fixtureDir
	}
	image := getEnvOr("ASYNC_OPCUA_IMAGE", defaultAsyncOpcuaImage)
	containerName := dockerContainerName(t)
	cmdCtx, cmdCancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(cmdCtx, "docker", "run", "--rm",
		"--name", containerName,
		"--add-host=host.docker.internal:host-gateway",
		"-v", fixtureDir+":/fixtures:ro",
		"-v", certFile+":/certs/cert.crt:ro",
		"-v", keyFile+":/certs/cert.key:ro",
		"-v", runtimePKI+":/certs/pki",
		image,
		"server",
		"--fixture", "/fixtures/baseline.json",
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--pki-dir", "/certs/pki",
		"--reverse-connect", fmt.Sprintf("opc.tcp://host.docker.internal:%d", clientPort),
		"--reverse-connect-interval-ms", "300",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cmdCancel()
		t.Fatalf("start adapter reverse server (%s): %v", image, err)
	}
	t.Cleanup(func() {
		dockerReleaseMount(containerName, "/certs/pki")
		dockerStop(containerName)
		cmdCancel()
		_ = cmd.Wait()
	})
	startCtx, startCancel := context.WithTimeout(context.Background(), serverReadyTimeout)
	defer startCancel()
	for exec.CommandContext(startCtx, "docker", "exec",
		containerName, "test", "-f", "/run/opcua-interop/ready").Run() != nil {
		select {
		case <-startCtx.Done():
			t.Fatalf("timed out waiting for adapter server (container: %s)", containerName)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
