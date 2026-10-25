//go:build interop

// SPDX-License-Identifier: MIT

// Harness for the node-opcua (TypeScript / Node.js,
// https://github.com/node-opcua/node-opcua) adapter of opcua-interop, new in
// opcua-interop v0.15.0 (node-opcua 2.187.12).
//
//	NODE_OPCUA_IMAGE   Docker image of the node-opcua adapter (default: defaultNodeOpcuaImage)
//
// The node-opcua peer runs with every interop run against the image pinned by
// digest below (opcua-interop interopVersion); set NODE_OPCUA_IMAGE to test another
// build. The usual capability gating applies.
//
//	NODE_OPCUA_IMAGE=ghcr.io/otfabric/opcua-interop-node-opcua:dev \
//	    go test -tags=interop -run NodeOpcua ./interop/
//
// Ledger: testdata/ledger-node-opcua.json, validated without Docker by
// TestNodeOpcuaLedgerValid. Directions:
//
//	go-client-to-node-opcua-server   go-opcua client → node-opcua adapter server
//	node-opcua-client-to-go-server   node-opcua adapter client → go-opcua server
//	node-opcua-server-to-go-lds      node-opcua server registers with a go-opcua LDS
//	node-opcua-client-to-go-lds      node-opcua client registers a server with a go-opcua LDS
//
// node-opcua validates peer certificates against the trusted CA of the
// adapter's PKI (<pki>/trusted/certs), so the node-opcua-server /
// node-opcua-client identities of the opcua-interop v0.15.0 test PKI
// (certs/generate.sh, or certs/generate.sh --add-node-opcua for an existing
// PKI) are all the secure tests need.
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

// defaultNodeOpcuaImage is the node-opcua adapter of the opcua-interop release
// named by interopVersion (multi-arch index digest; see harness_test.go).
// dirNodeOpcuaClientToGoServer is the ledger direction of the node-opcua
// client against the go server, for subtests a shared test builds.
const dirNodeOpcuaClientToGoServer = "node-opcua-client-to-go-server"

const defaultNodeOpcuaImage = "ghcr.io/otfabric/opcua-interop-node-opcua@sha256:a6ab1cc6482bfdabe44597490b4617c4736a800d3c52bea77765d4fd26c18281"

// requireNodeOpcuaImage skips (or fails with
// OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 when NODE_OPCUA_IMAGE is set) when
// the node-opcua adapter image cannot report its capabilities.
func requireNodeOpcuaImage(t *testing.T) *adapterCaps {
	t.Helper()
	caps, image := imageCapabilities(t, nodeOpcuaEnv, defaultNodeOpcuaImage)
	requirePinnedVersion(t, nodeOpcuaEnv, caps, image)
	return caps
}

// startNodeOpcuaServer starts the node-opcua adapter container in server mode.
func startNodeOpcuaServer(t *testing.T) *serverHandle {
	t.Helper()
	requireNodeOpcuaImage(t)
	return startAdapterServer(t, "NODE_OPCUA_IMAGE", defaultNodeOpcuaImage)
}

// startNodeOpcuaSecureServer starts the node-opcua adapter with its
// certificate and the secure endpoints of the fixture.
func startNodeOpcuaSecureServer(t *testing.T) *serverHandle {
	t.Helper()
	requireNodeOpcuaImage(t)
	return startSecureAdapterServer(t, "NODE_OPCUA_IMAGE", defaultNodeOpcuaImage, "node-opcua-server")
}

// runNodeOpcuaClient runs the node-opcua adapter in client mode.
func runNodeOpcuaClient(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireNodeOpcuaImage(t)
	return runAdapterClient(t, "NODE_OPCUA_IMAGE", defaultNodeOpcuaImage, endpoint, subcmd, args...)
}

// runNodeOpcuaClientResult runs the node-opcua adapter in client mode and
// returns the parsed result even when the container exits non-zero.
func runNodeOpcuaClientResult(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireNodeOpcuaImage(t)
	return runAdapterClientResult(t, "NODE_OPCUA_IMAGE", defaultNodeOpcuaImage, endpoint, subcmd, args...)
}

// startNodeOpcuaSecureReverseServer starts the node-opcua adapter with its
// certificate, the secure endpoints and a reverse connect target; no port is
// published, the server is only reachable through the connections it opens.
func startNodeOpcuaSecureReverseServer(t *testing.T, clientPort int) {
	t.Helper()
	requireNodeOpcuaImage(t)
	pki := pkiDir(t)
	certFile := filepath.Join(pki, "node-opcua-server", "cert.crt")
	keyFile := filepath.Join(pki, "node-opcua-server", "cert.key")
	adapterPKI := filepath.Join(pki, "node-opcua-server", "pki")
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
	image := getEnvOr("NODE_OPCUA_IMAGE", defaultNodeOpcuaImage)
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
