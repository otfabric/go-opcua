//go:build interop

// SPDX-License-Identifier: MIT

// Package interop contains interoperability tests for go-opcua.
//
// Tests start opcua-interop adapter containers, wait for the server ready
// file, exercise the go-opcua API, and assert results. They own the full
// container lifecycle: start, wait, run, teardown.
//
// Run with:
//
//	go test -tags=interop -v ./interop/...
//
// Environment variables (all optional):
//
//	OPEN62541_IMAGE            Docker image for the open62541 adapter (default: digest-pinned v0.5.0)
//	MILO_IMAGE                 Docker image for the Milo adapter      (default: digest-pinned v0.5.0)
//	OPCUA_INTEROP_FIXTURE_DIR  Directory containing baseline.json     (default: testdata)
//	OPCUA_INTEROP_PKI_DIR      Root of the test PKI tree              (default: ../../opcua-interop/certs/test-pki)
package interop

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// Single source of truth for the pinned opcua-interop release.
	// Keep INTEROP.md, coverage.json evidence versions, and CI workflow env in sync.
	// Digests are GHCR multi-arch indexes from the current v0.5.0 publication:
	// https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0
	// https://github.com/otfabric/opcua-interop/actions/runs/30127189340
	// When opcua-interop republishes v0.5.0, update these digests in lockstep
	// (harness defaults, interop.yml, INTEROP.md). Do not introduce v0.5.1/RC pins.
	interopVersion = "v0.5.0"

	defaultOpen62541Image = "ghcr.io/otfabric/opcua-interop-open62541@sha256:d9650e1b63fd0df1c840335d1951c848437530de0670c279ef905440a3bc77d6"
	defaultMiloImage      = "ghcr.io/otfabric/opcua-interop-milo@sha256:af502530b7043763220474d6dcf0deef62215e0b3c112cc8eab9849ec1d4e321"
	defaultFixtureDir     = "testdata"

	interopNamespaceURI = "urn:otfabric:opcua-interop:model"
	endpointPath        = "/opcua-interop"

	serverReadyTimeout = 60 * time.Second
	clientTimeout      = 30 * time.Second
	dialTimeout        = 10 * time.Second
)

// Ensure the constant is referenced so unused-const tooling stays quiet until
// pin updates consume it in docs/validation helpers.
var _ = interopVersion

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

func getEnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

// ---------------------------------------------------------------------------
// Docker helpers
// ---------------------------------------------------------------------------

func dockerContainerName(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("interop-%d-%s", os.Getpid(), t.Name())
	return strings.NewReplacer("/", "_", " ", "_", "(", "", ")", "").Replace(name)
}

func dockerStop(name string) {
	exec.Command("docker", "stop", "-t", "2", name).Run() //nolint:errcheck
}

// ---------------------------------------------------------------------------
// Adapter server handle (Go-client direction)
// ---------------------------------------------------------------------------

// serverHandle holds the OPC UA endpoint URL and cleanup for a running adapter.
type serverHandle struct {
	endpoint string
	stopFn   func()
}

// startAdapterServer starts an opcua-interop adapter container in server mode
// with the baseline fixture. imageEnvVar is the env variable name for the image
// override; defaultImage is the fallback. It polls for the ready file and
// registers cleanup with t.
func startAdapterServer(t *testing.T, imageEnvVar, defaultImage string) *serverHandle {
	t.Helper()

	port := freePort(t)
	image := getEnvOr(imageEnvVar, defaultImage)
	containerName := dockerContainerName(t)
	fixtureDir := getEnvOr("OPCUA_INTEROP_FIXTURE_DIR", defaultFixtureDir)

	// Resolve to absolute path for the volume mount.
	if !strings.HasPrefix(fixtureDir, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		fixtureDir = cwd + "/" + fixtureDir
	}

	cmdCtx, cmdCancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(cmdCtx, "docker", "run", "--rm",
		"--name", containerName,
		"-p", fmt.Sprintf("%d:4840", port),
		"-v", fixtureDir+":/fixtures:ro",
		image,
		"server",
		"--fixture", "/fixtures/baseline.json",
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cmdCancel()
		t.Fatalf("start adapter server (%s): %v", image, err)
	}

	stop := func() {
		dockerStop(containerName)
		cmdCancel()
		_ = cmd.Wait()
	}

	// Poll for the ready file written by the adapter inside the container.
	startCtx, startCancel := context.WithTimeout(context.Background(), serverReadyTimeout)
	defer startCancel()

	for {
		if exec.CommandContext(startCtx, "docker", "exec",
			containerName, "test", "-f", "/run/opcua-interop/ready").Run() == nil {
			break
		}
		select {
		case <-startCtx.Done():
			stop()
			t.Fatalf("timed out waiting for adapter server (container: %s)", containerName)
		default:
			time.Sleep(500 * time.Millisecond)
		}
	}

	h := &serverHandle{
		endpoint: fmt.Sprintf("opc.tcp://localhost:%d%s", port, endpointPath),
		stopFn:   stop,
	}
	t.Cleanup(stop)
	return h
}

// startOpen62541Server starts the open62541 adapter container in server mode.
func startOpen62541Server(t *testing.T) *serverHandle {
	t.Helper()
	return startAdapterServer(t, "OPEN62541_IMAGE", defaultOpen62541Image)
}

// startMiloServer starts the Milo (Java) adapter container in server mode.
func startMiloServer(t *testing.T) *serverHandle {
	t.Helper()
	return startAdapterServer(t, "MILO_IMAGE", defaultMiloImage)
}

// ---------------------------------------------------------------------------
// Adapter client JSON result types (opcua-interop contract, schema v1.0)
// ---------------------------------------------------------------------------

// adapterResult is the canonical output envelope emitted by every adapter client command.
type adapterResult struct {
	SchemaVersion string          `json:"schemaVersion"`
	Adapter       string          `json:"adapter"`
	Operation     string          `json:"operation"`
	Success       bool            `json:"success"`
	ServiceResult statusCodeObj   `json:"serviceResult"`
	Results       json.RawMessage `json:"results"`
	Error         json.RawMessage `json:"error"` // null | {"category","message"}
}

// statusCodeObj is the structured status code embedded in adapter results.
type statusCodeObj struct {
	Name     string `json:"name"`
	Code     uint32 `json:"code"`
	Severity string `json:"severity"`
}

func (s statusCodeObj) String() string {
	return fmt.Sprintf("%s (0x%08X)", s.Name, s.Code)
}

// parseBrowseNames unmarshals a browse results JSON array and returns the set
// of browse-name strings it contains. Each element is expected to have a
// "browseName" object with a "name" field.
func parseBrowseNames(t *testing.T, raw json.RawMessage) map[string]bool {
	t.Helper()
	var items []struct {
		BrowseName struct {
			NS   uint16 `json:"ns"`
			Name string `json:"name"`
		} `json:"browseName"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("parseBrowseNames: unmarshal: %v (raw=%s)", err, raw)
	}
	names := make(map[string]bool, len(items))
	for _, it := range items {
		names[it.BrowseName.Name] = true
	}
	return names
}

// writeResultItem is one per-item entry from an adapter write results array.
type writeResultItem struct {
	NodeID     string        `json:"nodeId"`
	StatusCode statusCodeObj `json:"statusCode"`
}

// parseWriteResults unmarshals the write results array from an adapterResult.
func parseWriteResults(t *testing.T, raw json.RawMessage) []writeResultItem {
	t.Helper()
	var items []writeResultItem
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("parseWriteResults: %v; raw: %s", err, raw)
	}
	return items
}

// statusCodeIs reports whether the adapter status matches the expected OPC UA code.
func statusCodeIs(sr statusCodeObj, want ua.StatusCode) bool {
	return sr.Code == uint32(want)
}

// statusCodeNameHas reports whether the symbolic name contains substr (adapters
// may or may not prefix with "Status").
func statusCodeNameHas(sr statusCodeObj, substr string) bool {
	return strings.Contains(sr.Name, substr)
}

// browseRef is one reference from an adapter browse results array.
type browseRef struct {
	BrowseName struct {
		Name string `json:"name"`
	} `json:"browseName"`
	NodeClass string `json:"nodeClass"`
}

// parseBrowseRefs unmarshals browse results including NodeClass.
func parseBrowseRefs(t *testing.T, raw json.RawMessage) []browseRef {
	t.Helper()
	var items []browseRef
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("parseBrowseRefs: %v; raw: %s", err, raw)
	}
	return items
}

// setKeys returns the sorted keys of a string→bool map for error messages.
func setKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// parseAdapterOutput finds the last line in raw that starts with '{' and parses
// it as an adapterResult. Adapter clients may emit ANSI-coloured log lines to
// stdout before the JSON result; this function skips those lines.
func parseAdapterOutput(raw []byte) (adapterResult, error) {
	var jsonLine []byte
	for _, line := range bytes.Split(raw, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			jsonLine = trimmed
		}
	}
	if jsonLine == nil {
		return adapterResult{}, fmt.Errorf("no JSON object found in output")
	}
	var result adapterResult
	if err := json.Unmarshal(jsonLine, &result); err != nil {
		return adapterResult{}, err
	}
	return result, nil
}

// runAdapterClient runs an opcua-interop adapter container in client mode
// against the provided endpoint. The adapter writes a single JSON object to
// stdout which is parsed and returned.
func runAdapterClient(t *testing.T, imageEnvVar, defaultImage, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()

	image := getEnvOr(imageEnvVar, defaultImage)

	// Replace localhost with host.docker.internal so the container can
	// reach a host-side port (Go server or mapped container port).
	dockerEndpoint := strings.ReplaceAll(endpoint, "localhost", "host.docker.internal")

	cmdArgs := []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		image,
		"client", subcmd, "--endpoint", dockerEndpoint,
	}
	cmdArgs = append(cmdArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Stderr = os.Stderr

	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("adapter client %q (%s): %v\noutput: %s", subcmd, image, err, raw)
	}

	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse adapter client output: %v\nraw: %s", err, raw)
	}
	return result
}

// runAdapterClientResult runs an adapter client and always returns the parsed
// result, even if the container exits with a non-zero code.  Use this for
// negative tests (e.g. credential rejection) where the adapter exits non-zero
// but still writes a JSON result to stdout.  The test fails only if no parseable
// JSON result is found in the output.
func runAdapterClientResult(t *testing.T, imageEnvVar, defaultImage, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()

	image := getEnvOr(imageEnvVar, defaultImage)
	dockerEndpoint := strings.ReplaceAll(endpoint, "localhost", "host.docker.internal")

	cmdArgs := []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		image,
		"client", subcmd, "--endpoint", dockerEndpoint,
	}
	cmdArgs = append(cmdArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Stderr = os.Stderr

	// Output() returns bytes even on non-zero exit; capture them regardless.
	raw, _ := cmd.Output()

	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse adapter client output (no JSON found): %v\nraw: %s", err, raw)
	}
	return result
}

// runOpen62541Client runs the open62541 adapter in client mode.
func runOpen62541Client(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	return runAdapterClient(t, "OPEN62541_IMAGE", defaultOpen62541Image, endpoint, subcmd, args...)
}

// runOpen62541ClientResult runs the open62541 adapter in client mode and
// returns the parsed result even when the container exits non-zero (e.g. when
// the per-item status is Uncertain or Bad but the JSON result is still useful).
func runOpen62541ClientResult(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	return runAdapterClientResult(t, "OPEN62541_IMAGE", defaultOpen62541Image, endpoint, subcmd, args...)
}

// runMiloClient runs the Milo (Java) adapter in client mode.
func runMiloClient(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	return runAdapterClient(t, "MILO_IMAGE", defaultMiloImage, endpoint, subcmd, args...)
}

// runMiloClientResult runs the Milo adapter in client mode and returns the
// parsed result even when the container exits non-zero.
func runMiloClientResult(t *testing.T, endpoint, subcmd string, args ...string) adapterResult {
	t.Helper()
	return runAdapterClientResult(t, "MILO_IMAGE", defaultMiloImage, endpoint, subcmd, args...)
}

// ---------------------------------------------------------------------------
// Go server (adapter-client direction)
// ---------------------------------------------------------------------------

// startGoServer starts a go-opcua server populated with the interop namespace
// and the full baseline fixture node set, matching opcua-interop/fixtures/baseline/fixture.json.
// Returns the endpoint URL with actual port.
func startGoServer(t *testing.T) string {
	t.Helper()

	port := freePort(t)

	s, err := server.New(
		// Listen on all interfaces so Docker containers can reach the server.
		// Advertise only host.docker.internal (not 0.0.0.0) so adapter
		// clients that do GetEndpoints + reconnect pick a routable URL.
		server.ListenOn(fmt.Sprintf("0.0.0.0:%d", port)),
		server.EndPoint("host.docker.internal", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	objs := ns.Objects()

	addVar := func(name string, val interface{}) {
		n := ns.AddNewVariableStringNode(name, val)
		objs.AddRef(n, server.RefTypeIDHasComponent, true)
	}

	// Scalars — values match baseline fixture initialValue fields.
	addVar("Scalar.Boolean", true)
	addVar("Scalar.SByte", int8(-100))
	addVar("Scalar.Byte", uint8(200))
	addVar("Scalar.Int16", int16(-12345))
	addVar("Scalar.UInt16", uint16(54321))
	addVar("Scalar.Int32", int32(-123456789))
	addVar("Scalar.UInt32", uint32(3234567890))
	addVar("Scalar.Int64", int64(-1234567890123456789))
	addVar("Scalar.UInt64", uint64(12345678901234567890))
	addVar("Scalar.Float", float32(12.5))
	addVar("Scalar.Double", float64(-12345.6789))
	addVar("Scalar.String", "OPC UA \u2013 \u517c\u5bb9\u6027 \u2013 \u0394")
	addVar("Scalar.DateTime", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	addVar("Scalar.Guid", ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"))
	addVar("Scalar.ByteString", []byte("opcua-compat"))
	addVar("Scalar.XmlElement", ua.XMLElement("<compat>test</compat>"))
	addVar("Scalar.NodeId", ua.NewNumericNodeID(0, 85))
	addVar("Scalar.QualifiedName", &ua.QualifiedName{NamespaceIndex: 0, Name: "Objects"})
	addVar("Scalar.LocalizedText", ua.NewLocalizedTextWithLocale("OPC UA Compatibility", "en"))
	addVar("Scalar.StatusCode", ua.StatusOK)

	// Arrays — values match baseline fixture initialValue fields.
	addVar("Array.Empty", []int32{})
	addVar("Array.OneElement", []int32{42})
	addVar("Array.Int32", []int32{0, 1, -1, 2147483647, -2147483648, -123456789})
	addVar("Array.String", []string{"alpha", "beta", "OPC UA \u2013 \u517c\u5bb9\u6027", ""})
	addVar("Array.ByteString", [][]byte{{1, 2, 3}, {4, 5, 6}})
	// 3×2 Double matrix stored as nested slice (row-major); go-opcua encodes
	// the VariantArrayDimensions field automatically from the slice shape.
	addVar("Array.Boolean", []bool{true, false, true})
	addVar("Array.Double", []float64{0.0, 1.5, -1.5, 3.141592653589793})
	addVar("Array.Matrix2D", [][]float64{{1.1, 2.2}, {3.3, 4.4}, {5.5, 6.6}})

	// Access control.
	addVar("Access.ReadWrite", int32(42))
	// Access.ReadOnly — read-only string node (CurrentRead, no CurrentWrite).
	roID := ua.NewStringNodeID(ns.ID(), "Access.ReadOnly")
	roNode := server.NewNode(
		roID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("Access.ReadOnly")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Read-Only Variable", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
		},
		nil,
		func() *ua.DataValue { return server.DataValueFromValue("immutable") },
	)
	ns.AddNode(roNode)
	objs.AddRef(roNode, server.RefTypeIDHasComponent, true)
	// Access.WriteOnly — write-only Int32 node (CurrentWrite, no CurrentRead).
	var writeOnlyValue atomic.Int32
	woID := ua.NewStringNodeID(ns.ID(), "Access.WriteOnly")
	woNode := server.NewNode(
		woID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("Access.WriteOnly")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Write-Only Variable", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentWrite)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentWrite)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
		},
		nil,
		func() *ua.DataValue { return server.DataValueFromValue(writeOnlyValue.Load()) },
	)
	ns.AddNode(woNode)
	objs.AddRef(woNode, server.RefTypeIDHasComponent, true)

	// DataValues — nodes with explicit timestamps for DataValue metadata tests.
	dvID := ua.NewStringNodeID(ns.ID(), "DataValues.GoodWithTimestamps")
	dvNode := server.NewNode(
		dvID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("DataValues.GoodWithTimestamps")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Good With Both Timestamps", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
		},
		nil,
		func() *ua.DataValue {
			now := time.Now()
			return &ua.DataValue{
				EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
				Value:           ua.MustVariant(float64(3.14159)),
				SourceTimestamp: now,
				ServerTimestamp: now,
			}
		},
	)
	ns.AddNode(dvNode)
	objs.AddRef(dvNode, server.RefTypeIDHasComponent, true)

	// DataValues.Uncertain — Int32 node with Uncertain status (UncertainInitialValue = 0x40920000).
	uncertainID := ua.NewStringNodeID(ns.ID(), "DataValues.Uncertain")
	uncertainNode := server.NewNode(
		uncertainID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("DataValues.Uncertain")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Uncertain Status", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
		},
		nil,
		func() *ua.DataValue {
			return &ua.DataValue{
				EncodingMask: ua.DataValueValue | ua.DataValueStatusCode,
				Value:        ua.MustVariant(int32(0)),
				Status:       ua.StatusCode(0x40920000), // UncertainInitialValue
			}
		},
	)
	ns.AddNode(uncertainNode)
	objs.AddRef(uncertainNode, server.RefTypeIDHasComponent, true)

	nsIdx := ns.ID()

	// Dynamic.Toggle — bool alternating every 500 ms.
	var toggleAtomic atomic.Bool
	toggleID := ua.NewStringNodeID(nsIdx, "Dynamic.Toggle")
	toggleNode := server.NewNode(
		toggleID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("Dynamic.Toggle")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Boolean Toggle", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
		},
		nil,
		func() *ua.DataValue {
			return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(toggleAtomic.Load())}
		},
	)
	ns.AddNode(toggleNode)
	objs.AddRef(toggleNode, server.RefTypeIDHasComponent, true)

	// Dynamic.Ramp — float64 increasing from 0 to 100 in steps of 1 every 100 ms, then resetting.
	var rampAtomic atomic.Value
	rampAtomic.Store(float64(0.0))
	rampID := ua.NewStringNodeID(nsIdx, "Dynamic.Ramp")
	rampNode := server.NewNode(
		rampID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("Dynamic.Ramp")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Ramp", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
		},
		nil,
		func() *ua.DataValue {
			return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(rampAtomic.Load().(float64))}
		},
	)
	ns.AddNode(rampNode)
	objs.AddRef(rampNode, server.RefTypeIDHasComponent, true)

	// Dynamic.Counter — Int64 counter incrementing by 1 every 250 ms.
	var ctrAtomic atomic.Int64
	counterID := ua.NewStringNodeID(nsIdx, "Dynamic.Counter")
	counterNode := server.NewNode(
		counterID,
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:       server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:      server.DataValueFromValue(attrs.BrowseName("Dynamic.Counter")),
			ua.AttributeIDDisplayName:     server.DataValueFromValue(attrs.DisplayName("Counter", "en")),
			ua.AttributeIDAccessLevel:     server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDUserAccessLevel: server.DataValueFromValue(uint8(ua.AccessLevelTypeCurrentRead)),
			ua.AttributeIDValueRank:       server.DataValueFromValue(int32(-1)),
		},
		nil,
		func() *ua.DataValue {
			return &ua.DataValue{
				EncodingMask: ua.DataValueValue,
				Value:        ua.MustVariant(ctrAtomic.Load()),
			}
		},
	)
	ns.AddNode(counterNode)
	objs.AddRef(counterNode, server.RefTypeIDHasComponent, true)

	// Methods folder.
	methodsFolderID := ua.NewStringNodeID(nsIdx, "Methods")
	methodsFolder := server.NewFolderNode(methodsFolderID, "Methods")
	ns.AddNode(methodsFolder)
	objs.AddRef(methodsFolder, server.RefTypeIDHasComponent, true)

	// Methods.Add — Int32(a) + Int32(b) → Int32(result).
	addMethodNode := func(name string,
		inputs, outputs []*ua.Argument,
		handler server.MethodHandler,
	) {
		mid := ua.NewStringNodeID(nsIdx, name)
		mn := server.NewFolderNode(mid, name)
		mn.SetNodeClass(ua.NodeClassMethod)
		ns.AddNode(mn)
		methodsFolder.AddRef(mn, id.HasComponent, true)
		addMethodArgsProperty(ns, mn, nsIdx, name, "InputArguments", inputs...)
		addMethodArgsProperty(ns, mn, nsIdx, name, "OutputArguments", outputs...)
		s.RegisterMethod(methodsFolderID, mid, handler)
	}

	int32Arg := func(name, desc string) *ua.Argument {
		return &ua.Argument{
			Name: name, DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1,
			Description: ua.NewLocalizedText(desc),
		}
	}
	stringArg := func(name, desc string) *ua.Argument {
		return &ua.Argument{
			Name: name, DataType: ua.NewNumericNodeID(0, id.String), ValueRank: -1,
			Description: ua.NewLocalizedText(desc),
		}
	}

	addMethodNode("Methods.Add",
		[]*ua.Argument{int32Arg("a", "First operand."), int32Arg("b", "Second operand.")},
		[]*ua.Argument{int32Arg("result", "Sum of a and b.")},
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 2 {
				return nil, ua.StatusBadArgumentsMissing
			}
			a, okA := args[0].Value().(int32)
			b, okB := args[1].Value().(int32)
			if !okA || !okB {
				return nil, ua.StatusBadInvalidArgument
			}
			return []*ua.Variant{ua.MustVariant(a + b)}, ua.StatusOK
		},
	)

	addMethodNode("Methods.Echo",
		[]*ua.Argument{stringArg("input", "String to echo.")},
		[]*ua.Argument{stringArg("output", "Echoed string.")},
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 1 {
				return nil, ua.StatusBadArgumentsMissing
			}
			s, ok := args[0].Value().(string)
			if !ok {
				return nil, ua.StatusBadInvalidArgument
			}
			return []*ua.Variant{ua.MustVariant(s)}, ua.StatusOK
		},
	)

	doubleArg := func(name, desc string) *ua.Argument {
		return &ua.Argument{
			Name: name, DataType: ua.NewNumericNodeID(0, id.Double), ValueRank: -1,
			Description: ua.NewLocalizedText(desc),
		}
	}
	boolArg := func(name, desc string) *ua.Argument {
		return &ua.Argument{
			Name: name, DataType: ua.NewNumericNodeID(0, id.Boolean), ValueRank: -1,
			Description: ua.NewLocalizedText(desc),
		}
	}

	addMethodNode("Methods.Multiply",
		[]*ua.Argument{doubleArg("a", "First factor."), doubleArg("b", "Second factor.")},
		[]*ua.Argument{doubleArg("result", "Product of a and b.")},
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 2 {
				return nil, ua.StatusBadArgumentsMissing
			}
			a, okA := args[0].Value().(float64)
			b, okB := args[1].Value().(float64)
			if !okA || !okB {
				return nil, ua.StatusBadInvalidArgument
			}
			return []*ua.Variant{ua.MustVariant(a * b)}, ua.StatusOK
		},
	)

	addMethodNode("Methods.NoArguments",
		[]*ua.Argument{},
		[]*ua.Argument{boolArg("success", "Always true.")},
		func(_ context.Context, _, _ *ua.NodeID, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			return []*ua.Variant{ua.MustVariant(true)}, ua.StatusOK
		},
	)

	addMethodNode("Methods.MultipleOutputs",
		[]*ua.Argument{int32Arg("input", "Input value.")},
		[]*ua.Argument{int32Arg("doubled", "input * 2"), stringArg("label", "String representation of input.")},
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 1 {
				return nil, ua.StatusBadArgumentsMissing
			}
			v, ok := args[0].Value().(int32)
			if !ok {
				return nil, ua.StatusBadInvalidArgument
			}
			return []*ua.Variant{
				ua.MustVariant(v * 2),
				ua.MustVariant(strconv.FormatInt(int64(v), 10)),
			}, ua.StatusOK
		},
	)

	addMethodNode("Methods.Fail",
		[]*ua.Argument{},
		[]*ua.Argument{},
		func(_ context.Context, _, _ *ua.NodeID, _ []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			return nil, ua.StatusBadInternalError
		},
	)

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// Start counter goroutine after server is running.
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		ctx := t.Context()
		for {
			select {
			case <-ticker.C:
				ctrAtomic.Add(1)
				s.ChangeNotification(counterID)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Toggle goroutine — flips the bool every 500 ms.
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		ctx := t.Context()
		for {
			select {
			case <-ticker.C:
				toggleAtomic.Store(!toggleAtomic.Load())
				s.ChangeNotification(toggleID)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Ramp goroutine — increments by 1.0 every 100 ms, resets at 100.0.
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		ctx := t.Context()
		for {
			select {
			case <-ticker.C:
				cur := rampAtomic.Load().(float64)
				next := cur + 1.0
				if next > 100.0 {
					next = 0.0
				}
				rampAtomic.Store(next)
				s.ChangeNotification(rampID)
			case <-ctx.Done():
				return
			}
		}
	}()

	return fmt.Sprintf("opc.tcp://localhost:%d", port)
}

// ---------------------------------------------------------------------------
// Go server helper: method argument properties
// ---------------------------------------------------------------------------

// addMethodArgsProperty attaches an InputArguments or OutputArguments property
// variable to a method node, using the same encoding as the OPC UA spec.
func addMethodArgsProperty(ns *server.NodeNameSpace, methodNode *server.Node, nsIdx uint16, methodName, propName string, args ...*ua.Argument) {
	if len(args) == 0 {
		return
	}
	eos := make([]*ua.ExtensionObject, len(args))
	for i, a := range args {
		eos[i] = ua.NewExtensionObject(a)
	}
	value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(eos)}
	node := server.NewNode(
		ua.NewStringNodeID(nsIdx, methodName+"."+propName),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(propName)),
			ua.AttributeIDDataType:   server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
		},
		nil,
		func() *ua.DataValue { return value },
	)
	ns.AddNode(node)
	methodNode.AddRef(node, id.HasProperty, true)
}

// ---------------------------------------------------------------------------
// Go client dial helper
// ---------------------------------------------------------------------------

func dialClient(t *testing.T, endpoint string) *opcua.Client {
	t.Helper()

	c, err := opcua.NewClient(endpoint,
		opcua.SecurityModeString("None"),
		opcua.AuthAnonymous(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect(%q): %v", endpoint, err)
	}

	t.Cleanup(func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		c.Close(ctx2)
	})

	return c
}

// dialUsernameClient connects to endpoint over a None/None channel and
// authenticates with username and password. It returns (client, nil) on
// success, or (nil, error) when the server rejects the connection or
// credentials — callers use the error to assert rejection in negative tests.
//
// GetEndpoints is called first so the correct UserName token policyId is
// picked up from the server's advertised token policies. Without this step
// the UserNameIdentityToken.PolicyID would be empty and Milo returns
// BadIdentityTokenInvalid before even reaching the credential check.
func dialUsernameClient(t *testing.T, endpoint, user, pass string) (*opcua.Client, error) {
	t.Helper()

	discoverCtx, discoverCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer discoverCancel()

	eps, err := opcua.GetEndpoints(discoverCtx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("GetEndpoints: %w", err)
	}

	// Find the None/None endpoint — username over None is intentionally
	// unencrypted (test-only). It must exist because the fixture has users.
	var chosen *ua.EndpointDescription
	for _, ep := range eps {
		if ep.SecurityPolicyURI == ua.SecurityPolicyURINone &&
			ep.SecurityMode == ua.MessageSecurityModeNone {
			// Also require that this endpoint offers a UserName token policy.
			for _, tok := range ep.UserIdentityTokens {
				if tok.TokenType == ua.UserTokenTypeUserName {
					chosen = ep
					break
				}
			}
			if chosen != nil {
				break
			}
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("server does not advertise a UserName token policy on None/None endpoint")
	}
	chosen.EndpointURL = endpoint

	c, err := opcua.NewClient(endpoint,
		opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeUserName),
		opcua.AuthUsername(user, pass),
	)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		c.Close(ctx2) //nolint:errcheck
	})
	return c, nil
}

// ---------------------------------------------------------------------------
// Security test PKI helpers
// ---------------------------------------------------------------------------

// pkiDir returns the absolute path to the test PKI root, either from the
// OPCUA_INTEROP_PKI_DIR env variable or from the conventional sibling-repo path
// (../../opcua-interop/certs/test-pki relative to this package). If neither
// exists the test is skipped.
func pkiDir(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("OPCUA_INTEROP_PKI_DIR"); v != "" {
		return v
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	candidate := filepath.Join(cwd, "..", "..", "opcua-interop", "certs", "test-pki")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	t.Skip("OPCUA_INTEROP_PKI_DIR not set and default path not found; skipping security test")
	return ""
}

// loadCACert reads and parses the CA certificate from the test PKI.
func loadCACert(t *testing.T, caPath string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA cert %s: %v", caPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("decode PEM from %s: no block found", caPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert
}

// startSecureAdapterServer starts an opcua-interop adapter container in server
// mode with the baseline fixture, certificate, private key, and PKI trust dir
// mounted from the test PKI tree. adapterPKIName is the subdirectory name
// under pkiDir (e.g. "open62541-server", "milo-server").
//
// The PKI directory is copied to a per-test temporary directory before
// mounting so the container can write rejected-certificate entries without
// mutating the checked-in source tree.
func startSecureAdapterServer(t *testing.T, imageEnvVar, defaultImage, adapterPKIName string) *serverHandle {
	t.Helper()

	pki := pkiDir(t)
	certFile := filepath.Join(pki, adapterPKIName, "cert.crt")
	keyFile := filepath.Join(pki, adapterPKIName, "cert.key")
	adapterPKI := filepath.Join(pki, adapterPKIName, "pki")

	for _, f := range []string{certFile, keyFile, adapterPKI} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("test PKI file missing (%s): %v — run certs/generate.sh first", f, err)
		}
	}

	// Copy the PKI tree to a writable temp directory. Milo's
	// FileBasedCertificateQuarantine and open62541's trust-list manager may
	// write rejected-certificate entries; a read-only mount would silently
	// break those paths and produce misleading test results.
	runtimePKI := filepath.Join(t.TempDir(), "pki")
	if err := copyDir(adapterPKI, runtimePKI); err != nil {
		t.Fatalf("copy PKI to temp dir: %v", err)
	}

	port := freePort(t)
	image := getEnvOr(imageEnvVar, defaultImage)
	containerName := dockerContainerName(t)
	fixtureDir := getEnvOr("OPCUA_INTEROP_FIXTURE_DIR", defaultFixtureDir)
	if !strings.HasPrefix(fixtureDir, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		fixtureDir = cwd + "/" + fixtureDir
	}

	cmdCtx, cmdCancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(cmdCtx, "docker", "run", "--rm",
		"--name", containerName,
		"-p", fmt.Sprintf("%d:4840", port),
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
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cmdCancel()
		t.Fatalf("start secure adapter server (%s): %v", image, err)
	}

	stop := func() {
		dockerStop(containerName)
		cmdCancel()
		_ = cmd.Wait()
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), serverReadyTimeout)
	defer startCancel()

	for {
		if exec.CommandContext(startCtx, "docker", "exec",
			containerName, "test", "-f", "/run/opcua-interop/ready").Run() == nil {
			break
		}
		select {
		case <-startCtx.Done():
			stop()
			t.Fatalf("timed out waiting for secure adapter server (container: %s)", containerName)
		default:
			time.Sleep(500 * time.Millisecond)
		}
	}

	h := &serverHandle{
		endpoint: fmt.Sprintf("opc.tcp://localhost:%d%s", port, endpointPath),
		stopFn:   stop,
	}
	t.Cleanup(stop)
	return h
}

// startOpen62541SecureServer starts the open62541 adapter with OPC UA SecureChannel enabled.
func startOpen62541SecureServer(t *testing.T) *serverHandle {
	t.Helper()
	return startSecureAdapterServer(t, "OPEN62541_IMAGE", defaultOpen62541Image, "open62541-server")
}

// startMiloSecureServer starts the Milo adapter with OPC UA SecureChannel enabled.
func startMiloSecureServer(t *testing.T) *serverHandle {
	t.Helper()
	return startSecureAdapterServer(t, "MILO_IMAGE", defaultMiloImage, "milo-server")
}

// ---------------------------------------------------------------------------
// Error-reason helpers for negative security tests
// ---------------------------------------------------------------------------

// isCertRejectionError returns true if err is an OPC UA status code that
// indicates the server rejected the client certificate. Acceptable codes are
// BadCertificateUntrusted and BadSecurityChecksFailed; the exact code depends
// on which part of the handshake failed and how each stack propagates it.
//
// Any other error (network error, timeout, wrong endpoint, key mismatch) is
// not accepted as proof of certificate rejection and the caller should fail.
func isCertRejectionError(err error) bool {
	if err == nil {
		return false
	}
	for _, target := range []error{
		ua.StatusBadCertificateUntrusted,
		ua.StatusBadSecurityChecksFailed,
		ua.StatusBadCertificateInvalid,
		ua.StatusBadCertificateURIInvalid,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// isIdentityRejectedError returns true if err is an OPC UA status code that
// indicates the server refused the presented user identity token. Acceptable
// codes are BadUserAccessDenied, BadIdentityTokenRejected, and
// BadIdentityTokenInvalid.
func isIdentityRejectedError(err error) bool {
	if err == nil {
		return false
	}
	for _, target := range []error{
		ua.StatusBadUserAccessDenied,
		ua.StatusBadIdentityTokenRejected,
		ua.StatusBadIdentityTokenInvalid,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// isIdentityRejectedServiceResult returns true if the adapter-result service
// result name indicates identity/credential rejection.  This is the adapter
// equivalent of isIdentityRejectedError for tests that use runAdapterClient.
func isIdentityRejectedServiceResult(name string) bool {
	for _, suffix := range []string{
		"UserAccessDenied",
		"IdentityTokenRejected",
		"IdentityTokenInvalid",
	} {
		if strings.Contains(name, suffix) {
			return true
		}
	}
	return false
}

// copyDir recursively copies src into dst, creating dst if it does not exist.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

// dialSecureClient connects go-opcua to endpoint using the given security policy
// and mode. It uses the consumer certificate from the test PKI as client identity
// and the shared CA as server trust anchor. The matching endpoint is selected via
// GetEndpoints so the server certificate is taken from the server's advertisement.
func dialSecureClient(t *testing.T, endpoint, policy, mode string) *opcua.Client {
	t.Helper()

	pki := pkiDir(t)
	consumerCert := filepath.Join(pki, "consumer", "cert.crt")
	consumerKey := filepath.Join(pki, "consumer", "cert.key")
	caPath := filepath.Join(pki, "ca", "ca.crt")

	ca := loadCACert(t, caPath)

	// Discover endpoints with a plain None/None call to get the server certificate
	// and endpoint list without needing security material on this first call.
	discoverCtx, discoverCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer discoverCancel()

	eps, err := opcua.GetEndpoints(discoverCtx, endpoint)
	if err != nil {
		t.Fatalf("GetEndpoints(%q): %v", endpoint, err)
	}

	wantPolicy := ua.FormatSecurityPolicyURI(policy)
	wantMode := ua.MessageSecurityModeFromString(mode)

	var chosen *ua.EndpointDescription
	for _, ep := range eps {
		if ep.SecurityPolicyURI == wantPolicy && ep.SecurityMode == wantMode {
			chosen = ep
			break
		}
	}
	if chosen == nil {
		t.Fatalf("server did not advertise %s/%s endpoint (got %d endpoints)", policy, mode, len(eps))
	}

	// Rewrite endpoint URL to our mapped port while keeping the server certificate
	// and security parameters from the advertised endpoint.
	chosen.EndpointURL = endpoint

	c, err := opcua.NewClient(endpoint,
		opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeAnonymous),
		opcua.CertificateFile(consumerCert),
		opcua.PrivateKeyFile(consumerKey),
		opcua.TrustedCertificates(ca),
		opcua.AuthAnonymous(),
	)
	if err != nil {
		t.Fatalf("NewClient (secure): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect secure (%q %s/%s): %v", endpoint, policy, mode, err)
	}

	t.Cleanup(func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		c.Close(ctx2)
	})

	return c
}

// ---------------------------------------------------------------------------
// Secure Go server (adapter-client → go server direction)
// ---------------------------------------------------------------------------

// loadGoServerCert reads and PEM-decodes the go-server certificate from the
// test PKI, returning the raw DER bytes.
func loadGoServerCert(t *testing.T) []byte {
	t.Helper()
	pki := pkiDir(t)
	certPath := filepath.Join(pki, "go-server", "cert.crt")
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Skipf("go-server cert missing (%s): run certs/generate.sh first", certPath)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("go-server cert %s: not PEM", certPath)
	}
	return block.Bytes
}

// loadGoServerKey reads and parses the go-server RSA private key from the
// test PKI. Accepts both PKCS#8 and PKCS#1 PEM formats.
func loadGoServerKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	pki := pkiDir(t)
	keyPath := filepath.Join(pki, "go-server", "cert.key")
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Skipf("go-server key missing (%s): run certs/generate.sh first", keyPath)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("go-server key %s: not PEM", keyPath)
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk
		}
		t.Fatalf("go-server key: PKCS#8 parsed but not RSA")
	}
	rk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("go-server key %s: parse failed: %v", keyPath, err)
	}
	return rk
}

// goServerUsers holds the test credentials that startSecureGoServer exposes,
// matching the baseline fixture's users array so adapter-client tests can
// authenticate with the same fixture credentials.
var goServerUsers = map[string]string{
	"test-user": "test-password",
}

// startSecureGoServer starts a go-opcua server with the go-server certificate
// and Basic256Sha256 Sign and SignAndEncrypt endpoints enabled alongside the
// default None/None endpoint.  It also enables UserName authentication using
// the same credentials declared in the baseline fixture.  Returns the endpoint
// URL (localhost:port/…).
func startSecureGoServer(t *testing.T) string {
	t.Helper()

	certDER := loadGoServerCert(t)
	privateKey := loadGoServerKey(t)

	port := freePort(t)

	s, err := server.New(
		// Listen on all interfaces so both the host-side Go client and
		// Docker adapter containers can reach the server.  Advertise only
		// host.docker.internal so adapter clients (which do GetEndpoints +
		// reconnect) pick a routable URL, not the 0.0.0.0 wildcard.
		server.ListenOn(fmt.Sprintf("0.0.0.0:%d", port)),
		server.EndPoint("host.docker.internal", port),
		server.Certificate(certDER),
		server.PrivateKey(privateKey),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableSecurity("Aes128_Sha256_RsaOaep", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableSecurity("Aes256_Sha256_RsaPss", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(username, password string) error {
			if pw, ok := goServerUsers[username]; ok && pw == password {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
	)
	if err != nil {
		t.Fatalf("startSecureGoServer: server.New: %v", err)
	}

	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	objs := ns.Objects()
	addVar := func(name string, val interface{}) {
		n := ns.AddNewVariableStringNode(name, val)
		objs.AddRef(n, server.RefTypeIDHasComponent, true)
	}
	addVar("Scalar.Int32", int32(42))
	addVar("Scalar.String", "hello")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		s.Close()
	})

	go func() {
		if err := s.Start(ctx); err != nil && ctx.Err() == nil {
			t.Logf("startSecureGoServer: server exited: %v", err)
		}
	}()

	addr := fmt.Sprintf("localhost:%d", port)
	deadline := time.Now().Add(serverReadyTimeout)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("tcp", addr); err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Sprintf("opc.tcp://localhost:%d%s", port, endpointPath)
}

// runSecureAdapterClient runs an adapter container in client mode over a
// Basic256Sha256 secure channel. It mounts the adapter client certificate,
// private key, and the shared CA certificate from the test PKI tree.
// clientPKIName is the subdirectory under pkiDir (e.g. "open62541-client").
func runSecureAdapterClient(t *testing.T, imageEnvVar, defaultImage, clientPKIName, endpoint, subcmd, policy, mode string, extraArgs ...string) adapterResult {
	t.Helper()

	pki := pkiDir(t)
	certFile := filepath.Join(pki, clientPKIName, "cert.crt")
	keyFile := filepath.Join(pki, clientPKIName, "cert.key")
	caCert := filepath.Join(pki, "ca", "ca.crt")

	for _, f := range []string{certFile, keyFile, caCert} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("adapter client PKI file missing (%s): run certs/generate.sh first", f)
		}
	}

	image := getEnvOr(imageEnvVar, defaultImage)
	dockerEndpoint := strings.ReplaceAll(endpoint, "localhost", "host.docker.internal")

	cmdArgs := []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", certFile + ":/certs/cert.crt:ro",
		"-v", keyFile + ":/certs/cert.key:ro",
		"-v", caCert + ":/certs/ca.crt:ro",
		image,
		"client", subcmd,
		"--endpoint", dockerEndpoint,
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--trust-list", "/certs/ca.crt",
		"--security-policy", policy,
		"--security-mode", mode,
	}
	cmdArgs = append(cmdArgs, extraArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Stderr = os.Stderr

	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("secure adapter client %q (%s): %v\noutput: %s", subcmd, image, err, raw)
	}

	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse secure adapter client output: %v\nraw: %s", err, raw)
	}
	return result
}

// runSecureAdapterClientResult is like runSecureAdapterClient but does not
// fatal when the adapter exits non-zero. It parses the JSON output regardless
// of exit status and returns the result. Use for negative tests expecting
// connection or service failure.
func runSecureAdapterClientResult(t *testing.T, imageEnvVar, defaultImage, clientPKIName, endpoint, subcmd, policy, mode string, extraArgs ...string) adapterResult {
	t.Helper()

	pki := pkiDir(t)
	certFile := filepath.Join(pki, clientPKIName, "cert.crt")
	keyFile := filepath.Join(pki, clientPKIName, "cert.key")
	caCert := filepath.Join(pki, "ca", "ca.crt")

	for _, f := range []string{certFile, keyFile, caCert} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("adapter client PKI file missing (%s): run certs/generate.sh first", f)
		}
	}

	image := getEnvOr(imageEnvVar, defaultImage)
	dockerEndpoint := strings.ReplaceAll(endpoint, "localhost", "host.docker.internal")

	cmdArgs := []string{"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", certFile + ":/certs/cert.crt:ro",
		"-v", keyFile + ":/certs/cert.key:ro",
		"-v", caCert + ":/certs/ca.crt:ro",
		image,
		"client", subcmd,
		"--endpoint", dockerEndpoint,
		"--certificate", "/certs/cert.crt",
		"--private-key", "/certs/cert.key",
		"--trust-list", "/certs/ca.crt",
		"--security-policy", policy,
		"--security-mode", mode,
	}
	cmdArgs = append(cmdArgs, extraArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Stderr = os.Stderr

	// Do not fatal on non-zero exit — the adapter may exit non-zero when the
	// server rejects the connection.  Attempt to parse whatever JSON was produced.
	raw, _ := cmd.Output()
	if len(raw) == 0 {
		t.Logf("runSecureAdapterClientResult: no output from adapter")
		return adapterResult{}
	}
	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Logf("runSecureAdapterClientResult: parse failed: %v\nraw: %s", err, raw)
		return adapterResult{}
	}
	return result
}

// loadCACertDER reads the CA certificate from the test PKI and returns DER bytes.
func loadCACertDER(t *testing.T) []byte {
	t.Helper()
	pki := pkiDir(t)
	caPath := filepath.Join(pki, "ca", "ca.crt")
	raw, err := os.ReadFile(caPath)
	if err != nil {
		t.Skipf("CA cert missing (%s): run certs/generate.sh first", caPath)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("CA cert %s: not PEM", caPath)
	}
	return block.Bytes
}

// startTrustGoServer starts a secure go-opcua server configured with
// WithClientCertificateTrustList using the test PKI CA certificate, so only
// adapter clients whose certificates are signed by that CA are accepted.
// Returns the endpoint URL.
func startTrustGoServer(t *testing.T) string {
	t.Helper()

	certDER := loadGoServerCert(t)
	privateKey := loadGoServerKey(t)
	caDER := loadCACertDER(t)

	port := freePort(t)
	s, err := server.New(
		server.ListenOn(fmt.Sprintf("0.0.0.0:%d", port)),
		server.EndPoint("host.docker.internal", port),
		server.Certificate(certDER),
		server.PrivateKey(privateKey),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.WithClientCertificateTrustList(caDER),
	)
	if err != nil {
		t.Fatalf("startTrustGoServer: server.New: %v", err)
	}

	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	objs := ns.Objects()
	addVar := func(name string, val interface{}) {
		n := ns.AddNewVariableStringNode(name, val)
		objs.AddRef(n, server.RefTypeIDHasComponent, true)
	}
	addVar("Scalar.Int32", int32(42))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		s.Close()
	})

	go func() {
		if err := s.Start(ctx); err != nil && ctx.Err() == nil {
			t.Logf("startTrustGoServer: server exited: %v", err)
		}
	}()

	addr := fmt.Sprintf("localhost:%d", port)
	deadline := time.Now().Add(serverReadyTimeout)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("tcp", addr); err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Sprintf("opc.tcp://localhost:%d%s", port, endpointPath)
}

// isCertRejectedServiceResult returns true if the adapter-result service
// result name indicates certificate-based rejection. Untrusted-cert tests
// reject at OpenSecureChannel, so adapters may also surface channel-closed statuses.
func isCertRejectedServiceResult(sr statusCodeObj) bool {
	for _, suffix := range []string{
		"CertificateUntrusted",
		"CertificateInvalid",
		"SecurityChecksFailed",
		"BadSecurity",
		"SecureChannelClosed",
		"SecureChannelIdInvalid",
		"ConnectionClosed",
		"TcpInternalError",
		"Certificate",
	} {
		if strings.Contains(sr.Name, suffix) {
			return true
		}
	}
	return false
}

// isUntrustedClientRejected reports whether an adapter client failed in a way
// consistent with OpenSecureChannel certificate rejection. Some stacks surface
// a certificate StatusCode; others fail at transport with Success=false and a
// non-certificate serviceResult (or empty JSON after the channel drops).
func isUntrustedClientRejected(r adapterResult) bool {
	if r.Success {
		return false
	}
	if isCertRejectedServiceResult(r.ServiceResult) {
		return true
	}
	// Channel dropped before a useful serviceResult was recorded.
	if len(r.Error) > 0 && string(r.Error) != "null" {
		return true
	}
	// Empty/zero result from a non-zero docker exit (parse may yield Good defaults).
	return r.ServiceResult.Code == 0 && r.Operation != ""
}
