//go:build interop

// SPDX-License-Identifier: MIT

// Shared helpers of the PubSub (Part 14) peer tests: the open62541 adapter
// as a PubSub publisher / subscriber / SKS (server --pubsub-config,
// opcua-interop docs/CLIENT_CONTRACT.md §14), the Mosquitto broker, the
// fixture variables of the PubSub folder and static keys. Not ledger
// evidence by itself.
//
// Networking (contract §14.4), the same on Docker Desktop and on Linux:
//
//   - container → host: the adapter publishes to host.docker.internal:<port>
//     (every container is started with --add-host
//     host.docker.internal:host-gateway, which Linux needs and Docker Desktop
//     ignores); the Go side listens on all interfaces.
//   - host → container: the adapter's subscriber connection binds
//     opc.udp://0.0.0.0:<port> and the port is published with
//     -p <port>:<port>/udp; the Go side sends to 127.0.0.1:<port>.
//   - MQTT: the broker container publishes 1883 on a free host port; the Go
//     side connects to 127.0.0.1:<port>, the adapter to
//     host.docker.internal:<port>.
//
// Multicast does not cross the Docker Desktop VM and is not used.

package interop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	_ "github.com/otfabric/go-opcua/pubsub/transport/mqtt" // mqtt:// scheme
	_ "github.com/otfabric/go-opcua/pubsub/transport/udp"  // opc.udp:// scheme
	"github.com/otfabric/go-opcua/ua"
)

const (
	// mosquittoImage is the broker of the opcua-interop MQTT tests
	// (README "MQTT broker"): Eclipse Mosquitto 2.0.22, multi-arch index.
	mosquittoImage = "eclipse-mosquitto:2.0.22@sha256:09b62ff32c2e7b64d4b431b9a89236073289b68db273de2b089edeb9b0d92b5c"

	// mosquittoConf is opcua-interop mqtt/mosquitto.conf: one plain
	// listener, anonymous clients, no persistence.
	mosquittoConf = "listener 1883 0.0.0.0\nallow_anonymous true\npersistence false\nlog_dest stdout\nlog_type error\nlog_type warning\nlog_type notice\nlog_type information\n"

	psProfileUDP      = "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"
	psProfileMQTTUADP = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-uadp"
	psProfileMQTTJSON = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json"

	// psNetworkMessageMask is the UADP NetworkMessageContentMask of the
	// adapter examples: PublisherId | GroupHeader | WriterGroupId |
	// SequenceNumber | PayloadHeader | Timestamp.
	psNetworkMessageMask = 231
	// psDataSetMessageMask: Timestamp | Status | MajorVersion |
	// MinorVersion | SequenceNumber.
	psDataSetMessageMask = 61

	psReceiveTimeout = 20 * time.Second
)

// requirePubSubServer gates on the pubsub server feature of the open62541
// adapter (opcua-interop v0.8.0).
func requirePubSubServer(t *testing.T) {
	t.Helper()
	requireServerFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "pubsub")
}

// ---------------------------------------------------------------------------
// Static keys
// ---------------------------------------------------------------------------

// psStaticKey256 is the PubSub-Aes256-CTR key of the adapter examples:
// signing key 0x01…0x20, encrypting key 0x65…0x84, key nonce A1 A2 A3 A4.
// psStaticKey128 is a PubSub-Aes128-CTR key: signing key 0x01…0x20,
// encrypting key 0x41…0x50, key nonce B1 B2 B3 B4.
var psStaticKey256, psStaticKey128 = func() ([]byte, []byte) {
	var k256, k128 []byte
	for i := byte(1); i <= 0x20; i++ {
		k256 = append(k256, i)
		k128 = append(k128, i)
	}
	for i := byte(0x65); i <= 0x84; i++ {
		k256 = append(k256, i)
	}
	for i := byte(0x41); i <= 0x50; i++ {
		k128 = append(k128, i)
	}
	return append(k256, 0xA1, 0xA2, 0xA3, 0xA4), append(k128, 0xB1, 0xB2, 0xB3, 0xB4)
}()

// staticKeyRing holds one static key without rotation.
func staticKeyRing(t *testing.T, p security.Policy, tokenID uint32, key []byte) *security.KeyRing {
	t.Helper()
	r := security.NewKeyRing("InteropGroup", p)
	if err := r.SetKeys(p.URI(), tokenID, [][]byte{key}, 0, 0); err != nil {
		t.Fatalf("SetKeys: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// The PubSub fixture variables (contract §14.7)
// ---------------------------------------------------------------------------

type psVar struct {
	name string // PubSub.<name>
	typ  uint32
	rank int32
}

// psVars are the writable PubSub.* variables of the baseline fixture: the
// published fields of a publisher, the TargetVariables of a subscriber.
var psVars = []psVar{
	{"Boolean", id.Boolean, -1}, {"Int32", id.Int32, -1}, {"Int64", id.Int64, -1},
	{"UInt64", id.UInt64, -1}, {"Double", id.Double, -1}, {"String", id.String, -1},
	{"DateTime", id.DateTime, -1}, {"ByteString", id.ByteString, -1},
	{"Int32Array", id.Int32, 1}, {"DoubleArray", id.Double, 1},
}

// psVarsRaw are the variables a RawData DataSet carries: scalars only (the
// RawData encoding of an array needs fixed ArrayDimensions), String and
// ByteString with a MaxStringLength.
var psVarsRaw = []psVar{
	{"Boolean", id.Boolean, -1}, {"Int32", id.Int32, -1}, {"Int64", id.Int64, -1},
	{"UInt64", id.UInt64, -1}, {"Double", id.Double, -1}, {"String", id.String, -1},
	{"DateTime", id.DateTime, -1}, {"ByteString", id.ByteString, -1},
}

const psMaxStringLength = 32

func psNode(name string) string { return "nsu=" + interopNamespaceURI + ";s=PubSub." + name }

// psValues returns fresh values for vars: every run, and every call, uses
// other values so that a match proves the message was produced from them.
func psValues(vars []psVar, n int32) []any {
	out := make([]any, len(vars))
	for i, v := range vars {
		switch v.name {
		case "Boolean":
			out[i] = n%2 == 0
		case "Int32":
			out[i] = n
		case "Int64":
			out[i] = -9_000_000_000_000_000 - int64(n)
		case "UInt64":
			out[i] = uint64(1)<<63 + uint64(n)
		case "Double":
			out[i] = float64(n) + 0.25
		case "String":
			out[i] = fmt.Sprintf("pubsub-Δ-%d", n)
		case "DateTime":
			out[i] = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Add(time.Duration(n) * time.Millisecond)
		case "ByteString":
			out[i] = []byte{0, 1, byte(n), byte(n >> 8), 255}
		case "Int32Array":
			out[i] = []int32{n, -1, 7}
		case "DoubleArray":
			out[i] = []float64{1.5, -2.25, float64(n)}
		}
	}
	return out
}

var psNonce struct {
	sync.Mutex
	n int32
}

// psFresh returns a number not used before in this process.
func psFresh() int32 {
	psNonce.Lock()
	defer psNonce.Unlock()
	if psNonce.n == 0 {
		psNonce.n = int32(time.Now().UnixNano()%1_000_000) + 1000
	}
	psNonce.n += 17
	return psNonce.n
}

// psMetaData is the DataSetMetaData of vars.
func psMetaData(vars []psVar, maxStringLength uint32) *ua.DataSetMetaDataType {
	md := &ua.DataSetMetaDataType{Name: "InteropDataSet",
		ConfigurationVersion: &ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 1}}
	for _, v := range vars {
		f := psFieldMeta(v.name, v.typ, v.rank)
		if v.typ == id.String || v.typ == id.ByteString {
			f.MaxStringLength = maxStringLength
		}
		md.Fields = append(md.Fields, f)
	}
	return md
}

// writePubSubVars writes values into the PubSub.* variables of a server.
func writePubSubVars(t *testing.T, endpoint string, vars []psVar, values []any) {
	t.Helper()
	c := dialClient(t, endpoint)
	ctx, ns := findNS(t, c)
	req := &ua.WriteRequest{}
	for i, v := range vars {
		req.NodesToWrite = append(req.NodesToWrite, &ua.WriteValue{
			NodeID: ua.NewStringNodeID(ns, "PubSub."+v.name), AttributeID: ua.AttributeIDValue,
			Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(values[i])},
		})
	}
	resp, err := c.Write(ctx, req)
	if err != nil {
		t.Fatalf("write PubSub variables: %v", err)
	}
	for i, r := range resp.Results {
		if r != ua.StatusOK {
			t.Fatalf("write PubSub.%s: %v", vars[i].name, r)
		}
	}
}

// waitPubSubVars polls the PubSub.* variables of a server until they hold
// values (type and value), or fails after timeout.
func waitPubSubVars(t *testing.T, endpoint string, vars []psVar, values []any, timeout time.Duration) {
	t.Helper()
	c := dialClient(t, endpoint)
	_, ns := findNS(t, c)
	req := &ua.ReadRequest{TimestampsToReturn: ua.TimestampsToReturnNeither}
	for _, v := range vars {
		req.NodesToRead = append(req.NodesToRead, &ua.ReadValueID{NodeID: ua.NewStringNodeID(ns, "PubSub."+v.name), AttributeID: ua.AttributeIDValue})
	}
	want := make([]string, len(values))
	for i, v := range values {
		want[i] = variantKey(t, ua.MustVariant(v))
	}
	deadline := time.Now().Add(timeout)
	var last []string
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := c.Read(ctx, req)
		cancel()
		if err == nil && len(resp.Results) == len(vars) {
			last = last[:0]
			match := true
			for i, r := range resp.Results {
				got := "?"
				if r.Status == ua.StatusOK {
					got = variantKey(t, r.Value)
				}
				last = append(last, fmt.Sprintf("%s=%v", vars[i].name, r.Value))
				if got != want[i] {
					match = false
				}
			}
			if match {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the subscriber's TargetVariables did not follow within %v\n want %v\n got  %v (read error %v)", timeout, values, last, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Configuration documents (contract §14.1, §14.2)
// ---------------------------------------------------------------------------

type jobj = map[string]any

func eo(typeID string, body jobj) jobj { return jobj{"UaTypeId": typeID, "UaBody": body} }

// psPublisherIDJSON is a PublisherId Variant: UaType 3 Byte, 5 UInt16,
// 7 UInt32, 9 UInt64, 12 String.
func psPublisherIDJSON(uaType int, v any) jobj { return jobj{"UaType": uaType, "Value": v} }

func psMetaDataJSON(vars []psVar, maxStringLength uint32) jobj {
	var fields []jobj
	for _, v := range vars {
		f := jobj{"Name": v.name, "BuiltInType": v.typ, "DataType": fmt.Sprintf("i=%d", v.typ), "ValueRank": v.rank}
		if maxStringLength > 0 && (v.typ == id.String || v.typ == id.ByteString) {
			f["MaxStringLength"] = maxStringLength
		}
		fields = append(fields, f)
	}
	return jobj{"Name": "InteropDataSet", "Fields": fields, "ConfigurationVersion": jobj{"MajorVersion": 1, "MinorVersion": 1}}
}

func psPublishedDataSetJSON(vars []psVar, maxStringLength uint32) jobj {
	var items []jobj
	for _, v := range vars {
		items = append(items, jobj{"PublishedVariable": psNode(v.name), "AttributeId": 13})
	}
	return jobj{"Name": "InteropDataSet", "DataSetMetaData": psMetaDataJSON(vars, maxStringLength),
		"DataSetSource": eo("i=15581", jobj{"PublishedData": items})}
}

func psTargetVariablesJSON(vars []psVar) jobj {
	var tv []jobj
	for _, v := range vars {
		tv = append(tv, jobj{"TargetNodeId": psNode(v.name), "AttributeId": 13})
	}
	return eo("i=15631", jobj{"TargetVariables": tv})
}

// psSecurity sets SecurityMode and SecurityGroupId on a group.
func psSecure(group jobj, mode ua.MessageSecurityMode, groupID string) jobj {
	if mode > ua.MessageSecurityModeNone {
		group["SecurityMode"] = int(mode)
		group["SecurityGroupId"] = groupID
	}
	return group
}

// psSecurityGroupJSON is a securityGroups entry; key nil: no static key.
func psSecurityGroupJSON(groupID, policyURI string, tokenID uint32, key []byte) jobj {
	g := jobj{"securityGroupId": groupID, "securityPolicyUri": policyURI}
	if key != nil {
		g["keys"] = []jobj{{"tokenId": tokenID, "key": base64.StdEncoding.EncodeToString(key)}}
	}
	return g
}

// ---------------------------------------------------------------------------
// The adapter as PubSub node
// ---------------------------------------------------------------------------

type pubsubServer struct {
	name     string
	endpoint string // opc.tcp://localhost:<port>/opcua-interop
}

type pubsubServerOpts struct {
	config   jobj  // the --pubsub-config document
	udpPorts []int // published as <p>:<p>/udp
	// secure starts the server with the open62541-server certificate of
	// the test PKI (needed for sksClient, serveSks and SetSecurityKeys).
	secure bool
	// hostNetwork runs the container in the host's network namespace
	// (Linux only): multicast between the host and the container works
	// there, while it does not cross Docker Desktop's VM or a bridge.
	hostNetwork bool
}

// startPubSubServer starts the open62541 adapter with a PubSub
// configuration. The adapter applies it before it writes its ready file
// and exits when it rejects it.
func startPubSubServer(t *testing.T, o pubsubServerOpts) *pubsubServer {
	t.Helper()
	requirePubSubServer(t)

	dir := containerScratchDir(t)
	doc, err := json.MarshalIndent(o.config, "", "  ")
	if err != nil {
		t.Fatalf("pubsub config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pubsub.json"), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := shareWithContainers(dir); err != nil {
		t.Fatal(err)
	}
	fixtureDir := getEnvOr("OPCUA_INTEROP_FIXTURE_DIR", defaultFixtureDir)
	if !filepath.IsAbs(fixtureDir) {
		cwd, _ := os.Getwd()
		fixtureDir = filepath.Join(cwd, fixtureDir)
	}

	port := freePort(t)
	name := dockerContainerName(t)
	args := []string{"run", "--rm", "--name", name,
		"-v", fixtureDir + ":/fixtures:ro",
		"-v", dir + ":/pubsub:ro",
	}
	serverArgs := []string{"server", "--fixture", "/fixtures/baseline.json", "--pubsub-config", "/pubsub/pubsub.json"}
	if o.hostNetwork {
		// No port mapping: the server binds the host port itself.
		args = append(args, "--network", "host")
		serverArgs = append(serverArgs, "--bind-port", fmt.Sprint(port), "--advertised-host", "localhost")
	} else {
		args = append(args, "--add-host=host.docker.internal:host-gateway", "-p", fmt.Sprintf("%d:4840", port))
		for _, p := range o.udpPorts {
			args = append(args, "-p", fmt.Sprintf("%d:%d/udp", p, p))
		}
	}
	if o.secure {
		pki := pkiDir(t)
		runtimePKI := filepath.Join(containerScratchDir(t), "pki")
		if err := copyDir(filepath.Join(pki, "open62541-server", "pki"), runtimePKI); err != nil {
			t.Fatalf("copy PKI: %v", err)
		}
		if err := shareWithContainers(runtimePKI); err != nil {
			t.Fatal(err)
		}
		args = append(args,
			"-v", filepath.Join(pki, "open62541-server", "cert.crt")+":/certs/cert.crt:ro",
			"-v", filepath.Join(pki, "open62541-server", "cert.key")+":/certs/cert.key:ro",
			"-v", runtimePKI+":/certs/pki")
		serverArgs = append(serverArgs, "--certificate", "/certs/cert.crt", "--private-key", "/certs/cert.key", "--pki-dir", "/certs/pki")
	}
	args = append(args, getEnvOr("OPEN62541_IMAGE", defaultOpen62541Image))
	args = append(args, serverArgs...)

	var logs bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the open62541 PubSub server: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			if o.secure {
				dockerReleaseMount(name, "/certs/pki")
			}
			dockerStop(name)
			select {
			case err := <-exited:
				_ = err // docker run exits non-zero when stopped
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
			}
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			t.Logf("open62541 PubSub server %s log:\n%s", name, logs.String())
		}
	})

	deadline := time.Now().Add(serverReadyTimeout)
	for {
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("the open62541 PubSub server exited (%v) — the configuration was rejected?\nconfig: %s\nlog:\n%s", err, doc, logs.String())
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ready := exec.CommandContext(ctx, "docker", "exec", name, "test", "-f", "/run/opcua-interop/ready").Run() == nil
		cancel()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the open62541 PubSub server\nlog:\n%s", logs.String())
		}
		time.Sleep(300 * time.Millisecond)
	}
	return &pubsubServer{name: name, endpoint: fmt.Sprintf("opc.tcp://localhost:%d%s", port, endpointPath)}
}

// freeUDPPort returns a UDP port that is free on the host.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	return testport.UDP(t)
}

// startMosquitto starts the MQTT broker and returns its host port.
func startMosquitto(t *testing.T) int {
	t.Helper()
	dir := containerScratchDir(t)
	conf := filepath.Join(dir, "mosquitto.conf")
	if err := os.WriteFile(conf, []byte(mosquittoConf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := shareWithContainers(dir); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	name := dockerContainerName(t) + "-mosquitto"
	var logs bytes.Buffer
	cmd := exec.Command("docker", "run", "--rm", "--name", name, "-p", fmt.Sprintf("%d:1883", port),
		"-v", conf+":/mosquitto-interop.conf:ro", mosquittoImage, "mosquitto", "-c", "/mosquitto-interop.conf")
	var mu sync.Mutex
	cmd.Stdout = lockedWriter{&mu, &logs}
	cmd.Stderr = lockedWriter{&mu, &logs}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mosquitto: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		dockerStop(name)
		<-done
		if t.Failed() {
			mu.Lock()
			t.Logf("mosquitto log:\n%s", logs.String())
			mu.Unlock()
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		mu.Lock()
		up := strings.Contains(logs.String(), "running")
		mu.Unlock()
		if up {
			return port
		}
		select {
		case <-done:
			t.Fatalf("mosquitto exited:\n%s", logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("mosquitto did not start:\n%s", logs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// psListen opens a PubSub transport connection and delivers what it
// receives on topic (ignored for UDP).
func psListen(t *testing.T, cfg transport.Config, topic string) <-chan *transport.Message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := transport.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open %s: %v", cfg.URL, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ch := make(chan *transport.Message, 256)
	if _, err := conn.Subscribe(ctx, topic, 0, func(m *transport.Message) {
		select {
		case ch <- m:
		default: // the test reads only the recent ones
		}
	}); err != nil {
		t.Fatalf("subscribe %s %s: %v", cfg.URL, topic, err)
	}
	return ch
}

// psDial opens a PubSub transport connection for sending.
func psDial(t *testing.T, cfg transport.Config) transport.Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := transport.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open %s: %v", cfg.URL, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// dialSecureUserClient is dialSecureClient with a UserName identity.
func dialSecureUserClient(t *testing.T, endpoint, policy, mode, user, pass string) *opcua.Client {
	t.Helper()
	pki := pkiDir(t)
	ca := loadCACert(t, filepath.Join(pki, "ca", "ca.crt"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, endpoint)
	if err != nil {
		t.Fatalf("GetEndpoints(%q): %v", endpoint, err)
	}
	var chosen *ua.EndpointDescription
	for _, ep := range eps {
		if ep.SecurityPolicyURI == ua.FormatSecurityPolicyURI(policy) && ep.SecurityMode == ua.MessageSecurityModeFromString(mode) {
			chosen = ep
			break
		}
	}
	if chosen == nil {
		t.Fatalf("no %s/%s endpoint", policy, mode)
	}
	chosen.EndpointURL = endpoint
	c, err := opcua.NewClient(endpoint,
		opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeUserName),
		opcua.CertificateFile(filepath.Join(pki, "consumer", "cert.crt")),
		opcua.PrivateKeyFile(filepath.Join(pki, "consumer", "cert.key")),
		opcua.TrustedCertificates(ca),
		opcua.AuthUsername(user, pass),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect %s/%s as %s: %v", policy, mode, user, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	return c
}

// TestPubSub_MiloHasNoPubSub is the evidence behind the "unsupported" Milo
// rows of the pubsub profile: Eclipse Milo 1.1.8 has no PubSub (Part 14)
// implementation (only the generated DataTypes and ObjectType stubs), and the
// Milo adapter declares pubsub.supported=false and refuses --pubsub-config
// and the codec pubsub-* operations (contract §14.12).
func TestPubSub_MiloHasNoPubSub(t *testing.T) {
	caps, image := imageCapabilities(t, "MILO_IMAGE", defaultMiloImage)
	requirePinnedVersion(t, "MILO_IMAGE", caps, image)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", image, "print-capabilities").Output()
	if err != nil {
		t.Fatalf("print-capabilities: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var doc struct {
		PubSub *struct {
			Supported bool   `json:"supported"`
			Reason    string `json:"reason"`
		} `json:"pubsub"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &doc); err != nil {
		t.Fatalf("print-capabilities: %v", err)
	}
	if doc.PubSub == nil {
		capabilityUnavailable(t, "adapter %s (version %s) does not declare pubsub; need opcua-interop v0.8.0", image, caps.Adapter.Version)
	}
	if doc.PubSub.Supported {
		t.Fatalf("the Milo adapter declares PubSub support: update the pubsub rows of interop/coverage.json")
	}
	t.Logf("Milo: %s", doc.PubSub.Reason)
	// The adapter refuses the codec operations.
	r := runMiloClientCodecPubSub(t, image)
	if r.Success {
		t.Errorf("the Milo adapter ran codec pubsub-uadp-decode: %+v", r)
	}
}

func runMiloClientCodecPubSub(t *testing.T, image string) adapterResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	raw, _ := exec.CommandContext(ctx, "docker", "run", "--rm", image, "client", "codec", "pubsub-uadp-decode", "--document", "AQ==").Output()
	r, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("codec pubsub-uadp-decode on Milo: %v\nraw: %s", err, raw)
	}
	return r
}
