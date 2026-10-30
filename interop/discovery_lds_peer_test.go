//go:build interop

// SPDX-License-Identifier: MIT

// Peer evidence for discovery beyond GetEndpoints: Local Discovery Server
// registration (RegisterServer / RegisterServer2) and the multicast extension
// (FindServersOnNetwork, mDNS), go-opcua against open62541 and Eclipse Milo.
// COVERAGE.md: discovery / discovery.lds-registration,
// discovery.register-server, discovery.register-server2.mdns,
// discovery.find-servers-on-network, discovery.multicast
//
// Adapter surface (opcua-interop client contract §1, §11, §13):
//
//	server --lds                     open62541: the adapter is an LDS with mDNS
//	server --register-with <url>     both: the adapter server registers with an LDS
//	client find-servers-on-network   both: FindServersOnNetwork
//	client register-server           both: RegisterServer2 / RegisterServer
//
// advertised by print-capabilities as serverFeatures ["lds", "mdns",
// "register-with"] and as clientOperations. A test is skipped when its
// feature is missing, and fails instead when
// OPCUA_INTEROP_REQUIRE_CAPABILITIES=1.
//
// Eclipse Milo 1.1.8 is no discovery server: it answers RegisterServer,
// RegisterServer2 and FindServersOnNetwork with Bad_ServiceUnsupported and
// has no mDNS (TestMiloServer_DiscoveryServerUnsupported pins that down). It
// registers with an LDS and its client calls the services, so the directions
// towards a go-opcua LDS are covered for both peers.
//
// mDNS needs both peers on one network segment. Docker Desktop does not route
// multicast between the host and containers, so for those assertions the
// go-opcua side runs in a container as well (see ./discoverypeer), next to
// the adapter on a user-defined bridge network, and is queried through a
// published port. The tests create and remove that network themselves; all
// they need is a Docker daemon that allows user-defined bridge networks.

package interop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// discoveryWait bounds how long a registration or an mDNS discovery may take.
const discoveryWait = 60 * time.Second

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// startAdapterServerWith is startAdapterServer with extra `docker run`
// arguments (before the image) and extra adapter arguments (after "server").
func startAdapterServerWith(t *testing.T, imageEnvVar, defaultImage string, dockerArgs, serverArgs []string) (*serverHandle, string) {
	t.Helper()
	requireOptionalPeer(t, imageEnvVar, defaultImage)

	image := getEnvOr(imageEnvVar, defaultImage)
	fixtureDir := getEnvOr("OPCUA_INTEROP_FIXTURE_DIR", defaultFixtureDir)
	if !filepath.IsAbs(fixtureDir) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		fixtureDir = filepath.Join(cwd, fixtureDir)
	}

	for range publishAttempts {
		port := freePort(t)
		containerName := dockerContainerName(t) + fmt.Sprintf("-%d", port)
		args := []string{"run", "--rm", "--name", containerName,
			"-p", fmt.Sprintf("%d:4840", port),
			"-v", fixtureDir + ":/fixtures:ro",
			"--add-host=host.docker.internal:host-gateway",
		}
		args = append(args, dockerArgs...)
		args = append(args, image, "server", "--fixture", "/fixtures/baseline.json")
		for _, a := range serverArgs {
			// {port} is the host port the server is published on.
			args = append(args, strings.ReplaceAll(a, "{port}", fmt.Sprint(port)))
		}

		cmdCtx, cmdCancel := context.WithCancel(context.Background())
		run, err := startDockerRun(exec.CommandContext(cmdCtx, "docker", args...), nil)
		if err != nil {
			cmdCancel()
			t.Fatalf("start adapter server (%s): %v", image, err)
		}
		var once sync.Once
		stop := func() {
			once.Do(func() {
				// SIGTERM with a grace period: an adapter that registered with
				// a discovery server unregisters on the way out.
				exec.Command("docker", "stop", "-t", "15", containerName).Run() //nolint:errcheck
				cmdCancel()
				run.wait()
			})
		}

		startCtx, startCancel := context.WithTimeout(context.Background(), serverReadyTimeout)
		err = waitDockerReady(startCtx, run, containerName)
		startCancel()
		if run.portTaken() {
			cmdCancel()
			dockerRemove(containerName)
			t.Logf("host port %d taken: another one", port)
			continue
		}
		if err != nil {
			stop()
			t.Fatalf("waiting for adapter server (container: %s): %v", containerName, err)
		}
		t.Cleanup(stop)
		return &serverHandle{endpoint: fmt.Sprintf("opc.tcp://localhost:%d%s", port, endpointPath), stopFn: stop}, containerName
	}
	t.Fatalf("no host port Docker could publish the adapter server on in %d attempts", publishAttempts)
	return nil, ""
}

// startGoLDS starts an in-process go-opcua Local Discovery Server that
// adapters in containers can reach as host.docker.internal.
func startGoLDS(t *testing.T, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	all := append([]server.Option{
		server.ListenOn("0.0.0.0:0"),
		server.EndPoint("host.docker.internal", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI("urn:otfabric:go-opcua:interop:lds"),
		server.ServerName("go-opcua LDS"),
	}, opts...)
	s, err := server.New(all...)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, fmt.Sprintf("opc.tcp://localhost:%d", s.Port())
}

// awaitDiscovery polls cond until it holds or discoveryWait has passed.
func awaitDiscovery(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(discoveryWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", discoveryWait, what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// foundServerURIs returns the application URIs FindServers reports at
// endpoint, or nil if the call fails.
func foundServerURIs(endpoint string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	servers, err := opcua.FindServers(ctx, endpoint)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range servers {
		out = append(out, s.ApplicationURI)
	}
	return out
}

// serversOnNetwork returns the records FindServersOnNetwork reports at
// endpoint, or nil if the call fails.
func serversOnNetwork(endpoint string) []*ua.ServerOnNetwork {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	recs, err := opcua.FindServersOnNetwork(ctx, endpoint)
	if err != nil {
		return nil
	}
	return recs
}

// ---------------------------------------------------------------------------
// Registration: go-opcua server -> open62541 LDS
// ---------------------------------------------------------------------------

// TestOpen62541LDS_GoServerRegisters: a go-opcua server registers with the
// open62541 LDS, is found there with FindServers, and unregisters on Close.
func TestOpen62541LDS_GoServerRegisters(t *testing.T) {
	t.Run("coverage/discovery.lds-registration/go-server-to-open62541-lds", func(t *testing.T) {
		requireServerFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "lds")
		lds, _ := startAdapterServerWith(t, "OPEN62541_IMAGE", defaultOpen62541Image, nil, []string{"--lds"})

		const uri = "urn:otfabric:go-opcua:interop:registrant"
		var mu sync.Mutex
		var events []server.RegistrationEvent
		srv, err := server.New(
			server.ListenOn("0.0.0.0:0"),
			server.EndPoint("host.docker.internal", 0),
			server.EnableSecurity("None", ua.MessageSecurityModeNone),
			server.EnableAuthMode(ua.UserTokenTypeAnonymous),
			server.ApplicationURI(uri),
			server.ServerName("go-opcua registrant"),
			server.WithDiscoveryRegistration(lds.endpoint,
				server.RegisterInsecure(),
				server.RegisterMdnsServerName("GoRegistrant"),
				server.RegisterServerCapabilities("DA"),
				server.RegisterEventHandler(func(e server.RegistrationEvent) {
					mu.Lock()
					events = append(events, e)
					mu.Unlock()
				}),
			),
		)
		if err != nil {
			t.Fatalf("server.New: %v", err)
		}
		if err := srv.Start(context.Background()); err != nil {
			t.Fatalf("server.Start: %v", err)
		}
		closed := false
		t.Cleanup(func() {
			if !closed {
				_ = srv.Close()
			}
		})

		// The LDS can list the server before the RegisterServer2 response, and
		// with it the registration event, reaches the registrant: wait for both.
		var accepted *server.RegistrationEvent
		acceptedEvent := func() *server.RegistrationEvent {
			mu.Lock()
			defer mu.Unlock()
			for i := range events {
				if events[i].Err == nil && events[i].Online {
					e := events[i]
					return &e
				}
			}
			return nil
		}
		awaitDiscovery(t, "the open62541 LDS to list the go-opcua server and the registration to succeed", func() bool {
			if accepted = acceptedEvent(); accepted == nil {
				return false
			}
			return slices.Contains(foundServerURIs(lds.endpoint), uri)
		})
		if accepted.Service != "RegisterServer2" {
			t.Errorf("registered with %s, want RegisterServer2 (open62541 implements it)", accepted.Service)
		}
		t.Logf("registered with %s, configuration results %v", accepted.Service, accepted.ConfigurationResults)
		// The MdnsDiscoveryConfiguration of RegisterServer2 was accepted and
		// took effect: the LDS serves a FindServersOnNetwork record under the
		// requested mDNS server name with the registered capabilities.
		if len(accepted.ConfigurationResults) != 1 || accepted.ConfigurationResults[0] != ua.StatusOK {
			t.Errorf("configuration results %v, want [Good]", accepted.ConfigurationResults)
		}
		isRegistrant := func(r *ua.ServerOnNetwork) bool { return strings.HasPrefix(r.ServerName, "GoRegistrant") }
		var rec *ua.ServerOnNetwork
		awaitDiscovery(t, "the open62541 LDS to serve a record for the registered server", func() bool {
			for _, r := range serversOnNetwork(lds.endpoint) {
				if isRegistrant(r) {
					rec = r
					return true
				}
			}
			return false
		})
		t.Logf("open62541 LDS: id=%d name=%q url=%s caps=%v", rec.RecordID, rec.ServerName, rec.DiscoveryURL, rec.ServerCapabilities)
		if !strings.Contains(rec.DiscoveryURL, fmt.Sprintf(":%d", srv.Port())) || !slices.Contains(rec.ServerCapabilities, "DA") {
			t.Errorf("record of the registered server: url=%s caps=%v, want port %d and capability DA", rec.DiscoveryURL, rec.ServerCapabilities, srv.Port())
		}

		closed = true
		if err := srv.Close(); err != nil {
			t.Fatalf("server.Close: %v", err)
		}
		awaitDiscovery(t, "the open62541 LDS to drop the unregistered server", func() bool {
			uris := foundServerURIs(lds.endpoint)
			return uris != nil && !slices.Contains(uris, uri)
		})
		awaitDiscovery(t, "the open62541 LDS to withdraw the record of the unregistered server", func() bool {
			recs := serversOnNetwork(lds.endpoint)
			return recs != nil && !slices.ContainsFunc(recs, isRegistrant)
		})
	})
}

// ---------------------------------------------------------------------------
// Registration: peer server -> go-opcua LDS
// ---------------------------------------------------------------------------

// assertPeerServerRegistersWithGoLDS: the adapter server registers with a
// go-opcua LDS (--register-with); a go-opcua client and the adapter client
// find it there and the discovered URL leads to the server; it unregisters
// when it is stopped.
func assertPeerServerRegistersWithGoLDS(t *testing.T, imageEnv, defaultImage string) {
	t.Helper()
	requireServerFeature(t, imageEnv, defaultImage, "register-with")

	var mu sync.Mutex
	online := map[string]bool{}
	lds, ldsURL := startGoLDS(t, server.WithLocalDiscoveryServer(
		server.LDSAllowInsecureRegistration(),
		server.LDSRegistrationCallback(func(rs *ua.RegisteredServer) {
			mu.Lock()
			online[rs.ServerURI] = rs.IsOnline
			mu.Unlock()
		}),
	))
	ldsFromContainer := strings.ReplaceAll(ldsURL, "localhost", "host.docker.internal")
	// The server advertises the address it is reachable at from the host,
	// which is therefore what it has to register as its discovery URL.
	peer, _ := startAdapterServerWith(t, imageEnv, defaultImage, nil, []string{
		"--advertised-host", "localhost", "--advertised-port", "{port}",
		"--register-with", ldsFromContainer,
	})

	awaitDiscovery(t, "the peer server to register with the go-opcua LDS", func() bool {
		return len(lds.RegisteredServers()) > 0
	})
	reg := lds.RegisteredServers()[0]
	t.Logf("registered: uri=%s urls=%v names=%d type=%v", reg.ServerURI, reg.DiscoveryURLs, len(reg.ServerNames), reg.ServerType)
	if reg.ServerURI != "urn:otfabric:opcua-interop:server" {
		t.Errorf("registered ServerUri = %q, want the adapter's ApplicationUri", reg.ServerURI)
	}
	if !slices.Contains(reg.DiscoveryURLs, peer.endpoint) {
		t.Errorf("registered discovery URLs %v do not contain the advertised endpoint %s", reg.DiscoveryURLs, peer.endpoint)
	}
	if len(reg.ServerNames) == 0 || reg.ServerNames[0].Text == "" {
		t.Errorf("registered without a server name: %+v", reg.ServerNames)
	}
	if !reg.IsOnline {
		t.Errorf("registered with IsOnline=false")
	}

	// A go-opcua client finds it through the LDS, next to the LDS itself,
	// and the discovery URL it gets leads to the server.
	ctx := shortTestCtx(t)
	found, err := opcua.FindServers(ctx, ldsURL)
	if err != nil {
		t.Fatalf("FindServers on the go-opcua LDS: %v", err)
	}
	var app *ua.ApplicationDescription
	uris := make([]string, 0, len(found))
	for _, a := range found {
		uris = append(uris, a.ApplicationURI)
		if a.ApplicationURI == reg.ServerURI {
			app = a
		}
	}
	if app == nil || !slices.Contains(uris, "urn:otfabric:go-opcua:interop:lds") {
		t.Fatalf("FindServers on the go-opcua LDS: %v", uris)
	}
	if len(app.DiscoveryURLs) == 0 {
		t.Fatalf("FindServers lists %s without discovery URLs", app.ApplicationURI)
	}
	c := dialClient(t, app.DiscoveryURLs[0])
	_, nsIdx := findNS(t, c)
	if dv, err := c.ReadValue(ctx, ua.NewStringNodeID(nsIdx, "Scalar.Int32")); err != nil || dv.Value.Int() != -123456789 {
		t.Errorf("read through the discovered URL %s: %v %v", app.DiscoveryURLs[0], dv, err)
	}

	// ... and so does the adapter client of the same stack.
	result := runAdapterClient(t, imageEnv, defaultImage, ldsURL, "find-servers")
	if !result.Success {
		t.Fatalf("find-servers failed: %s %s", result.ServiceResult, result.Error)
	}
	var apps []struct {
		ApplicationURI string   `json:"applicationUri"`
		DiscoveryURLs  []string `json:"discoveryUrls"`
	}
	if err := json.Unmarshal(result.Results, &apps); err != nil {
		t.Fatalf("unmarshal find-servers results: %v\nraw: %s", err, result.Results)
	}
	listed := false
	for _, a := range apps {
		if a.ApplicationURI == reg.ServerURI && slices.Contains(a.DiscoveryURLs, peer.endpoint) {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("adapter find-servers on the go-opcua LDS does not list %s at %s: %s", reg.ServerURI, peer.endpoint, result.Results)
	}

	// Stopping the server unregisters it (IsOnline=false).
	peer.stopFn()
	awaitDiscovery(t, "the peer server to unregister", func() bool {
		return len(lds.RegisteredServers()) == 0
	})
	mu.Lock()
	defer mu.Unlock()
	if on, seen := online[reg.ServerURI]; !seen || on {
		t.Errorf("the last RegisterServer call for %s had IsOnline=%v, want false", reg.ServerURI, on)
	}
}

// TestGoLDS_Open62541ServerRegisters: open62541 server -> go-opcua LDS.
func TestGoLDS_Open62541ServerRegisters(t *testing.T) {
	t.Run("coverage/discovery.lds-registration/open62541-server-to-go-lds", func(t *testing.T) {
		assertPeerServerRegistersWithGoLDS(t, "OPEN62541_IMAGE", defaultOpen62541Image)
	})
}

// TestGoLDS_MiloServerRegisters: Milo server -> go-opcua LDS.
func TestGoLDS_MiloServerRegisters(t *testing.T) {
	t.Run("coverage/discovery.lds-registration/milo-server-to-go-lds", func(t *testing.T) {
		assertPeerServerRegistersWithGoLDS(t, "MILO_IMAGE", defaultMiloImage)
	})
}

// TestGoLDS_Open62541Client_RegisterServer: the open62541 client command
// register-server registers a server with a go-opcua LDS.
func TestGoLDS_Open62541Client_RegisterServer(t *testing.T) {
	t.Run("coverage/discovery.register-server/open62541-client-to-go-lds", func(t *testing.T) {
		assertClientRegistersWithGoLDS(t, "OPEN62541_IMAGE", defaultOpen62541Image)
	})
}

// TestGoLDS_MiloClient_RegisterServer: the same with the Milo client.
func TestGoLDS_MiloClient_RegisterServer(t *testing.T) {
	t.Run("coverage/discovery.register-server/milo-client-to-go-lds", func(t *testing.T) {
		assertClientRegistersWithGoLDS(t, "MILO_IMAGE", defaultMiloImage)
	})
}

// registerServerResult is the result item of the adapter's register-server.
type registerServerResult struct {
	Service                   string          `json:"service"`
	ServerURI                 string          `json:"serverUri"`
	IsOnline                  bool            `json:"isOnline"`
	StatusCode                statusCodeObj   `json:"statusCode"`
	Fallback                  bool            `json:"fallback"`
	RegisterServer2StatusCode *statusCodeObj  `json:"registerServer2StatusCode"`
	ConfigurationResults      []statusCodeObj `json:"configurationResults"`
}

func parseRegisterServer(t *testing.T, result adapterResult) registerServerResult {
	t.Helper()
	var items []registerServerResult
	if err := json.Unmarshal(result.Results, &items); err != nil || len(items) != 1 {
		t.Fatalf("register-server results (%v): %s (serviceResult=%s error=%s)", err, result.Results, result.ServiceResult, result.Error)
	}
	return items[0]
}

// assertClientRegistersWithGoLDS drives RegisterServer and RegisterServer2 of
// a go-opcua LDS without the multicast extension from the adapter client.
// (RegisterServer2 against an LDS with the multicast extension:
// TestMulticast_GoAndOpen62541.)
func assertClientRegistersWithGoLDS(t *testing.T, imageEnv, defaultImage string) {
	t.Helper()
	requireAdapterOp(t, imageEnv, defaultImage, "register-server")
	requireAdapterClientFeature(t, imageEnv, defaultImage, "register-server2")
	lds, ldsURL := startGoLDS(t, server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()))

	const (
		uri = "urn:otfabric:opcua-interop:registered-by-client"
		url = "opc.tcp://registered-by-client:4840"
	)
	registered := func() *ua.RegisteredServer {
		for _, r := range lds.RegisteredServers() {
			if r.ServerURI == uri {
				return r
			}
		}
		return nil
	}

	// RegisterServer.
	result := runAdapterClientResult(t, imageEnv, defaultImage, ldsURL, "register-server",
		"--service", "RegisterServer",
		"--server-uri", uri, "--server-name", "Registered By Client", "--discovery-url", url)
	item := parseRegisterServer(t, result)
	if !result.Success || item.Service != "RegisterServer" || !statusCodeIs(item.StatusCode, ua.StatusOK) {
		t.Fatalf("RegisterServer failed: %+v (serviceResult=%s error=%s)", item, result.ServiceResult, result.Error)
	}
	reg := registered()
	if reg == nil || len(lds.RegisteredServers()) != 1 {
		t.Fatalf("registered servers after RegisterServer: %+v", lds.RegisteredServers())
	}
	if !slices.Contains(reg.DiscoveryURLs, url) {
		t.Errorf("discovery URLs: %v", reg.DiscoveryURLs)
	}
	if len(reg.ServerNames) != 1 || reg.ServerNames[0].Text != "Registered By Client" {
		t.Errorf("server names: %+v", reg.ServerNames)
	}
	if !slices.Contains(foundServerURIs(ldsURL), uri) {
		t.Errorf("FindServers does not list the server registered by the adapter client")
	}

	// Unregister (IsOnline=false).
	result = runAdapterClientResult(t, imageEnv, defaultImage, ldsURL, "register-server",
		"--service", "RegisterServer", "--online", "false",
		"--server-uri", uri, "--discovery-url", url)
	if item = parseRegisterServer(t, result); !result.Success || item.IsOnline {
		t.Fatalf("unregister failed: %+v (serviceResult=%s error=%s)", item, result.ServiceResult, result.Error)
	}
	if registered() != nil || slices.Contains(foundServerURIs(ldsURL), uri) {
		t.Fatalf("still registered after IsOnline=false: %+v", lds.RegisteredServers())
	}
	// Unregistering what is not registered is reported as such.
	result = runAdapterClientResult(t, imageEnv, defaultImage, ldsURL, "register-server",
		"--service", "RegisterServer", "--online", "false",
		"--server-uri", uri, "--discovery-url", url)
	if item = parseRegisterServer(t, result); result.Success || !statusCodeIs(item.StatusCode, ua.StatusBadNothingToDo) {
		t.Errorf("unregistering an unknown server: %+v, want BadNothingToDo", item)
	}

	// RegisterServer2 (the adapter's default) with an
	// MdnsDiscoveryConfiguration. This LDS has no multicast extension: the
	// server is registered, the service result is Good and the discovery
	// configuration is answered with Bad_NotSupported (Part 4 §5.4.6). The
	// adapter reports a configuration result that is not Good as a failed
	// command.
	result = runAdapterClientResult(t, imageEnv, defaultImage, ldsURL, "register-server",
		"--server-uri", uri, "--server-name", "Registered By Client", "--discovery-url", url,
		"--mdns-name", "registered-by-client", "--capability", "DA")
	item = parseRegisterServer(t, result)
	if item.Service != "RegisterServer2" || item.Fallback || !statusCodeIs(item.StatusCode, ua.StatusOK) {
		t.Fatalf("RegisterServer2: %+v (serviceResult=%s error=%s)", item, result.ServiceResult, result.Error)
	}
	if len(item.ConfigurationResults) != 1 || !statusCodeIs(item.ConfigurationResults[0], ua.StatusBadNotSupported) {
		t.Errorf("RegisterServer2 configuration results %+v, want [BadNotSupported] from an LDS without the multicast extension", item.ConfigurationResults)
	}
	if registered() == nil {
		t.Errorf("RegisterServer2 answered Good but the server is not registered: %+v", lds.RegisteredServers())
	}
}

// ---------------------------------------------------------------------------
// Eclipse Milo is no discovery server
// ---------------------------------------------------------------------------

// TestMiloServer_DiscoveryServerUnsupported pins down why the ledger rows of
// the directions towards a Milo discovery server are "unsupported": the Milo
// server answers FindServersOnNetwork, RegisterServer2 and RegisterServer
// with Bad_ServiceUnsupported. go-opcua reports that cleanly on both paths.
func TestMiloServer_DiscoveryServerUnsupported(t *testing.T) {
	h := startMiloServer(t)

	ctx := shortTestCtx(t)
	if _, err := opcua.FindServersOnNetwork(ctx, h.endpoint); !errors.Is(err, ua.StatusBadServiceUnsupported) {
		t.Errorf("FindServersOnNetwork on the Milo server: %v, want BadServiceUnsupported", err)
	}

	events := make(chan server.RegistrationEvent, 16)
	srv, err := server.New(
		server.ListenOn("127.0.0.1:0"),
		server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.ApplicationURI("urn:otfabric:go-opcua:interop:registrant"),
		server.WithDiscoveryRegistration(h.endpoint,
			server.RegisterInsecure(),
			server.RegisterEventHandler(func(e server.RegistrationEvent) {
				select {
				case events <- e:
				default:
				}
			}),
		),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer srv.Close() //nolint:errcheck
	select {
	case e := <-events:
		// RegisterServer2 is unsupported, go-opcua falls back to
		// RegisterServer, which is unsupported as well.
		if e.Service != "RegisterServer" || !errors.Is(e.Err, ua.StatusBadServiceUnsupported) {
			t.Errorf("registration with the Milo server: service=%s err=%v, want RegisterServer / BadServiceUnsupported", e.Service, e.Err)
		}
	case <-time.After(discoveryWait):
		t.Fatal("no registration attempt was reported")
	}
}

// ---------------------------------------------------------------------------
// Multicast extension: container to container
// ---------------------------------------------------------------------------

// dockerNetwork creates a user-defined bridge network and removes it when the
// test ends.
func dockerNetwork(t *testing.T) string {
	t.Helper()
	name := strings.ToLower(dockerContainerName(t)) + "-net"
	if out, err := exec.Command("docker", "network", "create", name).CombinedOutput(); err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "network", "rm", name).Run() }) //nolint:errcheck
	return name
}

// buildDiscoveryPeer cross-compiles ./discoverypeer for the Docker host and
// returns the directory that holds the binary.
func buildDiscoveryPeer(t *testing.T) string {
	t.Helper()
	arch, err := exec.Command("docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	// The directory must be shareable with Docker; a temp dir below the
	// working directory is, on every Docker Desktop default configuration.
	dir, err := os.MkdirTemp(".", ".discoverypeer-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	cmd := exec.Command("go", "build", "-tags", "interop", "-o", filepath.Join(abs, "discoverypeer"), "./discoverypeer")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+strings.TrimSpace(string(arch)), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build discoverypeer: %v\n%s", err, out)
	}
	// The image's user is not root and has to read and execute the binary.
	if err := os.Chmod(abs, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return abs
}

// startGoPeerContainer runs the go-opcua discovery peer in a container on the
// given network and returns the URL of its published port and its URL on the
// network (opc.tcp://<hostname>:<port>).
//
// The peer listens on the same port number inside the container as the one
// published on the host: the go-opcua server answers a Hello whose
// EndpointUrl names another port than the one it listens on with
// Bad_TcpEndpointUrlInvalid, so a remapped port (-p 5000:4840) would make it
// unreachable from the host.
func startGoPeerContainer(t *testing.T, network, image, binDir string, peerArgs ...string) (hostURL, netURL, hostname string) {
	t.Helper()
	var port int
	var name string
	for attempt := 1; ; attempt++ {
		port = freePort(t)
		hostname = fmt.Sprintf("gopeer%d", port)
		name = strings.ToLower(dockerContainerName(t)) + "-" + hostname
		args := []string{"run", "--rm", "-d", "--name", name, "--hostname", hostname, "--network", network,
			"-p", fmt.Sprintf("%d:%d", port, port),
			"-v", binDir + ":/peer:ro",
			"--entrypoint", "/peer/discoverypeer",
			image, "-port", fmt.Sprint(port), "-host", hostname,
		}
		args = append(args, peerArgs...)
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err == nil {
			break
		}
		// docker run -d returns once the ports are published: a taken
		// host port fails it here, before anything knows the port.
		if dockerPortTaken(string(out)) && attempt < publishAttempts {
			dockerRemove(name)
			t.Logf("host port %d taken: another one", port)
			continue
		}
		t.Fatalf("start go-opcua peer container: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "100", name).CombinedOutput()
			t.Logf("go-opcua peer container log:\n%s", logs)
		}
		exec.Command("docker", "stop", "-t", "10", name).Run() //nolint:errcheck
	})
	hostURL = fmt.Sprintf("opc.tcp://localhost:%d", port)
	awaitDiscovery(t, "the go-opcua peer container to listen", func() bool { return foundServerURIs(hostURL) != nil })
	return hostURL, fmt.Sprintf("opc.tcp://%s:%d", hostname, port), hostname
}

// runAdapterClientOnNetwork runs an adapter client in a container on a
// user-defined Docker network. A failed command is not fatal: the result is
// returned as the adapter reported it.
func runAdapterClientOnNetwork(t *testing.T, imageEnv, defaultImage, network, subcmd string, args ...string) adapterResult {
	t.Helper()
	requireOptionalPeer(t, imageEnv, defaultImage)
	image := getEnvOr(imageEnv, defaultImage)
	cmdArgs := append([]string{"run", "--rm", "--network", network, image, "client", subcmd}, args...)
	raw, _ := runClientContainer(t, cmdArgs)
	result, err := parseAdapterOutput(raw)
	if err != nil {
		t.Fatalf("parse adapter client output: %v\nraw: %s", err, raw)
	}
	return result
}

// TestMulticast_GoAndPeers puts a go-opcua LDS and the open62541 LDS on one
// network segment (both in containers, see the file comment) and checks that
// each finds the other with mDNS and reports it from FindServersOnNetwork,
// that the open62541, Milo, async-opcua and dotnet clients get the records of the go-opcua LDS,
// and that RegisterServer2 with an MdnsDiscoveryConfiguration makes a server
// appear in them.
func TestMulticast_GoAndPeers(t *testing.T) {
	requireServerFeature(t, "OPEN62541_IMAGE", defaultOpen62541Image, "lds", "mdns")
	image := getEnvOr("OPEN62541_IMAGE", defaultOpen62541Image)

	network := dockerNetwork(t)
	binDir := buildDiscoveryPeer(t)
	adapter, adapterContainer := startAdapterServerWith(t, "OPEN62541_IMAGE", defaultOpen62541Image,
		[]string{"--network", network}, []string{"--lds"})
	goURL, goNetURL, goHost := startGoPeerContainer(t, network, image, binDir,
		"-name", "GoPeer", "-uri", "urn:otfabric:go-opcua:interop:mdns-peer", "-lds", "-mdns", "-caps", "DA,LDS")
	goInstance := "GoPeer-" + goHost

	find := func(recs []*ua.ServerOnNetwork, match func(*ua.ServerOnNetwork) bool) *ua.ServerOnNetwork {
		for _, r := range recs {
			if match(r) {
				return r
			}
		}
		return nil
	}
	isGo := func(r *ua.ServerOnNetwork) bool { return r.ServerName == goInstance }

	// open62541 browses, go-opcua announces: the open62541 LDS learned about
	// the go-opcua server through mDNS.
	t.Run("coverage/discovery.multicast/open62541-lds-discovers-go", func(t *testing.T) {
		// The record the wait found: a second query can fail (nil) or, with
		// mDNS records coming and going, miss it.
		var rec *ua.ServerOnNetwork
		awaitDiscovery(t, "the open62541 LDS to discover the go-opcua server with mDNS", func() bool {
			rec = find(serversOnNetwork(adapter.endpoint), isGo)
			return rec != nil
		})
		t.Logf("open62541 LDS: id=%d name=%q url=%s caps=%v", rec.RecordID, rec.ServerName, rec.DiscoveryURL, rec.ServerCapabilities)
		// The record carries the mDNS host name (<hostname>.local) and port.
		if !strings.Contains(rec.DiscoveryURL, goHost) || !strings.HasSuffix(strings.TrimSuffix(rec.DiscoveryURL, "/"), goNetURL[strings.LastIndex(goNetURL, ":"):]) {
			t.Errorf("discovery URL of the go-opcua server: %s, want host %s and the port of %s", rec.DiscoveryURL, goHost, goNetURL)
		}
		if !slices.Contains(rec.ServerCapabilities, "DA") || !slices.Contains(rec.ServerCapabilities, "LDS") {
			t.Errorf("capabilities of the go-opcua server: %v", rec.ServerCapabilities)
		}
	})

	// The go-opcua client calls FindServersOnNetwork on the open62541 LDS:
	// records, capability filter, paging.
	t.Run("coverage/discovery.find-servers-on-network/go-client-to-open62541-lds", func(t *testing.T) {
		var all []*ua.ServerOnNetwork
		var rec *ua.ServerOnNetwork
		awaitDiscovery(t, "the open62541 LDS to list the go-opcua server", func() bool {
			all = serversOnNetwork(adapter.endpoint)
			rec = find(all, isGo)
			return rec != nil
		})
		// The LDS lists itself as well.
		if find(all, func(r *ua.ServerOnNetwork) bool { return !isGo(r) && slices.Contains(r.ServerCapabilities, "LDS") }) == nil {
			t.Errorf("the open62541 LDS does not list itself: %d records", len(all))
		}

		ctx := shortTestCtx(t)
		c, err := opcua.NewClient(adapter.endpoint, opcua.InsecureNoSecurity(), opcua.AutoReconnect(false))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := c.Dial(ctx); err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer c.Close(ctx) //nolint:errcheck
		resp, err := c.FindServersOnNetworkWithFilter(ctx, rec.RecordID, 1, []string{"DA"})
		if err != nil {
			t.Fatalf("FindServersOnNetwork with filter: %v", err)
		}
		if len(resp.Servers) != 1 || resp.Servers[0].ServerName != goInstance {
			t.Errorf("FindServersOnNetwork(start=%d, max=1, caps=DA): %d records", rec.RecordID, len(resp.Servers))
		}
		if resp.LastCounterResetTime.IsZero() {
			t.Errorf("LastCounterResetTime is not set")
		}
		// A capability nobody announces matches nothing.
		resp, err = c.FindServersOnNetworkWithFilter(ctx, 0, 0, []string{"NOSUCHCAP"})
		if err != nil {
			t.Fatalf("FindServersOnNetwork with an unmatched filter: %v", err)
		}
		if len(resp.Servers) != 0 {
			t.Errorf("capability filter NOSUCHCAP matched %d records", len(resp.Servers))
		}
	})

	// go-opcua browses, open62541 announces.
	t.Run("coverage/discovery.multicast/go-lds-discovers-open62541", func(t *testing.T) {
		hostOut, err := exec.Command("docker", "inspect", "--format", "{{.Config.Hostname}}", adapterContainer).Output()
		if err != nil {
			t.Fatalf("docker inspect: %v", err)
		}
		adapterHost := strings.TrimSpace(string(hostOut))
		isAdapter := func(r *ua.ServerOnNetwork) bool {
			return r.ServerName != goInstance && strings.Contains(r.DiscoveryURL, adapterHost)
		}
		var rec *ua.ServerOnNetwork
		awaitDiscovery(t, "the go-opcua server to discover the open62541 LDS with mDNS", func() bool {
			rec = find(serversOnNetwork(goURL), isAdapter)
			return rec != nil
		})
		t.Logf("go-opcua: id=%d name=%q url=%s caps=%v", rec.RecordID, rec.ServerName, rec.DiscoveryURL, rec.ServerCapabilities)
		if !slices.Contains(rec.ServerCapabilities, "LDS") {
			t.Errorf("capabilities of the open62541 LDS: %v", rec.ServerCapabilities)
		}
		// The adapter announces "<mdns-name>-<hostname>".
		if !strings.HasPrefix(rec.ServerName, "opcua-interop-lds") {
			t.Errorf("server name of the open62541 LDS: %q", rec.ServerName)
		}
	})

	// The peer clients ask the go-opcua LDS, container to container.
	type onNetworkRecord struct {
		RecordID           uint32   `json:"recordId"`
		ServerName         string   `json:"serverName"`
		DiscoveryURL       string   `json:"discoveryUrl"`
		ServerCapabilities []string `json:"serverCapabilities"`
	}
	peerFindServersOnNetwork := func(t *testing.T, imageEnv, defaultImage string, args ...string) []onNetworkRecord {
		t.Helper()
		result := runAdapterClientOnNetwork(t, imageEnv, defaultImage, network, "find-servers-on-network",
			append([]string{"--endpoint", goNetURL}, args...)...)
		if !result.Success {
			t.Fatalf("find-servers-on-network failed: serviceResult=%s error=%s", result.ServiceResult, result.Error)
		}
		var recs []onNetworkRecord
		if err := json.Unmarshal(result.Results, &recs); err != nil {
			t.Fatalf("find-servers-on-network results: %v\nraw: %s", err, result.Results)
		}
		return recs
	}
	peers := []struct{ name, imageEnv, defaultImage string }{
		{"open62541", "OPEN62541_IMAGE", defaultOpen62541Image},
		{"milo", "MILO_IMAGE", defaultMiloImage},
		{"async-opcua", "ASYNC_OPCUA_IMAGE", defaultAsyncOpcuaImage},
		{"dotnet", dotnetEnv, defaultDotnetImage},
		{"node-opcua", nodeOpcuaEnv, defaultNodeOpcuaImage},
		{"asyncua", asyncuaEnv, defaultAsyncuaImage},
	}
	for _, p := range peers {
		t.Run("coverage/discovery.find-servers-on-network/"+p.name+"-client-to-go-lds", func(t *testing.T) {
			requireAdapterOp(t, p.imageEnv, p.defaultImage, "find-servers-on-network")
			recs := peerFindServersOnNetwork(t, p.imageEnv, p.defaultImage)
			// The go-opcua server lists itself with its capabilities.
			var self *onNetworkRecord
			for i := range recs {
				if recs[i].ServerName == goInstance {
					self = &recs[i]
				}
			}
			if self == nil {
				t.Fatalf("find-servers-on-network on the go-opcua LDS does not list %s: %+v", goInstance, recs)
			}
			if !strings.Contains(self.DiscoveryURL, goHost) || !slices.Contains(self.ServerCapabilities, "DA") || !slices.Contains(self.ServerCapabilities, "LDS") {
				t.Errorf("record of the go-opcua LDS: %+v", *self)
			}
			// The capability filter is applied by the go-opcua server.
			if recs := peerFindServersOnNetwork(t, p.imageEnv, p.defaultImage, "--capability", "NOSUCHCAP"); len(recs) != 0 {
				t.Errorf("capability filter NOSUCHCAP matched %+v", recs)
			}
			if recs := peerFindServersOnNetwork(t, p.imageEnv, p.defaultImage, "--capability", "DA", "--max-records", "1"); len(recs) != 1 {
				t.Errorf("capability filter DA with max-records 1 returned %+v", recs)
			}
		})
	}

	// RegisterServer2 with an MdnsDiscoveryConfiguration against the
	// go-opcua LDS with the multicast extension: the configuration is
	// accepted and the server appears in FindServersOnNetwork under the
	// requested mDNS server name.
	for _, p := range peers {
		t.Run("coverage/discovery.register-server2.mdns/"+p.name+"-client-to-go-lds", func(t *testing.T) {
			requireAdapterOp(t, p.imageEnv, p.defaultImage, "register-server")
			requireAdapterClientFeature(t, p.imageEnv, p.defaultImage, "register-server2")
			uri := "urn:otfabric:opcua-interop:registered-by-" + p.name
			url := "opc.tcp://registered-by-" + p.name + ":4999"
			mdnsName := "registered-by-" + p.name
			// The instance name is the mDNS server name and the host of the
			// discovery URL ("<name>-<host>", Part 12 Annex C).
			isRegistered := func(r *ua.ServerOnNetwork) bool { return strings.HasPrefix(r.ServerName, mdnsName) }

			result := runAdapterClientOnNetwork(t, p.imageEnv, p.defaultImage, network, "register-server",
				"--endpoint", goNetURL, "--server-uri", uri, "--server-name", "Registered by "+p.name,
				"--discovery-url", url, "--mdns-name", mdnsName, "--capability", "DA")
			item := parseRegisterServer(t, result)
			if !result.Success || item.Service != "RegisterServer2" || item.Fallback || !statusCodeIs(item.StatusCode, ua.StatusOK) {
				t.Fatalf("RegisterServer2 failed: %+v (serviceResult=%s error=%s)", item, result.ServiceResult, result.Error)
			}
			if len(item.ConfigurationResults) != 1 || !statusCodeIs(item.ConfigurationResults[0], ua.StatusOK) {
				t.Errorf("configuration results %+v, want [Good]", item.ConfigurationResults)
			}
			if !slices.Contains(foundServerURIs(goURL), uri) {
				t.Errorf("FindServers on the go-opcua LDS does not list %s", uri)
			}
			rec := find(serversOnNetwork(goURL), isRegistered)
			if rec == nil {
				t.Fatalf("FindServersOnNetwork on the go-opcua LDS does not list %q", mdnsName)
			}
			t.Logf("go-opcua LDS: id=%d name=%q url=%s caps=%v", rec.RecordID, rec.ServerName, rec.DiscoveryURL, rec.ServerCapabilities)
			if rec.DiscoveryURL != url || !slices.Contains(rec.ServerCapabilities, "DA") {
				t.Errorf("record of the registered server: url=%s caps=%v", rec.DiscoveryURL, rec.ServerCapabilities)
			}

			// Unregistering withdraws the record.
			result = runAdapterClientOnNetwork(t, p.imageEnv, p.defaultImage, network, "register-server",
				"--endpoint", goNetURL, "--server-uri", uri, "--discovery-url", url, "--mdns-name", mdnsName, "--online", "false")
			if item := parseRegisterServer(t, result); !result.Success {
				t.Fatalf("unregister failed: %+v (serviceResult=%s error=%s)", item, result.ServiceResult, result.Error)
			}
			if slices.Contains(foundServerURIs(goURL), uri) {
				t.Errorf("FindServers still lists %s after it unregistered", uri)
			}
			// The mDNS record goes as its goodbye takes effect, a second
			// after it (RFC 6762 §10.1): a copy of an earlier announcement
			// the LDS hears after the withdrawal lists it until then.
			deadline := time.Now().Add(5 * time.Second)
			for find(serversOnNetwork(goURL), isRegistered) != nil {
				if time.Now().After(deadline) {
					t.Errorf("FindServersOnNetwork still lists %q 5 s after it unregistered", mdnsName)
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
}
