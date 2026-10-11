// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// discoveryServer builds a server for the discovery unit tests: it is not
// started, the discovery manager is driven directly.
func discoveryServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	all := append([]Option{
		EndPoint("lds-host", 4840),
		EndPoint("lds-alias", 4840),
		ApplicationURI("urn:test:lds"),
		ServerName("Test LDS"),
	}, opts...)
	s, err := newServerNoNS(all...)
	require.NoError(t, err)
	return s
}

// fakeClock is a settable time source.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func useFakeClock(s *Server) *fakeClock {
	c := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	s.disc.now = c.Now
	return c
}

func regServer(uri string) *ua.RegisteredServer {
	return &ua.RegisteredServer{
		ServerURI:     uri,
		ProductURI:    "urn:test:product",
		ServerNames:   []*ua.LocalizedText{ua.NewLocalizedTextWithLocale("Press", "en"), ua.NewLocalizedTextWithLocale("Presse", "de")},
		ServerType:    ua.ApplicationTypeServer,
		DiscoveryURLs: []string{"opc.tcp://press7:4841/ua"},
		IsOnline:      true,
	}
}

func registeredURIs(s *Server) []string {
	var out []string
	for _, rs := range s.RegisteredServers() {
		out = append(out, rs.ServerURI)
	}
	return out
}

// testCertificate returns a self-signed certificate with the given
// application URIs.
func testCertificate(t *testing.T, uris ...string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "discovery test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// securedChannel returns a channel that looks like one opened with the
// given mode and peer certificate.
func securedChannel(mode ua.MessageSecurityMode, cert []byte) *uasc.SecureChannel {
	policy := ua.SecurityPolicyURIBasic256Sha256
	if mode == ua.MessageSecurityModeNone {
		policy = ua.SecurityPolicyURINone
	}
	return uasc.NewCryptoChannel(&uasc.Config{SecurityPolicyURI: policy, SecurityMode: mode, RemoteCertificate: cert})
}

func TestLDS_RegistrationValidation(t *testing.T) {
	s := discoveryServer(t, WithLocalDiscoveryServer(LDSAllowInsecureRegistration(), LDSMaxRegisteredServers(2)))
	d := s.disc

	mod := func(f func(*ua.RegisteredServer)) *ua.RegisteredServer {
		rs := regServer("urn:test:a")
		f(rs)
		return rs
	}
	manyURLs := make([]string, maxDiscoveryURLs+1)
	for i := range manyURLs {
		manyURLs[i] = fmt.Sprintf("opc.tcp://h%d:4840", i)
	}

	for _, tc := range []struct {
		name string
		rs   *ua.RegisteredServer
		want ua.StatusCode
	}{
		{"nil server", nil, ua.StatusBadInvalidArgument},
		{"no server uri", mod(func(r *ua.RegisteredServer) { r.ServerURI = "" }), ua.StatusBadServerURIInvalid},
		{"client application", mod(func(r *ua.RegisteredServer) { r.ServerType = ua.ApplicationTypeClient }), ua.StatusBadInvalidArgument},
		{"no names", mod(func(r *ua.RegisteredServer) { r.ServerNames = nil }), ua.StatusBadServerNameMissing},
		{"empty names", mod(func(r *ua.RegisteredServer) { r.ServerNames = []*ua.LocalizedText{nil, {}} }), ua.StatusBadServerNameMissing},
		{"no discovery urls", mod(func(r *ua.RegisteredServer) { r.DiscoveryURLs = nil }), ua.StatusBadDiscoveryURLMissing},
		{"empty discovery url", mod(func(r *ua.RegisteredServer) { r.DiscoveryURLs = []string{"opc.tcp://a:1", ""} }), ua.StatusBadDiscoveryURLMissing},
		{"too many discovery urls", mod(func(r *ua.RegisteredServer) { r.DiscoveryURLs = manyURLs }), ua.StatusBadTooManyOperations},
		{"semaphore file missing", mod(func(r *ua.RegisteredServer) { r.SemaphoreFilePath = filepath.Join(t.TempDir(), "nope") }), ua.StatusBadSemaphoreFileMissing},
		{"unregister unknown", mod(func(r *ua.RegisteredServer) { r.IsOnline = false }), ua.StatusBadNothingToDo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, results := d.register(nil, tc.rs, nil)
			require.Equal(t, tc.want, status)
			require.Empty(t, results)
			require.Empty(t, s.RegisteredServers())
		})
	}

	// A discovery server and a client-and-server are fine.
	for _, typ := range []ua.ApplicationType{ua.ApplicationTypeServer, ua.ApplicationTypeClientAndServer} {
		status, _ := d.register(nil, mod(func(r *ua.RegisteredServer) { r.ServerType = typ }), nil)
		require.Equal(t, ua.StatusOK, status)
	}
	status, _ := d.register(nil, mod(func(r *ua.RegisteredServer) {
		r.ServerURI, r.ServerType = "urn:test:lds2", ua.ApplicationTypeDiscoveryServer
	}), nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, []string{"urn:test:a", "urn:test:lds2"}, registeredURIs(s))

	// The table is full; a renewal still works, a new server does not.
	status, _ = d.register(nil, regServer("urn:test:c"), nil)
	require.Equal(t, ua.StatusBadResourceUnavailable, status)
	status, _ = d.register(nil, regServer("urn:test:a"), nil)
	require.Equal(t, ua.StatusOK, status)

	// Unregistering only needs the ServerUri.
	status, _ = d.register(nil, &ua.RegisteredServer{ServerURI: "urn:test:a"}, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, []string{"urn:test:lds2"}, registeredURIs(s))

	// What is returned is a copy.
	s.RegisteredServers()[0].DiscoveryURLs[0] = "changed"
	require.Equal(t, "opc.tcp://press7:4841/ua", s.RegisteredServers()[0].DiscoveryURLs[0])
}

func TestLDS_NotEnabled(t *testing.T) {
	s := discoveryServer(t)
	status, _ := s.disc.register(nil, regServer("urn:test:a"), nil)
	require.Equal(t, ua.StatusBadServiceUnsupported, status)
	require.Empty(t, s.RegisteredServers())
	require.Empty(t, s.ServersOnNetwork())
	s.disc.stop() // never started: nothing to do
}

func TestLDS_RegistrationSecurity(t *testing.T) {
	own := testCertificate(t, "urn:test:a", "urn:test:alias")
	other := testCertificate(t, "urn:test:b")
	noURI := testCertificate(t)

	t.Run("default", func(t *testing.T) {
		s := discoveryServer(t, WithLocalDiscoveryServer())
		for _, tc := range []struct {
			name string
			sc   *uasc.SecureChannel
			uri  string
			want ua.StatusCode
		}{
			{"no channel", nil, "urn:test:a", ua.StatusBadSecurityModeInsufficient},
			{"no security", securedChannel(ua.MessageSecurityModeNone, nil), "urn:test:a", ua.StatusBadSecurityModeInsufficient},
			{"invalid mode", securedChannel(ua.MessageSecurityModeInvalid, own), "urn:test:a", ua.StatusBadSecurityModeInsufficient},
			{"sign", securedChannel(ua.MessageSecurityModeSign, own), "urn:test:a", ua.StatusOK},
			{"sign and encrypt, second uri", securedChannel(ua.MessageSecurityModeSignAndEncrypt, own), "urn:test:alias", ua.StatusOK},
			{"foreign uri", securedChannel(ua.MessageSecurityModeSignAndEncrypt, other), "urn:test:a", ua.StatusBadServerURIInvalid},
			{"certificate without uri", securedChannel(ua.MessageSecurityModeSignAndEncrypt, noURI), "urn:test:a", ua.StatusBadServerURIInvalid},
			{"no certificate", securedChannel(ua.MessageSecurityModeSignAndEncrypt, nil), "urn:test:a", ua.StatusBadServerURIInvalid},
			{"garbage certificate", securedChannel(ua.MessageSecurityModeSignAndEncrypt, []byte("junk")), "urn:test:a", ua.StatusBadServerURIInvalid},
		} {
			status, _ := s.disc.register(tc.sc, regServer(tc.uri), nil)
			require.Equal(t, tc.want, status, tc.name)
		}
		// Nobody but the server itself can remove its registration.
		status, _ := s.disc.register(securedChannel(ua.MessageSecurityModeSign, other), &ua.RegisteredServer{ServerURI: "urn:test:a"}, nil)
		require.Equal(t, ua.StatusBadServerURIInvalid, status)
		require.Contains(t, registeredURIs(s), "urn:test:a")
	})

	t.Run("uri check skipped", func(t *testing.T) {
		s := discoveryServer(t, WithLocalDiscoveryServer(LDSSkipServerURICheck()))
		status, _ := s.disc.register(securedChannel(ua.MessageSecurityModeSign, other), regServer("urn:test:a"), nil)
		require.Equal(t, ua.StatusOK, status)
		status, _ = s.disc.register(nil, regServer("urn:test:a"), nil)
		require.Equal(t, ua.StatusBadSecurityModeInsufficient, status, "security is still required")
	})

	t.Run("insecure allowed", func(t *testing.T) {
		s := discoveryServer(t, WithLocalDiscoveryServer(LDSAllowInsecureRegistration()))
		status, _ := s.disc.register(securedChannel(ua.MessageSecurityModeNone, nil), regServer("urn:test:a"), nil)
		require.Equal(t, ua.StatusOK, status)
		// On a secured channel the certificate still decides.
		status, _ = s.disc.register(securedChannel(ua.MessageSecurityModeSign, other), regServer("urn:test:a"), nil)
		require.Equal(t, ua.StatusBadServerURIInvalid, status)
	})
}

func TestLDS_ExpiryRenewalAndSemaphore(t *testing.T) {
	var events []string
	s := discoveryServer(t, WithLocalDiscoveryServer(
		LDSAllowInsecureRegistration(),
		LDSRegistrationTimeout(10*time.Minute),
		LDSRegistrationCallback(func(rs *ua.RegisteredServer) {
			events = append(events, fmt.Sprintf("%s online=%v", rs.ServerURI, rs.IsOnline))
			rs.DiscoveryURLs[0] = "the callback gets a copy"
		}),
	))
	d := s.disc
	clock := useFakeClock(s)

	semaphore := filepath.Join(t.TempDir(), "online")
	require.NoError(t, os.WriteFile(semaphore, nil, 0o600))
	withFile := regServer("urn:test:semaphore")
	withFile.SemaphoreFilePath = semaphore

	for _, rs := range []*ua.RegisteredServer{regServer("urn:test:renewed"), regServer("urn:test:silent"), withFile} {
		status, _ := d.register(nil, rs, nil)
		require.Equal(t, ua.StatusOK, status)
	}
	require.Equal(t, "opc.tcp://press7:4841/ua", s.RegisteredServers()[0].DiscoveryURLs[0])

	// Just before the timeout nothing happens.
	clock.Advance(10 * time.Minute)
	d.cleanup(clock.Now())
	require.Len(t, s.RegisteredServers(), 3)

	// One server renews, then the timeout of the first registrations passes.
	status, _ := d.register(nil, regServer("urn:test:renewed"), nil)
	require.Equal(t, ua.StatusOK, status)
	clock.Advance(time.Second)
	d.cleanup(clock.Now())
	require.Equal(t, []string{"urn:test:renewed", "urn:test:semaphore"}, registeredURIs(s),
		"the silent server expired, the renewed one and the one with a semaphore file stay")

	// A registration with a semaphore file does not time out ...
	clock.Advance(24 * time.Hour)
	d.cleanup(clock.Now())
	require.Equal(t, []string{"urn:test:semaphore"}, registeredURIs(s))
	// ... it ends when the file is deleted.
	require.NoError(t, os.Remove(semaphore))
	d.cleanup(clock.Now())
	require.Empty(t, s.RegisteredServers())

	require.Equal(t, []string{
		"urn:test:renewed online=true", "urn:test:silent online=true", "urn:test:semaphore online=true",
		"urn:test:renewed online=true",
	}, events)
}

func TestLDS_TimeoutConfiguration(t *testing.T) {
	var c ldsConfig
	require.Equal(t, DefaultRegistrationTimeout, c.registrationTimeout())
	require.Equal(t, time.Hour, DefaultRegistrationTimeout, "the default of open62541")
	LDSRegistrationTimeout(5 * time.Second)(&c)
	require.Equal(t, 5*time.Second, c.registrationTimeout())
	LDSRegistrationTimeout(0)(&c)
	require.Zero(t, c.registrationTimeout())

	// Without a timeout a registration stays until it is removed.
	s := discoveryServer(t, WithLocalDiscoveryServer(LDSAllowInsecureRegistration(), LDSRegistrationTimeout(-1)))
	clock := useFakeClock(s)
	status, _ := s.disc.register(nil, regServer("urn:test:a"), nil)
	require.Equal(t, ua.StatusOK, status)
	clock.Advance(1000 * time.Hour)
	s.disc.cleanup(clock.Now())
	require.Len(t, s.RegisteredServers(), 1)
}

func TestLDS_CleanupLoop(t *testing.T) {
	s := discoveryServer(t, WithLocalDiscoveryServer(LDSAllowInsecureRegistration(), LDSRegistrationTimeout(20*time.Millisecond)))
	status, _ := s.disc.register(nil, regServer("urn:test:a"), nil)
	require.Equal(t, ua.StatusOK, status)
	require.NoError(t, s.disc.start(context.Background()))
	require.Eventually(t, func() bool { return len(s.RegisteredServers()) == 0 }, 30*time.Second, 5*time.Millisecond)
	s.disc.stop()
	s.disc.stop()
}

func TestLDS_DiscoveryConfigurations(t *testing.T) {
	mdnsCfg := func(name string, caps ...string) *ua.ExtensionObject {
		return ua.NewExtensionObject(&ua.MdnsDiscoveryConfiguration{MdnsServerName: name, ServerCapabilities: caps})
	}
	configs := []*ua.ExtensionObject{
		ua.NewExtensionObject(&ua.DiscoveryConfiguration{}),
		mdnsCfg("First", "DA"),
		nil,
		mdnsCfg("Second", "HD"),
		ua.NewExtensionObject(&ua.Argument{}),
	}

	t.Run("without the multicast extension", func(t *testing.T) {
		s := discoveryServer(t, WithLocalDiscoveryServer(LDSAllowInsecureRegistration()))
		status, results := s.disc.register(nil, regServer("urn:test:a"), configs)
		require.Equal(t, ua.StatusOK, status, "the server is registered nevertheless")
		require.Equal(t, []ua.StatusCode{
			ua.StatusBadNotSupported, ua.StatusBadNotSupported, ua.StatusBadNotSupported,
			ua.StatusBadNotSupported, ua.StatusBadNotSupported,
		}, results)
		require.Len(t, s.RegisteredServers(), 1)

		// The results are reported with a failed registration too.
		bad := regServer("urn:test:b")
		bad.DiscoveryURLs = nil
		status, results = s.disc.register(nil, bad, configs[:2])
		require.Equal(t, ua.StatusBadDiscoveryURLMissing, status)
		require.Len(t, results, 2)
	})

	t.Run("with the multicast extension", func(t *testing.T) {
		s := discoveryServer(t,
			WithLocalDiscoveryServer(LDSAllowInsecureRegistration()),
			WithMulticastDiscovery(MulticastHostname("lds-host")),
		)
		status, results := s.disc.register(nil, regServer("urn:test:a"), configs)
		require.Equal(t, ua.StatusOK, status)
		require.Equal(t, []ua.StatusCode{
			ua.StatusBadNotSupported, ua.StatusOK, ua.StatusBadNotSupported,
			ua.StatusBadNotSupported, ua.StatusBadNotSupported,
		}, results, "the first mDNS configuration is used")

		// The mDNS server name stands in for a missing server name.
		anonymous := regServer("urn:test:b")
		anonymous.ServerNames = nil
		status, _ = s.disc.register(nil, anonymous, []*ua.ExtensionObject{mdnsCfg("OnlyMdns")})
		require.Equal(t, ua.StatusOK, status)
		status, _ = s.disc.register(nil, anonymous, []*ua.ExtensionObject{mdnsCfg("")})
		require.Equal(t, ua.StatusBadServerNameMissing, status)
	})
}

func TestLDS_FindServers(t *testing.T) {
	s := discoveryServer(t, WithLocalDiscoveryServer(
		LDSAllowInsecureRegistration(), LDSApplicationType(ua.ApplicationTypeDiscoveryServer)))
	d := s.disc
	second := regServer("urn:test:b")
	second.ServerNames = nil
	second.GatewayServerURI = "urn:test:gateway"
	second.ServerType = ua.ApplicationTypeClientAndServer
	for _, rs := range []*ua.RegisteredServer{regServer("urn:test:a"), second} {
		// second has no server name: register it through an mDNS name
		status, _ := d.register(nil, rs, nil)
		if rs == second {
			require.Equal(t, ua.StatusBadServerNameMissing, status)
			rs.ServerNames = []*ua.LocalizedText{}
			d.mu.Lock()
			d.servers[rs.ServerURI] = &registration{server: rs, lastSeen: d.now()}
			d.order = append(d.order, rs.ServerURI)
			d.mu.Unlock()
			continue
		}
		require.Equal(t, ua.StatusOK, status)
	}

	uris := func(apps []*ua.ApplicationDescription) []string {
		var out []string
		for _, a := range apps {
			out = append(out, a.ApplicationURI)
		}
		return out
	}

	all := d.findServers(&ua.FindServersRequest{})
	require.Equal(t, []string{"urn:test:lds", "urn:test:a", "urn:test:b"}, uris(all))
	self := all[0]
	require.Equal(t, ua.ApplicationTypeDiscoveryServer, self.ApplicationType)
	require.Equal(t, "Test LDS", self.ApplicationName.Text)
	require.Equal(t, []string{"opc.tcp://lds-host:4840", "opc.tcp://lds-alias:4840"}, self.DiscoveryURLs)
	require.Equal(t, "Press", all[1].ApplicationName.Text)
	require.Equal(t, "urn:test:product", all[1].ProductURI)
	require.Equal(t, ua.ApplicationTypeServer, all[1].ApplicationType)
	require.Equal(t, []string{"opc.tcp://press7:4841/ua"}, all[1].DiscoveryURLs)
	require.Empty(t, all[2].ApplicationName.Text, "a server without names has an empty name")
	require.Equal(t, "urn:test:gateway", all[2].GatewayServerURI)
	require.Equal(t, ua.ApplicationTypeClientAndServer, all[2].ApplicationType)

	// ServerUris filter
	require.Equal(t, []string{"urn:test:a"}, uris(d.findServers(&ua.FindServersRequest{ServerURIs: []string{"urn:test:a", "urn:x"}})))
	require.Equal(t, []string{"urn:test:lds"}, uris(d.findServers(&ua.FindServersRequest{ServerURIs: []string{"urn:test:lds"}})))
	require.Empty(t, d.findServers(&ua.FindServersRequest{ServerURIs: []string{"urn:x"}}))

	// LocaleIds: the first requested locale the server has a name in
	name := func(locales ...string) *ua.LocalizedText {
		return d.findServers(&ua.FindServersRequest{LocaleIDs: locales, ServerURIs: []string{"urn:test:a"}})[0].ApplicationName
	}
	require.Equal(t, "Presse", name("de").Text)
	require.Equal(t, "Presse", name("fr", "DE", "en").Text)
	require.Equal(t, "Press", name("en", "de").Text)
	require.Equal(t, "Press", name("fr").Text)

	// EndpointUrl: the discovery URLs of the server on the host the client used
	own := func(endpointURL string) []string {
		return d.findServers(&ua.FindServersRequest{EndpointURL: endpointURL})[0].DiscoveryURLs
	}
	require.Equal(t, []string{"opc.tcp://lds-alias:4840"}, own("opc.tcp://LDS-ALIAS:4840/some/path"))
	require.Equal(t, []string{"opc.tcp://lds-host:4840"}, own("opc.tcp://lds-host:9999"))
	require.Len(t, own("opc.tcp://unknown-host:4840"), 2, "an unknown host gets the default")
	require.Len(t, own("not a url"), 2)
	require.Len(t, own("http://lds-host:4840"), 2)
	// ... while the URLs of registered servers are theirs
	reg := d.findServers(&ua.FindServersRequest{EndpointURL: "opc.tcp://lds-alias:4840"})[1]
	require.Equal(t, []string{"opc.tcp://press7:4841/ua"}, reg.DiscoveryURLs)
}

func TestLDS_ServiceHandlers(t *testing.T) {
	s := discoveryServer(t, WithLocalDiscoveryServer(LDSAllowInsecureRegistration()))
	svc := &DiscoveryService{srv: s}
	ctx := context.Background()

	resp, err := svc.RegisterServer(ctx, nil, &ua.RegisterServerRequest{RequestHeader: reqHeader(), Server: regServer("urn:test:a")}, 1)
	require.NoError(t, err)
	require.IsType(t, &ua.RegisterServerResponse{}, resp)
	require.Equal(t, ua.StatusOK, resp.Header().ServiceResult)

	resp, err = svc.RegisterServer2(ctx, nil, &ua.RegisterServer2Request{
		RequestHeader:          reqHeader(),
		Server:                 regServer("urn:test:b"),
		DiscoveryConfiguration: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.MdnsDiscoveryConfiguration{MdnsServerName: "B"})},
	}, 1)
	require.NoError(t, err)
	r2 := resp.(*ua.RegisterServer2Response)
	require.Equal(t, ua.StatusOK, r2.ResponseHeader.ServiceResult)
	require.Equal(t, []ua.StatusCode{ua.StatusBadNotSupported}, r2.ConfigurationResults)

	resp, err = svc.RegisterServer(ctx, nil, &ua.RegisterServerRequest{RequestHeader: reqHeader()}, 1)
	require.NoError(t, err)
	require.IsType(t, &ua.ServiceFault{}, resp)
	require.Equal(t, ua.StatusBadInvalidArgument, resp.Header().ServiceResult)
	require.EqualValues(t, 1, resp.Header().RequestHandle)

	resp, err = svc.RegisterServer2(ctx, nil, &ua.RegisterServer2Request{RequestHeader: reqHeader(), Server: &ua.RegisteredServer{}}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadServerURIInvalid, resp.Header().ServiceResult)

	fs, err := svc.FindServers(ctx, nil, &ua.FindServersRequest{RequestHeader: reqHeader()}, 1)
	require.NoError(t, err)
	require.Len(t, fs.(*ua.FindServersResponse).Servers, 3)

	// wrong request types
	_, err = svc.RegisterServer(ctx, nil, &ua.FindServersRequest{}, 1)
	require.ErrorIs(t, err, ua.StatusBadRequestTypeInvalid)
	_, err = svc.RegisterServer2(ctx, nil, &ua.FindServersRequest{}, 1)
	require.ErrorIs(t, err, ua.StatusBadRequestTypeInvalid)
	_, err = svc.FindServersOnNetwork(ctx, nil, &ua.FindServersRequest{}, 1)
	require.ErrorIs(t, err, ua.StatusBadRequestTypeInvalid)
}

// --- multicast extension --------------------------------------------------------

// multicastServer returns a server whose mDNS node runs on link, with the
// multicast part of the discovery manager started.
func multicastServer(t *testing.T, link *mdns.MemNetwork, opts ...Option) *Server {
	t.Helper()
	all := append([]Option{
		WithLocalDiscoveryServer(LDSAllowInsecureRegistration()),
		func(c *serverConfig) error {
			c.multicast.conns = func() ([]mdns.PacketConn, error) { return []mdns.PacketConn{link.Conn()}, nil }
			return nil
		},
	}, opts...)
	s := discoveryServer(t, all...)
	require.NoError(t, s.disc.start(context.Background()))
	t.Cleanup(s.disc.stop)
	return s
}

// browseLink attaches an mDNS browser to link and returns a function that
// reports the instances it currently knows.
func browseLink(t *testing.T, link *mdns.MemNetwork) func() map[string]mdns.Instance {
	t.Helper()
	node, err := mdns.New(mdns.Config{Conns: []mdns.PacketConn{link.Conn()}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	var mu sync.Mutex
	known := map[string]mdns.Instance{}
	require.NoError(t, node.Browse(opcuaServiceType, func(e mdns.Event) {
		mu.Lock()
		defer mu.Unlock()
		if e.Removed {
			delete(known, e.Instance.Name)
			return
		}
		known[e.Instance.Name] = e.Instance
	}))
	return func() map[string]mdns.Instance {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string]mdns.Instance, len(known))
		for k, v := range known {
			out[k] = v
		}
		return out
	}
}

func onNetworkNames(s *Server) []string {
	var out []string
	for _, r := range s.ServersOnNetwork() {
		out = append(out, r.ServerName)
	}
	return out
}

const wait = 30 * time.Second

func TestMulticast_AnnouncesItselfAndRegisteredServers(t *testing.T) {
	link := mdns.NewMemNetwork()
	seen := browseLink(t, link)
	s := multicastServer(t, link, WithMulticastDiscovery(MulticastHostname("lds-host.example.com"), MulticastServerName("Plant LDS")))

	// The server itself: record 0, announced with its own host name.
	require.Equal(t, []string{"Plant LDS-lds-host"}, onNetworkNames(s))
	self := s.ServersOnNetwork()[0]
	require.Zero(t, self.RecordID)
	require.Equal(t, "opc.tcp://lds-host:4840", self.DiscoveryURL)
	require.Equal(t, []string{"LDS"}, self.ServerCapabilities)
	require.Eventually(t, func() bool { _, ok := seen()["Plant LDS-lds-host"]; return ok }, wait, 5*time.Millisecond)
	inst := seen()["Plant LDS-lds-host"]
	require.Equal(t, "lds-host.local.", inst.Host)
	require.EqualValues(t, 4840, inst.Port)
	require.Equal(t, []string{"path=/", "caps=LDS"}, inst.Text)

	// A registered server with an mDNS configuration: one instance per
	// discovery URL that has a host name.
	rs := regServer("urn:test:press")
	rs.DiscoveryURLs = []string{
		"opc.tcp://press7:4841/ua/server", // a plain host name is on the local link
		"opc.tcp://192.0.2.7:4841",        // an address has no mDNS mapping
		"opc.tcp://press7.factory.example:4842",
		"opc.tcp://localhost:4843", // the discovery server's own machine
		"http://press7:80",         // not an opc.tcp URL
		"opc.tcp://press7:4841/ua/server",
	}
	mdnsCfg := []*ua.ExtensionObject{ua.NewExtensionObject(&ua.MdnsDiscoveryConfiguration{
		MdnsServerName: "Press 7", ServerCapabilities: []string{"DA", "HD"},
	})}
	status, results := s.disc.register(nil, rs, mdnsCfg)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, results)

	want := []string{"Plant LDS-lds-host", "Press 7-press7", "Press 7-press7.factory.example", "Press 7-localhost"}
	require.Equal(t, want, onNetworkNames(s))
	require.Eventually(t, func() bool { return len(seen()) == 4 }, wait, 5*time.Millisecond)

	rec := s.ServersOnNetwork()[1]
	require.EqualValues(t, 1, rec.RecordID)
	require.Equal(t, "opc.tcp://press7:4841/ua/server", rec.DiscoveryURL, "the URL as registered")
	require.Equal(t, []string{"DA", "HD"}, rec.ServerCapabilities)

	inst = seen()["Press 7-press7"]
	require.Equal(t, "press7.local.", inst.Host)
	require.EqualValues(t, 4841, inst.Port)
	require.Equal(t, []string{"path=/ua/server", "caps=DA,HD"}, inst.Text)
	require.Equal(t, "press7.factory.example.", seen()["Press 7-press7.factory.example"].Host)
	require.Equal(t, "lds-host.local.", seen()["Press 7-localhost"].Host)

	// A renewal with the same data keeps the records; one with fewer URLs
	// and other capabilities withdraws and updates.
	status, _ = s.disc.register(nil, rs, mdnsCfg)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, want, onNetworkNames(s))
	require.EqualValues(t, 1, s.ServersOnNetwork()[1].RecordID)

	rs.DiscoveryURLs = rs.DiscoveryURLs[:1]
	status, _ = s.disc.register(nil, rs, []*ua.ExtensionObject{ua.NewExtensionObject(&ua.MdnsDiscoveryConfiguration{
		MdnsServerName: "Press 7", ServerCapabilities: []string{"DA"},
	})})
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, []string{"Plant LDS-lds-host", "Press 7-press7"}, onNetworkNames(s))
	require.Equal(t, []string{"DA"}, s.ServersOnNetwork()[1].ServerCapabilities)
	require.Eventually(t, func() bool {
		k := seen()
		return len(k) == 2 && len(k["Press 7-press7"].Text) == 2 && k["Press 7-press7"].Text[1] == "caps=DA"
	}, wait, 5*time.Millisecond)

	// A server registered without an mDNS configuration is announced under
	// its first server name with the capability "NA".
	legacy := regServer("urn:test:oven")
	legacy.ServerNames = []*ua.LocalizedText{ua.NewLocalizedText("Oven")}
	legacy.DiscoveryURLs = []string{"opc.tcp://oven1:4840"}
	status, _ = s.disc.register(nil, legacy, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Eventually(t, func() bool { _, ok := seen()["Oven-oven1"]; return ok }, wait, 5*time.Millisecond)
	require.Equal(t, []string{"path=/", "caps=NA"}, seen()["Oven-oven1"].Text)
	require.EqualValues(t, 4, s.ServersOnNetwork()[2].RecordID, "record ids are not reused")

	// Another server cannot take an instance name that is in use.
	clash := regServer("urn:test:impostor")
	clash.ServerNames = []*ua.LocalizedText{ua.NewLocalizedText("Oven")}
	clash.DiscoveryURLs = []string{"opc.tcp://oven1:9999"}
	status, _ = s.disc.register(nil, clash, nil)
	require.Equal(t, ua.StatusOK, status, "it is registered, but not announced")
	require.Equal(t, "opc.tcp://oven1:4840", s.ServersOnNetwork()[2].DiscoveryURL)
	status, _ = s.disc.register(nil, &ua.RegisteredServer{ServerURI: "urn:test:impostor"}, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Len(t, s.ServersOnNetwork(), 3)

	// Unregistering and expiry withdraw the announcements.
	status, _ = s.disc.register(nil, &ua.RegisteredServer{ServerURI: "urn:test:press"}, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, []string{"Plant LDS-lds-host", "Oven-oven1"}, onNetworkNames(s))
	s.disc.cleanup(time.Now().Add(1000 * time.Hour))
	require.Equal(t, []string{"Plant LDS-lds-host"}, onNetworkNames(s))
	require.Eventually(t, func() bool { return len(seen()) == 1 }, wait, 5*time.Millisecond)

	// Stopping says goodbye for the server itself.
	s.disc.stop()
	require.Eventually(t, func() bool { return len(seen()) == 0 }, wait, 5*time.Millisecond)
}

func TestMulticast_DiscoversServersOnNetwork(t *testing.T) {
	link := mdns.NewMemNetwork()
	s := multicastServer(t, link, WithMulticastDiscovery(MulticastHostname("lds-host"), MulticastMaxServersOnNetwork(16)))

	peer, err := mdns.New(mdns.Config{Conns: []mdns.PacketConn{link.Conn()}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })
	announce := func(name, host string, port uint16, text ...string) {
		require.NoError(t, peer.Register(mdns.Service{Instance: name, Type: opcuaServiceType, Host: host, Port: port, Text: text}))
	}
	has := func(name string) func() bool {
		return func() bool {
			for _, n := range onNetworkNames(s) {
				if n == name {
					return true
				}
			}
			return false
		}
	}

	announce("Robot-cell3", "cell3.local.", 4840, "path=/robot", "caps=DA,AC")
	require.Eventually(t, has("Robot-cell3"), wait, 5*time.Millisecond)
	rec := s.ServersOnNetwork()[1]
	require.EqualValues(t, 1, rec.RecordID)
	require.Equal(t, "opc.tcp://cell3.local:4840/robot", rec.DiscoveryURL)
	require.Equal(t, []string{"DA", "AC"}, rec.ServerCapabilities)

	// A changed announcement updates the record and keeps its id.
	announce("Robot-cell3", "cell3.local.", 4841, "PATH=robot2", "CAPS= da ,,hd ", "other=1", "novalue")
	require.Eventually(t, func() bool {
		r := s.ServersOnNetwork()
		return len(r) == 2 && r[1].DiscoveryURL == "opc.tcp://cell3.local:4841/robot2"
	}, wait, 5*time.Millisecond)
	rec = s.ServersOnNetwork()[1]
	require.EqualValues(t, 1, rec.RecordID)
	require.Equal(t, []string{"da", "hd"}, rec.ServerCapabilities)

	// Announcements that are not usable OPC UA servers are ignored; the
	// next good one proves that they were processed.
	announce("Bad host", `bad\032host.local.`, 4840, "path=/")
	announce("Plain", "plain.local.", 4842, "path=/")
	require.Eventually(t, has("Plain"), wait, 5*time.Millisecond)
	require.NotContains(t, onNetworkNames(s), "Bad host")
	require.Equal(t, "opc.tcp://plain.local:4842", s.ServersOnNetwork()[2].DiscoveryURL, `"/" stands for no path`)
	require.Empty(t, s.ServersOnNetwork()[2].ServerCapabilities)

	// A server that says goodbye leaves the table.
	require.True(t, peer.Unregister("Plain", opcuaServiceType))
	require.Eventually(t, func() bool { return !has("Plain")() }, wait, 5*time.Millisecond)
	require.Len(t, s.ServersOnNetwork(), 2)

	// A registered server may use the name of a discovered one: the
	// discovery server does not announce it a second time.
	rs := regServer("urn:test:robot")
	rs.ServerNames = []*ua.LocalizedText{ua.NewLocalizedText("Robot")}
	rs.DiscoveryURLs = []string{"opc.tcp://cell3:4841/robot2"}
	status, _ := s.disc.register(nil, rs, nil)
	require.Equal(t, ua.StatusOK, status)
	require.Equal(t, "opc.tcp://cell3.local:4841/robot2", s.ServersOnNetwork()[1].DiscoveryURL, "still the discovered record")
	status, _ = s.disc.register(nil, &ua.RegisteredServer{ServerURI: "urn:test:robot"}, nil)
	require.Equal(t, ua.StatusOK, status)
	require.True(t, has("Robot-cell3")())

	// The returned records are copies.
	s.ServersOnNetwork()[1].ServerCapabilities[0] = "changed"
	require.Equal(t, "da", s.ServersOnNetwork()[1].ServerCapabilities[0])
}

func TestMulticast_FindServersOnNetwork(t *testing.T) {
	s := discoveryServer(t, WithMulticastDiscovery())
	d := s.disc
	clock := useFakeClock(s)
	d.resetAt = clock.Now()
	d.mu.Lock()
	d.putRecordLocked("Self", selfOwner, "opc.tcp://self:4840", []string{"LDS"})
	d.putRecordLocked("A", "", "opc.tcp://a:4840", []string{"DA", "HD"})
	d.putRecordLocked("B", "", "opc.tcp://b:4840", []string{"DA"})
	d.putRecordLocked("C", "", "opc.tcp://c:4840", []string{"da", "AC", "hd"})
	d.mu.Unlock()

	find := func(start, limit uint32, filter ...string) []string {
		_, recs := d.findServersOnNetwork(&ua.FindServersOnNetworkRequest{
			StartingRecordID: start, MaxRecordsToReturn: limit, ServerCapabilityFilter: filter,
		})
		var out []string
		for _, r := range recs {
			out = append(out, fmt.Sprintf("%d:%s", r.RecordID, r.ServerName))
		}
		return out
	}
	require.Equal(t, []string{"0:Self", "1:A", "2:B", "3:C"}, find(0, 0))
	require.Equal(t, []string{"0:Self", "1:A"}, find(0, 2))
	require.Equal(t, []string{"2:B", "3:C"}, find(2, 2))
	require.Equal(t, []string{"3:C"}, find(3, 0))
	require.Empty(t, find(4, 0))
	require.Equal(t, []string{"1:A", "2:B", "3:C"}, find(0, 0, "DA"))
	require.Equal(t, []string{"1:A", "3:C"}, find(0, 0, "HD", "da"))
	require.Equal(t, []string{"1:A"}, find(0, 1, "HD"))
	require.Equal(t, []string{"3:C"}, find(2, 5, "HD"))
	require.Empty(t, find(0, 0, "LDS", "DA"))
	require.Equal(t, []string{"0:Self"}, find(0, 0, "lds"))

	// through the service handler
	svc := &DiscoveryService{srv: s}
	resp, err := svc.FindServersOnNetwork(context.Background(), nil, &ua.FindServersOnNetworkRequest{
		RequestHeader: reqHeader(), ServerCapabilityFilter: []string{"AC"},
	}, 1)
	require.NoError(t, err)
	on := resp.(*ua.FindServersOnNetworkResponse)
	require.Equal(t, ua.StatusOK, on.ResponseHeader.ServiceResult)
	require.Len(t, on.Servers, 1)
	require.Equal(t, clock.Now(), on.LastCounterResetTime)

	// Removed records leave gaps; a discovered server cannot take over a
	// record the discovery server vouches for.
	d.mu.Lock()
	d.dropRecordLocked("b", "")
	d.dropRecordLocked("Self", "") // wrong owner: stays
	d.putRecordLocked("SELF", "", "opc.tcp://impostor:1", nil)
	d.mu.Unlock()
	require.Equal(t, []string{"0:Self", "1:A", "3:C"}, find(0, 0))
	require.Equal(t, "opc.tcp://self:4840", s.ServersOnNetwork()[0].DiscoveryURL)

	// When the record id counter wraps around, the reset time tells clients
	// to start over.
	resetBefore, _ := d.findServersOnNetwork(&ua.FindServersOnNetworkRequest{})
	clock.Advance(time.Hour)
	d.mu.Lock()
	d.nextID = math.MaxUint32
	d.putRecordLocked("Last", "", "opc.tcp://last:4840", nil)
	d.putRecordLocked("First again", "", "opc.tcp://first:4840", nil)
	d.mu.Unlock()
	resetAfter, _ := d.findServersOnNetwork(&ua.FindServersOnNetworkRequest{})
	require.True(t, resetAfter.After(resetBefore))
	require.Equal(t, clock.Now(), resetAfter)
	require.EqualValues(t, 0, s.ServersOnNetwork()[4].RecordID)
}

func TestMulticast_StartErrors(t *testing.T) {
	failing := func(c *serverConfig) error {
		c.multicast.conns = func() ([]mdns.PacketConn, error) { return nil, fmt.Errorf("no network") }
		return nil
	}
	s := discoveryServer(t, WithMulticastDiscovery(MulticastHostname("h")), failing)
	require.ErrorContains(t, s.disc.start(context.Background()), "no network")

	none := func(c *serverConfig) error {
		c.multicast.conns = func() ([]mdns.PacketConn, error) { return nil, nil }
		return nil
	}
	s = discoveryServer(t, WithMulticastDiscovery(MulticastHostname("h")), none)
	require.ErrorContains(t, s.disc.start(context.Background()), "no transport")

	s = discoveryServer(t, WithMulticastDiscovery(MulticastHostname("not a host name")))
	require.ErrorContains(t, s.disc.start(context.Background()), "host name")

	s = discoveryServer(t, WithMulticastDiscovery(MulticastHostname("h"), MulticastInterfaces("no-such-interface0")))
	require.ErrorContains(t, s.disc.start(context.Background()), "no-such-interface0")

	// An instance name that cannot be announced (no port: the server is not
	// listening and its endpoint has port 0).
	link := mdns.NewMemNetwork()
	noPort, err := newServerNoNS(EndPoint("h", 0), ApplicationURI("urn:x"), WithMulticastDiscovery(MulticastHostname("h")),
		func(c *serverConfig) error {
			c.multicast.conns = func() ([]mdns.PacketConn, error) { return []mdns.PacketConn{link.Conn()}, nil }
			return nil
		})
	require.NoError(t, err)
	require.ErrorContains(t, noPort.disc.start(context.Background()), "announce")

	// Start reports the failure and does not leave the listener open.
	srv, err := New(EndPoint("localhost", 0), EnableSecurity("None", ua.MessageSecurityModeNone),
		WithMulticastDiscovery(MulticastHostname("h")), failing)
	require.NoError(t, err)
	require.ErrorContains(t, srv.Start(context.Background()), "no network")
	require.NoError(t, srv.Close())
}

func TestMulticast_Helpers(t *testing.T) {
	// instance names: "<name>-<host>", cut to a DNS label the way open62541 does
	require.Equal(t, "Press-host", instanceName("Press", "host"))
	require.Equal(t, "Press", instanceName("Press", ""))
	long := strings.Repeat("n", 40)
	require.Equal(t, long+"-"+strings.Repeat("h", 22), instanceName(long, strings.Repeat("h", 40)))
	require.Len(t, instanceName(strings.Repeat("n", 80), "host"), 63)
	require.Equal(t, strings.Repeat("n", 62), instanceName(strings.Repeat("n", 62), "host"), "no room for a host part")
	require.Equal(t, strings.Repeat("é", 31), instanceName(strings.Repeat("é", 40), "h"), "never cut inside a character")

	require.Equal(t, []string{"path=/", "caps=NA"}, txtRecord("", nil))
	require.Equal(t, []string{"path=/ua", "caps=DA,HD"}, txtRecord("ua", []string{"DA", "HD"}))
	many := make([]string, 100)
	for i := range many {
		many[i] = "CAP"
	}
	for _, s := range txtRecord("/"+strings.Repeat("p", 300), many) {
		require.LessOrEqual(t, len(s), 255)
	}

	require.Equal(t, "press7", hostLabel(" press7.factory.example "))
	require.Equal(t, "press7", hostLabel("press7.local"))
	require.Empty(t, hostLabel(""))
	require.Empty(t, hostLabel("bad host"))
	require.Empty(t, hostLabel(strings.Repeat("h", 64)))

	for host, want := range map[string]string{
		"press7":                 "press7.local.",
		"LocalHost":              "lds.local.",
		"press7.local":           "press7.local.",
		"press7.factory.example": "press7.factory.example.",
		"press7.example.":        "press7.example.",
		"192.0.2.7":              "",
		"::1":                    "",
		"":                       "",
		"bad host":               "",
	} {
		got, _ := srvTarget(host, "lds")
		require.Equal(t, want, got, host)
	}
	_, local := srvTarget("LDS", "lds")
	require.True(t, local)
	_, local = srvTarget("lds.local", "lds")
	require.True(t, local)
	_, local = srvTarget("other", "lds")
	require.False(t, local)

	for raw, want := range map[string]string{
		"opc.tcp://host:4841/a/b":  "host|4841|/a/b",
		"OPC.TCP://host":           "host|4840|",
		"opc.tcp://[fe80::1]:4842": "fe80::1|4842|",
		"opc.tcp://host:0":         "|0|",
		"opc.tcp://host:99999":     "|0|",
		"opc.tcp://host:port":      "|0|",
		"opc.tcp://":               "|0|",
		"http://host:80":           "|0|",
		"%zz":                      "|0|",
	} {
		host, port, path := splitDiscoveryURL(raw)
		require.Equal(t, want, fmt.Sprintf("%s|%d|%s", host, port, path), raw)
	}

	// What the network announces is checked before it is handed to clients.
	url, caps, ok := discoveredServer(mdns.Instance{Name: "A", Host: "a.local.", Port: 4840,
		Text: []string{"path=/x", "caps=DA", "caps\x00=evil", "path=\x01bad", "caps=\xff"}})
	require.True(t, ok)
	require.Equal(t, "opc.tcp://a.local:4840/x", url)
	require.Equal(t, []string{"DA"}, caps)
	for _, bad := range []mdns.Instance{
		{Name: "A", Host: "a.local.", Port: 0},
		{Name: "A", Host: "", Port: 1},
		{Name: "A", Host: `a\.b.local.`, Port: 1},
		{Name: "", Host: "a.local.", Port: 1},
		{Name: "\xff", Host: "a.local.", Port: 1},
	} {
		_, _, ok := discoveredServer(bad)
		require.False(t, ok, "%+v", bad)
	}

	require.True(t, hasCapabilities([]string{"DA"}, nil))
	require.False(t, hasCapabilities(nil, []string{"DA"}))
}
