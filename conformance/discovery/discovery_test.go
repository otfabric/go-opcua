// SPDX-License-Identifier: MIT

package discovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/conformkit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// Discovery beyond GetEndpoints: Part 4 §5.4 (FindServers,
// FindServersOnNetwork, RegisterServer, RegisterServer2) and Part 12 (Local
// Discovery Server, multicast extension), Go server against Go server and Go
// client.

// discoveryOpts are the client options for talking to a discovery endpoint.
func discoveryOpts() []opcua.Option {
	return []opcua.Option{opcua.DialTimeout(30 * time.Second), opcua.RequestTimeout(30 * time.Second)}
}

// knownServerURIs returns the application URIs FindServers reports at url.
func knownServerURIs(t *testing.T, url string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	servers, err := opcua.FindServers(ctx, url, discoveryOpts()...)
	require.NoError(t, err)
	uris := make([]string, 0, len(servers))
	for _, s := range servers {
		uris = append(uris, s.ApplicationURI)
	}
	return uris
}

// dialDiscovery opens a SecureChannel (no session) to url.
func dialDiscovery(t *testing.T, url string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	all := append(discoveryOpts(), opcua.AutoReconnect(false))
	c, err := opcua.NewClient(url, append(all, opts...)...)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	require.NoError(t, c.Dial(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func sampleServer(uri string, online bool) *ua.RegisteredServer {
	return &ua.RegisteredServer{
		ServerURI:     uri,
		ProductURI:    "urn:otfabric:conformance:product",
		ServerNames:   []*ua.LocalizedText{ua.NewLocalizedTextWithLocale("Sample", "en"), ua.NewLocalizedTextWithLocale("Beispiel", "de")},
		ServerType:    ua.ApplicationTypeServer,
		DiscoveryURLs: []string{"opc.tcp://sample-host:4841/ua"},
		IsOnline:      online,
	}
}

const (
	ldsURI        = "urn:otfabric:conformance:lds"
	registrantURI = "urn:otfabric:conformance:registrant"
)

// TestDiscovery_RegisterWithLDS_NoSecurity: server A registers with LDS B
// over a channel without security (allowed explicitly on both sides), a
// client finds A through B, and A unregisters when it is closed.
func TestDiscovery_RegisterWithLDS_NoSecurity(t *testing.T) {
	var seen sync.Map // ServerUri -> last IsOnline
	_, ldsURL := newServer(t,
		server.ApplicationURI(ldsURI),
		server.WithLocalDiscoveryServer(
			server.LDSAllowInsecureRegistration(),
			server.LDSApplicationType(ua.ApplicationTypeDiscoveryServer),
			server.LDSRegistrationCallback(func(rs *ua.RegisteredServer) { seen.Store(rs.ServerURI, rs.IsOnline) }),
		),
	)

	var log conformkit.RegistrationLog
	a, aURL := newServer(t,
		server.ApplicationURI(registrantURI),
		server.ServerName("Registrant"),
		server.WithDiscoveryRegistration(ldsURL,
			server.RegisterInsecure(),
			server.RegisterEventHandler(log.Handle),
			server.RegisterRequestTimeout(30*time.Second),
		),
	)
	eventually(t, func() bool { return log.Count(conformkit.Registered) > 0 }, "A registers with the LDS")

	ev := log.Snapshot()[0]
	require.Equal(t, "RegisterServer2", ev.Service)
	require.Equal(t, ldsURL, ev.DiscoveryServerURL)
	require.Equal(t, ua.MessageSecurityModeNone, ev.SecurityMode)
	// The LDS has no multicast extension: it registers the server and says
	// that it ignored the mDNS configuration.
	require.Equal(t, []ua.StatusCode{ua.StatusBadNotSupported}, ev.ConfigurationResults)

	// A client finds A through the LDS: the LDS itself first, then A.
	ctx := context.Background()
	servers, err := opcua.FindServers(ctx, ldsURL, discoveryOpts()...)
	require.NoError(t, err)
	require.Len(t, servers, 2)
	require.Equal(t, ldsURI, servers[0].ApplicationURI)
	require.Equal(t, ua.ApplicationTypeDiscoveryServer, servers[0].ApplicationType)
	require.Equal(t, registrantURI, servers[1].ApplicationURI)
	require.Equal(t, "Registrant", servers[1].ApplicationName.Text)
	require.Equal(t, ua.ApplicationTypeServer, servers[1].ApplicationType)
	require.Equal(t, []string{aURL}, servers[1].DiscoveryURLs)

	// ... and can connect to what it found.
	c := newClient(t, servers[1].DiscoveryURLs[0])
	v, err := c.Node(ua.NewNumericNodeID(0, id.ServerServerStatusState)).Value(ctx)
	require.NoError(t, err)
	require.EqualValues(t, ua.ServerStateRunning, v.Value())

	online, ok := seen.Load(registrantURI)
	require.True(t, ok)
	require.Equal(t, true, online)

	// Closing A unregisters it.
	require.NoError(t, a.Close())
	require.Equal(t, 1, log.Count(conformkit.Unregistered), "events: %+v", log.Snapshot())
	require.Equal(t, []string{ldsURI}, knownServerURIs(t, ldsURL))
	online, _ = seen.Load(registrantURI)
	require.Equal(t, false, online)
}

// TestDiscovery_RegisterWithLDS_Secured: by default a registration needs a
// secured channel and the ServerUri of the registrant's certificate.
func TestDiscovery_RegisterWithLDS_Secured(t *testing.T) {
	p := pki(t)
	lds, ldsURL := newServer(t,
		server.Certificate(p.serverCert), server.PrivateKey(p.serverKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		server.WithLocalDiscoveryServer(),
	)
	// The subtests run in parallel against this one discovery server (every
	// server start marks its test parallel), so each registers an application
	// URI of its own and none asserts on the whole table.
	registeredHere := func() []string {
		var out []string
		for _, rs := range lds.RegisteredServers() {
			out = append(out, rs.ServerURI)
		}
		return out
	}

	t.Run("server registers with its certificate", func(t *testing.T) {
		var log conformkit.RegistrationLog
		var validated [][]byte
		a, _ := newServer(t,
			server.Certificate(p.clientCert), server.PrivateKey(p.clientKey),
			server.WithDiscoveryRegistration(ldsURL,
				server.RegisterEventHandler(log.Handle),
				server.RegisterRequestTimeout(30*time.Second),
				server.RegisterCertificateValidator(func(der []byte) error {
					validated = append(validated, der)
					return nil
				}),
			),
		)
		eventually(t, func() bool { return log.Count(conformkit.Registered) > 0 }, "A registers with the LDS")
		require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, log.Snapshot()[0].SecurityMode,
			"the most secure endpoint of the LDS is used")
		require.Equal(t, p.serverCert, validated[0])
		uris := knownServerURIs(t, ldsURL)
		require.Equal(t, serverAppURI, uris[0], "the discovery server itself comes first")
		require.Contains(t, uris, clientAppURI)
		require.Contains(t, registeredHere(), clientAppURI)

		require.NoError(t, a.Close())
		require.NotContains(t, knownServerURIs(t, ldsURL), clientAppURI)
		require.NotContains(t, registeredHere(), clientAppURI)
	})

	t.Run("pinned policy and mode", func(t *testing.T) {
		var log conformkit.RegistrationLog
		a, _ := newServer(t,
			server.Certificate(p.userCert), server.PrivateKey(p.userKey),
			server.WithDiscoveryRegistration(ldsURL,
				server.RegisterSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
				server.RegisterEventHandler(log.Handle),
				server.RegisterRequestTimeout(30*time.Second),
			),
		)
		eventually(t, func() bool { return log.Count(conformkit.Registered) > 0 }, "A registers with the LDS")
		require.Equal(t, ua.MessageSecurityModeSign, log.Snapshot()[0].SecurityMode)
		require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, log.Snapshot()[0].SecurityPolicyURI)
		require.Contains(t, registeredHere(), "urn:otfabric:conformance:user")
		require.NoError(t, a.Close())
		require.NotContains(t, registeredHere(), "urn:otfabric:conformance:user")
	})

	t.Run("no security is refused", func(t *testing.T) {
		c := dialDiscovery(t, ldsURL)
		_, err := c.RegisterServer(context.Background(), sampleServer(clientAppURI, true))
		require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)
		_, err = c.RegisterServer2(context.Background(), sampleServer(clientAppURI, true))
		require.ErrorIs(t, err, ua.StatusBadSecurityModeInsufficient)

		// A server that insists on no security does not get in either, and
		// keeps trying.
		var log conformkit.RegistrationLog
		a, _ := newServer(t,
			server.ApplicationURI(registrantURI),
			server.WithDiscoveryRegistration(ldsURL,
				server.RegisterInsecure(),
				server.RegisterSecurity("None", ua.MessageSecurityModeNone),
				server.RegisterBackoff(10*time.Millisecond, 50*time.Millisecond),
				server.RegisterEventHandler(log.Handle),
			),
		)
		eventually(t, func() bool { return log.Count(conformkit.Failed) >= 3 }, "the registration is retried")
		for _, e := range log.Snapshot() {
			require.ErrorIs(t, e.Err, ua.StatusBadSecurityModeInsufficient)
		}
		require.NoError(t, a.Close())
		require.Zero(t, log.Count(conformkit.Unregistered), "a server that never registered does not unregister")
	})

	t.Run("a certificate only registers its own URI", func(t *testing.T) {
		ep := endpointFor(t, ldsURL, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
		c := dialDiscovery(t, ldsURL,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.Certificate(p.strangerCert), opcua.PrivateKey(p.strangerKey),
			opcua.TrustedCertificates(p.serverCertX509),
		)
		ctx := context.Background()
		_, err := c.RegisterServer(ctx, sampleServer("urn:somebody:else", true))
		require.ErrorIs(t, err, ua.StatusBadServerURIInvalid)

		// its own URI is fine, with RegisterServer2 and RegisterServer
		const own = "urn:otfabric:conformance:stranger"
		resp, err := c.RegisterServer2(ctx, sampleServer(own, true),
			&ua.MdnsDiscoveryConfiguration{MdnsServerName: "Stranger", ServerCapabilities: []string{"DA"}})
		require.NoError(t, err)
		require.Equal(t, []ua.StatusCode{ua.StatusBadNotSupported}, resp.ConfigurationResults)
		_, err = c.RegisterServer(ctx, sampleServer(own, true))
		require.NoError(t, err)
		require.Contains(t, knownServerURIs(t, ldsURL), own)

		// and it cannot remove somebody else
		_, err = c.RegisterServer(ctx, sampleServer(serverAppURI, false))
		require.ErrorIs(t, err, ua.StatusBadServerURIInvalid)
		_, err = c.RegisterServer(ctx, sampleServer(own, false))
		require.NoError(t, err)
		require.NotContains(t, knownServerURIs(t, ldsURL), own)
	})
}

// TestDiscovery_URICheckCanBeSkipped: a gateway may register servers other
// than itself if the discovery server allows it.
func TestDiscovery_URICheckCanBeSkipped(t *testing.T) {
	p := pki(t)
	_, ldsURL := newServer(t,
		server.Certificate(p.serverCert), server.PrivateKey(p.serverKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.WithLocalDiscoveryServer(server.LDSSkipServerURICheck(), server.LDSMaxRegisteredServers(2)),
	)
	ep := endpointFor(t, ldsURL, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
	c := dialDiscovery(t, ldsURL,
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
		opcua.Certificate(p.clientCert), opcua.PrivateKey(p.clientKey),
		opcua.TrustedCertificates(p.serverCertX509),
	)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_, err := c.RegisterServer(ctx, sampleServer(fmt.Sprintf("urn:behind:gateway:%d", i), true))
		require.NoError(t, err)
	}
	// the table is bounded
	_, err := c.RegisterServer(ctx, sampleServer("urn:behind:gateway:2", true))
	require.ErrorIs(t, err, ua.StatusBadResourceUnavailable)
	// a renewal is not a new entry
	_, err = c.RegisterServer(ctx, sampleServer("urn:behind:gateway:1", true))
	require.NoError(t, err)
}

// TestDiscovery_FindServersFilters: ServerUris, LocaleIds and EndpointUrl of
// FindServers.
func TestDiscovery_FindServersFilters(t *testing.T) {
	_, ldsURL := newServer(t,
		server.ApplicationURI(ldsURI),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
	)
	c := dialDiscovery(t, ldsURL)
	ctx := context.Background()
	_, err := c.RegisterServer(ctx, sampleServer("urn:sample:1", true))
	require.NoError(t, err)
	_, err = c.RegisterServer(ctx, sampleServer("urn:sample:2", true))
	require.NoError(t, err)

	uris := func(resp *ua.FindServersResponse) []string {
		var out []string
		for _, s := range resp.Servers {
			out = append(out, s.ApplicationURI)
		}
		return out
	}

	all, err := c.FindServers(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{ldsURI, "urn:sample:1", "urn:sample:2"}, uris(all))
	require.Equal(t, []string{ldsURL}, all.Servers[0].DiscoveryURLs)
	require.Equal(t, "Sample", all.Servers[1].ApplicationName.Text, "the first name without a locale filter")
	require.Equal(t, []string{"opc.tcp://sample-host:4841/ua"}, all.Servers[1].DiscoveryURLs,
		"the discovery URLs of a registered server are returned as registered")

	one, err := c.FindServersWithFilter(ctx, []string{"fr", "de"}, []string{"urn:sample:2", "urn:not:there"})
	require.NoError(t, err)
	require.Equal(t, []string{"urn:sample:2"}, uris(one))
	require.Equal(t, "Beispiel", one.Servers[0].ApplicationName.Text)
	require.Equal(t, "de", one.Servers[0].ApplicationName.Locale)

	fallback, err := c.FindServersWithFilter(ctx, []string{"fr"}, []string{ldsURI, "urn:sample:1"})
	require.NoError(t, err)
	require.Equal(t, []string{ldsURI, "urn:sample:1"}, uris(fallback))
	require.Equal(t, "Sample", fallback.Servers[1].ApplicationName.Text, "no name in the locale: the first one")

	none, err := c.FindServersWithFilter(ctx, nil, []string{"urn:not:there"})
	require.NoError(t, err)
	require.Empty(t, none.Servers)

	// A client that reached the server under a host name the server does
	// not know gets the default discovery URLs.
	var resp *ua.FindServersResponse
	err = c.Send(ctx, &ua.FindServersRequest{EndpointURL: "opc.tcp://some-nat-address:1234"}, func(r ua.Response) error {
		var ok bool
		resp, ok = r.(*ua.FindServersResponse)
		require.True(t, ok)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{ldsURL}, resp.Servers[0].DiscoveryURLs)
}

// TestDiscovery_RegistrationExpires: a server that dies without
// unregistering disappears from the LDS when its registration times out,
// while a server that renews its registration stays.
func TestDiscovery_RegistrationExpires(t *testing.T) {
	const timeout = 3 * time.Second
	lds, ldsURL := newServer(t,
		server.ApplicationURI(ldsURI),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration(), server.LDSRegistrationTimeout(timeout)),
	)
	registeredURIs := func() []string {
		var out []string
		for _, rs := range lds.RegisteredServers() {
			out = append(out, rs.ServerURI)
		}
		return out
	}

	var dying, living conformkit.RegistrationLog
	_, _ = newServer(t,
		server.ApplicationURI("urn:otfabric:conformance:alive"),
		server.WithDiscoveryRegistration(ldsURL,
			server.RegisterInsecure(),
			server.RegisterInterval(timeout/20),
			server.RegisterRequestTimeout(30*time.Second),
			server.RegisterEventHandler(living.Handle),
		),
	)
	eventually(t, func() bool { return living.Count(conformkit.Registered) > 0 }, "the living server registers")
	livingSince := time.Now()

	// The "dying" server reaches the LDS through a proxy that is cut before
	// the server is closed: its unregistration never arrives.
	proxy := testutil.NewChaosProxy(t, ldsURL[len("opc.tcp://"):], 1)
	beforeRegistration := time.Now()
	doomed, _ := newServer(t,
		server.ApplicationURI("urn:otfabric:conformance:doomed"),
		server.WithDiscoveryRegistration(proxy.EndpointURL(),
			server.RegisterInsecure(),
			server.RegisterInterval(time.Hour), // registers once
			server.RegisterRequestTimeout(2*time.Second),
			server.RegisterEventHandler(dying.Handle),
		),
	)
	eventually(t, func() bool { return dying.Count(conformkit.Registered) > 0 }, "the doomed server registers")

	proxy.SetRefuse(true)
	proxy.DropAll()
	require.NoError(t, doomed.Close())
	require.Equal(t, 1, dying.Count(func(e server.RegistrationEvent) bool { return !e.Online && e.Err != nil }),
		"the unregistration failed: %+v", dying.Snapshot())

	eventually(t, func() bool {
		return !slices.Contains(registeredURIs(), "urn:otfabric:conformance:doomed")
	}, "the registration of the dead server expires")
	require.GreaterOrEqual(t, time.Since(beforeRegistration), timeout, "not before the timeout")

	// The server that renews is still there: it keeps renewing for another
	// timeout after the other registration expired (20 intervals), by which
	// time it has outlived its own timeout more than twice. Renewals that
	// stopped, or that did not extend the registration, would have removed
	// it after one timeout; watching it for longer shows nothing new.
	renewals := living.Count(conformkit.Registered)
	eventually(t, func() bool {
		return living.Count(conformkit.Registered) >= renewals+20 && time.Since(livingSince) >= 2*timeout+timeout/2
	}, "the living server keeps renewing")
	require.Equal(t, []string{"urn:otfabric:conformance:alive"}, registeredURIs())
	require.Equal(t, []string{ldsURI, "urn:otfabric:conformance:alive"}, knownServerURIs(t, ldsURL))
}

// TestDiscovery_SemaphoreFile: a registration with a semaphore file lives as
// long as the file exists, whatever the timeout.
func TestDiscovery_SemaphoreFile(t *testing.T) {
	_, ldsURL := newServer(t,
		server.ApplicationURI(ldsURI),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration(), server.LDSRegistrationTimeout(200*time.Millisecond)),
	)
	dir := t.TempDir()
	semaphore := filepath.Join(dir, "server.online")

	c := dialDiscovery(t, ldsURL)
	ctx := context.Background()
	withFile := sampleServer("urn:sample:semaphore", true)
	withFile.SemaphoreFilePath = semaphore
	_, err := c.RegisterServer(ctx, withFile)
	require.ErrorIs(t, err, ua.StatusBadSemaphoreFileMissing)

	require.NoError(t, os.WriteFile(semaphore, nil, 0o600))
	_, err = c.RegisterServer(ctx, withFile)
	require.NoError(t, err)
	_, err = c.RegisterServer(ctx, sampleServer("urn:sample:plain", true))
	require.NoError(t, err)

	// the plain registration times out, the one with the file stays
	eventually(t, func() bool { return !slices.Contains(knownServerURIs(t, ldsURL), "urn:sample:plain") }, "the plain registration expires")
	require.Contains(t, knownServerURIs(t, ldsURL), "urn:sample:semaphore")

	require.NoError(t, os.Remove(semaphore))
	eventually(t, func() bool { return !slices.Contains(knownServerURIs(t, ldsURL), "urn:sample:semaphore") }, "the registration ends with its semaphore file")
}

// TestDiscovery_RegisterSemaphoreFileOption: a server passes its semaphore
// file to the discovery server.
func TestDiscovery_RegisterSemaphoreFileOption(t *testing.T) {
	lds, ldsURL := newServer(t,
		server.ApplicationURI(ldsURI),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
	)
	semaphore := filepath.Join(t.TempDir(), "server.online")
	require.NoError(t, os.WriteFile(semaphore, nil, 0o600))

	var log conformkit.RegistrationLog
	_, _ = newServer(t,
		server.ApplicationURI(registrantURI),
		server.WithDiscoveryRegistration(ldsURL,
			server.RegisterInsecure(),
			server.RegisterSemaphoreFile(semaphore),
			server.RegisterDiscoveryURLs("opc.tcp://public-name:4840/ua"),
			server.RegisterMdnsServerName("Registrant"),
			server.RegisterServerCapabilities("DA", "HD"),
			server.RegisterEventHandler(log.Handle),
			server.RegisterRequestTimeout(30*time.Second),
		),
	)
	eventually(t, func() bool { return log.Count(conformkit.Registered) > 0 }, "the server registers")
	reg := lds.RegisteredServers()
	require.Len(t, reg, 1)
	require.Equal(t, semaphore, reg[0].SemaphoreFilePath)
	require.Equal(t, []string{"opc.tcp://public-name:4840/ua"}, reg[0].DiscoveryURLs)
}

// TestDiscovery_FallbackToRegisterServer: a discovery server that predates
// RegisterServer2 is registered with through RegisterServer.
func TestDiscovery_FallbackToRegisterServer(t *testing.T) {
	for _, status := range []ua.StatusCode{ua.StatusBadServiceUnsupported, ua.StatusBadNotSupported} {
		t.Run(status.Error(), func(t *testing.T) {
			parallel(t)
			lds, err := server.New(
				server.EndPoint("localhost", 0),
				server.EnableSecurity("None", ua.MessageSecurityModeNone),
				server.EnableAuthMode(ua.UserTokenTypeAnonymous),
				server.ApplicationURI(ldsURI),
				server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
			)
			require.NoError(t, err)
			var register2Calls int
			var mu sync.Mutex
			// A handler registered before Start takes precedence over the
			// built-in one.
			lds.RegisterHandler(id.RegisterServer2RequestEncodingDefaultBinary,
				func(context.Context, *uasc.SecureChannel, ua.Request, uint32) (ua.Response, error) {
					mu.Lock()
					register2Calls++
					mu.Unlock()
					return nil, status
				})
			require.NoError(t, lds.Start(context.Background()))
			t.Cleanup(func() { _ = lds.Close() })
			ldsURL := fmt.Sprintf("opc.tcp://localhost:%d", lds.Port())

			var log conformkit.RegistrationLog
			a, _ := newServer(t,
				server.ApplicationURI(registrantURI),
				server.WithDiscoveryRegistration(ldsURL,
					server.RegisterInsecure(),
					server.RegisterInterval(20*time.Millisecond),
					server.RegisterEventHandler(log.Handle),
					server.RegisterRequestTimeout(30*time.Second),
				),
			)
			eventually(t, func() bool { return log.Count(conformkit.Registered) >= 3 }, "A registers and renews")
			for _, e := range log.Snapshot() {
				require.NoError(t, e.Err)
				require.Equal(t, "RegisterServer", e.Service)
				require.Empty(t, e.ConfigurationResults)
			}
			mu.Lock()
			require.Equal(t, 1, register2Calls, "RegisterServer2 is tried once")
			mu.Unlock()
			require.Equal(t, []string{ldsURI, registrantURI}, knownServerURIs(t, ldsURL))

			// the unregistration uses RegisterServer as well
			require.NoError(t, a.Close())
			require.Equal(t, 1, log.Count(conformkit.Unregistered))
			require.Equal(t, []string{ldsURI}, knownServerURIs(t, ldsURL))
		})
	}
}

// TestDiscovery_LDSDownAtStartAndStop: a discovery server that cannot be
// reached neither holds up Start nor Close; the registration succeeds once
// the discovery server is there.
func TestDiscovery_LDSDownAtStartAndStop(t *testing.T) {
	parallel(t) // before anything is timed: it parks the test until the serial ones are done
	// The proxy accepts and resets connections until the LDS exists.
	proxy := testutil.NewChaosProxy(t, "127.0.0.1:1", 1)
	proxy.SetRefuse(true)

	var log conformkit.RegistrationLog
	start := time.Now()
	a, _ := newServer(t,
		server.ApplicationURI(registrantURI),
		server.WithDiscoveryRegistration(proxy.EndpointURL(),
			server.RegisterInsecure(),
			server.RegisterBackoff(10*time.Millisecond, 100*time.Millisecond),
			server.RegisterRequestTimeout(30*time.Second),
			server.RegisterEventHandler(log.Handle),
		),
	)
	require.Less(t, time.Since(start), 20*time.Second, "Start does not wait for the discovery server")
	eventually(t, func() bool { return log.Count(conformkit.Failed) >= 3 }, "the registration is retried")
	require.Zero(t, log.Count(conformkit.Registered))

	_, ldsURL := newServer(t,
		server.ApplicationURI(ldsURI),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
	)
	proxy.SetBackend(ldsURL[len("opc.tcp://"):])
	proxy.SetRefuse(false)
	eventually(t, func() bool { return log.Count(conformkit.Registered) > 0 }, "the registration succeeds once the LDS is up")
	require.Contains(t, knownServerURIs(t, ldsURL), registrantURI)

	// The LDS goes away again: Close still returns promptly.
	proxy.SetRefuse(true)
	proxy.DropAll()
	start = time.Now()
	require.NoError(t, a.Close())
	require.Less(t, time.Since(start), 20*time.Second, "Close does not wait for the discovery server")
}

// TestDiscovery_RegistrationNeedsSecurityOrOptIn: configuration errors are
// reported by Start, not discovered at run time.
func TestDiscovery_RegistrationNeedsSecurityOrOptIn(t *testing.T) {
	p := pki(t)
	base := []server.Option{
		server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}
	startErr := func(opts ...server.Option) error {
		srv, err := server.New(append(slices.Clone(base), opts...)...)
		if err != nil {
			return err
		}
		err = srv.Start(context.Background())
		_ = srv.Close()
		return err
	}
	const lds = "opc.tcp://localhost:4840"

	require.ErrorContains(t, startErr(server.WithDiscoveryRegistration(lds)), "needs a certificate")
	require.ErrorContains(t, startErr(server.WithDiscoveryRegistration(lds,
		server.RegisterSecurity("Basic256Sha256", ua.MessageSecurityModeSign))), "needs a certificate")
	require.ErrorContains(t, startErr(
		server.Certificate(p.serverCert), server.PrivateKey(p.serverKey),
		server.WithDiscoveryRegistration(lds, server.RegisterSecurity("None", ua.MessageSecurityModeNone))), "RegisterInsecure")
	require.ErrorContains(t, startErr(server.WithDiscoveryRegistration(lds,
		server.RegisterSecurity("Basic256Sha256", ua.MessageSecurityModeNone))), "cannot be used")
	require.ErrorContains(t, startErr(server.WithDiscoveryRegistration(lds,
		server.RegisterSecurity("NoSuchPolicy", ua.MessageSecurityModeSign))), "unsupported security policy")
	require.ErrorContains(t, startErr(server.WithDiscoveryRegistration("http://not-opc")), "discovery server URL")
	require.ErrorContains(t, startErr(server.ApplicationURI("")), "empty ApplicationURI")
}

// TestDiscovery_SecuredRegistrationFailures: a registration that must be
// secured fails, and is retried, if the discovery server offers nothing
// suitable or its certificate is not trusted.
func TestDiscovery_SecuredRegistrationFailures(t *testing.T) {
	p := pki(t)
	_, plainLDS := newServer(t,
		server.ApplicationURI(ldsURI),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
	)
	_, securedLDS := newServer(t,
		server.Certificate(p.serverCert), server.PrivateKey(p.serverKey),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.WithLocalDiscoveryServer(),
	)
	fast := server.RegisterBackoff(10*time.Millisecond, 50*time.Millisecond)

	var noEndpoint, untrusted, fallback conformkit.RegistrationLog
	_, _ = newServer(t,
		server.Certificate(p.clientCert), server.PrivateKey(p.clientKey),
		server.WithDiscoveryRegistration(plainLDS, fast, server.RegisterEventHandler(noEndpoint.Handle)),
		server.WithDiscoveryRegistration(securedLDS, fast, server.RegisterEventHandler(untrusted.Handle),
			server.RegisterCertificateValidator(func([]byte) error { return ua.StatusBadCertificateUntrusted })),
		// With RegisterInsecure the server settles for no security where
		// nothing better is offered.
		server.WithDiscoveryRegistration(plainLDS, fast, server.RegisterInsecure(), server.RegisterEventHandler(fallback.Handle)),
	)
	eventually(t, func() bool {
		return noEndpoint.Count(conformkit.Failed) >= 2 && untrusted.Count(conformkit.Failed) >= 2 && fallback.Count(conformkit.Registered) > 0
	},
		"the outcomes of the three registrations")
	require.ErrorIs(t, noEndpoint.Snapshot()[0].Err, ua.StatusBadSecurityModeRejected)
	require.ErrorIs(t, untrusted.Snapshot()[0].Err, ua.StatusBadCertificateUntrusted)
	require.Equal(t, ua.MessageSecurityModeNone, fallback.Snapshot()[0].SecurityMode)
	require.Zero(t, noEndpoint.Count(conformkit.Registered))
	require.Zero(t, untrusted.Count(conformkit.Registered))
}

// --- multicast extension --------------------------------------------------------

// onLink returns the server option that puts a server's mDNS responder on an
// in-memory link, so that the tests do not depend on multicast being
// available on the machine.
func onLink(link *mdns.MemNetwork) server.Option {
	return testhook.ServerMulticastTransport(link).(server.Option)
}

func serverNames(records []*ua.ServerOnNetwork) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.ServerName)
	}
	return out
}

// TestDiscovery_FindServersOnNetwork: servers that announce themselves with
// mDNS show up in the ServerOnNetwork table of a discovery server, with
// record ids, paging and the capability filter of the service.
func TestDiscovery_FindServersOnNetwork(t *testing.T) {
	link := mdns.NewMemNetwork()
	lds, ldsURL := newServer(t,
		server.ApplicationURI(ldsURI),
		server.ServerName("LDS"),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
		server.WithMulticastDiscovery(server.MulticastHostname("lds-host"), server.MulticastMaxServersOnNetwork(100)),
		onLink(link),
	)
	require.Equal(t, []string{"LDS-lds-host"}, serverNames(lds.ServersOnNetwork()))

	// Three servers with different capabilities announce themselves, one
	// after the other so that the record ids are known.
	type announced struct {
		name string
		caps []string
		srv  *server.Server
	}
	servers := []*announced{
		{name: "Press", caps: []string{"DA", "HD"}},
		{name: "Oven", caps: []string{"DA"}},
		{name: "Robot", caps: []string{"DA", "AC", "HD"}},
	}
	for i, a := range servers {
		a.srv, _ = newServer(t,
			server.ApplicationURI("urn:otfabric:conformance:"+a.name),
			server.WithMulticastDiscovery(
				server.MulticastServerName(a.name),
				server.MulticastHostname("host"+fmt.Sprint(i)),
				server.MulticastCapabilities(a.caps...),
				server.MulticastInterfaces(), // no restriction
				server.MulticastIPv4Only(),
			),
			onLink(link),
		)
		eventually(t, func() bool { return len(lds.ServersOnNetwork()) == i+2 }, "the LDS discovers "+a.name)
	}

	c := dialDiscovery(t, ldsURL)
	ctx := context.Background()

	all, err := c.FindServersOnNetwork(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"LDS-lds-host", "Press-host0", "Oven-host1", "Robot-host2"}, serverNames(all.Servers))
	for i, rec := range all.Servers {
		require.EqualValues(t, i, rec.RecordID, "record ids count up from 0")
	}
	require.Equal(t, []string{"LDS"}, all.Servers[0].ServerCapabilities)
	require.Equal(t, fmt.Sprintf("opc.tcp://lds-host:%d", lds.Port()), all.Servers[0].DiscoveryURL)
	require.Equal(t, []string{"DA", "HD"}, all.Servers[1].ServerCapabilities)
	require.Equal(t, fmt.Sprintf("opc.tcp://host0.local:%d", servers[0].srv.Port()), all.Servers[1].DiscoveryURL)
	require.WithinDuration(t, time.Now(), all.LastCounterResetTime, 10*time.Minute)

	// paging: starting record id and maximum number of records
	page, err := c.FindServersOnNetworkWithFilter(ctx, 0, 2, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"LDS-lds-host", "Press-host0"}, serverNames(page.Servers))
	next := page.Servers[len(page.Servers)-1].RecordID + 1
	page, err = c.FindServersOnNetworkWithFilter(ctx, next, 2, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"Oven-host1", "Robot-host2"}, serverNames(page.Servers))
	require.Equal(t, all.LastCounterResetTime, page.LastCounterResetTime)
	page, err = c.FindServersOnNetworkWithFilter(ctx, page.Servers[1].RecordID+1, 2, nil)
	require.NoError(t, err)
	require.Empty(t, page.Servers)

	// capability filter: all capabilities must be present, case-insensitive
	filtered, err := c.FindServersOnNetworkWithFilter(ctx, 0, 0, []string{"hd", "DA"})
	require.NoError(t, err)
	require.Equal(t, []string{"Press-host0", "Robot-host2"}, serverNames(filtered.Servers))
	filtered, err = c.FindServersOnNetworkWithFilter(ctx, 0, 1, []string{"HD"})
	require.NoError(t, err)
	require.Equal(t, []string{"Press-host0"}, serverNames(filtered.Servers))
	filtered, err = c.FindServersOnNetworkWithFilter(ctx, 2, 0, []string{"HD"})
	require.NoError(t, err)
	require.Equal(t, []string{"Robot-host2"}, serverNames(filtered.Servers))
	filtered, err = c.FindServersOnNetworkWithFilter(ctx, 0, 0, []string{"LDS", "DA"})
	require.NoError(t, err)
	require.Empty(t, filtered.Servers)

	// every server with the extension answers the service, not only the LDS
	eventually(t, func() bool { return len(servers[2].srv.ServersOnNetwork()) == 4 }, "the last server discovers the others")
	onRobot, err := opcua.FindServersOnNetwork(ctx, fmt.Sprintf("opc.tcp://localhost:%d", servers[2].srv.Port()), discoveryOpts()...)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"Robot-host2", "LDS-lds-host", "Press-host0", "Oven-host1"}, serverNames(onRobot))
	require.Equal(t, "Robot-host2", onRobot[0].ServerName, "the server itself has the first record")

	// a server that goes away says goodbye and leaves the table; ids are not reused
	require.NoError(t, servers[1].srv.Close())
	eventually(t, func() bool { return len(lds.ServersOnNetwork()) == 3 }, "the closed server leaves the table")
	all, err = c.FindServersOnNetwork(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"LDS-lds-host", "Press-host0", "Robot-host2"}, serverNames(all.Servers))
	require.EqualValues(t, 3, all.Servers[2].RecordID)

	// the package-level helper reports both views of the discovery server
	res, err := opcua.DiscoverServers(ctx, ldsURL, discoveryOpts()...)
	require.NoError(t, err)
	require.Equal(t, opcua.DiscoveryURL(ldsURL), res.DiscoveryServerURL)
	require.True(t, res.MulticastSupported)
	require.Len(t, res.Servers, 1)
	require.Len(t, res.ServersOnNetwork, 3)
	require.Equal(t, all.LastCounterResetTime, res.LastCounterResetTime)
}

// TestDiscovery_LDSAnnouncesRegisteredServers: with the multicast extension
// an LDS announces the servers registered with it (RegisterServer2 with an
// MdnsDiscoveryConfiguration, or RegisterServer with defaults), so that other
// discovery servers on the network learn about them.
func TestDiscovery_LDSAnnouncesRegisteredServers(t *testing.T) {
	link := mdns.NewMemNetwork()
	lds, ldsURL := newServer(t,
		server.ApplicationURI(ldsURI),
		server.ServerName("LDS"),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
		server.WithMulticastDiscovery(server.MulticastHostname("lds-host")),
		onLink(link),
	)
	// A second discovery server on the same network segment.
	other, otherURL := newServer(t,
		server.ApplicationURI("urn:otfabric:conformance:lds2"),
		server.ServerName("LDS2"),
		server.WithLocalDiscoveryServer(),
		server.WithMulticastDiscovery(server.MulticastHostname("other-host")),
		onLink(link),
	)
	eventually(t, func() bool { return len(other.ServersOnNetwork()) == 2 && len(lds.ServersOnNetwork()) == 2 },
		"the discovery servers see each other")

	// A server without mDNS of its own registers with the first LDS.
	var log conformkit.RegistrationLog
	a, _ := newServer(t,
		server.ApplicationURI(registrantURI),
		server.ServerName("Registrant"),
		server.WithDiscoveryRegistration(ldsURL,
			server.RegisterInsecure(),
			server.RegisterDiscoveryURLs("opc.tcp://plc7:4855/ua/server", "opc.tcp://192.0.2.7:4855"),
			server.RegisterMdnsServerName("Line 3.Press"),
			server.RegisterServerCapabilities("DA", "HD"),
			server.RegisterInterval(50*time.Millisecond),
			server.RegisterEventHandler(log.Handle),
			server.RegisterRequestTimeout(30*time.Second),
		),
	)
	eventually(t, func() bool { return log.Count(conformkit.Registered) > 0 }, "A registers")
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, log.Snapshot()[0].ConfigurationResults,
		"an LDS with the multicast extension accepts the mDNS configuration")

	find := func(records []*ua.ServerOnNetwork, name string) *ua.ServerOnNetwork {
		for _, r := range records {
			if r.ServerName == name {
				return r
			}
		}
		return nil
	}
	// On the LDS it registered with: the discovery URL as registered. The
	// URL with an IP address has no mDNS mapping and is not announced.
	const instance = "Line 3.Press-plc7"
	eventually(t, func() bool { return find(lds.ServersOnNetwork(), instance) != nil }, "the LDS lists the registered server")
	rec := find(lds.ServersOnNetwork(), instance)
	require.Equal(t, "opc.tcp://plc7:4855/ua/server", rec.DiscoveryURL)
	require.Equal(t, []string{"DA", "HD"}, rec.ServerCapabilities)
	require.Len(t, lds.ServersOnNetwork(), 3)

	// On the other discovery server: learned through mDNS.
	eventually(t, func() bool { return find(other.ServersOnNetwork(), instance) != nil }, "the other LDS discovers the registered server")
	rec = find(other.ServersOnNetwork(), instance)
	require.Equal(t, "opc.tcp://plc7.local:4855/ua/server", rec.DiscoveryURL)
	require.Equal(t, []string{"DA", "HD"}, rec.ServerCapabilities)

	// A client asking the other discovery server for historians finds it.
	ctx := context.Background()
	c := dialDiscovery(t, otherURL)
	resp, err := c.FindServersOnNetworkWithFilter(ctx, 0, 0, []string{"HD"})
	require.NoError(t, err)
	require.Equal(t, []string{instance}, serverNames(resp.Servers))

	// Renewals do not create new records.
	id := rec.RecordID
	renewals := log.Count(conformkit.Registered)
	eventually(t, func() bool { return log.Count(conformkit.Registered) >= renewals+5 }, "A renews its registration")
	require.Equal(t, id, find(other.ServersOnNetwork(), instance).RecordID)
	require.Len(t, lds.ServersOnNetwork(), 3)

	// A server registered with plain RegisterServer is announced under its
	// first server name with the capability "NA".
	reg := dialDiscovery(t, ldsURL)
	legacy := sampleServer("urn:sample:legacy", true)
	_, err = reg.RegisterServer(ctx, legacy)
	require.NoError(t, err)
	eventually(t, func() bool { return find(other.ServersOnNetwork(), "Sample-sample-host") != nil }, "the legacy registration is announced")
	require.Equal(t, []string{"NA"}, find(other.ServersOnNetwork(), "Sample-sample-host").ServerCapabilities)

	// Unregistering withdraws the announcement.
	require.NoError(t, a.Close())
	eventually(t, func() bool {
		return find(lds.ServersOnNetwork(), instance) == nil && find(other.ServersOnNetwork(), instance) == nil
	}, "the announcement of the unregistered server is withdrawn")
	legacy.IsOnline = false
	_, err = reg.RegisterServer(ctx, legacy)
	require.NoError(t, err)
	eventually(t, func() bool { return len(other.ServersOnNetwork()) == 2 }, "the legacy announcement is withdrawn")
}

// TestDiscovery_WithoutMulticastExtension: FindServersOnNetwork is not
// offered without the extension, and the discovery helper copes with that.
func TestDiscovery_WithoutMulticastExtension(t *testing.T) {
	_, ldsURL := newServer(t, server.ApplicationURI(ldsURI), server.WithLocalDiscoveryServer())
	ctx := context.Background()

	_, err := opcua.FindServersOnNetwork(ctx, ldsURL, discoveryOpts()...)
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)

	res, err := opcua.DiscoverServers(ctx, ldsURL, discoveryOpts()...)
	require.NoError(t, err)
	require.False(t, res.MulticastSupported)
	require.Nil(t, res.ServersOnNetwork)
	require.Len(t, res.Servers, 1)

	// A server that is not a discovery server does not accept registrations.
	_, plainURL := newServer(t)
	c := dialDiscovery(t, plainURL)
	_, err = c.RegisterServer(ctx, sampleServer("urn:sample:1", true))
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)
	_, err = c.RegisterServer2(ctx, sampleServer("urn:sample:1", true))
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)

	// nobody listens on the well-known port of this address
	short, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = opcua.DiscoverServers(short, "127.0.0.1:1", opcua.DialTimeout(2*time.Second))
	require.Error(t, err)
}
