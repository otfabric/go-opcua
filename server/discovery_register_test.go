// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// startedServer starts a server on a free port of localhost and closes it at
// the end of the test.
func startedServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	s, err := New(append([]Option{EndPoint("localhost", 0)}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// startedLDS starts a Local Discovery Server with the endpoints of opts.
func startedLDS(t *testing.T, lds []LDSOption, opts ...Option) (*Server, string) {
	t.Helper()
	s := startedServer(t, append([]Option{
		ApplicationURI("urn:test:register:lds"),
		ServerName("LDS"),
		WithLocalDiscoveryServer(lds...),
	}, opts...)...)
	return s, fmt.Sprintf("opc.tcp://localhost:%d", s.Port())
}

// registrant returns a started server that registers with url and the
// channel its registration events arrive on.
func registrant(t *testing.T, url, uri string, reg []RegistrationOption, opts ...Option) (*Server, chan RegistrationEvent) {
	t.Helper()
	events := make(chan RegistrationEvent, 64)
	reg = append([]RegistrationOption{
		RegisterInterval(time.Hour),
		RegisterRequestTimeout(5 * time.Second),
		RegisterEventHandler(func(ev RegistrationEvent) { events <- ev }),
	}, reg...)
	s := startedServer(t, append([]Option{
		ApplicationURI(uri),
		ServerName("Registrant"),
		WithDiscoveryRegistration(url, reg...),
	}, opts...)...)
	return s, events
}

func nextEvent(t *testing.T, events <-chan RegistrationEvent) RegistrationEvent {
	t.Helper()
	select {
	case ev := <-events:
		return ev
	case <-time.After(30 * time.Second):
		t.Fatal("no registration event")
		return RegistrationEvent{}
	}
}

func TestRegistration_Options(t *testing.T) {
	for name, opt := range map[string]Option{
		"url":      WithDiscoveryRegistration("http://[::1"),
		"policy":   WithDiscoveryRegistration("opc.tcp://localhost:4840", RegisterSecurity("urn:no-such-policy", ua.MessageSecurityModeSign)),
		"none":     WithDiscoveryRegistration("opc.tcp://localhost:4840", RegisterSecurity(ua.SecurityPolicyURINone, ua.MessageSecurityModeSign)),
		"modeNone": WithDiscoveryRegistration("opc.tcp://localhost:4840", RegisterSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeNone)),
	} {
		_, err := New(EndPoint("localhost", 0), opt)
		require.Error(t, err, name)
	}

	// What depends on other options is checked by Start.
	for name, opts := range map[string][]Option{
		"no certificate": {WithDiscoveryRegistration("opc.tcp://localhost:4840")},
		"None needs RegisterInsecure": {WithDiscoveryRegistration("opc.tcp://localhost:4840",
			RegisterSecurity(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone))},
		"policy needs a certificate": {WithDiscoveryRegistration("opc.tcp://localhost:4840", RegisterInsecure(),
			RegisterSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt))},
	} {
		s, err := New(append([]Option{EndPoint("localhost", 0)}, opts...)...)
		require.NoError(t, err, name)
		require.Error(t, s.Start(context.Background()), name)
	}

	rc := &registrationConfig{}
	for _, o := range []RegistrationOption{
		RegisterBackoff(time.Millisecond, time.Second),
		RegisterSemaphoreFile("/tmp/semaphore"),
		RegisterDiscoveryURLs("opc.tcp://elsewhere:4840"),
		RegisterMdnsServerName("mdns-name"),
		RegisterServerCapabilities("DA", "HD"),
		RegisterCertificateValidator(func([]byte) error { return nil }),
	} {
		o(rc)
	}
	require.Equal(t, defaultRegisterRequestTimeout, rc.timeout())
	s := discoveryServer(t)
	rs := s.registeredServer(rc, true)
	require.Equal(t, []string{"opc.tcp://elsewhere:4840"}, rs.DiscoveryURLs)
	require.Equal(t, "/tmp/semaphore", rs.SemaphoreFilePath)
	m := s.mdnsConfiguration(rc)
	require.Equal(t, "mdns-name", m.MdnsServerName)
	require.Equal(t, []string{"DA", "HD"}, m.ServerCapabilities)
	m = s.mdnsConfiguration(&registrationConfig{})
	require.Equal(t, "Test LDS", m.MdnsServerName)
	require.Equal(t, []string{"NA"}, m.ServerCapabilities)
}

func TestRegistration_AssignResponse(t *testing.T) {
	var resp *ua.RegisterServerResponse
	require.NoError(t, assignResponse(&ua.RegisterServerResponse{ResponseHeader: &ua.ResponseHeader{}}, &resp))
	require.NotNil(t, resp)
	err := assignResponse(&ua.RegisterServerResponse{ResponseHeader: &ua.ResponseHeader{ServiceResult: ua.StatusBadInternalError}}, &resp)
	require.ErrorIs(t, err, ua.StatusBadInternalError)
	err = assignResponse(&ua.ServiceFault{ResponseHeader: &ua.ResponseHeader{ServiceResult: ua.StatusBadServiceUnsupported}}, &resp)
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)
	require.True(t, registerServer2Unsupported(err))
	require.Error(t, assignResponse(&ua.ServiceFault{ResponseHeader: &ua.ResponseHeader{}}, &resp))
	require.Error(t, assignResponse(nil, &resp))
}

// TestRegistration_InsecureRegisterAndUnregister registers over SecurityPolicy
// None and unregisters on Close.
func TestRegistration_InsecureRegisterAndUnregister(t *testing.T) {
	accepted := make(chan *ua.RegisteredServer, 8)
	lds, url := startedLDS(t, []LDSOption{LDSAllowInsecureRegistration(), LDSRegistrationCallback(func(rs *ua.RegisteredServer) { accepted <- rs })},
		EnableSecurity("None", ua.MessageSecurityModeNone))

	const uri = "urn:test:register:insecure"
	s, events := registrant(t, url, uri, []RegistrationOption{RegisterInsecure(), RegisterMdnsServerName("press")},
		EnableSecurity("None", ua.MessageSecurityModeNone))
	ev := nextEvent(t, events)
	require.NoError(t, ev.Err)
	require.True(t, ev.Online)
	require.Equal(t, "RegisterServer2", ev.Service)
	require.Equal(t, ua.SecurityPolicyURINone, ev.SecurityPolicyURI)
	require.Equal(t, url, ev.DiscoveryServerURL)
	require.Contains(t, registeredURIs(lds), uri)
	require.Equal(t, uri, (<-accepted).ServerURI)

	require.NoError(t, s.Close())
	ev = nextEvent(t, events)
	require.NoError(t, ev.Err)
	require.False(t, ev.Online)
	require.NotContains(t, registeredURIs(lds), uri)
}

// TestRegistration_Secure registers on the most secure endpoint of the
// discovery server with the certificate of the server.
func TestRegistration_Secure(t *testing.T) {
	ldsCert, ldsKey, err := testpki.SelfSigned("lds", "urn:test:register:lds")
	require.NoError(t, err)
	lds, url := startedLDS(t, nil,
		Certificate(ldsCert), PrivateKey(ldsKey),
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
		EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))

	const uri = "urn:test:register:secure"
	cert, key, err := testpki.SelfSigned("registrant", uri)
	require.NoError(t, err)
	var seen []byte
	_, events := registrant(t, url, uri, []RegistrationOption{RegisterCertificateValidator(func(der []byte) error { seen = der; return nil })},
		Certificate(cert), PrivateKey(key), EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))
	ev := nextEvent(t, events)
	require.NoError(t, ev.Err)
	require.Equal(t, ua.SecurityPolicyURIBasic256Sha256, ev.SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, ev.SecurityMode)
	require.Equal(t, ldsCert, seen)
	require.Contains(t, registeredURIs(lds), uri)

	// A policy and mode of the endpoints of the discovery server.
	const uri2 = "urn:test:register:sign"
	cert2, key2, err := testpki.SelfSigned("registrant 2", uri2)
	require.NoError(t, err)
	_, events = registrant(t, url, uri2, []RegistrationOption{RegisterSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign)},
		Certificate(cert2), PrivateKey(key2), EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))
	ev = nextEvent(t, events)
	require.NoError(t, ev.Err)
	require.Equal(t, ua.MessageSecurityModeSign, ev.SecurityMode)

	// The certificate validator refuses the discovery server.
	const uri3 = "urn:test:register:refused"
	cert3, key3, err := testpki.SelfSigned("registrant 3", uri3)
	require.NoError(t, err)
	refused := errors.New("not this one")
	_, events = registrant(t, url, uri3, []RegistrationOption{RegisterCertificateValidator(func([]byte) error { return refused })},
		Certificate(cert3), PrivateKey(key3), EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))
	ev = nextEvent(t, events)
	require.ErrorIs(t, ev.Err, refused)
}

// TestRegistration_Failures covers a discovery server without a usable
// endpoint, one that does not serve the registration services, and one that
// cannot be reached.
func TestRegistration_Failures(t *testing.T) {
	// Only SecurityPolicy None: no secured endpoint.
	_, url := startedLDS(t, []LDSOption{LDSAllowInsecureRegistration()}, EnableSecurity("None", ua.MessageSecurityModeNone))
	cert, key, err := testpki.SelfSigned("registrant", "urn:test:register:fail")
	require.NoError(t, err)
	backoff := RegisterBackoff(time.Hour, time.Hour)
	_, events := registrant(t, url, "urn:test:register:fail", []RegistrationOption{backoff},
		Certificate(cert), PrivateKey(key), EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))
	ev := nextEvent(t, events)
	require.ErrorIs(t, ev.Err, ua.StatusBadSecurityModeRejected)

	// RegisterInsecure falls back to SecurityPolicy None.
	_, events = registrant(t, url, "urn:test:register:fail", []RegistrationOption{backoff, RegisterInsecure()},
		Certificate(cert), PrivateKey(key), EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))
	ev = nextEvent(t, events)
	require.NoError(t, ev.Err)
	require.Equal(t, ua.SecurityPolicyURINone, ev.SecurityPolicyURI)

	// A server that is no discovery server: RegisterServer2 and then
	// RegisterServer are refused.
	plain := startedServer(t, ApplicationURI("urn:test:register:plain"), EnableSecurity("None", ua.MessageSecurityModeNone))
	plainURL := fmt.Sprintf("opc.tcp://localhost:%d", plain.Port())
	_, events = registrant(t, plainURL, "urn:test:register:legacy", []RegistrationOption{backoff, RegisterInsecure()},
		EnableSecurity("None", ua.MessageSecurityModeNone))
	ev = nextEvent(t, events)
	require.Equal(t, "RegisterServer", ev.Service)
	require.ErrorIs(t, ev.Err, ua.StatusBadServiceUnsupported)

	// Nothing listens: the attempt fails, and Close does not unregister.
	gone := startedServer(t, EnableSecurity("None", ua.MessageSecurityModeNone))
	goneURL := fmt.Sprintf("opc.tcp://localhost:%d", gone.Port())
	require.NoError(t, gone.Close())
	s, events := registrant(t, goneURL, "urn:test:register:gone", []RegistrationOption{backoff, RegisterInsecure()},
		EnableSecurity("None", ua.MessageSecurityModeNone))
	ev = nextEvent(t, events)
	require.Error(t, ev.Err)
	require.NoError(t, s.Close())
	select {
	case ev := <-events:
		t.Fatalf("event after Close: %+v", ev)
	default:
	}

	// Secured, but nothing listens for GetEndpoints.
	_, events = registrant(t, goneURL, "urn:test:register:gone2", []RegistrationOption{backoff},
		Certificate(cert), PrivateKey(key), EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt))
	ev = nextEvent(t, events)
	require.ErrorContains(t, ev.Err, "get endpoints")
}
