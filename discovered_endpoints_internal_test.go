// SPDX-License-Identifier: MIT

package opcua

import (
	"runtime"
	"testing"
	"weak"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
)

// testEndpoints returns the endpoints of a server with three endpoints, the
// way GetEndpoints describes them.
func testEndpoints() []*ua.EndpointDescription {
	ep := func(policy string, mode ua.MessageSecurityMode, level uint8) *ua.EndpointDescription {
		return &ua.EndpointDescription{
			EndpointURL:         "opc.tcp://server:4840",
			Server:              &ua.ApplicationDescription{ApplicationURI: "urn:server"},
			ServerCertificate:   []byte{1, 2, 3},
			SecurityPolicyURI:   policy,
			SecurityMode:        mode,
			SecurityLevel:       level,
			TransportProfileURI: ua.TransportProfileUATCP,
			UserIdentityTokens: []*ua.UserTokenPolicy{
				{PolicyID: "anonymous", TokenType: ua.UserTokenTypeAnonymous},
				{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256},
			},
		}
	}
	return []*ua.EndpointDescription{
		ep(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0),
		ep(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, 3),
		ep(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 13),
	}
}

// TestVerifyEndpointList: the endpoint list the client selected from and the
// ServerEndpoints of CreateSession differ when an endpoint of one has no
// endpoint in the other with the same security policy, mode, level,
// transport profile and user token policies, application URI (when both
// name the application) and certificate (when both carry one).
func TestVerifyEndpointList(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		change func(server []*ua.EndpointDescription) []*ua.EndpointDescription
		ok     bool
	}{
		{"same list", func(s []*ua.EndpointDescription) []*ua.EndpointDescription { return s }, true},
		{"another order", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			return []*ua.EndpointDescription{s[2], s[0], s[1]}
		}, true},
		{"another endpoint URL", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			for _, e := range s {
				e.EndpointURL = "opc.tcp://10.0.0.1:4840/"
			}
			return s
		}, true},
		{"an endpoint once more under another URL", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			e := *s[2]
			e.EndpointURL = "opc.tcp://10.0.0.1:4840"
			return append(s, &e)
		}, true},
		{"user token policies in another order", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			for _, e := range s {
				e.UserIdentityTokens = []*ua.UserTokenPolicy{e.UserIdentityTokens[1], e.UserIdentityTokens[0]}
			}
			return s
		}, true},
		{"no certificate in CreateSession", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			for _, e := range s {
				e.ServerCertificate = nil
			}
			return s
		}, true},
		{"no application in CreateSession", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			for _, e := range s {
				e.Server = nil
			}
			return s
		}, true},
		{"nil entries", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			return append([]*ua.EndpointDescription{nil}, append(s, nil)...)
		}, true},

		{"an endpoint missing", func(s []*ua.EndpointDescription) []*ua.EndpointDescription { return s[:2] }, false},
		{"the first endpoint missing", func(s []*ua.EndpointDescription) []*ua.EndpointDescription { return s[1:] }, false},
		{"no endpoints", func([]*ua.EndpointDescription) []*ua.EndpointDescription { return nil }, false},
		{"an extra endpoint", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			e := *s[2]
			e.SecurityPolicyURI = ua.SecurityPolicyURIAes256Sha256RsaPss
			return append(s, &e)
		}, false},
		{"a changed security mode", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[1].SecurityMode = ua.MessageSecurityModeSignAndEncrypt
			return s
		}, false},
		{"a changed security policy", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[2].SecurityPolicyURI = ua.SecurityPolicyURIAes128Sha256RsaOaep
			return s
		}, false},
		{"a changed security level", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[1].SecurityLevel = 4
			return s
		}, false},
		{"a changed certificate", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[2].ServerCertificate = []byte{1, 2, 4}
			return s
		}, false},
		{"a longer certificate", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[2].ServerCertificate = []byte{1, 2, 3, 0}
			return s
		}, false},
		{"a changed transport profile", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[0].TransportProfileURI = ua.TransportProfileWSS
			return s
		}, false},
		{"a changed application URI", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[1].Server = &ua.ApplicationDescription{ApplicationURI: "urn:other"}
			return s
		}, false},
		{"a user token policy missing", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[2].UserIdentityTokens = s[2].UserIdentityTokens[:1]
			return s
		}, false},
		{"an extra user token policy", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[2].UserIdentityTokens = append(s[2].UserIdentityTokens, &ua.UserTokenPolicy{PolicyID: "x509", TokenType: ua.UserTokenTypeCertificate})
			return s
		}, false},
		{"a user token policy twice instead of another", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[2].UserIdentityTokens = []*ua.UserTokenPolicy{s[2].UserIdentityTokens[1], s[2].UserIdentityTokens[1]}
			return s
		}, false},
		{"a changed user token policy", func(s []*ua.EndpointDescription) []*ua.EndpointDescription {
			s[2].UserIdentityTokens[1] = &ua.UserTokenPolicy{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURINone}
			return s
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			discovered := newEndpointList(testEndpoints())
			err := verifyEndpointList(discovered, tt.change(testEndpoints()))
			if tt.ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
			}
		})
	}

	// Without a discovered list there is nothing to compare.
	require.NoError(t, verifyEndpointList(nil, testEndpoints()[:1]))
	// A certificate the discovered endpoints do not carry is not compared.
	noCert := testEndpoints()
	for _, e := range noCert {
		e.ServerCertificate = nil
	}
	require.NoError(t, verifyEndpointList(newEndpointList(noCert), testEndpoints()))
}

// TestEndpointListIsACopy: the list keeps what the endpoints held when it
// was made.
func TestEndpointListIsACopy(t *testing.T) {
	t.Parallel()
	eps := testEndpoints()
	l := newEndpointList(eps)
	eps[2].SecurityMode = ua.MessageSecurityModeSign
	eps[2].ServerCertificate[0] = 9
	eps[2].UserIdentityTokens[0].PolicyID = "changed"
	eps[2].Server.ApplicationURI = "urn:changed"
	require.NoError(t, verifyEndpointList(l, testEndpoints()))
	require.Nil(t, newEndpointList(nil))
	require.Nil(t, newEndpointList([]*ua.EndpointDescription{nil}))
}

// TestDiscoveredEndpointsOptions: the client compares the list given with
// DiscoveredEndpoints, else the list of the GetEndpoints response the
// endpoint given to SecurityFromEndpoint came in, and none with
// InsecureSkipDiscoveredEndpointsCheck, in any order of the options.
func TestDiscoveredEndpointsOptions(t *testing.T) {
	t.Parallel()
	eps := testEndpoints()
	rememberEndpoints(eps)
	given := testEndpoints()[1:]
	copied := *eps[1]

	list := func(opts ...Option) endpointList {
		t.Helper()
		opts = append(opts, InsecureNoSecurity())
		c, err := NewClient("opc.tcp://server:4840", opts...)
		require.NoError(t, err)
		if l := c.discoveredEndpoints.Load(); l != nil {
			return *l
		}
		return nil
	}
	from := func(ep *ua.EndpointDescription) Option { return SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous) }

	require.Nil(t, list(), "no endpoint, no list")
	require.Equal(t, newEndpointList(eps), list(from(eps[1])), "endpoint from GetEndpoints")
	require.Nil(t, list(from(&copied)), "a copy of an endpoint from GetEndpoints")
	require.Equal(t, newEndpointList(given), list(DiscoveredEndpoints(given)))
	require.Equal(t, newEndpointList(given), list(from(eps[1]), DiscoveredEndpoints(given)), "the option comes first")
	require.Equal(t, newEndpointList(given), list(DiscoveredEndpoints(given), from(eps[1])), "the option comes first")
	require.Nil(t, list(from(eps[1]), InsecureSkipDiscoveredEndpointsCheck()))
	require.Nil(t, list(InsecureSkipDiscoveredEndpointsCheck(), DiscoveredEndpoints(given)))
	require.Nil(t, list(DiscoveredEndpoints(given), InsecureSkipDiscoveredEndpointsCheck()))

	for _, empty := range [][]*ua.EndpointDescription{nil, {}, {nil}} {
		_, err := NewClient("opc.tcp://server:4840", InsecureNoSecurity(), DiscoveredEndpoints(empty))
		require.ErrorContains(t, err, "DiscoveredEndpoints: no endpoints")
	}
	runtime.KeepAlive(eps)
}

// TestDiscoveredEndpointsAreForgotten: the list of a GetEndpoints response
// is kept only while its endpoints are.
func TestDiscoveredEndpointsAreForgotten(t *testing.T) {
	t.Parallel()
	eps := testEndpoints()
	rememberEndpoints(eps)
	rememberEndpoints(eps) // twice: still one entry per endpoint
	keys := make([]weak.Pointer[ua.EndpointDescription], len(eps))
	for i, ep := range eps {
		keys[i] = weak.Make(ep)
	}
	require.Len(t, discoveredList(eps[2]), 3)
	require.Nil(t, discoveredList(nil))
	runtime.KeepAlive(eps) // the last use of the endpoints

	// Other tests of the package remember endpoints too: count the entries
	// of this test only. Cleanups run after a collection, on a goroutine of
	// the runtime.
	present := func() int {
		discovered.mu.Lock()
		defer discovered.mu.Unlock()
		n := 0
		for _, k := range keys {
			if _, ok := discovered.m[k]; ok {
				n++
			}
		}
		return n
	}
	for i := 0; i < 1000 && present() > 0; i++ {
		runtime.GC()
		runtime.Gosched()
	}
	require.Zero(t, present(), "entries left after the endpoints were collected")
}

// TestRefetchedEndpointsReplaceTheList: after a server certificate change the
// client compares the next CreateSession with the endpoints it fetched again,
// which carry the new certificate, when it compares a list at all.
func TestRefetchedEndpointsReplaceTheList(t *testing.T) {
	t.Parallel()
	rotated := testEndpoints()
	for _, e := range rotated {
		e.ServerCertificate = []byte{4, 5, 6}
	}
	list := func(c *Client) endpointList {
		if l := c.discoveredEndpoints.Load(); l != nil {
			return *l
		}
		return nil
	}
	newClient := func(opts ...Option) *Client {
		c, err := NewClient("opc.tcp://server:4840", append(opts, InsecureNoSecurity())...)
		require.NoError(t, err)
		return c
	}

	c := newClient(DiscoveredEndpoints(testEndpoints()))
	require.ErrorIs(t, verifyEndpointList(list(c), rotated), ua.StatusBadSecurityChecksFailed, "the old list has the old certificate")
	c.useRefetchedEndpoints(rotated)
	require.Equal(t, newEndpointList(rotated), list(c))
	require.NoError(t, verifyEndpointList(list(c), rotated))
	c.useRefetchedEndpoints(nil)
	require.Equal(t, newEndpointList(rotated), list(c), "an empty answer keeps the list")

	c = newClient()
	c.useRefetchedEndpoints(rotated)
	require.Nil(t, list(c), "no list, no comparison")
	c = newClient(DiscoveredEndpoints(testEndpoints()), InsecureSkipDiscoveredEndpointsCheck())
	c.useRefetchedEndpoints(rotated)
	require.Nil(t, list(c), "comparison off")
}
