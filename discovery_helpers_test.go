// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestPackageFindServers(t *testing.T) {
	t.Parallel()
	_, url := testutil.NewTestServer(t)
	servers, err := opcua.FindServers(context.Background(), url)
	require.NoError(t, err)
	require.NotEmpty(t, servers)
}

func TestPackageGetEndpoints(t *testing.T) {
	t.Parallel()
	_, url := testutil.NewTestServer(t)
	eps, err := opcua.GetEndpoints(context.Background(), url)
	require.NoError(t, err)
	require.NotEmpty(t, eps)
}

func TestPackageFindServersOnNetwork(t *testing.T) {
	t.Parallel()
	_, url := testutil.NewTestServer(t)
	_, err := opcua.FindServersOnNetwork(context.Background(), url)
	require.Error(t, err)
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)
}

func TestDiscoveryURL(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]string{
		"press7":                     "opc.tcp://press7:4840",
		"press7.factory.example":     "opc.tcp://press7.factory.example:4840",
		"192.0.2.7":                  "opc.tcp://192.0.2.7:4840",
		"fe80::1":                    "opc.tcp://[fe80::1]:4840",
		"[fe80::1]":                  "opc.tcp://[fe80::1]:4840",
		"press7:4855":                "opc.tcp://press7:4855",
		"[fe80::1]:4855":             "opc.tcp://[fe80::1]:4855",
		"opc.tcp://press7:4855/path": "opc.tcp://press7:4855/path",
	} {
		require.Equal(t, want, opcua.DiscoveryURL(host), host)
	}
	require.Equal(t, 4840, opcua.DiscoveryPort)
}

// dialOnly opens a SecureChannel without a session, which is all the
// discovery services need.
func dialOnly(t *testing.T, url string) *opcua.Client {
	t.Helper()
	c, err := opcua.NewClient(url, opcua.InsecureNoSecurity(), opcua.AutoReconnect(false), opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(30*time.Second))
	require.NoError(t, err)
	require.NoError(t, c.Dial(context.Background()))
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func TestClientRegisterServer(t *testing.T) {
	t.Parallel()
	srv, url := testutil.NewTestServer(t,
		server.ApplicationURI("urn:test:lds"),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()),
	)
	c := dialOnly(t, url)
	ctx := context.Background()

	rs := &ua.RegisteredServer{
		ServerURI:     "urn:test:registered",
		ServerNames:   []*ua.LocalizedText{ua.NewLocalizedText("Registered")},
		ServerType:    ua.ApplicationTypeServer,
		DiscoveryURLs: []string{"opc.tcp://somewhere:4841"},
		IsOnline:      true,
	}
	resp, err := c.RegisterServer(ctx, rs)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.ResponseHeader.ServiceResult)

	// RegisterServer2 takes configuration values and ready-made extension
	// objects alike.
	resp2, err := c.RegisterServer2(ctx, rs,
		&ua.MdnsDiscoveryConfiguration{MdnsServerName: "Registered", ServerCapabilities: []string{"DA"}},
		ua.NewExtensionObject(&ua.MdnsDiscoveryConfiguration{MdnsServerName: "Again"}),
	)
	require.NoError(t, err)
	require.Equal(t, []ua.StatusCode{ua.StatusBadNotSupported, ua.StatusBadNotSupported}, resp2.ConfigurationResults)
	require.Len(t, srv.RegisteredServers(), 1)

	found, err := c.FindServersWithFilter(ctx, []string{"en"}, []string{"urn:test:registered"})
	require.NoError(t, err)
	require.Len(t, found.Servers, 1)
	require.Equal(t, "Registered", found.Servers[0].ApplicationName.Text)

	_, err = c.FindServersOnNetworkWithFilter(ctx, 0, 10, []string{"DA"})
	require.ErrorIs(t, err, ua.StatusBadServiceUnsupported)

	res, err := opcua.DiscoverServers(ctx, url)
	require.NoError(t, err)
	require.Equal(t, url, res.DiscoveryServerURL)
	require.Len(t, res.Servers, 2)
	require.False(t, res.MulticastSupported)

	rs.IsOnline = false
	_, err = c.RegisterServer(ctx, rs)
	require.NoError(t, err)
	_, err = c.RegisterServer(ctx, rs)
	require.ErrorIs(t, err, ua.StatusBadNothingToDo)
	_, err = c.RegisterServer2(ctx, nil)
	require.ErrorIs(t, err, ua.StatusBadServerURIInvalid, "no server: an empty one on the wire")
}

func TestDiscoverServersErrors(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := opcua.DiscoverServers(ctx, "127.0.0.1:1", opcua.DialTimeout(2*time.Second))
	require.Error(t, err)
	_, err = opcua.DiscoverServers(ctx, "host", opcua.SecurityPolicy("no such policy"))
	require.Error(t, err)
}
