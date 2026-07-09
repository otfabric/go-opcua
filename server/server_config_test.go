// SPDX-License-Identifier: MIT

package server

import (
	"log/slog"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestServerConfigOptions(t *testing.T) {
	logger := slog.Default()
	srv, err := New(
		ServerName("TestServer"),
		ManufacturerName("OTFabric"),
		ProductName("go-opcua"),
		SoftwareVersion("1.0"),
		SetLogger(logger),
		WithSlogLogger(logger),
	)
	require.NoError(t, err)
	require.Equal(t, "TestServer", srv.cfg.applicationName)
	require.Equal(t, "OTFabric", srv.cfg.manufacturerName)
	require.Equal(t, "go-opcua", srv.cfg.productName)
	require.Equal(t, "1.0", srv.cfg.softwareVersion)
	require.Equal(t, logger, srv.cfg.logger)
}

func TestServerConfigEnableSecurityAndAuth(t *testing.T) {
	_, err := New(
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
}

func TestDefaultChannelConfig(t *testing.T) {
	cfg := defaultChannelConfig()
	require.NotNil(t, cfg)
	require.Equal(t, ua.SecurityPolicyURINone, cfg.SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeNone, cfg.SecurityMode)
}

func TestServerStatus(t *testing.T) {
	srv := newTestServer()
	status := srv.Status()
	require.NotNil(t, status)
	if status.CurrentTime.IsZero() {
		t.Fatal("Status.CurrentTime should not be zero")
	}
}

func TestServerURLs(t *testing.T) {
	srv, err := New(EndPoint("localhost", 4840))
	require.NoError(t, err)
	urls := srv.URLs()
	// May be empty before Start() but should not panic.
	_ = urls
}

// TestChangeNotification_BeforeStart verifies that calling ChangeNotification
// before Start() does not panic (MonitoredItemService is nil until Start).
func TestChangeNotification_BeforeStart(t *testing.T) {
	// New() does not call Start, so MonitoredItemService is nil here.
	srv, err := New(EndPoint("localhost", 0))
	require.NoError(t, err)
	nid := ua.NewNumericNodeID(0, 1)
	require.NotPanics(t, func() {
		srv.ChangeNotification(nid)
	})
}
