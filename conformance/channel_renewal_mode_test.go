// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// A SecureChannel keeps the security mode it was opened with. A renewal that
// names another mode must be refused by the server with
// BadSecurityModeRejected; it used to be stored as the channel's new mode,
// which let a renewal downgrade SignAndEncrypt to Sign.
func TestChannelRenewal_ModeChangeIsRefused(t *testing.T) {
	parallel(t)
	p := pki(t)
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.EnableSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign),
		server.EnableSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	url := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	open := func(t *testing.T, mode ua.MessageSecurityMode) (*uasc.SecureChannel, *uasc.Config) {
		conn, err := uacp.Dial(ctx, url)
		require.NoError(t, err)
		cfg := &uasc.Config{
			SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			SecurityMode:      mode,
			Certificate:       p.ClientCert,
			LocalKey:          p.ClientKey,
			RemoteCertificate: p.ServerCert,
			Lifetime:          uint32(time.Hour / time.Millisecond),
			RequestTimeout:    10 * time.Second,
			Logger:            slog.New(slog.DiscardHandler),
		}
		sc, err := uasc.NewSecureChannel(url, conn, cfg, make(chan error, 8))
		require.NoError(t, err)
		t.Cleanup(func() { _ = sc.Close() })
		require.NoError(t, sc.Open(ctx))
		return sc, cfg
	}

	t.Run("SameModeIsRenewed", func(t *testing.T) {
		sc, _ := open(t, ua.MessageSecurityModeSignAndEncrypt)
		require.NoError(t, sc.Renew(ctx))
		require.NoError(t, sc.Renew(ctx))
	})

	for _, tc := range []struct {
		name          string
		opened, renew ua.MessageSecurityMode
	}{
		{"DowngradeIsRefused", ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign},
		{"UpgradeIsRefused", ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, cfg := open(t, tc.opened)
			require.NoError(t, sc.Renew(ctx))

			// The next renewal asks for a mode the channel was not opened with.
			cfg.SecurityMode = tc.renew
			err := sc.Renew(ctx)
			require.ErrorIs(t, err, ua.StatusBadSecurityModeRejected)
		})
	}
}
