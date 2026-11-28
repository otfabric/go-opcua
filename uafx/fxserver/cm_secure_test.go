// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
)

// TestConnectionManagerSecure: a ConnectionManager on a SignAndEncrypt
// Basic256Sha256 endpoint with user names and a CMAuthorizer. The user
// "admin" may edit, process and write the file, the user "viewer" may only
// read; a revocation between Open and CloseAndUpdate makes CloseAndUpdate
// Bad_UserAccessDenied and changes nothing (Part 81 F.3.3: "The Client
// shall be authorized to modify the configuration").
func TestConnectionManagerSecure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	der, key, err := testpki.SelfSigned("cm", appURI)
	require.NoError(t, err)
	srvCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	users := map[string]string{"admin": "admin-secret", "viewer": "viewer-secret"}
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.ApplicationURI(appURI),
		server.Certificate(der), server.PrivateKey(key),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if p, ok := users[user]; ok && p == pass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}))
	require.NoError(t, err)
	ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
	require.NoError(t, err)
	m, err := fxcm.New(fxcm.Options{Dialer: offlineDialer{}, ApplicationURI: "urn:test:cm", Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = m.Close() })
	_, err = m.Add(cmConf("Line1"))
	require.NoError(t, err)

	var revoked atomic.Bool
	var asked atomic.Int32
	authorize := func(_ context.Context, r fxserver.CMRequest) ua.StatusCode {
		asked.Add(1)
		var tok ua.IdentityToken
		var mode ua.MessageSecurityMode
		switch {
		case r.Caller != nil:
			tok, mode = r.Caller.Identity, r.Caller.SecurityMode
		case r.Session != nil:
			return ua.StatusBadUserAccessDenied // no Variable writes in this test
		}
		u, ok := tok.(*ua.UserNameIdentityToken)
		if !ok || u.UserName != "admin" || revoked.Load() || mode != ua.MessageSecurityModeSignAndEncrypt {
			return ua.StatusBadUserAccessDenied
		}
		return ua.StatusOK
	}
	cm, err := fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{
		Manager: m, Editable: true, File: true, Authorizer: authorize, Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	cleanup.Register(t, func() { _ = cm.Close() })
	require.NoError(t, srv.Start(ctx))
	cleanup.Register(t, func() { _ = srv.Close() })

	connect := func(user string) *opcua.Client {
		t.Helper()
		cder, ckey, err := testpki.SelfSigned(user, "urn:test:"+user)
		require.NoError(t, err)
		addr := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
		eps, err := opcua.GetEndpoints(ctx, addr)
		require.NoError(t, err)
		ep, err := opcua.SelectEndpoint(eps, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, cder)
		require.NoError(t, err)
		c, err := opcua.NewClient(addr, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName),
			opcua.ApplicationURI("urn:test:"+user), opcua.AutoReconnect(false),
			opcua.Certificate(cder), opcua.PrivateKey(ckey), opcua.TrustedCertificates(srvCert),
			opcua.AuthUsername(user, users[user]))
		require.NoError(t, err)
		require.NoError(t, c.Connect(ctx))
		cleanup.Register(t, func() { _ = c.Close(ctx) })
		return c
	}
	admin, viewer := connect("admin"), connect("viewer")
	set, ok := cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
	require.True(t, ok)

	file := ua.NewStringNodeID(ns.CM, "cm.File")
	call := func(c *opcua.Client, name string, args ...any) ([]*ua.Variant, ua.StatusCode) {
		t.Helper()
		in := make([]*ua.Variant, len(args))
		for i, a := range args {
			in[i] = ua.MustVariant(a)
		}
		res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: file, MethodID: ua.NewStringNodeID(ns.CM, "cm.File."+name), InputArguments: in})
		require.NoError(t, err)
		return res.OutputArguments, res.StatusCode
	}

	// The viewer reads the sets but changes nothing: all its sets refused
	// is the Method result Bad_UserAccessDenied (Tables 81 and 85).
	_, _, err = uafx.EditConnectionConfigurationSets(ctx, viewer, uafx.StartEditing, []*ua.NodeID{set})
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	_, _, err = uafx.ProcessConnectionConfigurationSets(ctx, viewer, uafx.ActionEstablishConnections, []*ua.NodeID{set})
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
	var sc ua.StatusCode
	_, sc = call(viewer, "Open", uint8(0x06))
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	out, sc := call(viewer, "Open", uint8(0x01))
	require.Equal(t, ua.StatusOK, sc, "reading the file needs no authorization")
	_, sc = call(viewer, "Close", out[0].Value().(uint32))
	require.Equal(t, ua.StatusOK, sc)

	// The admin edits and leaves the edit.
	sc, rs, err := uafx.EditConnectionConfigurationSets(ctx, admin, uafx.StartEditing, []*ua.NodeID{set})
	require.NoError(t, err)
	assert.Equal(t, ua.StatusGood, sc)
	assert.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)
	_, rs, err = uafx.EditConnectionConfigurationSets(ctx, admin, uafx.DiscardUpdates, []*ua.NodeID{set})
	require.NoError(t, err)
	assert.Equal(t, []ua.StatusCode{ua.StatusGood}, rs)

	// Open as the admin, revoke, CloseAndUpdate: refused, nothing added.
	body, err := fxcm.EncodeFile([]*uafx.ConnectionConfigurationSetConf{cmConf("Line2")})
	require.NoError(t, err)
	out, sc = call(admin, "Open", uint8(0x06))
	require.Equal(t, ua.StatusOK, sc)
	h := out[0].Value().(uint32)
	_, sc = call(admin, "Write", h, body)
	require.Equal(t, ua.StatusOK, sc)
	revoked.Store(true)
	before := asked.Load()
	_, sc = call(admin, "CloseAndUpdate", h, true, []byte{byte(uafx.ElementAdd)})
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)
	assert.Greater(t, asked.Load(), before, "CloseAndUpdate asked the authorizer")
	_, ok = cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line2"})
	assert.False(t, ok, "a refused CloseAndUpdate adds nothing")
	assert.Len(t, m.Keys(), 1)
	_, sc = call(admin, "Close", h)
	assert.Equal(t, ua.StatusBadInvalidArgument, sc, "the refused CloseAndUpdate closed the handle")
	_, sc = call(admin, "Open", uint8(0x06))
	assert.Equal(t, ua.StatusBadUserAccessDenied, sc)

	// Granted again: the same file applies.
	revoked.Store(false)
	out, sc = call(admin, "Open", uint8(0x06))
	require.Equal(t, ua.StatusOK, sc, "the refused handle no longer blocks a writer")
	h = out[0].Value().(uint32)
	_, sc = call(admin, "Write", h, body)
	require.Equal(t, ua.StatusOK, sc)
	out, sc = call(admin, "CloseAndUpdate", h, true, []byte{byte(uafx.ElementAdd)})
	require.Equal(t, ua.StatusOK, sc)
	assert.Equal(t, true, out[0].Value())
	_, ok = cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line2"})
	assert.True(t, ok)
}
