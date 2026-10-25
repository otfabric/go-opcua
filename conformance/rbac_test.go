// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// rbacNodeSet declares nodes with per-role permissions:
//
//	Recipe   (Variable) anonymous: browse+read; Operator: browse+read+write
//	Secret   (Variable) SecurityAdmin only
//	Vault    (Object)   Operator: browse; holds Secret
//	Dispense (Method)   Operator: browse+call; anonymous: browse
const rbacNodeSet = `<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://otfabric.com/conformance/rbac</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasComponent">i=47</Alias>
    <Alias Alias="Organizes">i=35</Alias>
  </Aliases>
  <UAObject NodeId="ns=1;i=100" BrowseName="1:Vault">
    <DisplayName>Vault</DisplayName>
    <RolePermissions>
      <RolePermission Permissions="1">Operator</RolePermission>
      <RolePermission Permissions="131071">SecurityAdmin</RolePermission>
    </RolePermissions>
    <References>
      <Reference ReferenceType="Organizes" IsForward="false">i=85</Reference>
      <Reference ReferenceType="HasComponent">ns=1;i=101</Reference>
      <Reference ReferenceType="HasComponent">ns=1;i=102</Reference>
      <Reference ReferenceType="HasComponent">ns=1;i=103</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=101" BrowseName="1:Recipe" DataType="String">
    <DisplayName>Recipe</DisplayName>
    <RolePermissions>
      <RolePermission Permissions="33">Anonymous</RolePermission>
      <RolePermission Permissions="97">Operator</RolePermission>
      <RolePermission Permissions="131071">SecurityAdmin</RolePermission>
    </RolePermissions>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=100</Reference>
    </References>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=102" BrowseName="1:Secret" DataType="String">
    <DisplayName>Secret</DisplayName>
    <RolePermissions>
      <RolePermission Permissions="131071">SecurityAdmin</RolePermission>
    </RolePermissions>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=100</Reference>
    </References>
  </UAVariable>
  <UAMethod NodeId="ns=1;i=103" BrowseName="1:Dispense">
    <DisplayName>Dispense</DisplayName>
    <RolePermissions>
      <RolePermission Permissions="1">Anonymous</RolePermission>
      <RolePermission Permissions="4097">Operator</RolePermission>
    </RolePermissions>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=100</Reference>
    </References>
  </UAMethod>
</UANodeSet>`

// TestAccessControl_RolePermissionsPerUser enables role-based access control
// and verifies read, write, browse and call permissions per user identity.
func TestAccessControl_RolePermissionsPerUser(t *testing.T) {
	roleFor := map[string]ua.WellKnownRole{
		"olivia": ua.RoleOperator,
		"sam":    ua.RoleSecurityAdmin,
		"guest":  ua.RoleAuthenticatedUser,
	}
	srv, url := newServer(t,
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(user, pass string) error {
			if _, ok := roleFor[user]; ok && pass == user+"-pw" {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if u, ok := tok.(*ua.UserNameIdentityToken); ok {
				return []*ua.NodeID{roleFor[u.UserName].NodeID()}
			}
			return server.DefaultRoleMapper(tok)
		}),
		server.WithAccessController(server.NewRBACAccessController(nil)),
	)
	require.NoError(t, srv.ImportNodeSetXML([]byte(rbacNodeSet)))
	f := testutil.AddFixture(t, srv) // fixture nodes carry no role permissions
	ctx := context.Background()

	vault, recipe, secret, dispense := ua.NewNumericNodeID(1, 100), ua.NewNumericNodeID(1, 101), ua.NewNumericNodeID(1, 102), ua.NewNumericNodeID(1, 103)
	srv.RegisterMethod(vault, dispense, func(context.Context, *ua.NodeID, *ua.NodeID, []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		return []*ua.Variant{ua.MustVariant("dispensed")}, ua.StatusOK
	})
	// Give the imported variables a value.
	for node, v := range map[*ua.NodeID]string{recipe: "flour, water", secret: "the launch code"} {
		require.NoError(t, srv.Node(node).SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(v)))
	}

	ep := endpointFor(t, url, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone)
	login := func(user string) *opcua.Client {
		if user == "" {
			return newClient(t, url)
		}
		return newClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername(user, user+"-pw"))
	}
	denied := ua.StatusBadUserAccessDenied

	type expect struct {
		readRecipe, writeRecipe, readSecret, browseVault, call ua.StatusCode
	}
	for _, tc := range []struct {
		user string
		want expect
	}{
		{"", expect{readRecipe: ua.StatusOK, writeRecipe: denied, readSecret: denied, browseVault: denied, call: denied}},
		{"guest", expect{readRecipe: denied, writeRecipe: denied, readSecret: denied, browseVault: denied, call: denied}},
		{"olivia", expect{readRecipe: ua.StatusOK, writeRecipe: ua.StatusOK, readSecret: denied, browseVault: ua.StatusOK, call: ua.StatusOK}},
		{"sam", expect{readRecipe: ua.StatusOK, writeRecipe: ua.StatusOK, readSecret: ua.StatusOK, browseVault: ua.StatusOK, call: denied}},
	} {
		name := tc.user
		if name == "" {
			name = "anonymous"
		}
		t.Run(name, func(t *testing.T) {
			c := login(tc.user)

			dv, err := c.ReadValue(ctx, recipe)
			require.NoError(t, err)
			require.Equal(t, tc.want.readRecipe, dv.Status, "read Recipe")
			if tc.want.readRecipe != ua.StatusOK {
				require.Nil(t, dv.Value.Value(), "a denied read must not disclose the value")
			}

			dv, err = c.ReadValue(ctx, secret)
			require.NoError(t, err)
			require.Equal(t, tc.want.readSecret, dv.Status, "read Secret")
			if tc.want.readSecret == ua.StatusOK {
				require.Equal(t, "the launch code", dv.Value.Value())
			} else {
				require.Nil(t, dv.Value.Value())
			}

			st, err := c.WriteNodeValue(ctx, recipe, "changed by "+name)
			require.NoError(t, err)
			require.Equal(t, tc.want.writeRecipe, st, "write Recipe")

			res := browseOne(t, c, &ua.BrowseDescription{
				NodeID: vault, BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: refType(id.HasComponent),
			}, 0)
			require.Equal(t, tc.want.browseVault, res.StatusCode, "browse Vault")
			if tc.want.browseVault == ua.StatusOK {
				require.Equal(t, ids(recipe, secret, dispense), targets(res.References))
			} else {
				require.Empty(t, res.References)
			}

			call, err := c.CallMethod(ctx, vault, dispense)
			require.NoError(t, err)
			require.Equal(t, tc.want.call, call.StatusCode, "call Dispense")
			if tc.want.call == ua.StatusOK {
				require.Equal(t, "dispensed", call.OutputArguments[0].Value())
			} else {
				require.Empty(t, call.OutputArguments)
			}

			// Nodes without role permissions stay open to everybody.
			dv, err = c.ReadValue(ctx, f.Int32)
			require.NoError(t, err)
			require.Equal(t, ua.StatusOK, dv.Status)
		})
	}

	// The effect of the permitted writes: the last writer in table order is sam.
	dv, err := login("sam").ReadValue(ctx, recipe)
	require.NoError(t, err)
	require.Equal(t, "changed by sam", dv.Value.Value())

	// A wrong password is refused before any role is assigned.
	_, err = dialClient(t, url, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeUserName), opcua.AuthUsername("sam", "nope"))
	require.ErrorIs(t, err, ua.StatusBadUserAccessDenied)
}

// TestSecurity_CredentialsFromFiles connects with the certificate, private key
// and server certificate supplied as files.
func TestSecurity_CredentialsFromFiles(t *testing.T) {
	p := pki(t)
	f, url := secureServer(t)
	dir := t.TempDir()
	write := func(name, typ string, der []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
		return path
	}
	certPEM := write("client-cert.pem", "CERTIFICATE", p.ClientCert)
	keyPEM := write("client-key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(p.ClientKey))
	serverPEM := write("server-cert.pem", "CERTIFICATE", p.ServerCert)
	// DER files are accepted as well.
	certDER := filepath.Join(dir, "client-cert.der")
	require.NoError(t, os.WriteFile(certDER, p.ClientCert, 0o600))

	for name, certFile := range map[string]string{"PEM": certPEM, "DER": certDER} {
		t.Run(name, func(t *testing.T) {
			c := newClient(t, url,
				opcua.SecurityPolicy("Basic256Sha256"),
				opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
				opcua.RemoteCertificateFile(serverPEM),
				opcua.CertificateFile(certFile),
				opcua.PrivateKeyFile(keyPEM),
				opcua.TrustedCertificates(p.ServerCertX509),
			)
			require.Equal(t, ua.MessageSecurityModeSignAndEncrypt, c.SecurityMode())
			dv, err := c.ReadValue(context.Background(), f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())
		})
	}

	t.Run("MissingFiles", func(t *testing.T) {
		for _, opt := range []opcua.Option{
			opcua.CertificateFile(filepath.Join(dir, "nope.pem")),
			opcua.PrivateKeyFile(filepath.Join(dir, "nope.pem")),
			opcua.RemoteCertificateFile(filepath.Join(dir, "nope.pem")),
		} {
			_, err := opcua.NewClient(url, opt)
			require.Error(t, err)
		}
	})
}

// TestServer_LoggerOptions verifies both server logger options route the
// server's log records to the supplied logger.
func TestServer_LoggerOptions(t *testing.T) {
	for name, logOpt := range map[string]func(*slog.Logger) server.Option{
		"SetLogger":      server.SetLogger,
		"WithSlogLogger": server.WithSlogLogger,
	} {
		t.Run(name, func(t *testing.T) {
			logs := &logCounter{}
			srv, err := server.New(
				server.EndPoint("localhost", 0),
				server.EnableSecurity("None", ua.MessageSecurityModeNone),
				server.EnableAuthMode(ua.UserTokenTypeAnonymous),
				logOpt(slog.New(logs)),
			)
			require.NoError(t, err)
			require.NoError(t, srv.Start(context.Background()))
			t.Cleanup(func() { _ = srv.Close() })
			f := testutil.AddFixture(t, srv)
			require.NotZero(t, srv.Port(), "an OS-assigned port is reported after Start")

			url := fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
			c := newClient(t, url)
			dv, err := c.ReadValue(context.Background(), f.Int32)
			require.NoError(t, err)
			require.Equal(t, int32(42), dv.Value.Value())
			eps, err := c.GetEndpoints(context.Background())
			require.NoError(t, err)
			require.Equal(t, url, eps.Endpoints[0].EndpointURL)
			require.Equal(t, []string{url}, srv.URLs())

			// The server logged the session being created through our logger.
			require.Equal(t, 1, logs.Count("handling CreateSession request"))
		})
	}
}
