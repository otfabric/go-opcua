// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// genTestKeyAndCert returns an RSA private key and self-signed DER certificate
// suitable for server config tests.
func genTestKeyAndCert(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	appURI, _ := url.Parse("urn:test:server")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		URIs:         []*url.URL{appURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}

func TestServerOption_PrivateKey(t *testing.T) {
	key, _ := genTestKeyAndCert(t)
	srv, err := New(PrivateKey(key))
	require.NoError(t, err)
	require.Equal(t, key, srv.cfg.privateKey)
}

func TestServerOption_Certificate(t *testing.T) {
	_, der := genTestKeyAndCert(t)
	srv, err := New(Certificate(der))
	require.NoError(t, err)
	require.Equal(t, der, srv.cfg.certificate)
	require.Equal(t, "urn:test:server", srv.cfg.applicationURI)
}

func TestServerOption_Certificate_InvalidDER(t *testing.T) {
	_, err := New(Certificate([]byte("not-a-cert")))
	require.Error(t, err)
}

func TestServerOption_ListenOn(t *testing.T) {
	srv, err := New(ListenOn("0.0.0.0:4840"))
	require.NoError(t, err)
	require.Equal(t, "opc.tcp://0.0.0.0:4840", srv.cfg.listenAddr)
}

func TestServerOption_WithUsernameValidator(t *testing.T) {
	called := false
	v := UsernameValidator(func(username, password string) error {
		called = true
		return nil
	})
	srv, err := New(WithUsernameValidator(v))
	require.NoError(t, err)
	require.NotNil(t, srv.cfg.usernameValidator)
	_ = srv.cfg.usernameValidator("u", "p")
	require.True(t, called)
}

func TestServerOption_WithX509UserValidator(t *testing.T) {
	called := false
	v := X509UserValidator(func(certDER []byte) error {
		called = true
		return nil
	})
	srv, err := New(WithX509UserValidator(v))
	require.NoError(t, err)
	require.NotNil(t, srv.cfg.x509UserValidator)
	_ = srv.cfg.x509UserValidator(nil)
	require.True(t, called)
}

func TestServerOption_AllowUsernameOnNone(t *testing.T) {
	srv, err := New(AllowUsernameOnNone())
	require.NoError(t, err)
	require.True(t, srv.cfg.allowUsernameOnNone)
}

func TestServerOption_WithRoleMapper(t *testing.T) {
	called := false
	rm := RoleMapper(func(token ua.IdentityToken) []*ua.NodeID {
		called = true
		return nil
	})
	srv, err := New(WithRoleMapper(rm))
	require.NoError(t, err)
	require.NotNil(t, srv.cfg.roleMapper)
	_ = srv.cfg.roleMapper(nil)
	require.True(t, called)
}
