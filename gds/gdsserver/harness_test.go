// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil/leakcheck"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

func TestMain(m *testing.M) { leakcheck.Main(m) }

// Users of the test server and the roles they get.
const (
	userDiscoveryAdmin = "dadmin"
	userCAAdmin        = "caadmin"
	userSecurityAdmin  = "secadmin"
	userPlain          = "user"
	password           = "pw"
)

var p256Type = ua.NewNumericNodeID(0, id.EccNistP256ApplicationCertificateType)

// env is a GDS on a server with ECC endpoints.
type env struct {
	t     *testing.T
	srv   *server.Server
	gds   *GDS
	url   string
	store *MemoryStore
	cfg   Config
}

func pkiOf(t *testing.T) *testpki.PKI {
	t.Helper()
	p, err := testpki.Get()
	require.NoError(t, err)
	return p
}

// newEnv starts a GDS whose application group issues NIST P-256
// certificates (cheap keys) unless cfg sets other types.
func newEnv(t *testing.T, cfg Config) *env {
	t.Helper()
	if cfg.CertificateTypes == nil {
		cfg.CertificateTypes = []*ua.NodeID{p256Type}
	}
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	e := &env{t: t, cfg: cfg}
	e.store, _ = cfg.Store.(*MemoryStore)
	e.start()
	return e
}

func (e *env) start() {
	t := e.t
	t.Helper()
	ecc := pkiOf(t).ECC
	var g atomic.Pointer[GDS]
	srv, err := server.New(
		server.EndPoint("localhost", 0),
		server.ApplicationIdentity(ecc.Server[testpki.CurveP256].Cert, ecc.Server[testpki.CurveP256].Key),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSign),
		server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if pass != password {
				return ua.StatusBadUserAccessDenied
			}
			return nil
		}),
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			u, ok := tok.(*ua.UserNameIdentityToken)
			if !ok {
				return server.DefaultRoleMapper(tok)
			}
			roles := []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID()}
			switch u.UserName {
			case userDiscoveryAdmin:
				roles = append(roles, g.Load().DiscoveryAdminRole())
			case userCAAdmin:
				roles = append(roles, g.Load().CertificateAuthorityAdminRole())
			case userSecurityAdmin:
				roles = append(roles, ua.RoleSecurityAdmin.NodeID())
			}
			return roles
		}),
	)
	require.NoError(t, err)
	gd, err := Attach(srv, e.cfg)
	require.NoError(t, err)
	g.Store(gd)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	e.srv, e.gds = srv, gd
	e.url = fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
}

// restart replaces the server by a new one with the same Store.
func (e *env) restart() {
	e.t.Helper()
	e.gds.Close()
	require.NoError(e.t, e.srv.Close())
	e.start()
}

// dialOpts are the options of a client.
type dialOpts struct {
	mode ua.MessageSecurityMode
	user string // "" for anonymous
	cert []byte
	key  crypto.Signer
}

func (e *env) dial(o dialOpts) *opcua.Client {
	e.t.Helper()
	c, err := e.tryDial(o)
	require.NoError(e.t, err)
	return c
}

func (e *env) tryDial(o dialOpts) (*opcua.Client, error) {
	t := e.t
	t.Helper()
	ecc := pkiOf(t).ECC
	if o.mode == 0 {
		o.mode = ua.MessageSecurityModeSignAndEncrypt
	}
	tok := ua.UserTokenTypeAnonymous
	if o.user != "" {
		tok = ua.UserTokenTypeUserName
	}
	opts := []opcua.Option{
		opcua.DialTimeout(30 * time.Second),
		opcua.RequestTimeout(30 * time.Second),
		opcua.AutoReconnect(false),
	}
	if o.mode == ua.MessageSecurityModeNone {
		opts = append(opts, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.SecurityPolicy("None"))
		if o.user != "" {
			opts = append(opts, opcua.AuthUsername(o.user, password))
		} else {
			opts = append(opts, opcua.AuthAnonymous())
		}
	} else {
		ep := e.endpoint(o.mode)
		cert, key := ecc.Client[testpki.CurveP256].Cert, ecc.Client[testpki.CurveP256].Key
		if o.cert != nil {
			cert, key = o.cert, o.key
		}
		opts = append(opts,
			opcua.SecurityFromEndpoint(ep, tok),
			opcua.Certificate(cert),
			opcua.TrustedCertificates(ecc.Server[testpki.CurveP256].X509),
		)
		opts = append(opts, opcua.PrivateKeySigner(key))
		if o.user != "" {
			opts = append(opts, opcua.AuthUsername(o.user, password))
		}
	}
	c, err := opcua.NewClient(e.url, opts...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		_ = c.Close(context.Background())
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, nil
}

func (e *env) endpoint(mode ua.MessageSecurityMode) *ua.EndpointDescription {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, e.url)
	require.NoError(e.t, err)
	for _, ep := range eps {
		if ep.SecurityPolicyURI == ua.SecurityPolicyURIECCNistP256 && ep.SecurityMode == mode {
			return ep
		}
	}
	e.t.Fatalf("no endpoint %v", mode)
	return nil
}

// pull returns a PullClient over a new client.
func (e *env) pull(o dialOpts) *gds.PullClient { return gds.NewPullClient(e.dial(o)) }

func (e *env) admin() *gds.PullClient     { return e.pull(dialOpts{user: userDiscoveryAdmin}) }
func (e *env) caAdmin() *gds.PullClient   { return e.pull(dialOpts{user: userCAAdmin}) }
func (e *env) anonymous() *gds.PullClient { return e.pull(dialOpts{}) }

// record returns the record of a server application.
func record(uri string, urls ...string) *gds.ApplicationRecord {
	if len(urls) == 0 {
		urls = []string{"opc.tcp://localhost:4840"}
	}
	return &gds.ApplicationRecord{
		ApplicationURI:   uri,
		ApplicationType:  ua.ApplicationTypeServer,
		ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedText("App " + uri)},
		ProductURI:       "urn:otfabric:product",
		DiscoveryURLs:    urls,
	}
}

// clientRecord is the record of the test client application.
func clientRecord() *gds.ApplicationRecord {
	r := record(testpki.ClientAppURI)
	r.ApplicationType = ua.ApplicationTypeClient
	r.DiscoveryURLs = nil
	return r
}

// selfAdminAll accepts every certificate with the URI of the record.
func selfAdminAll(*gds.ApplicationRecord, *x509.Certificate) bool { return true }

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// clock is a Config.Now that tests move forward.
type clock struct{ offset atomic.Int64 }

func (c *clock) now() time.Time          { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *clock) advance(d time.Duration) { c.offset.Add(int64(d)) }
