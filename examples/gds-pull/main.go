// SPDX-License-Identifier: MIT

// Example gds-pull demonstrates the pull model of OPC UA Part 12: a Global
// Discovery Server (package gdsserver) issues an application instance
// certificate, and gds.PullClient obtains it and applies it to a server and
// a client.
//
// Everything runs in one process:
//
//  1. a GDS on opc.tcp://localhost:4850 with a generated CA, approving every
//     request (gdsserver.Config.AutoApprove),
//  2. an administrator (DiscoveryAdmin and CertificateAuthorityAdmin) that
//     registers a server application and enrolls it (gds.PullClient.Enroll),
//  3. the enrolled server, started with Enrollment.ServerOptions, and a
//     client enrolled the same way that connects to it.
//
// Usage:
//
//	go run ./examples/gds-pull
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/gds/gdsserver"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

const (
	adminUser = "admin"
	adminPass = "admin-pw"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	gdsURL, stop := startGDS(ctx)
	defer stop()

	admin, closeAdmin := connectAdmin(ctx, gdsURL)
	defer closeAdmin()

	// Enroll a server: the GDS registers it, generates its key and issues
	// the certificate.
	srvEnroll, err := admin.Enroll(ctx, &gds.EnrollRequest{
		Record: &gds.ApplicationRecord{
			ApplicationURI:   "urn:example:gds-pull:server",
			ApplicationType:  ua.ApplicationTypeServer,
			ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedText("Enrolled server")},
			ProductURI:       "urn:example:gds-pull",
			DiscoveryURLs:    []string{"opc.tcp://localhost:4851"},
		},
		CertificateType: gds.EccNistP256ApplicationCertificateType,
		PollInterval:    100 * time.Millisecond,
	})
	if err != nil {
		log.Fatalf("enroll the server: %v", err)
	}
	cert, _ := x509.ParseCertificate(srvEnroll.Certificate)
	log.Printf("server certificate %q issued by %q, %d trusted certificates", cert.Subject.CommonName, cert.Issuer.CommonName, len(srvEnroll.TrustList.TrustedCertificates))

	// Enroll a client with a key of its own (StartSigningRequest).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cliEnroll, err := admin.Enroll(ctx, &gds.EnrollRequest{
		Record: &gds.ApplicationRecord{
			ApplicationURI:   "urn:example:gds-pull:client",
			ApplicationType:  ua.ApplicationTypeClient,
			ApplicationNames: []*ua.LocalizedText{ua.NewLocalizedText("Enrolled client")},
			ProductURI:       "urn:example:gds-pull",
		},
		CertificateType: gds.EccNistP256ApplicationCertificateType,
		Key:             key,
		PollInterval:    100 * time.Millisecond,
	})
	if err != nil {
		log.Fatalf("enroll the client: %v", err)
	}

	// The enrolled server trusts what the GDS trusts.
	srv, err := server.New(append(srvEnroll.ServerOptions(),
		server.EndPoint("localhost", 4851),
		server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)...)
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	opts, err := cliEnroll.ClientOptions()
	if err != nil {
		log.Fatal(err)
	}
	c, err := dial(ctx, "opc.tcp://localhost:4851", ua.UserTokenTypeAnonymous, opts...)
	if err != nil {
		log.Fatalf("connect with the enrolled certificates: %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	log.Printf("the enrolled client is connected to the enrolled server")
}

// startGDS starts a server with a GDS on port 4850.
func startGDS(ctx context.Context) (string, func()) {
	cert, key := selfSigned("urn:example:gds-pull:gds", "localhost")
	var g atomic.Pointer[gdsserver.GDS]
	srv, err := server.New(
		server.EndPoint("localhost", 4850),
		server.ApplicationIdentity(cert, key),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(func(user, pass string) error {
			if user == adminUser && pass == adminPass {
				return nil
			}
			return ua.StatusBadUserAccessDenied
		}),
		// The administrator manages the directory and the CA.
		server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
			if u, ok := tok.(*ua.UserNameIdentityToken); ok && u.UserName == adminUser {
				return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), g.Load().DiscoveryAdminRole(), g.Load().CertificateAuthorityAdminRole()}
			}
			return server.DefaultRoleMapper(tok)
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	gd, err := gdsserver.Attach(srv, gdsserver.Config{
		CertificateTypes: []*ua.NodeID{gds.EccNistP256ApplicationCertificateType},
		AutoApprove:      true,
	})
	if err != nil {
		log.Fatal(err)
	}
	g.Store(gd)
	if err := srv.Start(ctx); err != nil {
		log.Fatal(err)
	}
	return "opc.tcp://localhost:4850", func() {
		gd.Close()
		_ = srv.Close()
	}
}

// connectAdmin connects to the GDS as the administrator, over
// SignAndEncrypt as the GDS requires for certificate requests.
func connectAdmin(ctx context.Context, gdsURL string) (*gds.PullClient, func()) {
	cert, key := selfSigned("urn:example:gds-pull:admin", "localhost")
	c, err := dial(ctx, gdsURL, ua.UserTokenTypeUserName,
		opcua.Certificate(cert),
		opcua.PrivateKeySigner(key),
		opcua.AuthUsername(adminUser, adminPass),
		opcua.InsecureSkipVerify(), // the example does not validate the self-signed GDS certificate
	)
	if err != nil {
		log.Fatalf("connect to the GDS: %v", err)
	}
	return gds.NewPullClient(c), func() { _ = c.Close(context.Background()) }
}

// dial connects over the ECC_nistP256 SignAndEncrypt endpoint of url.
func dial(ctx context.Context, endpoint string, tok ua.UserTokenType, opts ...opcua.Option) (*opcua.Client, error) {
	eps, err := opcua.GetEndpoints(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	var ep *ua.EndpointDescription
	for _, e := range eps {
		if e.SecurityPolicyURI == ua.SecurityPolicyURIECCNistP256 && e.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
			ep = e
		}
	}
	if ep == nil {
		return nil, fmt.Errorf("%s has no ECC_nistP256 SignAndEncrypt endpoint", endpoint)
	}
	c, err := opcua.NewClient(endpoint, append(opts, opcua.SecurityFromEndpoint(ep, tok), opcua.AutoReconnect(false))...)
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// selfSigned makes a self-signed ECDSA P-256 application instance
// certificate.
func selfSigned(uri, host string) ([]byte, crypto.Signer) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: uri},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		log.Fatal(err)
	}
	return der, key
}
