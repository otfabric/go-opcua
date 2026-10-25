// SPDX-License-Identifier: MIT

package testpki

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
)

// TLSPKI holds TLS certificates for the HTTPS and WebSocket transports
// (Part 6 §7.4, §7.5): a CA, a server certificate for localhost and
// 127.0.0.1 issued by it, a client certificate issued by it and a
// self-signed server certificate nobody trusts. They are P-256 certificates,
// separate from the application instance certificates, as the TLS
// certificates of an OPC UA application may be.
type TLSPKI struct {
	CA       *Identity
	Server   tls.Certificate
	Client   tls.Certificate
	Stranger tls.Certificate
	// Roots holds the CA only.
	Roots *x509.CertPool
}

var (
	tlsOnce sync.Once
	tlsVal  *TLSPKI
	tlsErr  error
)

// TLS returns the TLS PKI of this test binary, building it on first use.
func TLS() (*TLSPKI, error) {
	tlsOnce.Do(func() { tlsVal, tlsErr = buildTLS() })
	return tlsVal, tlsErr
}

func buildTLS() (*TLSPKI, error) {
	ca, err := newCA()
	if err != nil {
		return nil, err
	}
	p := &TLSPKI{CA: ca, Roots: x509.NewCertPool()}
	p.Roots.AddCert(ca.X509)

	leaf := func(cn string, issuer *Identity) (tls.Certificate, error) {
		var (
			id  *Identity
			err error
		)
		if issuer != nil {
			id, err = NewIdentity(CurveP256, cn, "", issuer.X509, issuer.Key)
		} else {
			id, err = NewIdentity(CurveP256, cn, "", nil, nil)
		}
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.Certificate{Certificate: [][]byte{id.Cert}, PrivateKey: id.Key, Leaf: id.X509}, nil
	}
	if p.Server, err = leaf("tls server", ca); err != nil {
		return nil, err
	}
	if p.Client, err = leaf("tls client", ca); err != nil {
		return nil, err
	}
	if p.Stranger, err = leaf("tls stranger", nil); err != nil {
		return nil, err
	}
	return p, nil
}

// newCA creates a self-signed P-256 CA.
func newCA() (*Identity, error) {
	id, err := NewIdentity(CurveP256, "tls CA", "", nil, nil)
	if err != nil {
		return nil, err
	}
	tmpl := id.X509
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	tmpl.DNSNames = nil
	tmpl.IPAddresses = []net.IP{}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.Key.Public(), id.Key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Identity{Cert: der, Key: id.Key, X509: parsed}, nil
}

// ServerConfig returns a TLS configuration that serves the server
// certificate.
func (p *TLSPKI) ServerConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{p.Server}, MinVersion: tls.VersionTLS12}
}

// ClientConfig returns a TLS configuration that trusts the CA only.
func (p *TLSPKI) ClientConfig() *tls.Config {
	return &tls.Config{RootCAs: p.Roots, MinVersion: tls.VersionTLS12}
}
