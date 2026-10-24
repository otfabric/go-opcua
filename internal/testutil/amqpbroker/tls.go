// SPDX-License-Identifier: MIT

package amqpbroker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// TestTLS returns a server configuration with a fresh certificate for
// 127.0.0.1 and localhost that verifies client certificates if a client
// presents one (for SASL EXTERNAL), and a client configuration that trusts
// it. With clientCert the client configuration carries a client
// certificate issued by the same test CA.
func TestTLS(clientCert bool) (server, client *tls.Config, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "amqpbroker test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}
	issue := func(serial int64, tmpl *x509.Certificate) (tls.Certificate, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		tmpl.SerialNumber = big.NewInt(serial)
		tmpl.NotBefore, tmpl.NotAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			return tls.Certificate{}, err
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
	}
	srv, err := issue(2, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "amqpbroker"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	})
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server = &tls.Config{
		Certificates: []tls.Certificate{srv},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	client = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if clientCert {
		cli, err := issue(3, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "amqp client"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return nil, nil, err
		}
		client.Certificates = []tls.Certificate{cli}
	}
	return server, client, nil
}
