// SPDX-License-Identifier: MIT

package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"slices"

	"github.com/otfabric/go-opcua/ua"
)

// The DefaultHttpsGroup (Part 12 §7.8.3): its certificate is the TLS
// certificate of the opc.https and opc.wss endpoints, which the TLS
// handshakes read for every new connection, and its trust list validates
// the TLS client certificates if HTTPSClientCertificates asks for them.

type tlsCertificate = tls.Certificate

// newTLSIdentity returns the certificate of the DefaultHttpsGroup for a
// certificate, its issuers and key.
func newTLSIdentity(cert []byte, issuers [][]byte, key crypto.Signer) *tlsIdentity {
	chain := append([][]byte{cert}, issuers...)
	return &tlsIdentity{
		cert:    cert,
		issuers: issuers,
		key:     key,
		tls:     &tls.Certificate{Certificate: chain, PrivateKey: key},
	}
}

// initialTLSIdentity is the certificate of the DefaultHttpsGroup a server
// starts with: the first certificate of TLSConfig, or else the RSA
// application instance certificate the TLS endpoints use without one. A
// TLSConfig with GetCertificate only leaves the group without a
// certificate until UpdateCertificate installs one.
func initialTLSIdentity(sc *serverConfig) *tlsIdentity {
	if c := sc.tlsConfig; c != nil {
		if len(c.Certificates) == 0 || len(c.Certificates[0].Certificate) == 0 {
			return nil
		}
		key, ok := c.Certificates[0].PrivateKey.(crypto.Signer)
		if !ok {
			return nil
		}
		x := c.Certificates[0]
		return &tlsIdentity{cert: x.Certificate[0], issuers: slices.Clone(x.Certificate[1:]), key: key, tls: &x}
	}
	if len(sc.certificate) == 0 || sc.privateKey == nil {
		return nil
	}
	return newTLSIdentity(sc.certificate, nil, sc.privateKey)
}

// tlsKeySupported reports whether crypto/tls can serve a certificate with
// the key: RSA of at least 2048 bits, ECDSA on a NIST curve, Ed25519.
func tlsKeySupported(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return true
		}
	case ed25519.PublicKey:
		return true
	}
	return false
}

// tlsConfig returns the TLS configuration of the opc.https and opc.wss
// listeners with the certificate of the DefaultHttpsGroup, which ApplyChanges
// replaces for the connections that follow, and with the TLS client
// certificate validation HTTPSClientCertificates selects.
func (m *pushManager) tlsConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	certs, getCert := cfg.Certificates, cfg.GetCertificate
	cfg.Certificates = nil
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if x := m.https.Load(); x != nil {
			return x.tls, nil
		}
		if getCert != nil {
			return getCert(hello)
		}
		if len(certs) > 0 {
			return &certs[0], nil
		}
		return nil, ua.StatusBadCertificateInvalid
	}
	switch m.cfg.HTTPSClientCertificates {
	case HTTPSClientCertificatesVerifyIfGiven:
		cfg.ClientAuth = tls.RequestClientCert
	case HTTPSClientCertificatesRequire:
		cfg.ClientAuth = tls.RequireAnyClientCert
	case HTTPSClientCertificatesIgnore:
		return cfg
	}
	cfg.ClientCAs = nil
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		return m.verifyTLSClient(raw)
	}
	return cfg
}

// verifyTLSClient validates the TLS client certificate chain against the
// trust list of the DefaultHttpsGroup. Without a certificate it passes; the
// TLS configuration has refused that already where one is required.
func (m *pushManager) verifyTLSClient(raw [][]byte) error {
	if len(raw) == 0 {
		return nil
	}
	var chain []byte
	for _, c := range raw {
		chain = append(chain, c...)
	}
	if sc := m.validateWith(groupHTTPS, chain); sc != ua.StatusOK {
		return sc
	}
	return nil
}
