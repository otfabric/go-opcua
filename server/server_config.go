// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

// Option is an option function type to modify the configuration.
type Option func(*serverConfig) error

// PrivateKey sets the RSA private key in the secure channel configuration.
func PrivateKey(key *rsa.PrivateKey) Option {
	return func(s *serverConfig) error {
		s.privateKey = key
		return nil
	}
}

// EndPoint adds an advertised endpoint to the server based on the host name
// and port.  The first EndPoint registered is also used as the TCP bind
// address unless ListenOn is called explicitly.
func EndPoint(host string, port int) Option {
	return func(s *serverConfig) error {
		if s.endpoints == nil {
			s.endpoints = make([]string, 0)
		}
		ep := fmt.Sprintf("opc.tcp://%s:%d", host, port)
		s.endpoints = append(s.endpoints, ep)
		return nil
	}
}

// ListenOn sets the TCP address the server binds to (e.g. "0.0.0.0:4840").
// Use this when you want the server to accept connections on all interfaces
// without advertising "0.0.0.0" as a reachable endpoint URL.  If not set,
// the server listens on the first EndPoint address.
func ListenOn(addr string) Option {
	return func(s *serverConfig) error {
		s.listenAddr = "opc.tcp://" + addr
		return nil
	}
}

// Certificate sets the client X509 certificate in the secure channel configuration
// and also detects and sets the ApplicationURI from the URI within the certificate.
func Certificate(cert []byte) Option {
	return func(s *serverConfig) error {
		s.certificate = cert

		x509cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return fmt.Errorf("server: failed to parse x509 certificate: %w", err)
		}

		if len(x509cert.URIs) > 0 {
			s.applicationURI = x509cert.URIs[0].String()
		}
		return nil
	}
}

// EnableSecurity registers a new endpoint security mode to the server.
// This will also register the security policy against each enabled auth mode.
func EnableSecurity(secPolicy string, secMode ua.MessageSecurityMode) Option {
	return func(s *serverConfig) error {
		if !strings.HasPrefix(secPolicy, "http://opcfoundation.org/UA/SecurityPolicy#") {
			secPolicy = "http://opcfoundation.org/UA/SecurityPolicy#" + secPolicy
		}

		var ok bool
		ss := uapolicy.SupportedPolicies()
		for _, sp := range ss {
			if sp == secPolicy {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("server: unsupported security policy %q", secPolicy)
		}

		for _, sec := range s.enabledSec {
			if sec.secPolicy == secPolicy && sec.secMode == secMode {
				return fmt.Errorf("server: security policy %q with mode %v already exists", secPolicy, secMode)
			}
		}

		sec := security{
			secPolicy: secPolicy,
			secMode:   secMode,
		}

		s.enabledSec = append(s.enabledSec, sec)
		return nil
	}
}

// UsernameValidator is a function that validates a username and password.
// Return nil to accept, or an error (typically ua.StatusBadUserAccessDenied)
// to reject the credentials.
type UsernameValidator func(username, password string) error

// WithUsernameValidator registers a username/password validator called during
// ActivateSession when the client presents a UserNameIdentityToken.
// EnableAuthMode(ua.UserTokenTypeUserName) must also be called.
func WithUsernameValidator(v UsernameValidator) Option {
	return func(s *serverConfig) error {
		s.usernameValidator = v
		return nil
	}
}

// X509UserValidator validates an X.509 identity token presented by a client
// during ActivateSession. The certificate is provided as DER-encoded bytes.
//
// The server already verifies that the client holds the corresponding private
// key (via the UserTokenSignature). This callback is responsible for trust
// decisions: checking the certificate against a configured trust store,
// verifying revocation status, or applying application-specific policy.
//
// Return nil to accept the certificate, or an error to reject it.
// ua.StatusBadIdentityTokenRejected and ua.StatusBadUserAccessDenied are
// the appropriate status codes for policy-based rejection.
type X509UserValidator func(certDER []byte) error

// WithX509UserValidator registers a certificate validator called during
// ActivateSession when the client presents an X509IdentityToken.
// EnableAuthMode(ua.UserTokenTypeCertificate) must also be called.
//
// If no validator is registered the server rejects all X.509 user tokens
// (the server still advertises the token type when the auth mode is enabled,
// but tokens cannot be activated without a configured validator).
func WithX509UserValidator(v X509UserValidator) Option {
	return func(s *serverConfig) error {
		s.x509UserValidator = v
		return nil
	}
}

// ClientCertificateValidator validates the application certificate presented
// by a connecting client during OpenSecureChannel (and again at CreateSession
// as defense-in-depth). The certificate is provided as DER-encoded bytes.
//
// Return nil to accept the client, or a ua.StatusCode error to reject it.
// ua.StatusBadCertificateUntrusted is the appropriate code when the certificate
// is not in the server's configured trust store.
//
// When no validator is registered, the server accepts any application certificate
// (the secure channel still enforces message security; this validator controls
// trust-store based application-level access control).
type ClientCertificateValidator func(certDER []byte) error

// WithClientCertificateTrustList configures the server to verify connecting
// clients' application certificates against the provided CA certificate pool.
// Clients that present a certificate not signed by one of the provided CA
// certificates are rejected with BadCertificateUntrusted at OpenSecureChannel
// (CreateSession retains the same check as defense-in-depth).
//
// Each caCertDER is a DER-encoded X.509 CA certificate.
// Passing an empty list configures a server that rejects all client certificates.
func WithClientCertificateTrustList(caCertDER ...[]byte) Option {
	return func(s *serverConfig) error {
		pool := x509.NewCertPool()
		for _, der := range caCertDER {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("WithClientCertificateTrustList: %w", err)
			}
			pool.AddCert(cert)
		}
		s.clientCertificateValidator = func(certDER []byte) error {
			if len(certDER) == 0 {
				return nil // no certificate presented; non-certificate channel
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return ua.StatusBadCertificateInvalid
			}
			opts := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}
			if _, err := cert.Verify(opts); err != nil {
				return ua.StatusBadCertificateUntrusted
			}
			return nil
		}
		return nil
	}
}

// AllowUsernameOnNone permits the server to advertise UserName token policies
// on None/None (unencrypted) endpoints.  The OPC UA specification permits this
// for test deployments (Part 4 §5.6.3.2).  By default, non-anonymous tokens
// are only advertised on encrypted endpoints.
func AllowUsernameOnNone() Option {
	return func(s *serverConfig) error {
		s.allowUsernameOnNone = true
		return nil
	}
}

// EnableAuthMode registers a new user authentication mode to the server.
// All AuthModes except Anonymous require encryption by default, so EnableSecurity()
// must also be called with at least one non-"None" SecurityPolicy.
func EnableAuthMode(tokenType ua.UserTokenType) Option {
	return func(s *serverConfig) error {
		for _, a := range s.enabledAuth {
			if a.tokenType == tokenType {
				return fmt.Errorf("server: auth mode %v already registered", tokenType)
			}
		}

		a := authMode{
			tokenType: tokenType,
		}

		s.enabledAuth = append(s.enabledAuth, a)
		return nil
	}
}

func defaultChannelConfig() *uasc.Config {
	return &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
	}
}

func ServerName(name string) Option {
	return func(s *serverConfig) error {
		s.applicationName = name
		return nil
	}
}

func ManufacturerName(name string) Option {
	return func(s *serverConfig) error {
		s.manufacturerName = name
		return nil
	}
}

func ProductName(name string) Option {
	return func(s *serverConfig) error {
		s.productName = name
		return nil
	}
}

func SoftwareVersion(name string) Option {
	return func(s *serverConfig) error {
		s.softwareVersion = name
		return nil
	}
}

// SetLogger sets the logger for the server.
func SetLogger(l *slog.Logger) Option {
	return func(s *serverConfig) error {
		s.logger = l
		return nil
	}
}

// WithSlogLogger sets the logger from an slog.Logger.
func WithSlogLogger(l *slog.Logger) Option {
	return func(s *serverConfig) error {
		s.logger = l
		return nil
	}
}
