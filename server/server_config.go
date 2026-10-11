// SPDX-License-Identifier: MIT

package server

import (
	"crypto"
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
//
// Together with Certificate it configures the server's RSA application
// instance certificate. Certificates of other key types, for the ECC security
// policies, are added with ApplicationIdentity.
func PrivateKey(key *rsa.PrivateKey) Option {
	return func(s *serverConfig) error {
		s.privateKey = key
		return nil
	}
}

// ApplicationIdentity adds an application instance certificate and its
// private key to the server. It may be given several times, once per key
// type, and combined with Certificate and PrivateKey:
//
//   - an RSA certificate serves the RSA security policies (Basic256Sha256,
//     Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss, ...),
//   - an ECDSA P-256 certificate serves ECC_nistP256, ECC_nistP256_AesGcm
//     and ECC_nistP256_ChaChaPoly,
//   - an ECDSA P-384 certificate serves ECC_nistP384 and the three
//     ECC_nistP256 policies,
//   - an Ed25519 certificate serves ECC_curve25519.
//
// A server that offers RSA and ECC endpoints therefore has (at least) two
// certificates. For every SecureChannel the server uses the first configured
// certificate whose key fits the security policy the client selected, and
// each endpoint advertises the certificate of its policy. All certificates of
// a server should carry the same ApplicationURI.
//
// cert is the DER encoded certificate. An ECC key only has to sign, so it may
// be any crypto.Signer with an ECDSA or Ed25519 public key (for example a key
// held in an HSM); an RSA key must be an *rsa.PrivateKey.
func ApplicationIdentity(cert []byte, key crypto.Signer) Option {
	return func(s *serverConfig) error {
		x509cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return fmt.Errorf("server: failed to parse x509 certificate: %w", err)
		}
		if !uapolicy.KeyMatchesCertificate(key, cert) {
			return fmt.Errorf("server: private key does not belong to the certificate %q", x509cert.Subject.String())
		}
		s.identities = append(s.identities, applicationIdentity{certificate: cert, key: key})

		// The first certificate of a server without a Certificate option is
		// also the one used where no security policy selects one: on
		// unsecured channels.
		if s.certificate == nil {
			s.certificate = cert
			if len(x509cert.URIs) > 0 {
				s.applicationURI = x509cert.URIs[0].String()
			}
			if rsaKey, ok := key.(*rsa.PrivateKey); ok && s.privateKey == nil {
				s.privateKey = rsaKey
			}
		}
		return nil
	}
}

// applicationIdentity is an application instance certificate with its key.
type applicationIdentity struct {
	certificate []byte
	key         crypto.Signer
}

// identityFor returns the application instance certificate and private key
// the server uses with the security policy.
func (s *serverConfig) identityFor(policyURI string) ([]byte, crypto.Signer, bool) {
	// The Certificate / PrivateKey pair comes first: it is what a server
	// without ApplicationIdentity has, and it must keep behaving as before.
	var primary crypto.Signer
	if s.privateKey != nil {
		primary = s.privateKey
	}
	if policyURI == ua.SecurityPolicyURINone {
		return s.certificate, primary, true
	}
	if s.certificate != nil && primary != nil && uapolicy.CheckCertificate(policyURI, s.certificate) == nil {
		return s.certificate, primary, true
	}
	for _, id := range s.identities {
		if uapolicy.CheckCertificate(policyURI, id.certificate) == nil {
			return id.certificate, id.key, true
		}
	}
	return nil, nil, false
}

// canSecure reports whether the server has an application instance
// certificate with its key: the Certificate / PrivateKey pair or one added
// with ApplicationIdentity (which is all a server with ECC certificates only
// has).
func (s *serverConfig) canSecure() bool {
	return (len(s.certificate) > 0 && s.privateKey != nil) || len(s.identities) > 0
}

// certificateFor returns the certificate an endpoint with the security policy
// advertises.
func (s *serverConfig) certificateFor(policyURI string) []byte {
	if cert, _, ok := s.identityFor(policyURI); ok {
		return cert
	}
	return s.certificate
}

// localIdentity selects the certificate and key for a new SecureChannel. It
// is the place where a client that asks for a security policy this server
// does not offer is turned away, before a SecurityToken is issued.
func (s *serverConfig) localIdentity(policyURI string) ([]byte, crypto.Signer, error) {
	if len(s.enabledSec) > 0 {
		enabled := false
		for _, sec := range s.enabledSec {
			if sec.secPolicy == policyURI {
				enabled = true
				break
			}
		}
		if !enabled {
			return nil, nil, fmt.Errorf("server: security policy %q is not enabled", policyURI)
		}
	}
	cert, key, ok := s.identityFor(policyURI)
	if !ok {
		return nil, nil, fmt.Errorf("server: no application instance certificate for security policy %q", policyURI)
	}
	return cert, key, nil
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

		if len(x509cert.URIs) > 0 && !s.applicationURISet {
			s.applicationURI = x509cert.URIs[0].String()
		}
		return nil
	}
}

// ApplicationURI sets the ApplicationUri of the server: the globally unique
// name it reports in its endpoint descriptions and announces as ServerUri
// when it opens a reverse connection (see [WithReverseConnect]).
//
// A server with a certificate does not need this option: the ApplicationUri
// is taken from the certificate (see [Certificate]), with which it must be
// identical anyway. Use it for a server without a certificate, which has no
// ApplicationUri otherwise.
func ApplicationURI(uri string) Option {
	return func(s *serverConfig) error {
		if uri == "" {
			return fmt.Errorf("server: empty ApplicationURI")
		}
		s.applicationURI = uri
		s.applicationURISet = true
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

// WithResponseWriteTimeout sets how long the server waits for a response to
// be written to a client before it gives up on that client.
//
// Every secure channel has its own response writer, so a client that stops
// reading its responses does not hold up the others. Once a response to such
// a client has been waiting for d, the client is considered stalled and its
// connection is closed; its session and subscriptions then end through their
// own timeouts unless the client reconnects. Other channels are not
// affected.
//
// The default is 15 seconds. Choose a larger value for clients on very slow
// links that fetch large responses. Zero or a negative value selects the
// default.
func WithResponseWriteTimeout(d time.Duration) Option {
	return func(s *serverConfig) error {
		s.responseWriteTimeout = d
		return nil
	}
}

// WithMaxPendingResponses sets how many requests of one secure channel may
// be in flight, that is received but not yet answered on the wire, at a
// time.
//
// When a client has n requests in flight the server stops reading further
// requests from that client until responses have been written. This bounds
// the memory one client can occupy with queued responses and applies TCP
// back pressure to a client that sends requests faster than it reads the
// answers; it never drops a request. Publish requests that are waiting for
// a notification do not count.
//
// The default is 256. Zero or a negative value selects the default.
func WithMaxPendingResponses(n int) Option {
	return func(s *serverConfig) error {
		s.maxPendingResponses = n
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
// By default logging is disabled (silent discard handler).
// Pass nil to restore the silent default.
func SetLogger(l *slog.Logger) Option {
	return func(s *serverConfig) error {
		if l == nil {
			s.logger = silentLogger()
			return nil
		}
		s.logger = l
		return nil
	}
}

// WithSlogLogger sets the logger from an slog.Logger.
// Pass nil to restore the silent default.
func WithSlogLogger(l *slog.Logger) Option {
	return func(s *serverConfig) error {
		if l == nil {
			s.logger = silentLogger()
			return nil
		}
		s.logger = l
		return nil
	}
}
