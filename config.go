// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package opcua

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/logger"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

// serverCertValidator holds options for server certificate validation.
type serverCertValidator struct {
	insecureSkipVerify bool
	trustedCerts       *x509.CertPool
	trustedCertsList   []*x509.Certificate
}

const (
	DefaultDialTimeout = 10 * time.Second
)

// DefaultClientConfig returns the default configuration for a client
// to establish a secure channel.
func DefaultClientConfig() *uasc.Config {
	return &uasc.Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Lifetime:          uint32(time.Hour / time.Millisecond),
		RequestTimeout:    10 * time.Second,
		AutoReconnect:     true,
		ReconnectInterval: 5 * time.Second,
	}
}

// DefaultSessionConfig returns the default configuration for a client
// to establish a session.
func DefaultSessionConfig() *uasc.SessionConfig {
	return &uasc.SessionConfig{
		SessionTimeout: 20 * time.Minute,
		ClientDescription: &ua.ApplicationDescription{
			ApplicationURI:  "urn:otfabric:opcua:client",
			ProductURI:      "urn:otfabric:opcua",
			ApplicationName: ua.NewLocalizedText("otfabric/go-opcua - OPC UA implementation in Go"),
			ApplicationType: ua.ApplicationTypeClient,
		},
		LocaleIDs:          []string{"en-us"},
		UserTokenSignature: &ua.SignatureData{},
	}
}

// Config contains all config options.
type Config struct {
	dialer              *uacp.Dialer
	sechan              *uasc.Config
	session             *uasc.SessionConfig
	logger              logger.Logger
	stateCh             chan<- ConnState
	stateFunc           func(ConnState)
	metrics             ClientMetrics
	retryPolicy         RetryPolicy
	skipNamespaceUpdate bool
	certValidator       serverCertValidator
}

func DefaultDialer() *uacp.Dialer {
	return &uacp.Dialer{
		Dialer: &net.Dialer{
			Timeout: DefaultDialTimeout,
		},
		ClientACK: uacp.DefaultClientACK,
	}
}

func newConfig() *Config {
	return &Config{
		dialer:  DefaultDialer(),
		sechan:  DefaultClientConfig(),
		session: DefaultSessionConfig(),
		logger:  logger.Default(),
	}
}

// ApplyConfig applies the config options to the default configuration.
func ApplyConfig(opts ...Option) (*Config, error) {
	cfg := newConfig()

	var errs []error
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			errs = append(errs, err)
		}
	}
	return cfg, errors.Join(errs...)
}

// Option is an option function type to modify the configuration.
type Option func(*Config) error

// WithRetryPolicy sets the retry policy for failed client requests.
// By default no retries are performed.
//
// Example:
//
//	// Retry up to 4 times with exponential back-off.
//	opcua.WithRetryPolicy(opcua.ExponentialBackoff(200*time.Millisecond, 5*time.Second, 4))
func WithRetryPolicy(p RetryPolicy) Option {
	return func(cfg *Config) error {
		cfg.retryPolicy = p
		return nil
	}
}

// WithLogger sets the logger for the client.
// By default, the library delegates to slog.Default().
func WithLogger(l Logger) Option {
	return func(cfg *Config) error {
		cfg.logger = l
		return nil
	}
}

// WithSlogLogger sets the logger from an *slog.Logger.
// This is a convenience wrapper around WithLogger that adapts the
// slog.Logger's handler to the library's Logger interface.
func WithSlogLogger(l *slog.Logger) Option {
	return func(cfg *Config) error {
		cfg.logger = logger.NewSlogLogger(l.Handler())
		return nil
	}
}

// ApplicationName sets the application name in the session configuration.
func ApplicationName(s string) Option {
	return func(cfg *Config) error {
		cfg.session.ClientDescription.ApplicationName = ua.NewLocalizedText(s)
		return nil
	}
}

// ApplicationURI sets the application uri in the session configuration.
func ApplicationURI(s string) Option {
	return func(cfg *Config) error {
		cfg.session.ClientDescription.ApplicationURI = s
		return nil
	}
}

// AutoReconnect sets the auto reconnect state of the secure channel.
func AutoReconnect(b bool) Option {
	return func(cfg *Config) error {
		cfg.sechan.AutoReconnect = b
		return nil
	}
}

// ReconnectInterval is interval duration between each reconnection attempt.
func ReconnectInterval(d time.Duration) Option {
	return func(cfg *Config) error {
		cfg.sechan.ReconnectInterval = d
		return nil
	}
}

// Lifetime sets the lifetime of the secure channel in milliseconds.
func Lifetime(d time.Duration) Option {
	return func(cfg *Config) error {
		cfg.sechan.Lifetime = uint32(d / time.Millisecond)
		return nil
	}
}

// Locales sets the locales in the session configuration.
func Locales(locale ...string) Option {
	return func(cfg *Config) error {
		cfg.session.LocaleIDs = locale
		return nil
	}
}

// ProductURI sets the product uri in the session configuration.
func ProductURI(s string) Option {
	return func(cfg *Config) error {
		cfg.session.ClientDescription.ProductURI = s
		return nil
	}
}

// stubbed out for testing.
var randomRequestID func() uint32 = nil

// RandomRequestID assigns a random initial request id.
//
// The request id is generated using the 'rand' package and it
// is the caller's responsibility to initialize the random number
// generator properly.
func RandomRequestID() Option {
	return func(cfg *Config) error {
		if randomRequestID != nil {
			cfg.sechan.RequestIDSeed = randomRequestID()
		} else {
			cfg.sechan.RequestIDSeed = uint32(rand.Int31())
		}
		return nil
	}
}

// RemoteCertificate sets the server certificate.
func RemoteCertificate(cert []byte) Option {
	return func(cfg *Config) error {
		cfg.sechan.RemoteCertificate = cert
		return nil
	}
}

// RemoteCertificateFile sets the server certificate from the file
// in PEM or DER encoding.
func RemoteCertificateFile(filename string) Option {
	return func(cfg *Config) error {
		if filename == "" {
			return nil
		}

		cert, err := loadCertificate(filename)
		if err != nil {
			return err
		}
		cfg.sechan.RemoteCertificate = cert
		return nil
	}
}

// SecurityMode sets the security mode for the secure channel.
func SecurityMode(m ua.MessageSecurityMode) Option {
	return func(cfg *Config) error {
		cfg.sechan.SecurityMode = m
		return nil
	}
}

// SecurityModeString sets the security mode for the secure channel.
// Valid values are "None", "Sign", and "SignAndEncrypt".
func SecurityModeString(s string) Option {
	return func(cfg *Config) error {
		cfg.sechan.SecurityMode = ua.MessageSecurityModeFromString(s)
		return nil
	}
}

// SecurityPolicy sets the security policy uri for the secure channel.
func SecurityPolicy(s string) Option {
	return func(cfg *Config) error {
		cfg.sechan.SecurityPolicyURI = ua.FormatSecurityPolicyURI(s)
		return nil
	}
}

// SkipNamespaceUpdate disables automatic namespace table update on connect
// and reconnect. Use this when the server does not support namespace queries.
// See https://github.com/otfabric/go-opcua/pull/512 for discussion.
func SkipNamespaceUpdate() Option {
	return func(cfg *Config) error {
		cfg.skipNamespaceUpdate = true
		return nil
	}
}

// SessionName sets the name in the session configuration.
func SessionName(s string) Option {
	return func(cfg *Config) error {
		cfg.session.SessionName = s
		return nil
	}
}

// SessionTimeout sets the timeout in the session configuration.
func SessionTimeout(d time.Duration) Option {
	return func(cfg *Config) error {
		cfg.session.SessionTimeout = d
		return nil
	}
}

// PrivateKey sets the RSA private key in the secure channel configuration.
func PrivateKey(key *rsa.PrivateKey) Option {
	return func(cfg *Config) error {
		cfg.sechan.LocalKey = key
		return nil
	}
}

// PrivateKeyFile sets the RSA private key in the secure channel configuration
// from a PEM or DER encoded file.
func PrivateKeyFile(filename string) Option {
	return func(cfg *Config) error {
		if filename == "" {
			return nil
		}
		key, err := loadPrivateKey(filename)
		if err != nil {
			return err
		}
		cfg.sechan.LocalKey = key
		return nil
	}
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidPrivateKey, err)
	}

	derBytes := b
	if strings.HasSuffix(filename, ".pem") {
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("%w: failed to decode PEM block", errors.ErrInvalidPrivateKey)
		}
		derBytes = block.Bytes
	}

	pk, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidPrivateKey, err)
	}
	return pk, nil
}

// Certificate sets the client X509 certificate in the secure channel configuration.
// It also detects and sets the ApplicationURI from the URI within the certificate.
func Certificate(cert []byte) Option {
	return func(cfg *Config) error {
		return setCertificate(cert, cfg)
	}
}

// CertificateFile sets the client X509 certificate in the secure channel configuration
// from the PEM or DER encoded file. It also detects and sets the ApplicationURI
// from the URI within the certificate.
func CertificateFile(filename string) Option {
	return func(cfg *Config) error {
		if filename == "" {
			return nil
		}

		cert, err := loadCertificate(filename)
		if err != nil {
			return err
		}
		return setCertificate(cert, cfg)
	}
}

func loadCertificate(filename string) ([]byte, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errors.ErrInvalidCertificate, err)
	}

	if !strings.HasSuffix(filename, ".pem") {
		return b, nil
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: failed to decode PEM block", errors.ErrInvalidCertificate)
	}
	return block.Bytes, nil
}

func setCertificate(cert []byte, cfg *Config) error {
	cfg.sechan.Certificate = cert

	// Extract the application URI from the certificate.
	x509cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrInvalidCertificate, err)
	}
	if len(x509cert.URIs) == 0 {
		return nil
	}
	appURI := x509cert.URIs[0].String()
	if appURI == "" {
		return nil
	}
	cfg.session.ClientDescription.ApplicationURI = appURI
	return nil
}

// SecurityFromEndpoint sets the server-related security parameters from
// a chosen endpoint (received from GetEndpoints()).
func SecurityFromEndpoint(ep *ua.EndpointDescription, authType ua.UserTokenType) Option {
	return func(cfg *Config) error {
		cfg.sechan.SecurityPolicyURI = ep.SecurityPolicyURI
		cfg.sechan.SecurityMode = ep.SecurityMode
		cfg.sechan.RemoteCertificate = ep.ServerCertificate
		cfg.sechan.Thumbprint = uapolicy.Thumbprint(ep.ServerCertificate)

		for _, t := range ep.UserIdentityTokens {
			if t.TokenType != authType {
				continue
			}

			if cfg.session.UserIdentityToken == nil {
				switch authType {
				case ua.UserTokenTypeAnonymous:
					cfg.session.UserIdentityToken = &ua.AnonymousIdentityToken{}
				case ua.UserTokenTypeUserName:
					cfg.session.UserIdentityToken = &ua.UserNameIdentityToken{}
				case ua.UserTokenTypeCertificate:
					cfg.session.UserIdentityToken = &ua.X509IdentityToken{}
				case ua.UserTokenTypeIssuedToken:
					cfg.session.UserIdentityToken = &ua.IssuedIdentityToken{}
				}
			}

			cfg.session.UserIdentityToken.SetPolicyID(t.PolicyID)
			if t.SecurityPolicyURI != "" {
				cfg.session.AuthPolicyURI = t.SecurityPolicyURI
			} else {
				cfg.session.AuthPolicyURI = ep.SecurityPolicyURI
			}
			return nil
		}

		if cfg.session.UserIdentityToken == nil {
			cfg.session.UserIdentityToken = &ua.AnonymousIdentityToken{PolicyID: defaultAnonymousPolicyID}
			cfg.session.AuthPolicyURI = ua.SecurityPolicyURINone
		}
		return nil
	}
}

// AuthPolicyID sets the policy ID of the user identity token.
//
// This can be called before or after an AuthXXX method. If called before,
// the policy ID is stored and applied once the token type is set.
//
// Most callers should use SecurityFromEndpoint which automatically
// determines the correct policy ID from the endpoint description.
func AuthPolicyID(policy string) Option {
	return func(cfg *Config) error {
		if cfg.session.UserIdentityToken == nil {
			// Defer until an AuthXXX method creates the token.
			cfg.session.PendingPolicyID = policy
			return nil
		}
		cfg.session.UserIdentityToken.SetPolicyID(policy)
		return nil
	}
}

// AuthAnonymous sets the authentication mode to anonymous.
//
// The policy ID is typically set via SecurityFromEndpoint.
// It can also be set explicitly with AuthPolicyID (in any order).
func AuthAnonymous() Option {
	return func(cfg *Config) error {
		if cfg.session.UserIdentityToken == nil {
			cfg.session.UserIdentityToken = &ua.AnonymousIdentityToken{}
		}

		_, ok := cfg.session.UserIdentityToken.(*ua.AnonymousIdentityToken)
		if !ok {
			cfg.logger.Warnf("non-anonymous authentication already configured, ignoring")
			return nil
		}
		applyPendingPolicyID(cfg)
		return nil
	}
}

// AuthUsername sets the authentication mode to username/password.
//
// The policy ID is typically set via SecurityFromEndpoint.
// It can also be set explicitly with AuthPolicyID (in any order).
func AuthUsername(user, pass string) Option {
	return func(cfg *Config) error {
		if cfg.session.UserIdentityToken == nil {
			cfg.session.UserIdentityToken = &ua.UserNameIdentityToken{}
		}

		t, ok := cfg.session.UserIdentityToken.(*ua.UserNameIdentityToken)
		if !ok {
			cfg.logger.Warnf("non-username authentication already configured, ignoring")
			return nil
		}

		t.UserName = user
		cfg.session.AuthPassword = pass
		applyPendingPolicyID(cfg)
		return nil
	}
}

// AuthCertificate sets the authentication mode to X509 certificate.
//
// The policy ID is typically set via SecurityFromEndpoint.
// It can also be set explicitly with AuthPolicyID (in any order).
func AuthCertificate(cert []byte) Option {
	return func(cfg *Config) error {
		if cfg.session.UserIdentityToken == nil {
			cfg.session.UserIdentityToken = &ua.X509IdentityToken{}
		}

		t, ok := cfg.session.UserIdentityToken.(*ua.X509IdentityToken)
		if !ok {
			cfg.logger.Warnf("non-certificate authentication already configured, ignoring")
			return nil
		}

		t.CertificateData = cert
		applyPendingPolicyID(cfg)
		return nil
	}
}

// AuthPrivateKey sets the client's authentication RSA private key
// Note: PolicyID still needs to be set outside of this method, typically through
// the SecurityFromEndpoint() Option.
func AuthPrivateKey(key *rsa.PrivateKey) Option {
	return func(cfg *Config) error {
		cfg.sechan.UserKey = key
		return nil
	}
}

// AuthIssuedToken sets the authentication mode to an externally-issued token.
//
// tokenData is the opaque token value whose format depends on the token type
// advertised by the server's UserTokenPolicy (e.g. SAML, JWT, WS-Security).
// See OPC-UA Part 4, §7.36.6 for details on IssuedIdentityToken encoding.
//
// The policy ID is typically set via SecurityFromEndpoint.
// It can also be set explicitly with AuthPolicyID (in any order).
func AuthIssuedToken(tokenData []byte) Option {
	return func(cfg *Config) error {
		if cfg.session.UserIdentityToken == nil {
			cfg.session.UserIdentityToken = &ua.IssuedIdentityToken{}
		}

		t, ok := cfg.session.UserIdentityToken.(*ua.IssuedIdentityToken)
		if !ok {
			cfg.logger.Warnf("non-issued token authentication already configured, ignoring")
			return nil
		}

		t.TokenData = tokenData
		applyPendingPolicyID(cfg)
		return nil
	}
}

// applyPendingPolicyID applies a deferred policy ID (set by AuthPolicyID
// before any AuthXXX call) to the current user identity token.
func applyPendingPolicyID(cfg *Config) {
	if cfg.session.PendingPolicyID != "" && cfg.session.UserIdentityToken != nil {
		cfg.session.UserIdentityToken.SetPolicyID(cfg.session.PendingPolicyID)
		cfg.session.PendingPolicyID = ""
	}
}

// RequestTimeout sets the timeout for all requests over SecureChannel.
func RequestTimeout(t time.Duration) Option {
	return func(cfg *Config) error {
		cfg.sechan.RequestTimeout = t
		return nil
	}
}

// Dialer sets the uacp.Dialer to establish the connection to the server.
func Dialer(d *uacp.Dialer) Option {
	return func(cfg *Config) error {
		cfg.dialer = d
		return nil
	}
}

// DialTimeout sets the timeout for establishing the UACP connection.
// Defaults to DefaultDialTimeout. Set to zero for no timeout.
func DialTimeout(d time.Duration) Option {
	return func(cfg *Config) error {
		cfg.dialer.Dialer.Timeout = d
		return nil
	}
}

// MaxMessageSize sets the maximum message size for the UACP handshake.
func MaxMessageSize(n uint32) Option {
	return func(cfg *Config) error {
		cfg.dialer.ClientACK.MaxMessageSize = n
		return nil
	}
}

// MaxChunkCount sets the maximum chunk count for the UACP handshake.
func MaxChunkCount(n uint32) Option {
	return func(cfg *Config) error {
		cfg.dialer.ClientACK.MaxChunkCount = n
		return nil
	}
}

// ReceiveBufferSize sets the receive buffer size for the UACP handshake.
func ReceiveBufferSize(n uint32) Option {
	return func(cfg *Config) error {
		cfg.dialer.ClientACK.ReceiveBufSize = n
		return nil
	}
}

// SendBufferSize sets the send buffer size for the UACP handshake.
func SendBufferSize(n uint32) Option {
	return func(cfg *Config) error {
		cfg.dialer.ClientACK.SendBufSize = n
		return nil
	}
}

// WithConnStateHandler sets a callback for receiving client connection state changes.
func WithConnStateHandler(h func(ConnState)) Option {
	return func(cfg *Config) error {
		cfg.stateFunc = h
		return nil
	}
}

// WithConnStateChan sets a channel for receiving client connection state changes.
// The caller must provide a buffered channel and consume it promptly to prevent
// blocking. Sends are context-aware: if the context is cancelled, the state
// change is dropped rather than blocking.
func WithConnStateChan(ch chan<- ConnState) Option {
	return func(cfg *Config) error {
		cfg.stateCh = ch
		return nil
	}
}

// WithMetrics sets a metrics callback handler for the client.
// All methods are called synchronously; implementations must be non-blocking.
func WithMetrics(m ClientMetrics) Option {
	return func(cfg *Config) error {
		cfg.metrics = m
		return nil
	}
}

// InsecureSkipVerify disables server certificate validation.
// When set, the client still parses the server certificate to extract the
// public key (required for signing and encryption), but does not verify the
// trust chain, expiration, or application URI.
//
// This is INSECURE and should only be used for development and testing.
func InsecureSkipVerify() Option {
	return func(cfg *Config) error {
		cfg.certValidator.insecureSkipVerify = true
		return nil
	}
}

// TrustedCertificates adds CA or self-signed certificates to the trust pool
// used to validate the server certificate. The provided certificates are
// merged with the system CA pool. If the system pool is unavailable, only
// the provided certificates are trusted.
//
// Use this to trust self-signed server certificates or private CAs without
// disabling all validation via InsecureSkipVerify.
func TrustedCertificates(certs ...*x509.Certificate) Option {
	return func(cfg *Config) error {
		if cfg.certValidator.trustedCerts == nil {
			cfg.certValidator.trustedCerts = x509.NewCertPool()
		}
		for _, c := range certs {
			cfg.certValidator.trustedCerts.AddCert(c)
			cfg.certValidator.trustedCertsList = append(cfg.certValidator.trustedCertsList, c)
		}
		return nil
	}
}

// validateServerCertificate validates a DER-encoded server certificate
// against the configured trust settings. It checks:
//   - Trust chain (system CA pool + user-supplied trusted certificates)
//   - Expiration / not-yet-valid
//   - Key usage (DigitalSignature, KeyEncipherment)
//
// If insecureSkipVerify is set the function returns nil immediately.
// If securityMode is None, no validation is performed.
func (cfg *Config) validateServerCertificate(der []byte, securityMode ua.MessageSecurityMode) error {
	if securityMode == ua.MessageSecurityModeNone {
		return nil
	}

	if cfg.certValidator.insecureSkipVerify {
		return nil
	}

	if len(der) == 0 {
		return nil
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("opcua: server certificate validation failed: %w", err)
	}

	// Build verification options.
	roots, err := x509.SystemCertPool()
	if err != nil {
		// System pool unavailable (e.g. some stripped containers).
		roots = x509.NewCertPool()
	}
	// Merge user-supplied trusted certs into root pool so self-signed
	// server certificates and private CAs are accepted.
	for _, c := range cfg.certValidator.trustedCertsList {
		roots.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("opcua: server certificate validation failed: %w", err)
	}

	// Verify key usage bits. OPC UA servers should have DigitalSignature and
	// KeyEncipherment. We only warn here because many OPC UA test servers
	// and self-signed certs don't set key usage properly.
	const requiredUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if cert.KeyUsage != 0 && cert.KeyUsage&requiredUsage != requiredUsage {
		cfg.logger.Warnf("opcua: server certificate missing recommended key usage bits (DigitalSignature, KeyEncipherment)")
	}

	return nil
}
