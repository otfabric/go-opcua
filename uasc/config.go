// SPDX-License-Identifier: MIT

package uasc

import (
	"crypto"
	"crypto/rsa"
	"log/slog"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// Config represents a configuration which UASC client/server has in common.
type Config struct {

	// SecurityPolicyURI is the URI of the Security Policy used to secure the Message.
	// This field is encoded as a UTF-8 string without a null terminator.
	SecurityPolicyURI string

	// Certificate is the X.509 v3 Certificate assigned to the sending application Instance.
	// This is a DER encoded blob.
	// The structure of an X.509 v3 Certificate is defined in X.509 v3.
	// The DER format for a Certificate is defined in X690.
	// This indicates what Private Key was used to sign the MessageChunk.
	// The Stack shall close the channel and report an error to the application if
	// the Certificate is too large for the buffer size supported by the
	// transport layer.
	// This field shall be null if the Message is not signed.
	Certificate []byte

	// LocalKey is a RSA Private Key which will be used to encrypt the OpenSecureChannel
	// messages.  It is the key associated with Certificate
	//
	// For a key of another type (the ECC security policies) set
	// LocalPrivateKey instead.
	LocalKey *rsa.PrivateKey

	// LocalPrivateKey is the private key associated with Certificate, of any
	// supported type: an *rsa.PrivateKey for the RSA security policies, a
	// crypto.Signer with an ECDSA public key for the ECC ones. It takes
	// precedence over LocalKey.
	LocalPrivateKey crypto.Signer

	// UserKey is a RSA Private Key which will be used to sign the UserTokenSignature.
	// It is the key associated with AuthCertificate
	//
	// For a key of another type set UserPrivateKey instead.
	UserKey *rsa.PrivateKey

	// UserPrivateKey is the private key associated with the certificate of an
	// X509IdentityToken, of any supported type. It takes precedence over
	// UserKey.
	UserPrivateKey crypto.Signer

	// LocalIdentity, when set on a server SecureChannel, selects the
	// application instance certificate and private key for the security
	// policy a client opens the channel with. A server that offers RSA and
	// ECC endpoints has one certificate per key type; the policy decides
	// which one applies. It is called once, for the first OpenSecureChannel
	// request, and its result replaces Certificate and LocalPrivateKey.
	// An error rejects the channel with Bad_SecurityPolicyRejected.
	LocalIdentity func(securityPolicyURI string) (certificate []byte, key crypto.Signer, err error)

	// Thumbprint is the thumbprint of the X.509 v3 Certificate assigned to the receiving
	// application Instance.
	// The thumbprint is the CertificateDigest of the DER encoded form of the
	// Certificate.
	// This indicates what public key was used to encrypt the MessageChunk.
	// This field shall be null if the Message is not encrypted.
	Thumbprint []byte

	// RemoteCertificate is the X.509 Certificate for the receiving instance.
	// Used to encrypt the message chunks in the OpenSecureChannel phase.
	RemoteCertificate []byte

	// RequestIDSeed is the initial value for RequestID counter in each new SecureChannel
	RequestIDSeed uint32

	// SecurityMode is The type of security to apply to the messages. The type MessageSecurityMode
	// is defined in 7.15.
	// A SecureChannel may have to be created even if the securityMode is NONE. The exact behaviour
	// depends on the mapping used and is described in the Part 6.
	SecurityMode ua.MessageSecurityMode

	// AutoReconnect will make sure that once communication is restored,
	// the old session is used whenever possible and that Susbcription data is not missed.
	// You may choose to use AutoReconnect (true by default) or do it manually.
	// AutoReconnect will make the UaClient to try to reconnect to the server every second,
	// once the communication is broken. If you do it manually, you must be prepared to do it until it succeeds.
	AutoReconnect bool

	// ReconnectInterval is interval duration between each reconnection attempt,
	// ignored if AutoReconnect is set to false.
	ReconnectInterval time.Duration

	// Lifetime is the requested lifetime, in milliseconds, for the new SecurityToken when the
	// SecureChannel works as client. It specifies when the Client expects to renew the SecureChannel
	// by calling the OpenSecureChannel Service again. If a SecureChannel is not renewed, then all
	// Messages sent using the current SecurityTokens shall be rejected by the receiver.
	// Lifetime can also be the revised lifetime, the lifetime of the SecurityToken in milliseconds.
	// The UTC expiration time for the token may be calculated by adding the lifetime to the createdAt time.
	Lifetime uint32

	// RequestTimeout is timeout duration for all synchronous requests over SecureChannel.
	// If the Server doesn't respond within RequestTimeout time, Client returns StatusBadTimeout
	RequestTimeout time.Duration

	// Logger is the logger for protocol-level messages.
	// If nil, logging is disabled.
	Logger *slog.Logger

	// ClientCertificateValidator, when set on a server SecureChannel, is
	// invoked during OpenSecureChannel after the peer certificate is known.
	// Return nil to accept; return a ua.StatusCode (typically
	// StatusBadCertificateUntrusted) to reject the channel open.
	// Nil means no application-certificate trust check at channel open.
	ClientCertificateValidator func(certDER []byte) error

	// HTTPSJSONContentType is the Content-Type of the requests of an
	// https-uajson channel (NewHTTPSJSONChannel). Empty means
	// HTTPSJSONContentType (Part 6 §7.4.2); HTTPSJSONContentTypeLegacy
	// reaches servers that take only that one (UA-.NETStandard 2.0.1).
	HTTPSJSONContentType string
}

// localKey returns the private key of the application instance certificate,
// or nil if there is none. The result is never a typed nil.
func (c *Config) localKey() crypto.PrivateKey {
	if c.LocalPrivateKey != nil {
		return c.LocalPrivateKey
	}
	if c.LocalKey != nil {
		return c.LocalKey
	}
	return nil
}

// userKey returns the private key of the user certificate, or nil.
func (c *Config) userKey() crypto.PrivateKey {
	if c.UserPrivateKey != nil {
		return c.UserPrivateKey
	}
	if c.UserKey != nil {
		return c.UserKey
	}
	return nil
}

// SessionConfig is a set of common configurations used in Session.
type SessionConfig struct {
	// AuthenticationToken is the secret Session identifier used to verify that the request is
	// associated with the Session. The SessionAuthenticationToken type is defined in 7.31.
	AuthenticationToken *ua.NodeID

	// ClientDescription is the information that describes the Client application.
	// The type ApplicationDescription is defined in 7.1.
	ClientDescription *ua.ApplicationDescription

	// ServerEndpoints is the list of Endpoints that the Server supports.
	// The Server shall return a set of EndpointDescriptions available for the serverUri
	// specified in the request. The EndpointDescription type is defined in 7.10. The Client
	// shall verify this list with the list from a DiscoveryEndpoint if it used a
	// DiscoveryEndpoint to fetch the EndpointDescriptions.
	// It is recommended that Servers only include the server.applicationUri, endpointUrl,
	// securityMode, securityPolicyUri, userIdentityTokens, transportProfileUri and
	// securityLevel with all other parameters set to null. Only the recommended
	// parameters shall be verified by the client.
	ServerEndpoints []*ua.EndpointDescription

	// LocaleIDs is the list of locale ids in priority order for localized strings. The first
	// LocaleId in the list has the highest priority. If the Server returns a localized string
	// to the Client, the Server shall return the translation with the highest priority that
	// it can. If it does not have a translation for any of the locales identified in this list,
	// then it shall return the string value that it has and include the locale id with the
	// string. See Part 3 for more detail on locale ids. If the Client fails to specify at least
	// one locale id, the Server shall use any that it has.
	// This parameter only needs to be specified during the first call to ActivateSession during
	// a single application Session. If it is not specified the Server shall keep using the
	// current localeIds for the Session.
	LocaleIDs []string

	// UserIdentityToken is the credentials of the user associated with the Client application.
	// The Server uses these credentials to determine whether the Client should be allowed to
	// activate a Session and what resources the Client has access to during this Session.
	// The UserIdentityToken is an extensible parameter type defined in 7.36.
	// The EndpointDescription specifies what UserIdentityTokens the Server shall accept.
	// Null or empty user token shall always be interpreted as anonymous.
	UserIdentityToken ua.IdentityToken

	// If the Client specified a user identity token that supports digital signatures, then it
	// shall create a signature and pass it as this parameter. Otherwise the parameter is null.
	// The SignatureAlgorithm depends on the identity token type.
	// The SignatureData type is defined in 7.32.
	UserTokenSignature *ua.SignatureData

	// SessionName is an optional name of the session.
	// The default is a unique value for every new session.
	SessionName string

	// If Session works as a client, SessionTimeout is the requested maximum number of milliseconds
	// that a Session should remain open without activity. If the Client fails to issue a Service
	// request within this interval, then the Server shall automatically terminate the Client Session.
	// If Session works as a server, SessionTimeout is an actual maximum number of milliseconds
	// that a Session shall remain open without activity. The Server should attempt to honour the
	// Client request for this parameter,but may negotiate this value up or down to meet its own constraints.
	SessionTimeout time.Duration

	// Stored version of the password to authenticate against a server
	// todo: storing passwords in memory seems wrong
	AuthPassword string

	// PolicyURI to use when encrypting secrets for the User Identity Token
	// Could be different from the secure channel's policy
	AuthPolicyURI string

	// PendingPolicyID is set by AuthPolicyID when called before an AuthXXX
	// method. AuthXXX methods apply it after token creation so that
	// AuthPolicyID can be called in any order relative to AuthXXX.
	PendingPolicyID string
}
