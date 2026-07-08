// SPDX-License-Identifier: MIT

package errors

import "errors"

// Connection errors.
var (
	ErrAlreadyConnected    = errors.New("opcua: already connected")
	ErrNotConnected        = errors.New("opcua: not connected")
	ErrSecureChannelClosed = errors.New("opcua: secure channel closed")
	ErrSessionClosed       = errors.New("opcua: session closed")
	ErrSessionNotActivated = errors.New("opcua: session not activated")
	ErrReconnectAborted    = errors.New("opcua: reconnect aborted")
)

// Configuration errors.
var (
	ErrInvalidEndpoint    = errors.New("opcua: invalid endpoint")
	ErrNoCertificate      = errors.New("opcua: no certificate")
	ErrInvalidPrivateKey  = errors.New("opcua: invalid private key")
	ErrInvalidCertificate = errors.New("opcua: invalid certificate")
	ErrNoMatchingEndpoint = errors.New("opcua: no matching endpoint")
	ErrNoEndpoints        = errors.New("opcua: no endpoints available")
)

// Subscription errors.
var (
	ErrSubscriptionNotFound  = errors.New("opcua: subscription not found")
	ErrMonitoredItemNotFound = errors.New("opcua: monitored item not found")
	ErrInvalidSubscriptionID = errors.New("opcua: invalid subscription ID")
	ErrSlowConsumer          = errors.New("opcua: slow consumer: messages may be dropped")
)

// Namespace errors.
var (
	ErrNamespaceNotFound    = errors.New("opcua: namespace not found")
	ErrInvalidNamespaceType = errors.New("opcua: invalid namespace array type")
)

// Codec errors.
var (
	ErrUnsupportedType = errors.New("opcua: unsupported type")
	ErrArrayTooLarge   = errors.New("opcua: array too large")
	ErrUnbalancedArray = errors.New("opcua: unbalanced multi-dimensional array")
)

// Response errors.
var (
	ErrInvalidResponseType = errors.New("opcua: invalid response type")
	ErrEmptyResponse       = errors.New("opcua: empty response")
)

// Security errors.
var (
	ErrUnsupportedSecurityPolicy = errors.New("opcua: unsupported security policy")
	ErrInvalidSecurityConfig     = errors.New("opcua: invalid security configuration")
	ErrSignatureValidationFailed = errors.New("opcua: signature validation failed")
	ErrInvalidCiphertext         = errors.New("opcua: invalid ciphertext")
	ErrInvalidPlaintext          = errors.New("opcua: invalid plaintext")
)

// Protocol errors.
var (
	ErrInvalidMessageType = errors.New("opcua: invalid message type")
	ErrMessageTooLarge    = errors.New("opcua: message too large")
	ErrMessageTooSmall    = errors.New("opcua: message too small")
	ErrTooManyChunks      = errors.New("opcua: too many chunks")
	ErrInvalidState       = errors.New("opcua: invalid state")
	ErrDuplicateHandler   = errors.New("opcua: duplicate handler registration")
	ErrUnknownService     = errors.New("opcua: unknown service")
)

// Node ID errors.
var (
	ErrInvalidNodeID         = errors.New("opcua: invalid node ID")
	ErrInvalidNamespace      = errors.New("opcua: invalid namespace")
	ErrTypeAlreadyRegistered = errors.New("opcua: type already registered")
)
