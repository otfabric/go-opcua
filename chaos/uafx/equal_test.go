// SPDX-License-Identifier: MIT

package uafx

import (
	"reflect"
	"strings"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// equal reports whether two reports are the same.
func equal(a, b *uafx.Report) bool { return reflect.DeepEqual(a, b) }

// isFaultError reports whether err is an error a caller must expect while
// the transport is disturbed or the bytes of a secured message are altered
// or lost. It is the classification of chaos/secure.
func isFaultError(err error) bool {
	if chaoskit.IsConnectionError(err) {
		return true
	}
	for _, sc := range []ua.StatusCode{
		// a signature, tag, padding or sequence number that does not verify
		ua.StatusBadSecurityChecksFailed,
		ua.StatusBadSequenceNumberInvalid,
		// a damaged chunk header or OpenSecureChannel message
		ua.StatusBadSecurityPolicyRejected,
		ua.StatusBadCertificateInvalid,
		ua.StatusBadDecodingError,
		ua.StatusBadTCPMessageTypeInvalid,
		ua.StatusBadTCPMessageTooLarge,
		ua.StatusBadTCPSecureChannelUnknown,
		ua.StatusBadTCPInternalError,
	} {
		if errors.Is(err, sc) {
			return true
		}
	}
	if errors.Is(err, errors.ErrMessageTooLarge) || errors.Is(err, errors.ErrMessageTooSmall) || errors.Is(err, errors.ErrInvalidMessageType) {
		return true
	}
	return errors.Is(err, errors.ErrInvalidState) &&
		(strings.Contains(err.Error(), "openingInstance is nil") || strings.Contains(err.Error(), "SecureChannelID="))
}
