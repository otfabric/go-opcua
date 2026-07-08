// SPDX-License-Identifier: MIT

package opcua

import (
	"fmt"
	"strings"
	"time"
)

// ClientMetrics receives callbacks for client-side OPC-UA service calls.
// All methods are called synchronously; implementations must be non-blocking
// (e.g. increment an atomic counter, send on a buffered channel).
//
// Attach an implementation via [WithMetrics].
type ClientMetrics interface {
	// OnRequest is called before the request is sent to the server.
	// The service parameter is the OPC-UA service name (e.g. "Read", "Write",
	// "Browse", "Call", "CreateSubscription").
	OnRequest(service string)

	// OnResponse is called after a successful round-trip.
	OnResponse(service string, duration time.Duration)

	// OnError is called when a request fails with a non-timeout error.
	OnError(service string, duration time.Duration, err error)

	// OnTimeout is called when a request fails due to a timeout.
	OnTimeout(service string, duration time.Duration)
}

// serviceName extracts a human-readable service name from a request type.
// For example, *ua.ReadRequest becomes "Read" and *ua.CreateSubscriptionRequest
// becomes "CreateSubscription".
func serviceName(req any) string {
	s := fmt.Sprintf("%T", req)
	// Strip package prefix (e.g. "*ua.")
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	// Strip "Request" suffix
	s = strings.TrimSuffix(s, "Request")
	return s
}
