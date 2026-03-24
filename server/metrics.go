package server

import (
	"fmt"
	"strings"
	"time"
)

// ServerMetrics receives callbacks for server-side OPC-UA service calls.
// All methods are called synchronously; implementations must be non-blocking
// (e.g. increment an atomic counter, send on a buffered channel).
//
// Attach an implementation via [WithMetrics].
type ServerMetrics interface {
	// OnRequest is called before invoking the service handler.
	// The service parameter is the OPC-UA service name (e.g. "Read", "Write",
	// "Browse", "Call", "CreateSubscription").
	OnRequest(service string)

	// OnResponse is called after the handler returns without error.
	OnResponse(service string, duration time.Duration)

	// OnError is called when the handler returns an error.
	OnError(service string, duration time.Duration, err error)
}

// WithMetrics sets a metrics callback handler for the server.
// All methods are called synchronously; implementations must be non-blocking.
func WithMetrics(m ServerMetrics) Option {
	return func(s *serverConfig) error {
		s.metrics = m
		return nil
	}
}

// serviceName extracts a human-readable service name from a request type.
// For example, *ua.ReadRequest becomes "Read".
func serviceName(req any) string {
	s := fmt.Sprintf("%T", req)
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(s, "Request")
	return s
}
