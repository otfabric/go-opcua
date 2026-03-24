// Package errors provides sentinel errors and helpers for the OPC-UA library.
//
// # Sentinel errors
//
// Use the named sentinel errors in sentinel.go (e.g. ErrNotConnected,
// ErrSessionClosed) so that callers can use [errors.Is] and [errors.As]:
//
//	import opcuaerrors "github.com/otfabric/go-opcua/errors"
//	if errors.Is(err, opcuaerrors.ErrNotConnected) { ... }
//
// When wrapping errors, use %w so that [errors.Is] and [errors.Unwrap] work:
//
//	return nil, fmt.Errorf("connect: %w", opcuaerrors.ErrInvalidEndpoint)
package errors
