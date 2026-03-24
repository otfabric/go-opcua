package errors

import (
	"errors"
)

// Prefix is the default error string prefix.
const Prefix = "opcua: "

// New wraps errors.New.
//
// Deprecated: Use sentinel errors from errors/sentinel.go instead.
// Example: var ErrFoo = errors.New("opcua: foo").
func New(text string) error {
	return errors.New(Prefix + text)
}

// Is wraps errors.Is.
func Is(err error, target error) bool {
	return errors.Is(err, target)
}

// As wraps errors.As. Prefer using [errors.As] from the standard library with target as any.
func As(err error, target any) bool {
	return errors.As(err, target)
}

// Unwrap wraps errors.Unwrap.
func Unwrap(err error) error {
	return errors.Unwrap(err)
}

// Join wraps errors.Join.
func Join(errs ...error) error {
	return errors.Join(errs...)
}
