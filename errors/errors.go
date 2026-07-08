// SPDX-License-Identifier: MIT

package errors

import (
	"errors"
)

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
