// SPDX-License-Identifier: MIT

package fxcm

import (
	"errors"
	"fmt"
	"strings"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// ErrConfig is in the chain of every error about an invalid
// ConnectionConfigurationSet or file.
var ErrConfig = errors.New("fxcm: configuration")

// ErrManager is in the chain of the errors of the ConnectionManager that are
// not about the content of a set, such as an edit by a client that does not
// hold the Lock.
var ErrManager = errors.New("fxcm: manager")

// Finding is one defect of a ConnectionConfigurationSet.
type Finding struct {
	// Path names the field, such as "Connections[0].Endpoint1.Name".
	Path string
	// Clause is the clause of Part 81 the defect violates, or
	// "library interpretation" where the library decides.
	Clause string
	// Problem says what is wrong.
	Problem string
}

func (f Finding) String() string {
	return f.Path + ": " + f.Problem + " (" + f.Clause + ")"
}

// ConfigError is a ConnectionConfigurationSet that is not valid: one Finding
// per defect. ErrConfig and ua.StatusBadConfigurationError are in its chain;
// its FxError is ConnectionConfigurationSetInvalid (§10.25).
type ConfigError struct {
	Key      SetKey
	Findings []Finding
}

func (e *ConfigError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "fxcm: the ConnectionConfigurationSet %s is not valid", e.Key)
	for i, f := range e.Findings {
		if i == 3 {
			fmt.Fprintf(&b, "; and %d more", len(e.Findings)-3)
			break
		}
		b.WriteString("; ")
		b.WriteString(f.String())
	}
	return b.String()
}

// Unwrap returns ErrConfig and ua.StatusBadConfigurationError.
func (e *ConfigError) Unwrap() []error {
	return []error{ErrConfig, ua.StatusBadConfigurationError}
}

// FxError returns ConnectionConfigurationSetInvalid, the FxError of an
// invalid set (§10.25).
func (e *ConfigError) FxError() uafx.FxError { return uafx.FxErrorConnectionConfigurationSetInvalid }

// statusError is an error of the package with the StatusCode the
// specification gives for it in its chain.
type statusError struct {
	sentinel error
	code     ua.StatusCode
	msg      string
}

func (e *statusError) Error() string         { return e.sentinel.Error() + ": " + e.msg }
func (e *statusError) Unwrap() []error       { return []error{e.sentinel, e.code} }
func (e *statusError) Status() ua.StatusCode { return e.code }

func managerError(code ua.StatusCode, format string, args ...any) error {
	return &statusError{sentinel: ErrManager, code: code, msg: fmt.Sprintf(format, args...)}
}

func configError(code ua.StatusCode, format string, args ...any) error {
	return &statusError{sentinel: ErrConfig, code: code, msg: fmt.Sprintf(format, args...)}
}

// StatusOf returns the StatusCode in the chain of err: Good for nil,
// ua.StatusBad for an error without one.
func StatusOf(err error) ua.StatusCode {
	if err == nil {
		return ua.StatusGood
	}
	var c ua.StatusCode
	if errors.As(err, &c) {
		return c
	}
	return ua.StatusBad
}
