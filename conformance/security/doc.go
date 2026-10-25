// SPDX-License-Identifier: MIT

// Package security holds the conformance tests of secure channels and user
// identities: every RSA and ECC security policy in both secure modes, the
// identity token types, certificate validation and secure channel renewal.
// They are a package of their own because CI gives every package 120 s under
// the race detector; the helpers are shared with the other conformance
// packages through conformkit.
package security
