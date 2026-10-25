// SPDX-License-Identifier: MIT

// Package eccext holds the conformance tests of the ECC_brainpoolP256r1,
// ECC_brainpoolP384r1 and ECC_curve448 security policies. They belong with
// the tests of conformance/security (helpers_test.go and ecc_helpers_test.go
// are copies of the helpers of the conformance packages) in a package of their
// own because the Brainpool curves run on math/big: under the race detector
// these tests alone take as much CPU as a third of the conformance suite, which
// CI gives 120 s per package.
package eccext
