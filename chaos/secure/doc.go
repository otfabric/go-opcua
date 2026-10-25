// SPDX-License-Identifier: MIT

// Package secure is the chaos-monkey and parallelism suite for secured
// channels: what package chaos does with SecurityPolicy None, done over one
// RSA policy (Basic256Sha256), the ECC policies ECC_nistP256,
// ECC_nistP384, ECC_brainpoolP256r1 and ECC_brainpoolP384r1, and the ECC
// policies with authenticated encryption ECC_nistP256_AesGcm,
// ECC_nistP256_ChaChaPoly, ECC_curve25519 and ECC_curve448, all in
// SignAndEncrypt mode with a username identity (encrypted with the server
// certificate on RSA, an EccEncryptedSecret on ECC).
//
// The package contains only tests, of a Go client against a Go server in
// one process. See package chaos for the common invariants and the knobs
// (CHAOS_SEED, CHAOS_DURATION, CHAOS_LOG); CHAOS_POLICY=<substring>
// restricts the scenarios to the policies whose name contains it.
//
// # What is tested
//
// The randomized scenario (monkey_test.go) runs one long-lived client per
// policy against one server that offers them all, with a mixed workload that
// includes requests and responses of several chunks, while the monkey
// injects every fault of the unsecured scenario plus attacks on the
// protected messages, made with ChaosProxy.SetFrameMangle: bit flips, chunks
// repeated at once or later (across a token renewal, on another channel),
// chunks lost while the connection stays up, chunks reordered or delivered
// on the wrong connection. A channel lifetime of 1.2 s keeps the channels
// renewing their tokens, with fresh ephemeral keys and key chaining.
//
// Because a secured channel either delivers an authentic message or fails,
// every result is verified, also while messages are being altered:
//
//   - every value read, and every value a subscription delivers, is one a
//     writer produced (the values of the test nodes are recognisable);
//   - a multi-chunk message arrives complete and in order or not at all, in
//     both directions;
//   - the server executes a request at most once;
//   - errors are connection-class or security-check errors;
//   - and the invariants of package chaos: no panic, race, deadlock or leak,
//     ordered streams, legal ConnState transitions, every client back to
//     Connected on its policy with its subscriptions delivering, a server
//     that serves a new client of every policy and holds nothing for the
//     departed ones.
//
// The parallelism tests (parallel_test.go) inject no faults and accept no
// errors: many goroutines with multi-chunk messages on one ECC or AEAD
// client; clients of every policy, mode and identity at once against the
// mixed RSA+ECC server; token renewals with requests in flight; and (with
// connection cuts as the only fault) sessions that move to a new channel
// under load without being replaced.
//
// regression_test.go pins down the product defects the suite found.
package secure
