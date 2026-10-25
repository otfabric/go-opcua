// SPDX-License-Identifier: MIT

// Package certmgmt holds the parallelism and robustness suite of the push
// certificate management of Part 12 §7 (server.WithPushManagement, package
// gds).
//
// The package contains only tests. They are meant to be run with the race
// detector:
//
//	go test -race ./chaos/certmgmt/
//	CHAOS_SEED=42 go test -race ./chaos/certmgmt/              # replay a seed
//	CHAOS_DURATION=60s go test -race ./chaos/certmgmt/         # longer churn
//
// # What is tested
//
// Several SecurityAdmin clients replace the trust list (WriteTrustList,
// AddCertificate, RemoveCertificate), install other application instance
// certificates (UpdateCertificate, with other keys too), create self-signed
// HTTPS certificates and delete them (DeleteCertificate), change the trust
// lists of the HTTPS and UserToken groups, manage the certificate and trust
// list of a certificate group of the application, try to delete the
// certificate the endpoints advertise, reset the server to its defaults
// (ResetToServerDefaults), read GetCertificates and the
// TransactionDiagnostics, apply and cancel their
// transactions, and drop their sessions in the middle of one, while
// other clients open and close secured channels and sessions with trusted,
// untrusted and revoked certificates and long-lived clients keep reading.
// The certificate alarms are evaluated every few milliseconds meanwhile.
//
// # Invariants
//
//   - every channel and session is validated against one trust list that an
//     ApplyChanges installed, never a mix of two: the trust lists of the
//     scenario reject one client certificate for different reasons (not
//     trusted in one, revoked in the other), and a mix of them would accept
//     it
//   - a certificate that every trust list trusts is never rejected, one that
//     none trusts never accepted, and the rejected list reports it
//   - every channel presents one of the certificates the admins installed
//   - ApplyChanges never deletes the certificate the endpoints advertise
//   - the trust list and certificate of the group of the application
//     applied last are the ones the application gets
//   - channels and sessions opened before a change keep working
//   - no panic, no data race, no deadlock, no goroutine left behind
//
// No assertion is made on how many operations complete in the time window.
package certmgmt
