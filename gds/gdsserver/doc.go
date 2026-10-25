// SPDX-License-Identifier: MIT

// Package gdsserver makes a server.Server a Global Discovery Server (GDS)
// by the pull model of OPC UA Part 12 (v1.05): the Directory object with
// the application directory (§6: RegisterApplication, UpdateApplication,
// UnregisterApplication, FindApplications, GetApplication,
// QueryApplications, QueryServers) and certificate management (§7.9:
// StartSigningRequest, StartNewKeyPairRequest, FinishRequest,
// RevokeCertificate, GetCertificateGroups, GetCertificates, GetTrustList,
// GetCertificateStatus, CheckRevocationStatus) with the TrustList of its
// DefaultApplicationGroup.
//
// Attach imports the GDS information model (namespace
// http://opcfoundation.org/UA/GDS/, node ids of package gdsid) into a
// server before it starts. The GDS signs certificates with its own
// certificate authorities, one per key family (RSA, NIST P-256, NIST
// P-384, Ed25519, Ed448; the Brainpool types are signed by the NIST CA
// with the same hash), issues their CRLs and publishes them in the trust
// list. The CAs are generated on first use or configured with
// Config.Issuers. The state lives in a Store (MemoryStore by default).
//
// # Authorization
//
// Part 12 §6.2 and §7.2 define who may call what, which the GDS enforces:
//
//   - RegisterApplication needs the DiscoveryAdmin role.
//   - UpdateApplication and UnregisterApplication need DiscoveryAdmin or
//     the application itself.
//   - GetApplication needs an authenticated user, an administrator or the
//     application itself.
//   - FindApplications, QueryApplications and QueryServers are open to
//     every session.
//   - StartSigningRequest, StartNewKeyPairRequest and FinishRequest need
//     the CertificateAuthorityAdmin role or the application itself over a
//     SignAndEncrypt channel.
//   - RevokeCertificate needs CertificateAuthorityAdmin.
//   - GetCertificateGroups, GetCertificates, GetTrustList and
//     GetCertificateStatus need CertificateAuthorityAdmin or the
//     application itself.
//   - CheckRevocationStatus is open to every session on a signed channel.
//   - The TrustList may be read by CertificateAuthorityAdmin,
//     SecurityAdmin and the registered applications, and changed by
//     CertificateAuthorityAdmin over SignAndEncrypt.
//
// Every method except FindApplications, GetApplication, QueryApplications
// and QueryServers needs a signed channel. The roles DiscoveryAdmin and
// CertificateAuthorityAdmin are nodes of the GDS namespace
// (GDS.DiscoveryAdminRole, GDS.CertificateAuthorityAdminRole); a
// server.WithRoleMapper gives them to sessions.
//
// "The application itself" is a session whose channel certificate carries
// the ApplicationUri of the record and is a certificate the GDS issued to
// the application and did not revoke. An application that has no such
// certificate yet, typically one with a self-signed certificate that asks
// for its first one, is accepted only when Config.SelfAdmin says so;
// otherwise a CertificateAuthorityAdmin requests the first certificate for
// it.
//
// # Certificate requests
//
// A request waits for approval (GDS.Requests, GDS.ApproveRequest) unless
// Config.AutoApprove is set; FinishRequest returns Bad_NothingToDo while it
// waits and issues the certificate once it is approved. A signing request
// must carry the ApplicationUri of the application and a key of the
// certificate type; the issued certificate gets the host names of the
// discovery URLs. crypto/x509 cannot parse requests with Brainpool or
// Ed448 keys: StartSigningRequest refuses them with Bad_NotSupported, and
// StartNewKeyPairRequest serves those types. The private key of
// StartNewKeyPairRequest is returned as PEM (PKCS #8, encrypted with
// PBES2 when a password is given); PFX is not supported.
package gdsserver
