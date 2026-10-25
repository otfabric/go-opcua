// SPDX-License-Identifier: MIT

// Package gdsserver makes a server.Server a Global Discovery Server (GDS)
// by the pull model of OPC UA Part 12 (v1.05): the Directory object with
// the application directory (§6: RegisterApplication, UpdateApplication,
// UnregisterApplication, FindApplications, GetApplication,
// QueryApplications, QueryServers) and certificate management (§7.9:
// StartSigningRequest, StartNewKeyPairRequest, FinishRequest,
// RevokeCertificate, GetCertificateGroups, GetCertificates, GetTrustList,
// GetCertificateStatus, CheckRevocationStatus) with the TrustLists of its
// certificate groups.
//
// Attach imports the GDS information model (namespace
// http://opcfoundation.org/UA/GDS/, node ids of package gdsid) into a
// server before it starts. The GDS signs certificates with its own
// certificate authorities, one per key type (RSA, NIST P-256, NIST P-384,
// brainpoolP256r1, brainpoolP384r1, Ed25519, Ed448), issues their CRLs and
// publishes them in the trust lists. The CAs are generated on first use or
// configured with Config.Issuers. The state lives in a Store: MemoryStore
// by default, or NewFileStore for a directory (one JSON file per record,
// written atomically, private files).
//
// # Certificate groups
//
//   - DefaultApplicationGroup: the application certificate types of
//     Config.CertificateTypes; its trust list holds every CA of the GDS.
//   - DefaultHttpsGroup: HttpsCertificateType (TLS server certificates,
//     RSA or ECDSA on P-256 or P-384) when the GDS has an RSA, NistP256 or
//     NistP384 CA; its trust list holds those CAs. A request for it may
//     leave out the ApplicationUri.
//   - DefaultUserTokenGroup: issues no certificates; its trust list holds
//     what a CertificateAuthorityAdmin adds (the issuers of the X.509 user
//     tokens a server accepts).
//
// GetCertificateGroups returns the application group for a client and all
// three (the HTTPS group only if it issues) for a server.
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
//   - The TrustLists may be read by CertificateAuthorityAdmin,
//     SecurityAdmin and the registered applications, and changed by
//     CertificateAuthorityAdmin over SignAndEncrypt.
//
// Every method except FindApplications, GetApplication, QueryApplications
// and QueryServers needs a signed channel. The roles DiscoveryAdmin and
// CertificateAuthorityAdmin are nodes of the GDS namespace
// (GDS.DiscoveryAdminRole, GDS.CertificateAuthorityAdminRole); a
// server.WithRoleMapper gives them to sessions.
//
// The methods carry the RolePermissions of the GDS NodeSet, which the GDS
// honours besides the rules above: a session none of whose roles has the
// Call permission is refused, except for the methods an application calls
// for itself (ApplicationSelfAdmin is a privilege, not a role). The
// server.RBACAccessController applies the same RolePermissions before the
// GDS sees a call and has no notion of the application itself: with it,
// an application without a role cannot call those methods for itself.
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
// certificate type, of any key type (uapolicy parses and checks the
// request); the issued certificate gets the host names of the discovery
// URLs. The private key of StartNewKeyPairRequest is returned as PEM
// (PKCS #8, encrypted with PBES2 when a password is given) or PFX (PKCS #12
// with the certificate and its issuer, protected with the password).
//
// # Audit events
//
// When the server audits (server.WithAuditing), the methods report the
// audit events of the GDS NodeSet to the Server object and the Directory:
// ApplicationRegistrationChangedAuditEventType (Register, Update,
// Unregister), CertificateRequestedAuditEventType (StartSigningRequest,
// StartNewKeyPairRequest), CertificateDeliveredAuditEventType
// (FinishRequest, except while the request waits) and
// CertificateRevokedAuditEventType, with the arguments but without the
// password and the private key. A server.EventAccessController (the
// RBACAccessController: ReceiveEvents for SecurityAdmin, by the NodeSet)
// decides who receives them.
package gdsserver
