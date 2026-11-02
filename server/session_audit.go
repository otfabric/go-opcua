// SPDX-License-Identifier: MIT

package server

import (
	"crypto/sha1" //nolint:gosec // the certificate thumbprint of OPC UA is SHA-1 (Part 6 §6.2.2)
	"encoding/hex"
	"net"
	"strconv"
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

// Audit events of the SecureChannel and Session service sets (Part 4
// §6.5.5, §6.5.6; Part 5 §6.4.5 to §6.4.18), and the refused requests a
// SessionObserver is told about (Rejection).
//
// With auditing on ([WithAuditing]) the server reports to its Server
// object:
//
//   - AuditOpenSecureChannelEventType for an OpenSecureChannel that issued
//     a token and for every one that failed, a renewal too;
//   - AuditChannelEventType when an opened channel ends;
//   - AuditCreateSessionEventType and AuditActivateSessionEventType for
//     every CreateSession and ActivateSession, refused ones too;
//   - AuditSessionEventType when a session ends ("Session/CloseSession",
//     "Session/Timeout", "Session/Terminated") and for a failed
//     CloseSession;
//   - an AuditCertificateEventType subtype for an application or user
//     certificate a request was refused for.
//
// The user identity token of an AuditActivateSessionEventType carries no
// password and no issued token data (Part 5 §6.4.10).

// The Service of a [Rejection].
const (
	RejectedOpenSecureChannel = "OpenSecureChannel"
	RejectedCreateSession     = "CreateSession"
	RejectedActivateSession   = "ActivateSession"
)

// Rejection describes a request of a client that the server refused, for
// [SessionObserver.OnRejected].
type Rejection struct {
	// Service is the service the server refused: RejectedOpenSecureChannel
	// (e.g. an untrusted application certificate), RejectedCreateSession
	// or RejectedActivateSession (e.g. a wrong password).
	Service string
	// Status is the status the request was refused with.
	Status ua.StatusCode
	// RemoteAddr is the address of the client; nil over opc.https.
	RemoteAddr net.Addr
	// SecurityPolicyURI and SecurityMode are those of the secure channel;
	// for OpenSecureChannel those the client asked for.
	SecurityPolicyURI string
	SecurityMode      ua.MessageSecurityMode
	// ClientCertificate is the application instance certificate the client
	// sent, if any.
	ClientCertificate []byte
	// Session describes the session of a CreateSession (as far as the
	// request tells) or ActivateSession, with the identity type and user the
	// client tried; nil for OpenSecureChannel. The ID is nil when the
	// server knows no session.
	Session *SessionInfo
}

// Source names of the audit events (Part 5 §6.4.5 to §6.4.12, Part 4
// §6.5.6).
const (
	auditSourceOpenChannel   = "SecureChannel/OpenSecureChannel"
	auditSourceCloseChannel  = "SecureChannel/CloseSecureChannel"
	auditSourceCreateSession = "Session/CreateSession"
	auditSourceActivate      = "Session/ActivateSession"
	auditSourceCloseSession  = "Session/CloseSession"
	auditSourceTimeout       = "Session/Timeout"
	auditSourceTerminated    = "Session/Terminated"
	auditSourceCertificate   = "Security/Certificate"
)

// channelOpened is told about every OpenSecureChannel request of the
// channel sc with the id id, and the status it was answered with.
func (s *Server) channelOpened(sc *uasc.SecureChannel, chID uint32, req *ua.OpenSecureChannelRequest, st ua.StatusCode) {
	bad := isBad(st)
	if bad {
		s.observeRejected(Rejection{
			Service:           RejectedOpenSecureChannel,
			Status:            st,
			RemoteAddr:        sc.RemoteAddr(),
			SecurityPolicyURI: sc.SecurityPolicyURI(),
			SecurityMode:      req.SecurityMode,
			ClientCertificate: sc.RemoteCertificate(),
		})
	}
	// A renewal is audited only when it fails (Part 4 §6.5.5).
	if !s.auditing.Load() || (!bad && req.RequestType == ua.SecurityTokenRequestTypeRenew) {
		return
	}
	cert := sc.RemoteCertificate()
	var certEvent []byte
	if bad {
		certEvent = s.auditCertificate(cert, st, "")
	}
	msg := "OpenSecureChannel"
	if bad {
		msg += ": " + st.Error()
	}
	ev := s.securityAuditEvent(id.AuditOpenSecureChannelEventType, auditSourceOpenChannel, msg, st,
		"System/OpenSecureChannel", auditEntryOf(req.RequestHeader))
	f := ev.Fields
	f["SecureChannelId"] = ua.MustVariant(channelIDString(chID))
	f["ClientCertificate"] = ua.MustVariant(cert)
	f["ClientCertificateThumbprint"] = ua.MustVariant(thumbprint(cert))
	f["RequestType"] = ua.MustVariant(int32(req.RequestType))
	f["SecurityPolicyUri"] = ua.MustVariant(sc.SecurityPolicyURI())
	f["SecurityMode"] = ua.MustVariant(int32(req.SecurityMode))
	f["RequestedLifetime"] = ua.MustVariant(float64(req.RequestedLifetime))
	if certEvent != nil {
		f["CertificateErrorEventId"] = ua.MustVariant(certEvent)
	}
	s.emitAudit(ev)
}

// channelClosed is told when a channel that was opened ended.
func (s *Server) channelClosed(chID uint32) {
	if !s.auditing.Load() {
		return
	}
	ev := s.securityAuditEvent(id.AuditChannelEventType, auditSourceCloseChannel, "CloseSecureChannel", ua.StatusOK,
		"System/CloseSecureChannel", "")
	ev.Fields["SecureChannelId"] = ua.MustVariant(channelIDString(chID))
	s.emitAudit(ev)
}

// sessionServiceDone audits a call of the Session service set and tells
// the session observer about a refused one. It runs on the dispatcher after
// the handler.
func (s *Server) sessionServiceDone(sc *uasc.SecureChannel, req ua.Request, resp ua.Response, err error) {
	st := statusOfResult(resp, err)
	switch r := req.(type) {
	case *ua.CreateSessionRequest:
		s.createSessionDone(sc, r, resp, st)
	case *ua.ActivateSessionRequest:
		s.activateSessionDone(sc, r, st)
	case *ua.CloseSessionRequest:
		// A session that ends is audited when the broker forgets it
		// (sessionRemoved); here only a CloseSession that failed.
		if isBad(st) && s.auditing.Load() {
			ev := s.securityAuditEvent(id.AuditSessionEventType, auditSourceCloseSession, "CloseSession: "+st.Error(), st,
				"", auditEntryOf(r.RequestHeader))
			ev.Fields["SessionId"] = ua.MustVariant((*ua.NodeID)(nil))
			s.emitAudit(ev)
		}
	}
}

func (s *Server) createSessionDone(sc *uasc.SecureChannel, req *ua.CreateSessionRequest, resp ua.Response, st ua.StatusCode) {
	bad := isBad(st)
	cr, _ := resp.(*ua.CreateSessionResponse)
	if bad {
		s.observeRejected(Rejection{
			Service:           RejectedCreateSession,
			Status:            st,
			RemoteAddr:        remoteAddrOf(sc),
			SecurityPolicyURI: policyOf(sc),
			SecurityMode:      modeOf(sc),
			ClientCertificate: req.ClientCertificate,
			Session: &SessionInfo{
				Name:              req.SessionName,
				Client:            req.ClientDescription,
				EndpointURL:       req.EndpointURL,
				RemoteAddr:        remoteAddrOf(sc),
				SecurityPolicyURI: policyOf(sc),
				SecurityMode:      modeOf(sc),
			},
		})
	}
	if !s.auditing.Load() {
		return
	}
	if bad {
		s.auditCertificate(req.ClientCertificate, st, "")
	}
	msg := "CreateSession " + req.SessionName
	if bad {
		msg += ": " + st.Error()
	}
	ev := s.securityAuditEvent(id.AuditCreateSessionEventType, auditSourceCreateSession, msg, st,
		"System/CreateSession", auditEntryOf(req.RequestHeader))
	f := ev.Fields
	var sessionID *ua.NodeID
	var revised float64
	if !bad && cr != nil {
		sessionID, revised = cr.SessionID, cr.RevisedSessionTimeout
	}
	f["SessionId"] = ua.MustVariant(sessionID)
	f["SecureChannelId"] = ua.MustVariant(s.channelIDOf(sc))
	f["ClientCertificate"] = ua.MustVariant(req.ClientCertificate)
	f["ClientCertificateThumbprint"] = ua.MustVariant(thumbprint(req.ClientCertificate))
	f["RevisedSessionTimeout"] = ua.MustVariant(revised)
	s.emitAudit(ev)
}

func (s *Server) activateSessionDone(sc *uasc.SecureChannel, req *ua.ActivateSessionRequest, st ua.StatusCode) {
	bad := isBad(st)
	tok := requestedIdentity(req)
	var sess *session
	if hdr := req.RequestHeader; hdr != nil && hdr.AuthenticationToken != nil {
		sess = s.sb.peek(hdr.AuthenticationToken)
	}
	if bad {
		info := SessionInfo{}
		if sess != nil {
			info = sess.obs.snapshot()
		}
		info.RemoteAddr, info.SecurityPolicyURI, info.SecurityMode = remoteAddrOf(sc), policyOf(sc), modeOf(sc)
		info.User, _ = userOf(tok)
		info.IdentityType = tokenTypeOf(tok)
		info.Reactivated = sess != nil && sess.activated.Load()
		s.observeRejected(Rejection{
			Service:           RejectedActivateSession,
			Status:            st,
			RemoteAddr:        info.RemoteAddr,
			SecurityPolicyURI: info.SecurityPolicyURI,
			SecurityMode:      info.SecurityMode,
			ClientCertificate: certificateOf(sc, sess),
			Session:           &info,
		})
	}
	if !s.auditing.Load() {
		return
	}
	if x, ok := tok.(*ua.X509IdentityToken); ok && bad {
		s.auditCertificate(x.CertificateData, st, "")
	}
	var sessionID *ua.NodeID
	if sess != nil {
		sessionID = sess.ID
	}
	msg := "ActivateSession"
	if bad {
		msg += ": " + st.Error()
	}
	ev := s.securityAuditEvent(id.AuditActivateSessionEventType, auditSourceActivate, msg, st,
		auditUserID(tok), auditEntryOf(req.RequestHeader))
	f := ev.Fields
	f["SessionId"] = ua.MustVariant(sessionID)
	certs := make([]*ua.ExtensionObject, 0, len(req.ClientSoftwareCertificates))
	for _, c := range req.ClientSoftwareCertificates {
		certs = append(certs, ua.NewExtensionObject(c))
	}
	f["ClientSoftwareCertificates"] = ua.MustVariant(certs)
	f["UserIdentityToken"] = ua.MustVariant(ua.NewExtensionObject(withoutSecrets(tok)))
	f["SecureChannelId"] = ua.MustVariant(s.channelIDOf(sc))
	if !bad && sess != nil {
		f["CurrentRoleIds"] = ua.MustVariant(sess.handle().Roles())
	}
	s.emitAudit(ev)
}

// auditSessionEnd audits the end of a session the server created.
func (s *Server) auditSessionEnd(sess *session, reason SessionCloseReason) {
	if !s.auditing.Load() || sess.obs.snapshot().ID == nil {
		return
	}
	source := auditSourceTerminated
	switch reason {
	case SessionClosedByClient:
		source = auditSourceCloseSession
	case SessionTimedOut:
		source = auditSourceTimeout
	case SessionClosedByServer:
		source = auditSourceTerminated
	}
	ev := s.securityAuditEvent(id.AuditSessionEventType, source, "session "+reason.String(), ua.StatusOK,
		auditUserID(sess.identityToken), "")
	ev.Fields["SessionId"] = ua.MustVariant(sess.ID)
	s.emitAudit(ev)
}

// auditCertificate reports the AuditCertificateEventType subtype of a
// certificate a request was refused for with st (Part 5 §6.4.12 to
// §6.4.18) and returns its EventId; nil if st is no certificate error or
// there is no certificate.
func (s *Server) auditCertificate(cert []byte, st ua.StatusCode, invalidURI string) []byte {
	typ, ok := certificateAuditType(st)
	if !ok || len(cert) == 0 {
		return nil
	}
	ev := s.securityAuditEvent(typ, auditSourceCertificate, "certificate rejected: "+st.Error(), st, "", "")
	ev.Fields["Certificate"] = ua.MustVariant(cert)
	if typ == id.AuditCertificateDataMismatchEventType {
		ev.Fields["InvalidUri"] = ua.MustVariant(invalidURI)
		ev.Fields["InvalidHostname"] = ua.MustVariant("")
	}
	s.emitAudit(ev)
	return ev.EventID
}

// certificateAuditType returns the AuditCertificateEventType subtype of a
// certificate status.
func certificateAuditType(st ua.StatusCode) (uint32, bool) {
	switch st {
	case ua.StatusBadCertificateTimeInvalid, ua.StatusBadCertificateIssuerTimeInvalid:
		return id.AuditCertificateExpiredEventType, true
	case ua.StatusBadCertificateUntrusted, ua.StatusBadCertificateChainIncomplete:
		return id.AuditCertificateUntrustedEventType, true
	case ua.StatusBadCertificateRevoked, ua.StatusBadCertificateIssuerRevoked,
		ua.StatusBadCertificateRevocationUnknown, ua.StatusBadCertificateIssuerRevocationUnknown:
		return id.AuditCertificateRevokedEventType, true
	case ua.StatusBadCertificateUseNotAllowed, ua.StatusBadCertificateIssuerUseNotAllowed,
		ua.StatusBadCertificatePolicyCheckFailed:
		return id.AuditCertificateMismatchEventType, true
	case ua.StatusBadCertificateURIInvalid, ua.StatusBadCertificateHostNameInvalid:
		return id.AuditCertificateDataMismatchEventType, true
	case ua.StatusBadCertificateInvalid:
		return id.AuditCertificateInvalidEventType, true
	default:
		return 0, false
	}
}

// securityAuditEvent builds an AuditSecurityEventType event (Part 5 §6.4.4)
// of type typ for the Server object.
func (s *Server) securityAuditEvent(typ uint32, source, msg string, st ua.StatusCode, userID, auditEntry string) *BaseEvent {
	now := s.now()
	return &BaseEvent{
		EventID:    newEventID(),
		EventType:  ua.NewNumericNodeID(0, typ),
		SourceNode: ua.NewNumericNodeID(0, id.Server),
		SourceName: source,
		Time:       now,
		Message:    ua.NewLocalizedTextWithLocale(msg, "en"),
		Severity:   100,
		Fields: map[string]*ua.Variant{
			// AuditEventType (Part 5 §6.4.3)
			"ActionTimeStamp":    ua.MustVariant(now),
			"Status":             ua.MustVariant(!isBad(st)),
			"ServerId":           ua.MustVariant(s.cfg.applicationURI),
			"ClientAuditEntryId": ua.MustVariant(auditEntry),
			"ClientUserId":       ua.MustVariant(userID),
			// AuditSecurityEventType (Part 5 §6.4.4)
			"StatusCodeId": ua.MustVariant(st),
		},
		audit: true,
	}
}

// emitAudit reports an audit event of the server to its Server object.
func (s *Server) emitAudit(ev *BaseEvent) {
	s.emitEvent(ua.NewNumericNodeID(0, id.Server), ev, true)
}

// observeRejected tells the session observer about a refused request.
func (s *Server) observeRejected(r Rejection) {
	if o := s.cfg.sessionObserver; o != nil {
		defer s.recoverObserver("OnRejected")
		o.OnRejected(r)
	}
}

// requestedIdentity returns the identity token of an ActivateSession
// request; a null or empty one is anonymous (Part 4 §5.6.3).
func requestedIdentity(req *ua.ActivateSessionRequest) ua.IdentityToken {
	if req.UserIdentityToken != nil {
		if tok, ok := req.UserIdentityToken.Value.(ua.IdentityToken); ok {
			return tok
		}
	}
	return &ua.AnonymousIdentityToken{}
}

// withoutSecrets returns tok without its password or issued token data, the
// secrets a token carries.
func withoutSecrets(tok ua.IdentityToken) ua.IdentityToken {
	switch t := tok.(type) {
	case *ua.UserNameIdentityToken:
		c := *t
		c.Password, c.EncryptionAlgorithm = nil, ""
		return &c
	case *ua.IssuedIdentityToken:
		c := *t
		c.TokenData, c.EncryptionAlgorithm = nil, ""
		return &c
	}
	return tok
}

// auditUserID is the ClientUserId of an audit event of a user (Part 5
// §6.4.3).
func auditUserID(tok ua.IdentityToken) string {
	switch t := tok.(type) {
	case *ua.UserNameIdentityToken:
		return t.UserName
	case *ua.X509IdentityToken:
		if cert, err := uapolicy.LeafCertificate(t.CertificateData); err == nil {
			return cert.Subject.String()
		}
		return "X509"
	case *ua.IssuedIdentityToken:
		return "IssuedToken"
	}
	return "Anonymous"
}

func auditEntryOf(hdr *ua.RequestHeader) string {
	if hdr == nil {
		return ""
	}
	return hdr.AuditEntryID
}

// thumbprint is the hex SHA-1 thumbprint of the leaf of a certificate
// (chain); empty without one.
func thumbprint(cert []byte) string {
	if len(cert) == 0 {
		return ""
	}
	if leaf, err := uapolicy.LeafCertificate(cert); err == nil {
		cert = leaf.Raw
	}
	sum := sha1.Sum(cert) //nolint:gosec // see the import
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// channelIDOf returns the SecureChannelId of sc for an audit event; empty
// for a virtual channel of opc.https or opcua+uajson.
func (s *Server) channelIDOf(sc *uasc.SecureChannel) string {
	if s.cb == nil || sc == nil {
		return ""
	}
	return channelIDString(s.cb.channelID(sc))
}

func channelIDString(chID uint32) string {
	if chID == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(chID), 10)
}

func remoteAddrOf(sc *uasc.SecureChannel) net.Addr {
	if sc == nil {
		return nil
	}
	return sc.RemoteAddr()
}

func policyOf(sc *uasc.SecureChannel) string {
	if sc == nil {
		return ua.SecurityPolicyURINone
	}
	return sc.SecurityPolicyURI()
}

func modeOf(sc *uasc.SecureChannel) ua.MessageSecurityMode {
	if sc == nil {
		return ua.MessageSecurityModeNone
	}
	return sc.SecurityMode()
}

// certificateOf returns the application certificate of a session, else of
// its channel.
func certificateOf(sc *uasc.SecureChannel, sess *session) []byte {
	if sess != nil && len(sess.remoteCertificate) > 0 {
		return sess.remoteCertificate
	}
	if sc == nil {
		return nil
	}
	return sc.RemoteCertificate()
}
