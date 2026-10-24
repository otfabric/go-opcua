// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
	"github.com/otfabric/go-opcua/uasc"
)

const (
	sessionTimeoutMin     = 100 * time.Millisecond // Part 4 practical floor
	sessionTimeoutMax     = 30 * time.Minute
	sessionTimeoutDefault = 60 * time.Second

	sessionNonceLength = 32
)

// SessionService implements the Session Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6
type SessionService struct {
	srv *Server
}

// CreateSession implements the OPC UA CreateSession service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.2
func (s *SessionService) CreateSession(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Info("handling CreateSession request")

	req, err := safeReq[*ua.CreateSessionRequest](r)
	if err != nil {
		return nil, err
	}

	// A session may only be created over a SecureChannel whose security
	// policy and mode match one of the endpoints this server exposes
	// (Part 4 §5.6.2). Without this check a client could simply pick a weaker
	// policy/mode than any the operator enabled.
	if st := s.checkChannelSecurity(sc); st != ua.StatusOK {
		s.srv.cfg.logger.Warn("CreateSession rejected: secure channel security not enabled on this server",
			"policy", sc.SecurityPolicyURI(), "mode", sc.SecurityMode())
		return nil, st
	}

	// New session
	sess := s.srv.sb.NewSession()

	// Ensure session timeout is reasonable
	sessionTimeout := time.Duration(req.RequestedSessionTimeout) * time.Millisecond
	if sessionTimeout > sessionTimeoutMax || sessionTimeout < sessionTimeoutMin {
		sessionTimeout = sessionTimeoutDefault
	}
	sess.setTimeout(sessionTimeout)

	nonce := make([]byte, sessionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		s.srv.cfg.logger.Warn("error creating session nonce")
		return nil, ua.StatusBadInternalError
	}
	sess.serverNonce = nonce
	sess.clientNonce = req.ClientNonce
	sess.remoteCertificate = req.ClientCertificate

	// Validate the client's application certificate against the server's
	// configured trust store (OPC UA Part 4 §5.6.3). Skip validation when no
	// validator is configured (the secure channel still enforces message
	// integrity; this is an additional application-level trust check).
	if s.srv.cfg.clientCertificateValidator != nil && len(req.ClientCertificate) > 0 {
		if err := s.srv.cfg.clientCertificateValidator(req.ClientCertificate); err != nil {
			s.srv.cfg.logger.Warn("client certificate rejected", "error", err)
			// The client never learns of the session: do not keep it
			// until its timeout.
			_ = s.srv.sb.Close(sess.AuthTokenID)
			return nil, err
		}
	}

	sig, alg, err := sc.NewCreateSessionSignature(req.ClientCertificate, req.ClientNonce, nonce)
	if err != nil {
		s.srv.cfg.logger.Warn("error creating session signature")
		_ = s.srv.sb.Close(sess.AuthTokenID)
		return nil, ua.StatusBadInternalError
	}

	matchingEndpoints := make([]*ua.EndpointDescription, 0)
	reqTrimmedURL, _ := strings.CutSuffix(req.EndpointURL, "/")
	for i := range s.srv.endpoints {
		ep := s.srv.endpoints[i]
		epTrimmedURL, _ := strings.CutSuffix(ep.EndpointURL, "/")
		if epTrimmedURL == reqTrimmedURL {
			matchingEndpoints = append(matchingEndpoints, ep)
		}
	}

	hdr := responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK)
	if st := s.issueEphemeralKey(sc, sess, req.RequestHeader, hdr, true); st != ua.StatusOK {
		_ = s.srv.sb.Close(sess.AuthTokenID)
		return nil, st
	}

	response := &ua.CreateSessionResponse{
		ResponseHeader:        hdr,
		SessionID:             sess.ID,
		AuthenticationToken:   sess.AuthTokenID,
		RevisedSessionTimeout: float64(sess.cfg.sessionTimeout / time.Millisecond),
		MaxRequestMessageSize: 0, // Not used
		ServerSignature: &ua.SignatureData{
			Signature: sig,
			Algorithm: alg,
		},
		ServerCertificate: s.serverCertificate(sc),
		ServerNonce:       nonce,
		ServerEndpoints:   matchingEndpoints,
	}

	return response, nil
}

// ActivateSession implements the OPC UA ActivateSession service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.3
func (s *SessionService) ActivateSession(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.ActivateSessionRequest](r)
	if err != nil {
		return nil, err
	}

	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)
	if sess == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	var clientSignature []byte
	if req.ClientSignature != nil {
		clientSignature = req.ClientSignature.Signature
	}
	err = sc.VerifyActivateSessionSignature(sess.remoteCertificate, sess.serverNonce, sess.clientNonce, clientSignature)
	if err != nil {
		s.srv.cfg.logger.Warn("error verifying session signature", "error", err)
		return nil, ua.StatusBadSecurityChecksFailed
	}

	// The client computed its user token signature / encrypted its password
	// against the nonce it last received, so keep that one for validating the
	// identity token before handing out the next nonce.
	// The new nonce is therefore only stored once the token has been accepted.
	prevNonce := sess.serverNonce

	nonce := make([]byte, sessionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		s.srv.cfg.logger.Warn("error creating session nonce")
		return nil, ua.StatusBadInternalError
	}

	// Extract user identity, validate credentials, and resolve roles.
	if req.UserIdentityToken != nil {
		if token, ok := req.UserIdentityToken.Value.(ua.IdentityToken); ok {
			sess.identityToken = token
		}
	}

	// Validate username/password credentials if the client presented a
	// UserNameIdentityToken. Without a validator nobody can check them, so
	// they are rejected.
	if uname, ok := sess.identityToken.(*ua.UserNameIdentityToken); ok {
		if s.srv.cfg.usernameValidator == nil {
			s.srv.cfg.logger.Warn("ActivateSession username rejected: no UsernameValidator configured",
				"username", uname.UserName)
			return nil, ua.StatusBadUserAccessDenied
		}
		// On secured channels the password arrives encrypted with the server
		// certificate (Part 4 §7.41). Decrypt it before validation.
		password, st := s.decryptUserPassword(sc, sess, uname, prevNonce)
		if st != ua.StatusOK {
			s.srv.cfg.logger.Warn("ActivateSession username token: cannot decrypt password",
				"username", uname.UserName, "status", st)
			return nil, st
		}
		uname.Password = password
		uname.EncryptionAlgorithm = ""
		if v := s.srv.cfg.usernameValidator; v != nil {
			if err := v(uname.UserName, string(uname.Password)); err != nil {
				s.srv.cfg.logger.Info("ActivateSession username rejected",
					"username", uname.UserName,
					"password_len", len(uname.Password),
					"error", err,
				)
				return nil, ua.StatusBadUserAccessDenied
			}
			s.srv.cfg.logger.Info("ActivateSession username accepted",
				"username", uname.UserName,
				"password_len", len(uname.Password),
			)
		}
	}

	// The data of an issued token is a secret like a password. With an ECC
	// security policy it arrives as an EccEncryptedSecret; the role mapper
	// gets the token the issuer created.
	if issued, ok := sess.identityToken.(*ua.IssuedIdentityToken); ok && uapolicy.IsECC(s.userTokenPolicy(sc)) {
		data, st := s.decryptEccSecret(sc, sess, issued.TokenData, prevNonce)
		if st != ua.StatusOK {
			s.srv.cfg.logger.Warn("ActivateSession issued token: cannot decrypt token data", "status", st)
			return nil, st
		}
		issued.TokenData = data
		issued.EncryptionAlgorithm = ""
	}

	// An issued token is only accepted by a configured validator: without
	// one nobody has checked it.
	if issued, ok := sess.identityToken.(*ua.IssuedIdentityToken); ok {
		v := s.srv.cfg.issuedTokenValidator
		if v == nil {
			s.srv.cfg.logger.Warn("ActivateSession issued token rejected: no IssuedTokenValidator configured")
			return nil, ua.StatusBadIdentityTokenRejected
		}
		if err := v(issued); err != nil {
			s.srv.cfg.logger.Info("ActivateSession issued token rejected by validator", "error", err)
			return nil, ua.StatusBadIdentityTokenRejected
		}
	}

	// Validate X.509 identity token (OPC UA Part 4 §5.6.3.3).
	if x509tok, ok := sess.identityToken.(*ua.X509IdentityToken); ok {
		if err := s.validateX509UserToken(sc, sess, req, x509tok); err != nil {
			return nil, err
		}
	}

	sess.serverNonce = nonce

	if rm := s.srv.cfg.roleMapper; rm != nil {
		sess.roles = rm(sess.identityToken)
	} else {
		sess.roles = DefaultRoleMapper(sess.identityToken)
	}

	hdr := responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK)
	if st := s.issueEphemeralKey(sc, sess, req.RequestHeader, hdr, false); st != ua.StatusOK {
		return nil, st
	}

	sess.activated.Store(true)

	response := &ua.ActivateSessionResponse{
		ResponseHeader: hdr,
		ServerNonce:    nonce,
		// Results:         []ua.StatusCode{},
		// DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	return response, nil
}

// validateX509UserToken verifies an X509IdentityToken presented in ActivateSession.
//
// Per OPC UA Part 4 §5.6.3.3:
//  1. The certificate in the token must be parseable.
//  2. The UserTokenSignature must be a valid signature over (serverCertificate || serverNonce)
//     using the private key that corresponds to the token certificate. This proves the
//     client possesses the key and prevents certificate-replay attacks.
//  3. The server's configured X509UserValidator is called for trust-store and
//     application-level policy decisions.
func (s *SessionService) validateX509UserToken(
	sc *uasc.SecureChannel,
	sess *session,
	req *ua.ActivateSessionRequest,
	tok *ua.X509IdentityToken,
) error {
	if len(tok.CertificateData) == 0 {
		return ua.StatusBadIdentityTokenInvalid
	}

	userCert, err := x509.ParseCertificate(tok.CertificateData)
	if err != nil {
		s.srv.cfg.logger.Warn("ActivateSession X.509 user token: cannot parse certificate", "error", err)
		return ua.StatusBadIdentityTokenInvalid
	}

	// Verify the UserTokenSignature: signature over (serverCertificate || serverNonce).
	// This proves the client holds the private key for the presented certificate.
	{
		// Determine the security policy for the user token: the token policy may
		// specify its own URI; fall back to the secure channel policy.
		policyURI := sc.SecurityPolicyURI()
		if tok.PolicyID != "" {
			// Look up the policy URI from the user token policy; if not found, keep
			// the channel policy.
			for _, ep := range s.srv.Endpoints() {
				for _, utp := range ep.UserIdentityTokens {
					if utp.PolicyID == tok.PolicyID && utp.SecurityPolicyURI != "" {
						policyURI = utp.SecurityPolicyURI
					}
				}
			}
		}

		if policyURI != ua.SecurityPolicyURINone {
			// Without a signature nothing shows that the client holds the
			// private key: a certificate is public and anyone can present it.
			if req.UserTokenSignature == nil || len(req.UserTokenSignature.Signature) == 0 {
				s.srv.cfg.logger.Warn("ActivateSession X.509 user token: no user token signature")
				return ua.StatusBadUserSignatureInvalid
			}

			remoteKey, keyErr := uapolicy.CertificatePublicKey(tok.CertificateData)
			if keyErr != nil {
				s.srv.cfg.logger.Warn("ActivateSession X.509 user token: cannot extract public key", "error", keyErr)
				return ua.StatusBadIdentityTokenInvalid
			}

			// The key type of the user certificate has to fit the policy: an
			// ECC policy verifies ECDSA signatures only, ECC_curve25519
			// Ed25519 ones.
			if encErr := uapolicy.CheckPublicKey(policyURI, remoteKey); encErr != nil {
				s.srv.cfg.logger.Warn("ActivateSession X.509 user token: cannot build asymmetric context", "error", encErr)
				return ua.StatusBadIdentityTokenInvalid
			}

			// Message is serverCertificate || serverNonce per Part 4 §7.37,
			// or the channel bound data of Part 4 §6.1.8 if the policies of
			// the channel and of the token have SecureChannelEnhancements.
			sigErr := sc.VerifySessionUserTokenSignature(policyURI, tok.CertificateData, s.serverCertificate(sc), sess.serverNonce, sess.clientNonce, req.UserTokenSignature.Signature)
			if sigErr != nil {
				s.srv.cfg.logger.Warn("ActivateSession X.509 user token: signature verification failed", "error", sigErr)
				return ua.StatusBadUserSignatureInvalid
			}
		}
	}

	// Delegate trust-store and policy decisions to the configured validator.
	if v := s.srv.cfg.x509UserValidator; v != nil {
		if err := v(tok.CertificateData); err != nil {
			s.srv.cfg.logger.Info("ActivateSession X.509 user token rejected by validator",
				"subject", userCert.Subject.String(),
				"error", err,
			)
			return ua.StatusBadIdentityTokenRejected
		}
		s.srv.cfg.logger.Info("ActivateSession X.509 user token accepted",
			"subject", userCert.Subject.String(),
		)
		return nil
	}

	// No validator means no configured trust decision: reject to avoid silently
	// accepting tokens that have not been vetted.
	s.srv.cfg.logger.Warn("ActivateSession X.509 user token rejected: no X509UserValidator configured",
		"subject", userCert.Subject.String(),
	)
	return ua.StatusBadIdentityTokenRejected
}

// checkChannelSecurity reports whether the secure channel uses a security
// policy / mode combination enabled on this server. Servers constructed
// without any EnableSecurity option (bare unit-test servers) are not
// restricted.
func (s *SessionService) checkChannelSecurity(sc *uasc.SecureChannel) ua.StatusCode {
	if sc == nil || len(s.srv.cfg.enabledSec) == 0 {
		return ua.StatusOK
	}
	policy, mode := sc.SecurityPolicyURI(), sc.SecurityMode()
	policyKnown := false
	for _, sec := range s.srv.cfg.enabledSec {
		if sec.secPolicy != policy {
			continue
		}
		policyKnown = true
		if sec.secMode == mode {
			return ua.StatusOK
		}
	}
	if policyKnown {
		return ua.StatusBadSecurityModeRejected
	}
	return ua.StatusBadSecurityPolicyRejected
}

// decryptUserPassword returns the clear-text password of a UserNameIdentityToken.
//
// When the token carries no EncryptionAlgorithm the password is already clear
// text (unsecured token policy). Otherwise the secret was encrypted with the
// server certificate's public key using the asymmetric algorithm of the
// SecureChannel's security policy and has the layout (Part 4 §7.41.2.3):
//
//	UInt32 length | password bytes | serverNonce
//
// The trailing nonce must match the nonce this server last issued for the
// session, which binds the secret to this activation and prevents replay.
//
// With an ECC security policy there is no asymmetric encryption. The password
// is an EccEncryptedSecret instead, whatever the token says about its
// EncryptionAlgorithm (see decryptEccSecret).
func (s *SessionService) decryptUserPassword(sc *uasc.SecureChannel, sess *session, tok *ua.UserNameIdentityToken, serverNonce []byte) ([]byte, ua.StatusCode) {
	if uapolicy.IsECC(s.userTokenPolicy(sc)) {
		return s.decryptEccSecret(sc, sess, tok.Password, serverNonce)
	}
	if tok.EncryptionAlgorithm == "" {
		return tok.Password, ua.StatusOK
	}
	if sc == nil {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	policyURI := sc.SecurityPolicyURI()
	if policyURI == ua.SecurityPolicyURINone {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	_, key, ok := s.srv.cfg.identityFor(policyURI)
	if !ok || key == nil {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	enc, err := uapolicy.AsymmetricKeys(policyURI, key, nil)
	if err != nil {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	if enc.EncryptionURI() != tok.EncryptionAlgorithm {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	plain, err := enc.Decrypt(tok.Password)
	if err != nil || len(plain) < 4 {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	n := int(binary.LittleEndian.Uint32(plain[:4]))
	if n < len(serverNonce) || 4+n > len(plain) {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	secret := plain[4 : 4+n]
	pwLen := n - len(serverNonce)
	if !bytes.Equal(secret[pwLen:], serverNonce) {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	return secret[:pwLen], ua.StatusOK
}

// CloseSession implements the OPC UA CloseSession service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.4
func (s *SessionService) CloseSession(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.CloseSessionRequest](r)
	if err != nil {
		return nil, err
	}

	authToken := req.RequestHeader.AuthenticationToken
	if s.srv.historyCPs != nil && authToken != nil {
		s.srv.historyCPs.releaseSession(authToken.String())
	}

	// The Publish requests queued for the session will not be answered by
	// a subscription any more: answer them now (Part 4 §5.6.4).
	if ss := s.srv.SubscriptionService; ss != nil && authToken != nil {
		ss.releasePublishRequests(s.srv.sb.peek(authToken), ua.StatusBadSessionClosed)
	}

	err = s.srv.sb.Close(authToken)
	if err != nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	// Per Part 4 §5.6.4, if DeleteSubscriptions is true the server should
	// delete all subscriptions associated with the session.
	if req.DeleteSubscriptions {
		ss := s.srv.SubscriptionService
		if ss == nil {
			// Service not yet initialized (server not yet started).
			goto respond
		}
		ss.Mu.Lock()
		var toDelete []uint32
		for id, sub := range ss.Subs {
			if own, _ := sub.sessionChannel(); own != nil && own.AuthTokenID.Equal(req.RequestHeader.AuthenticationToken) {
				toDelete = append(toDelete, id)
			}
		}
		ss.Mu.Unlock()
		for _, id := range toDelete {
			ss.DeleteSubscription(id)
		}
	}
respond:

	response := &ua.CloseSessionResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
	}

	return response, nil
}

// Cancel implements the OPC UA Cancel service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.5
func (s *SessionService) Cancel(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.CancelRequest](r)
	if err != nil {
		return nil, err
	}

	// Per OPC-UA spec, Cancel cancels outstanding service requests
	// matching the given RequestHandle. The server returns the number
	// of requests successfully cancelled.
	// In this implementation outstanding requests are limited to
	// queued Publish requests on the session.
	session := s.srv.Session(req.Header())
	var cancelCount uint32

	if session != nil {
		// Drain publish requests matching the handle.
		remaining := make([]PubReq, 0)
	drain:
		for {
			select {
			case pr := <-session.PublishRequests:
				if pr.Req.RequestHeader.RequestHandle == req.RequestHandle {
					cancelCount++
				} else {
					remaining = append(remaining, pr)
				}
			default:
				break drain
			}
		}
		// Put back the non-matching ones.
		for _, pr := range remaining {
			select {
			case session.PublishRequests <- pr:
			default:
			}
		}
	}

	return &ua.CancelResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		CancelCount:    cancelCount,
	}, nil
}

// serverCertificate returns the application instance certificate the server
// uses on the channel: with certificates of several key types it is the one
// that fits the security policy of the channel.
func (s *SessionService) serverCertificate(sc *uasc.SecureChannel) []byte {
	if sc != nil {
		if cert := sc.LocalCertificate(); len(cert) > 0 {
			return cert
		}
	}
	return s.srv.cfg.certificate
}

// userTokenPolicy returns the security policy that protects the user identity
// tokens of a channel. The UserTokenPolicies of this server do not name a
// policy of their own, so it is the policy of the SecureChannel.
func (s *SessionService) userTokenPolicy(sc *uasc.SecureChannel) string {
	if sc == nil {
		return ua.SecurityPolicyURINone
	}
	return sc.SecurityPolicyURI()
}

// issueEphemeralKey puts a new ephemeral key for the session into the
// response header if the client is due one (Part 6 §6.8.2):
//
//   - the request names an ECDHPolicyUri: a key for that policy, or
//     Bad_SecurityPolicyRejected if the policy cannot be used;
//   - CreateSession over an ECC channel without a request: a key for the
//     policy of the channel, so that clients that do not ask still get one;
//   - ActivateSession without a request, after the previous key was used: a
//     new key for the policy the client asked for last;
//   - otherwise nothing, and the previous key stays valid.
func (s *SessionService) issueEphemeralKey(sc *uasc.SecureChannel, sess *session, reqHdr *ua.RequestHeader, respHdr *ua.ResponseHeader, create bool) ua.StatusCode {
	if sc == nil {
		return ua.StatusOK
	}
	channelPolicy := s.userTokenPolicy(sc)

	var policyURI string
	requested, ok := "", false
	if reqHdr != nil {
		requested, ok = uasc.ECDHPolicyFromHeader(reqHdr.AdditionalHeader)
	}
	switch {
	case ok:
		// User identity tokens are protected with the policy of the
		// channel; a key for any other policy would never be used, and the
		// certificate of the channel could not sign it.
		if !uapolicy.IsECC(requested) || requested != channelPolicy {
			s.srv.cfg.logger.Warn("ephemeral key requested for a security policy that is not available", "policy", requested)
			return ua.StatusBadSecurityPolicyRejected
		}
		policyURI = requested
	case create && uapolicy.IsECC(channelPolicy):
		policyURI = channelPolicy
	case !create && sess.ecdhKeyUsed && uapolicy.IsECC(sess.ecdhPolicy) && sess.ecdhPolicy == channelPolicy:
		policyURI = sess.ecdhPolicy
	default:
		return ua.StatusOK
	}

	key, err := uapolicy.NewEphemeralKey(policyURI)
	if err != nil {
		s.srv.cfg.logger.Warn("cannot create an ephemeral key", "policy", policyURI, "error", err)
		return ua.StatusBadInternalError
	}
	public := key.PublicKey()
	signature, err := sc.NewEphemeralKeySignature(policyURI, public)
	if err != nil {
		s.srv.cfg.logger.Warn("cannot sign the ephemeral key", "policy", policyURI, "error", err)
		return ua.StatusBadInternalError
	}

	sess.ecdhKey = key
	sess.ecdhPolicy = policyURI
	sess.ecdhKeyUsed = false
	respHdr.AdditionalHeader = uasc.NewECDHKeyHeader(policyURI, &ua.EphemeralKeyType{PublicKey: public, Signature: signature})
	return ua.StatusOK
}

// decryptEccSecret returns the secret of a user identity token that is
// protected with an ECC security policy: an EccEncryptedSecret (Part 4
// §7.41.2.3) made for the ephemeral key this server handed out for the
// session.
//
// The secret must be signed with the application instance key of the client
// that owns the SecureChannel and be bound to the session nonce the server
// issued last. The ephemeral key is spent by the attempt, whatever its
// outcome: no second secret is accepted for it.
func (s *SessionService) decryptEccSecret(sc *uasc.SecureChannel, sess *session, data, serverNonce []byte) ([]byte, ua.StatusCode) {
	key := sess.ecdhKey
	sess.ecdhKey = nil
	sess.ecdhKeyUsed = true
	if sc == nil || key == nil || key.PolicyURI() != s.userTokenPolicy(sc) {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	clientCert := sc.RemoteCertificate()
	if len(clientCert) == 0 {
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	secret, err := uasc.DecryptUserSecret(key, data, clientCert, serverNonce)
	if err != nil {
		// The reason is not told to the client, and never includes the
		// secret itself.
		s.srv.cfg.logger.Warn("cannot decrypt the EccEncryptedSecret of a user identity token", "error", err)
		return nil, ua.StatusBadIdentityTokenInvalid
	}
	return secret, ua.StatusOK
}
