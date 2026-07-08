// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

const (
	sessionTimeoutMin     = 100            // 100ms
	sessionTimeoutMax     = 30 * 60 * 1000 // 30 minutes
	sessionTimeoutDefault = 60 * 1000      // 60s

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
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.CreateSessionRequest](r)
	if err != nil {
		return nil, err
	}

	// New session
	sess := s.srv.sb.NewSession()

	// Ensure session timeout is reasonable
	sess.cfg.sessionTimeout = time.Duration(req.RequestedSessionTimeout) * time.Millisecond
	if sess.cfg.sessionTimeout > sessionTimeoutMax || sess.cfg.sessionTimeout < sessionTimeoutMin {
		sess.cfg.sessionTimeout = sessionTimeoutDefault
	}

	nonce := make([]byte, sessionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		s.srv.cfg.logger.Warn("error creating session nonce")
		return nil, ua.StatusBadInternalError
	}
	sess.serverNonce = nonce
	sess.remoteCertificate = req.ClientCertificate

	sig, alg, err := sc.NewSessionSignature(req.ClientCertificate, req.ClientNonce)
	if err != nil {
		s.srv.cfg.logger.Warn("error creating session signature")
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

	response := &ua.CreateSessionResponse{
		ResponseHeader:        responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		SessionID:             sess.ID,
		AuthenticationToken:   sess.AuthTokenID,
		RevisedSessionTimeout: float64(sess.cfg.sessionTimeout / time.Millisecond),
		MaxRequestMessageSize: 0, // Not used
		ServerSignature: &ua.SignatureData{
			Signature: sig,
			Algorithm: alg,
		},
		ServerCertificate: s.srv.cfg.certificate,
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

	err = sc.VerifySessionSignature(sess.remoteCertificate, sess.serverNonce, req.ClientSignature.Signature)
	if err != nil {
		s.srv.cfg.logger.Warn("error verifying session signature", "error", err)
		return nil, ua.StatusBadSecurityChecksFailed
	}

	nonce := make([]byte, sessionNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		s.srv.cfg.logger.Warn("error creating session nonce")
		return nil, ua.StatusBadInternalError
	}
	sess.serverNonce = nonce

	// Extract user identity and resolve roles.
	if req.UserIdentityToken != nil {
		if token, ok := req.UserIdentityToken.Value.(ua.IdentityToken); ok {
			sess.identityToken = token
		}
	}
	if rm := s.srv.cfg.roleMapper; rm != nil {
		sess.roles = rm(sess.identityToken)
	} else {
		sess.roles = DefaultRoleMapper(sess.identityToken)
	}

	response := &ua.ActivateSessionResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		ServerNonce:    nonce,
		// Results:         []ua.StatusCode{},
		// DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	return response, nil
}

// CloseSession implements the OPC UA CloseSession service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.6.4
func (s *SessionService) CloseSession(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.CloseSessionRequest](r)
	if err != nil {
		return nil, err
	}

	err = s.srv.sb.Close(req.RequestHeader.AuthenticationToken)
	if err != nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	// Per Part 4 §5.6.4, if DeleteSubscriptions is true the server should
	// delete all subscriptions associated with the session.
	if req.DeleteSubscriptions {
		ss := s.srv.SubscriptionService
		ss.Mu.Lock()
		var toDelete []uint32
		for id, sub := range ss.Subs {
			if sub.Session != nil && sub.Session.AuthTokenID.Equal(req.RequestHeader.AuthenticationToken) {
				toDelete = append(toDelete, id)
			}
		}
		ss.Mu.Unlock()
		for _, id := range toDelete {
			ss.DeleteSubscription(id)
		}
	}

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
