// SPDX-License-Identifier: MIT

package server

import "github.com/otfabric/go-opcua/ua"

// CloseSession ends a session on the application's behalf, e.g. when the user
// it was activated for has been disabled or has lost a role. The session is
// closed as a CloseSession with DeleteSubscriptions would close it (Part 4
// §5.6.4): its subscriptions are deleted, its queued Publish requests are
// answered with Bad_SessionClosed and its continuation points released. The
// client's next request of the session fails with Bad_SessionIdInvalid, so it
// has to create and activate a new one, with credentials the server checks
// again. The [SessionObserver] is told SessionClosedByServer.
//
// sessionID is the SessionId (SessionInfo.ID, [Session.ID]). CloseSession
// returns ua.StatusBadSessionIDInvalid if the server has no such session.
func (s *Server) CloseSession(sessionID *ua.NodeID) error {
	if sessionID == nil {
		return ua.StatusBadSessionIDInvalid
	}
	sess := s.sb.closeID(sessionID)
	if sess == nil {
		return ua.StatusBadSessionIDInvalid
	}
	s.cfg.logger.Info("session closed by the application", "session_id", sess.ID)
	if ss := s.SubscriptionService; ss != nil {
		ss.releasePublishRequests(sess, ua.StatusBadSessionClosed)
		ss.deleteSessionSubscriptions(sess.AuthTokenID)
	}
	if _, cps := s.history(); cps != nil && sess.AuthTokenID != nil {
		cps.releaseSession(sess.AuthTokenID.String())
	}
	if s.sb.removed != nil {
		s.sb.removed(sess, SessionClosedByServer)
	}
	return nil
}
