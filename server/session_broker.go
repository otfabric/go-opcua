// SPDX-License-Identifier: MIT

package server

import (
	"log/slog"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/ua"
)

type session struct {
	cfg sessionConfig

	ID                *ua.NodeID
	AuthTokenID       *ua.NodeID
	serverNonce       []byte
	remoteCertificate []byte

	// identityToken is the user identity provided during ActivateSession.
	identityToken ua.IdentityToken

	// roles is the set of well-known role NodeIDs assigned to this session
	// based on the identity token. Set during ActivateSession.
	roles []*ua.NodeID

	PublishRequests chan PubReq

	// statusChanges holds the StatusChangeNotifications of subscriptions that
	// ended while no Publish request was available to announce it. They are
	// delivered with the next Publish request of the session.
	statusMu      sync.Mutex
	statusChanges []pendingStatusChange

	// activated is set once ActivateSession succeeded. Until then the
	// session cannot be used for anything but activating or closing it.
	activated atomic.Bool

	// lastActivity is the time (UnixNano) the session was last used. timeout
	// is the revised session timeout in nanoseconds. Both are accessed by the
	// request handlers and by the session reaper.
	lastActivity atomic.Int64
	timeout      atomic.Int64
}

// pendingStatusChange is a StatusChangeNotification waiting for a Publish
// request.
type pendingStatusChange struct {
	subID  uint32
	seq    uint32
	status ua.StatusCode
}

// maxPendingStatusChanges bounds the notifications kept for a session whose
// client does not send Publish requests any more.
const maxPendingStatusChanges = 1000

// addStatusChange queues a StatusChangeNotification for the session.
func (s *session) addStatusChange(c pendingStatusChange) {
	s.statusMu.Lock()
	if len(s.statusChanges) < maxPendingStatusChanges {
		s.statusChanges = append(s.statusChanges, c)
	}
	s.statusMu.Unlock()
}

// takeStatusChange returns the oldest queued StatusChangeNotification.
func (s *session) takeStatusChange() (pendingStatusChange, bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if len(s.statusChanges) == 0 {
		return pendingStatusChange{}, false
	}
	c := s.statusChanges[0]
	s.statusChanges = s.statusChanges[1:]
	return c, true
}

// touch records activity on the session, restarting its timeout.
func (s *session) touch() {
	s.lastActivity.Store(time.Now().UnixNano())
}

// setTimeout sets the revised session timeout (Part 4 §5.6.2).
func (s *session) setTimeout(d time.Duration) {
	s.cfg.sessionTimeout = d
	s.timeout.Store(int64(d))
}

// expired reports whether the session has been idle for longer than its
// timeout.
func (s *session) expired(now time.Time) bool {
	timeout := time.Duration(s.timeout.Load())
	if timeout <= 0 {
		timeout = sessionTimeoutDefault
	}
	return now.Sub(time.Unix(0, s.lastActivity.Load())) > timeout
}

type sessionConfig struct {
	sessionTimeout time.Duration
}

type sessionBroker struct {
	// mu protects concurrent modification of s
	mu sync.Mutex

	// s contains all sessions watched by the session broker
	s      map[string]*session
	logger *slog.Logger
}

func newSessionBroker(l *slog.Logger) *sessionBroker {
	return &sessionBroker{
		s:      make(map[string]*session),
		logger: l,
	}
}

func (sb *sessionBroker) NewSession() *session {
	s := &session{
		ID:              ua.NewGUIDNodeID(1, uuid.New().String()),
		AuthTokenID:     ua.NewNumericNodeID(0, uint32(mrand.Int31())),
		PublishRequests: make(chan PubReq, 100),
	}
	s.touch()

	sb.mu.Lock()
	sb.s[s.AuthTokenID.String()] = s
	sb.mu.Unlock()

	return s
}

func (sb *sessionBroker) Close(authToken *ua.NodeID) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.s[authToken.String()] == nil {
		sb.logger.Warn("sessionBroker.Close: error looking up session", "auth_token", authToken)
	}
	delete(sb.s, authToken.String())

	return nil
}

// closeAll forgets every session.
func (sb *sessionBroker) closeAll() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	clear(sb.s)
}

func (sb *sessionBroker) Session(authToken *ua.NodeID) *session {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	s := sb.s[authToken.String()]
	if s == nil {
		sb.logger.Warn("sessionBroker.Session: error looking up session", "auth_token", authToken)
		return nil
	}
	// Every service request looks its session up, so this is where the
	// session timeout is restarted.
	s.touch()

	return s
}

// reapExpired removes and returns the sessions whose timeout has elapsed.
//
// Part 4 §5.6.2: a session that receives no request within its revised
// timeout is closed by the server. Without this a client that disappears
// without CloseSession (crash, network loss) leaks its session forever.
func (sb *sessionBroker) reapExpired(now time.Time) []*session {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	var expired []*session
	for k, s := range sb.s {
		if s.expired(now) {
			expired = append(expired, s)
			delete(sb.s, k)
		}
	}
	return expired
}
