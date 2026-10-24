// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

type session struct {
	cfg sessionConfig

	ID          *ua.NodeID
	AuthTokenID *ua.NodeID
	serverNonce []byte
	// clientNonce is the nonce of the CreateSession request. The channel
	// bound signatures of ActivateSession cover it.
	clientNonce       []byte
	remoteCertificate []byte

	// ecdhKey is the ephemeral key handed to the client for the next user
	// identity token that is protected with an ECC security policy
	// (EccEncryptedSecret). It is good for one ActivateSession. ecdhPolicy
	// is the policy the client last asked a key for; ecdhKeyUsed records
	// that the current key was consumed, in which case the next
	// ActivateSession response brings a new one unasked (Part 6 §6.8.2).
	ecdhKey     *uapolicy.EphemeralKey
	ecdhPolicy  string
	ecdhKeyUsed bool

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

	// lastActivity is when the session was last used, in nanoseconds since
	// monoEpoch (monotonic: a step of the wall clock neither expires a session
	// nor keeps one alive). timeout is the revised session timeout in
	// nanoseconds. Both are accessed by the channels' read loops, the request
	// handlers and the session reaper.
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

// monoEpoch is the reference of session activity times. time.Since and
// Time.Sub of times that carry a monotonic reading use the monotonic clock.
var monoEpoch = time.Now()

// touch records activity on the session, restarting its timeout.
func (s *session) touch() {
	s.touchAt(time.Now())
}

// touchAt records activity at t.
func (s *session) touchAt(t time.Time) {
	s.lastActivity.Store(int64(t.Sub(monoEpoch)))
}

// touchIfAlive restarts the timeout of a session that has not timed out at
// now and reports whether it had not. A request must not revive a session
// whose timeout elapsed before the reaper removed it.
func (s *session) touchIfAlive(now time.Time) bool {
	if s.expired(now) {
		return false
	}
	s.touchAt(now)
	return true
}

// idle returns how long the session has been unused at now.
func (s *session) idle(now time.Time) time.Duration {
	return now.Sub(monoEpoch) - time.Duration(s.lastActivity.Load())
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
	return s.idle(now) > timeout
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

	// closed is set while the server is shut down. A request that is still
	// being handled then (the dispatcher is not waited for) gets a session
	// that the broker does not keep: nothing would ever remove it.
	closed bool
}

func newSessionBroker(l *slog.Logger) *sessionBroker {
	return &sessionBroker{
		s:      make(map[string]*session),
		logger: l,
	}
}

// newAuthenticationToken returns the secret a client presents with every
// request of a session (Part 4 §7.36: "the Server shall generate a token that
// is difficult to guess"). It is an opaque NodeId with 256 random bits from
// the system's cryptographic generator; knowing tokens of other sessions
// gives no information about it.
func newAuthenticationToken() *ua.NodeID {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on supported platforms; without
		// randomness no session can be given a safe token.
		panic("server: no cryptographic randomness for a session token: " + err.Error())
	}
	return ua.NewByteStringNodeID(0, b)
}

func (sb *sessionBroker) NewSession() *session {
	s := &session{
		ID:              ua.NewGUIDNodeID(1, uuid.New().String()),
		AuthTokenID:     newAuthenticationToken(),
		PublishRequests: make(chan PubReq, 100),
	}
	s.touch()

	sb.mu.Lock()
	if !sb.closed {
		sb.s[s.AuthTokenID.String()] = s
	}
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

// peek returns the session with the given token without restarting its
// timeout, or nil.
func (sb *sessionBroker) peek(authToken *ua.NodeID) *session {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.s[authToken.String()]
}

// closeAll forgets every session and keeps none from now on.
func (sb *sessionBroker) closeAll() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	clear(sb.s)
	sb.closed = true
}

// reopen makes the broker keep sessions again. It is called when the server
// starts.
func (sb *sessionBroker) reopen() {
	sb.mu.Lock()
	sb.closed = false
	sb.mu.Unlock()
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
	// session timeout is restarted. A session that has timed out stays
	// closed although the reaper has not removed it yet (Part 4 §5.6.2).
	if !s.touchIfAlive(time.Now()) {
		return nil
	}

	return s
}

// touchToken restarts the timeout of the session with the given
// authentication token, if there is one. The channels call it when a request
// arrives: Part 4 §5.6.2 counts the time since the server received a request,
// and requests are handled one at a time, so a request waiting behind slow
// ones must already keep its session alive.
func (sb *sessionBroker) touchToken(authToken *ua.NodeID) {
	if authToken == nil {
		return
	}
	sb.mu.Lock()
	s := sb.s[authToken.String()]
	sb.mu.Unlock()
	if s != nil {
		s.touchIfAlive(time.Now())
	}
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
