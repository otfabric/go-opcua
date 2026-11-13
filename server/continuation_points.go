// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The default per-session continuation point limits.
const (
	defaultMaxBrowseContinuationPoints = 10
	defaultMaxQueryContinuationPoints  = 5
)

// continuationPointTTL is how long an unused continuation point of Browse or
// Query is kept. Part 4 §7.9 lets a server release continuation points it
// cannot keep; the client then gets Bad_ContinuationPointInvalid.
const continuationPointTTL = 10 * time.Minute

// WithMaxBrowseContinuationPoints sets how many Browse continuation points
// one session may hold. A Browse that would need more answers
// Bad_NoContinuationPoints for that node (Part 4 §5.8.2, §7.9). The limit is
// published as ServerCapabilities.MaxBrowseContinuationPoints (Part 5
// §6.3.2).
//
// The default is 10. Zero or a negative value selects the default.
func WithMaxBrowseContinuationPoints(n int) Option {
	return func(s *serverConfig) error {
		s.maxBrowseContinuationPoints = n
		return nil
	}
}

// WithMaxQueryContinuationPoints sets how many QueryFirst continuation points
// one session may hold. A QueryFirst that would need more fails with
// Bad_NoContinuationPoints (Part 4 §7.9). The limit is published as
// ServerCapabilities.MaxQueryContinuationPoints (Part 5 §6.3.2).
//
// The default is 5. Zero or a negative value selects the default.
func WithMaxQueryContinuationPoints(n int) Option {
	return func(s *serverConfig) error {
		s.maxQueryContinuationPoints = n
		return nil
	}
}

func (s *serverConfig) browseContinuationPointLimit() int {
	return limitOrDefault(s.maxBrowseContinuationPoints, defaultMaxBrowseContinuationPoints)
}

func (s *serverConfig) queryContinuationPointLimit() int {
	return limitOrDefault(s.maxQueryContinuationPoints, defaultMaxQueryContinuationPoints)
}

// bindContinuationPointCapabilities serves the continuation point limits
// from their ServerCapabilities variables (Part 5 §6.3.2).
func (s *Server) bindContinuationPointCapabilities() {
	for _, c := range []struct {
		nodeID uint32
		limit  func() int
	}{
		{id.ServerServerCapabilitiesMaxBrowseContinuationPoints, s.cfg.browseContinuationPointLimit},
		{id.ServerServerCapabilitiesMaxQueryContinuationPoints, s.cfg.queryContinuationPointLimit},
	} {
		n := s.ownNode(c.nodeID)
		if n == nil {
			continue
		}
		limit := c.limit
		n.mu.Lock()
		n.val = func() *ua.DataValue { return DataValueFromValue(capabilityValue(limit())) }
		n.mu.Unlock()
	}
}

// cpEntry is a stored continuation point.
type cpEntry[T any] struct {
	owner   string // the AuthenticationToken of the owning session
	expires time.Time
	data    T
}

// cpStore holds the continuation points of a service. Continuation points
// belong to the session that created them (Part 4 §7.9): another session
// cannot use them, each session holds at most a limited number of them, and
// they are released with the session.
type cpStore[T any] struct {
	mu      sync.Mutex
	cps     map[string]*cpEntry[T]
	perSess map[string]int
	now     func() time.Time
}

func newCPStore[T any]() *cpStore[T] {
	return &cpStore[T]{
		cps:     make(map[string]*cpEntry[T]),
		perSess: make(map[string]int),
		now:     time.Now,
	}
}

// expireLocked drops the expired continuation points. Caller holds c.mu.
func (c *cpStore[T]) expireLocked(now time.Time) {
	for tok, e := range c.cps {
		if now.After(e.expires) {
			c.dropLocked(tok, e)
		}
	}
}

func (c *cpStore[T]) dropLocked(tok string, e *cpEntry[T]) {
	delete(c.cps, tok)
	if c.perSess[e.owner]--; c.perSess[e.owner] <= 0 {
		delete(c.perSess, e.owner)
	}
}

// store saves data for owner and returns its token, or false when owner
// already holds limit continuation points.
func (c *cpStore[T]) store(owner string, limit int, data T) ([]byte, bool) {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	tok := hex.EncodeToString(buf[:])

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.perSess[owner] >= limit {
		c.expireLocked(now)
		if c.perSess[owner] >= limit {
			return nil, false
		}
	}
	c.cps[tok] = &cpEntry[T]{owner: owner, expires: now.Add(continuationPointTTL), data: data}
	c.perSess[owner]++
	return []byte(tok), true
}

// take removes and returns the continuation point tok of owner. It is false
// for an unknown or expired token and for the token of another session.
func (c *cpStore[T]) take(owner string, tok []byte) (T, bool) {
	var zero T
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cps[string(tok)]
	if !ok || e.owner != owner {
		return zero, false
	}
	c.dropLocked(string(tok), e)
	if c.now().After(e.expires) {
		return zero, false
	}
	return e.data, true
}

// releaseSession drops the continuation points of owner.
func (c *cpStore[T]) releaseSession(owner string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.perSess[owner] == 0 {
		return
	}
	for tok, e := range c.cps {
		if e.owner == owner {
			c.dropLocked(tok, e)
		}
	}
}

// len returns the number of stored continuation points.
func (c *cpStore[T]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cps)
}

// sessionKey is the owner key of the continuation points of sess.
func sessionKey(sess *session) string {
	if sess == nil || sess.AuthTokenID == nil {
		return ""
	}
	return sess.AuthTokenID.String()
}
