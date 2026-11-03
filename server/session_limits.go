// SPDX-License-Identifier: MIT

package server

import (
	"math"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The defaults of the session and subscription limits. They are those of
// open62541 (UA_ServerConfig: maxSessions 100, maxSubscriptions 1024,
// maxSubscriptionsPerSession 64); UA-.NETStandard also allows 100 sessions
// (ServerConfiguration.MaxSessionCount).
const (
	defaultMaxSessions                = 100
	defaultMaxSubscriptions           = 1024
	defaultMaxSubscriptionsPerSession = 64
)

// WithMaxSessions sets how many sessions the server keeps at a time,
// activated or not. CreateSession fails with Bad_TooManySessions when the
// server has that many (Part 4 §5.6.2); a session that is closed or times
// out frees its place. The limit is published as
// ServerCapabilities.MaxSessions (Part 5 §6.3.2).
//
// The default is 100. Zero or a negative value selects the default.
func WithMaxSessions(n int) Option {
	return func(s *serverConfig) error {
		s.maxSessions = n
		return nil
	}
}

// WithMaxSubscriptions sets how many subscriptions the server keeps at a
// time over all sessions, including those whose session was closed without
// deleting them and that wait for their lifetime to expire.
// CreateSubscription fails with Bad_TooManySubscriptions when the server has
// that many (Part 4 §5.13.2). The limit is published as
// ServerCapabilities.MaxSubscriptions (Part 5 §6.3.2).
//
// The default is 1024. Zero or a negative value selects the default.
func WithMaxSubscriptions(n int) Option {
	return func(s *serverConfig) error {
		s.maxSubscriptions = n
		return nil
	}
}

// WithMaxSubscriptionsPerSession sets how many subscriptions one session
// may own. CreateSubscription fails with Bad_TooManySubscriptions when the
// session has that many (Part 4 §5.13.2), and TransferSubscriptions does not
// move more subscriptions into a session than that: the excess ones get
// Bad_TooManySubscriptions in their TransferResult and stay where they are.
// The limit is published as ServerCapabilities.MaxSubscriptionsPerSession
// (Part 5 §6.3.2).
//
// The default is 64. Zero or a negative value selects the default.
func WithMaxSubscriptionsPerSession(n int) Option {
	return func(s *serverConfig) error {
		s.maxSubscriptionsPerSession = n
		return nil
	}
}

// limitOrDefault returns n, or def for zero or a negative n.
func limitOrDefault(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

func (s *serverConfig) sessionLimit() int {
	return limitOrDefault(s.maxSessions, defaultMaxSessions)
}

func (s *serverConfig) subscriptionLimit() int {
	return limitOrDefault(s.maxSubscriptions, defaultMaxSubscriptions)
}

func (s *serverConfig) subscriptionsPerSessionLimit() int {
	return limitOrDefault(s.maxSubscriptionsPerSession, defaultMaxSubscriptionsPerSession)
}

// capabilityValue returns a limit as the UInt32 of its ServerCapabilities
// variable; a limit beyond UInt32 is published as its largest value.
func capabilityValue(n int) uint32 {
	// int64: where int is 32 bits every int fits a UInt32.
	if int64(n) >= math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

// bindSessionCapabilities serves the session and subscription limits from
// the MaxSessions, MaxSubscriptions and MaxSubscriptionsPerSession
// variables of ServerCapabilities (Part 5 §6.3.2), which the built-in node
// set declares without a value.
func (s *Server) bindSessionCapabilities() {
	for _, c := range []struct {
		nodeID uint32
		limit  func() int
	}{
		{id.ServerServerCapabilitiesMaxSessions, s.cfg.sessionLimit},
		{id.ServerServerCapabilitiesMaxSubscriptions, s.cfg.subscriptionLimit},
		{id.ServerServerCapabilitiesMaxSubscriptionsPerSession, s.cfg.subscriptionsPerSessionLimit},
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

// subscriptionsOfLocked returns the number of subscriptions sess owns.
// Caller must hold s.Mu.
func (s *SubscriptionService) subscriptionsOfLocked(sess *session) int {
	n := 0
	for _, sub := range s.Subs {
		if owner, _ := sub.sessionChannel(); owner == sess {
			n++
		}
	}
	return n
}
