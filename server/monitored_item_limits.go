// SPDX-License-Identifier: MIT

package server

import (
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// The defaults of the monitored item limits.
const (
	defaultMaxMonitoredItems                       = 100_000
	defaultMaxMonitoredItemsPerSession             = 20_000
	defaultMaxMonitoredItemsPerSubscription        = 10_000
	defaultEventQueueSize                   uint32 = 1000
	maxEventQueueSize                       uint32 = 10_000
)

// WithMaxMonitoredItems sets how many monitored items the server keeps at a
// time over all subscriptions. CreateMonitoredItems answers
// Bad_TooManyMonitoredItems for the items beyond it (Part 4 §5.12.2). The
// limit is published as ServerCapabilities.MaxMonitoredItems (Part 5
// §6.3.2).
//
// The default is 100000. Zero or a negative value selects the default.
func WithMaxMonitoredItems(n int) Option {
	return func(s *serverConfig) error {
		s.maxMonitoredItems = n
		return nil
	}
}

// WithMaxMonitoredItemsPerSubscription sets how many monitored items one
// subscription may have. CreateMonitoredItems answers
// Bad_TooManyMonitoredItems for the items beyond it (Part 4 §5.12.2). The
// limit is published as ServerCapabilities.MaxMonitoredItemsPerSubscription
// (Part 5 §6.3.2).
//
// The default is 10000. Zero or a negative value selects the default.
func WithMaxMonitoredItemsPerSubscription(n int) Option {
	return func(s *serverConfig) error {
		s.maxMonitoredItemsPerSubscription = n
		return nil
	}
}

// WithMaxMonitoredItemsPerSession sets how many monitored items the
// subscriptions of one session may have together. CreateMonitoredItems
// answers Bad_TooManyMonitoredItems for the items beyond it (Part 4
// §5.12.2). The spec defines no ServerCapabilities variable for this limit.
//
// The default is 20000. Zero or a negative value selects the default.
func WithMaxMonitoredItemsPerSession(n int) Option {
	return func(s *serverConfig) error {
		s.maxMonitoredItemsPerSession = n
		return nil
	}
}

func (s *serverConfig) monitoredItemLimit() int {
	return limitOrDefault(s.maxMonitoredItems, defaultMaxMonitoredItems)
}

func (s *serverConfig) monitoredItemsPerSubscriptionLimit() int {
	return limitOrDefault(s.maxMonitoredItemsPerSubscription, defaultMaxMonitoredItemsPerSubscription)
}

func (s *serverConfig) monitoredItemsPerSessionLimit() int {
	return limitOrDefault(s.maxMonitoredItemsPerSession, defaultMaxMonitoredItemsPerSession)
}

// bindMonitoredItemCapabilities serves the monitored item limits from their
// ServerCapabilities variables (Part 5 §6.3.2).
func (s *Server) bindMonitoredItemCapabilities() {
	for _, c := range []struct {
		nodeID uint32
		limit  func() int
	}{
		{id.ServerServerCapabilitiesMaxMonitoredItems, s.cfg.monitoredItemLimit},
		{id.ServerServerCapabilitiesMaxMonitoredItemsPerSubscription, s.cfg.monitoredItemsPerSubscriptionLimit},
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

// itemCounts are the numbers of monitored items CreateMonitoredItems checks
// against the limits.
type itemCounts struct {
	total, session, subscription int
}

// itemCountsLocked counts the monitored items of the server, of the
// subscriptions of sess and of subscription subID. Caller must hold s.Mu.
func (s *MonitoredItemService) itemCountsLocked(sess *session, subID uint32) itemCounts {
	c := itemCounts{total: len(s.Items), subscription: len(s.Subs[subID])}
	ss := s.SubService
	ss.Mu.Lock()
	subs := make([]*Subscription, 0, len(ss.Subs))
	for _, sub := range ss.Subs {
		subs = append(subs, sub)
	}
	ss.Mu.Unlock()
	for _, sub := range subs {
		if sub.ownedBy(sess) {
			c.session += len(s.Subs[sub.ID])
		}
	}
	return c
}

// full reports whether one more item would exceed a limit of cfg.
func (c itemCounts) full(cfg *serverConfig) bool {
	return c.total >= cfg.monitoredItemLimit() ||
		c.session >= cfg.monitoredItemsPerSessionLimit() ||
		c.subscription >= cfg.monitoredItemsPerSubscriptionLimit()
}

// reviseEventQueueSize revises the QueueSize of an event item. Zero selects
// the default event queue size of the server (Part 4 §7.21
// MonitoringParameters); the size is at most maxEventQueueSize.
func reviseEventQueueSize(requested uint32) uint32 {
	if requested == 0 {
		return defaultEventQueueSize
	}
	if requested > maxEventQueueSize {
		return maxEventQueueSize
	}
	return requested
}
