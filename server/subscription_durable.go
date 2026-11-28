// SPDX-License-Identifier: MIT

package server

import (
	"math"
)

// DurableSubscriptions are the limits of the durable subscriptions of
// SetSubscriptionDurable (OPC 10000-5 §9.3, OPC 10000-4 §6.8), which is
// "used to set a Subscription into this durable mode and to allow much
// longer lifetimes and queue sizes than for normal Subscriptions".
//
// A durable subscription of this server lives in memory: it survives its
// session (a session that is closed without DeleteSubscriptions or times
// out, a lost connection) for its lifetime, as any subscription does (Part
// 4 §5.14.1.1), and a client takes it over with TransferSubscriptions. It
// does not survive a restart of the server: the server does not store
// subscriptions, their MonitoredItems or queues (Part 4 §6.8 asks a server
// with durable subscriptions to "Store Subscriptions settings and sent
// notification messages with sequence numbers" and "Store MonitoredItem
// settings and queues"). See LIMITATIONS.md.
type DurableSubscriptions struct {
	// Disabled leaves SetSubscriptionDurable without an implementation; a
	// call is Bad_MethodInvalid, as before v1.43.0.
	Disabled bool
	// MaxLifetimeInHours is the longest lifetime of a durable subscription,
	// the revisedLifetimeInHours of a request for 0 hours or more. Zero
	// selects the default, 24 hours.
	MaxLifetimeInHours uint32
	// MaxQueueSize is the largest QueueSize of a MonitoredItem of a durable
	// subscription, for data and event items. Zero selects the default,
	// 10000.
	MaxQueueSize uint32
}

// The defaults of DurableSubscriptions: a choice of this library, OPC
// 10000-4 §6.8 leaves the numbers to the profiles of OPC 10000-7.
const (
	defaultDurableLifetimeInHours uint32 = 24
	defaultDurableQueueSize       uint32 = 10_000
)

// WithDurableSubscriptions sets the limits of durable subscriptions, or
// with Disabled turns SetSubscriptionDurable off. Without it, the server
// has durable subscriptions with the default limits.
func WithDurableSubscriptions(d DurableSubscriptions) Option {
	return func(s *serverConfig) error {
		s.durable = d
		return nil
	}
}

func (d DurableSubscriptions) maxLifetimeInHours() uint32 {
	if d.MaxLifetimeInHours == 0 {
		return defaultDurableLifetimeInHours
	}
	return d.MaxLifetimeInHours
}

func (d DurableSubscriptions) maxQueueSize() uint32 {
	if d.MaxQueueSize == 0 {
		return defaultDurableQueueSize
	}
	return d.MaxQueueSize
}

// msPerHour is an hour in milliseconds, the unit of the publishing
// interval (Part 4 §5.14.2.2).
const msPerHour = 3_600_000.0

// maxDurableLifetimeCount bounds the LifetimeCount of a durable
// subscription: the subscription counts it in an int, which has 32 bits on
// some platforms.
const maxDurableLifetimeCount = math.MaxInt32

// lifetimeCountFor returns the LifetimeCount of a subscription that lives
// hours hours at the publishing interval pi (ms): the count of intervals,
// rounded up, at least three keep-alive counts (Part 4: "The
// lifetime count shall be a minimum of three times the keep keep-alive
// count", §5.14.2.2) and minLifetimeCount, at most
// maxDurableLifetimeCount.
func lifetimeCountFor(hours uint32, pi float64, keepAlive uint32) uint32 {
	count := math.Ceil(float64(hours) * msPerHour / pi)
	lowest := max(uint64(minLifetimeCount), 3*uint64(keepAlive))
	switch {
	case count < float64(lowest):
		count = float64(lowest)
	case count > maxDurableLifetimeCount:
		count = maxDurableLifetimeCount
	}
	return uint32(count)
}

// lifetimeInHours returns the whole hours of count publishing intervals of
// pi ms. The small epsilon keeps a count rounded up from exactly n hours
// at n hours despite floating point.
func lifetimeInHours(count uint32, pi float64) uint32 {
	h := math.Floor(float64(count)*pi/msPerHour + 1e-9)
	if h > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(h)
}

// reviseDurableLifetime revises the RequestedLifetimeCount of a
// ModifySubscription of a durable subscription: up to the count of
// MaxLifetimeInHours, not the limit of other subscriptions.
// "ModifySubscription can be used to change the parameters of the durable
// Subscription", and "ModifySubscription does not change the durable mode
// of the Subscription" (Part 4 §6.8); a client that keeps the lifetime
// calculates the LifetimeCount from the hours and the PublishingInterval.
func (d DurableSubscriptions) reviseDurableLifetime(requested uint32, pi float64, keepAlive uint32) uint32 {
	highest := lifetimeCountFor(d.maxLifetimeInHours(), pi, keepAlive)
	lowest := lifetimeCountFor(0, pi, keepAlive)
	return min(max(requested, lowest), highest)
}

// reviseDurableQueueSize revises the QueueSize of a MonitoredItem of a
// durable subscription: as for any item (0 is one value, or the default
// size of an event queue), but up to MaxQueueSize.
func (d DurableSubscriptions) reviseDurableQueueSize(requested uint32, event bool) uint32 {
	switch {
	case requested == 0 && event:
		return defaultEventQueueSize
	case requested == 0:
		return 1
	}
	return min(requested, d.maxQueueSize())
}

// reviseItemQueueSize revises the QueueSize of a MonitoredItem of sub.
func (s *serverConfig) reviseItemQueueSize(sub *Subscription, requested uint32, event bool) uint32 {
	switch {
	case sub != nil && sub.durable.Load():
		return s.durable.reviseDurableQueueSize(requested, event)
	case event:
		return reviseEventQueueSize(requested)
	}
	return reviseQueueSize(requested)
}
