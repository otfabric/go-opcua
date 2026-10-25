// SPDX-License-Identifier: MIT

// Package subscription holds the conformance tests of the Subscription and
// MonitoredItem service sets: publishing, keep-alives, republishing, queues,
// data-change and event filters, the monitor package and subscription
// recovery after a reconnect.
// They are a package of their own because CI gives every package 120 s under
// the race detector; the helpers are shared with the other conformance
// packages through conformkit.
package subscription
