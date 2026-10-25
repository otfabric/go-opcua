// SPDX-License-Identifier: MIT

// Package fakeclock is a manual clock for tests of timer-driven code
// (server.WithAlarmClock): time moves only when the test advances it, and
// the timers that fall due run in the advancing goroutine, in order of
// their due time, before Advance returns.
package fakeclock

import (
	"slices"
	"sync"
	"time"
)

// Clock is a manual clock. The zero value is not usable; use New.
type Clock struct {
	mu     sync.Mutex
	now    time.Time
	seq    uint64
	timers []*timer
}

type timer struct {
	at  time.Time
	seq uint64
	f   func()
}

// New returns a clock that starts at start.
func New(start time.Time) *Clock { return &Clock{now: start} }

// Now returns the time of the clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// AfterFunc schedules f at Now()+d and returns its stop function.
func (c *Clock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	t := &timer{at: c.now.Add(d), seq: c.seq, f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		i := slices.Index(c.timers, t)
		if i < 0 {
			return false
		}
		c.timers = slices.Delete(c.timers, i, i+1)
		return true
	}
}

// Pending returns the number of timers that have not run.
func (c *Clock) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// Advance moves the clock forward by d and runs the timers that fall due,
// each at its own due time; a timer a callback schedules within the
// advanced span runs too.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	end := c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var next *timer
		for _, t := range c.timers {
			if !t.at.After(end) && (next == nil || t.at.Before(next.at) || (t.at.Equal(next.at) && t.seq < next.seq)) {
				next = t
			}
		}
		if next == nil {
			c.now = end
			c.mu.Unlock()
			return
		}
		c.timers = slices.DeleteFunc(c.timers, func(t *timer) bool { return t == next })
		if next.at.After(c.now) {
			c.now = next.at
		}
		c.mu.Unlock()
		next.f()
	}
}
