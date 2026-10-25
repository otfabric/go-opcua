// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"time"
)

// Clock is the time source of the alarm timers: shelving, OnDelay /
// OffDelay, ReAlarmTime and the alarm metrics. The default is the system
// clock; a test passes its own with [WithAlarmClock] to run the timers
// without waiting.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// AfterFunc calls f after d (in a goroutine of its own, or, for a
	// test clock, when the test advances the clock). stop prevents the
	// call if it has not happened yet and reports whether it did.
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

// timerStop stops a timer of a Clock.
type timerStop = func() bool

// systemClock is the Clock of the time package.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }

// WithAlarmClock sets the clock of the alarm timers (default: the system
// clock).
func WithAlarmClock(clock Clock) Option {
	return func(c *serverConfig) error {
		if clock == nil {
			return errors.New("server: WithAlarmClock: nil clock")
		}
		c.alarmClock = clock
		return nil
	}
}

// alarmClock returns the clock of the alarm timers.
func (s *Server) alarmClock() Clock {
	if s.cfg.alarmClock != nil {
		return s.cfg.alarmClock
	}
	return systemClock{}
}

// now is the current time of the alarm clock.
func (s *Server) now() time.Time { return s.alarmClock().Now() }
