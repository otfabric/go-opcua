package opcua

import (
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// RetryPolicy controls retry behaviour for failed client requests.
// The policy is consulted after each failed attempt to determine whether
// to retry and how long to wait before the next attempt.
//
// Attach an implementation via [WithRetryPolicy].
type RetryPolicy interface {
	// ShouldRetry is called after each failed attempt.
	// attempt is zero-based (0 = first failure).
	// Return (true, delay) to retry after delay, or (false, 0) to stop.
	ShouldRetry(attempt int, err error) (bool, time.Duration)
}

// noRetry is the default policy that never retries.
type noRetry struct{}

func (noRetry) ShouldRetry(int, error) (bool, time.Duration) { return false, 0 }

// NoRetry returns a RetryPolicy that never retries (default behaviour).
func NoRetry() RetryPolicy { return noRetry{} }

// ExponentialBackoffConfig provides full control over exponential back-off
// retry behaviour.
type ExponentialBackoffConfig struct {
	BaseDelay      time.Duration // default 100 ms
	MaxDelay       time.Duration // default 30 s
	MaxAttempts    int           // 0 = unlimited (pair with a context deadline)
	RetryOnTimeout bool          // default false: timeouts are not retried
}

// exponentialBackoff implements RetryPolicy with exponential back-off.
type exponentialBackoff struct {
	cfg ExponentialBackoffConfig
}

func (e *exponentialBackoff) ShouldRetry(attempt int, err error) (bool, time.Duration) {
	if !e.cfg.RetryOnTimeout && err == ua.StatusBadTimeout {
		return false, 0
	}
	if e.cfg.MaxAttempts > 0 && attempt >= e.cfg.MaxAttempts {
		return false, 0
	}
	delay := e.cfg.BaseDelay
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay > e.cfg.MaxDelay {
			delay = e.cfg.MaxDelay
			break
		}
	}
	return true, delay
}

// ExponentialBackoff returns a RetryPolicy with exponential back-off.
// delay = base × 2^attempt, capped at maxDelay. Stops after maxAttempts retries.
// maxAttempts = 0 means unlimited (always pair with a context deadline).
func ExponentialBackoff(base, maxDelay time.Duration, maxAttempts int) RetryPolicy {
	return NewExponentialBackoff(ExponentialBackoffConfig{
		BaseDelay:   base,
		MaxDelay:    maxDelay,
		MaxAttempts: maxAttempts,
	})
}

// NewExponentialBackoff returns a RetryPolicy with full control over the
// exponential back-off parameters via ExponentialBackoffConfig.
func NewExponentialBackoff(cfg ExponentialBackoffConfig) RetryPolicy {
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 100 * time.Millisecond
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 30 * time.Second
	}
	return &exponentialBackoff{cfg: cfg}
}
