// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestNoRetry(t *testing.T) {
	t.Parallel()
	p := NoRetry()
	ok, d := p.ShouldRetry(0, errors.New("fail"))
	require.False(t, ok)
	require.Zero(t, d)
}

func TestExponentialBackoff(t *testing.T) {
	t.Parallel()
	p := ExponentialBackoff(100*time.Millisecond, time.Second, 3)

	ok, d := p.ShouldRetry(0, ua.StatusBad)
	require.True(t, ok)
	require.Equal(t, 100*time.Millisecond, d)

	ok, d = p.ShouldRetry(1, ua.StatusBad)
	require.True(t, ok)
	require.Equal(t, 200*time.Millisecond, d)

	ok, _ = p.ShouldRetry(3, ua.StatusBad)
	require.False(t, ok)
}

func TestExponentialBackoff_NoTimeoutRetry(t *testing.T) {
	t.Parallel()
	p := NewExponentialBackoff(ExponentialBackoffConfig{BaseDelay: 50 * time.Millisecond})
	ok, _ := p.ShouldRetry(0, ua.StatusBadTimeout)
	require.False(t, ok)
}

func TestExponentialBackoff_RetryOnTimeout(t *testing.T) {
	t.Parallel()
	p := NewExponentialBackoff(ExponentialBackoffConfig{
		BaseDelay:      50 * time.Millisecond,
		RetryOnTimeout: true,
	})
	ok, d := p.ShouldRetry(0, ua.StatusBadTimeout)
	require.True(t, ok)
	require.Equal(t, 50*time.Millisecond, d)
}

func TestExponentialBackoff_Defaults(t *testing.T) {
	t.Parallel()
	p := NewExponentialBackoff(ExponentialBackoffConfig{})
	ok, d := p.ShouldRetry(0, ua.StatusBad)
	require.True(t, ok)
	require.Equal(t, 100*time.Millisecond, d)
}

func TestWithRetryPolicy(t *testing.T) {
	t.Parallel()
	c, err := NewClient("opc.tcp://example.com:4840", InsecureNoSecurity(), WithRetryPolicy(ExponentialBackoff(time.Second, time.Minute, 1)))
	require.NoError(t, err)
	_ = c.Close(context.Background())
}

// A timeout is recognised when it is wrapped, too.
func TestExponentialBackoffWrappedTimeout(t *testing.T) {
	t.Parallel()
	p := NewExponentialBackoff(ExponentialBackoffConfig{})
	retry, _ := p.ShouldRetry(0, fmt.Errorf("read: %w", ua.StatusBadTimeout))
	require.False(t, retry)
}
