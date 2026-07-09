// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/errors"
	"github.com/stretchr/testify/require"
)

func TestDialDefaultTimeout(t *testing.T) {
	// 203.0.113.0/24 is IETF TEST-NET-3 — addresses that should not respond.
	const blackhole = "opc.tcp://203.0.113.0:4840"

	start := time.Now()
	_, err := DialTCP(context.Background(), blackhole)
	elapsed := time.Since(start)

	require.Error(t, err)
	var oe *net.OpError
	require.True(t, errors.As(err, &oe))
	require.True(t, oe.Timeout())

	pct := 0.10
	require.InDelta(t, float64(DefaultDialTimeout), float64(elapsed), float64(DefaultDialTimeout)*pct)
}

func TestDialWithTimeout_zeroMeansNoLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := DialTCPWithTimeout(ctx, "opc.tcp://203.0.113.0:4840", 0)
	elapsed := time.Since(start)

	require.Error(t, err)
	// Should respect the context deadline (~50ms), not DefaultDialTimeout.
	require.Less(t, elapsed, DefaultDialTimeout/2)
}
