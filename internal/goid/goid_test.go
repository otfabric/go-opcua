// SPDX-License-Identifier: MIT

package goid

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/testutil/leakcheck"
)

func TestMain(m *testing.M) { leakcheck.Main(m) }

func TestID(t *testing.T) {
	id := ID()
	require.NotZero(t, id)
	require.Equal(t, id, ID(), "stable within a goroutine")
	other := make(chan uint64)
	go func() { other <- ID() }()
	o := <-other
	require.NotZero(t, o)
	require.NotEqual(t, id, o)
}

func TestParse(t *testing.T) {
	require.Equal(t, uint64(12), parse([]byte("goroutine 12 [running]:\n")))
	require.Zero(t, parse([]byte("thread 12 [running]")))
	require.Zero(t, parse([]byte("goroutine 12")))
	require.Zero(t, parse([]byte("goroutine x [running]")))
}
