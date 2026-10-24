// SPDX-License-Identifier: MIT

package transport

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistry(t *testing.T) {
	var got Config
	// The registry is global: remove the scheme again so the test can run
	// more than once in a process (-count).
	t.Cleanup(func() {
		mu.Lock()
		delete(openers, "test.fake")
		mu.Unlock()
	})
	Register("test.fake", func(_ context.Context, cfg Config) (Connection, error) {
		got = cfg
		return nil, errors.New("fake")
	})
	require.Contains(t, Schemes(), "test.fake")
	require.Panics(t, func() { Register("test.fake", nil) })

	_, err := Open(context.Background(), Config{URL: "test.fake://x"})
	require.EqualError(t, err, "fake")
	require.Equal(t, "test.fake://x", got.URL)

	_, err = Open(context.Background(), Config{URL: "nope://x"})
	require.ErrorContains(t, err, "no transport")
	_, err = Open(context.Background(), Config{URL: "no-scheme"})
	require.Error(t, err)

	s, err := Scheme("opc.udp://239.0.0.1:4840")
	require.NoError(t, err)
	require.Equal(t, "opc.udp", s)
	_, err = Scheme(":x")
	require.Error(t, err)
}
