// SPDX-License-Identifier: MIT

package cleanup_test

import (
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/otfabric/go-opcua/internal/testutil/cleanup"
)

type fixture struct{ buf [1 << 20]byte }

// TestRegisterRuns: the function runs at the end of the test, after the
// cleanups registered after it (LIFO, as tb.Cleanup).
func TestRegisterRuns(t *testing.T) {
	var order []string
	t.Run("sub", func(t *testing.T) {
		cleanup.Register(t, func() { order = append(order, "first") })
		cleanup.Register(t, func() { order = append(order, "second") })
	})
	if len(order) != 2 || order[0] != "second" || order[1] != "first" {
		t.Fatalf("order %v, want [second first]", order)
	}
}

// TestRegisterReleases: what the function captured can be collected once
// it ran, while the finished parallel test is still held by its parent.
func TestRegisterReleases(t *testing.T) {
	var wp weak.Pointer[fixture]
	ran := make(chan struct{})
	t.Run("group", func(t *testing.T) {
		t.Run("owner", func(t *testing.T) {
			t.Parallel()
			t.Cleanup(func() { close(ran) }) // runs after the one below
			f := &fixture{}
			wp = weak.Make(f)
			cleanup.Register(t, func() { f.buf[0] = 1 })
		})
		t.Run("check", func(t *testing.T) {
			t.Parallel()
			<-ran
			// The owner test has ended; its parent, group, has not.
			deadline := time.Now().Add(5 * time.Second)
			for wp.Value() != nil {
				if time.Now().After(deadline) {
					t.Fatal("the fixture captured by the cleanup is still reachable")
				}
				runtime.GC()
				time.Sleep(10 * time.Millisecond)
			}
		})
	})
}
