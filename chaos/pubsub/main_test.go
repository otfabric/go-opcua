// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
)

// TestMain adds a final, process-wide goroutine leak check: the parallel
// tests cannot check for leaks themselves (their goroutines overlap), so
// whatever any of them left behind is caught after all of them finished.
func TestMain(m *testing.M) { chaoskit.Main(m) }
