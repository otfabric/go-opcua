// SPDX-License-Identifier: MIT

package gdspull

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
)

// TestMain adds a final, process-wide goroutine leak check.
func TestMain(m *testing.M) { chaoskit.Main(m) }
