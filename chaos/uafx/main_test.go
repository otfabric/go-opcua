// SPDX-License-Identifier: MIT

package uafx

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
)

// TestMain adds a final, process-wide goroutine leak check.
func TestMain(m *testing.M) { chaoskit.Main(m) }
