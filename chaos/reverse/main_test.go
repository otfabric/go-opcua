// SPDX-License-Identifier: MIT

package reverse

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
)

// TestMain adds a final, process-wide goroutine leak check to the checks the
// scenarios make themselves.
func TestMain(m *testing.M) { chaoskit.Main(m) }
