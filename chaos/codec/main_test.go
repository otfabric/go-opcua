// SPDX-License-Identifier: MIT

package codec

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
)

// TestMain adds a final, process-wide goroutine leak check: the servers and
// clients of the NodeSet scenarios must not leave anything behind.
func TestMain(m *testing.M) { chaoskit.Main(m) }
