// SPDX-License-Identifier: MIT

package eth

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/leakcheck"
)

// TestMain fails the test binary if goroutines of this module are still
// running after all tests finished (a Close that did not stop everything).
func TestMain(m *testing.M) { leakcheck.Main(m) }
