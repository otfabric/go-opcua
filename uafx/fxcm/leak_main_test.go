// SPDX-License-Identifier: MIT

package fxcm

import (
	"testing"

	"github.com/otfabric/go-opcua/internal/testutil/leakcheck"
)

// TestMain fails the test binary if goroutines of this module are still
// running after all tests finished.
func TestMain(m *testing.M) { leakcheck.Main(m) }
