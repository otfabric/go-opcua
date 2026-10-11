// SPDX-License-Identifier: MIT

package chaos

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestMain adds a final, process-wide goroutine leak check. The serial
// scenarios check for leaks themselves; the parallel tests cannot (their
// goroutines overlap), so whatever any of them left behind is caught here,
// after every test has finished and cleaned up.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		var leaked []string
		ok := eventually(settleLimit, func() bool {
			leaked = leaked[:0]
			for _, stack := range moduleGoroutines() {
				// the goroutine running TestMain itself
				if strings.Contains(stack, "chaos.TestMain(") {
					continue
				}
				leaked = append(leaked, stack)
			}
			return len(leaked) == 0
		})
		if !ok {
			fmt.Fprintf(os.Stderr, "GOROUTINE LEAK: %d goroutine(s) of this module are still running after all tests finished:\n\n%s\n",
				len(leaked), strings.Join(leaked, "\n\n"))
			code = 1
		}
	}
	os.Exit(code)
}
