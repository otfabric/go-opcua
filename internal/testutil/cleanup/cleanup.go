// SPDX-License-Identifier: MIT

// Package cleanup registers test cleanups that let go of what they close.
//
// The testing package keeps a parallel test, with the cleanup functions it
// registered, until its parent test ends: the parent's queue of parallel
// subtests holds it, and running a cleanup shortens the slice of cleanups
// without clearing its element. For a top-level parallel test the parent
// ends with the test binary. A cleanup that closes a server therefore keeps
// the closed server, with its address space, reachable to the end of the
// run: in uafx/fxcm about 200 AutomationComponent servers of about 27 MB
// each, which took the live heap of the package past 6 GB.
package cleanup

import "testing"

// Register registers f with tb.Cleanup and drops the reference to f once f
// has run, so that what f captures can be collected while tb is still
// reachable.
func Register(tb testing.TB, f func()) {
	tb.Helper()
	tb.Cleanup(func() {
		f()
		f = nil
	})
}
