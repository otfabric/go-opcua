// SPDX-License-Identifier: MIT

// Package leakcheck finds goroutines of this module that are still running
// after the tests of a package have finished: a receive loop, timer or
// handler that its owner's Close did not stop. It uses only the standard
// library, so the tests of every package of the module can use it.
//
//	func TestMain(m *testing.M) { leakcheck.Main(m) }
package leakcheck

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

const modulePath = "github.com/otfabric/go-opcua"

// SettleTime is how long goroutines get to exit after the last test before
// they are reported.
var SettleTime = 10 * time.Second

// AllStacks returns the stacks of all goroutines.
func AllStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// ModuleGoroutines returns the stacks of all goroutines that run or were
// created by code of this module, keyed by goroutine id. ignore lists
// substrings of stacks that are not reported.
func ModuleGoroutines(ignore ...string) map[string]string {
	out := make(map[string]string)
stacks:
	for _, g := range strings.Split(AllStacks(), "\n\n") {
		if !strings.Contains(g, modulePath) {
			continue
		}
		for _, s := range ignore {
			if strings.Contains(g, s) {
				continue stacks
			}
		}
		header, _, _ := strings.Cut(g, "\n")
		fields := strings.Fields(header) // "goroutine 12 [running]:"
		if len(fields) < 2 {
			continue
		}
		out[fields[1]] = g
	}
	return out
}

// Leaked waits up to settle for the module's goroutines (except those
// matching ignore) to exit and returns the stacks of those that did not.
func Leaked(settle time.Duration, ignore ...string) []string {
	deadline := time.Now().Add(settle)
	for wait := 5 * time.Millisecond; ; {
		gs := ModuleGoroutines(ignore...)
		if len(gs) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			out := make([]string, 0, len(gs))
			for _, s := range gs {
				out = append(out, s)
			}
			return out
		}
		time.Sleep(wait)
		if wait < 200*time.Millisecond {
			wait *= 2
		}
	}
}

// Main runs the tests of a package and then fails the binary if goroutines
// of this module are still running after SettleTime. ignore lists stack
// substrings of goroutines that live on purpose (process-wide workers).
func Main(m *testing.M, ignore ...string) {
	code := m.Run()
	if code == 0 {
		// The goroutine running TestMain itself.
		ignore = append(ignore, "leakcheck.Main(", "chaoskit.Main(")
		if leaked := Leaked(SettleTime, ignore...); len(leaked) > 0 {
			fmt.Fprintf(os.Stderr, "GOROUTINE LEAK: %d goroutine(s) of this module are still running after all tests finished:\n\n%s\n",
				len(leaked), strings.Join(leaked, "\n\n"))
			code = 1
		}
	}
	os.Exit(code)
}
