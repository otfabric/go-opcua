// SPDX-License-Identifier: MIT

//go:build !(linux || windows || darwin || dragonfly || freebsd || netbsd || openbsd)

package mdns

// setMulticastOptions is a no-op where the socket options are not available:
// the defaults (a hop limit of 1, no loopback) still work on the local link.
func setMulticastOptions(uintptr, bool) {}
