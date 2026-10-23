// SPDX-License-Identifier: MIT

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package udp

import "syscall"

const soReusePort = syscall.SO_REUSEPORT

// setIPv4Option sets IP_MULTICAST_TTL or IP_MULTICAST_LOOP, which take a
// single byte on the BSDs.
func setIPv4Option(fd, opt, v int) error {
	return syscall.SetsockoptByte(fd, syscall.IPPROTO_IP, opt, byte(v))
}
