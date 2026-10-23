// SPDX-License-Identifier: MIT

package udp

import "syscall"

// soReusePort is SO_REUSEPORT, which package syscall does not define for
// Linux.
const soReusePort = 0xf

func setIPv4Option(fd, opt, v int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, opt, v)
}
