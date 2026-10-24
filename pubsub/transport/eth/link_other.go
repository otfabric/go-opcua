// SPDX-License-Identifier: MIT

//go:build !(linux || darwin || freebsd)

package eth

import "net"

// Other systems (Windows, the other BSDs, ...) have no raw Ethernet access
// in this package: Open fails with ErrNotSupported.

const (
	privilegeHint       = "an OS this package supports"
	tagCountsAgainstMTU = false
	// Supported reports whether the OS has an implementation.
	Supported = false
)

func openOSLink(linkConfig) (link, error) { return nil, ErrNotSupported }

// osMACHidden reports whether the OS hid the MAC address of an interface:
// never.
func osMACHidden(net.HardwareAddr) bool { return false }
