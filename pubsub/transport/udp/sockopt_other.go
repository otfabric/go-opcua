// SPDX-License-Identifier: MIT

//go:build !(linux || windows || darwin || dragonfly || freebsd || netbsd || openbsd)

package udp

import (
	"errors"
	"net"
	"net/netip"
)

// On other systems unicast works; multicast and shared ports do not.

var errUnsupported = errors.New("not supported on this system")

func setReuse(uintptr, bool) error { return nil }

func setBroadcast(uintptr) error { return errUnsupported }

func joinGroup(uintptr, bool, netip.Addr, *net.Interface) error { return errUnsupported }

func setMulticastInterface(uintptr, bool, *net.Interface) error { return errUnsupported }

func setMulticastTTL(uintptr, bool, int) error { return errUnsupported }

func setMulticastLoop(uintptr, bool, bool) error { return errUnsupported }

const (
	soSndBuf = 0
	soRcvBuf = 0
)

func growBuffer(uintptr, int, int) error { return nil }
