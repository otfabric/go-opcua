// SPDX-License-Identifier: MIT

package eth

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// link is a raw Ethernet link on one interface, opened by the OS layer
// (link_linux.go, link_bsd.go). A receiving link delivers the frames of
// EtherType 0xB62C (tagged or not) the interface receives; a sending link
// receives nothing.
type link interface {
	// read blocks for the next frame and copies it into buf. outgoing
	// reports a frame this host sent, seen by the receive tap (Linux). It
	// returns net.ErrClosed once the link is closed.
	read(buf []byte) (n int, outgoing bool, err error)
	// write sends one complete frame; a zero deadline does not time out.
	write(frame []byte, deadline time.Time) error
	// close closes the link and makes a blocked read return.
	close() error
}

// linkConfig describes the link to open.
type linkConfig struct {
	ifi *net.Interface
	// recv opens a receiving link, otherwise a sending one.
	recv bool
	// group is the multicast group a receiving link joins (nil: none).
	group net.HardwareAddr
	// loopback asks for the frames sent by this host as well (BSD: see
	// sent; Linux delivers them anyway, marked outgoing).
	loopback bool
}

// filterInsn is a classic BPF instruction, the filter language of bpf(4)
// devices and of Linux socket filters (SO_ATTACH_FILTER).
type filterInsn struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

// Classic BPF opcodes.
const (
	bpfLdHAbs = 0x28 // BPF_LD | BPF_H | BPF_ABS: A = the 16 bits at k
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K: A == k ? jt : jf
	bpfRetK   = 0x06 // BPF_RET | BPF_K: keep k bytes (0: drop)
)

// recvFilter selects the frames of EtherType 0xB62C, untagged or behind one
// 802.1Q tag, in the kernel. The frames are checked again after reading.
var recvFilter = []filterInsn{
	{code: bpfLdHAbs, k: 12},                    // 0: A = EtherType
	{code: bpfJeqK, jt: 3, jf: 0, k: EtherType}, // 1: OPC UA: accept
	{code: bpfJeqK, jt: 0, jf: 3, k: tpid8021Q}, // 2: no 802.1Q tag: drop
	{code: bpfLdHAbs, k: 16},                    // 3: A = EtherType after the tag
	{code: bpfJeqK, jt: 0, jf: 1, k: EtherType}, // 4: not OPC UA: drop
	{code: bpfRetK, k: 0xFFFFFFFF},              // 5: accept the whole frame
	{code: bpfRetK, k: 0},                       // 6: drop
}

// openLink opens the link of the OS; tests replace it.
var openLink = openOSLink

// ErrNotSupported is returned by Open on an OS without raw Ethernet access
// for this package (anything but Linux, macOS and FreeBSD).
var ErrNotSupported = fmt.Errorf("pubsub/transport/eth: the Ethernet transport is not supported on this OS: %w", errors.ErrUnsupported)

// errFrameTooLarge is returned by a link for a frame the OS rejects as too
// large for the interface.
var errFrameTooLarge = transport.ErrMessageTooLarge

// privilegeError explains a failure to open a raw socket or BPF device.
func privilegeError(what string, err error) error {
	return fmt.Errorf("pubsub/transport/eth: %s: %w (raw Ethernet access needs %s)", what, err, privilegeHint)
}
