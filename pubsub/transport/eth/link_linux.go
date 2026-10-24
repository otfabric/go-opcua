// SPDX-License-Identifier: MIT

package eth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Linux: AF_PACKET raw sockets (packet(7)). The socket is non-blocking and
// wrapped in an os.File, so reads and writes wait in the runtime poller and
// Close wakes a blocked read.
//
// A receiving socket is bound to ETH_P_ALL with a socket filter for the
// EtherType, not to the EtherType itself: only ETH_P_ALL sockets see the
// frames this host sends (the outgoing tap) and the frames of VLANs
// without a VLAN interface. The kernel moves the tag of a received frame
// out of the data (into PACKET_AUXDATA), so received frames are read
// untagged; sent frames are read as written.

const (
	privilegeHint       = "CAP_NET_RAW or root"
	tagCountsAgainstMTU = false // the kernel allows 4 more bytes for a tagged frame
	// Supported reports whether the OS has an implementation.
	Supported = true
)

// The system calls, replaced by tests.
var (
	sysSocket = unix.Socket
	sysBind   = unix.Bind
	sysJoin   = unix.SetsockoptPacketMreq
	sysFilter = unix.SetsockoptSockFprog
	sysRecv   = unix.Recvmsg
	sysSendto = unix.Sendto
)

// htons converts to network byte order, as AF_PACKET wants the protocol.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

type packetLink struct {
	f       *os.File
	rc      syscall.RawConn
	ifindex int
	to      unix.SockaddrLinklayer // destination of written frames
	closed  atomic.Bool
}

func openOSLink(cfg linkConfig) (link, error) {
	// Protocol 0: the socket receives nothing until it is bound, after
	// the filter is in place. A sending socket stays at protocol 0.
	fd, err := sysSocket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, privilegeError("open AF_PACKET socket", err)
	}
	f := os.NewFile(uintptr(fd), "packet:"+cfg.ifi.Name)
	fail := func(what string, err error) (link, error) {
		_ = f.Close()
		return nil, fmt.Errorf("pubsub/transport/eth: %s on %s: %w", what, cfg.ifi.Name, err)
	}
	var proto uint16
	if cfg.recv {
		filter := make([]unix.SockFilter, len(recvFilter))
		for i, in := range recvFilter {
			filter[i] = unix.SockFilter{Code: in.code, Jt: in.jt, Jf: in.jf, K: in.k}
		}
		if err := sysFilter(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
			return fail("attach filter", err)
		}
		proto = htons(unix.ETH_P_ALL)
	}
	// Bind to the interface: frames of other interfaces are not queued.
	if err := sysBind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: cfg.ifi.Index}); err != nil {
		return fail("bind", err)
	}
	if cfg.group != nil {
		mreq := &unix.PacketMreq{Ifindex: int32(cfg.ifi.Index), Type: unix.PACKET_MR_MULTICAST, Alen: 6}
		copy(mreq.Address[:], cfg.group)
		// The membership ends with the socket.
		if err := sysJoin(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
			return fail("join "+FormatMAC(cfg.group), err)
		}
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return fail("raw conn", err)
	}
	l := &packetLink{f: f, rc: rc, ifindex: cfg.ifi.Index}
	l.to = unix.SockaddrLinklayer{Protocol: htons(EtherType), Ifindex: cfg.ifi.Index, Halen: 6}
	return l, nil
}

func (l *packetLink) read(buf []byte) (int, bool, error) {
	for {
		var (
			n, flags int
			from     unix.Sockaddr
			rerr     error
		)
		err := l.rc.Read(func(fd uintptr) bool {
			n, _, flags, from, rerr = sysRecv(int(fd), buf, nil, 0)
			return !errors.Is(rerr, unix.EAGAIN)
		})
		switch {
		case err != nil || l.closed.Load():
			return 0, false, net.ErrClosed
		case errors.Is(rerr, unix.EINTR):
			continue
		case rerr != nil:
			return 0, false, rerr
		case flags&unix.MSG_TRUNC != 0:
			continue // larger than buf: not one of ours
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || ll.Ifindex != l.ifindex {
			continue // not from the interface
		}
		return n, ll.Pkttype == unix.PACKET_OUTGOING, nil
	}
}

func (l *packetLink) write(frame []byte, deadline time.Time) error {
	if len(frame) < headerLen {
		return errShortFrame
	}
	to := l.to
	copy(to.Addr[:], frame[:6])
	_ = l.f.SetWriteDeadline(deadline)
	var werr error
	err := l.rc.Write(func(fd uintptr) bool {
		werr = sysSendto(int(fd), frame, 0, &to)
		return !errors.Is(werr, unix.EAGAIN)
	})
	switch {
	case l.closed.Load():
		return net.ErrClosed
	case err != nil:
		return err
	case errors.Is(werr, unix.EMSGSIZE):
		return fmt.Errorf("%w: frame of %d bytes", errFrameTooLarge, len(frame))
	}
	return werr
}

func (l *packetLink) close() error {
	l.closed.Store(true)
	return l.f.Close()
}

// osMACHidden reports whether the OS hid the MAC address of an interface:
// never.
func osMACHidden(net.HardwareAddr) bool { return false }
