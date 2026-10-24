// SPDX-License-Identifier: MIT

package eth

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// packetFake replaces the system calls of link_linux.go: a packet socket
// is one end of a non-blocking datagram socket pair whose other end the
// test reads and writes. A datagram written to the peer is
//
//	[pkttype][ifindex][control] frame...
//
// control 1 reports a truncated frame, 2 EINTR, 3 an I/O error.
type packetFake struct {
	mu        sync.Mutex
	peers     []int
	socketErr error
	bindErr   error
	joinErr   error
	filterErr error
	binds     []unix.SockaddrLinklayer
	joins     []unix.PacketMreq
	filters   int
	sendErr   error
	sentTo    []unix.SockaddrLinklayer
}

func usePacketFake(t *testing.T) *packetFake {
	t.Helper()
	fk := &packetFake{}
	oldSocket, oldBind, oldJoin, oldFilter, oldRecv, oldSend := sysSocket, sysBind, sysJoin, sysFilter, sysRecv, sysSendto
	sysSocket = fk.socket
	sysBind = fk.bind
	sysJoin = fk.join
	sysFilter = fk.filter
	sysRecv = fk.recv
	sysSendto = fk.sendto
	t.Cleanup(func() {
		sysSocket, sysBind, sysJoin, sysFilter, sysRecv, sysSendto = oldSocket, oldBind, oldJoin, oldFilter, oldRecv, oldSend
		fk.mu.Lock()
		defer fk.mu.Unlock()
		for _, p := range fk.peers {
			_ = unix.Close(p)
		}
	})
	return fk
}

func (fk *packetFake) socket(domain, typ, proto int) (int, error) {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	if fk.socketErr != nil {
		return -1, fk.socketErr
	}
	if domain != unix.AF_PACKET || typ&unix.SOCK_RAW == 0 || typ&unix.SOCK_NONBLOCK == 0 || proto != 0 {
		return -1, unix.EINVAL
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	fk.peers = append(fk.peers, fds[1])
	return fds[0], nil
}

func (fk *packetFake) bind(_ int, sa unix.Sockaddr) error {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	fk.binds = append(fk.binds, *sa.(*unix.SockaddrLinklayer))
	return fk.bindErr
}

func (fk *packetFake) join(_, level, opt int, mreq *unix.PacketMreq) error {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	if level != unix.SOL_PACKET || opt != unix.PACKET_ADD_MEMBERSHIP {
		return unix.EINVAL
	}
	fk.joins = append(fk.joins, *mreq)
	return fk.joinErr
}

func (fk *packetFake) filter(_, level, opt int, prog *unix.SockFprog) error {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	if level != unix.SOL_SOCKET || opt != unix.SO_ATTACH_FILTER || int(prog.Len) != len(recvFilter) {
		return unix.EINVAL
	}
	fk.filters++
	return fk.filterErr
}

func (fk *packetFake) recv(fd int, p, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
	buf := make([]byte, len(p)+3)
	n, _, _, _, err := unix.Recvmsg(fd, buf, oob, flags)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if n < 3 {
		return 0, 0, 0, &unix.SockaddrUnix{}, nil // not a link-layer source
	}
	from := &unix.SockaddrLinklayer{Pkttype: buf[0], Ifindex: int(buf[1])}
	var rflags int
	switch buf[2] {
	case 1:
		rflags = unix.MSG_TRUNC
	case 2:
		return 0, 0, 0, nil, unix.EINTR
	case 3:
		return 0, 0, 0, nil, unix.EIO
	}
	return copy(p, buf[3:n]), 0, rflags, from, nil
}

func (fk *packetFake) sendto(fd int, p []byte, flags int, to unix.Sockaddr) error {
	fk.mu.Lock()
	fk.sentTo = append(fk.sentTo, *to.(*unix.SockaddrLinklayer))
	err := fk.sendErr
	fk.mu.Unlock()
	if err != nil {
		return err
	}
	return unix.Sendto(fd, p, flags, nil)
}

func (fk *packetFake) peer(t *testing.T, i int) int {
	t.Helper()
	fk.mu.Lock()
	defer fk.mu.Unlock()
	require.Greater(t, len(fk.peers), i)
	return fk.peers[i]
}

var eth0 = &net.Interface{Index: 2, Name: "eth0", MTU: 1500, HardwareAddr: macA}

func TestPacketOpenAndRead(t *testing.T) {
	fk := usePacketFake(t)
	l, err := openOSLink(linkConfig{ifi: eth0, recv: true, group: grp})
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.close() })
	require.Equal(t, 1, fk.filters)
	require.Equal(t, []unix.SockaddrLinklayer{{Protocol: htons(unix.ETH_P_ALL), Ifindex: 2}}, fk.binds)
	require.Len(t, fk.joins, 1)
	require.Equal(t, int32(2), fk.joins[0].Ifindex)
	require.Equal(t, uint16(unix.PACKET_MR_MULTICAST), fk.joins[0].Type)
	require.Equal(t, uint16(6), fk.joins[0].Alen)
	require.Equal(t, []byte(grp), fk.joins[0].Address[:6])
	peer := fk.peer(t, 0)

	f := frameTo(macA, Address{}, "frame")
	put := func(pkttype, ifindex, control byte, frame []byte) {
		_, err := unix.Write(peer, append([]byte{pkttype, ifindex, control}, frame...))
		require.NoError(t, err)
	}
	put(unix.PACKET_HOST, 3, 0, f)       // other interface: skipped
	put(unix.PACKET_HOST, 2, 1, f)       // truncated: skipped
	put(unix.PACKET_HOST, 2, 2, f)       // EINTR: retried
	_, err = unix.Write(peer, []byte{1}) // no link-layer source: skipped
	require.NoError(t, err)
	put(unix.PACKET_MULTICAST, 2, 0, f)
	put(unix.PACKET_OUTGOING, 2, 0, f)
	put(unix.PACKET_HOST, 2, 3, f) // an I/O error is returned

	buf := make([]byte, 128)
	n, outgoing, err := l.read(buf)
	require.NoError(t, err)
	require.False(t, outgoing)
	require.Equal(t, f, buf[:n])
	n, outgoing, err = l.read(buf)
	require.NoError(t, err)
	require.True(t, outgoing)
	require.Equal(t, f, buf[:n])
	_, _, err = l.read(buf)
	require.ErrorIs(t, err, unix.EIO)

	// Close wakes a blocked read.
	done := make(chan error, 1)
	go func() {
		_, _, err := l.read(buf)
		done <- err
	}()
	require.NoError(t, l.close())
	require.ErrorIs(t, <-done, net.ErrClosed)
}

func TestPacketWrite(t *testing.T) {
	fk := usePacketFake(t)
	l, err := openOSLink(linkConfig{ifi: eth0})
	require.NoError(t, err)
	require.Zero(t, fk.filters)
	require.Empty(t, fk.joins)
	require.Equal(t, []unix.SockaddrLinklayer{{Protocol: 0, Ifindex: 2}}, fk.binds)
	peer := fk.peer(t, 0)

	f := frameTo(grp, Address{}, "hello")
	require.NoError(t, l.write(f, time.Now().Add(time.Hour)))
	buf := make([]byte, 128)
	n, err := unix.Read(peer, buf)
	require.NoError(t, err)
	require.Equal(t, f, buf[:n])
	require.Equal(t, unix.SockaddrLinklayer{Protocol: htons(EtherType), Ifindex: 2, Halen: 6, Addr: [8]byte{0x01, 0x00, 0x5e, 0x7f, 0x00, 0x01}}, fk.sentTo[0])

	require.ErrorIs(t, l.write(f[:10], time.Time{}), errShortFrame)
	fk.mu.Lock()
	fk.sendErr = unix.EMSGSIZE
	fk.mu.Unlock()
	require.ErrorIs(t, l.write(f, time.Time{}), errFrameTooLarge)
	fk.mu.Lock()
	fk.sendErr = unix.ENETDOWN
	fk.mu.Unlock()
	require.ErrorIs(t, l.write(f, time.Time{}), unix.ENETDOWN)

	require.NoError(t, l.close())
	require.ErrorIs(t, l.write(f, time.Time{}), net.ErrClosed)
}

// A write that cannot complete before its deadline fails.
func TestPacketWriteDeadline(t *testing.T) {
	fk := usePacketFake(t)
	l, err := openOSLink(linkConfig{ifi: eth0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.close() })
	fk.mu.Lock()
	fk.sendErr = unix.EAGAIN // the socket buffer stays full
	fk.mu.Unlock()
	err = l.write(frameTo(grp, Address{}, "x"), time.Now().Add(-time.Second))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestPacketOpenErrors(t *testing.T) {
	fk := usePacketFake(t)
	fk.socketErr = unix.EPERM
	_, err := openOSLink(linkConfig{ifi: eth0, recv: true})
	require.ErrorIs(t, err, os.ErrPermission)
	require.ErrorContains(t, err, "open AF_PACKET socket: operation not permitted (raw Ethernet access needs CAP_NET_RAW or root)")

	boom := errors.New("boom")
	fk.socketErr, fk.filterErr = nil, boom
	_, err = openOSLink(linkConfig{ifi: eth0, recv: true})
	require.ErrorContains(t, err, "attach filter on eth0: boom")

	fk.filterErr, fk.bindErr = nil, boom
	_, err = openOSLink(linkConfig{ifi: eth0})
	require.ErrorContains(t, err, "bind on eth0: boom")

	fk.bindErr, fk.joinErr = nil, boom
	_, err = openOSLink(linkConfig{ifi: eth0, recv: true, group: grp})
	require.ErrorContains(t, err, "join 01-00-5e-7f-00-01 on eth0: boom")
}

func TestHtons(t *testing.T) {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], htons(EtherType))
	require.Equal(t, [2]byte{0xB6, 0x2C}, raw) // network byte order in memory
}

func TestOSMACHidden(t *testing.T) {
	require.False(t, osMACHidden(net.HardwareAddr{2, 0, 0, 0, 0, 0}))
}
