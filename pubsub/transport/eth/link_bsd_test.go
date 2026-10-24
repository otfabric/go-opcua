// SPDX-License-Identifier: MIT

//go:build darwin || freebsd

package eth

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// bpfFake replaces the system calls of link_bsd.go: a BPF device is one
// end of a datagram socket pair whose other end the test reads and writes,
// with a receive timeout like BIOCSRTIMEOUT.
type bpfFake struct {
	mu       sync.Mutex
	openErrs map[string]error
	peers    []int
	ioctls   []uint
	ifName   string
	fail     map[uint]error
	dlt      uint32
	blen     uint32
	addErr   error
	sockErr  error
	multi    []string
}

func useBPFFake(t *testing.T) *bpfFake {
	t.Helper()
	fk := &bpfFake{
		openErrs: map[string]error{"/dev/bpf": unix.ENOENT, "/dev/bpf0": unix.EBUSY},
		fail:     map[uint]error{},
		dlt:      unix.DLT_EN10MB,
		blen:     4096,
	}
	oldOpen, oldIoctl, oldSocket := sysOpen, sysIoctl, sysSocket
	sysOpen = fk.open
	sysIoctl = fk.ioctl
	sysSocket = fk.socket
	t.Cleanup(func() {
		sysOpen, sysIoctl, sysSocket = oldOpen, oldIoctl, oldSocket
		fk.mu.Lock()
		defer fk.mu.Unlock()
		for _, p := range fk.peers {
			_ = unix.Close(p)
		}
	})
	return fk
}

func (fk *bpfFake) open(path string, _ int, _ uint32) (int, error) {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	if err, ok := fk.openErrs[path]; ok {
		return -1, err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	tv := unix.NsecToTimeval((20 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fds[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return -1, err
	}
	fk.peers = append(fk.peers, fds[1])
	return fds[0], nil
}

func (fk *bpfFake) ioctl(_ int, req uint, arg unsafe.Pointer) error {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	fk.ioctls = append(fk.ioctls, req)
	if err := fk.fail[req]; err != nil {
		return err
	}
	switch req {
	case unix.BIOCGDLT:
		*(*uint32)(arg) = fk.dlt
	case unix.BIOCGBLEN:
		*(*uint32)(arg) = fk.blen
	case unix.BIOCSETIF:
		ifr := (*[unix.IFNAMSIZ + 16]byte)(arg)
		n := 0
		for n < unix.IFNAMSIZ && ifr[n] != 0 {
			n++
		}
		fk.ifName = string(ifr[:n])
	case unix.SIOCADDMULTI, unix.SIOCDELMULTI:
		ifr := (*[unix.IFNAMSIZ + 16]byte)(arg)
		sdl := ifr[unix.IFNAMSIZ:]
		op := "add "
		if req == unix.SIOCDELMULTI {
			op = "del "
		}
		if sdl[1] != unix.AF_LINK || sdl[6] != 6 {
			return unix.EINVAL
		}
		fk.multi = append(fk.multi, op+FormatMAC(net.HardwareAddr(sdl[8:14])))
		if req == unix.SIOCADDMULTI {
			return fk.addErr
		}
	}
	return nil
}

func (fk *bpfFake) socket(domain, typ, proto int) (int, error) {
	fk.mu.Lock()
	err := fk.sockErr
	fk.mu.Unlock()
	if err != nil {
		return -1, err
	}
	return unix.Socket(domain, typ, proto)
}

func (fk *bpfFake) peer(t *testing.T, i int) int {
	t.Helper()
	fk.mu.Lock()
	defer fk.mu.Unlock()
	require.Greater(t, len(fk.peers), i)
	return fk.peers[i]
}

func (fk *bpfFake) multicast() []string {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	return append([]string(nil), fk.multi...)
}

// bpfRecord encodes one bpf_hdr record: header, frame, alignment padding.
func bpfRecord(frame []byte, datalen int) []byte {
	hdrlen := (bpfMinHdr + bpfAlign - 1) &^ (bpfAlign - 1)
	b := make([]byte, hdrlen, hdrlen+len(frame)+bpfAlign)
	binary.NativeEndian.PutUint32(b[bpfCaplenOff:], uint32(len(frame)))
	binary.NativeEndian.PutUint32(b[bpfDatalenOff:], uint32(datalen))
	binary.NativeEndian.PutUint16(b[bpfHdrlenOff:], uint16(hdrlen))
	b = append(b, frame...)
	for len(b)%bpfAlign != 0 {
		b = append(b, 0)
	}
	return b
}

var eth0 = &net.Interface{Index: 2, Name: "eth0", MTU: 1500, HardwareAddr: macA}

func TestBPFOpenAndRead(t *testing.T) {
	fk := useBPFFake(t)
	l, err := openOSLink(linkConfig{ifi: eth0, recv: true, group: grp, loopback: true})
	require.NoError(t, err)
	require.Equal(t, "eth0", fk.ifName)
	require.Equal(t, []string{"add 01-00-5e-7f-00-01"}, fk.multicast())
	peer := fk.peer(t, 0)

	f1 := frameTo(macA, Address{}, "one")
	f2 := frameTo(macA, Address{VLAN: true, VID: 3}, "two")
	big := frameTo(macA, Address{}, string(make([]byte, 100)))
	cut := frameTo(macA, Address{}, "cut")
	var buf []byte
	buf = append(buf, bpfRecord(f1, len(f1))...)
	buf = append(buf, bpfRecord(cut, len(cut)+10)...) // cut short by the capture: skipped
	buf = append(buf, bpfRecord(big, len(big))...)    // larger than the read buffer: skipped
	buf = append(buf, bpfRecord(f2, len(f2))...)
	_, err = unix.Write(peer, buf)
	require.NoError(t, err)

	rb := make([]byte, 64)
	n, outgoing, err := l.read(rb)
	require.NoError(t, err)
	require.False(t, outgoing)
	require.Equal(t, f1, rb[:n])
	n, _, err = l.read(rb)
	require.NoError(t, err)
	require.Equal(t, f2, rb[:n])

	// An empty read (the read timeout) and malformed records are skipped.
	_, err = unix.Write(peer, nil)
	require.NoError(t, err)
	bad := bpfRecord(f1, len(f1))
	binary.NativeEndian.PutUint16(bad[bpfHdrlenOff:], 2) // header too short
	_, err = unix.Write(peer, bad)
	require.NoError(t, err)
	bad = bpfRecord(f1, len(f1))
	binary.NativeEndian.PutUint32(bad[bpfCaplenOff:], 4000) // beyond the buffer
	_, err = unix.Write(peer, bad)
	require.NoError(t, err)
	_, err = unix.Write(peer, []byte{1, 2, 3}) // shorter than a header
	require.NoError(t, err)
	_, err = unix.Write(peer, bpfRecord(f2, len(f2)))
	require.NoError(t, err)
	n, _, err = l.read(rb)
	require.NoError(t, err)
	require.Equal(t, f2, rb[:n])

	// Close ends a blocked read and leaves the group.
	done := make(chan error, 1)
	go func() {
		_, _, err := l.read(rb)
		done <- err
	}()
	require.NoError(t, l.close())
	require.ErrorIs(t, <-done, net.ErrClosed)
	_, _, err = l.read(rb)
	require.ErrorIs(t, err, net.ErrClosed)
	require.Equal(t, []string{"add 01-00-5e-7f-00-01", "del 01-00-5e-7f-00-01"}, fk.multicast())
}

func TestBPFWrite(t *testing.T) {
	fk := useBPFFake(t)
	l, err := openOSLink(linkConfig{ifi: eth0})
	require.NoError(t, err)
	require.Empty(t, fk.multicast())
	peer := fk.peer(t, 0)
	f := frameTo(grp, Address{}, "hello")
	require.NoError(t, l.write(f, time.Time{}))
	rb := make([]byte, 128)
	n, err := unix.Read(peer, rb)
	require.NoError(t, err)
	require.Equal(t, f, rb[:n])

	err = l.write(make([]byte, 1<<20), time.Time{})
	require.ErrorIs(t, err, errFrameTooLarge)
	_ = unix.Close(peer) // other errors are returned as they are
	fk.mu.Lock()
	fk.peers = fk.peers[1:]
	fk.mu.Unlock()
	require.Error(t, l.write(f, time.Time{}))

	require.NoError(t, l.close())
	require.ErrorIs(t, l.write(f, time.Time{}), net.ErrClosed)
}

func TestBPFOpenDevices(t *testing.T) {
	fk := useBPFFake(t)
	// The cloning device first.
	fk.openErrs = map[string]error{}
	l, err := openOSLink(linkConfig{ifi: eth0})
	require.NoError(t, err)
	require.NoError(t, l.close())

	// All busy.
	fk.openErrs = map[string]error{"/dev/bpf": unix.ENOENT}
	for i := range bpfDevices {
		fk.openErrs["/dev/bpf"+strconv.Itoa(i)] = unix.EBUSY
	}
	_, err = openOSLink(linkConfig{ifi: eth0})
	require.ErrorContains(t, err, "all BPF devices are busy")

	// The busy ones up to the last device that exists.
	fk.openErrs = map[string]error{"/dev/bpf": unix.ENOENT, "/dev/bpf0": unix.EBUSY, "/dev/bpf1": unix.ENOENT}
	_, err = openOSLink(linkConfig{ifi: eth0})
	require.ErrorContains(t, err, "all BPF devices are busy")

	// No permission.
	fk.openErrs = map[string]error{"/dev/bpf": unix.ENOENT, "/dev/bpf0": unix.EACCES}
	_, err = openOSLink(linkConfig{ifi: eth0})
	require.ErrorIs(t, err, os.ErrPermission)
	require.ErrorContains(t, err, "open /dev/bpf0")
	require.ErrorContains(t, err, privilegeHint)
}

func TestBPFOpenErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, req := range []uint{unix.BIOCSBLEN, unix.BIOCSETIF, unix.BIOCGDLT, unix.BIOCIMMEDIATE,
		unix.BIOCSHDRCMPLT, unix.BIOCSSEESENT, unix.BIOCSRTIMEOUT, unix.BIOCSETF, unix.BIOCGBLEN, unix.SIOCADDMULTI} {
		fk := useBPFFake(t)
		fk.fail[req] = boom
		_, err := openOSLink(linkConfig{ifi: eth0, recv: true, group: grp})
		require.ErrorIs(t, err, boom, "ioctl %#x", req)
		require.ErrorContains(t, err, "on eth0")
	}

	fk := useBPFFake(t)
	fk.dlt = 0 // DLT_NULL: a loopback interface
	_, err := openOSLink(linkConfig{ifi: eth0})
	require.ErrorContains(t, err, "not an Ethernet interface")

	fk.dlt, fk.blen = unix.DLT_EN10MB, 0
	_, err = openOSLink(linkConfig{ifi: eth0})
	require.ErrorContains(t, err, "buffer of 0 bytes")

	fk.blen = 4096
	_, err = openOSLink(linkConfig{ifi: &net.Interface{Name: "a-very-long-interface-name"}})
	require.ErrorContains(t, err, "too long")

	fk.sockErr = boom
	_, err = openOSLink(linkConfig{ifi: eth0, recv: true, group: grp})
	require.ErrorIs(t, err, boom)
}

// A group someone else joined already (EADDRINUSE) is not left on close.
func TestBPFGroupJoinedElsewhere(t *testing.T) {
	fk := useBPFFake(t)
	fk.addErr = unix.EADDRINUSE
	l, err := openOSLink(linkConfig{ifi: eth0, recv: true, group: grp})
	require.NoError(t, err)
	require.NoError(t, l.close())
	require.Equal(t, []string{"add 01-00-5e-7f-00-01"}, fk.multicast())
}

func TestBPFRecordLayout(t *testing.T) {
	require.Equal(t, int(unsafe.Sizeof(unix.BpfHdr{}.Hdrlen)), 2)
	require.Positive(t, bpfAlign)
	require.Less(t, bpfDatalenOff, bpfHdrlenOff)
	require.Len(t, recvFilter, 7)
}

// The real BPF devices: lo0 is not an Ethernet interface. Skipped without
// access to /dev/bpf*.
func TestBPFRealLoopbackRejected(t *testing.T) {
	ifs, err := net.Interfaces()
	require.NoError(t, err)
	for i := range ifs {
		if ifs[i].Flags&net.FlagLoopback == 0 {
			continue
		}
		_, err := openOSLink(linkConfig{ifi: &ifs[i], recv: true})
		if errors.Is(err, os.ErrPermission) {
			t.Skip("no access to the BPF devices:", err)
		}
		require.ErrorContains(t, err, "not an Ethernet interface")
		return
	}
	t.Skip("no loopback interface")
}

func TestOSMACHidden(t *testing.T) {
	placeholder := net.HardwareAddr{2, 0, 0, 0, 0, 0}
	require.Equal(t, runtime.GOOS == "darwin", osMACHidden(placeholder))
	require.False(t, osMACHidden(macA))
}
