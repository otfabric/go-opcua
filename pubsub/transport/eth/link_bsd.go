// SPDX-License-Identifier: MIT

//go:build darwin || freebsd

package eth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS and FreeBSD: BPF devices (bpf(4)). A device is bound to the
// interface, writes frames (the kernel sets the source address) and reads
// the frames a filter program selects. bpf devices do not work with kqueue for writing,
// so the device is used in blocking mode with a read timeout: a read
// returns at least every bpfReadTimeout, which bounds Close.

const (
	privilegeHint = "root or read-write access to /dev/bpf*"
	// tagCountsAgainstMTU: bpf(4) counts a VLAN tag as payload.
	tagCountsAgainstMTU = true
	// Supported reports whether the OS has an implementation.
	Supported = true

	bpfBuffer      = 1 << 16 // requested buffer size (BIOCSBLEN)
	bpfReadTimeout = 50 * time.Millisecond
	bpfDevices     = 256 // /dev/bpf0 .. /dev/bpf255
	iftEther       = 6   // IFT_ETHER of net/if_types.h
)

// The system calls, replaced by tests.
var (
	sysOpen   = unix.Open
	sysIoctl  = ioctl
	sysSocket = unix.Socket
	sysClose  = unix.Close
)

// osMACHidden reports whether mac is the placeholder macOS reports instead
// of the MAC address of an interface to a process without privileges.
func osMACHidden(mac net.HardwareAddr) bool {
	return runtime.GOOS == "darwin" && string(mac) == "\x02\x00\x00\x00\x00\x00"
}

// ioctl is ioctl(2) with a pointer argument, which x/sys/unix does not
// export for these requests.
func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func ioctlInt(fd int, req uint, v uint32) error { return sysIoctl(fd, req, unsafe.Pointer(&v)) }

// sendFilter rejects everything: a sending device reads nothing.
var sendFilter = []filterInsn{{code: bpfRetK, k: 0}}

// bpfProgram converts a filter program for BIOCSETF.
func bpfProgram(prog []filterInsn) []unix.BpfInsn {
	out := make([]unix.BpfInsn, len(prog))
	for i, in := range prog {
		out[i] = unix.BpfInsn{Code: in.code, Jt: in.jt, Jf: in.jf, K: in.k}
	}
	return out
}

// Offsets in struct bpf_hdr and the alignment of its records
// (BPF_WORDALIGN): 4 bytes on macOS, sizeof(long) on FreeBSD.
var (
	bpfCaplenOff  = int(unsafe.Offsetof(unix.BpfHdr{}.Caplen))
	bpfDatalenOff = int(unsafe.Offsetof(unix.BpfHdr{}.Datalen))
	bpfHdrlenOff  = int(unsafe.Offsetof(unix.BpfHdr{}.Hdrlen))
	bpfMinHdr     = bpfHdrlenOff + 2
	bpfAlign      = bpfAlignment()
)

func bpfAlignment() int {
	if runtime.GOOS == "darwin" {
		return 4
	}
	return int(unsafe.Sizeof(uintptr(0)))
}

type bpfLink struct {
	f       *os.File
	buf     []byte
	pending []byte // records of the last read not handed out yet
	ifi     *net.Interface
	group   net.HardwareAddr // joined by this link, left on close
	closed  atomic.Bool
}

// openBPF opens a free BPF device: the cloning /dev/bpf (FreeBSD) or the
// first /dev/bpfN that is not busy.
func openBPF() (int, error) {
	fd, err := sysOpen("/dev/bpf", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err == nil {
		return fd, nil
	}
	for i := range bpfDevices {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err = sysOpen(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			return fd, nil
		case errors.Is(err, unix.EBUSY):
			continue
		case errors.Is(err, unix.ENOENT) && i > 0:
			return -1, fmt.Errorf("pubsub/transport/eth: all BPF devices are busy")
		default:
			return -1, privilegeError("open "+path, err)
		}
	}
	return -1, fmt.Errorf("pubsub/transport/eth: all BPF devices are busy")
}

func openOSLink(cfg linkConfig) (link, error) {
	fd, err := openBPF()
	if err != nil {
		return nil, err
	}
	l := &bpfLink{ifi: cfg.ifi}
	fail := func(what string, err error) (link, error) {
		_ = sysClose(fd)
		return nil, fmt.Errorf("pubsub/transport/eth: %s on %s: %w", what, cfg.ifi.Name, err)
	}
	if err := ioctlInt(fd, unix.BIOCSBLEN, bpfBuffer); err != nil {
		return fail("BIOCSBLEN", err)
	}
	var ifr [unix.IFNAMSIZ + 16]byte // struct ifreq
	if len(cfg.ifi.Name) >= unix.IFNAMSIZ {
		return fail("interface name", errors.New("too long"))
	}
	copy(ifr[:], cfg.ifi.Name)
	if err := sysIoctl(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fail("BIOCSETIF", err)
	}
	var dlt uint32
	if err := sysIoctl(fd, unix.BIOCGDLT, unsafe.Pointer(&dlt)); err != nil {
		return fail("BIOCGDLT", err)
	}
	if dlt != unix.DLT_EN10MB {
		return fail("open", fmt.Errorf("not an Ethernet interface (data link type %d)", dlt))
	}
	seeSent := uint32(0)
	if cfg.loopback {
		seeSent = 1
	}
	for _, o := range []struct {
		req uint
		v   uint32
	}{
		{unix.BIOCIMMEDIATE, 1}, // deliver frames when they arrive
		// The kernel sets the source address of written frames: macOS
		// hides the MAC address from unprivileged processes (osMACHidden).
		{unix.BIOCSHDRCMPLT, 0},
		{unix.BIOCSSEESENT, seeSent},
	} {
		if err := ioctlInt(fd, o.req, o.v); err != nil {
			return fail(fmt.Sprintf("ioctl %#x", o.req), err)
		}
	}
	tv := unix.NsecToTimeval(bpfReadTimeout.Nanoseconds())
	if err := sysIoctl(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fail("BIOCSRTIMEOUT", err)
	}
	insns := bpfProgram(sendFilter)
	if cfg.recv {
		insns = bpfProgram(recvFilter)
	}
	prog := unix.BpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}
	if err := sysIoctl(fd, unix.BIOCSETF, unsafe.Pointer(&prog)); err != nil {
		return fail("BIOCSETF", err)
	}
	var blen uint32
	if err := sysIoctl(fd, unix.BIOCGBLEN, unsafe.Pointer(&blen)); err != nil {
		return fail("BIOCGBLEN", err)
	}
	if blen == 0 || blen > 1<<24 {
		return fail("BIOCGBLEN", fmt.Errorf("buffer of %d bytes", blen))
	}
	l.buf = make([]byte, blen)
	if cfg.recv && cfg.group != nil {
		joined, err := multicast(unix.SIOCADDMULTI, cfg.ifi, cfg.group)
		if err != nil {
			return fail("join "+FormatMAC(cfg.group), err)
		}
		if joined {
			l.group = cfg.group
		}
	}
	l.f = os.NewFile(uintptr(fd), "bpf:"+cfg.ifi.Name)
	return l, nil
}

// multicast joins (SIOCADDMULTI) or leaves (SIOCDELMULTI) a link-layer
// multicast group of the interface. Unlike a Linux packet socket
// membership it is not tied to the device: it is left explicitly. joined
// is false if the group was joined already (FreeBSD: EADDRINUSE), which
// leaves it to whoever joined it.
func multicast(req uint, ifi *net.Interface, group net.HardwareAddr) (joined bool, err error) {
	s, err := sysSocket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = sysClose(s) }()
	var ifr [unix.IFNAMSIZ + 16]byte
	copy(ifr[:], ifi.Name)
	// struct sockaddr_dl in ifr_addr: len, family, index, type, nlen,
	// alen, slen, then the address (nlen 0: no name before it).
	sdl := ifr[unix.IFNAMSIZ:]
	sdl[0], sdl[1] = 16, unix.AF_LINK
	binary.NativeEndian.PutUint16(sdl[2:4], uint16(ifi.Index))
	sdl[4], sdl[5], sdl[6], sdl[7] = iftEther, 0, 6, 0
	copy(sdl[8:14], group)
	err = sysIoctl(s, req, unsafe.Pointer(&ifr))
	if req == unix.SIOCADDMULTI && errors.Is(err, unix.EADDRINUSE) {
		return false, nil
	}
	return err == nil, err
}

func (l *bpfLink) read(buf []byte) (int, bool, error) {
	for {
		if rec, ok := l.next(); ok {
			if len(rec) > len(buf) {
				continue
			}
			return copy(buf, rec), false, nil
		}
		if l.closed.Load() {
			return 0, false, net.ErrClosed
		}
		n, err := l.f.Read(l.buf)
		switch {
		case l.closed.Load() || errors.Is(err, os.ErrClosed):
			return 0, false, net.ErrClosed
		case errors.Is(err, io.EOF), errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
			continue // read timeout
		case err != nil:
			return 0, false, err
		}
		l.pending = l.buf[:n]
	}
}

// next returns the next complete frame of the pending records. A record
// is struct bpf_hdr (bh_hdrlen bytes), the captured bytes (bh_caplen) and
// padding to bpfAlign. A truncated or malformed record ends the buffer.
func (l *bpfLink) next() ([]byte, bool) {
	for len(l.pending) > 0 {
		p := l.pending
		if len(p) < bpfMinHdr {
			l.pending = nil
			return nil, false
		}
		caplen := int(binary.NativeEndian.Uint32(p[bpfCaplenOff:]))
		datalen := int(binary.NativeEndian.Uint32(p[bpfDatalenOff:]))
		hdrlen := int(binary.NativeEndian.Uint16(p[bpfHdrlenOff:]))
		if hdrlen < bpfMinHdr || caplen > len(p)-hdrlen {
			l.pending = nil
			return nil, false
		}
		rec := p[hdrlen : hdrlen+caplen]
		adv := (hdrlen + caplen + bpfAlign - 1) &^ (bpfAlign - 1)
		if adv >= len(p) {
			l.pending = nil
		} else {
			l.pending = p[adv:]
		}
		if caplen == datalen { // skip frames the capture cut short
			return rec, true
		}
	}
	return nil, false
}

func (l *bpfLink) write(frame []byte, _ time.Time) error {
	if l.closed.Load() {
		return net.ErrClosed
	}
	_, err := l.f.Write(frame)
	switch {
	case l.closed.Load() || errors.Is(err, os.ErrClosed):
		return net.ErrClosed
	case errors.Is(err, unix.EMSGSIZE):
		return fmt.Errorf("%w: frame of %d bytes", errFrameTooLarge, len(frame))
	}
	return err
}

func (l *bpfLink) close() error {
	l.closed.Store(true)
	var err error
	if l.group != nil {
		_, err = multicast(unix.SIOCDELMULTI, l.ifi, l.group)
	}
	return errors.Join(err, l.f.Close())
}
