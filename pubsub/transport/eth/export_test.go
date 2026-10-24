// SPDX-License-Identifier: MIT

package eth

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// MemSegment is an in-memory Ethernet segment for the tests of package
// eth_test: it replaces the OS links (and the interfaces, with those of
// eth_test.go) for the duration of a test, so that publishers and
// subscribers run over the Ethernet transport without raw socket access.
// Every frame a link sends reaches every receiving link, unless Drop says
// otherwise; where the OS marks the frames this host sends (Linux), they
// arrive marked outgoing, as through the OS's tap. Tests using it must not run in
// parallel.
type MemSegment struct {
	// Drop, if set, is asked about every frame before it is delivered.
	Drop func(frame []byte) bool

	mu    sync.Mutex
	links map[*memLink]struct{}

	Sent, Delivered, Dropped atomic.Int64
}

// MemInterface is the interface of a MemSegment, MemInterfaceMAC its MAC
// address.
const MemInterface = "eth0"

// MemInterfaceMAC returns the MAC address of MemInterface.
func MemInterfaceMAC() string { return FormatMAC(macA) }

// UseMemSegment installs a MemSegment until the end of the test.
func UseMemSegment(t testing.TB) *MemSegment {
	t.Helper()
	seg := &MemSegment{links: map[*memLink]struct{}{}}
	oldOpen, oldIf := openLink, interfaceByName
	openLink = func(cfg linkConfig) (link, error) {
		l := &memLink{seg: seg, cfg: cfg, in: make(chan []byte, 4096), done: make(chan struct{})}
		if cfg.recv {
			seg.mu.Lock()
			seg.links[l] = struct{}{}
			seg.mu.Unlock()
		}
		return l, nil
	}
	interfaceByName = func(name string) (*net.Interface, error) {
		if ifi, ok := fakeInterfaces[name]; ok {
			cp := *ifi
			return &cp, nil
		}
		return nil, errors.New("no such interface")
	}
	t.Cleanup(func() { openLink, interfaceByName = oldOpen, oldIf })
	return seg
}

func (s *MemSegment) deliver(frame []byte) {
	s.Sent.Add(1)
	if s.Drop != nil && s.Drop(frame) {
		s.Dropped.Add(1)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for l := range s.links {
		select {
		case l.in <- bytes.Clone(frame):
			s.Delivered.Add(1)
		default:
			s.Dropped.Add(1)
		}
	}
}

type memLink struct {
	seg  *MemSegment
	cfg  linkConfig
	in   chan []byte
	done chan struct{}
	once sync.Once
}

func (l *memLink) read(buf []byte) (int, bool, error) {
	select {
	case b := <-l.in:
		// A frame of this host (the interface's source address) comes
		// through the outgoing tap where there is one, as from the OS.
		own := len(b) >= 12 && l.cfg.ifi != nil && bytes.Equal(b[6:12], l.cfg.ifi.HardwareAddr)
		return copy(buf, b), outgoingTap && own, nil
	case <-l.done:
		return 0, false, net.ErrClosed
	}
}

func (l *memLink) write(frame []byte, _ time.Time) error {
	select {
	case <-l.done:
		return net.ErrClosed
	default:
	}
	if len(frame) > MaxPayload+headerLen+tagLen {
		return errFrameTooLarge
	}
	l.seg.deliver(frame)
	return nil
}

func (l *memLink) close() error {
	l.once.Do(func() { close(l.done) })
	l.seg.mu.Lock()
	delete(l.seg.links, l)
	l.seg.mu.Unlock()
	return nil
}
