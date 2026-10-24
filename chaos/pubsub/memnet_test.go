// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// memnet is an in-memory datagram network for the PubSub runtime: the
// transport "chaosmem" (registered below) connects every connection with
// the same URL to one segment, which delivers what any of them sends to
// all of them (like a multicast group with loopback), through the faults
// of the segment. The runtime treats it as a datagram transport on a
// shared address: UADP, chunks and discovery behave as over UDP
// multicast, without sockets, ports or kernel buffers.

const memScheme = "chaosmem"

// memMaxMessage is the largest payload a segment carries (that of UDP).
const memMaxMessage = 65507

type memNet struct {
	mu   sync.Mutex
	segs map[string]*memSegment
	n    atomic.Int64
}

var mnet = &memNet{segs: map[string]*memSegment{}}

func init() {
	transport.Register(memScheme, func(_ context.Context, cfg transport.Config) (transport.Connection, error) {
		return &memConn{seg: mnet.segment(cfg.URL)}, nil
	})
}

// memURL returns the URL of a new segment.
func memURL(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s://seg-%d", memScheme, mnet.n.Add(1))
}

func (n *memNet) segment(url string) *memSegment {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.segs[url]
	if s == nil {
		s = &memSegment{url: url, subs: map[*memSub]struct{}{}, rng: rand.New(rand.NewSource(1))}
		s.f.Store(&faults{})
		n.segs[url] = s
	}
	return s
}

// memSegment is one broadcast domain.
type memSegment struct {
	url string
	f   atomic.Pointer[faults]

	mu   sync.Mutex
	subs map[*memSub]struct{}
	rng  *rand.Rand
	held []byte
	// tap, if set, sees every payload sent, before the faults.
	tap func([]byte)

	sent, delivered, dropped atomic.Int64
}

// seed sets the random source of the faults.
func (s *memSegment) seed(seed int64) {
	s.mu.Lock()
	s.rng = rand.New(rand.NewSource(seed))
	s.mu.Unlock()
}

// set changes the faults; clean faults release a held datagram.
func (s *memSegment) set(f faults) {
	s.f.Store(&f)
	if f == (faults{}) {
		s.mu.Lock()
		held := s.held
		s.held = nil
		s.mu.Unlock()
		if held != nil {
			s.broadcast(held)
		}
	}
}

func (s *memSegment) setTap(f func([]byte)) {
	s.mu.Lock()
	s.tap = f
	s.mu.Unlock()
}

// subscribers returns the number of open subscriptions.
func (s *memSegment) subscribers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.subs)
}

// inject delivers b to every subscriber, past the faults.
func (s *memSegment) inject(b []byte) { s.broadcast(append([]byte(nil), b...)) }

// injectSync calls the handlers of the subscribers with b in the calling
// goroutine, past the faults and the queues: the runtime has processed b
// when it returns.
func (s *memSegment) injectSync(b []byte) {
	s.mu.Lock()
	subs := make([]*memSub, 0, len(s.subs))
	for sub := range s.subs {
		subs = append(subs, sub)
	}
	s.mu.Unlock()
	for _, sub := range subs {
		sub.h(&transport.Message{Payload: append([]byte(nil), b...), Received: time.Now()})
	}
}

// send applies the faults to one datagram and delivers the result.
func (s *memSegment) send(payload []byte) {
	b := append([]byte(nil), payload...)
	s.sent.Add(1)
	f := s.f.Load()
	s.mu.Lock()
	if s.tap != nil {
		s.tap(append([]byte(nil), b...))
	}
	roll := func(p float64) bool { return p > 0 && s.rng.Float64() < p }
	var out [][]byte
	switch {
	case f.blackhole || roll(f.drop):
		s.dropped.Add(1)
	default:
		if roll(f.corrupt) {
			for range 1 + s.rng.Intn(3) {
				b[s.rng.Intn(len(b))] ^= byte(1 + s.rng.Intn(255))
			}
		}
		if roll(f.truncate) && len(b) > 1 {
			b = b[:s.rng.Intn(len(b))]
		}
		out = append(out, b)
		if roll(f.dup) {
			out = append(out, b)
		}
		if s.held != nil {
			out = append(out, s.held)
			s.held = nil
		} else if roll(f.reorder) {
			s.held, out = b, out[1:]
		}
	}
	var delay time.Duration
	if f.delay > 0 {
		delay = f.delay + time.Duration(s.rng.Int63n(int64(f.delay)))
	}
	s.mu.Unlock()
	for _, o := range out {
		if delay > 0 {
			time.AfterFunc(delay, func() { s.broadcast(o) })
			continue
		}
		s.broadcast(o)
	}
}

// broadcast queues b for every subscriber; a full queue drops it, as a
// socket buffer does.
func (s *memSegment) broadcast(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sub := range s.subs {
		select {
		case sub.ch <- b:
			s.delivered.Add(1)
		default:
			s.dropped.Add(1)
		}
	}
}

type memSub struct {
	h    transport.Handler
	ch   chan []byte
	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

func (sub *memSub) run() {
	defer sub.wg.Done()
	for {
		select {
		case <-sub.done:
			return
		case b := <-sub.ch:
			sub.h(&transport.Message{Payload: b, Received: time.Now()})
		}
	}
}

// memConn is a connection to a segment.
type memConn struct {
	seg *memSegment

	mu     sync.Mutex
	closed bool
	subs   map[*memSub]struct{}
}

var errMemClosed = errors.New("chaosmem: closed")

func (c *memConn) Send(_ context.Context, payload []byte, _ transport.PublishOptions) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errMemClosed
	}
	if len(payload) > memMaxMessage {
		return transport.ErrMessageTooLarge
	}
	c.seg.send(payload)
	return nil
}

func (c *memConn) Subscribe(_ context.Context, _ string, _ byte, h transport.Handler) (func() error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errMemClosed
	}
	sub := &memSub{h: h, ch: make(chan []byte, 4096), done: make(chan struct{})}
	if c.subs == nil {
		c.subs = map[*memSub]struct{}{}
	}
	c.subs[sub] = struct{}{}
	c.seg.mu.Lock()
	c.seg.subs[sub] = struct{}{}
	c.seg.mu.Unlock()
	sub.wg.Add(1)
	go sub.run()
	return func() error { c.cancel(sub); return nil }, nil
}

func (c *memConn) cancel(sub *memSub) {
	c.seg.mu.Lock()
	delete(c.seg.subs, sub)
	c.seg.mu.Unlock()
	c.mu.Lock()
	delete(c.subs, sub)
	c.mu.Unlock()
	sub.once.Do(func() { close(sub.done) })
	sub.wg.Wait()
}

func (c *memConn) MaxMessageSize() int { return memMaxMessage }

func (c *memConn) Close() error {
	c.mu.Lock()
	c.closed = true
	subs := make([]*memSub, 0, len(c.subs))
	for sub := range c.subs {
		subs = append(subs, sub)
	}
	c.mu.Unlock()
	for _, sub := range subs {
		c.cancel(sub)
	}
	return nil
}
