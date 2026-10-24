// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// psMem is an in-memory datagram transport ("confmem://name") for the
// PubSub tests that need a shared segment, as multicast provides one, on
// hosts without multicast loopback: every datagram sent on a segment
// reaches every subscription on it, including those of the sender. The
// runtimes use it with the UDP transport profile.
const psMemScheme = "confmem"

var psMemNet = struct {
	mu   sync.Mutex
	n    atomic.Int64
	segs map[string]*psMemSegment
}{segs: map[string]*psMemSegment{}}

func init() {
	transport.Register(psMemScheme, func(_ context.Context, cfg transport.Config) (transport.Connection, error) {
		psMemNet.mu.Lock()
		defer psMemNet.mu.Unlock()
		s := psMemNet.segs[cfg.URL]
		if s == nil {
			s = &psMemSegment{subs: map[*psMemSub]struct{}{}}
			psMemNet.segs[cfg.URL] = s
		}
		return &psMemConn{seg: s, subs: map[*psMemSub]struct{}{}}, nil
	})
}

// psMemURL returns the URL of a new segment.
func psMemURL(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s://seg-%d", psMemScheme, psMemNet.n.Add(1))
}

type psMemSegment struct {
	mu   sync.Mutex
	subs map[*psMemSub]struct{}
}

type psMemSub struct {
	h    transport.Handler
	ch   chan []byte
	done chan struct{}
	wg   sync.WaitGroup
}

func (sub *psMemSub) run() {
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

type psMemConn struct {
	seg    *psMemSegment
	mu     sync.Mutex
	closed bool
	subs   map[*psMemSub]struct{}
}

const psMemMaxMessage = 65507

func (c *psMemConn) Send(_ context.Context, payload []byte, _ transport.PublishOptions) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errors.New("confmem: closed")
	}
	if len(payload) > psMemMaxMessage {
		return transport.ErrMessageTooLarge
	}
	c.seg.mu.Lock()
	defer c.seg.mu.Unlock()
	for sub := range c.seg.subs {
		select {
		case sub.ch <- append([]byte(nil), payload...):
		default: // a full socket buffer
		}
	}
	return nil
}

func (c *psMemConn) Subscribe(_ context.Context, _ string, _ byte, h transport.Handler) (func() error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("confmem: closed")
	}
	sub := &psMemSub{h: h, ch: make(chan []byte, 4096), done: make(chan struct{})}
	c.subs[sub] = struct{}{}
	c.seg.mu.Lock()
	c.seg.subs[sub] = struct{}{}
	c.seg.mu.Unlock()
	sub.wg.Add(1)
	go sub.run()
	var once sync.Once
	return func() error { once.Do(func() { c.cancel(sub) }); return nil }, nil
}

func (c *psMemConn) cancel(sub *psMemSub) {
	c.seg.mu.Lock()
	delete(c.seg.subs, sub)
	c.seg.mu.Unlock()
	c.mu.Lock()
	_, ok := c.subs[sub]
	delete(c.subs, sub)
	c.mu.Unlock()
	if ok {
		close(sub.done)
		sub.wg.Wait()
	}
}

func (c *psMemConn) MaxMessageSize() int { return psMemMaxMessage }

func (c *psMemConn) Close() error {
	c.mu.Lock()
	c.closed = true
	subs := make([]*psMemSub, 0, len(c.subs))
	for sub := range c.subs {
		subs = append(subs, sub)
	}
	c.mu.Unlock()
	for _, sub := range subs {
		c.cancel(sub)
	}
	return nil
}
