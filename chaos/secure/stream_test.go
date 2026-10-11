// SPDX-License-Identifier: MIT

package secure

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// stream is a subscription on one or more int64 counter nodes together with a
// consumer goroutine that checks the values it receives.
//
// The counters are written with strictly increasing values, so within one
// monitored item the values delivered to the client must never go backwards
// and never be ahead of the writer: a value above the last one written was
// not produced by the writer. Equal values are tolerated: a re-created
// monitored item reports the current value again.
type stream struct {
	name string
	e    *env
	sub  *opcua.Subscription
	ch   chan *opcua.PublishNotificationData

	mu       sync.Mutex
	last     map[uint32]int64   // last value per client handle
	seq      map[uint32][]int64 // full history per client handle (if record)
	record   bool
	ordered  bool
	counters []int
	problems []string
	trail    []string // most recent notifications, for diagnostics

	received atomic.Int64
	errs     chaoskit.ErrorTally

	stop chan struct{}
	done chan struct{}
}

// streamParams are the default subscription parameters of a stream. The
// lifetime (60s without a Publish request) is far beyond what a loaded
// machine can delay a healthy client, so a subscription never expires in a
// fault-free test.
func streamParams() *opcua.SubscriptionParameters {
	return &opcua.SubscriptionParameters{
		Interval:          20 * time.Millisecond,
		MaxKeepAliveCount: 5,
		LifetimeCount:     3000,
	}
}

// shortLivedParams are for subscriptions that fault-injecting scenarios
// abandon on purpose (clients closed while unreachable): the server reclaims
// them after 2s. Nothing is asserted about their delivery.
func shortLivedParams() *opcua.SubscriptionParameters {
	return &opcua.SubscriptionParameters{
		Interval:          20 * time.Millisecond,
		MaxKeepAliveCount: 5,
		LifetimeCount:     100,
	}
}

// openStream subscribes c to the given counters with streamParams. bufSize is
// the capacity of the notification channel; 0 exercises the fully synchronous
// hand-off. If record is set the stream keeps the full value history.
func openStream(ctx context.Context, e *env, c *opcua.Client, name string, bufSize int, record bool, counters ...int) (*stream, error) {
	s, err := openStreamWith(ctx, e, c, name, bufSize, streamParams(), counters...)
	if s != nil && record {
		s.mu.Lock()
		s.record = true
		s.mu.Unlock()
	}
	return s, err
}

// openStreamWith is openStream with explicit subscription parameters.
func openStreamWith(ctx context.Context, e *env, c *opcua.Client, name string, bufSize int, params *opcua.SubscriptionParameters, counters ...int) (*stream, error) {
	s := &stream{
		name:     name,
		e:        e,
		ch:       make(chan *opcua.PublishNotificationData, bufSize),
		last:     make(map[uint32]int64),
		seq:      make(map[uint32][]int64),
		ordered:  true,
		counters: counters,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go s.consume()

	sub, err := c.Subscribe(ctx, params, s.ch)
	if err != nil {
		s.close()
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	s.sub = sub

	reqs := make([]*ua.MonitoredItemCreateRequest, len(counters))
	for i, ci := range counters {
		r := opcua.NewMonitoredItemCreateRequestWithDefaults(e.counterID(ci), ua.AttributeIDValue, uint32(ci))
		r.RequestedParameters.QueueSize = 100
		reqs[i] = r
	}
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, reqs...)
	if err == nil {
		for _, r := range res.Results {
			if r.StatusCode != ua.StatusOK {
				err = r.StatusCode
				break
			}
		}
	}
	if err != nil {
		_ = sub.Cancel(ctx)
		s.close()
		return nil, fmt.Errorf("monitor: %w", err)
	}
	return s, nil
}

func (s *stream) consume() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		case n := <-s.ch:
			s.handle(n)
		}
	}
}

func (s *stream) handle(n *opcua.PublishNotificationData) {
	if n.Error != nil {
		s.errs.Add(n.Error)
		if !isFaultError(n.Error) {
			s.problem("unexpected error notification: %v", n.Error)
		}
		return
	}
	dcn, ok := n.Value.(*ua.DataChangeNotification)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, mi := range dcn.MonitoredItems {
		if mi == nil || mi.Value == nil || mi.Value.Value == nil {
			s.problems = append(s.problems, fmt.Sprintf("notification without value: %+v", mi))
			continue
		}
		v, ok := mi.Value.Value.Value().(int64)
		if !ok {
			s.problems = append(s.problems, fmt.Sprintf("notification with %T value, want int64", mi.Value.Value.Value()))
			continue
		}
		h := mi.ClientHandle
		if h >= numCounters || !s.e.validCounter(int(h), v) {
			s.problems = append(s.problems, fmt.Sprintf("FORGED: handle %d delivered %d, which the writer never produced (node is at %d)",
				h, v, s.e.counters[h%numCounters].Load()))
			continue
		}
		s.trail = append(s.trail, fmt.Sprintf("%s sub=%d h=%d v=%d", time.Now().Format("05.000"), n.SubscriptionID, h, v))
		if len(s.trail) > 60 {
			s.trail = s.trail[len(s.trail)-60:]
		}
		if last, seen := s.last[h]; s.ordered && seen && v < last && len(s.problems) < 20 {
			s.problems = append(s.problems, fmt.Sprintf("REORDERED: handle %d delivered %d after %d; most recent notifications (time, subscription id, handle, value):\n      %s",
				h, v, last, strings.Join(s.trail, "\n      ")))
		}
		s.last[h] = v
		if s.record {
			s.seq[h] = append(s.seq[h], v)
		}
		s.received.Add(1)
	}
}

func (s *stream) problem(format string, args ...any) {
	s.mu.Lock()
	if len(s.problems) < 20 {
		s.problems = append(s.problems, fmt.Sprintf(format, args...))
	}
	s.mu.Unlock()
}

// handles returns the client handles (counter indexes) of the stream.
func (s *stream) handles() []uint32 {
	out := make([]uint32, len(s.counters))
	for i, c := range s.counters {
		out[i] = uint32(c)
	}
	return out
}

// lastValue returns the last value delivered for the given counter.
func (s *stream) lastValue(counter int) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last[uint32(counter)]
}

// close stops the consumer. It must be called after the subscription was
// cancelled or the client was closed.
func (s *stream) close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
}

// report fails the test for every problem the consumer observed.
func (s *stream) report(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.problems {
		t.Errorf("stream %s: %s", s.name, p)
	}
}
