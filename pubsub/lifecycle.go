// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"maps"
	"time"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
)

func newGUID() *ua.GUID { return ua.NewGUID(uuid.NewString()) }

// reconcileConnection runs or stops a connection and its groups. parentOp
// tells whether the runtime is Operational.
func (p *PubSub) reconcileConnection(c *connection, parentOp bool) {
	switch {
	case !c.enabled:
		p.stopConnection(c)
		p.setState(&c.base, ua.PubSubStateDisabled, nil)
	case !parentOp:
		p.stopConnection(c)
		p.setState(&c.base, ua.PubSubStatePaused, nil)
	default:
		if c.cancel == nil {
			p.startConnection(c)
		}
	}
	op := c.state == ua.PubSubStateOperational
	for _, g := range c.wgs {
		p.reconcileWriterGroup(g, op)
	}
	for _, g := range c.rgs {
		p.reconcileReaderGroup(g, op)
	}
	if c.cancel != nil {
		want := p.wantTopics(c)
		if !maps.Equal(want, c.topics) {
			c.topics = want
			select {
			case c.kick <- struct{}{}:
			default:
			}
		}
	}
}

// wantTopics returns the subscriptions a connection needs: for a datagram
// transport the address (topic ""), for a broker the queues of the running
// readers, with their QoS.
func (p *PubSub) wantTopics(c *connection) map[string]byte {
	want := map[string]byte{}
	for _, g := range c.rgs {
		for _, r := range g.readers {
			if !r.running {
				continue
			}
			if !c.broker {
				want[""] = 0
				continue
			}
			if r.brokerTS == nil {
				continue
			}
			if r.brokerTS.QueueName != "" {
				q := qosOf(r.brokerTS.RequestedDeliveryGuarantee, 0)
				if q > want[r.brokerTS.QueueName] {
					want[r.brokerTS.QueueName] = q
				} else if _, ok := want[r.brokerTS.QueueName]; !ok {
					want[r.brokerTS.QueueName] = q
				}
			}
			if r.brokerTS.MetaDataQueueName != "" {
				if _, ok := want[r.brokerTS.MetaDataQueueName]; !ok {
					want[r.brokerTS.MetaDataQueueName] = 1
				}
			}
		}
	}
	return want
}

func (p *PubSub) startConnection(c *connection) {
	c.gen++
	ctx, cancel := context.WithCancel(p.ctx)
	c.cancel = cancel
	c.kick = make(chan struct{}, 1)
	c.topics = nil
	p.setState(&c.base, ua.PubSubStatePreOperational, nil)
	gen, kick := c.gen, c.kick
	p.wg.Add(1)
	go p.runConnection(ctx, c, gen, kick)
}

func (p *PubSub) stopConnection(c *connection) {
	if c.cancel == nil {
		return
	}
	c.cancel()
	c.cancel = nil
	c.tc = nil
	c.topics = nil
	c.gen++
}

// transportConfig builds the transport configuration of a connection.
func (p *PubSub) transportConfig(c *connection) transport.Config {
	cfg := transport.Config{
		ProfileURI: c.cfg.TransportProfileURI,
		URL:        c.url,
		Interface:  c.iface,
		ClientID:   c.name,
		Logger:     p.log,
	}
	if len(c.cfg.ConnectionProperties) > 0 {
		cfg.Properties = map[string]string{}
		for _, kv := range c.cfg.ConnectionProperties {
			if kv == nil || kv.Key == nil {
				continue
			}
			if s, ok := variantValue(kv.Value).(string); ok {
				cfg.Properties[kv.Key.Name] = s
			}
		}
	}
	for _, f := range p.opts.transportConfig {
		f(c.cfg, &cfg)
	}
	return cfg
}

// runConnection opens the transport of a connection, retrying while it
// fails, and then keeps its subscriptions in line with the running readers
// until ctx ends.
func (p *PubSub) runConnection(ctx context.Context, c *connection, gen uint64, kick chan struct{}) {
	defer p.wg.Done()
	p.lock()
	tcfg := p.transportConfig(c)
	p.unlock()

	var tc transport.Connection
	for {
		var err error
		tc, err = transport.Open(ctx, tcfg)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		p.lock()
		if c.gen == gen {
			p.setState(&c.base, ua.PubSubStateError, err)
			p.reconcileLocked()
		}
		p.unlock()
		t := time.NewTimer(p.opts.retryInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	defer func() { _ = tc.Close() }()

	p.lock()
	if c.gen != gen {
		p.unlock()
		return
	}
	c.tc = tc
	p.setState(&c.base, ua.PubSubStateOperational, nil)
	p.reconcileLocked()
	p.unlock()

	subs := map[string]func() error{}
	defer func() {
		for _, cancel := range subs {
			_ = cancel()
		}
	}()
	var retry *time.Timer
	defer func() {
		if retry != nil {
			retry.Stop()
		}
	}()
	sync := func() {
		p.lock()
		if c.gen != gen {
			p.unlock()
			return
		}
		want := maps.Clone(c.topics)
		p.unlock()
		for topic, cancel := range subs {
			if _, ok := want[topic]; !ok {
				_ = cancel()
				delete(subs, topic)
			}
		}
		failed := false
		for topic, qos := range want {
			if _, ok := subs[topic]; ok {
				continue
			}
			topic := topic
			cancel, err := tc.Subscribe(ctx, topic, qos, func(m *transport.Message) {
				p.receive(c, gen, m)
			})
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				failed = true
				p.log.Warn("pubsub: subscribe failed", "connection", c.name, "topic", topic, "error", err)
				p.lock()
				c.err = err
				p.unlock()
				continue
			}
			subs[topic] = cancel
		}
		if failed && retry == nil {
			retry = time.AfterFunc(p.opts.retryInterval, func() {
				select {
				case kick <- struct{}{}:
				default:
				}
			})
		} else if failed {
			retry.Reset(p.opts.retryInterval)
		}
	}
	sync()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			sync()
		}
	}
}

// reconcileWriterGroup runs or stops a writer group and its writers.
func (p *PubSub) reconcileWriterGroup(g *writerGroup, parentOp bool) {
	switch {
	case !g.enabled:
		p.stopWriterGroup(g)
		p.setState(&g.base, ua.PubSubStateDisabled, nil)
	case !parentOp:
		p.stopWriterGroup(g)
		p.setState(&g.base, ua.PubSubStatePaused, nil)
	default:
		if g.cancel == nil {
			p.startWriterGroup(g)
		}
		if g.mode > ua.MessageSecurityModeNone && !g.keysOK {
			p.setState(&g.base, ua.PubSubStatePreOperational, nil)
		} else {
			p.setState(&g.base, ua.PubSubStateOperational, nil)
		}
	}
	op := g.state == ua.PubSubStateOperational
	for _, w := range g.writers {
		p.reconcileWriter(w, op)
	}
}

func (p *PubSub) startWriterGroup(g *writerGroup) {
	g.gen++
	g.keysOK = false
	ctx, cancel := context.WithCancel(p.ctx)
	g.cancel = cancel
	gen := g.gen
	p.wg.Add(1)
	go p.runWriterGroup(ctx, g, gen)
}

func (p *PubSub) stopWriterGroup(g *writerGroup) {
	if g.cancel == nil {
		return
	}
	g.cancel()
	g.cancel = nil
	g.gen++
	g.keysOK = false
}

// reconcileWriter runs or stops a DataSetWriter.
func (p *PubSub) reconcileWriter(w *dataSetWriter, parentOp bool) {
	switch {
	case !w.enabled:
		p.stopWriter(w)
		p.setState(&w.base, ua.PubSubStateDisabled, nil)
	case !parentOp:
		p.stopWriter(w)
		p.setState(&w.base, ua.PubSubStatePaused, nil)
	case w.cfg.DataSetName != "" && (w.pds == nil || p.comps[w.pds.id] == nil):
		p.stopWriter(w)
		p.setState(&w.base, ua.PubSubStateError, notFound(KindPublishedDataSet, 0))
	default:
		if !w.running {
			p.startWriter(w)
		}
		p.setState(&w.base, ua.PubSubStateOperational, nil)
	}
}

func (p *PubSub) startWriter(w *dataSetWriter) {
	w.running = true
	w.needKey = true
	w.sinceKey = 0
	w.last = nil
	w.lastSent = time.Time{}
	w.metaPending = w.brokerTS != nil && w.brokerTS.MetaDataQueueName != ""
	w.events = nil
	if w.pds == nil || w.pds.events == nil {
		return
	}
	es := p.opts.eventSource
	if es == nil {
		p.log.Warn("pubsub: writer publishes events but there is no event source", "writer", w.name)
		return
	}
	w.evGen++
	gen := w.evGen
	events := w.pds.events
	ctx := p.ctx
	p.later(func() {
		cancel, err := es.SubscribeEvents(ctx, events, func(fields []*ua.Variant) {
			p.lock()
			defer p.unlock()
			if w.evGen != gen || !w.running {
				return
			}
			if len(w.events) >= maxQueuedEvents {
				w.events = w.events[1:]
			}
			w.events = append(w.events, fields)
		})
		p.lock()
		defer p.unlock()
		if err != nil {
			if w.evGen == gen && w.running {
				p.setState(&w.base, ua.PubSubStateError, err)
			}
			return
		}
		if w.evGen != gen || !w.running {
			p.later(cancel)
			return
		}
		w.evCancel = cancel
	})
}

const maxQueuedEvents = 1000

func (p *PubSub) stopWriter(w *dataSetWriter) {
	if !w.running {
		return
	}
	w.running = false
	w.evGen++
	w.events = nil
	if w.evCancel != nil {
		p.later(w.evCancel)
		w.evCancel = nil
	}
}

// reconcileReaderGroup runs or stops a reader group and its readers.
func (p *PubSub) reconcileReaderGroup(g *readerGroup, parentOp bool) {
	switch {
	case !g.enabled:
		p.setState(&g.base, ua.PubSubStateDisabled, nil)
	case !parentOp:
		p.setState(&g.base, ua.PubSubStatePaused, nil)
	default:
		p.setState(&g.base, ua.PubSubStateOperational, nil)
	}
	op := g.state == ua.PubSubStateOperational
	for _, r := range g.readers {
		p.reconcileReader(r, op)
	}
}

// reconcileReader runs or stops a DataSetReader. A running reader stays in
// its state (PreOperational until the first message, Operational, Error
// after a MessageReceiveTimeout).
func (p *PubSub) reconcileReader(r *dataSetReader, parentOp bool) {
	switch {
	case !r.enabled:
		p.stopReader(r, true)
		p.setState(&r.base, ua.PubSubStateDisabled, nil)
	case !parentOp:
		p.stopReader(r, true)
		p.setState(&r.base, ua.PubSubStatePaused, nil)
	default:
		if !r.running {
			p.startReader(r)
		}
	}
}

func (p *PubSub) startReader(r *dataSetReader) {
	r.running = true
	r.streams = map[streamKey]*stream{}
	r.lastRecv = time.Now()
	p.setState(&r.base, ua.PubSubStatePreOperational, nil)
	p.armTimer(r)
}

// stopReader stops a reader. override applies the OverrideValueHandling of
// the target variables of a reader that was Operational.
func (p *PubSub) stopReader(r *dataSetReader, override bool) {
	if !r.running {
		return
	}
	r.running = false
	if r.timer != nil {
		r.timer.t.Stop()
		r.timer = nil
	}
	if override && r.state == ua.PubSubStateOperational {
		p.applyOverrides(r)
	}
}

// armTimer starts the MessageReceiveTimeout of a reader.
func (p *PubSub) armTimer(r *dataSetReader) {
	if r.timeout <= 0 {
		return
	}
	if r.timer != nil {
		return
	}
	ref := &timerRef{}
	ref.t = time.AfterFunc(r.timeout, func() { p.readerTimeout(r, ref) })
	r.timer = ref
}

// timerRef identifies an armed MessageReceiveTimeout. Its timer is only read
// under PubSub.mu, after AfterFunc returned.
type timerRef struct{ t *time.Timer }

// readerTimeout handles the expiry of the MessageReceiveTimeout of a reader.
func (p *PubSub) readerTimeout(r *dataSetReader, ref *timerRef) {
	p.lock()
	defer p.unlock()
	if r.timer != ref || !r.running {
		return
	}
	if rest := r.timeout - time.Since(r.lastRecv); rest > 0 {
		ref.t.Reset(rest)
		return
	}
	r.timer = nil
	if r.state != ua.PubSubStateOperational && r.state != ua.PubSubStatePreOperational {
		return
	}
	r.ctr.Timeouts++
	wasOp := r.state == ua.PubSubStateOperational
	p.setState(&r.base, ua.PubSubStateError, ua.StatusBadTimeout)
	if wasOp {
		p.applyOverrides(r)
	}
}
