// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
)

const defaultRetryInterval = 5 * time.Second

// PubSub is a PubSub runtime: the publishers and subscribers of one
// configuration. Create it with [New] and run it with [PubSub.Start].
//
// All methods are safe for concurrent use.
type PubSub struct {
	opts   options
	log    *slog.Logger
	codecs func(encoding) codec

	ksMu       sync.RWMutex
	keySources map[string]security.KeySource

	mu sync.Mutex
	// pending are the callbacks (events, handlers, target writes, event
	// subscriptions) collected under mu; unlock runs them after releasing
	// it, in order.
	pending []func()
	enabled bool
	running bool
	closed  bool
	root    base
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	nextID  ComponentID
	conns   []*connection
	pdss    []*publishedDataSet
	comps   map[ComponentID]component
}

// component is implemented by all components.
type component interface {
	b() *base
}

// base is the part every component shares. It is guarded by PubSub.mu.
type base struct {
	id      ComponentID
	kind    ComponentKind
	name    string
	parent  ComponentID
	enabled bool
	state   ua.PubSubState
	err     error
	ctr     Counters
}

func (b *base) b() *base { return b }

func (b *base) info() ComponentInfo {
	return ComponentInfo{ID: b.id, Kind: b.kind, Name: b.name, Parent: b.parent, Enabled: b.enabled, State: b.state}
}

// New creates a runtime for a configuration. cfg may be nil for an empty,
// enabled runtime to which components are added later. The configuration is
// copied; later changes to cfg have no effect.
func New(cfg *ua.PubSubConfigurationDataType, opts ...Option) (*PubSub, error) {
	if cfg == nil {
		cfg = &ua.PubSubConfigurationDataType{Enabled: true}
	}
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	p := &PubSub{
		comps:      map[ComponentID]component{},
		keySources: map[string]security.KeySource{},
	}
	for _, o := range opts {
		o(&p.opts)
	}
	p.log = p.opts.logger
	if p.log == nil {
		p.log = slog.New(slog.DiscardHandler)
	}
	p.codecs = p.opts.codecs
	if p.codecs == nil {
		p.codecs = defaultCodecs
	}
	if p.opts.retryInterval <= 0 {
		p.opts.retryInterval = defaultRetryInterval
	}
	for k, v := range p.opts.keySources {
		p.keySources[k] = v
	}
	p.root = base{id: Root, kind: KindPubSub, name: "PublishSubscribe", enabled: cfg.Enabled, state: ua.PubSubStateDisabled}
	p.enabled = cfg.Enabled

	p.lock()
	defer p.unlock()
	for _, pds := range cfg.PublishedDataSets {
		if _, err := p.addPublishedDataSetLocked(pds); err != nil {
			return nil, err
		}
	}
	for _, c := range cfg.Connections {
		if _, err := p.addConnectionLocked(c); err != nil {
			return nil, err
		}
	}
	p.reconcileLocked()
	return p, nil
}

// lock and unlock guard the runtime. unlock runs the callbacks collected
// while the lock was held.
func (p *PubSub) lock() { p.mu.Lock() }

func (p *PubSub) unlock() {
	fns := p.pending
	p.pending = nil
	p.mu.Unlock()
	for _, f := range fns {
		f()
	}
}

// later queues f to run after the lock is released.
func (p *PubSub) later(f func()) { p.pending = append(p.pending, f) }

func (p *PubSub) emit(ev Event) {
	if len(p.opts.eventHandlers) == 0 {
		return
	}
	hs := p.opts.eventHandlers
	p.later(func() {
		for _, h := range hs {
			h(ev)
		}
	})
}

func (p *PubSub) setState(b *base, s ua.PubSubState, err error) {
	if s == ua.PubSubStateError {
		b.err = err
	}
	if b.state == s {
		return
	}
	old := b.state
	b.state = s
	b.ctr.StateChanges++
	if s == ua.PubSubStateError {
		p.log.Warn("pubsub: state change", "kind", b.kind.String(), "name", b.name, "from", old.String(), "to", s.String(), "error", err)
	} else {
		p.log.Debug("pubsub: state change", "kind", b.kind.String(), "name", b.name, "from", old.String(), "to", s.String())
	}
	ev := Event{Type: EventStateChanged, Component: b.info(), OldState: old}
	if s == ua.PubSubStateError {
		ev.Err = err
	}
	p.emit(ev)
}

func (p *PubSub) newID() ComponentID {
	p.nextID++
	return p.nextID
}

// Start starts the runtime: connections open their transports, writer groups
// publish and readers subscribe. Cancelling ctx stops the runtime again (all
// components become Paused) until the next Start. Start on a running runtime
// does nothing; Start after Close returns [ErrClosed].
func (p *PubSub) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.lock()
	defer p.unlock()
	if p.closed {
		return ErrClosed
	}
	if p.running {
		return nil
	}
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.running = true
	runCtx := p.ctx
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		<-runCtx.Done()
		p.lock()
		defer p.unlock()
		if p.ctx == runCtx && p.running {
			p.running = false
			p.reconcileLocked()
		}
	}()
	p.reconcileLocked()
	return nil
}

// Close stops the runtime and waits for its goroutines. It closes all
// transports. Close is idempotent; the runtime cannot be started again.
func (p *PubSub) Close() error {
	p.lock()
	if p.closed {
		p.unlock()
		return nil
	}
	p.closed = true
	p.running = false
	p.reconcileLocked()
	if p.cancel != nil {
		p.cancel()
	}
	p.unlock()
	p.wg.Wait()
	return nil
}

// Running reports whether the runtime was started and is not stopped.
func (p *PubSub) Running() bool {
	p.lock()
	defer p.unlock()
	return p.running
}

// SetKeySource sets (or, with nil, removes) the keys of a SecurityGroup at
// run time, for example when a Security Key Service pushes new keys.
func (p *PubSub) SetKeySource(securityGroupID string, ks security.KeySource) {
	p.ksMu.Lock()
	if ks == nil {
		delete(p.keySources, securityGroupID)
	} else {
		p.keySources[securityGroupID] = ks
	}
	p.ksMu.Unlock()
}

// KeySource returns the keys of a SecurityGroup, nil if none are known.
func (p *PubSub) KeySource(securityGroupID string) security.KeySource {
	p.ksMu.RLock()
	ks := p.keySources[securityGroupID]
	p.ksMu.RUnlock()
	if ks != nil {
		return ks
	}
	for _, l := range p.opts.keyLookups {
		if ks := l(securityGroupID); ks != nil {
			return ks
		}
	}
	return nil
}

// reconcileLocked brings every component to the state its configuration and
// its parent call for, starting and stopping what has to run.
func (p *PubSub) reconcileLocked() {
	switch {
	case !p.enabled:
		p.setState(&p.root, ua.PubSubStateDisabled, nil)
	case !p.running:
		p.setState(&p.root, ua.PubSubStatePaused, nil)
	default:
		p.setState(&p.root, ua.PubSubStateOperational, nil)
	}
	op := p.root.state == ua.PubSubStateOperational
	for _, c := range p.conns {
		p.reconcileConnection(c, op)
	}
}

// Enable enables a component (or, with [Root], the runtime). Like the Enable
// method of the PubSubStatusType it fails with Bad_InvalidState if the
// component is not Disabled.
func (p *PubSub) Enable(id ComponentID) error { return p.setEnabled(id, true) }

// Disable disables a component (or, with [Root], the runtime). It fails with
// Bad_InvalidState if the component is already Disabled.
func (p *PubSub) Disable(id ComponentID) error { return p.setEnabled(id, false) }

func (p *PubSub) setEnabled(id ComponentID, on bool) error {
	p.lock()
	defer p.unlock()
	if p.closed {
		return ErrClosed
	}
	var b *base
	if id == Root {
		b = &p.root
	} else {
		c := p.comps[id]
		if c == nil {
			return fmt.Errorf("pubsub: no component with id %d: %w", id, ua.StatusBadNotFound)
		}
		b = c.b()
		if b.kind == KindPublishedDataSet {
			return fmt.Errorf("pubsub: a published data set has no state machine: %w", ua.StatusBadNotSupported)
		}
	}
	if b.enabled == on {
		if on {
			return fmt.Errorf("pubsub: %s %q is already enabled: %w", b.kind, b.name, ua.StatusBadInvalidState)
		}
		return fmt.Errorf("pubsub: %s %q is already disabled: %w", b.kind, b.name, ua.StatusBadInvalidState)
	}
	b.enabled = on
	if id == Root {
		p.enabled = on
	}
	p.reconcileLocked()
	return nil
}

// State returns the state of a component (or, with [Root], of the runtime).
func (p *PubSub) State(id ComponentID) (ua.PubSubState, error) {
	p.lock()
	defer p.unlock()
	if id == Root {
		return p.root.state, nil
	}
	c := p.comps[id]
	if c == nil {
		return ua.PubSubStateDisabled, fmt.Errorf("pubsub: no component with id %d: %w", id, ua.StatusBadNotFound)
	}
	return c.b().state, nil
}

// Status returns the state and the diagnostic counters of a component (or,
// with [Root], of the runtime). Counters are aggregated over the children.
func (p *PubSub) Status(id ComponentID) (Status, error) {
	p.lock()
	defer p.unlock()
	if id == Root {
		st := Status{ComponentInfo: p.root.info(), LastError: p.root.err}
		st.Counters = p.root.ctr
		for _, c := range p.conns {
			ctr := p.aggregate(c)
			st.Counters.add(&ctr)
		}
		return st, nil
	}
	c := p.comps[id]
	if c == nil {
		return Status{}, fmt.Errorf("pubsub: no component with id %d: %w", id, ua.StatusBadNotFound)
	}
	b := c.b()
	return Status{ComponentInfo: b.info(), LastError: b.err, Counters: p.aggregate(c)}, nil
}

func (p *PubSub) aggregate(c component) Counters {
	ctr := c.b().ctr
	switch x := c.(type) {
	case *connection:
		for _, g := range x.wgs {
			s := p.aggregate(g)
			ctr.add(&s)
		}
		for _, g := range x.rgs {
			s := p.aggregate(g)
			ctr.add(&s)
		}
	case *writerGroup:
		for _, w := range x.writers {
			ctr.add(&w.ctr)
		}
	case *readerGroup:
		for _, r := range x.readers {
			ctr.add(&r.ctr)
		}
	}
	return ctr
}

// Components lists the components of the runtime: connections, each followed
// by its writer groups with their writers and its reader groups with their
// readers, then the published data sets.
func (p *PubSub) Components() []ComponentInfo {
	p.lock()
	defer p.unlock()
	var out []ComponentInfo
	for _, c := range p.conns {
		out = append(out, c.info())
		for _, g := range c.wgs {
			out = append(out, g.info())
			for _, w := range g.writers {
				out = append(out, w.info())
			}
		}
		for _, g := range c.rgs {
			out = append(out, g.info())
			for _, r := range g.readers {
				out = append(out, r.info())
			}
		}
	}
	for _, d := range p.pdss {
		out = append(out, d.info())
	}
	return out
}

// Component returns the description of a component.
func (p *PubSub) Component(id ComponentID) (ComponentInfo, error) {
	p.lock()
	defer p.unlock()
	if id == Root {
		return p.root.info(), nil
	}
	c := p.comps[id]
	if c == nil {
		return ComponentInfo{}, fmt.Errorf("pubsub: no component with id %d: %w", id, ua.StatusBadNotFound)
	}
	return c.b().info(), nil
}

// Lookup returns the id of the component of the given kind and name below a
// parent ([Root] for connections and published data sets).
func (p *PubSub) Lookup(kind ComponentKind, parent ComponentID, name string) (ComponentID, bool) {
	p.lock()
	defer p.unlock()
	for id, c := range p.comps {
		b := c.b()
		if b.kind == kind && b.parent == parent && b.name == name {
			return id, true
		}
	}
	return 0, false
}

// Configuration returns the current configuration of the runtime, including
// the components added at run time and the DataSetMetaData readers learned
// from metadata messages.
func (p *PubSub) Configuration() *ua.PubSubConfigurationDataType {
	p.lock()
	defer p.unlock()
	cfg := &ua.PubSubConfigurationDataType{Enabled: p.enabled}
	for _, d := range p.pdss {
		cfg.PublishedDataSets = append(cfg.PublishedDataSets, d.config())
	}
	for _, c := range p.conns {
		cfg.Connections = append(cfg.Connections, c.config())
	}
	return cfg
}
