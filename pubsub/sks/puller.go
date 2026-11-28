// SPDX-License-Identifier: MIT

package sks

import (
	"context"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// DefaultPullInterval is how often a Puller reads the configuration of its
// runtime by default.
const DefaultPullInterval = time.Second

// PullerOptions configure a Puller.
type PullerOptions struct {
	// Dial opens a session with the SKS an element of SecurityKeyServices
	// describes, for one GetSecurityKeys call; the KeySource closes it
	// afterwards. Required; (*EndpointDialer).Dial is the usual one.
	Dial func(ctx context.Context, sks *ua.EndpointDescription) (*opcua.Client, error)
	// Interval is how often the configuration is read; 0 is
	// DefaultPullInterval.
	Interval time.Duration
	// Source is the Config of the KeySources the Puller starts; its
	// SecurityGroupID, Client and Dial are set by the Puller. Its
	// MinRetry and MaxRetry also bound the retries of the first fetch.
	Source Config
	// OnError, if set, is called with the error of a first fetch that
	// failed on every SKS of a SecurityGroup (before the retry) and,
	// through Source.OnError when that is not set, with the errors of
	// the background refreshes. It must not block.
	OnError func(securityGroupID string, err error)
}

// Puller supplies the keys of the secured groups of a PubSub runtime that
// pull them from an SKS (Part 14 §5.4.5.3, Figure 11): for every
// SecurityGroupId of a WriterGroup, ReaderGroup or DataSetReader with
// SecurityMode Sign or SignAndEncrypt whose SecurityKeyServices name an SKS
// with ApplicationType SERVER (the pull model, §6.2.5.4 Table 40), and
// whose keys the runtime has from no other source, it starts a KeySource
// on the first SKS that answers and sets it in the runtime
// (PubSub.SetKeySource). A first fetch that fails on every SKS is tried
// again with backoff (OPC 10000-81 E.5: the AutomationComponent retries
// with vendor-specific logic); until then the groups have no keys, which
// leaves them without secured messages (§5.4.5.3: PreOperational). When
// the configuration no longer has the SecurityGroupId, the Puller removes
// its KeySource from the runtime and closes it. A KeySource it set stays
// with the SKS it was started on while the group is configured.
type Puller struct {
	rt   *pubsub.PubSub
	opts PullerOptions

	mu      sync.Mutex
	closed  bool
	sources map[string]*KeySource
	pending map[string]context.CancelFunc

	wg   sync.WaitGroup
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// NewPuller starts a Puller on rt. It reads the configuration at once and
// then every Interval; Close stops it.
func NewPuller(rt *pubsub.PubSub, opts PullerOptions) (*Puller, error) {
	if rt == nil {
		return nil, errors.New("pubsub/sks: Puller needs a runtime")
	}
	if opts.Dial == nil {
		return nil, errors.New("pubsub/sks: Puller needs a Dial")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultPullInterval
	}
	if opts.Source.MinRetry <= 0 {
		opts.Source.MinRetry = DefaultMinRetry
	}
	if opts.Source.MaxRetry < opts.Source.MinRetry {
		opts.Source.MaxRetry = max(DefaultMaxRetry, opts.Source.MinRetry)
	}
	p := &Puller{rt: rt, opts: opts, sources: map[string]*KeySource{}, pending: map[string]context.CancelFunc{},
		stop: make(chan struct{}), done: make(chan struct{})}
	p.Sync()
	go p.run()
	return p, nil
}

func (p *Puller) run() {
	defer close(p.done)
	t := time.NewTicker(p.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.Sync()
		}
	}
}

// Sync reads the configuration of the runtime now: it starts the fetches
// of the SecurityGroups that need keys and drops the KeySources of those
// that are gone.
func (p *Puller) Sync() {
	want := pullGroups(p.rt.Configuration())
	var drop []*KeySource
	p.mu.Lock()
	defer func() {
		p.mu.Unlock()
		for _, ks := range drop {
			_ = ks.Close()
		}
	}()
	if p.closed {
		return
	}
	for g, ks := range p.sources {
		if _, ok := want[g]; !ok {
			delete(p.sources, g)
			p.rt.SetKeySource(g, nil)
			drop = append(drop, ks)
		}
	}
	for g, cancel := range p.pending {
		if _, ok := want[g]; !ok {
			delete(p.pending, g)
			cancel()
		}
	}
	for g, eps := range want {
		if p.sources[g] != nil || p.pending[g] != nil || p.rt.KeySource(g) != nil {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		p.pending[g] = cancel
		p.wg.Add(1)
		go p.fetch(ctx, g, eps)
	}
}

// fetch starts the KeySource of the SecurityGroup g on the first of eps
// that answers, and tries again with backoff until one does or ctx ends.
func (p *Puller) fetch(ctx context.Context, g string, eps []*ua.EndpointDescription) {
	defer p.wg.Done()
	wait := p.opts.Source.MinRetry
	for {
		var errs []error
		for _, ep := range eps {
			cfg := p.opts.Source
			cfg.SecurityGroupID, cfg.Client = g, nil
			cfg.Dial = func(ctx context.Context) (*opcua.Client, error) { return p.opts.Dial(ctx, ep) }
			if cfg.OnError == nil && p.opts.OnError != nil {
				cfg.OnError = func(err error) { p.opts.OnError(g, err) }
			}
			ks, err := NewKeySource(ctx, cfg)
			if err == nil {
				p.install(ctx, g, ks)
				return
			}
			errs = append(errs, err)
		}
		if ctx.Err() != nil {
			return
		}
		if p.opts.OnError != nil {
			p.opts.OnError(g, errors.Join(errs...))
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		wait = min(wait*2, p.opts.Source.MaxRetry)
	}
}

// install sets ks as the KeySource of g, unless the fetch was cancelled
// meanwhile.
func (p *Puller) install(ctx context.Context, g string, ks *KeySource) {
	p.mu.Lock()
	if p.closed || ctx.Err() != nil {
		p.mu.Unlock()
		_ = ks.Close()
		return
	}
	delete(p.pending, g)
	p.sources[g] = ks
	p.rt.SetKeySource(g, ks)
	p.mu.Unlock()
}

// SecurityGroups returns the SecurityGroupIds the Puller supplies keys
// for, sorted.
func (p *Puller) SecurityGroups() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.sources))
	for g := range p.sources {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// Close stops the Puller: the fetches in progress are cancelled, and the
// KeySources it set are removed from the runtime and closed.
func (p *Puller) Close() error {
	p.once.Do(func() {
		close(p.stop)
		<-p.done
		p.mu.Lock()
		p.closed = true
		for _, cancel := range p.pending {
			cancel()
		}
		p.pending = nil
		sources := p.sources
		p.sources = nil
		for g := range sources {
			p.rt.SetKeySource(g, nil)
		}
		p.mu.Unlock()
		p.wg.Wait()
		for _, ks := range sources {
			_ = ks.Close()
		}
	})
	return nil
}

// pullGroups returns, by SecurityGroupId, the SKS endpoints of the pull
// model (ApplicationType SERVER, Part 14 §6.2.5.4 Table 40) of the secured
// groups and DataSetReaders of cfg, in the order of the configuration. A
// DataSetReader without SecurityKeyServices of its own takes those of its
// ReaderGroup.
func pullGroups(cfg *ua.PubSubConfigurationDataType) map[string][]*ua.EndpointDescription {
	out := map[string][]*ua.EndpointDescription{}
	add := func(mode ua.MessageSecurityMode, g string, eps []*ua.EndpointDescription) {
		if g == "" || mode != ua.MessageSecurityModeSign && mode != ua.MessageSecurityModeSignAndEncrypt {
			return
		}
		for _, ep := range eps {
			if ep == nil || ep.Server == nil || ep.Server.ApplicationType != ua.ApplicationTypeServer {
				continue
			}
			if !slices.ContainsFunc(out[g], func(e *ua.EndpointDescription) bool { return sameEndpoint(e, ep) }) {
				out[g] = append(out[g], ep)
			}
		}
	}
	if cfg == nil {
		return out
	}
	for _, c := range cfg.Connections {
		if c == nil {
			continue
		}
		for _, wg := range c.WriterGroups {
			if wg != nil {
				add(wg.SecurityMode, wg.SecurityGroupID, wg.SecurityKeyServices)
			}
		}
		for _, rg := range c.ReaderGroups {
			if rg == nil {
				continue
			}
			add(rg.SecurityMode, rg.SecurityGroupID, rg.SecurityKeyServices)
			for _, r := range rg.DataSetReaders {
				if r == nil {
					continue
				}
				eps := r.SecurityKeyServices
				if len(eps) == 0 {
					eps = rg.SecurityKeyServices
				}
				add(r.SecurityMode, r.SecurityGroupID, eps)
			}
		}
	}
	return out
}

// sameEndpoint reports whether a and b name the same SKS endpoint.
func sameEndpoint(a, b *ua.EndpointDescription) bool {
	return a.Server.ApplicationURI == b.Server.ApplicationURI && a.SecurityPolicyURI == b.SecurityPolicyURI &&
		a.EndpointURL == b.EndpointURL && slices.Equal(a.Server.DiscoveryURLs, b.Server.DiscoveryURLs)
}
