// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// UADP discovery of datagram connections (Part 14 §7.2.4.6.12).
//
// A publisher listens for probes on its connection address when it is a
// multicast group (a unicast address belongs to the subscriber) and on the
// DiscoveryAddress of the connection, if configured. It answers the
// DataSetMetaData and DataSetWriter configuration probes on the connection
// address, where the subscribers of its messages listen, and the other
// probes on the DiscoveryAddress (as the .NET stack does). Answers are
// secured like the messages of the writer group they describe.
//
// The traffic reduction of §7.2.4.6.12.2 bounds what probes can make a
// publisher send: the same announcement at most every MinInterval, all
// announcements together at most Rate per second (bursts of Burst).
//
// A subscriber probes for the DataSetMetaData of a reader that has none, or
// that received a DataSetMessage of another MajorVersion: after a random
// delay of 100 to 500 ms, skipped while another subscriber's probe for it
// is recent, and repeated at an interval that doubles from MinInterval up
// to MaxProbeInterval until the announcement arrives.

// Defaults of DiscoveryOptions.
const (
	defaultDiscoveryMinInterval = 500 * time.Millisecond
	defaultDiscoveryRate        = 20
	defaultDiscoveryBurst       = 20
	defaultMaxProbeInterval     = 8 * time.Second
)

// First probe delay of a subscriber (§7.2.4.6.12.2: a random delay between
// 100 and 500 ms, so that the subscribers started together do not all
// probe).
const (
	probeDelayMin = 100 * time.Millisecond
	probeDelayMax = 500 * time.Millisecond
)

// maxLimiterKeys bounds the announcement times a limiter keeps.
const maxLimiterKeys = 4096

func (o DiscoveryOptions) normalized() DiscoveryOptions {
	if o.MinInterval <= 0 {
		o.MinInterval = defaultDiscoveryMinInterval
	}
	if o.Rate <= 0 {
		o.Rate = defaultDiscoveryRate
	}
	if o.Burst <= 0 {
		o.Burst = defaultDiscoveryBurst
	}
	if o.MaxProbeInterval <= 0 {
		o.MaxProbeInterval = defaultMaxProbeInterval
	}
	o.MaxProbeInterval = max(o.MaxProbeInterval, o.MinInterval)
	return o
}

func firstProbeDelay() time.Duration {
	return probeDelayMin + rand.N(probeDelayMax-probeDelayMin)
}

// discoveryKey identifies an announcement for the limiter: what it carries
// and in which layout. info 0 is the ApplicationInformation.
type discoveryKey struct {
	info   message.InformationType
	id     uint16
	layout message.DiscoveryLayout
}

// discoveryLimiter bounds the announcements a connection sends in answer to
// probes: the same announcement at most every MinInterval, all of them by
// a token bucket.
type discoveryLimiter struct {
	mu     sync.Mutex
	last   map[discoveryKey]time.Time
	tokens float64
	at     time.Time
}

func newDiscoveryLimiter() *discoveryLimiter {
	return &discoveryLimiter{last: map[discoveryKey]time.Time{}}
}

// allow tells whether an announcement may be sent now and records it.
func (l *discoveryLimiter) allow(k discoveryKey, now time.Time, o *DiscoveryOptions) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[k]; ok && now.Sub(t) < o.MinInterval && now.Sub(t) > -o.MinInterval {
		return false
	}
	if l.at.IsZero() || now.Before(l.at) {
		l.tokens = float64(o.Burst)
	} else {
		l.tokens = min(float64(o.Burst), l.tokens+now.Sub(l.at).Seconds()*o.Rate)
	}
	l.at = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	if len(l.last) >= maxLimiterKeys {
		for k, t := range l.last {
			if now.Sub(t) >= o.MinInterval {
				delete(l.last, k)
			}
		}
		if len(l.last) >= maxLimiterKeys {
			clear(l.last)
		}
	}
	l.last[k] = now
	return true
}

// listensForProbes tells whether a connection subscribes to its own
// address for discovery probes: a running UADP writer group on a shared
// datagram address. p.mu is held.
func (p *PubSub) listensForProbes(c *connection) bool {
	if p.opts.discovery.Disabled || c.broker || !c.shared {
		return false
	}
	for _, g := range c.wgs {
		if g.enc == encUADP && g.cancel != nil {
			return true
		}
	}
	return false
}

// discoveryChannel is where a connection sends probes and the announcements
// that are not for the subscribers of its messages: the DiscoveryAddress or
// a shared connection address. p.mu is held.
func (p *PubSub) discoveryChannel(c *connection) transport.Connection {
	if c.dtc != nil {
		return c.dtc
	}
	if c.shared {
		return c.tc
	}
	return nil
}

// announceRate is the interval of the cyclic DataSetMetaData announcements
// of a writer group: its DiscoveryAnnounceRate or the one of its
// connection. p.mu is held.
func (p *PubSub) announceRate(g *writerGroup) time.Duration {
	if p.opts.discovery.Disabled || g.conn.broker || g.enc != encUADP {
		return 0
	}
	if g.announce > 0 {
		return g.announce
	}
	return g.conn.disc.announce
}

// discoveryMaxSize is the size above which announcements are chunked.
func discoveryMaxSize(c *connection, tc transport.Connection) int {
	if c.disc.maxSize > 0 {
		return c.disc.maxSize
	}
	return tc.MaxMessageSize()
}

// openDiscovery opens the DiscoveryAddress of a connection, subscribing to
// it when the connection publishes or the address is shared. The returned
// function closes it.
func (p *PubSub) openDiscovery(ctx context.Context, c *connection, gen uint64, tcfg transport.Config) (transport.Connection, func()) {
	p.lock()
	url, iface := c.disc.url, c.disc.iface
	listen := sharedAddress(url) || len(c.wgs) > 0
	p.unlock()
	if url == "" || c.broker || p.opts.discovery.Disabled {
		return nil, func() {}
	}
	cfg := tcfg
	cfg.URL, cfg.ListenAddress = url, ""
	if iface != "" {
		cfg.Interface = iface
	}
	octx, cancel := context.WithTimeout(ctx, openTimeout)
	dtc, err := transport.Open(octx, cfg)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			p.log.Warn("pubsub: discovery address failed", "connection", c.name, "address", url, "error", err)
			p.lock()
			if c.gen == gen {
				c.err = err
			}
			p.unlock()
		}
		return nil, func() {}
	}
	stop := func() { _ = dtc.Close() }
	if listen {
		unsub, err := dtc.Subscribe(ctx, "", 0, func(m *transport.Message) { p.receive(c, gen, m) })
		if err != nil {
			p.log.Warn("pubsub: discovery address subscribe failed", "connection", c.name, "address", url, "error", err)
		} else {
			stop = func() {
				_ = unsub()
				_ = dtc.Close()
			}
		}
	}
	return dtc, stop
}

// announcement is an answer to a probe, ready to be encoded.
type announcement struct {
	nm *message.NetworkMessage
	// g is the writer group whose security applies, nil: unsecured.
	g  *writerGroup
	tc transport.Connection
}

// handleProbe answers a discovery probe received on a connection.
func (p *PubSub) handleProbe(c *connection, gen uint64, payload []byte) {
	o := &p.opts.discovery
	p.lock()
	if c.gen != gen {
		p.unlock()
		return
	}
	c.ctr.DiscoveryRequestsReceived++
	// A secured probe is verified with the keys of the first secured
	// writer group.
	var groupID string
	for _, g := range c.wgs {
		if g.mode > ua.MessageSecurityModeNone {
			groupID = g.cfg.SecurityGroupID
			break
		}
	}
	p.unlock()
	opts := &decodeOptions{}
	if groupID != "" {
		keys := p.KeySource(groupID)
		opts.Security = func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
			return ua.MessageSecurityModeNone, keys, nil
		}
	}
	var nm *message.NetworkMessage
	var err error
	if p.protect("decode", func() { nm, err = p.codecs(encUADP).Decode(payload, opts) }) {
		err = errDecodePanic
	}
	if err == nil && nm.Request == nil {
		err = uadp.ErrMalformed
	}
	if err != nil {
		p.decodeFailed(c, gen, nil, nil, err)
		return
	}
	req := nm.Request
	now := time.Now()

	p.lock()
	if c.gen != gen {
		p.unlock()
		return
	}
	p.markProbeSeen(c, nm, now)
	// A probe in the spec layout names the publisher it is for; the .NET
	// stack puts the PublisherId of the subscriber there instead.
	forUs := !o.Disabled && c.hasPub &&
		(req.Layout == message.DiscoveryLayoutDotNet || nm.UADPMask&ua.UADPNetworkMessageContentMaskPublisherID == 0 || samePublisher(nm.PublisherID, c.pubID))
	var answers []announcement
	if forUs {
		answers = p.answersLocked(c, req, now)
	}
	if len(answers) == 0 {
		c.ctr.DiscoveryRequestsIgnored++
	}
	maxSize := 0
	if c.tc != nil {
		maxSize = discoveryMaxSize(c, c.tc)
	}
	p.unlock()

	var sent, chunks uint64
	for _, a := range answers {
		if n, ok := p.sendAnnouncement(a, maxSize); ok {
			sent++
			chunks += n
		}
	}
	p.lock()
	if c.gen == gen {
		c.ctr.DiscoveryResponsesSent += sent
		c.ctr.ChunksSent += chunks
	}
	p.unlock()
}

// markProbeSeen notes a probe for the DataSetMetaData of the readers of a
// connection: they wait for its announcement instead of probing themselves
// (§7.2.4.6.12.2). A reader's own probe, which comes back on a shared
// address, does not count. p.mu is held.
func (p *PubSub) markProbeSeen(c *connection, nm *message.NetworkMessage, now time.Time) {
	req := nm.Request
	if req.ProbeType != message.ProbePublisherInformation || req.InformationType != message.InformationDataSetMetaData {
		return
	}
	hasPub := req.Layout == message.DiscoveryLayoutSpec && nm.UADPMask&ua.UADPNetworkMessageContentMaskPublisherID != 0
	for _, g := range c.rgs {
		for _, r := range g.readers {
			if !r.running || !r.hasPub || (hasPub && !samePublisher(nm.PublisherID, r.pub)) {
				continue
			}
			if len(req.DataSetWriterIDs) > 0 && !slices.Contains(req.DataSetWriterIDs, r.cfg.DataSetWriterID) {
				continue
			}
			if now.Sub(r.probeSent) < p.opts.discovery.MinInterval {
				continue
			}
			r.probeSeen = now
		}
	}
}

// answersLocked builds the announcements that answer a probe, as far as the
// limiter allows. p.mu is held.
func (p *PubSub) answersLocked(c *connection, req *message.DiscoveryRequest, now time.Time) []announcement {
	o := &p.opts.discovery
	disc := p.discoveryChannel(c)
	var out []announcement
	add := func(k discoveryKey, d *message.Discovery, g *writerGroup, tc transport.Connection) {
		if tc == nil || !c.limiter.allow(k, now, o) {
			return
		}
		d.Layout = req.Layout
		d.SequenceNumber = uint16(c.annSeq.Add(1))
		nm := &message.NetworkMessage{
			Type:        message.NetworkMessageDiscoveryResponse,
			UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
			PublisherID: c.pubID,
			Discovery:   d,
		}
		out = append(out, announcement{nm: nm, g: g, tc: tc})
	}
	key := func(info message.InformationType, id uint16) discoveryKey {
		return discoveryKey{info: info, id: id, layout: req.Layout}
	}
	if req.ProbeType == message.ProbeFindApplications {
		add(key(0, 0), &message.Discovery{Type: message.DiscoveryApplicationInformation, Application: p.applicationInformation(now)}, nil, disc)
		return out
	}
	if req.ProbeType != message.ProbePublisherInformation {
		return nil
	}
	wanted := func(id uint16) bool {
		return len(req.DataSetWriterIDs) == 0 || slices.Contains(req.DataSetWriterIDs, id)
	}
	switch req.InformationType {
	case message.InformationPublisherEndpoints:
		d := &message.Discovery{Type: message.DiscoveryPublisherEndpoints, StatusCode: ua.StatusBadNotSupported}
		if o.Endpoints != nil {
			d.Endpoints, d.StatusCode = o.Endpoints(), ua.StatusGood
		}
		add(key(req.InformationType, 0), d, nil, disc)
	case message.InformationDataSetMetaData:
		for _, g := range c.wgs {
			if g.enc != encUADP || g.cancel == nil {
				continue
			}
			for _, w := range g.writers {
				if !w.running || w.pds == nil || w.pds.md == nil || !wanted(w.cfg.DataSetWriterID) {
					continue
				}
				add(key(req.InformationType, w.cfg.DataSetWriterID), &message.Discovery{
					Type:            message.DiscoveryDataSetMetaData,
					DataSetWriterID: w.cfg.DataSetWriterID,
					MetaData:        w.pds.md,
					StatusCode:      ua.StatusGood,
				}, g, c.tc)
			}
		}
	case message.InformationDataSetWriterConfig:
		for _, g := range c.wgs {
			if g.enc != encUADP || g.cancel == nil {
				continue
			}
			var ids []uint16
			for _, w := range g.writers {
				if wanted(w.cfg.DataSetWriterID) {
					ids = append(ids, w.cfg.DataSetWriterID)
				}
			}
			if len(ids) > 0 {
				add(key(req.InformationType, g.cfg.WriterGroupID), writerConfig(g, ids, true), g, c.tc)
			}
		}
	case message.InformationWriterGroupConfig:
		for _, g := range c.wgs {
			if g.enc != encUADP || g.cancel == nil || g.cfg.WriterGroupID != req.WriterGroupID {
				continue
			}
			var ids []uint16
			for _, w := range g.writers {
				ids = append(ids, w.cfg.DataSetWriterID)
			}
			add(key(req.InformationType, g.cfg.WriterGroupID), writerConfig(g, ids, req.IncludeDataSetWriters), g, c.tc)
		}
	case message.InformationPubSubConnections:
		if len(req.TransportProfileURIs) > 0 && !slices.Contains(req.TransportProfileURIs, c.cfg.TransportProfileURI) {
			return nil
		}
		add(key(req.InformationType, 0), &message.Discovery{
			Type:        message.DiscoveryPubSubConnection,
			Connections: []*ua.PubSubConnectionDataType{connectionConfig(c, req.IncludeWriterGroups, req.IncludeDataSetWriters)},
		}, nil, disc)
	}
	return out
}

// writerConfig is the DataSetWriter configuration announcement of the
// writers ids of a group (§7.2.4.6.8).
func writerConfig(g *writerGroup, ids []uint16, writers bool) *message.Discovery {
	cfg := publicGroup(g, ids, writers)
	d := &message.Discovery{Type: message.DiscoveryDataSetWriterConfig, DataSetWriterIDs: ids, WriterGroup: cfg}
	for range ids {
		d.StatusCodes = append(d.StatusCodes, ua.StatusGood)
	}
	return d
}

// publicGroup is the configuration of a writer group as announced: with the
// writers ids (if writers), without the properties and the key services.
func publicGroup(g *writerGroup, ids []uint16, writers bool) *ua.WriterGroupDataType {
	cfg := g.config()
	cfg.GroupProperties = nil
	cfg.SecurityKeyServices = nil
	var ws []*ua.DataSetWriterDataType
	if writers {
		for _, w := range cfg.DataSetWriters {
			if slices.Contains(ids, w.DataSetWriterID) {
				w.DataSetWriterProperties = nil
				ws = append(ws, w)
			}
		}
	}
	cfg.DataSetWriters = ws
	return cfg
}

// connectionConfig is the configuration of a connection as announced:
// without reader groups and properties, with the writer groups (and their
// writers) if asked for.
func connectionConfig(c *connection, groups, writers bool) *ua.PubSubConnectionDataType {
	cfg, _ := clone(c.cfg)
	cfg.Enabled = c.enabled
	cfg.ConnectionProperties = nil
	cfg.ReaderGroups = nil
	cfg.WriterGroups = nil
	if groups {
		for _, g := range c.wgs {
			var ids []uint16
			for _, w := range g.writers {
				ids = append(ids, w.cfg.DataSetWriterID)
			}
			cfg.WriterGroups = append(cfg.WriterGroups, publicGroup(g, ids, writers))
		}
	}
	return cfg
}

// applicationInformation answers a FindApplications probe: the
// ApplicationDescription of the options or, without, the status of the
// runtime (§7.2.4.6.10). p.mu is held.
func (p *PubSub) applicationInformation(now time.Time) *message.ApplicationInformation {
	if f := p.opts.discovery.Application; f != nil {
		if d := f(); d != nil {
			return &message.ApplicationInformation{Type: message.ApplicationInformationDescription, Description: d, Capabilities: p.opts.discovery.Capabilities}
		}
	}
	return &message.ApplicationInformation{Type: message.ApplicationInformationStatus, Status: p.root.state, Timestamp: now}
}

// sendAnnouncement encodes an announcement, secured like its writer group
// and chunked above maxSize, and sends it. It returns the number of chunks
// sent (0 for an unchunked message) and whether it was sent.
func (p *PubSub) sendAnnouncement(a announcement, maxSize int) (uint64, bool) {
	opts := &uadp.EncodeOptions{}
	if g := a.g; g != nil && g.mode > ua.MessageSecurityModeNone {
		ks := p.KeySource(g.cfg.SecurityGroupID)
		if ks == nil {
			return 0, false
		}
		opts.SecurityMode, opts.Keys, opts.NextNonceSequence = g.mode, ks, g.nextNonce
	}
	cd := p.codecs(encUADP)
	b, err := cd.Encode(a.nm, opts)
	parts := [][]byte{b}
	if err == nil && maxSize > 0 && len(b) > maxSize {
		parts, err = cd.EncodeChunks(a.nm, opts, maxSize)
	}
	if err != nil {
		p.log.Warn("pubsub: discovery announcement failed", "type", a.nm.Discovery.Type, "error", err)
		return 0, false
	}
	for _, b := range parts {
		if err := a.tc.Send(p.ctx, b, transport.PublishOptions{}); err != nil {
			return 0, false
		}
	}
	if len(parts) > 1 {
		return uint64(len(parts)), true
	}
	return 0, true
}

// wantsProbe tells whether a reader probes for its DataSetMetaData: a UADP
// reader of a datagram connection with a discovery channel, for a writer
// with PublisherId and DataSetWriterId, without DataSetMetaData or with a
// version mismatch. p.mu is held.
func (p *PubSub) wantsProbe(r *dataSetReader) bool {
	c := r.group.conn
	if p.opts.discovery.Disabled || !r.running || r.enc != encUADP || c.broker || !r.hasPub || r.cfg.DataSetWriterID == 0 {
		return false
	}
	if c.disc.url == "" && !c.shared {
		return false
	}
	return r.md == nil || len(r.md.Fields) == 0 || r.needMeta
}

// scheduleProbe arms the probe timer of a reader, unless it is armed.
// p.mu is held.
func (p *PubSub) scheduleProbe(r *dataSetReader, d time.Duration) {
	if r.probe != nil {
		return
	}
	ref := &timerRef{}
	ref.t = time.AfterFunc(d, func() { p.probeTimer(r, ref) })
	r.probe = ref
}

// nextProbeWait doubles the interval between the probes of a reader, from
// MinInterval up to MaxProbeInterval. p.mu is held.
func (p *PubSub) nextProbeWait(r *dataSetReader) time.Duration {
	o := &p.opts.discovery
	if r.probeWait == 0 {
		r.probeWait = o.MinInterval
	} else {
		r.probeWait = min(2*r.probeWait, o.MaxProbeInterval)
	}
	return r.probeWait
}

// probeTimer sends the probe of a reader and arms the next one.
func (p *PubSub) probeTimer(r *dataSetReader, ref *timerRef) {
	p.lock()
	if r.probe != ref {
		p.unlock()
		return
	}
	r.probe = nil
	if p.closed || !p.wantsProbe(r) {
		p.unlock()
		return
	}
	c := r.group.conn
	o := &p.opts.discovery
	ch := p.discoveryChannel(c)
	now := time.Now()
	if ch == nil || (!r.probeSeen.IsZero() && now.Sub(r.probeSeen) < o.MinInterval) {
		// Not open yet, or another subscriber asked: wait for the
		// announcement.
		p.scheduleProbe(r, p.nextProbeWait(r))
		p.unlock()
		return
	}
	nm := &message.NetworkMessage{
		Type:        message.NetworkMessageDiscoveryRequest,
		UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
		PublisherID: r.pub,
		Request: &message.DiscoveryRequest{
			ProbeType:        message.ProbePublisherInformation,
			InformationType:  message.InformationDataSetMetaData,
			DataSetWriterIDs: []uint16{r.cfg.DataSetWriterID},
			Layout:           o.Layout,
		},
	}
	r.probeSent = now
	p.scheduleProbe(r, p.nextProbeWait(r))
	c.ctr.DiscoveryRequestsSent++
	p.wg.Add(1)
	p.unlock()
	defer p.wg.Done()
	b, err := p.codecs(encUADP).Encode(nm, nil)
	if err == nil {
		err = ch.Send(p.ctx, b, transport.PublishOptions{})
	}
	if err != nil && p.ctx.Err() == nil {
		p.log.Debug("pubsub: discovery probe failed", "reader", r.name, "error", err)
	}
}

// metaDataMismatch notes that a reader received a DataSetMessage of another
// MajorVersion than its DataSetMetaData and probes for the new one, at the
// current probe interval if it probed before. p.mu is held.
func (p *PubSub) metaDataMismatch(r *dataSetReader) {
	r.needMeta = true
	if !p.wantsProbe(r) || r.probe != nil {
		return
	}
	d := firstProbeDelay()
	if r.probeWait > 0 {
		d = p.nextProbeWait(r)
	}
	p.scheduleProbe(r, d)
}
