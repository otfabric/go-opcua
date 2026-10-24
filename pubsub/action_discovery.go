// SPDX-License-Identifier: MIT

package pubsub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// Discovery of PubSub Actions (Part 14 §6.2.11.2 in 1.05): the ActionMetaData
// of an Action writer (UADP announcement 7, Table 177; JSON
// "ua-action-metadata", Table 193) and the ActionResponder configuration of
// a connection (UADP announcement 6, Table 176; JSON "ua-action-responder",
// Table 194).
//
// A Responder sends them without a probe when its Action writer group
// becomes Operational (the configuration of its Actions appeared or
// changed): on a broker the ActionMetaData of every Action writer with a
// MetaDataQueueName, retained, and the ActionResponder retained on the
// action-responder topic of the Responder (derived from the default
// action-request QueueName of the group); on a datagram transport the
// ActionMetaData on the discovery channel (the DiscoveryAddress or a shared
// connection address), again every DiscoveryAnnounceRate. It answers a
// DataSetMetaData probe for an Action writer with its ActionMetaData and a
// PubSubConnections probe also with the ActionResponder, both on the
// discovery channel, where Requestors listen.
//
// A Requestor learns the ActionMetaData with [PubSub.DiscoverAction].

// ActionMetaData describes the Actions of an Action writer of a Responder:
// its targets and the DataSetMetaData of the requests and responses.
type ActionMetaData struct {
	Responder       message.PublisherID
	DataSetWriterID uint16
	ActionTargets   []*ua.ActionTargetDataType
	Request         *ua.DataSetMetaDataType
	Response        *ua.DataSetMetaDataType
	// ActionMethods are the Methods of the targets of a
	// PublishedActionMethod, one per target; empty otherwise.
	ActionMethods []*ua.ActionMethodDataType
}

// Apply returns t with the RequestMetaData and ResponseMetaData of m.
func (m *ActionMetaData) Apply(t ActionTarget) ActionTarget {
	t.RequestMetaData, t.ResponseMetaData = m.Request, m.Response
	return t
}

// Target returns the Action target with the id, nil if there is none.
func (m *ActionMetaData) Target(id uint16) *ua.ActionTargetDataType {
	for _, t := range m.ActionTargets {
		if t != nil && t.ActionTargetID == id {
			return t
		}
	}
	return nil
}

// ActionMetaDataTopic returns the default MQTT topic of the ActionMetaData
// of an Action writer (Part 14 §7.3.4.7.12 in 1.05):
// <prefix>/<encoding>/action-metadata/<responder>/<writerGroup>/<writer>. It
// is the MetaDataQueueName of the writer and the MetaDataAddress of the
// [ActionTarget] for [PubSub.DiscoverAction].
func ActionMetaDataTopic(prefix string, mapping MessageMapping, responder, writerGroup, writer string) string {
	return actionTopic(prefix, mapping, "action-metadata", responder, writerGroup) + "/" + writer
}

// ActionResponderTopic returns the MQTT topic of the ActionResponder
// message of a Responder (Part 14 §7.3.4.7.11 in 1.05):
// <prefix>/<encoding>/action-responder/<responder>.
func ActionResponderTopic(prefix string, mapping MessageMapping, responder string) string {
	enc := "uadp"
	if mapping == MappingJSON {
		enc = "json"
	}
	return prefix + "/" + enc + "/action-responder/" + responder
}

// responderTopic returns the action-responder topic of a Responder whose
// request queue has the default form .../action-request/<responder>/<group>,
// empty for another one.
func responderTopic(queue string) string {
	const req = "/action-request/"
	i := strings.LastIndex(queue, req)
	if i < 0 {
		return ""
	}
	responder, _, ok := strings.Cut(queue[i+len(req):], "/")
	if !ok || responder == "" {
		return ""
	}
	return queue[:i] + "/action-responder/" + responder
}

// actionMetaDataOf returns the ActionMetaData of an Action writer. The Name
// and ConfigurationVersion of the request are those of the response (Part
// 14 Table 177). p.mu is held.
func actionMetaDataOf(w *dataSetWriter, pub message.PublisherID) *ActionMetaData {
	d := w.pds
	resp := d.md
	req, _ := clone(d.action.RequestDataSetMetaData)
	if req == nil {
		req = &ua.DataSetMetaDataType{}
	}
	if resp != nil {
		req.Name, req.ConfigurationVersion = resp.Name, resp.ConfigurationVersion
	}
	m := &ActionMetaData{Responder: pub, DataSetWriterID: w.cfg.DataSetWriterID, ActionTargets: d.action.ActionTargets, Request: req, Response: resp}
	if d.methods != nil {
		for _, t := range d.action.ActionTargets {
			m.ActionMethods = append(m.ActionMethods, d.methods[t.ActionTargetID])
		}
	}
	return m
}

func (m *ActionMetaData) discovery() *message.Discovery {
	return &message.Discovery{
		Type:            message.DiscoveryActionMetaData,
		DataSetWriterID: m.DataSetWriterID,
		ActionTargets:   m.ActionTargets,
		RequestMetaData: m.Request,
		MetaData:        m.Response,
		ActionMethods:   m.ActionMethods,
	}
}

// actionResponderConfig is the ActionResponder configuration of a connection:
// its Action writer groups with only their Action writers, without reader
// groups and properties (Table 176). It is nil without Action writers.
// p.mu is held.
func actionResponderConfig(c *connection) *ua.PubSubConnectionDataType {
	cfg := connectionConfig(c, false, false)
	for _, g := range c.wgs {
		var ids []uint16
		for _, w := range g.writers {
			if w.isAction() {
				ids = append(ids, w.cfg.DataSetWriterID)
			}
		}
		if len(ids) > 0 {
			cfg.WriterGroups = append(cfg.WriterGroups, publicGroup(g, ids, true))
		}
	}
	if len(cfg.WriterGroups) == 0 {
		return nil
	}
	return cfg
}

// actionAnnouncement is an Action discovery message of a Responder, ready
// to be encoded: a UADP NetworkMessage secured like g or a JSON message.
type actionAnnouncement struct {
	nm   *message.NetworkMessage
	json []byte
	g    *writerGroup
	w    *dataSetWriter
	tc   transport.Connection
	// topic is the retained broker topic, empty on a datagram transport.
	topic string
}

// actionAnnouncementsLocked builds the unprompted Action discovery messages
// of the running Action writers ws of a group, with the ActionResponder
// message on a broker if responder. p.mu is held.
func (p *PubSub) actionAnnouncementsLocked(g *writerGroup, ws []*dataSetWriter, responder bool, now time.Time) []actionAnnouncement {
	c := g.conn
	if p.opts.discovery.Disabled || !c.hasPub || c.tc == nil {
		return nil
	}
	var out []actionAnnouncement
	uadpNM := func(d *message.Discovery) *message.NetworkMessage {
		d.SequenceNumber = uint16(c.annSeq.Add(1))
		return &message.NetworkMessage{
			Type:        message.NetworkMessageDiscoveryResponse,
			UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
			PublisherID: c.pubID,
			Discovery:   d,
		}
	}
	if !c.broker {
		disc := p.discoveryChannel(c)
		if disc == nil || g.enc != encUADP {
			return nil
		}
		for _, w := range ws {
			out = append(out, actionAnnouncement{nm: uadpNM(actionMetaDataOf(w, c.pubID).discovery()), g: g, w: w, tc: disc})
		}
		return out
	}
	for _, w := range ws {
		if w.brokerTS == nil || w.brokerTS.MetaDataQueueName == "" {
			continue
		}
		a := actionAnnouncement{g: g, w: w, tc: c.tc, topic: w.brokerTS.MetaDataQueueName}
		m := actionMetaDataOf(w, c.pubID)
		if g.enc == encJSON {
			b, err := jsonmsg.EncodeActionMetaData(&jsonmsg.ActionMetaDataMessage{PublisherID: c.pubID, DataSetWriterID: m.DataSetWriterID,
				DataSetWriterName: w.name, Timestamp: now, ActionTargets: m.ActionTargets, Request: m.Request, Response: m.Response, ActionMethods: m.ActionMethods}, nil)
			if err != nil {
				p.log.Warn("pubsub: ActionMetaData message failed", "writer", w.name, "error", err)
				continue
			}
			a.json = b
		} else {
			a.nm = uadpNM(m.discovery())
		}
		out = append(out, a)
	}
	if !responder || g.brokerTS == nil {
		return out
	}
	topic := responderTopic(g.brokerTS.QueueName)
	cfg := actionResponderConfig(c)
	if topic == "" || cfg == nil {
		return out
	}
	a := actionAnnouncement{tc: c.tc, topic: topic}
	if g.enc == encJSON {
		b, err := jsonmsg.EncodeActionResponder(&jsonmsg.ActionResponderMessage{PublisherID: c.pubID, Timestamp: now, Connection: cfg}, nil)
		if err != nil {
			p.log.Warn("pubsub: ActionResponder message failed", "connection", c.name, "error", err)
			return out
		}
		a.json = b
	} else {
		// Unsecured: it describes the connection, not one group.
		a.nm = uadpNM(&message.Discovery{Type: message.DiscoveryActionResponder, Connections: []*ua.PubSubConnectionDataType{cfg}})
	}
	return append(out, a)
}

// announceActions sends the unprompted Action discovery messages of a writer
// group that became Operational. p.mu is held; the messages go out in
// the background.
func (p *PubSub) announceActions(g *writerGroup) {
	var ws []*dataSetWriter
	now := time.Now()
	for _, w := range g.writers {
		if w.running && w.isAction() {
			ws = append(ws, w)
			w.metaSentAt = now
		}
	}
	if len(ws) == 0 {
		return
	}
	anns := p.actionAnnouncementsLocked(g, ws, true, now)
	if len(anns) == 0 {
		return
	}
	c, gen, ctx := g.conn, g.conn.gen, p.ctx
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.sendActionAnnouncements(ctx, c, gen, anns)
	}()
}

// sendActionAnnouncements encodes and sends Action discovery messages:
// UADP ones secured like their group and chunked above the discovery
// message size; on a broker retained.
func (p *PubSub) sendActionAnnouncements(ctx context.Context, c *connection, gen uint64, anns []actionAnnouncement) {
	var sent, chunks uint64
	var meta []*dataSetWriter
	for _, a := range anns {
		var parts [][]byte
		var err error
		enc := encJSON
		if a.nm != nil {
			enc = encUADP
			opts := &uadp.EncodeOptions{}
			if g := a.g; g != nil && g.mode > ua.MessageSecurityModeNone {
				ks := p.KeySource(g.cfg.SecurityGroupID)
				if ks == nil {
					continue
				}
				opts.SecurityMode, opts.Keys, opts.NextNonceSequence = g.mode, ks, g.nextNonce
			}
			cd := p.codecs(encUADP)
			var b []byte
			b, err = cd.Encode(a.nm, opts)
			parts = [][]byte{b}
			if maxSize := discoveryMaxSize(c, a.tc); err == nil && a.topic == "" && maxSize > 0 && len(b) > maxSize {
				parts, err = cd.EncodeChunks(a.nm, opts, maxSize)
			}
		} else {
			parts = [][]byte{a.json}
		}
		if err != nil {
			p.log.Warn("pubsub: Action discovery message failed", "connection", c.name, "error", err)
			continue
		}
		opts := transport.PublishOptions{}
		if a.topic != "" {
			b, ct, err := p.body(c, a.tc, enc, parts[0])
			if err != nil {
				p.log.Warn("pubsub: Action discovery message failed", "connection", c.name, "error", err)
				continue
			}
			parts[0] = b
			opts = transport.PublishOptions{Topic: a.topic, QoS: 1, Retain: true, ContentType: ct, MessageType: transport.MessageTypeMetaData}
		}
		ok := true
		for _, b := range parts {
			if err := a.tc.Send(ctx, b, opts); err != nil {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		sent++
		if len(parts) > 1 {
			chunks += uint64(len(parts))
		}
		if a.w != nil {
			meta = append(meta, a.w)
		}
	}
	p.lock()
	defer p.unlock()
	if c.gen != gen {
		return
	}
	c.ctr.DiscoveryResponsesSent += sent
	c.ctr.ChunksSent += chunks
	for _, w := range meta {
		w.ctr.MetaDataSent++
	}
}

// actionWaiter is a DiscoverAction waiting for the ActionMetaData of a
// writer of a Responder.
type actionWaiter struct {
	pub     message.PublisherID
	dswid   uint16
	mode    ua.MessageSecurityMode
	groupID string
	ch      chan *ActionMetaData
}

// DiscoverAction returns the ActionMetaData of the Action writer of a
// Responder addressed by t (Connection, PublisherID, DataSetWriterID and,
// for UADP, SecurityMode and SecurityGroupID). On a broker it is read from
// the retained message on t.MetaDataAddress (see [ActionMetaDataTopic]); on
// a datagram transport it is probed for on the discovery channel of the
// connection (its DiscoveryAddress or shared connection address), where the
// Responder answers. It waits up to t.Timeout (or the deadline of ctx, or
// ActionOptions.DefaultTimeout) and fails with Bad_Timeout. Apply the
// result to the target for [PubSub.CallAction].
func (p *PubSub) DiscoverAction(ctx context.Context, t ActionTarget) (*ActionMetaData, error) {
	pv, err := PublisherIDVariant(t.PublisherID)
	if err != nil {
		return nil, fmt.Errorf("pubsub: ActionTarget: %w: %w", err, ua.StatusBadInvalidArgument)
	}
	responder, ok, _ := publisherIDOf(pv)
	if !ok || t.DataSetWriterID == 0 {
		return nil, fmt.Errorf("pubsub: ActionTarget needs the PublisherId and DataSetWriterId of the Responder: %w", ua.StatusBadInvalidArgument)
	}
	mode := securityMode(t.SecurityMode)
	if mode > ua.MessageSecurityModeSignAndEncrypt || (mode > ua.MessageSecurityModeNone && t.SecurityGroupID == "") {
		return nil, fmt.Errorf("pubsub: ActionTarget: SecurityMode %v needs a SecurityGroupId: %w", t.SecurityMode, ua.StatusBadInvalidArgument)
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = p.opts.actions.DefaultTimeout
		if dl, ok := ctx.Deadline(); ok {
			timeout = time.Until(dl)
		}
	}

	p.lock()
	if p.closed {
		p.unlock()
		return nil, ErrClosed
	}
	var c *connection
	for _, x := range p.conns {
		if x.name == t.Connection {
			c = x
		}
	}
	listen := ""
	var probeOn transport.Connection
	var setupErr error
	switch {
	case c == nil:
		setupErr = fmt.Errorf("pubsub: no connection %q: %w", t.Connection, ua.StatusBadNotFound)
	case c.cancel == nil || c.tc == nil:
		setupErr = fmt.Errorf("pubsub: connection %q is not running: %w", c.name, ua.StatusBadInvalidState)
	case c.broker:
		listen = t.MetaDataAddress
		if listen == "" {
			setupErr = fmt.Errorf("pubsub: ActionTarget needs the MetaDataAddress (the MetaDataQueueName of the Responder's writer): %w", ua.StatusBadInvalidArgument)
		}
	case isJSONProfile(c.cfg.TransportProfileURI):
		setupErr = fmt.Errorf("pubsub: datagram discovery is UADP only: %w", ua.StatusBadInvalidArgument)
	default:
		probeOn = p.discoveryChannel(c)
		if probeOn == nil {
			setupErr = fmt.Errorf("pubsub: connection %q has no discovery channel (a DiscoveryAddress or a shared address): %w", c.name, ua.StatusBadInvalidState)
		}
	}
	if setupErr != nil {
		p.unlock()
		return nil, setupErr
	}
	wt := &actionWaiter{pub: responder, dswid: t.DataSetWriterID, mode: mode, groupID: t.SecurityGroupID, ch: make(chan *ActionMetaData, 1)}
	c.act.init()
	c.act.waiters[wt] = struct{}{}
	subscribe := c.broker || probeOn == c.tc
	if subscribe {
		c.act.listen[listen]++
		p.updateTopics(c)
	}
	gen, seq := c.gen, c.topicsSeq
	p.unlock()
	defer func() {
		p.lock()
		defer p.unlock()
		if c.gen != gen {
			return
		}
		delete(c.act.waiters, wt)
		if len(c.act.waiters) == 0 {
			c.act.reasm = nil
		}
		if subscribe {
			if c.act.listen[listen]--; c.act.listen[listen] <= 0 {
				delete(c.act.listen, listen)
			}
			p.updateTopics(c)
		}
	}()

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	fail := func(err error) (*ActionMetaData, error) {
		if p.isClosed() {
			return nil, ErrClosed
		}
		if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("pubsub: no ActionMetaData of writer %d of %v: %w", t.DataSetWriterID, responder, ua.StatusBadTimeout)
		}
		return nil, err
	}
	if subscribe {
		if err := p.waitSubscribed(cctx, c, gen, seq, listen); err != nil {
			return fail(err)
		}
	}
	var probe []byte
	if probeOn != nil {
		probe, err = p.codecs(encUADP).Encode(&message.NetworkMessage{
			Type:        message.NetworkMessageDiscoveryRequest,
			UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
			PublisherID: responder,
			Request: &message.DiscoveryRequest{
				ProbeType:        message.ProbePublisherInformation,
				InformationType:  message.InformationDataSetMetaData,
				DataSetWriterIDs: []uint16{t.DataSetWriterID},
			},
		}, nil)
		if err != nil {
			return nil, err
		}
	}
	o := &p.opts.discovery
	wait := o.MinInterval
	for {
		var tick <-chan time.Time
		stop := func() bool { return false }
		if probe != nil {
			p.lock()
			if c.gen == gen {
				c.ctr.DiscoveryRequestsSent++
			}
			p.unlock()
			if err := probeOn.Send(cctx, probe, transport.PublishOptions{}); err != nil && cctx.Err() == nil {
				p.log.Debug("pubsub: action discovery probe failed", "connection", c.name, "error", err)
			}
			tm := time.NewTimer(wait)
			tick = tm.C
			wait = min(2*wait, o.MaxProbeInterval)
			stop = tm.Stop
		}
		select {
		case m := <-wt.ch:
			stop()
			return m, nil
		case <-cctx.Done():
			stop()
			return fail(cctx.Err())
		case <-tick:
		}
	}
}

// isActionMetaData tells whether a message may be an ActionMetaData
// message: a JSON "ua-action-metadata" message or a UADP discovery
// announcement (whose type may be encrypted).
func isActionMetaData(enc encoding, m *transport.Message) bool {
	if enc == encJSON {
		return bytes.Contains(m.Payload, []byte(`"`+jsonmsg.MessageTypeActionMetaData+`"`))
	}
	t, _, err := uadp.PeekType(m.Payload)
	return err == nil && t == message.NetworkMessageDiscoveryResponse
}

// receiveActionMetaData hands an ActionMetaData message to the
// DiscoverAction calls waiting for it. It reports whether the message was
// one: the others (and every chunk, which a reader may be reassembling)
// take the regular path.
func (p *PubSub) receiveActionMetaData(c *connection, gen uint64, enc encoding, m *transport.Message) bool {
	p.lock()
	if c.gen != gen || len(c.act.waiters) == 0 {
		p.unlock()
		return false
	}
	waiters := make([]*actionWaiter, 0, len(c.act.waiters))
	for w := range c.act.waiters {
		waiters = append(waiters, w)
	}
	p.unlock()
	if enc == encJSON {
		jm, err := jsonmsg.DecodeActionMetaData(m.Payload, nil)
		if err != nil {
			return false
		}
		// The JSON mapping has no message security.
		p.deliverActionMetaData(c, gen, waiters, &ActionMetaData{Responder: jm.PublisherID, DataSetWriterID: jm.DataSetWriterID,
			ActionTargets: jm.ActionTargets, Request: jm.Request, Response: jm.Response, ActionMethods: jm.ActionMethods}, ua.MessageSecurityModeNone, "")
		return true
	}
	var keyGroup string
	opts := &decodeOptions{}
	opts.Accept = func(h *message.NetworkMessage) bool {
		for _, w := range waiters {
			if samePublisher(h.PublisherID, w.pub) {
				return true
			}
		}
		return false
	}
	// The least security a waiter for the Responder requires, verified
	// with the keys of the first secured one.
	opts.Security = func(h *message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
		mode := ua.MessageSecurityModeInvalid
		var ks security.KeySource
		for _, w := range waiters {
			if !samePublisher(h.PublisherID, w.pub) {
				continue
			}
			if mode == ua.MessageSecurityModeInvalid || w.mode < mode {
				mode = w.mode
			}
			if w.mode > ua.MessageSecurityModeNone && ks == nil {
				ks, keyGroup = p.KeySource(w.groupID), w.groupID
			}
		}
		return max(mode, ua.MessageSecurityModeNone), ks, nil
	}
	cd := p.codecs(encUADP)
	var nm *message.NetworkMessage
	var err error
	if p.protect("decode", func() { nm, err = cd.Decode(m.Payload, opts) }) {
		return false
	}
	if err != nil {
		return false
	}
	chunk := nm.Chunk != nil
	if chunk {
		// Reassembled apart from the readers, which get the chunk as
		// well.
		now := time.Now()
		p.lock()
		if c.gen != gen || len(c.act.waiters) == 0 {
			p.unlock()
			return false
		}
		if c.act.reasm == nil {
			c.act.reasm = uadp.NewReassembler(p.opts.reassembly)
		}
		r := c.act.reasm
		p.unlock()
		r.Expire(now)
		payload, _, err := r.Add(nm, now)
		if err != nil || payload == nil {
			return false
		}
		chunkNM := nm
		if p.protect("decode", func() { nm, err = cd.DecodeReassembled(chunkNM, payload, opts) }) || err != nil {
			return false
		}
	}
	d := nm.Discovery
	if d == nil || d.Type != message.DiscoveryActionMetaData {
		return false
	}
	p.deliverActionMetaData(c, gen, waiters, &ActionMetaData{Responder: nm.PublisherID, DataSetWriterID: d.DataSetWriterID,
		ActionTargets: d.ActionTargets, Request: d.RequestMetaData, Response: d.MetaData, ActionMethods: d.ActionMethods}, securityOf(nm), keyGroup)
	return !chunk
}

// deliverActionMetaData hands an ActionMetaData to the waiters of its
// writer whose security it satisfies.
func (p *PubSub) deliverActionMetaData(c *connection, gen uint64, waiters []*actionWaiter, m *ActionMetaData, got ua.MessageSecurityMode, keyGroup string) {
	n := uint64(0)
	for _, w := range waiters {
		if w.dswid != m.DataSetWriterID || !samePublisher(m.Responder, w.pub) || !securedFor(w.mode, w.groupID, got, keyGroup) {
			continue
		}
		select {
		case w.ch <- m:
			n++
		default:
		}
	}
	p.lock()
	if c.gen == gen {
		c.ctr.DiscoveryResponsesReceived += n
	}
	p.unlock()
}
