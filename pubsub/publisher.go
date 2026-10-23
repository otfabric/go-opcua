// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// runWriterGroup publishes a writer group every PublishingInterval, starting
// after its offset, until ctx ends.
func (p *PubSub) runWriterGroup(ctx context.Context, g *writerGroup, gen uint64) {
	defer p.wg.Done()
	first := time.NewTimer(g.offset)
	select {
	case <-ctx.Done():
		first.Stop()
		return
	case <-first.C:
	}
	p.publishCycle(ctx, g, gen)
	t := time.NewTicker(g.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.publishCycle(ctx, g, gen)
		}
	}
}

// planned is a writer of a publish cycle with the variables to sample.
type planned struct {
	w     *dataSetWriter
	items []*ua.PublishedVariableDataType
}

// outDSM is a DataSetMessage ready to be packed into a NetworkMessage.
type outDSM struct {
	dsm   *message.DataSetMessage
	w     *dataSetWriter
	topic string
	qos   byte
	// own: the writer has its own queue, its messages are sent alone.
	own bool
}

// sendStats are the counters of one publish cycle.
type sendStats struct {
	nm, bytes, encErr, sendErr uint64
	lastErr                    error
	dsm, ka                    map[*dataSetWriter]uint64
	meta                       map[*dataSetWriter]bool
	// lost are the writers of messages that could not be encoded or
	// sent: their next message is a key frame, so that a change carried
	// by a lost delta frame is not missing until the next regular one.
	lost map[*dataSetWriter]bool
}

// publishCycle samples the writers of a group, builds their DataSetMessages
// and sends them.
func (p *PubSub) publishCycle(ctx context.Context, g *writerGroup, gen uint64) {
	if !g.pubMu.lock(ctx) {
		return
	}
	defer g.pubMu.unlock()

	p.lock()
	if g.gen != gen {
		p.unlock()
		return
	}
	mode, groupID := g.mode, g.cfg.SecurityGroupID
	p.unlock()

	var ks security.KeySource
	if mode > ua.MessageSecurityModeNone {
		ks = p.KeySource(groupID)
		ok := ks != nil
		if ok {
			_, err := ks.CurrentKeys()
			ok = err == nil
		}
		p.lock()
		if g.gen != gen {
			p.unlock()
			return
		}
		if g.keysOK != ok {
			g.keysOK = ok
			p.reconcileLocked()
		}
		p.unlock()
		if !ok {
			return
		}
	}

	p.lock()
	if g.gen != gen || g.state != ua.PubSubStateOperational || g.conn.tc == nil {
		p.unlock()
		return
	}
	tc := g.conn.tc
	pubID := g.conn.pubID
	var plan []planned
	mds := map[uint16]*ua.DataSetMetaDataType{}
	for _, w := range g.writers {
		if !w.running || w.state != ua.PubSubStateOperational {
			continue
		}
		e := planned{w: w}
		if w.pds != nil {
			e.items = w.pds.items
			mds[w.cfg.DataSetWriterID] = w.pds.md
		}
		plan = append(plan, e)
	}
	p.unlock()
	if len(plan) == 0 {
		return
	}

	values := make([][]*ua.DataValue, len(plan))
	for i, e := range plan {
		if len(e.items) > 0 {
			values[i] = p.sample(ctx, e.items)
		}
	}

	now := time.Now()
	var outs []*outDSM
	var metas []*dataSetWriter
	p.lock()
	if g.gen != gen {
		p.unlock()
		return
	}
	for i, e := range plan {
		w := e.w
		if !w.running {
			continue
		}
		for _, dsm := range p.buildMessages(w, values[i], now) {
			o := &outDSM{dsm: dsm, w: w}
			if g.brokerTS != nil {
				o.topic = g.brokerTS.QueueName
				o.qos = qosOf(g.brokerTS.RequestedDeliveryGuarantee, 0)
			}
			if w.brokerTS != nil && w.brokerTS.QueueName != "" {
				o.topic = w.brokerTS.QueueName
				o.qos = qosOf(w.brokerTS.RequestedDeliveryGuarantee, o.qos)
				o.own = true
			}
			outs = append(outs, o)
		}
		if w.brokerTS != nil && w.brokerTS.MetaDataQueueName != "" && w.pds != nil {
			upd := duration(w.brokerTS.MetaDataUpdateTime)
			if w.metaPending || (upd > 0 && now.Sub(w.metaSentAt) >= upd) {
				metas = append(metas, w)
			}
		}
	}
	p.unlock()

	st := &sendStats{dsm: map[*dataSetWriter]uint64{}, ka: map[*dataSetWriter]uint64{}, meta: map[*dataSetWriter]bool{}, lost: map[*dataSetWriter]bool{}}
	lookup := func(_ message.PublisherID, _ uint16, dswID uint16) *ua.DataSetMetaDataType {
		if md := mds[dswID]; md != nil {
			return md
		}
		if len(mds) == 1 {
			for _, md := range mds {
				return md
			}
		}
		return nil
	}
	enc := &encoder{p: p, g: g, tc: tc, pubID: pubID, ks: ks, mode: mode, lookup: lookup, now: now, st: st}
	if len(outs) > 0 {
		enc.sendData(ctx, outs)
	}
	for _, w := range metas {
		enc.sendMetaData(ctx, w)
	}

	p.lock()
	g.ctr.NetworkMessagesSent += st.nm
	g.ctr.BytesSent += st.bytes
	g.ctr.EncodeErrors += st.encErr
	g.ctr.SendErrors += st.sendErr
	if st.lastErr != nil {
		g.err = st.lastErr
	}
	for w, n := range st.dsm {
		w.ctr.DataSetMessagesSent += n
	}
	for w, n := range st.ka {
		w.ctr.KeepAlivesSent += n
	}
	for w := range st.meta {
		w.ctr.MetaDataSent++
		w.metaPending = false
		w.metaSentAt = now
	}
	for w := range st.lost {
		w.needKey = true
	}
	p.unlock()
}

// sample reads the values of published variables and applies their
// SubstituteValues.
func (p *PubSub) sample(ctx context.Context, items []*ua.PublishedVariableDataType) []*ua.DataValue {
	var vals []*ua.DataValue
	if ds := p.opts.dataSource; ds != nil {
		// A panicking DataSource yields no values: the fields are Bad.
		p.protect("DataSource", func() { vals = ds.ReadPublishedData(ctx, items) })
	}
	out := make([]*ua.DataValue, len(items))
	now := time.Now()
	for i, it := range items {
		var dv *ua.DataValue
		if i < len(vals) {
			dv = vals[i]
		}
		if dv == nil {
			if p.opts.dataSource == nil {
				dv = &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadWaitingForInitialData}
			} else {
				dv = &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadNoData}
			}
		}
		if isBad(dv.Status) && variantValue(it.SubstituteValue) != nil {
			dv = &ua.DataValue{
				EncodingMask:    ua.DataValueValue | ua.DataValueStatusCode | ua.DataValueSourceTimestamp,
				Value:           it.SubstituteValue,
				Status:          ua.StatusUncertainSubstituteValue,
				SourceTimestamp: now,
			}
		}
		out[i] = dv
	}
	return out
}

func isBad(s ua.StatusCode) bool { return uint32(s)&0x80000000 != 0 }

// sameValue reports whether two samples carry the same value and status.
func sameValue(a, b *ua.DataValue) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Status != b.Status {
		return false
	}
	av, bv := variantValue(a.Value), variantValue(b.Value)
	return reflect.DeepEqual(av, bv)
}

// buildMessages builds the DataSetMessages of a writer for one cycle: a key
// frame, a delta frame with the changed fields, the queued events, or a
// keep-alive message when nothing was sent for KeepAliveTime. p.mu is held.
func (p *PubSub) buildMessages(w *dataSetWriter, vals []*ua.DataValue, now time.Time) []*message.DataSetMessage {
	g := w.group
	keepAliveDue := func() bool {
		if g.keepAlive <= 0 {
			return w.pds == nil
		}
		return w.lastSent.IsZero() || now.Sub(w.lastSent) >= g.keepAlive
	}
	var out []*message.DataSetMessage
	switch {
	case w.pds == nil || (w.pds.events == nil && len(w.pds.items) == 0):
		// Heartbeat writer.
	case w.pds.events != nil:
		for _, ev := range w.events {
			dsm := p.newDSM(w, message.DataSetMessageEvent, now)
			for i, v := range ev {
				dsm.Fields = append(dsm.Fields, p.field(w, i, &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}))
			}
			out = append(out, dsm)
		}
		w.events = nil
	default:
		kfc := w.cfg.KeyFrameCount
		if kfc == 0 {
			kfc = 1
		}
		if w.needKey || kfc == 1 || w.sinceKey >= kfc-1 || len(w.last) != len(vals) {
			dsm := p.newDSM(w, message.DataSetMessageKeyFrame, now)
			for i, v := range vals {
				dsm.Fields = append(dsm.Fields, p.field(w, i, v))
			}
			w.last = vals
			w.sinceKey = 0
			w.needKey = false
			out = append(out, dsm)
		} else {
			w.sinceKey++
			var dsm *message.DataSetMessage
			for i, v := range vals {
				if sameValue(w.last[i], v) {
					continue
				}
				if dsm == nil {
					dsm = p.newDSM(w, message.DataSetMessageDeltaFrame, now)
				}
				dsm.Fields = append(dsm.Fields, p.field(w, i, v))
				w.last[i] = v
			}
			if dsm != nil {
				out = append(out, dsm)
			}
		}
	}
	if len(out) == 0 && keepAliveDue() {
		out = append(out, p.newDSM(w, message.DataSetMessageKeepAlive, now))
	}
	for _, dsm := range out {
		if dsm.Type == message.DataSetMessageKeepAlive {
			// A keep-alive carries the sequence number of the next data
			// message (Part 14 §7.2.2.3.4).
			dsm.SequenceNumber = w.seq + 1
		} else {
			w.seq++
			dsm.SequenceNumber = w.seq
		}
		if w.group.enc == encJSON {
			// open62541 rejects JSON sequence numbers above 65535.
			dsm.SequenceNumber &= 0xffff
		}
	}
	if len(out) > 0 {
		w.lastSent = now
	}
	return out
}

func (p *PubSub) newDSM(w *dataSetWriter, t message.DataSetMessageType, now time.Time) *message.DataSetMessage {
	g := w.group
	mask := w.cfg.DataSetFieldContentMask
	dsm := &message.DataSetMessage{
		DataSetWriterID:   w.cfg.DataSetWriterID,
		Type:              t,
		Valid:             true,
		UADPMask:          w.uadpMask,
		JSONMask:          w.jsonMask,
		FieldContentMask:  mask,
		FieldEncoding:     fieldEncoding(mask),
		Timestamp:         now,
		Status:            ua.StatusGood,
		DataSetWriterName: w.name,
		WriterGroupName:   g.name,
	}
	if w.pds != nil && w.pds.md != nil && w.pds.md.ConfigurationVersion != nil {
		dsm.MetaDataVersion = *w.pds.md.ConfigurationVersion
	}
	if g.enc == encJSON && w.jsonMask&ua.JSONDataSetMessageContentMaskPublisherID != 0 {
		id := g.conn.pubID
		dsm.PublisherID = &id
	}
	return dsm
}

// fieldEncoding returns the UADP field encoding of a DataSetFieldContentMask.
func fieldEncoding(mask ua.DataSetFieldContentMask) message.FieldEncoding {
	switch {
	case mask&ua.DataSetFieldContentMaskRawData != 0:
		return message.FieldEncodingRawData
	case mask&(ua.DataSetFieldContentMaskStatusCode|ua.DataSetFieldContentMaskSourceTimestamp|
		ua.DataSetFieldContentMaskServerTimestamp|ua.DataSetFieldContentMaskSourcePicoSeconds|
		ua.DataSetFieldContentMaskServerPicoSeconds) != 0:
		return message.FieldEncodingDataValue
	default:
		return message.FieldEncodingVariant
	}
}

// field builds a message field from a sample, keeping only what the
// DataSetFieldContentMask selects.
func (p *PubSub) field(w *dataSetWriter, i int, dv *ua.DataValue) *message.Field {
	f := &message.Field{Index: uint16(i)}
	if md := w.pds.md; md != nil && i < len(md.Fields) {
		f.Name = md.Fields[i].Name
	}
	mask := w.cfg.DataSetFieldContentMask
	switch fieldEncoding(mask) {
	case message.FieldEncodingVariant, message.FieldEncodingRawData:
		v := dv.Value
		if isBad(dv.Status) && fieldEncoding(mask) == message.FieldEncodingVariant {
			// With the Variant encoding a Bad status is sent in place of
			// the value (Part 14 §7.2.2.3.5).
			v = ua.MustVariant(dv.Status)
		}
		if v == nil {
			v = ua.MustVariant(nil)
		}
		f.Value = &ua.DataValue{EncodingMask: ua.DataValueValue, Value: v}
	default:
		out := &ua.DataValue{Value: dv.Value}
		if out.Value != nil {
			out.EncodingMask |= ua.DataValueValue
		}
		if mask&ua.DataSetFieldContentMaskStatusCode != 0 && dv.Status != ua.StatusGood {
			out.Status = dv.Status
			out.EncodingMask |= ua.DataValueStatusCode
		}
		if mask&ua.DataSetFieldContentMaskSourceTimestamp != 0 && !dv.SourceTimestamp.IsZero() {
			out.SourceTimestamp = dv.SourceTimestamp
			out.EncodingMask |= ua.DataValueSourceTimestamp
		}
		if mask&ua.DataSetFieldContentMaskSourcePicoSeconds != 0 && dv.SourcePicoseconds != 0 {
			out.SourcePicoseconds = dv.SourcePicoseconds
			out.EncodingMask |= ua.DataValueSourcePicoseconds
		}
		if mask&ua.DataSetFieldContentMaskServerTimestamp != 0 && !dv.ServerTimestamp.IsZero() {
			out.ServerTimestamp = dv.ServerTimestamp
			out.EncodingMask |= ua.DataValueServerTimestamp
		}
		if mask&ua.DataSetFieldContentMaskServerPicoSeconds != 0 && dv.ServerPicoseconds != 0 {
			out.ServerPicoseconds = dv.ServerPicoseconds
			out.EncodingMask |= ua.DataValueServerPicoseconds
		}
		f.Value = out
	}
	return f
}

// encoder packs, encodes and sends the messages of one publish cycle.
type encoder struct {
	p      *PubSub
	g      *writerGroup
	tc     transport.Connection
	pubID  message.PublisherID
	ks     security.KeySource
	mode   ua.MessageSecurityMode
	lookup message.MetaDataLookup
	now    time.Time
	st     *sendStats
	number uint16
}

var errTooLarge = errors.New("pubsub: DataSetMessage exceeds MaxNetworkMessageSize")

// sendData packs DataSetMessages into NetworkMessages: per queue, in the
// DataSetOrdering of the group, split to fit MaxNetworkMessageSize.
func (e *encoder) sendData(ctx context.Context, outs []*outDSM) {
	g := e.g
	ordering := ua.DataSetOrderingTypeUndefined
	single := false
	if g.enc == encUADP {
		ordering = g.uadpMsg.DataSetOrdering
		if g.uadpMsg.NetworkMessageContentMask&ua.UADPNetworkMessageContentMaskPayloadHeader == 0 {
			// Without a PayloadHeader a NetworkMessage carries one
			// DataSetMessage.
			single = true
		}
	}
	if ordering == ua.DataSetOrderingTypeAscendingWriterIDSingle {
		single = true
	}
	if ordering != ua.DataSetOrderingTypeUndefined {
		sort.SliceStable(outs, func(i, j int) bool {
			return outs[i].dsm.DataSetWriterID < outs[j].dsm.DataSetWriterID
		})
	}
	// Bucket by queue: the group queue first, then the writer queues.
	var chunks [][]*outDSM
	var shared []*outDSM
	own := map[*dataSetWriter]int{}
	for _, o := range outs {
		switch {
		case single:
			chunks = append(chunks, []*outDSM{o})
		case o.own:
			if i, ok := own[o.w]; ok {
				chunks[i] = append(chunks[i], o)
			} else {
				own[o.w] = len(chunks)
				chunks = append(chunks, []*outDSM{o})
			}
		default:
			shared = append(shared, o)
		}
	}
	if len(shared) > 0 {
		chunks = append([][]*outDSM{shared}, chunks...)
	}

	maxSize := int(g.cfg.MaxNetworkMessageSize)
	if maxSize == 0 {
		maxSize = e.tc.MaxMessageSize()
	}
	for len(chunks) > 0 {
		chunk := chunks[0]
		chunks = chunks[1:]
		nm := e.dataMessage(chunk)
		b, err := e.encode(nm)
		if err != nil {
			e.fail(err, true)
			e.lose(chunk)
			continue
		}
		if maxSize > 0 && len(b) > maxSize {
			if len(chunk) > 1 {
				h := len(chunk) / 2
				chunks = append([][]*outDSM{chunk[:h], chunk[h:]}, chunks...)
				continue
			}
			e.fail(fmt.Errorf("%w: %d > %d bytes (writer %q)", errTooLarge, len(b), maxSize, chunk[0].w.name), true)
			e.lose(chunk)
			continue
		}
		e.number++
		if !e.send(ctx, b, transport.PublishOptions{Topic: chunk[0].topic, QoS: chunk[0].qos}) {
			e.lose(chunk)
			continue
		}
		g.nmSeq++
		for _, o := range chunk {
			if o.dsm.Type == message.DataSetMessageKeepAlive {
				e.st.ka[o.w]++
			} else {
				e.st.dsm[o.w]++
			}
		}
	}
}

// dataMessage builds the NetworkMessage of a chunk.
func (e *encoder) dataMessage(chunk []*outDSM) *message.NetworkMessage {
	g := e.g
	nm := &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		PublisherID: e.pubID,
		Timestamp:   e.now,
	}
	for _, o := range chunk {
		nm.Messages = append(nm.Messages, o.dsm)
	}
	if g.enc == encUADP {
		nm.UADPMask = g.uadpMsg.NetworkMessageContentMask
		nm.GroupHeader = message.GroupHeader{
			WriterGroupID:        g.cfg.WriterGroupID,
			GroupVersion:         g.uadpMsg.GroupVersion,
			NetworkMessageNumber: e.number + 1,
			SequenceNumber:       g.nmSeq + 1,
		}
	} else {
		nm.JSONMask = g.jsonMsg.NetworkMessageContentMask
		nm.MessageID = uuid.NewString()
		nm.WriterGroupName = g.name
	}
	if len(chunk) == 1 && chunk[0].w.pds != nil && chunk[0].w.pds.md != nil && hasFieldID(chunk[0].w.pds.md.DataSetClassID) {
		nm.DataSetClassID = chunk[0].w.pds.md.DataSetClassID
	}
	return nm
}

func (e *encoder) encode(nm *message.NetworkMessage) ([]byte, error) {
	opts := &uadp.EncodeOptions{MetaData: e.lookup}
	if e.mode > ua.MessageSecurityModeNone && e.g.enc == encUADP {
		e.g.nonceSeq++
		opts.SecurityMode = e.mode
		opts.Keys = e.ks
		opts.NonceSequence = e.g.nonceSeq
	}
	return e.p.codecs(e.g.enc).Encode(nm, opts)
}

// lose records the writers of DataSetMessages that were not sent.
func (e *encoder) lose(chunk []*outDSM) {
	for _, o := range chunk {
		if o.dsm.Type != message.DataSetMessageKeepAlive {
			e.st.lost[o.w] = true
		}
	}
}

func (e *encoder) fail(err error, encode bool) {
	if encode {
		e.st.encErr++
	} else {
		e.st.sendErr++
	}
	e.st.lastErr = err
	e.p.log.Warn("pubsub: publish failed", "writer_group", e.g.name, "error", err)
}

// send sends an encoded message, repeating it as the datagram transport
// settings ask.
func (e *encoder) send(ctx context.Context, b []byte, opts transport.PublishOptions) bool {
	if err := e.tc.Send(ctx, b, opts); err != nil {
		if ctx.Err() == nil {
			e.fail(err, false)
		}
		return false
	}
	e.st.nm++
	e.st.bytes += uint64(len(b))
	if ts := e.g.dgramTS; ts != nil {
		delay := duration(ts.MessageRepeatDelay)
		for range ts.MessageRepeatCount {
			if delay > 0 {
				t := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					t.Stop()
					return true
				case <-t.C:
				}
			}
			if err := e.tc.Send(ctx, b, opts); err != nil {
				return true
			}
			e.st.nm++
			e.st.bytes += uint64(len(b))
		}
	}
	return true
}

// sendMetaData announces the DataSetMetaData of a writer on its
// MetaDataQueueName, retained by the broker for late subscribers.
func (e *encoder) sendMetaData(ctx context.Context, w *dataSetWriter) {
	g := e.g
	md := w.pds.md
	var b []byte
	var err error
	if g.enc == encJSON {
		b, err = e.p.codecs(encJSON).EncodeMetaData(&jsonmsg.MetaDataMessage{
			MessageID:       uuid.NewString(),
			PublisherID:     e.pubID,
			DataSetWriterID: w.cfg.DataSetWriterID,
			WriterGroupName: g.name,
			MetaData:        md,
			Timestamp:       e.now,
		})
	} else {
		b, err = e.encode(&message.NetworkMessage{
			Type:        message.NetworkMessageDiscoveryResponse,
			UADPMask:    ua.UADPNetworkMessageContentMaskPublisherID,
			PublisherID: e.pubID,
			Discovery: &message.Discovery{
				Type:            message.DiscoveryDataSetMetaData,
				SequenceNumber:  g.nmSeq,
				DataSetWriterID: w.cfg.DataSetWriterID,
				MetaData:        md,
				StatusCode:      ua.StatusGood,
			},
		})
	}
	if err != nil {
		e.fail(err, true)
		return
	}
	if e.send(ctx, b, transport.PublishOptions{Topic: w.brokerTS.MetaDataQueueName, QoS: 1, Retain: true}) {
		e.st.meta[w] = true
	}
}
