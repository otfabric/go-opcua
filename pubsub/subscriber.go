// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// streamKey identifies the DataSetMessages of one writer as a reader sees
// them.
type streamKey struct {
	pub string
	pt  message.PublisherIDType
	wg  uint16
	dsw uint16
}

// stream is what a reader keeps per writer: the sequence number and the
// fields of the last key frame with the deltas merged onto them.
type stream struct {
	hasSeq bool
	seq    uint32
	fields []*ua.DataValue
	key    bool
}

// readerSnap is the filter of a running reader, copied for the decoder
// callbacks that run outside the lock.
type readerSnap struct {
	r         *dataSetReader
	pub       message.PublisherID
	hasPub    bool
	wgid      uint16
	dswid     uint16
	mode      ua.MessageSecurityMode
	groupID   string
	topic     string
	metaTopic string
}

func (p *PubSub) snapshotReaders(c *connection) []readerSnap {
	var out []readerSnap
	for _, g := range c.rgs {
		if g.state != ua.PubSubStateOperational {
			continue
		}
		for _, r := range g.readers {
			if !r.running {
				continue
			}
			s := readerSnap{r: r, pub: r.pub, hasPub: r.hasPub, wgid: r.cfg.WriterGroupID, dswid: r.cfg.DataSetWriterID, mode: r.mode, groupID: r.groupID}
			if r.brokerTS != nil {
				s.topic, s.metaTopic = r.brokerTS.QueueName, r.brokerTS.MetaDataQueueName
			}
			out = append(out, s)
		}
	}
	return out
}

// samePublisher compares PublisherIds by value: the JSON mapping carries
// them as strings, so a numeric id may come back with another type.
func samePublisher(a, b message.PublisherID) bool {
	return a.String() == b.String()
}

// pubOf returns the PublisherId of a DataSetMessage: its own (JSON) or the
// one of the NetworkMessage, if the message carries one.
func pubOf(nm *message.NetworkMessage, dsm *message.DataSetMessage) (message.PublisherID, bool) {
	if dsm != nil && dsm.PublisherID != nil {
		return *dsm.PublisherID, true
	}
	if nm.UADPMask&ua.UADPNetworkMessageContentMaskPublisherID != 0 || nm.JSONMask&ua.JSONNetworkMessageContentMaskPublisherID != 0 {
		return nm.PublisherID, true
	}
	return message.PublisherID{}, false
}

// wgOf returns the WriterGroupId of a UADP NetworkMessage, if it has one.
func wgOf(nm *message.NetworkMessage) (uint16, bool) {
	m := nm.UADPMask
	if m&ua.UADPNetworkMessageContentMaskGroupHeader != 0 && m&ua.UADPNetworkMessageContentMaskWriterGroupID != 0 {
		return nm.GroupHeader.WriterGroupID, true
	}
	return 0, false
}

// topicMatch matches an MQTT topic against a filter with + and #.
func topicMatch(filter, topic string) bool {
	if filter == topic {
		return true
	}
	f := strings.Split(filter, "/")
	t := strings.Split(topic, "/")
	for i, part := range f {
		if part == "#" {
			return true
		}
		if i >= len(t) {
			return false
		}
		if part != "+" && part != t[i] {
			return false
		}
	}
	return len(f) == len(t)
}

// matches tells whether a reader takes a DataSetMessage (dsm nil: any
// message of the NetworkMessage header).
func (s *readerSnap) matches(nm *message.NetworkMessage, dsm *message.DataSetMessage, enc encoding, topic string) bool {
	if s.topic != "" && topic != "" && !topicMatch(s.topic, topic) && (s.metaTopic == "" || !topicMatch(s.metaTopic, topic)) {
		return false
	}
	if s.hasPub {
		id, ok := pubOf(nm, dsm)
		if !ok {
			// A JSON NetworkMessage without header may still carry the
			// PublisherId in its DataSetMessages.
			if enc != encJSON || dsm != nil {
				return false
			}
		} else if !samePublisher(id, s.pub) {
			return false
		}
	}
	if s.wgid != 0 && enc == encUADP {
		wg, ok := wgOf(nm)
		if !ok || wg != s.wgid {
			return false
		}
	}
	if s.dswid != 0 {
		if dsm != nil {
			return dsm.DataSetWriterID == 0 || dsm.DataSetWriterID == s.dswid
		}
		if len(nm.Messages) == 0 {
			return true
		}
		for _, m := range nm.Messages {
			if m.DataSetWriterID == 0 || m.DataSetWriterID == s.dswid {
				return true
			}
		}
		return false
	}
	return true
}

// errDecodePanic is the decode error of a message whose decoding panicked
// (recovered and logged by protect).
var errDecodePanic = errors.New("pubsub: decoding the message panicked")

// receive handles a message received on a connection.
func (p *PubSub) receive(c *connection, gen uint64, m *transport.Message) {
	p.lock()
	if c.gen != gen {
		p.unlock()
		return
	}
	c.ctr.NetworkMessagesReceived++
	c.ctr.BytesReceived += uint64(len(m.Payload))
	snap := p.snapshotReaders(c)
	p.unlock()
	if len(snap) == 0 {
		return
	}
	recv := m.Received
	if recv.IsZero() {
		recv = time.Now()
	}
	enc := payloadEncoding(m.Payload)
	if enc == encJSON {
		// The JSON mapping has no message security: its messages are
		// only for the readers that require none.
		n := 0
		for _, s := range snap {
			if s.mode <= ua.MessageSecurityModeNone {
				snap[n] = s
				n++
			}
		}
		if n == 0 {
			p.decodeFailed(c, gen, snap, nil, fmt.Errorf("%w: unsecured JSON message, the readers require message security", uadp.ErrSecurityMode))
			return
		}
		snap = snap[:n]
	}
	cd := p.codecs(enc)
	// keyGroup is the SecurityGroup whose keys verified the message.
	var keyGroup string
	// hdr are the readers whose filter the header of the message matched,
	// for the diagnostics.
	var hdr []*readerSnap
	opts := &decodeOptions{}
	opts.DecodeOptions = uadp.DecodeOptions{
		Accept: func(h *message.NetworkMessage) bool {
			hdr = hdr[:0]
			for i := range snap {
				if snap[i].matches(h, nil, enc, m.Topic) {
					hdr = append(hdr, &snap[i])
				}
			}
			return len(hdr) > 0
		},
		// The decoder requires the least security a matching reader
		// requires and verifies with the keys of the first secured one;
		// every reader then only takes what satisfies its own security
		// (readerSnap.secured).
		Security: func(h *message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
			mode := ua.MessageSecurityModeInvalid
			var ks security.KeySource
			for i := range snap {
				s := &snap[i]
				if !s.matches(h, nil, enc, m.Topic) {
					continue
				}
				if rm := max(s.mode, ua.MessageSecurityModeNone); mode == ua.MessageSecurityModeInvalid || rm < mode {
					mode = rm
				}
				if s.mode > ua.MessageSecurityModeNone && ks == nil {
					ks = p.KeySource(s.groupID)
					keyGroup = s.groupID
				}
			}
			return max(mode, ua.MessageSecurityModeNone), ks, nil
		},
		MetaData: func(pub message.PublisherID, wgid, dswid uint16) *ua.DataSetMetaDataType {
			return p.lookupMetaData(snap, pub, wgid, dswid)
		},
	}

	isMeta := false
	for i := range snap {
		if snap[i].metaTopic != "" && m.Topic != "" && topicMatch(snap[i].metaTopic, m.Topic) {
			isMeta = true
		}
	}
	if enc == encJSON && (isMeta || isJSONMetaData(m.Payload)) {
		var md *jsonmsg.MetaDataMessage
		var err error
		if p.protect("decode", func() { md, err = cd.DecodeMetaData(m.Payload, opts) }) {
			err = errDecodePanic
		}
		if err != nil {
			p.decodeFailed(c, gen, snap, hdr, err)
			return
		}
		p.applyMetaData(c, gen, md.PublisherID, md.DataSetWriterID, md.MetaData, ua.MessageSecurityModeNone, "")
		return
	}
	if enc == encJSON {
		// Headerless JSON messages: the writer follows from the topic.
		var only *readerSnap
		n := 0
		for i := range snap {
			if snap[i].topic != "" && m.Topic != "" && topicMatch(snap[i].topic, m.Topic) {
				only = &snap[i]
				n++
			}
		}
		if n == 1 {
			opts.DataSetWriterID = only.dswid
			if only.hasPub {
				pub := only.pub
				opts.PublisherID = &pub
			}
		}
	}
	var nm *message.NetworkMessage
	var err error
	if p.protect("decode", func() { nm, err = cd.Decode(m.Payload, opts) }) {
		err = errDecodePanic
	}
	if err != nil {
		if errors.Is(err, uadp.ErrFiltered) {
			return
		}
		p.decodeFailed(c, gen, snap, hdr, err)
		return
	}
	got := securityOf(nm)
	if nm.Type == message.NetworkMessageDiscoveryResponse {
		p.lock()
		if c.gen == gen {
			p.countReceived(hdr, got, keyGroup)
		}
		p.unlock()
		if d := nm.Discovery; d != nil && d.Type == message.DiscoveryDataSetMetaData && d.MetaData != nil {
			p.applyMetaData(c, gen, nm.PublisherID, d.DataSetWriterID, d.MetaData, securityOf(nm), keyGroup)
		}
		return
	}
	if nm.Type != message.NetworkMessageDataSet {
		return
	}
	p.lock()
	defer p.unlock()
	if c.gen != gen {
		return
	}
	p.countReceived(hdr, got, keyGroup)
	for _, dsm := range nm.Messages {
		for i := range snap {
			s := &snap[i]
			if !s.matches(nm, dsm, enc, m.Topic) || !s.secured(got, keyGroup) {
				continue
			}
			r := s.r
			if !r.running || r.group.state != ua.PubSubStateOperational {
				continue
			}
			p.processDSM(r, nm, dsm, enc, recv)
		}
	}
}

// securityOf returns the security mode of a received NetworkMessage.
func securityOf(nm *message.NetworkMessage) ua.MessageSecurityMode {
	switch h := nm.Security; {
	case h == nil || !h.Signed:
		return ua.MessageSecurityModeNone
	case h.Encrypted:
		return ua.MessageSecurityModeSignAndEncrypt
	default:
		return ua.MessageSecurityModeSign
	}
}

// secured tells whether a message secured with mode by the keys of the
// SecurityGroup keyGroup satisfies the security a reader requires.
func (s *readerSnap) secured(mode ua.MessageSecurityMode, keyGroup string) bool {
	if s.mode <= ua.MessageSecurityModeNone {
		return true
	}
	return mode >= s.mode && s.groupID == keyGroup
}

// countReceived counts a received NetworkMessage for the reader groups of the
// readers whose filter its header matched and whose security it satisfies
// (ReceivedNetworkMessages, Part 14 §9.1.11.10). p.mu is held.
func (p *PubSub) countReceived(hdr []*readerSnap, got ua.MessageSecurityMode, keyGroup string) {
	var done []*readerGroup
	for _, s := range hdr {
		g := s.r.group
		if !s.secured(got, keyGroup) || slices.Contains(done, g) {
			continue
		}
		done = append(done, g)
		p.count(&g.base, CounterReceivedNetworkMessages, 1)
	}
}

// decodeFailed records a message that could not be decoded. hdr are the
// readers whose filter its header matched (none if the header could not be
// decoded: then all readers of the connection are concerned). A failure of
// the message security counts as a DecryptionError of the secured readers
// and of their groups, any other as a ReceivedInvalidNetworkMessage of the
// groups (Part 14 §9.1.11.10, §9.1.11.12).
func (p *PubSub) decodeFailed(c *connection, gen uint64, snap []readerSnap, hdr []*readerSnap, err error) {
	if len(hdr) == 0 {
		for i := range snap {
			hdr = append(hdr, &snap[i])
		}
	}
	sec := isSecurityError(err)
	p.lock()
	c.ctr.DecodeErrors++
	c.err = err
	if c.gen == gen {
		var done []*readerGroup
		for _, s := range hdr {
			if sec && s.mode <= ua.MessageSecurityModeNone {
				continue
			}
			if sec {
				p.count(&s.r.base, CounterDecryptionErrors, 1)
			}
			g := s.r.group
			if slices.Contains(done, g) {
				continue
			}
			done = append(done, g)
			if sec {
				p.count(&g.base, CounterDecryptionErrors, 1)
			} else {
				p.count(&g.base, CounterReceivedInvalidNetworkMessages, 1)
			}
		}
	}
	p.unlock()
	p.log.Debug("pubsub: decode failed", "connection", c.name, "error", err)
}

// lookupMetaData returns the DataSetMetaData of the reader that takes the
// messages of a writer. Without a PayloadHeader the writer id is 0.
func (p *PubSub) lookupMetaData(snap []readerSnap, pub message.PublisherID, wgid, dswid uint16) *ua.DataSetMetaDataType {
	p.lock()
	defer p.unlock()
	// The reader with the most specific filter: an unfiltered reader may
	// have learned the metadata of any writer.
	var best *ua.DataSetMetaDataType
	bestScore := -1
	for i := range snap {
		s := &snap[i]
		if s.hasPub && !samePublisher(s.pub, pub) {
			continue
		}
		if s.wgid != 0 && wgid != 0 && s.wgid != wgid {
			continue
		}
		if s.dswid != 0 && dswid != 0 && s.dswid != dswid {
			continue
		}
		if s.r.md == nil {
			continue
		}
		score := 0
		if s.hasPub {
			score++
		}
		if s.wgid != 0 {
			score++
		}
		if s.dswid != 0 {
			score++
		}
		if score > bestScore {
			best, bestScore = s.r.md, score
		}
	}
	return best
}

// applyMetaData updates the readers of a connection that take the messages
// of a writer with DataSetMetaData received from it. mode and keyGroup are
// the security of the message the DataSetMetaData came with: readers that
// require more do not take it.
func (p *PubSub) applyMetaData(c *connection, gen uint64, pub message.PublisherID, dswid uint16, md *ua.DataSetMetaDataType, mode ua.MessageSecurityMode, keyGroup string) {
	if md == nil {
		return
	}
	p.lock()
	defer p.unlock()
	if c.gen != gen {
		return
	}
	for _, g := range c.rgs {
		for _, r := range g.readers {
			if !r.running || (r.hasPub && !samePublisher(r.pub, pub)) || (r.cfg.DataSetWriterID != 0 && r.cfg.DataSetWriterID != dswid) {
				continue
			}
			if r.mode > ua.MessageSecurityModeNone && (mode < r.mode || r.groupID != keyGroup) {
				continue
			}
			r.ctr.MetaDataReceived++
			if r.md != nil && len(r.md.Fields) > 0 && sameVersion(r.md.ConfigurationVersion, md.ConfigurationVersion) {
				continue
			}
			cp, err := clone(md)
			if err != nil {
				continue
			}
			r.md = cp
			r.streams = map[streamKey]*stream{}
			p.log.Info("pubsub: reader metadata updated", "reader", r.name, "fields", len(cp.Fields))
		}
	}
}

func sameVersion(a, b *ua.ConfigurationVersionDataType) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.MajorVersion == b.MajorVersion && a.MinorVersion == b.MinorVersion
}

// Sequence number windows (Part 14 §7.2.2.3.4): a message is newer if it is
// less than a quarter of the number space ahead, older if less than a
// quarter behind, and resynchronises the reader otherwise.
const (
	seqWindow16 = 1 << 14
	seqWindow32 = 1 << 30
)

type seqVerdict uint8

const (
	seqNewer seqVerdict = iota
	seqDuplicate
	seqOlder
	seqResync
)

// compareSeq compares a received sequence number with the last one, with
// wraparound, in the 16 bits of UADP or the 32 bits of JSON.
func compareSeq(recv, last uint32, uadpSeq bool) seqVerdict {
	var d, n, w uint64
	if uadpSeq {
		d, n, w = uint64(uint16(recv-last)), 1<<16, seqWindow16
	} else {
		d, n, w = uint64(recv-last), 1<<32, seqWindow32
	}
	switch {
	case d == 0:
		return seqDuplicate
	case d < w:
		return seqNewer
	case d > n-w:
		return seqOlder
	default:
		return seqResync
	}
}

func hasSeq(dsm *message.DataSetMessage, enc encoding) bool {
	if enc == encJSON {
		return dsm.JSONMask&ua.JSONDataSetMessageContentMaskSequenceNumber != 0
	}
	return dsm.UADPMask&ua.UADPDataSetMessageContentMaskSequenceNumber != 0
}

func hasMajorVersion(dsm *message.DataSetMessage, enc encoding) bool {
	if enc == encJSON {
		return dsm.JSONMask&ua.JSONDataSetMessageContentMaskMetaDataVersion != 0
	}
	return dsm.UADPMask&ua.UADPDataSetMessageContentMaskMajorVersion != 0
}

// processDSM handles a DataSetMessage for a reader: sequence and version
// checks, state, merging of delta frames, delivery and target writes. p.mu is
// held.
func (p *PubSub) processDSM(r *dataSetReader, nm *message.NetworkMessage, dsm *message.DataSetMessage, enc encoding, recv time.Time) {
	if enc == encUADP && !dsm.Valid {
		return
	}
	pub, _ := pubOf(nm, dsm)
	wgid, _ := wgOf(nm)
	key := streamKey{pub: pub.String(), pt: pub.Type, wg: wgid, dsw: dsm.DataSetWriterID}
	st := r.streams[key]
	if st == nil {
		st = &stream{}
		r.streams[key] = st
	}
	keepAlive := dsm.Type == message.DataSetMessageKeepAlive
	if hasSeq(dsm, enc) {
		// UADP carries 16 bits; JSON publishers wrap at 16 bits as well
		// (open62541 rejects larger values), so both compare in 16 bits.
		seq := dsm.SequenceNumber & 0xffff
		if st.hasSeq {
			switch compareSeq(seq, st.seq, true) {
			case seqDuplicate:
				if !keepAlive {
					r.ctr.SequenceDiscards++
					return
				}
			case seqOlder:
				r.ctr.SequenceDiscards++
				return
			case seqResync:
				r.ctr.SequenceResyncs++
			case seqNewer:
			}
		}
		if !keepAlive {
			st.seq, st.hasSeq = seq, true
		}
	}
	if !keepAlive && r.md != nil && r.md.ConfigurationVersion != nil && r.md.ConfigurationVersion.MajorVersion != 0 &&
		hasMajorVersion(dsm, enc) && dsm.MetaDataVersion.MajorVersion != r.md.ConfigurationVersion.MajorVersion {
		r.ctr.VersionMismatches++
		p.count(&r.base, CounterFailedDataSetMessages, 1)
		return
	}

	r.lastRecv = recv
	p.armTimer(r)
	p.setState(&r.base, ua.PubSubStateOperational, nil)
	if keepAlive {
		r.ctr.KeepAlivesReceived++
		return
	}
	r.ctr.DataSetMessagesReceived++

	var mdFields []*ua.FieldMetaData
	if r.md != nil {
		mdFields = r.md.Fields
	}
	// The field index of a delta frame is bounded by the DataSet: its
	// DataSetMetaData or, without, the last key frame. Fields beyond it
	// are dropped; they must not size the DataSet.
	limit := max(len(dsm.Fields), len(mdFields))
	if dsm.Type == message.DataSetMessageDeltaFrame {
		limit = len(mdFields)
		if limit == 0 {
			limit = max(len(st.fields), len(dsm.Fields))
		}
	}
	idxs := make([]int, 0, len(dsm.Fields))
	msgFields := make([]*message.Field, 0, len(dsm.Fields))
	n := len(mdFields)
	for j, f := range dsm.Fields {
		i := fieldIndex(mdFields, f, j, dsm.Type, enc)
		if i < 0 || i >= limit {
			continue
		}
		idxs = append(idxs, i)
		msgFields = append(msgFields, f)
		if i >= n {
			n = i + 1
		}
	}
	if len(msgFields) < len(dsm.Fields) {
		r.ctr.DecodeErrors++
		p.count(&r.base, CounterFailedDataSetMessages, 1)
	}
	r.diag.lastStatus = dsm.Status
	if hasSeq(dsm, enc) {
		r.diag.lastSeq = uint16(dsm.SequenceNumber)
	}
	var fields []*ua.DataValue
	complete := true
	switch dsm.Type {
	case message.DataSetMessageKeyFrame:
		st.fields = make([]*ua.DataValue, n)
		st.key = true
	case message.DataSetMessageDeltaFrame:
		for len(st.fields) < n {
			st.fields = append(st.fields, nil)
		}
		complete = st.key
	case message.DataSetMessageEvent, message.DataSetMessageKeepAlive:
	}
	if dsm.Type == message.DataSetMessageEvent {
		fields = make([]*ua.DataValue, n)
	} else {
		fields = st.fields
	}
	for j, f := range msgFields {
		fields[idxs[j]] = normalizeValue(f.Value, mdFields, idxs[j])
	}

	ds := &ReceivedDataSet{
		Reader:          r.id,
		ReaderName:      r.name,
		PublisherID:     pub,
		WriterGroupID:   wgid,
		DataSetWriterID: dsm.DataSetWriterID,
		Status:          dsm.Status,
		MessageType:     dsm.Type,
		MetaDataVersion: dsm.MetaDataVersion,
		Changed:         idxs,
		Complete:        complete,
	}
	if hasSeq(dsm, enc) {
		ds.SequenceNumber = dsm.SequenceNumber
	}
	if wgid == 0 {
		ds.WriterGroupID = r.cfg.WriterGroupID
	}
	switch {
	case !dsm.Timestamp.IsZero():
		ds.Timestamp = dsm.Timestamp
	case !nm.Timestamp.IsZero():
		ds.Timestamp = nm.Timestamp
	default:
		ds.Timestamp = recv
	}
	if !hasMajorVersion(dsm, enc) && r.md != nil && r.md.ConfigurationVersion != nil {
		ds.MetaDataVersion = *r.md.ConfigurationVersion
	}
	ds.Fields = make([]ReceivedField, n)
	for i := range n {
		rf := ReceivedField{Index: i}
		if i < len(fields) && fields[i] != nil {
			v := *fields[i]
			rf.Value = &v
		}
		if i < len(mdFields) {
			rf.Name = mdFields[i].Name
		}
		ds.Fields[i] = rf
	}
	for j, f := range msgFields {
		if ds.Fields[idxs[j]].Name == "" {
			ds.Fields[idxs[j]].Name = f.Name
		}
	}

	if hs := p.opts.dataSetHandlers; len(hs) > 0 {
		p.later(func() {
			for _, h := range hs {
				h(ds)
			}
		})
	}
	p.writeTargets(r, ds)
	if r.mirror != nil {
		if mw, ok := p.opts.targetWriter.(MirrorWriter); ok {
			m := &MirrorWrite{Reader: r.id, ReaderName: r.name, Mirror: r.mirror, MetaData: r.md, Fields: ds.Fields, Changed: ds.Changed}
			ctx := p.ctx
			p.later(func() {
				if err := mw.WriteMirror(ctx, m); err != nil {
					p.targetErrors(r, []error{err})
				}
			})
		}
	}
}

// fieldIndex returns the DataSet index of the j-th field of a message: by
// name if the message names it (JSON), by the index of a delta frame, by
// position otherwise. UADP carries no field names: the names the decoder
// gives the fields come from the DataSetMetaData of some reader of the
// writer, not necessarily this one's.
func fieldIndex(md []*ua.FieldMetaData, f *message.Field, j int, t message.DataSetMessageType, enc encoding) int {
	if f.Name != "" && enc == encJSON {
		for i, m := range md {
			if m != nil && m.Name == f.Name {
				return i
			}
		}
	}
	if t == message.DataSetMessageDeltaFrame {
		return int(f.Index)
	}
	return j
}

// normalizeValue turns a field received with the Variant encoding whose
// value is a StatusCode in place of the value (a Bad status) back into a
// DataValue with that status.
func normalizeValue(dv *ua.DataValue, md []*ua.FieldMetaData, i int) *ua.DataValue {
	if dv == nil {
		return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadNoData}
	}
	if dv.Value != nil && dv.Value.Type() == ua.TypeIDStatusCode && i < len(md) && md[i] != nil && md[i].BuiltInType != uint8(ua.TypeIDStatusCode) {
		if sc, ok := dv.Value.Value().(ua.StatusCode); ok && isBad(sc) {
			return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: sc}
		}
	}
	return dv
}

// targetIndex returns the DataSet field a target variable takes: the field
// with its DataSetFieldId, or the field at its position.
func (r *dataSetReader) targetIndex(j int) int {
	t := r.targets[j]
	if hasFieldID(t.DataSetFieldID) && r.md != nil {
		for i, f := range r.md.Fields {
			if f != nil && sameGUID(f.DataSetFieldID, t.DataSetFieldID) {
				return i
			}
		}
		return -1
	}
	return j
}

// writeTargets writes the fields of a received DataSet to the target
// variables of a reader, applying the OverrideValueHandling to Bad values.
// p.mu is held; the writes run after it is released.
func (p *PubSub) writeTargets(r *dataSetReader, ds *ReceivedDataSet) {
	tw := p.opts.targetWriter
	if tw == nil || len(r.targets) == 0 {
		return
	}
	changed := map[int]bool{}
	for _, i := range ds.Changed {
		changed[i] = true
	}
	var writes []TargetWrite
	for j, t := range r.targets {
		i := r.targetIndex(j)
		if i < 0 || i >= len(ds.Fields) || !changed[i] || ds.Fields[i].Value == nil {
			continue
		}
		dv := ds.Fields[i].Value
		if t.ReceiverIndexRange != "" && dv.Value != nil {
			v, sc := ua.SliceVariantRead(dv.Value, t.ReceiverIndexRange)
			if sc != ua.StatusOK {
				r.ctr.TargetWriteErrors++
				continue
			}
			cp := *dv
			cp.Value = v
			dv = &cp
		}
		if isBad(dv.Status) {
			switch t.OverrideValueHandling {
			case ua.OverrideValueHandlingLastUsableValue:
				if r.lastGood[j] != nil {
					dv = lastUsable(r.lastGood[j])
				}
			case ua.OverrideValueHandlingOverrideValue:
				dv = overrideValue(t)
			case ua.OverrideValueHandlingDisabled:
			}
		} else {
			r.lastGood[j] = dv
		}
		writes = append(writes, TargetWrite{Reader: r.id, Target: t, Value: dv})
	}
	p.submitWrites(r, writes)
}

func lastUsable(dv *ua.DataValue) *ua.DataValue {
	out := &ua.DataValue{Value: dv.Value, Status: ua.StatusUncertainLastUsableValue, SourceTimestamp: dv.SourceTimestamp}
	out.UpdateMask()
	return out
}

func overrideValue(t *ua.FieldTargetDataType) *ua.DataValue {
	out := &ua.DataValue{Value: t.OverrideValue, SourceTimestamp: time.Now()}
	out.UpdateMask()
	return out
}

// applyOverrides writes the override values of the target variables of a
// reader that stopped being Operational (Error after a timeout, Paused,
// Disabled). p.mu is held.
func (p *PubSub) applyOverrides(r *dataSetReader) {
	if p.opts.targetWriter == nil {
		return
	}
	var writes []TargetWrite
	for j, t := range r.targets {
		switch t.OverrideValueHandling {
		case ua.OverrideValueHandlingLastUsableValue:
			if r.lastGood[j] != nil {
				writes = append(writes, TargetWrite{Reader: r.id, Target: t, Value: lastUsable(r.lastGood[j])})
			}
		case ua.OverrideValueHandlingOverrideValue:
			if variantValue(t.OverrideValue) != nil {
				writes = append(writes, TargetWrite{Reader: r.id, Target: t, Value: overrideValue(t)})
			}
		case ua.OverrideValueHandlingDisabled:
		}
	}
	p.submitWrites(r, writes)
}

func (p *PubSub) submitWrites(r *dataSetReader, writes []TargetWrite) {
	if len(writes) == 0 {
		return
	}
	tw := p.opts.targetWriter
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	p.later(func() {
		p.targetErrors(r, tw.WriteTargets(ctx, writes))
	})
}

func (p *PubSub) targetErrors(r *dataSetReader, errs []error) {
	var n uint64
	var last error
	for _, err := range errs {
		if err != nil {
			n++
			last = err
		}
	}
	if n == 0 {
		return
	}
	p.lock()
	r.ctr.TargetWriteErrors += n
	r.err = last
	p.unlock()
	p.log.Debug("pubsub: target write failed", "reader", r.name, "error", last)
}
