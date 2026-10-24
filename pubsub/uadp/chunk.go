// SPDX-License-Identifier: MIT

package uadp

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

// A chunk NetworkMessage (Part 14 §7.2.4.4.4 in 1.05) carries a piece of one
// DataSetMessage (an ActionRequest or ActionResponse among them, with the
// ActionHeader in every chunk) or of one discovery announcement. It has the headers of a
// NetworkMessage with the chunk bit of ExtendedFlags2; its PayloadHeader, if
// present, is only the DataSetWriterId of the DataSetMessage (Table 158), and
// its payload (Table 159), behind the security header, is
//
//	MessageSequenceNumber UInt16
//	ChunkOffset           UInt32
//	TotalSize             UInt32
//	ChunkData             ByteString
//
// Every chunk is secured on its own: it is signed and its payload encrypted
// like that of any NetworkMessage, with a MessageNonce of its own. All chunks
// but the last have the same size. EncodeChunks copies the other headers
// (PublisherId, DataSetClassId, GroupHeader, Timestamp, PicoSeconds,
// PromotedFields) into every chunk and gives each chunk the next GroupHeader
// SequenceNumber and NetworkMessageNumber, as the OPC Foundation .NET stack
// (2.x, UadpChunker) does; open62541 1.5.9 neither sends nor accepts chunks.

func writeChunk(b *ua.Buffer, c *message.Chunk) {
	b.WriteUint16(c.MessageSequenceNumber)
	b.WriteUint32(c.ChunkOffset)
	b.WriteUint32(c.TotalSize)
	// An empty ChunkData is written with length 0, not as the null
	// ByteString: Decode rejects both, but the length stays what
	// EncodeChunks computed with.
	b.WriteUint32(uint32(len(c.Data)))
	b.Write(c.Data)
}

func decodeChunk(data []byte) (*message.Chunk, error) {
	b := ua.NewBuffer(data)
	c := &message.Chunk{
		MessageSequenceNumber: b.ReadUint16(),
		ChunkOffset:           b.ReadUint32(),
		TotalSize:             b.ReadUint32(),
	}
	n := int64(int32(b.ReadUint32()))
	if b.Error() != nil {
		return nil, malformed("truncated chunk")
	}
	switch {
	case n <= 0:
		return nil, malformed("chunk without data")
	case n != int64(b.Len()):
		return nil, malformed("chunk data of %d bytes, %d left", n, b.Len())
	case c.TotalSize == 0 || uint64(c.ChunkOffset)+uint64(n) > uint64(c.TotalSize):
		return nil, malformed("chunk of %d bytes at %d of a message of %d bytes", n, c.ChunkOffset, c.TotalSize)
	}
	c.Data = b.ReadN(int(n))
	return c, nil
}

// EncodeChunks encodes nm as chunk NetworkMessages of at most maxSize bytes
// each, security included. nm is a NetworkMessage of type
// NetworkMessageDataSet with exactly one DataSetMessage (an action message
// too), or a discovery announcement; discovery probes are not chunked. Use it for a NetworkMessage
// that Encode makes larger than maxSize.
//
// The MessageSequenceNumber of the chunks is the low 16 bits of the
// SequenceNumber of the DataSetMessage, or the SequenceNumber of the
// announcement. Chunk i carries the GroupHeader SequenceNumber and
// NetworkMessageNumber of nm plus i: the caller advances its counters by the
// number of chunks. A secured chunk takes its MessageNonce from
// opts.NextNonceSequence, or from opts.NonceSequence plus i.
func EncodeChunks(nm *message.NetworkMessage, opts *EncodeOptions, maxSize int) ([][]byte, error) {
	if nm == nil {
		return nil, fmt.Errorf("%w: nil NetworkMessage", ErrMalformed)
	}
	if opts == nil {
		opts = &EncodeOptions{}
	}
	if nm.Chunk != nil {
		return nil, malformed("NetworkMessage is a chunk already")
	}
	body := ua.NewBuffer(nil)
	var seq uint16
	base := *nm
	switch nm.Type {
	case message.NetworkMessageDataSet:
		if len(nm.Messages) != 1 || nm.Messages[0] == nil {
			return nil, malformed("a chunked NetworkMessage carries one DataSetMessage, not %d", len(nm.Messages))
		}
		if nm.Action != nil {
			if err := checkAction(nm); err != nil {
				return nil, err
			}
		}
		e := &encoder{nm: nm, opts: opts}
		if err := e.encodeDataSetMessage(body, nm.Messages[0]); err != nil {
			return nil, err
		}
		seq = uint16(nm.Messages[0].SequenceNumber)
		base.Messages = []*message.DataSetMessage{{DataSetWriterID: nm.Messages[0].DataSetWriterID}}
	case message.NetworkMessageDiscoveryResponse:
		if nm.Discovery == nil {
			return nil, malformed("discovery announcement without body")
		}
		if err := encodeDiscovery(body, nm.Discovery); err != nil {
			return nil, err
		}
		seq = nm.Discovery.SequenceNumber
		base.Messages = nil
	default:
		return nil, malformed("a NetworkMessage of type %d is not chunked", nm.Type)
	}
	if body.Error() != nil {
		return nil, malformed("payload: %v", body.Error())
	}
	payload := body.Bytes()
	if uint64(len(payload)) > uint64(^uint32(0)) {
		return nil, malformed("message of %d bytes", len(payload))
	}

	// The overhead of a chunk: its headers and chunk fields, plus the
	// security header and the signature.
	base.Chunk = &message.Chunk{}
	empty, err := Encode(&base, &EncodeOptions{})
	if err != nil {
		return nil, err
	}
	overhead := len(empty)
	if sec, err := securityOverhead(opts); err != nil {
		return nil, err
	} else {
		overhead += sec
	}
	size := maxSize - overhead
	if size < 1 {
		return nil, malformed("a chunk of at most %d bytes has no room for data (%d bytes of headers)", maxSize, overhead)
	}

	n := (len(payload) + size - 1) / size
	out := make([][]byte, 0, n)
	for i := range n {
		off := i * size
		end := min(off+size, len(payload))
		c := base
		c.Chunk = &message.Chunk{MessageSequenceNumber: seq, ChunkOffset: uint32(off), TotalSize: uint32(len(payload)), Data: payload[off:end]}
		c.GroupHeader.SequenceNumber += uint16(i)
		c.GroupHeader.NetworkMessageNumber += uint16(i)
		o := *opts
		if o.NextNonceSequence == nil {
			o.NonceSequence += uint32(i)
		}
		b, err := Encode(&c, &o)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// securityOverhead returns the bytes the security adds to a NetworkMessage:
// the security header and the signature.
func securityOverhead(opts *EncodeOptions) (int, error) {
	if opts.SecurityMode <= ua.MessageSecurityModeNone {
		return 0, nil
	}
	if opts.Keys == nil || opts.Keys.Policy() == nil {
		return 0, secError("security mode %v without keys", opts.SecurityMode)
	}
	p := opts.Keys.Policy()
	// SecurityFlags, SecurityTokenId, NonceLength, MessageNonce.
	return 1 + 4 + 1 + p.MessageNonceLength() + p.SignatureLength(), nil
}

// DecodeReassembled decodes the message reassembled from the chunks of
// header, a chunk NetworkMessage returned by Decode: the DataSetMessage of
// its writer, or the discovery announcement. The headers, security included,
// are those of header; its security was checked chunk by chunk. Only
// opts.MetaData is used. The returned NetworkMessage has no Chunk.
func DecodeReassembled(header *message.NetworkMessage, payload []byte, opts *DecodeOptions) (*message.NetworkMessage, error) {
	if header == nil || header.Chunk == nil {
		return nil, malformed("not a chunk NetworkMessage")
	}
	if opts == nil {
		opts = &DecodeOptions{}
	}
	nm := *header
	nm.Chunk = nil
	nm.Messages = nil
	d := &decoder{b: bytes.Clone(payload), opts: opts}
	switch nm.Type {
	case message.NetworkMessageDataSet:
		m := &message.DataSetMessage{}
		if len(header.Messages) > 0 && header.Messages[0] != nil {
			m.DataSetWriterID = header.Messages[0].DataSetWriterID
		}
		nm.Messages = []*message.DataSetMessage{m}
		if err := d.decodeDataSetMessage(&nm, m, d.b); err != nil {
			return nil, err
		}
		if err := checkActionMessages(&nm); err != nil {
			return nil, err
		}
	case message.NetworkMessageDiscoveryResponse:
		disc, err := decodeDiscovery(d.b)
		if err != nil {
			return nil, err
		}
		nm.Discovery = disc
	default:
		return nil, malformed("chunk of a NetworkMessage of type %d", nm.Type)
	}
	return &nm, nil
}

// ErrChunkRejected is returned by [Reassembler.Add] for a chunk it discards:
// one outside its message, of a size the layout of the message does not
// allow, a duplicate, one of a message beyond the limits, or one there is no
// room for. It is wrapped with the reason.
var ErrChunkRejected = errors.New("pubsub/uadp: chunk rejected")

// Defaults of [ReassemblerOptions].
const (
	DefaultMaxReassembledSize   = 2 << 20
	DefaultMaxChunks            = 8192
	DefaultMaxPendingMessages   = 512
	DefaultMaxPendingBytes      = 32 << 20
	DefaultMaxPublisherMessages = 64
	DefaultMaxPublisherBytes    = 8 << 20
	DefaultReassemblyTimeout    = 5 * time.Second
	chunkOverhead               = 64
)

// ReassemblerOptions bound the memory of a [Reassembler]. Zero values select
// the defaults. Chunks arrive unauthenticated if the messages are not
// secured: the limits keep a sender from making the receiver hold more than
// MaxPendingBytes, and a single PublisherId from taking more than its share.
// Every stored chunk is charged its size plus a fixed 64 bytes.
type ReassemblerOptions struct {
	// MaxMessageSize is the largest TotalSize accepted (default 2 MiB).
	MaxMessageSize int
	// MaxChunks is the largest number of chunks of one message (default
	// 8192): it bounds the bookkeeping of tiny chunks.
	MaxChunks int
	// MaxPendingMessages and MaxPendingBytes limit the incomplete
	// messages of all publishers (default 512 and 32 MiB).
	MaxPendingMessages int
	MaxPendingBytes    int
	// MaxPublisherMessages and MaxPublisherBytes limit the incomplete
	// messages of one PublisherId (default 64 and 8 MiB). They are raised
	// to what one message of MaxMessageSize needs.
	MaxPublisherMessages int
	MaxPublisherBytes    int
	// Timeout is how long an incomplete message waits for its missing
	// chunks, counted from its first chunk (default 5 seconds).
	Timeout time.Duration
}

func (o *ReassemblerOptions) normalize() ReassemblerOptions {
	var n ReassemblerOptions
	if o != nil {
		n = *o
	}
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&n.MaxMessageSize, DefaultMaxReassembledSize)
	def(&n.MaxChunks, DefaultMaxChunks)
	def(&n.MaxPendingMessages, DefaultMaxPendingMessages)
	def(&n.MaxPendingBytes, DefaultMaxPendingBytes)
	def(&n.MaxPublisherMessages, DefaultMaxPublisherMessages)
	def(&n.MaxPublisherBytes, DefaultMaxPublisherBytes)
	if n.Timeout <= 0 {
		n.Timeout = DefaultReassemblyTimeout
	}
	// One complete message must fit the limits.
	n.MaxPublisherBytes = max(n.MaxPublisherBytes, n.MaxMessageSize+chunkOverhead*min(n.MaxChunks, n.MaxMessageSize))
	n.MaxPendingBytes = max(n.MaxPendingBytes, n.MaxPublisherBytes)
	n.MaxPendingMessages = max(n.MaxPendingMessages, n.MaxPublisherMessages)
	return n
}

// ReassemblerStats are the counters of a [Reassembler].
type ReassemblerStats struct {
	// Pending and PendingBytes are the incomplete messages and the bytes
	// charged for them.
	Pending      int
	PendingBytes int
	// Completed counts the reassembled messages (a message of a single
	// chunk included).
	Completed uint64
	// Rejected counts the chunks Add rejected.
	Rejected uint64
	// Expired and Evicted count the incomplete messages dropped after the
	// Timeout and to make room for others; Dropped counts their chunks.
	Expired uint64
	Evicted uint64
	Dropped uint64
}

// Reassembler reassembles chunked NetworkMessages. Chunks are kept per
// PublisherId, WriterGroupId, DataSetWriterId, NetworkMessage type, security
// mode and MessageSequenceNumber; the chunks of a message may arrive in any
// order and interleaved with those of other messages. It is safe for
// concurrent use.
type Reassembler struct {
	opts ReassemblerOptions

	mu      sync.Mutex
	pending map[reasmKey]*reasmEntry
	order   *list.List // of *reasmEntry, oldest first
	pubs    map[pubKey]*pubUsage
	bytes   int
	stats   ReassemblerStats
}

type pubKey struct {
	has bool
	typ message.PublisherIDType
	num uint64
	str string
}

type reasmKey struct {
	pub    pubKey
	wg     uint16
	typ    message.NetworkMessageType
	hasDSW bool
	dsw    uint16
	mode   ua.MessageSecurityMode
	seq    uint16
	// The ActionHeader of an action message: requests of several
	// Requestors to one writer, and the responses to them, are told
	// apart by the RequestorId and the CorrelationData.
	act       message.ActionMessageType
	requestor pubKey
	corr      string
}

type pubUsage struct{ msgs, bytes int }

type reasmEntry struct {
	key     reasmKey
	created time.Time
	elem    *list.Element
	total   int
	// size is the size of all chunks but the last, 0 until the first of
	// them arrived; lastIdx is then the index of the last chunk.
	size    int
	lastIdx int
	slots   map[int][]byte
	// A last chunk that arrives before the size is known.
	lastOff  int
	lastData []byte
	received int
	chunks   int
	charged  int
}

// NewReassembler returns a Reassembler with the given limits (nil: the
// defaults).
func NewReassembler(opts *ReassemblerOptions) *Reassembler {
	return &Reassembler{
		opts:    opts.normalize(),
		pending: map[reasmKey]*reasmEntry{},
		order:   list.New(),
		pubs:    map[pubKey]*pubUsage{},
	}
}

func rejected(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrChunkRejected}, args...)...)
}

func keyOf(nm *message.NetworkMessage) reasmKey {
	k := reasmKey{typ: nm.Type, seq: nm.Chunk.MessageSequenceNumber, mode: modeOf(nm.Security)}
	if nm.UADPMask&ua.UADPNetworkMessageContentMaskPublisherID != 0 {
		k.pub = pubKey{has: true, typ: nm.PublisherID.Type, num: nm.PublisherID.Num, str: nm.PublisherID.Str}
	}
	if nm.UADPMask&ua.UADPNetworkMessageContentMaskGroupHeader != 0 && nm.UADPMask&ua.UADPNetworkMessageContentMaskWriterGroupID != 0 {
		k.wg = nm.GroupHeader.WriterGroupID
	}
	if nm.Type == message.NetworkMessageDataSet && nm.UADPMask&ua.UADPNetworkMessageContentMaskPayloadHeader != 0 && len(nm.Messages) > 0 && nm.Messages[0] != nil {
		k.hasDSW, k.dsw = true, nm.Messages[0].DataSetWriterID
	}
	if a := nm.Action; a != nil {
		k.act, k.corr = a.Type, string(a.CorrelationData)
		if r := a.RequestorID; r != nil {
			k.requestor = pubKey{has: true, typ: r.Type, num: r.Num, str: r.Str}
		}
	}
	return k
}

// Add adds a chunk NetworkMessage returned by Decode, received at now. It
// returns the reassembled message, to be decoded with DecodeReassembled,
// once the chunk completes it, and nil while chunks are missing. A chunk it
// discards returns an error wrapping ErrChunkRejected. dropped is the number
// of chunks of incomplete messages Add dropped because they expired or to
// make room. The returned payload does not reference nm.
func (r *Reassembler) Add(nm *message.NetworkMessage, now time.Time) (payload []byte, dropped int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if nm == nil || nm.Chunk == nil {
		r.stats.Rejected++
		return nil, 0, rejected("not a chunk")
	}
	c := nm.Chunk
	dropped = r.expireLocked(now)
	payload, err = r.addLocked(nm, c, now, &dropped)
	if err != nil {
		r.stats.Rejected++
	}
	return payload, dropped, err
}

func (r *Reassembler) addLocked(nm *message.NetworkMessage, c *message.Chunk, now time.Time, dropped *int) ([]byte, error) {
	n := len(c.Data)
	switch {
	case n == 0:
		return nil, rejected("chunk without data")
	case c.TotalSize == 0 || uint64(c.TotalSize) > uint64(r.opts.MaxMessageSize):
		return nil, rejected("message of %d bytes, at most %d are accepted", c.TotalSize, r.opts.MaxMessageSize)
	case uint64(c.ChunkOffset)+uint64(n) > uint64(c.TotalSize):
		return nil, rejected("chunk of %d bytes at %d of a message of %d bytes", n, c.ChunkOffset, c.TotalSize)
	}
	total, off := int(c.TotalSize), int(c.ChunkOffset)
	last := off+n == total
	key := keyOf(nm)
	e := r.pending[key]
	isNew := e == nil
	if isNew {
		if off == 0 && last {
			r.stats.Completed++
			return bytes.Clone(c.Data), nil
		}
		e = &reasmEntry{key: key, created: now, total: total, slots: map[int][]byte{}}
	} else if e.total != total {
		return nil, rejected("TotalSize %d, the message has %d bytes", total, e.total)
	}
	if err := e.accept(off, n, last, r.opts.MaxChunks); err != nil {
		return nil, err
	}
	charge := n + chunkOverhead
	if !r.makeRoomLocked(key.pub, e, charge, isNew, dropped) {
		return nil, rejected("no room for the chunk (%d bytes pending)", r.bytes)
	}
	if isNew {
		r.pending[key] = e
		e.elem = r.order.PushBack(e)
		r.usage(key.pub).msgs++
	}
	e.store(off, bytes.Clone(c.Data), last)
	e.charged += charge
	r.bytes += charge
	r.usage(key.pub).bytes += charge
	if e.received < e.total {
		return nil, nil
	}
	r.removeLocked(e)
	r.stats.Completed++
	return e.assemble(), nil
}

func (r *Reassembler) usage(k pubKey) *pubUsage {
	u := r.pubs[k]
	if u == nil {
		u = &pubUsage{}
		r.pubs[k] = u
	}
	return u
}

// makeRoomLocked evicts the oldest incomplete messages, those of the same
// publisher first, until a chunk of charge bytes (and, for a new message,
// the message) fits the limits. The message the chunk belongs to is never
// evicted.
func (r *Reassembler) makeRoomLocked(pub pubKey, cur *reasmEntry, charge int, isNew bool, dropped *int) bool {
	newMsg := 0
	if isNew {
		newMsg = 1
	}
	fitsPub := func() bool {
		u := r.pubs[pub]
		if u == nil {
			return true
		}
		return u.bytes+charge <= r.opts.MaxPublisherBytes && u.msgs+newMsg <= r.opts.MaxPublisherMessages
	}
	fitsAll := func() bool {
		return r.bytes+charge <= r.opts.MaxPendingBytes && len(r.pending)+newMsg <= r.opts.MaxPendingMessages
	}
	for !fitsPub() {
		if !r.evictOldestLocked(cur, func(e *reasmEntry) bool { return e.key.pub == pub }, dropped) {
			return false
		}
	}
	for !fitsAll() {
		if !r.evictOldestLocked(cur, func(*reasmEntry) bool { return true }, dropped) {
			return false
		}
	}
	return true
}

func (r *Reassembler) evictOldestLocked(cur *reasmEntry, match func(*reasmEntry) bool, dropped *int) bool {
	for el := r.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*reasmEntry)
		if e == cur || !match(e) {
			continue
		}
		r.removeLocked(e)
		r.stats.Evicted++
		r.stats.Dropped += uint64(e.chunks)
		*dropped += e.chunks
		return true
	}
	return false
}

func (r *Reassembler) removeLocked(e *reasmEntry) {
	delete(r.pending, e.key)
	if e.elem != nil {
		r.order.Remove(e.elem)
		e.elem = nil
	}
	r.bytes -= e.charged
	if u := r.pubs[e.key.pub]; u != nil {
		u.msgs--
		u.bytes -= e.charged
		if u.msgs <= 0 {
			delete(r.pubs, e.key.pub)
		}
	}
}

// expireLocked drops the incomplete messages older than the Timeout and
// returns the number of their chunks.
func (r *Reassembler) expireLocked(now time.Time) int {
	n := 0
	for el := r.order.Front(); el != nil; {
		e := el.Value.(*reasmEntry)
		if now.Sub(e.created) < r.opts.Timeout {
			// Entries are in the order of their first chunk.
			break
		}
		el = el.Next()
		r.removeLocked(e)
		r.stats.Expired++
		r.stats.Dropped += uint64(e.chunks)
		n += e.chunks
	}
	return n
}

// Expire drops the incomplete messages that waited longer than the Timeout
// at now and returns the number of their chunks. Add expires messages as
// well; Expire releases their memory when no chunks arrive.
func (r *Reassembler) Expire(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.expireLocked(now)
}

// Reset drops all incomplete messages. It does not count them.
func (r *Reassembler) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.pending)
	clear(r.pubs)
	r.order.Init()
	r.bytes = 0
}

// Stats returns the counters.
func (r *Reassembler) Stats() ReassemblerStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stats
	st.Pending = len(r.pending)
	st.PendingBytes = r.bytes
	return st
}

// accept checks a chunk against the layout of its message ("All chunks,
// except for the last one shall have the same size", Part 14 §7.2.4.4.4 in
// 1.05) and rejects duplicates, without changing the entry.
func (e *reasmEntry) accept(off, n int, last bool, maxChunks int) error {
	if e.size == 0 {
		if last {
			if e.lastData != nil {
				return rejected("duplicate last chunk")
			}
			return nil
		}
		count := (e.total + n - 1) / n
		switch {
		case off%n != 0:
			return rejected("chunk of %d bytes at offset %d", n, off)
		case count > maxChunks:
			return rejected("message of %d chunks, at most %d are accepted", count, maxChunks)
		case e.lastData != nil && e.lastOff != (count-1)*n:
			return rejected("chunk of %d bytes does not fit the last chunk at %d", n, e.lastOff)
		}
		return nil
	}
	if off%e.size != 0 {
		return rejected("chunk at offset %d, the chunks have %d bytes", off, e.size)
	}
	i := off / e.size
	switch {
	case last && i != e.lastIdx:
		return rejected("last chunk at offset %d, expected at %d", off, e.lastIdx*e.size)
	case !last && n != e.size:
		return rejected("chunk of %d bytes, the chunks have %d", n, e.size)
	}
	if _, dup := e.slots[i]; dup {
		return rejected("duplicate chunk at offset %d", off)
	}
	return nil
}

func (e *reasmEntry) store(off int, data []byte, last bool) {
	e.chunks++
	e.received += len(data)
	if e.size == 0 {
		if last {
			e.lastOff, e.lastData = off, data
			return
		}
		e.size = len(data)
		e.lastIdx = (e.total+e.size-1)/e.size - 1
		if e.lastData != nil {
			e.slots[e.lastIdx] = e.lastData
			e.lastData = nil
		}
	}
	e.slots[off/e.size] = data
}

func (e *reasmEntry) assemble() []byte {
	out := make([]byte, e.total)
	for i, d := range e.slots {
		copy(out[i*e.size:], d)
	}
	return out
}
