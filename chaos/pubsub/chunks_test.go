// SPDX-License-Identifier: MIT

package pubsubchaos

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// Chunked NetworkMessages (Part 14 §7.2.4.4.4) under loss, duplication,
// reordering, interleaving, forged chunks and floods: the reassembly must
// stay within its limits, free the state of incomplete messages after the
// timeout, and never hand out a message other than the one that was sent.

const chunkNMMask = ua.UADPNetworkMessageContentMaskPublisherID | ua.UADPNetworkMessageContentMaskGroupHeader |
	ua.UADPNetworkMessageContentMaskWriterGroupID | ua.UADPNetworkMessageContentMaskSequenceNumber |
	ua.UADPNetworkMessageContentMaskPayloadHeader

// chunkValue is the field of the message seq of writer w of publisher pub:
// size bytes that differ for every message.
func chunkValue(pub uint64, w, seq uint16, size int) string {
	b := make([]byte, size)
	for i := range b {
		b[i] = 'a' + byte((uint64(i)*7+pub*13+uint64(w)*31+uint64(seq)*17)%26)
	}
	return string(b)
}

// chunkNM returns the NetworkMessage of chunkValue.
func chunkNM(pub uint64, w, seq uint16, size int) *message.NetworkMessage {
	return &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    chunkNMMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, pub),
		GroupHeader: message.GroupHeader{WriterGroupID: 1, SequenceNumber: seq},
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: w,
			Valid:           true,
			UADPMask:        ua.UADPDataSetMessageContentMaskSequenceNumber,
			FieldEncoding:   message.FieldEncodingVariant,
			SequenceNumber:  uint32(seq),
			Fields:          []*message.Field{{Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(chunkValue(pub, w, seq, size))}}},
		}},
	}
}

type chunkKey struct {
	pub     uint64
	w, seq  uint16
	size    int
	forged  bool
	encoded int
}

// decodedChunk is a received chunk with the message it belongs to.
type decodedChunk struct {
	nm  *message.NetworkMessage
	key chunkKey
}

// TestChaosChunkReassembler feeds the chunks of many messages of several
// publishers and writers to a Reassembler with small limits: dropped,
// duplicated, reordered and interleaved, mixed with forged chunks (random
// offsets and sizes, of other publishers and of the real ones) and with
// pauses beyond the timeout. At every step the Reassembler must stay within
// its limits; every message it completes must be the one sent (unless a
// forged chunk of the same message got in, which unsecured chunks cannot
// prevent) and decode; a message whose chunks all arrived in time must
// complete; and once the timeout has passed, Expire must leave nothing
// behind.
func TestChaosChunkReassembler(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	opts := uadp.ReassemblerOptions{
		MaxMessageSize:       32 << 10,
		MaxChunks:            128,
		MaxPendingMessages:   12,
		MaxPendingBytes:      160 << 10,
		MaxPublisherMessages: 5,
		MaxPublisherBytes:    80 << 10,
		Timeout:              300 * time.Millisecond,
	}
	r := uadp.NewReassembler(&opts)
	now := time.Unix(1_700_000_000, 0)
	seqs := map[[2]uint64]uint16{}
	forgedKeys := map[chunkKey]bool{} // messages a forged chunk was aimed at
	var completed, complete, lost int

	check := func(step string) {
		st := r.Stats()
		if st.Pending > opts.MaxPendingMessages || st.PendingBytes > opts.MaxPendingBytes || st.Pending < 0 || st.PendingBytes < 0 {
			t.Fatalf("%s: limits exceeded: %+v", step, st)
		}
	}

	end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
	for round := 0; round < 4 || time.Now().Before(end); round++ {
		clean := round%4 == 0
		var pool []decodedChunk
		var sentMsgs []chunkKey
		for range 1 + rng.Intn(6) {
			pub := uint64(1 + rng.Intn(3))
			w := uint16(1 + rng.Intn(3))
			k := [2]uint64{pub, uint64(w)}
			seqs[k]++
			key := chunkKey{pub: pub, w: w, seq: seqs[k], size: 200 + rng.Intn(12000)}
			chunks, err := uadp.EncodeChunks(chunkNM(pub, w, key.seq, key.size), nil, 64+rng.Intn(1400))
			if err != nil {
				t.Fatal(err)
			}
			key.encoded = len(chunks)
			sentMsgs = append(sentMsgs, key)
			for _, b := range chunks {
				nm, err := uadp.Decode(b, nil)
				if err != nil || nm.Chunk == nil {
					t.Fatalf("chunk does not decode: %v", err)
				}
				pool = append(pool, decodedChunk{nm, key})
			}
		}
		if !clean {
			// Loss, duplicates and forged chunks.
			var out []decodedChunk
			for _, c := range pool {
				if rng.Float64() < 0.1 {
					continue
				}
				out = append(out, c)
				if rng.Float64() < 0.1 {
					out = append(out, c)
				}
				if rng.Float64() < 0.1 {
					out = append(out, forgeChunk(rng, c, forgedKeys))
				}
			}
			pool = out
		}
		// Reorder: shuffle within windows, interleaving the messages.
		win := 1 + rng.Intn(8)
		for i := 0; i < len(pool); i += win {
			j := min(i+win, len(pool))
			rng.Shuffle(j-i, func(a, b int) { pool[i+a], pool[i+b] = pool[i+b], pool[i+a] })
		}
		got := map[chunkKey]bool{}
		for _, c := range pool {
			now = now.Add(time.Duration(rng.Intn(500)) * time.Microsecond)
			p, _, err := r.Add(c.nm, now)
			if err != nil && !errors.Is(err, uadp.ErrChunkRejected) {
				t.Fatalf("Add: %v", err)
			}
			check("add")
			if p == nil {
				continue
			}
			completed++
			k := c.key
			if k.forged {
				continue
			}
			if int(c.nm.Chunk.TotalSize) != len(p) {
				t.Fatalf("message %+v: %d bytes for TotalSize %d", k, len(p), c.nm.Chunk.TotalSize)
			}
			if forgedKeys[k] {
				continue
			}
			got[k] = true
			dec, err := uadp.DecodeReassembled(c.nm, p, nil)
			if err != nil {
				t.Fatalf("message %+v does not decode after reassembly: %v", k, err)
			}
			if len(dec.Messages) != 1 || len(dec.Messages[0].Fields) != 1 {
				t.Fatalf("message %+v: %d DataSetMessages", k, len(dec.Messages))
			}
			v, _ := dec.Messages[0].Fields[0].Value.Value.Value().(string)
			if v != chunkValue(k.pub, k.w, k.seq, k.size) || dec.Messages[0].DataSetWriterID != k.w || uint16(dec.Messages[0].SequenceNumber) != k.seq {
				t.Fatalf("message %+v: reassembled into something else (%d bytes)", k, len(v))
			}
		}
		for _, k := range sentMsgs {
			switch {
			case got[k]:
				complete++
			case clean && !forgedKeys[k] && len(sentMsgs) <= opts.MaxPublisherMessages && k.encoded <= opts.MaxChunks:
				// Every chunk arrived within the timeout and no limit
				// applies (a message of more than MaxChunks chunks is
				// rejected): the message must be complete.
				t.Fatalf("round %d: message %+v (%d chunks) was not reassembled; stats %+v", round, k, k.encoded, r.Stats())
			default:
				lost++
			}
		}
		if rng.Intn(5) == 0 {
			// A pause beyond the timeout: the next Add expires the
			// incomplete messages.
			now = now.Add(opts.Timeout + time.Millisecond)
		}
	}
	r.Expire(now.Add(opts.Timeout + time.Millisecond))
	st := r.Stats()
	if st.Pending != 0 || st.PendingBytes != 0 {
		t.Fatalf("state left after the timeout: %+v", st)
	}
	t.Logf("%d messages complete, %d lost to faults, %d payloads; %+v", complete, lost, completed, st)
	if complete == 0 {
		t.Fatal("no message was reassembled")
	}
}

// forgeChunk returns a forged chunk modelled on c: for another publisher,
// or for the same message with a random offset, size or TotalSize.
func forgeChunk(rng *rand.Rand, c decodedChunk, aimed map[chunkKey]bool) decodedChunk {
	cp := *c.nm
	ch := *c.nm.Chunk
	cp.Chunk = &ch
	k := c.key
	k.forged = true
	switch rng.Intn(4) {
	case 0: // another publisher, random message
		cp.PublisherID = message.NewPublisherID(message.PublisherIDUInt16, uint64(100+rng.Intn(50)))
		ch.MessageSequenceNumber = uint16(rng.Intn(1 << 16))
		ch.TotalSize = uint32(1 + rng.Intn(40000))
		ch.ChunkOffset = uint32(rng.Intn(int(ch.TotalSize)))
	case 1: // the same message, another TotalSize
		ch.TotalSize = uint32(rng.Intn(40000))
		aimed[c.key] = true
	case 2: // the same message, a random offset
		ch.ChunkOffset = uint32(rng.Intn(int(ch.TotalSize) + 10))
		aimed[c.key] = true
	default: // the same message, other data
		d := make([]byte, rng.Intn(len(ch.Data)+20))
		rng.Read(d)
		ch.Data = d
		aimed[c.key] = true
	}
	return decodedChunk{&cp, k}
}

// chunkedPair is a publisher and a subscriber of big data sets over a
// memnet segment: the DataSetMessages are about bigSize bytes and the
// MaxNetworkMessageSize of the writer group makes them chunks.
type chunkedPair struct {
	seg      *memSegment
	pub, sub *pubsub.PubSub
	chk      *checker
	readers  []string
}

func newChunkedPair(t *testing.T, seed int64, mode ua.MessageSecurityMode, maxSize uint32, ro uadp.ReassemblerOptions) *chunkedPair {
	t.Helper()
	p := &chunkedPair{seg: mnet.segment(memURL(t)), chk: newChecker()}
	p.seg.seed(seed)
	var pdss []*ua.PublishedDataSetDataType
	var ws []*ua.DataSetWriterDataType
	var rs []*ua.DataSetReaderDataType
	for i := range 2 {
		ds := fmt.Sprintf("%s%d", bigPrefix, i)
		pds := counterPDS(ds)
		pdss = append(pdss, pds)
		ws = append(ws, pubsub.DataSetWriter("w"+ds, uint16(i+1), ds))
		r := pubsub.DataSetReader(ds, uint16(7), 1, uint16(i+1), pubsub.DataSetMetaDataOf(pds))
		r.MessageReceiveTimeout = 2000
		rs = append(rs, r)
		p.readers = append(p.readers, ds)
	}
	wg := pubsub.WriterGroup("wg", 1, 10*time.Millisecond, ws...)
	wg.MaxNetworkMessageSize = maxSize
	rg := pubsub.ReaderGroup("rg", rs...)
	var keys []pubsub.Option
	if mode > ua.MessageSecurityModeNone {
		ks := keyService(t, "sg", security.PolicyURIAes256CTR, time.Hour, 2, 2)
		pubsub.Secure(wg, mode, "sg")
		pubsub.Secure(rg, mode, "sg")
		keys = append(keys, pubsub.WithKeySource("sg", keySource(t, ks, "sg")))
	}
	p.sub = startRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("sub", p.seg.url, nil), rg)),
		append([]pubsub.Option{pubsub.WithDataSetHandler(p.chk.handle), pubsub.WithChunkReassembly(ro), pubsub.WithDiscovery(pubsub.DiscoveryOptions{Disabled: true})}, keys...)...)
	p.pub = startRuntime(t, pubsub.NewConfiguration(pdss, pubsub.AttachWriterGroups(pubsub.UDPConnection("pub", p.seg.url, uint16(7)), wg)),
		append([]pubsub.Option{pubsub.WithDataSource(newCounterSource()), pubsub.WithDiscovery(pubsub.DiscoveryOptions{Disabled: true})}, keys...)...)
	return p
}

// TestChaosChunkedNetwork runs chunked data sets (unsecured and
// SignAndEncrypt) over an in-memory network that drops, duplicates,
// reorders, delays, truncates and (secured) corrupts the chunks, while a
// flooder sends forged chunks: of other publishers, and - secured - of the
// real one. The subscriber must never deliver a corrupt, duplicate or
// stale data set, its reassembly must discard what does not fit, and it
// must deliver again once the faults stop.
func TestChaosChunkedNetwork(t *testing.T) {
	t.Parallel()
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeNone, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			seed := chaoskit.Seed(t)
			rng := rand.New(rand.NewSource(seed))
			secured := mode > ua.MessageSecurityModeNone
			ro := uadp.ReassemblerOptions{MaxMessageSize: 16 << 10, MaxPendingMessages: 16, MaxPublisherMessages: 6, Timeout: 250 * time.Millisecond}
			p := newChunkedPair(t, seed, mode, 512, ro)
			p.chk.waitGrowth(t, 5, p.readers...)

			// The flooder: forged chunks at about 2 kHz.
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var forged atomic.Int64
			wg.Add(1)
			go func() {
				defer wg.Done()
				frng := rand.New(rand.NewSource(seed + 1))
				tk := time.NewTicker(time.Millisecond)
				defer tk.Stop()
				for {
					select {
					case <-stop:
						return
					case <-tk.C:
					}
					pub := uint64(100 + frng.Intn(1000))
					if secured && frng.Intn(2) == 0 {
						pub = 7 // fails the signature
					}
					b, err := forgedChunkBytes(frng, pub)
					if err != nil {
						continue
					}
					p.seg.inject(b)
					p.seg.inject(b)
					forged.Add(2)
				}
			}()

			end := time.Now().Add(chaoskit.Duration(t, defaultDuration))
			for time.Now().Before(end) {
				f, hold := randomFaults(rng, secured, 2*time.Second)
				if f.blackhole {
					f, hold = faults{drop: 0.5}, 300*time.Millisecond
				}
				t.Logf("%s: %v for %v", time.Now().Format("15:04:05.000"), f, hold)
				p.seg.set(f)
				time.Sleep(hold)
			}
			p.seg.set(faults{})
			close(stop)
			wg.Wait()

			p.chk.waitGrowth(t, 10, p.readers...)
			for _, r := range p.readers {
				waitState(t, p.sub, compID(t, p.sub, pubsub.KindDataSetReader, r), ua.PubSubStateOperational)
			}
			sc, pc := status(t, p.sub, pubsub.Root).Counters, status(t, p.pub, pubsub.Root).Counters
			t.Logf("segment: sent %d delivered %d dropped %d, forged %d", p.seg.sent.Load(), p.seg.delivered.Load(), p.seg.dropped.Load(), forged.Load())
			t.Logf("publisher: %+v", pc)
			t.Logf("subscriber: %+v", sc)
			if pc.ChunksSent == 0 || sc.ChunkedMessagesReceived == 0 {
				t.Errorf("no chunks: sent %d, reassembled %d", pc.ChunksSent, sc.ChunkedMessagesReceived)
			}
			if sc.ChunksDiscarded == 0 {
				t.Errorf("%d forged chunks, none discarded", forged.Load())
			}
			if pc.EncodeErrors != 0 {
				t.Errorf("%d encode errors", pc.EncodeErrors)
			}
			p.chk.sink.Report(t)
		})
	}
}

// forgedChunkBytes encodes a chunk of a message of pub that was never
// sent, with random sizes.
func forgedChunkBytes(rng *rand.Rand, pub uint64) ([]byte, error) {
	data := make([]byte, 1+rng.Intn(400))
	rng.Read(data)
	total := uint32(len(data) + rng.Intn(1<<15))
	nm := &message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		UADPMask:    chunkNMMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, pub),
		GroupHeader: message.GroupHeader{WriterGroupID: 1, SequenceNumber: uint16(rng.Intn(1 << 16))},
		Messages:    []*message.DataSetMessage{{DataSetWriterID: uint16(1 + rng.Intn(2))}},
		Chunk: &message.Chunk{
			MessageSequenceNumber: uint16(rng.Intn(1 << 16)),
			ChunkOffset:           uint32(rng.Intn(int(total - uint32(len(data)) + 1))),
			TotalSize:             total,
			Data:                  data,
		},
	}
	return uadp.Encode(nm, nil)
}
