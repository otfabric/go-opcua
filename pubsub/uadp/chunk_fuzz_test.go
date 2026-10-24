// SPDX-License-Identifier: MIT

package uadp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// FuzzDecodeChunks feeds arbitrary bytes to Decode and every chunk it accepts
// to a Reassembler and, with the bytes of the chunk as its only content, to
// DecodeReassembled; discovery probes it accepts are encoded again. None may
// panic, and the Reassembler must stay within its limits.
func FuzzDecodeChunks(f *testing.F) {
	chunks, err := EncodeChunks(chunkNM(), nil, 29)
	if err != nil {
		f.Fatal(err)
	}
	for _, c := range chunks {
		f.Add(c)
	}
	f.Add([]byte{0x91, 0x80, 0x09, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00})
	f.Add([]byte{0x91, 0x80, 0x04, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00})
	f.Add([]byte{0x91, 0x80, 0x04, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00})
	f.Add([]byte{0x91, 0x80, 0x04, 0x01, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x75, 0x01, 0x00})
	r := NewReassembler(&ReassemblerOptions{MaxMessageSize: 1 << 12, MaxChunks: 64, MaxPendingMessages: 8, MaxPublisherMessages: 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		nm, err := Decode(b, nil)
		if err != nil {
			return
		}
		if nm.Request != nil || nm.Discovery != nil {
			if _, err := Encode(nm, nil); err != nil {
				t.Fatalf("decoded discovery message does not encode: %v", err)
			}
		}
		if nm.Chunk == nil {
			return
		}
		if p, _, err := r.Add(nm, time.Unix(0, 0)); err == nil && p != nil {
			if len(p) != int(nm.Chunk.TotalSize) {
				t.Fatalf("reassembled %d bytes of %d", len(p), nm.Chunk.TotalSize)
			}
			_, _ = DecodeReassembled(nm, p, nil)
		}
		_, _ = DecodeReassembled(nm, nm.Chunk.Data, nil)
		if st := r.Stats(); st.Pending > 8 || st.PendingBytes > r.opts.MaxPendingBytes {
			t.Fatalf("limits exceeded: %+v", st)
		}
	})
}

// FuzzReassembler adds chunks described by the input, 9 bytes each: the
// publisher and the MessageSequenceNumber (a Byte each), the offset and the
// size of the chunk (UInt16 each), two unused bytes and the TotalSize (a
// Byte, in units of 8 bytes). The data of a chunk is that of a reference
// message, so every message the Reassembler returns must be the reference,
// whatever the order, the duplicates, the overlaps and the evictions.
func FuzzReassembler(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 4, 0, 0, 0, 1, 1, 0, 4, 0, 4, 0, 0, 0, 1})
	f.Add([]byte{1, 0, 4, 0, 4, 0, 0, 0, 1, 1, 0, 0, 0, 4, 0, 0, 0, 1, 2, 0, 0, 0, 2, 0, 0, 0, 1})
	ref := func(seq uint16, total int) []byte {
		out := make([]byte, total)
		for i := range out {
			out[i] = byte(i*7) ^ byte(seq) ^ byte(total)
		}
		return out
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		const maxSize = 255 * 8
		r := NewReassembler(&ReassemblerOptions{MaxMessageSize: maxSize, MaxChunks: 64, MaxPendingMessages: 6, MaxPublisherMessages: 3, Timeout: 50 * time.Millisecond})
		now := time.Unix(0, 0)
		for len(in) >= 9 {
			pub := uint64(in[0] % 4)
			seq := uint16(in[1] % 4)
			off := int(binary.LittleEndian.Uint16(in[2:]))
			n := int(binary.LittleEndian.Uint16(in[4:]))
			total := int(in[8]) * 8
			in = in[9:]
			now = now.Add(time.Millisecond)
			var data []byte
			if total > 0 && off < total {
				data = ref(seq, total)[off:min(off+n, total)]
			}
			p, _, err := r.Add(chunk(pub, seq, uint32(off), uint32(total), data), now)
			if err != nil && !errors.Is(err, ErrChunkRejected) {
				t.Fatal(err)
			}
			if p != nil && !bytes.Equal(p, ref(seq, total)) {
				t.Fatalf("reassembled %x, want %x", p, ref(seq, total))
			}
			st := r.Stats()
			if st.Pending > 6 || st.PendingBytes > r.opts.MaxPendingBytes {
				t.Fatalf("limits exceeded: %+v", st)
			}
			for k, u := range r.pubs {
				if u.msgs > 3 || u.bytes > r.opts.MaxPublisherBytes || u.msgs <= 0 {
					t.Fatalf("publisher %v: %+v", k, u)
				}
			}
		}
	})
}
