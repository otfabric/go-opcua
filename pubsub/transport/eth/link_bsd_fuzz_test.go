// SPDX-License-Identifier: MIT

//go:build darwin || freebsd

package eth

import (
	"testing"
	"unsafe"
)

// FuzzBPFRecords feeds an arbitrary read buffer of a BPF device to the
// record parser: it must not panic, must terminate, and every frame it
// returns must lie inside the buffer, after a record header.
func FuzzBPFRecords(f *testing.F) {
	frame := append(header(macA, macB, Address{}), "payload"...)
	f.Add(bpfRecord(frame, len(frame)))
	f.Add(append(bpfRecord(frame, len(frame)), bpfRecord(frame[:20], len(frame))...))
	f.Add(append(bpfRecord(frame, len(frame)), bpfRecord(nil, 0)...))
	f.Add(bpfRecord(frame, len(frame))[:bpfMinHdr+3])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, buf []byte) {
		l := &bpfLink{pending: buf}
		for i := 0; ; i++ {
			if i > len(buf) {
				t.Fatalf("no progress after %d records", i)
			}
			rec, ok := l.next()
			if !ok {
				break
			}
			if len(rec) == 0 {
				continue
			}
			off := int(uintptr(unsafe.Pointer(&rec[0])) - uintptr(unsafe.Pointer(&buf[0])))
			if off < bpfMinHdr || off+len(rec) > len(buf) {
				t.Fatalf("frame of %d bytes at %d outside the buffer of %d bytes", len(rec), off, len(buf))
			}
		}
		if len(l.pending) != 0 {
			t.Fatalf("%d bytes left pending after the parser gave up", len(l.pending))
		}
	})
}
