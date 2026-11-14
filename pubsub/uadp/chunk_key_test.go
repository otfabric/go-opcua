// SPDX-License-Identifier: MIT

package uadp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
)

// keyString is a string of n bytes that differs for each i.
func keyString(i, n int) string {
	s := fmt.Sprintf("%08d", i)
	return s + strings.Repeat("k", n-len(s))
}

// TestReassemblerChargesKeyStrings: the first stored chunk of a message is
// charged with the strings of its key, so first chunks of one data byte
// with the longest String PublisherId, String RequestorId and
// CorrelationData the decoder accepts keep the pending bytes, and the live
// heap, within MaxPendingBytes. It does not run in parallel: it measures
// the live heap.
func TestReassemblerChargesKeyStrings(t *testing.T) {
	opts := &ReassemblerOptions{MaxMessageSize: 16, MaxChunks: 16, MaxPendingMessages: 512, MaxPendingBytes: 1 << 20, MaxPublisherBytes: 64 << 10}
	const charge = 1 + chunkOverhead + 2*maxKeyString + maxActionString
	t0 := time.Unix(100, 0)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	r := NewReassembler(opts)
	for i := range opts.MaxPendingMessages {
		m := chunk(0, 1, 0, 2, []byte{1})
		m.PublisherID = message.StringPublisherID(keyString(i, maxKeyString))
		requestor := message.StringPublisherID(keyString(i, maxActionString))
		m.Action = &message.ActionHeader{Type: message.ActionRequest, RequestorID: &requestor, CorrelationData: []byte(keyString(i, maxKeyString))}
		_, _, err := r.Add(m, t0)
		require.NoError(t, err)
		st := r.Stats()
		require.LessOrEqual(t, st.PendingBytes, r.opts.MaxPendingBytes)
		require.Equal(t, st.Pending*charge, st.PendingBytes, "%d first chunks", i+1)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	st := r.Stats()
	require.Equal(t, r.opts.MaxPendingBytes/charge, st.Pending)
	require.Less(t, int64(after.HeapAlloc)-int64(before.HeapAlloc), int64(r.opts.MaxPendingBytes+1<<20), "live heap of %d pending messages", st.Pending)
	runtime.KeepAlive(r)

	// The charge goes with the message.
	r.Reset()
	require.Zero(t, r.Stats().PendingBytes)
	m := chunk(0, 1, 0, 2, []byte{1})
	m.PublisherID = message.StringPublisherID("p")
	_, _, err := r.Add(m, t0)
	require.NoError(t, err)
	require.Equal(t, 1+chunkOverhead+1, r.Stats().PendingBytes, "first chunk")
	m = chunk(0, 1, 1, 2, []byte{2})
	m.PublisherID = message.StringPublisherID("p")
	payload, _, err := r.Add(m, t0)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, payload)
	require.Zero(t, r.Stats().PendingBytes, "after the last chunk")
}

// TestDecodeKeyStringBounds is the boundary table of the lengths of a
// String PublisherId and of the CorrelationData of an ActionHeader: at most
// maxKeyString bytes, and never more than the input holds.
func TestDecodeKeyStringBounds(t *testing.T) {
	t.Parallel()
	const marker = "\xa5\x5a\xc3\x3c"
	encode := func(t *testing.T, pub string, corr []byte) []byte {
		t.Helper()
		nm := actionRequestNM()
		nm.PublisherID = message.StringPublisherID(pub)
		nm.Action.CorrelationData = corr
		b, err := Encode(nm, nil)
		require.NoError(t, err)
		return b
	}
	// declared replaces the length of the string marker in b; the null
	// length -1 also removes the marker.
	declared := func(t *testing.T, b []byte, n uint32) []byte {
		t.Helper()
		at := bytes.Index(b, append(binary.LittleEndian.AppendUint32(nil, uint32(len(marker))), marker...))
		require.GreaterOrEqual(t, at, 0)
		rest := b[at+4:]
		if n == 0xffffffff {
			rest = rest[len(marker):]
		}
		return append(binary.LittleEndian.AppendUint32(bytes.Clone(b[:at]), n), rest...)
	}
	for _, n := range []int{0, 1, maxKeyString - 1, maxKeyString, maxKeyString + 1, 2 * maxKeyString} {
		ok := n <= maxKeyString
		s := strings.Repeat("p", n)
		got, err := Decode(encode(t, s, []byte{1}), nil)
		if ok {
			require.NoError(t, err, "String PublisherId of %d bytes", n)
			require.Equal(t, s, got.PublisherID.Str)
		} else {
			require.ErrorIs(t, err, ErrMalformed, "String PublisherId of %d bytes", n)
		}
		got, err = Decode(encode(t, "p", []byte(s)), nil)
		if ok {
			require.NoError(t, err, "CorrelationData of %d bytes", n)
			require.Equal(t, []byte(s), append([]byte{}, got.Action.CorrelationData...))
		} else {
			require.ErrorIs(t, err, ErrMalformed, "CorrelationData of %d bytes", n)
		}
	}
	// Declared lengths: -1 is a null string, the others are more than the
	// input holds.
	for _, n := range []uint32{0xffffffff, maxKeyString + 1, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe} {
		for name, b := range map[string][]byte{
			"String PublisherId": encode(t, marker, []byte{1}),
			"CorrelationData":    encode(t, "p", []byte(marker)),
		} {
			got, err := Decode(declared(t, b, n), nil)
			if n == 0xffffffff {
				require.NoError(t, err, "%s of declared length %#x", name, n)
				if name == "String PublisherId" {
					require.Empty(t, got.PublisherID.Str)
				} else {
					require.NotNil(t, got.Action.CorrelationData)
					require.Empty(t, got.Action.CorrelationData)
				}
				continue
			}
			require.ErrorIs(t, err, ErrMalformed, "%s of declared length %#x", name, n)
		}
	}
}
