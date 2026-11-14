// SPDX-License-Identifier: MIT

package amqp

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// allocatedBytes returns the number of bytes fn allocates.
func allocatedBytes(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// nestedLists returns total bytes that start with an amqp-value section
// whose value is a list32 nested depth deep. Every list has all the bytes
// that follow it as its size and declares one element per byte, the most a
// compound of that size can declare.
func nestedLists(total, depth int) []byte {
	b := make([]byte, total)
	b[0], b[1], b[2] = codeDescribed, codeSmallUlong, byte(descAMQPValue)
	off := 3
	for range depth {
		b[off] = codeList32
		size := uint32(total - off - 5)
		binary.BigEndian.PutUint32(b[off+1:], size)
		binary.BigEndian.PutUint32(b[off+5:], size)
		off += 9
	}
	return b
}

// TestDecodeAllocationIsProportionalToInput: the elements that the
// compounds and arrays of an input declare are counted against the length of
// the input, at all nesting levels together, so the slices allocated for
// them stay within a fixed multiple of the input whatever its nesting.
func TestDecodeAllocationIsProportionalToInput(t *testing.T) {
	const factor = 32
	for _, tt := range []struct {
		name         string
		total, depth int
	}{
		{"one frame, one level", 64 << 10, 1},
		{"one frame, nested to the depth limit", 64 << 10, MaxDepth - 1},
		{"largest PubSub message, one level", 1<<20 + 64<<10, 1},
		{"largest PubSub message, nested to the depth limit", 1<<20 + 64<<10, MaxDepth - 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := nestedLists(tt.total, tt.depth)

			var m Message
			var err error
			n := allocatedBytes(func() { err = m.UnmarshalBinary(in) })
			require.ErrorIs(t, err, ErrProtocol)
			require.Less(t, n, uint64(factor*len(in)), "UnmarshalBinary: bytes allocated for %d bytes of input", len(in))

			n = allocatedBytes(func() { _, _, err = DecodeValue(in) })
			require.ErrorIs(t, err, ErrProtocol)
			require.Less(t, n, uint64(factor*len(in)), "DecodeValue: bytes allocated for %d bytes of input", len(in))

			// The same value where a frame carries its performative.
			n = allocatedBytes(func() { err = DecodeFrameBody(&Frame{Type: FrameAMQP}, in) })
			require.ErrorIs(t, err, ErrProtocol)
			require.Less(t, n, uint64(factor*len(in)), "DecodeFrameBody: bytes allocated for %d bytes of input", len(in))
		})
	}

	t.Run("arrays of a zero-width type nested in their descriptors", func(t *testing.T) {
		// An array32 of described nulls declares as many elements as it has
		// bytes; its descriptor is such an array again, and the innermost
		// descriptor is a long symbol.
		in := append([]byte{codeSym32, 0, 1, 0, 0}, make([]byte, 64<<10)...)
		for range MaxDepth/2 - 1 {
			size := uint32(4 + 1 + len(in) + 1)
			a := []byte{codeArray32}
			a = binary.BigEndian.AppendUint32(a, size)
			a = binary.BigEndian.AppendUint32(a, size)
			a = append(a, codeDescribed)
			a = append(a, in...)
			in = append(a, codeNull)
		}
		var err error
		n := allocatedBytes(func() { _, _, err = DecodeValue(in) })
		require.ErrorIs(t, err, ErrProtocol)
		require.Less(t, n, uint64(factor*len(in)), "bytes allocated for %d bytes of input", len(in))
	})
}

// TestElementBudgetBoundaries is the boundary table of the element budget:
// an input whose compounds and arrays declare exactly as many elements as
// the budget has is decoded, one element more is refused.
func TestElementBudgetBoundaries(t *testing.T) {
	list := func(elems ...[]byte) []byte {
		body := []byte{byte(len(elems))}
		for _, e := range elems {
			body = append(body, e...)
		}
		return append([]byte{codeList8, byte(len(body))}, body...)
	}
	null := []byte{codeNull}
	for _, tt := range []struct {
		name     string
		in       []byte
		declared int
	}{
		{"empty list", list(), 0},
		{"list of one", list(null), 1},
		{"list of three", list(null, null, null), 3},
		{"lists in a list", list(list(null, null), list(null, null)), 6},
		{"three levels", list(list(list(null))), 3},
		{"map of two pairs", []byte{codeMap8, 5, 4, codeNull, codeNull, codeNull, codeNull}, 4},
		{"array of a zero-width type", []byte{codeArray8, 2, 2, codeNull}, 2},
		{"array of bytes", []byte{codeArray8, 5, 3, codeUbyte, 1, 2, 3}, 3},
		{"array of lists", []byte{codeArray8, 6, 2, codeList8, 1, 0, 1, 0}, 2},
		{"described elements", []byte{codeArray8, 7, 2, codeDescribed, codeSmallUlong, 1, codeUbyte, 1, 2}, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The budget of the input itself is enough.
			require.LessOrEqual(t, tt.declared, len(tt.in))
			_, rest, err := DecodeValue(tt.in)
			require.NoError(t, err)
			require.Empty(t, rest)

			for _, budget := range []int{tt.declared, tt.declared + 1} {
				left := budget
				d := &decoder{b: tt.in, elems: &left}
				_, err := d.value()
				require.NoError(t, err, "budget %d", budget)
				require.Equal(t, budget-tt.declared, left, "budget left")
				require.Zero(t, d.depth)
			}
			if tt.declared == 0 {
				return
			}
			for _, budget := range []int{tt.declared - 1, 0} {
				left := budget
				d := &decoder{b: tt.in, elems: &left}
				_, err := d.value()
				require.ErrorIs(t, err, ErrProtocol, "budget %d", budget)
				require.GreaterOrEqual(t, left, 0)
			}
		})
	}
}

// TestMessageSectionsShareTheElementBudget: the sections of a message are
// decoded with one budget, the length of the message.
func TestMessageSectionsShareTheElementBudget(t *testing.T) {
	in := &Message{
		Header:                &Header{Durable: true, Priority: 4},
		MessageAnnotations:    map[Symbol]any{"a": uint32(1), "b": "x"},
		Properties:            &Properties{MessageID: "id", To: "queue", ContentType: "application/json"},
		ApplicationProperties: map[string]any{"k": int32(1)},
		Data:                  [][]byte{{1, 2, 3}},
	}
	b, err := in.MarshalBinary()
	require.NoError(t, err)

	var out Message
	require.NoError(t, out.UnmarshalBinary(b))
	require.Equal(t, in.Properties, out.Properties)
	require.Equal(t, in.Data, out.Data)

	// What the sections declare together is counted: with the decoder of
	// the message, the budget that is left is the length less the elements.
	dec := newDecoder(b)
	require.Equal(t, len(b), *dec.elems)
	sections := 0
	for len(dec.b) > 0 {
		_, err := dec.value()
		require.NoError(t, err)
		sections++
	}
	require.Equal(t, 5, sections)
	require.Less(t, *dec.elems, len(b))
	require.Greater(t, *dec.elems, 0)
}
