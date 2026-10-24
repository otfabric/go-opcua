// SPDX-License-Identifier: MIT

package amqp

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func roundTrip(t *testing.T, v any) any {
	t.Helper()
	b, err := AppendValue(nil, v)
	require.NoError(t, err, "%T", v)
	got, rest, err := DecodeValue(b)
	require.NoError(t, err, "%T % x", v, b)
	require.Empty(t, rest)
	return got
}

func TestValueRoundTrip(t *testing.T) {
	ts := time.UnixMilli(1700000000123).UTC()
	long := strings.Repeat("x", 300)
	same := []any{
		nil, true, false, uint8(7), uint16(65000), uint32(0), uint32(9), uint32(1 << 20),
		uint64(0), uint64(200), uint64(1 << 40), int8(-3), int16(-300), int32(5), int32(-1 << 20),
		int64(-5), int64(1 << 40), float32(1.5), 2.25, Decimal32{1, 2, 3, 4}, Decimal64{1},
		Decimal128{2}, Char('€'), ts, UUID{1, 2, 3}, []byte{1, 2}, []byte(long), "héllo", long,
		Symbol("sym"), Symbol(long), []any{}, []any{uint32(1), "a", []any{nil}},
		[]any{long, long}, Map{}, Map{{Key: Symbol("k"), Value: uint64(1)}, {Key: []byte{1}, Value: nil}},
		Map{{Key: "big", Value: long}},
		&Described{Descriptor: uint64(0x70), Value: []any{true}},
		&Described{Descriptor: Symbol("x:y"), Value: "v"},
		Array{}, Array{Symbol("a"), Symbol("b")}, Array{true, false}, Array{uint8(1)}, Array{uint16(1)},
		Array{uint32(1), uint32(1 << 20)}, Array{uint64(3)}, Array{int8(-1)}, Array{int16(-1)},
		Array{int32(-1)}, Array{int64(-1)}, Array{float32(1)}, Array{1.0}, Array{Char('a')},
		Array{ts}, Array{UUID{9}}, Array{[]byte{1}}, Array{"s", long}, Array{nil, nil},
	}
	for _, v := range same {
		require.Equal(t, v, roundTrip(t, v), "%#v", v)
	}
	require.Equal(t, int64(-200), roundTrip(t, -200))
	require.Equal(t, Array{int64(1), int64(2)}, roundTrip(t, Array{1, 2}))
	require.Equal(t, Array{Symbol("a")}, roundTrip(t, []Symbol{"a"}))
	require.Equal(t, &Described{Descriptor: uint64(1), Value: "v"}, roundTrip(t, Described{Descriptor: uint64(1), Value: "v"}))
	require.Nil(t, roundTrip(t, (*Described)(nil)))
	var big Array
	for i := range 300 {
		big = append(big, uint32(i))
	}
	require.Equal(t, big, roundTrip(t, big))

	m := Map{{Key: Symbol("a"), Value: 1}, {Key: []byte{1}, Value: 2}, {Key: []any{}, Value: 3}}
	v, ok := m.Get(Symbol("a"))
	require.True(t, ok)
	require.Equal(t, 1, v)
	_, ok = m.Get([]byte{1})
	require.False(t, ok)
	_, ok = m.Get("a")
	require.False(t, ok)
}

func TestValueEncodeErrors(t *testing.T) {
	for _, v := range []any{
		struct{}{}, []any{struct{}{}}, Map{{Key: struct{}{}}}, Map{{Key: "k", Value: struct{}{}}},
		Array{struct{}{}}, Array{"a", uint32(1)}, Array{[]any{}}, &Described{Descriptor: struct{}{}},
		&Described{Descriptor: uint64(1), Value: struct{}{}},
	} {
		_, err := AppendValue(nil, v)
		require.Error(t, err, "%#v", v)
	}
}

func TestDecodeMalformed(t *testing.T) {
	u32 := func(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for name, b := range map[string][]byte{
		"empty":                 {},
		"unknown constructor":   {0x99},
		"bool value":            {0x56, 2},
		"truncated bool":        {0x56},
		"truncated ubyte":       {0x50},
		"truncated short":       {0x61, 0},
		"truncated uint":        {0x70, 0, 0},
		"truncated ulong":       {0x80, 0},
		"truncated uuid":        {0x98, 1},
		"truncated str8 len":    {0xa1},
		"truncated str32 len":   {0xb1, 0, 0},
		"str8 past end":         {0xa1, 5, 'a'},
		"str32 past end":        cat([]byte{0xb1}, u32(math.MaxUint32), []byte("a")),
		"list8 no size":         {0xc0},
		"list8 size past end":   {0xc0, 9, 1},
		"list8 size zero":       {0xc0, 0},
		"list8 count over size": {0xc0, 1, 5},
		"list8 short element":   {0xc0, 2, 1, 0x70},
		"list8 trailing bytes":  {0xc0, 3, 1, 0x40, 0x40},
		"list32 small size":     cat([]byte{0xd0}, u32(2), []byte{0, 0}),
		"list32 huge count":     cat([]byte{0xd0}, u32(4), u32(math.MaxUint32)),
		"list32 no size":        {0xd0, 0},
		"map odd":               {0xc1, 2, 1, 0x40},
		"array no constructor":  {0xe0, 1, 0},
		"array count over size": {0xe0, 2, 200, 0x40},
		"array32 huge count":    cat([]byte{0xf0}, u32(5), u32(math.MaxUint32), []byte{0x40}),
		"array short element":   {0xe0, 3, 1, 0x70, 0},
		"array trailing":        {0xe0, 4, 1, 0x50, 1, 2},
		"array bad element":     {0xe0, 3, 1, 0x56, 7},
		"array nested desc":     {0xe0, 6, 1, 0x00, 0x53, 1, 0x00, 0},
		"array desc truncated":  {0xe0, 2, 1, 0x00},
		"array desc no elem":    {0xe0, 3, 1, 0x00, 0x40},
		"described no value":    {0x00, 0x53, 0x10},
		"described bad desc":    {0x00, 0xa1, 0, 0x40},
		"described no desc":     {0x00},
		"array32 no size":       {0xf0, 1},
	} {
		_, _, err := DecodeValue(b)
		require.ErrorIs(t, err, ErrProtocol, name)
	}
}

func TestDepthLimit(t *testing.T) {
	nest := func(n int) []byte {
		v := any(nil)
		for range n {
			v = []any{v}
		}
		b, err := AppendValue(nil, v)
		require.NoError(t, err)
		return b
	}
	_, _, err := DecodeValue(nest(MaxDepth))
	require.NoError(t, err)
	_, _, err = DecodeValue(nest(MaxDepth + 1))
	require.ErrorContains(t, err, "nested")
	// Described values count too, also as array element descriptors.
	b := []byte{}
	for range MaxDepth + 1 {
		b = append(b, 0x00, 0x53, 1)
	}
	_, _, err = DecodeValue(append(b, 0x40))
	require.ErrorContains(t, err, "nested")
	// So do arrays.
	b = []byte{}
	for range MaxDepth + 1 {
		b = append(b, 0x00, 0x53, 1)
	}
	b = append(b, 0xe0, 2, 0, 0x40)
	_, _, err = DecodeValue(b)
	require.ErrorContains(t, err, "nested")
	b = bytes.Repeat([]byte{0x00, 0x53, 1}, MaxDepth)
	b = append(b, 0xe0, 5, 1, 0x00, 0x53, 1, 0x40)
	_, _, err = DecodeValue(b)
	require.ErrorContains(t, err, "nested")
}

func frameRoundTrip(t *testing.T, f *Frame) *Frame {
	t.Helper()
	b, err := AppendFrame(nil, f)
	require.NoError(t, err)
	require.Equal(t, uint32(len(b)), FrameSize(b))
	got, err := ReadFrame(bytes.NewReader(b), uint32(len(b)))
	require.NoError(t, err)
	return got
}

func u32p(n uint32) *uint32 { return &n }

func TestPerformativesRoundTrip(t *testing.T) {
	rc := uint16(3)
	tr := true
	mode := ReceiverSettleSecond
	e := &Error{Condition: CondNotFound, Description: "d", Info: Map{{Key: Symbol("k"), Value: "v"}}}
	caps := []Symbol{"a", "b"}
	props := Map{{Key: Symbol("p"), Value: "v"}}
	bodies := []Body{
		&Open{ContainerID: "c", Hostname: "h", MaxFrameSize: 1024, ChannelMax: 7, IdleTimeout: 9,
			OfferedCapabilities: caps, DesiredCapabilities: caps, Properties: props},
		&Begin{RemoteChannel: &rc, NextOutgoingID: 1, IncomingWindow: 2, OutgoingWindow: 3, HandleMax: 4,
			OfferedCapabilities: caps, DesiredCapabilities: caps, Properties: props},
		&Attach{Name: "n", Handle: 1, Role: RoleSender, SndSettleMode: 1, RcvSettleMode: 1,
			Source: &Source{Address: "s", Durable: 1, ExpiryPolicy: "never", Timeout: 5, Dynamic: true,
				DistributionMode: "move", Filter: props, DefaultOutcome: &Described{Descriptor: uint64(0x24), Value: []any{}},
				Outcomes: caps, Capabilities: caps},
			Target:               &Target{Address: "t", Durable: 2, ExpiryPolicy: "link-detach", Timeout: 6, Dynamic: true, Capabilities: caps},
			InitialDeliveryCount: 5, MaxMessageSize: 1 << 40, OfferedCapabilities: caps, DesiredCapabilities: caps, Properties: props},
		&Attach{Name: "r", Handle: 2, Role: RoleReceiver},
		&Flow{NextIncomingID: u32p(1), IncomingWindow: 2, NextOutgoingID: 3, OutgoingWindow: 4, Handle: u32p(5),
			DeliveryCount: u32p(6), LinkCredit: u32p(7), Available: u32p(8), Drain: true, Echo: true, Properties: props},
		&Flow{IncomingWindow: 2, NextOutgoingID: 3, OutgoingWindow: 4},
		&Transfer{Handle: 1, DeliveryID: u32p(2), DeliveryTag: []byte{3}, MessageFormat: u32p(0), Settled: &tr,
			More: true, RcvSettleMode: &mode, State: &Received{SectionNumber: 1, SectionOffset: 2}, Resume: true, Aborted: true, Batchable: true},
		&Transfer{Handle: 1, State: &Accepted{}},
		&Transfer{Handle: 1, State: &Rejected{Error: e}},
		&Transfer{Handle: 1, State: &Rejected{}},
		&Transfer{Handle: 1, State: &Released{}},
		&Transfer{Handle: 1, State: &Modified{DeliveryFailed: true, UndeliverableHere: true, MessageAnnotations: props}},
		&Disposition{Role: RoleReceiver, First: 1, Last: u32p(4), Settled: true, State: &Accepted{}},
		&Disposition{Role: RoleSender, First: 1},
		&Detach{Handle: 1, Closed: true, Error: e},
		&Detach{Handle: 1},
		&End{Error: e}, &End{}, &Close{Error: e}, &Close{},
	}
	for _, body := range bodies {
		f := &Frame{Channel: 9, Body: body}
		if _, ok := body.(*Transfer); ok {
			f.Payload = []byte("payload")
		}
		require.Equal(t, f, frameRoundTrip(t, f), "%T", body)
	}
	for _, body := range []Body{
		&SASLMechanisms{Mechanisms: []Symbol{"PLAIN"}},
		&SASLInit{Mechanism: "PLAIN", InitialResponse: []byte("\x00u\x00p"), Hostname: "h"},
		&SASLInit{Mechanism: "ANONYMOUS"},
		&SASLChallenge{Challenge: []byte("c")}, &SASLResponse{Response: []byte("r")},
		&SASLOutcome{Code: SASLAuth, AdditionalData: []byte("x")},
	} {
		f := &Frame{Type: FrameSASL, Body: body}
		require.Equal(t, f, frameRoundTrip(t, f), "%T", body)
	}
	// Empty challenge and response encode as empty binaries.
	got := frameRoundTrip(t, &Frame{Type: FrameSASL, Body: &SASLChallenge{}})
	require.Equal(t, &SASLChallenge{Challenge: []byte{}}, got.Body)
	got = frameRoundTrip(t, &Frame{Type: FrameSASL, Body: &SASLResponse{}})
	require.Equal(t, &SASLResponse{Response: []byte{}}, got.Body)
	got = frameRoundTrip(t, &Frame{Type: FrameSASL, Body: &SASLMechanisms{}})
	require.Equal(t, &SASLMechanisms{Mechanisms: []Symbol{}}, got.Body)
	// An empty frame.
	require.Equal(t, &Frame{}, frameRoundTrip(t, &Frame{}))
}

// fieldsOf returns the encoded field values of a body, with all fields
// present (nulls kept).
func fieldsOf(b Body) []any { return b.fields() }

// TestPerformativeWrongTypes replaces each field of each frame body with a
// value of the wrong type and with nothing: decoding fails cleanly (or
// takes the default), never panics.
func TestPerformativeWrongTypes(t *testing.T) {
	rc := uint16(3)
	tr := true
	mode := ReceiverSettleSecond
	full := []struct {
		typ  byte
		body Body
	}{
		{FrameAMQP, &Open{ContainerID: "c", Hostname: "h", MaxFrameSize: 1, ChannelMax: 1, IdleTimeout: 1, OfferedCapabilities: []Symbol{"a"}, DesiredCapabilities: []Symbol{"a"}, Properties: Map{}}},
		{FrameAMQP, &Begin{RemoteChannel: &rc, HandleMax: 1, OfferedCapabilities: []Symbol{"a"}, DesiredCapabilities: []Symbol{"a"}, Properties: Map{}}},
		{FrameAMQP, &Attach{Name: "n", SndSettleMode: 1, RcvSettleMode: 1, Source: &Source{Address: "s"}, Target: &Target{Address: "t"}, MaxMessageSize: 1, OfferedCapabilities: []Symbol{"a"}, DesiredCapabilities: []Symbol{"a"}, Properties: Map{}}},
		{FrameAMQP, &Flow{NextIncomingID: u32p(1), Handle: u32p(1), DeliveryCount: u32p(1), LinkCredit: u32p(1), Available: u32p(1), Drain: true, Echo: true, Properties: Map{}}},
		{FrameAMQP, &Transfer{DeliveryID: u32p(1), DeliveryTag: []byte{1}, MessageFormat: u32p(0), Settled: &tr, More: true, RcvSettleMode: &mode, State: &Accepted{}, Resume: true, Aborted: true, Batchable: true}},
		{FrameAMQP, &Disposition{Last: u32p(1), Settled: true, State: &Accepted{}}},
		{FrameAMQP, &Detach{Closed: true, Error: &Error{Condition: "c", Description: "d", Info: Map{}}}},
		{FrameAMQP, &End{Error: &Error{Condition: "c"}}},
		{FrameAMQP, &Close{Error: &Error{Condition: "c"}}},
		{FrameSASL, &SASLMechanisms{Mechanisms: []Symbol{"a"}}},
		{FrameSASL, &SASLInit{Mechanism: "m", InitialResponse: []byte{1}, Hostname: "h"}},
		{FrameSASL, &SASLChallenge{Challenge: []byte{1}}},
		{FrameSASL, &SASLResponse{Response: []byte{1}}},
		{FrameSASL, &SASLOutcome{Code: 1, AdditionalData: []byte{1}}},
	}
	wrong := []any{Map{{Key: "x", Value: "y"}}, uint64(math.MaxUint64), []any{struct{}{}}}
	wrong[2] = &Described{Descriptor: uint64(0x99), Value: []any{}}
	for _, tc := range full {
		fields := fieldsOf(tc.body)
		for i := range fields {
			for _, w := range wrong {
				mod := append([]any(nil), fields...)
				mod[i] = w
				b, err := appendComposite(nil, tc.body.descriptor(), mod)
				require.NoError(t, err)
				f := &Frame{Type: tc.typ}
				_ = DecodeFrameBody(f, b) // must not panic
			}
			// Truncated after field i: the mandatory fields are missing.
			b, err := appendDescribed(nil, tc.body.descriptor(), fields[:i])
			require.NoError(t, err)
			_ = DecodeFrameBody(&Frame{Type: tc.typ}, b)
		}
	}
	// Some explicit cases.
	bad := func(typ byte, code uint64, fields ...any) {
		t.Helper()
		b, err := appendDescribed(nil, code, fields)
		require.NoError(t, err)
		require.ErrorIs(t, DecodeFrameBody(&Frame{Type: typ}, b), ErrProtocol, "%x %v", code, fields)
	}
	bad(FrameAMQP, descOpen)
	bad(FrameAMQP, descOpen, "c", nil, uint64(1)<<40)
	bad(FrameAMQP, descOpen, "c", nil, nil, uint32(1)<<20)
	bad(FrameAMQP, descBegin, nil, uint32(0), uint32(0))
	bad(FrameAMQP, descAttach, "n", uint32(0))
	bad(FrameAMQP, descAttach, "n", uint32(0), false, uint32(300))
	bad(FrameAMQP, descFlow, nil, uint32(0), uint32(0))
	bad(FrameAMQP, descTransfer)
	bad(FrameAMQP, descTransfer, uint32(0), nil, bytes.Repeat([]byte{1}, 33))
	bad(FrameAMQP, descDisposition, false)
	bad(FrameAMQP, descDetach)
	bad(FrameAMQP, descError)
	bad(FrameAMQP, 0x99)
	bad(FrameSASL, descSASLInit)
	bad(FrameSASL, descSASLOutcome)
	bad(FrameSASL, 0x99)
	bad(FrameSASL, descSASLMechanisms, []any{uint32(1)})
	bad(FrameAMQP, descTransfer, uint32(0), nil, nil, nil, nil, nil, nil, &Described{Descriptor: uint64(descAccepted), Value: "x"})
	bad(FrameAMQP, descTransfer, uint32(0), nil, nil, nil, nil, nil, nil, "notdescribed")
	bad(FrameAMQP, descTransfer, uint32(0), nil, nil, nil, nil, nil, nil, &Described{Descriptor: Symbol("nope"), Value: []any{}})
	bad(FrameAMQP, descDetach, uint32(0), nil, &Described{Descriptor: uint64(descError), Value: []any{}})
	bad(0x07, descClose)

	// Lenient: symbol for string, string for symbol, a single symbol or a
	// list for a symbol array, smaller unsigned types.
	ok := func(code uint64, fields ...any) Body {
		t.Helper()
		b, err := appendDescribed(nil, code, fields)
		require.NoError(t, err)
		f := &Frame{}
		require.NoError(t, DecodeFrameBody(f, b))
		return f.Body
	}
	o := ok(descOpen, Symbol("c"), nil, uint16(600), uint8(1), uint64(5), nil, nil, Symbol("x"), []any{"y", Symbol("z")})
	require.Equal(t, &Open{ContainerID: "c", MaxFrameSize: 600, ChannelMax: 1, IdleTimeout: 5,
		OfferedCapabilities: []Symbol{"x"}, DesiredCapabilities: []Symbol{"y", "z"}}, o)
	o = ok(descOpen, "c", nil, nil, nil, nil, nil, nil, "s")
	require.Equal(t, []Symbol{"s"}, o.(*Open).OfferedCapabilities)
	require.Equal(t, uint32(math.MaxUint32), o.(*Open).MaxFrameSize)
	a := ok(descAttach, "n", uint32(0), true, nil, nil, nil, nil, nil, nil, nil, uint8(9))
	require.Equal(t, uint64(9), a.(*Attach).MaxMessageSize)
	require.Equal(t, SenderSettleMixed, a.(*Attach).SndSettleMode)
	a = ok(descAttach, "n", uint32(0), true, nil, nil, nil, nil, nil, nil, nil, uint16(9))
	require.Equal(t, uint64(9), a.(*Attach).MaxMessageSize)
	a = ok(descAttach, "n", uint32(0), true, nil, nil, nil, nil, nil, nil, nil, uint32(9))
	require.Equal(t, uint64(9), a.(*Attach).MaxMessageSize)
	// Symbolic descriptors.
	b, err := appendDescribed(nil, Symbol("amqp:close:list"), []any{})
	require.NoError(t, err)
	f := &Frame{}
	require.NoError(t, DecodeFrameBody(f, b))
	require.Equal(t, &Close{}, f.Body)
}

func TestReadFrameErrors(t *testing.T) {
	frame := func(size uint32, doff, typ byte, body ...byte) []byte {
		b := binary.BigEndian.AppendUint32(nil, size)
		return append(append(b, doff, typ, 0, 0), body...)
	}
	closeBody := []byte{0x00, 0x53, 0x18, 0x45}
	cases := map[string][]byte{
		"size below 8":       frame(7, 2, 0),
		"doff below 2":       frame(8, 1, 0),
		"doff past size":     frame(8, 3, 0),
		"body not described": frame(9, 2, 0, 0x40),
		"unknown desc":       frame(12, 2, 0, 0x00, 0xa3, 1, 'x'),
		"body not list":      frame(11, 2, 0, 0x00, 0x53, 0x18),
		"bad value":          frame(9, 2, 0, 0x99),
		"trailing":           frame(13, 2, 0, append(closeBody, 0x40)...),
		"unknown type":       frame(12, 2, 9, closeBody...),
		"amqp in sasl":       frame(12, 2, 1, closeBody...),
	}
	for name, b := range cases {
		_, err := ReadFrame(bytes.NewReader(b), 1024)
		require.ErrorIs(t, err, ErrProtocol, name)
	}
	_, err := ReadFrame(bytes.NewReader(frame(5000, 2, 0)), 1024)
	require.ErrorIs(t, err, ErrFrameTooLarge)
	// A limit below 512 is raised to 512.
	_, err = ReadFrame(bytes.NewReader(frame(500, 2, 0)), 1)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = ReadFrame(bytes.NewReader(frame(20, 2, 0, 1, 2)), 1024)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = ReadFrame(bytes.NewReader([]byte{0, 0}), 1024)
	require.Error(t, err)
	// An extended header is skipped.
	f, err := ReadFrame(bytes.NewReader(frame(16, 3, 0, append([]byte{9, 9, 9, 9}, closeBody...)...)), 1024)
	require.NoError(t, err)
	require.Equal(t, &Close{}, f.Body)
}

func TestMessageRoundTrip(t *testing.T) {
	ts := time.UnixMilli(1700000000000).UTC()
	gs := uint32(3)
	m := &Message{
		Header:             &Header{Durable: true, Priority: 9, TTL: 1000, FirstAcquirer: true, DeliveryCount: 2},
		MessageAnnotations: map[Symbol]any{"x-opt-b": "b", "x-opt-a": int64(1)},
		Properties: &Properties{MessageID: UUID{1}, UserID: []byte("u"), To: "/queues/q", Subject: "ua-data",
			ReplyTo: "r", CorrelationID: uint64(5), ContentType: "application/json", ContentEncoding: "gzip",
			AbsoluteExpiryTime: ts, CreationTime: ts, GroupID: "g", GroupSequence: &gs, ReplyToGroupID: "rg"},
		ApplicationProperties: map[string]any{"b": int32(1), "a": "x"},
		Data:                  [][]byte{[]byte("ab"), []byte("cd")},
	}
	b, err := m.MarshalBinary()
	require.NoError(t, err)
	got := &Message{}
	require.NoError(t, got.UnmarshalBinary(b))
	require.Equal(t, m, got)
	require.Equal(t, []byte("abcd"), got.Payload())

	// Default header priority, ids of other types, an empty data section.
	m = &Message{Header: &Header{Priority: 4}, Properties: &Properties{MessageID: "id", CorrelationID: []byte{1}}, Data: [][]byte{nil}}
	b, err = m.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, got.UnmarshalBinary(b))
	require.Equal(t, uint8(4), got.Header.Priority)
	require.Equal(t, "id", got.Properties.MessageID)
	require.Equal(t, []byte{}, got.Payload())

	// Other bodies, read leniently.
	for _, tc := range []struct {
		m    *Message
		want []byte
	}{
		{&Message{Value: []byte("bin")}, []byte("bin")},
		{&Message{Value: "str"}, []byte("str")},
		{&Message{Value: uint32(1)}, nil},
		{&Message{HasValue: true}, nil},
		{&Message{Sequence: [][]any{{[]byte("a"), []byte("b")}, {[]byte("c")}}}, []byte("abc")},
		{&Message{Sequence: [][]any{{"no"}}}, nil},
		{&Message{}, nil},
	} {
		b, err := tc.m.MarshalBinary()
		require.NoError(t, err)
		got := &Message{}
		require.NoError(t, got.UnmarshalBinary(b))
		require.Equal(t, tc.want, got.Payload(), "%+v", tc.m)
	}

	_, err = (&Message{ApplicationProperties: map[string]any{"x": struct{}{}}}).MarshalBinary()
	require.Error(t, err)
	_, err = (&Message{MessageAnnotations: map[Symbol]any{"x": struct{}{}}}).MarshalBinary()
	require.Error(t, err)
	_, err = (&Message{Properties: &Properties{MessageID: struct{}{}}}).MarshalBinary()
	require.Error(t, err)
	_, err = (&Message{Header: &Header{}, Sequence: [][]any{{struct{}{}}}}).MarshalBinary()
	require.Error(t, err)
}

func TestMessageMalformed(t *testing.T) {
	sec := func(code uint64, v any) []byte {
		b, err := appendDescribed(nil, code, v)
		require.NoError(t, err)
		return b
	}
	data := sec(descData, []byte("x"))
	for name, b := range map[string][]byte{
		"not described":       {0x40},
		"bad value":           {0x99},
		"unknown section":     sec(0x99, nil),
		"symbolic unknown":    append([]byte{0x00, 0xa3, 1, 'x'}, 0x40),
		"two bodies":          append(append([]byte{}, data...), sec(descAMQPValue, "x")...),
		"two values":          append(sec(descAMQPValue, "x"), sec(descAMQPValue, "x")...),
		"header not list":     sec(descHeader, "x"),
		"header bad field":    sec(descHeader, []any{"x"}),
		"header bad priority": sec(descHeader, []any{nil, uint32(300)}),
		"header bad ttl":      sec(descHeader, []any{nil, nil, "x"}),
		"header bad fa":       sec(descHeader, []any{nil, nil, nil, "x"}),
		"header bad dc":       sec(descHeader, []any{nil, nil, nil, nil, "x"}),
		"annotations":         sec(descDeliveryAnnotations, "x"),
		"footer":              sec(descFooter, uint32(1)),
		"msg annotations":     sec(descMessageAnnotations, "x"),
		"props not list":      sec(descProperties, "x"),
		"app props":           sec(descApplicationProperties, "x"),
		"app props key":       sec(descApplicationProperties, Map{{Key: Symbol("k"), Value: "v"}}),
		"data":                sec(descData, "x"),
		"sequence":            sec(descAMQPSequence, "x"),
	} {
		require.ErrorIs(t, (&Message{}).UnmarshalBinary(b), ErrProtocol, name)
	}
	for i := range 13 {
		fields := make([]any, 13)
		fields[i] = Map{}
		require.ErrorIs(t, (&Message{}).UnmarshalBinary(sec(descProperties, fields)), ErrProtocol, "property %d", i)
	}
	// Ignored and lenient sections.
	m := &Message{}
	b := append(sec(descDeliveryAnnotations, Map{}), sec(descFooter, nil)...)
	b = append(b, sec(descMessageAnnotations, Map{{Key: uint64(1), Value: "x"}, {Key: Symbol("s"), Value: "y"}})...)
	b = append(b, sec(descProperties, []any{Symbol("sym-id")})...)
	require.NoError(t, m.UnmarshalBinary(b))
	require.Equal(t, map[Symbol]any{"s": "y"}, m.MessageAnnotations)
	require.Equal(t, "sym-id", m.Properties.MessageID)
}

func TestStateAndErrorHelpers(t *testing.T) {
	require.Equal(t, "c: d", (&Error{Condition: "c", Description: "d"}).Error())
	require.Nil(t, stateField(nil))
	require.True(t, isNull((*Error)(nil)))
	require.True(t, isNull((*Described)(nil)))
	require.False(t, isNull(uint32(0)))
	require.Nil(t, nested((*Target)(nil)))
	_, ok := descriptorCode("x")
	require.False(t, ok)
	_, _, err := composite("x", descError)
	require.Error(t, err)
	_, _, err = composite(&Described{Descriptor: uint64(descError), Value: "x"}, descError)
	require.Error(t, err)
	require.Equal(t, int64(-1), serialDiff(0, 1))
	require.True(t, inRange(5, math.MaxUint32, 10))
	require.False(t, inRange(11, math.MaxUint32, 10))
}
