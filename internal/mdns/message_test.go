// SPDX-License-Identifier: MIT

package mdns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// goldenAnnouncement is a hand-assembled DNS-SD announcement of one OPC UA
// server as it appears on the wire, with name compression.
func goldenAnnouncement() []byte {
	var b []byte
	app := func(parts ...any) {
		for _, p := range parts {
			switch v := p.(type) {
			case string:
				b = append(b, v...)
			case []byte:
				b = append(b, v...)
			case int:
				b = append(b, byte(v))
			}
		}
	}
	// header: response, authoritative; 3 answers, 1 additional
	app([]byte{0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 1})
	// @12 _opcua-tcp._tcp.local. PTR, TTL 4500
	app(10, "_opcua-tcp", 4, "_tcp", 5, "local", 0)
	app([]byte{0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, 14})
	// @45 "UA Srv-host" + pointer to @12
	app(11, "UA Srv-host", 0xc0, 12)
	// @59 SRV for the instance (pointer to @45), cache-flush, TTL 120
	app(0xc0, 45, []byte{0, 33, 0x80, 1, 0, 0, 0, 120, 0, 13})
	app([]byte{0, 0, 0, 0, 0x12, 0xe8}) // priority, weight, port 4840
	// @77 host + pointer to "local" @28
	app(4, "host", 0xc0, 28)
	// TXT for the instance, cache-flush, TTL 4500
	app(0xc0, 45, []byte{0, 16, 0x80, 1, 0, 0, 0x11, 0x94, 0, 20})
	app(7, "path=/x", 11, "caps=DA,LDS")
	// additional: A for host.local. (pointer to @77), cache-flush, TTL 120
	app(0xc0, 77, []byte{0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 10})
	return b
}

func goldenMessage() *Message {
	const (
		typ  = "_opcua-tcp._tcp.local."
		inst = "UA Srv-host._opcua-tcp._tcp.local."
	)
	return &Message{
		Response: true, Authoritative: true,
		Answers: []Record{
			{Name: typ, Type: TypePTR, Class: ClassIN, TTL: 4500, PTR: inst},
			{Name: inst, Type: TypeSRV, Class: ClassIN, CacheFlush: true, TTL: 120,
				SRV: &SRV{Port: 4840, Target: "host.local."}},
			{Name: inst, Type: TypeTXT, Class: ClassIN, CacheFlush: true, TTL: 4500,
				TXT: []string{"path=/x", "caps=DA,LDS"}},
		},
		Additionals: []Record{
			{Name: "host.local.", Type: TypeA, Class: ClassIN, CacheFlush: true, TTL: 120,
				Addr: netip.MustParseAddr("192.168.1.10")},
		},
	}
}

func TestUnpack_GoldenAnnouncement(t *testing.T) {
	m, err := Unpack(goldenAnnouncement())
	require.NoError(t, err)
	require.Equal(t, goldenMessage(), m)
}

func TestPack_GoldenAnnouncement(t *testing.T) {
	b, err := goldenMessage().Pack()
	require.NoError(t, err)
	require.Equal(t, hex.Dump(goldenAnnouncement()), hex.Dump(b))
}

// The PTR question every OPC UA browser sends.
func TestUnpack_GoldenQuery(t *testing.T) {
	b, err := hex.DecodeString("000000000001000000000000" +
		"0a5f6f706375612d746370045f746370056c6f63616c00" + "000c0001")
	require.NoError(t, err)
	m, err := Unpack(b)
	require.NoError(t, err)
	require.Equal(t, &Message{Questions: []Question{
		{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: ClassIN},
	}}, m)

	out, err := m.Pack()
	require.NoError(t, err)
	require.Equal(t, b, out)
}

func TestPackUnpack_RoundTrip(t *testing.T) {
	m := &Message{
		ID: 0xbeef, Opcode: 0, Truncated: true, RCode: 3,
		Questions: []Question{
			{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: ClassIN, Unicast: true},
			{Name: ".", Type: TypeANY, Class: ClassANY},
		},
		Answers: []Record{
			{Name: `Line 3\.Press\\A._opcua-tcp._tcp.local.`, Type: TypeTXT, Class: ClassIN, TTL: 1},
			{Name: "h.local.", Type: TypeAAAA, Class: ClassIN, TTL: 2, Addr: netip.MustParseAddr("fe80::1")},
			{Name: "h.local.", Type: 47, Class: ClassIN, TTL: 3, Data: []byte{1, 2, 3}},
			{Name: "H.LOCAL.", Type: 99, Class: 3, TTL: 4},
		},
		Authorities: []Record{
			{Name: "x.local.", Type: TypeSRV, Class: ClassIN, SRV: &SRV{Priority: 1, Weight: 2, Port: 3, Target: "."}},
		},
		Additionals: []Record{
			{Name: "bin\\000\\255.local.", Type: TypePTR, Class: ClassIN, PTR: "x.local."},
		},
	}
	b, err := m.Pack()
	require.NoError(t, err)
	got, err := Unpack(b)
	require.NoError(t, err)
	require.Equal(t, m, got)
}

func TestNames(t *testing.T) {
	labels, err := SplitName(`a\.b.c\\d.\065\000.local`)
	require.NoError(t, err)
	require.Equal(t, []string{"a.b", `c\d`, "A\x00", "local"}, labels)
	require.Equal(t, `a\.b.c\\d.A\000.local.`, JoinLabels(labels...))
	require.Equal(t, ".", JoinLabels())

	root, err := SplitName(".")
	require.NoError(t, err)
	require.Empty(t, root)

	require.True(t, EqualNames("Foo.Local", "foo.local."))
	require.False(t, EqualNames("foo.local.", "bar.local."))

	for _, bad := range []string{
		"", "a..b.", ".a.", `a\`, `a\1`, `a\12`, `a\999.`, `a\1x2.`,
		strings.Repeat("a", 64) + ".local.",
		strings.Repeat("abcdefgh.", 29),
	} {
		_, err := SplitName(bad)
		require.ErrorIs(t, err, ErrBadName, "%q", bad)
	}
}

func TestPack_Errors(t *testing.T) {
	rec := func(r Record) *Message { return &Message{Answers: []Record{r}} }
	cases := map[string]*Message{
		"bad question name": {Questions: []Question{{Name: "a..b"}}},
		"bad record name":   rec(Record{Name: ""}),
		"bad ptr":           rec(Record{Name: "a.", Type: TypePTR, PTR: ""}),
		"nil srv":           rec(Record{Name: "a.", Type: TypeSRV}),
		"bad srv target":    rec(Record{Name: "a.", Type: TypeSRV, SRV: &SRV{Target: "a..b"}}),
		"long txt":          rec(Record{Name: "a.", Type: TypeTXT, TXT: []string{strings.Repeat("x", 256)}}),
		"a with v6":         rec(Record{Name: "a.", Type: TypeA, Addr: netip.MustParseAddr("::1")}),
		"aaaa with v4":      rec(Record{Name: "a.", Type: TypeAAAA, Addr: netip.MustParseAddr("1.2.3.4")}),
		"a without addr":    rec(Record{Name: "a.", Type: TypeA}),
		"huge rdata":        rec(Record{Name: "a.", Type: 99, Data: make([]byte, 70000)}),
	}
	for name, m := range cases {
		_, err := m.Pack()
		require.Error(t, err, name)
	}

	// A message that does not fit 64 KiB.
	big := &Message{}
	for i := 0; i < 40; i++ {
		big.Answers = append(big.Answers, Record{Name: "a.", Type: 99, Data: make([]byte, 2000)})
	}
	_, err := big.Pack()
	require.ErrorIs(t, err, ErrTooLarge)

	// TXT: empty strings are skipped, no strings encode as one empty string.
	b, err := rec(Record{Name: "a.", Type: TypeTXT, TXT: []string{"", "k=v", ""}}).Pack()
	require.NoError(t, err)
	m, err := Unpack(b)
	require.NoError(t, err)
	require.Equal(t, []string{"k=v"}, m.Answers[0].TXT)
}

// header builds a message header with the given section counts.
func header(qd, an, ns, ar uint16) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[4:], qd)
	binary.BigEndian.PutUint16(b[6:], an)
	binary.BigEndian.PutUint16(b[8:], ns)
	binary.BigEndian.PutUint16(b[10:], ar)
	return b
}

func TestUnpack_Hostile(t *testing.T) {
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	fixed := func(typ uint16, rdlen uint16) []byte {
		b := make([]byte, 10)
		binary.BigEndian.PutUint16(b[0:], typ)
		binary.BigEndian.PutUint16(b[2:], ClassIN)
		binary.BigEndian.PutUint16(b[8:], rdlen)
		return b
	}
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrShortMessage},
		{"short header", make([]byte, 11), ErrShortMessage},
		{"oversized", make([]byte, 70000), ErrTooLarge},
		{"counts exceed size", header(0xffff, 0xffff, 0xffff, 0xffff), ErrTooMany},
		{"question count without data", header(1, 0, 0, 0), ErrTooMany},
		{"truncated question name", cat(header(1, 0, 0, 0), []byte{3, 'a', 'b', 'c', 0}), ErrShortMessage},
		{"question without type", cat(header(1, 0, 0, 0), []byte{1, 'a', 0, 0, 12, 0}), ErrShortMessage},
		{"label runs past the end", cat(header(1, 0, 0, 0), []byte{60, 'a', 0, 0, 0}), ErrShortMessage},
		{"pointer to itself", cat(header(1, 0, 0, 0), []byte{0xc0, 12, 0, 12, 0, 1}), ErrBadPointer},
		{"forward pointer", cat(header(1, 0, 0, 0), []byte{0xc0, 14, 0, 0, 12, 0, 1}), ErrBadPointer},
		{"pointer loop", cat(header(2, 0, 0, 0), []byte{1, 'a', 0xc0, 16, 0, 1, 0xc0, 12, 0, 1}), ErrBadPointer},
		{"truncated pointer", cat(header(1, 0, 0, 0), []byte{1, 'a', 1, 'b', 0xc0}), ErrShortMessage},
		{"reserved label type", cat(header(1, 0, 0, 0), []byte{0x80, 0, 0, 0, 0}), ErrBadName},
		{"record header cut", cat(header(0, 1, 0, 0), []byte{1, 'a', 0, 0, 1, 0, 1, 0, 0, 0, 0}), ErrShortMessage},
		{"rdata beyond message", cat(header(0, 1, 0, 0), []byte{0}, fixed(99, 50), []byte{1}), ErrShortMessage},
		{"a record size", cat(header(0, 1, 0, 0), []byte{0}, fixed(TypeA, 3), []byte{1, 2, 3}), ErrBadRData},
		{"aaaa record size", cat(header(0, 1, 0, 0), []byte{0}, fixed(TypeAAAA, 4), []byte{1, 2, 3, 4}), ErrBadRData},
		{"srv too short", cat(header(0, 1, 0, 0), []byte{0}, fixed(TypeSRV, 6), make([]byte, 6)), ErrBadRData},
		{"srv trailing bytes", cat(header(0, 1, 0, 0), []byte{0}, fixed(TypeSRV, 8), make([]byte, 8)), ErrBadRData},
		{"srv target leaves rdata", cat(header(0, 1, 0, 0), []byte{0}, fixed(TypeSRV, 7), make([]byte, 6), []byte{5}, []byte("abcde\x00")), ErrShortMessage},
		{"ptr trailing bytes", cat(header(0, 1, 0, 0), []byte{0}, fixed(TypePTR, 2), []byte{0, 0}), ErrBadRData},
		{"ptr empty", cat(header(0, 1, 0, 0), []byte{0}, fixed(TypePTR, 0)), ErrShortMessage},
		{"txt string beyond record", cat(header(0, 1, 0, 0), []byte{0}, fixed(TypeTXT, 2), []byte{5, 'a'}), ErrBadRData},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Unpack(tc.in)
			require.ErrorIs(t, err, tc.want)
		})
	}

	// A name of 255 bytes on the wire is the longest allowed.
	long := header(1, 0, 0, 0)
	for i := 0; i < 4; i++ {
		long = append(long, 62)
		long = append(long, bytes.Repeat([]byte{'a'}, 62)...)
	}
	ok := append(bytes.Clone(long), 1, 'a', 0, 0, 12, 0, 1) // 4*63 + 2 + 1 = 255
	_, err := Unpack(ok)
	require.NoError(t, err)
	tooLong := append(bytes.Clone(long), 2, 'a', 'a', 0, 0, 12, 0, 1)
	_, err = Unpack(tooLong)
	require.ErrorIs(t, err, ErrBadName)

	// A chain of backward pointers longer than the hop limit: every pointer
	// refers to the one before it, the first to a root label.
	chain := []byte{0}
	for i := 0; i <= maxPointerHops; i++ {
		target := 0
		if i > 0 {
			target = 1 + 2*(i-1)
		}
		chain = append(chain, 0xc0, byte(target))
	}
	_, _, err = unpackName(chain, len(chain)-2)
	require.ErrorIs(t, err, ErrBadPointer)
	name, next, err := unpackName(chain, len(chain)-4)
	require.NoError(t, err)
	require.Equal(t, ".", name)
	require.Equal(t, len(chain)-2, next)
}

func FuzzUnpack(f *testing.F) {
	f.Add(goldenAnnouncement())
	if b, err := goldenMessage().Pack(); err == nil {
		f.Add(b)
	}
	f.Add(header(1, 0, 0, 0))
	f.Add(append(header(1, 0, 0, 0), 0xc0, 12, 0, 12, 0, 1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > MaxPacketSize {
			return
		}
		m, err := Unpack(in)
		if err != nil {
			return
		}
		// What was decoded can be encoded again (unless decompressing the
		// names made it too large) and decodes to the same message.
		out, err := m.Pack()
		if err != nil {
			if errors.Is(err, ErrTooLarge) {
				return
			}
			t.Fatalf("decoded message does not encode: %v", err)
		}
		again, err := Unpack(out)
		if err != nil {
			t.Fatalf("re-encoded message does not decode: %v", err)
		}
		require.Equal(t, m, again)

		// The engine must survive it as well.
		n := newNode(Config{Conns: []PacketConn{NewMemNetwork().Conn()}})
		_ = n.Browse("_opcua-tcp._tcp", func(Event) {})
		_ = n.Register(Service{Instance: "f", Type: "_opcua-tcp._tcp", Host: "h.local.", Port: 1})
		src := netip.MustParseAddrPort("10.0.0.1:5353")
		n.mu.Lock()
		n.handlePacket(n.cfg.Now(), 0, in, src)
		n.handlePacket(n.cfg.Now(), 0, in, netip.MustParseAddrPort("10.0.0.1:1234"))
		n.mu.Unlock()
		out2, _, _ := n.step(n.cfg.Now())
		n.send(out2)
	})
}
