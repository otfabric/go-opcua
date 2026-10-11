// SPDX-License-Identifier: MIT

package mdns

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const opcType = "_opcua-tcp._tcp"

// recConn records what a node sends.
type recConn struct {
	mu      sync.Mutex
	multi   [][]byte
	uni     map[netip.AddrPort][][]byte
	addrs   []netip.Addr
	failing bool
	closed  chan struct{}
	once    sync.Once
}

func newRecConn(addrs ...string) *recConn {
	c := &recConn{uni: map[netip.AddrPort][][]byte{}, closed: make(chan struct{})}
	for _, a := range addrs {
		c.addrs = append(c.addrs, netip.MustParseAddr(a))
	}
	return c
}

func (c *recConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	<-c.closed
	return 0, netip.AddrPort{}, net.ErrClosed
}

func (c *recConn) WriteMulticast(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failing {
		return errors.New("network is down")
	}
	c.multi = append(c.multi, bytes.Clone(b))
	return nil
}

func (c *recConn) WriteTo(b []byte, dst netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uni[dst] = append(c.uni[dst], bytes.Clone(b))
	return nil
}

func (c *recConn) Addrs() []netip.Addr { return c.addrs }
func (c *recConn) Close() error        { c.once.Do(func() { close(c.closed) }); return nil }

// take returns and forgets the multicast messages sent so far.
func (c *recConn) take(t *testing.T) []*Message {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*Message
	for _, b := range c.multi {
		m, err := Unpack(b)
		require.NoError(t, err)
		out = append(out, m)
	}
	c.multi = nil
	return out
}

// bench is a node driven by hand with a fake clock.
type bench struct {
	t      *testing.T
	n      *Node
	conn   *recConn
	now    time.Time
	next   time.Time
	events []Event
	logs   *bytes.Buffer
}

func newBench(t *testing.T, mutate ...func(*Config)) *bench {
	b := &bench{t: t, conn: newRecConn("192.168.1.10", "fe80::1"), now: time.Unix(1_700_000_000, 0), logs: &bytes.Buffer{}}
	cfg := Config{
		Conns:  []PacketConn{b.conn},
		Now:    func() time.Time { return b.now },
		Logger: slog.New(slog.NewTextHandler(b.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	b.n = newNode(cfg)
	return b
}

// step runs the timers at the current fake time, sends what is due and
// delivers the events. It returns the messages sent and remembers the next
// deadline.
func (b *bench) step() []*Message {
	b.t.Helper()
	out, events, next := b.n.step(b.now)
	b.next = next
	b.n.send(out)
	for _, e := range events {
		e.fn(e.ev)
	}
	return b.conn.take(b.t)
}

func (b *bench) advance(d time.Duration) []*Message {
	b.t.Helper()
	b.now = b.now.Add(d)
	return b.step()
}

// runUntil steps through every deadline up to d from now and returns all
// messages sent on the way.
func (b *bench) runUntil(d time.Duration) []*Message {
	b.t.Helper()
	end := b.now.Add(d)
	all := b.step()
	for i := 0; i < 10000 && !b.next.IsZero() && !b.next.After(end); i++ {
		b.now = b.next
		all = append(all, b.step()...)
	}
	b.now = end
	return append(all, b.step()...)
}

func (b *bench) receive(m *Message, src string) []*Message {
	b.t.Helper()
	data, err := m.Pack()
	require.NoError(b.t, err)
	b.receiveRaw(data, src)
	return b.step()
}

func (b *bench) receiveRaw(data []byte, src string) {
	b.n.mu.Lock()
	b.n.handlePacket(b.now, 0, data, netip.MustParseAddrPort(src))
	b.n.mu.Unlock()
}

func (b *bench) browse() {
	require.NoError(b.t, b.n.Browse(opcType, func(e Event) { b.events = append(b.events, e) }))
}

func (b *bench) takeEvents() []Event {
	ev := b.events
	b.events = nil
	return ev
}

const peer = "192.168.1.20:5353"

func ptrQuery() *Message {
	return &Message{Questions: []Question{{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: ClassIN}}}
}

// announcement builds the response a remote responder sends for an instance.
func announcement(instance, host string, port uint16, ttl uint32, txt ...string) *Message {
	full := EscapeLabel(instance) + "._opcua-tcp._tcp.local."
	return &Message{Response: true, Authoritative: true, Answers: []Record{
		{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: ClassIN, TTL: ttl, PTR: full},
		{Name: full, Type: TypeSRV, Class: ClassIN, CacheFlush: true, TTL: ttl, SRV: &SRV{Port: port, Target: host}},
		{Name: full, Type: TypeTXT, Class: ClassIN, CacheFlush: true, TTL: ttl, TXT: txt},
	}}
}

func findRecord(msgs []*Message, typ uint16, name string) *Record {
	for _, m := range msgs {
		for _, sec := range [][]Record{m.Answers, m.Additionals} {
			for i := range sec {
				if sec[i].Type == typ && EqualNames(sec[i].Name, name) {
					return &sec[i]
				}
			}
		}
	}
	return nil
}

var testService = Service{
	Instance: "UA Srv-host", Type: opcType, Host: "host.local", Port: 4840,
	Text: []string{"path=/x", "caps=DA,LDS"}, LocalHost: true,
	Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")}, // duplicate of the interface address
}

const testFull = "UA Srv-host._opcua-tcp._tcp.local."

func TestResponder_AnnouncesTwice(t *testing.T) {
	b := newBench(t)
	require.NoError(t, b.n.Register(testService))

	first := b.step()
	require.Len(t, first, 1)
	m := first[0]
	require.True(t, m.Response)
	require.True(t, m.Authoritative)
	require.Empty(t, m.Questions)

	ptr := findRecord(first, TypePTR, "_opcua-tcp._tcp.local.")
	require.NotNil(t, ptr)
	require.Equal(t, testFull, ptr.PTR)
	require.Equal(t, DefaultOtherTTL, ptr.TTL)
	require.False(t, ptr.CacheFlush, "a shared record must not carry the cache-flush bit")

	srv := findRecord(first, TypeSRV, testFull)
	require.NotNil(t, srv)
	require.Equal(t, SRV{Port: 4840, Target: "host.local."}, *srv.SRV)
	require.Equal(t, DefaultHostTTL, srv.TTL)
	require.True(t, srv.CacheFlush)

	txt := findRecord(first, TypeTXT, testFull)
	require.Equal(t, []string{"path=/x", "caps=DA,LDS"}, txt.TXT)

	a := findRecord(first, TypeA, "host.local.")
	require.Equal(t, "192.168.1.10", a.Addr.String())
	aaaa := findRecord(first, TypeAAAA, "host.local.")
	require.Equal(t, "fe80::1", aaaa.Addr.String())
	var addrCount int
	for _, r := range m.Answers {
		if r.Type == TypeA || r.Type == TypeAAAA {
			addrCount++
		}
	}
	require.Equal(t, 2, addrCount, "an address is published once")

	enum := findRecord(first, TypePTR, serviceEnumeration)
	require.Equal(t, "_opcua-tcp._tcp.local.", enum.PTR)

	// nothing more before a second has passed, then the second announcement
	require.Empty(t, b.advance(900*time.Millisecond))
	require.Len(t, b.advance(100*time.Millisecond), 1)
	require.Empty(t, b.runUntil(10*time.Minute), "exactly two announcements")
}

func TestResponder_AnswersQueries(t *testing.T) {
	b := newBench(t)
	require.NoError(t, b.n.Register(testService))
	b.runUntil(5 * time.Second)

	t.Run("ptr with additionals", func(t *testing.T) {
		out := b.receive(ptrQuery(), peer)
		require.Len(t, out, 1)
		require.Len(t, out[0].Answers, 1)
		require.Equal(t, testFull, out[0].Answers[0].PTR)
		require.NotNil(t, findRecord(out, TypeSRV, testFull))
		require.NotNil(t, findRecord(out, TypeTXT, testFull))
		require.NotNil(t, findRecord(out, TypeA, "host.local."))
		require.Len(t, out[0].Additionals, 4)
	})

	t.Run("rate limit", func(t *testing.T) {
		require.Empty(t, b.receive(ptrQuery(), peer), "same record within a second")
		b.advance(1100 * time.Millisecond)
		require.Len(t, b.receive(ptrQuery(), peer), 1)
		b.advance(2 * time.Second)
	})

	t.Run("known answer suppression", func(t *testing.T) {
		q := ptrQuery()
		q.Answers = []Record{{Name: "_OPCUA-TCP._tcp.local.", Type: TypePTR, Class: ClassIN, TTL: DefaultOtherTTL/2 + 1, PTR: testFull}}
		require.Empty(t, b.receive(q, peer))
		// a known answer in the second half of its lifetime is answered
		q.Answers[0].TTL = DefaultOtherTTL/2 - 1
		require.Len(t, b.receive(q, peer), 1)
		b.advance(2 * time.Second)
	})

	t.Run("srv and txt", func(t *testing.T) {
		out := b.receive(&Message{Questions: []Question{
			{Name: strings.ToUpper(testFull), Type: TypeSRV, Class: ClassIN},
			{Name: testFull, Type: TypeTXT, Class: ClassANY, Unicast: true},
		}}, peer)
		require.Len(t, out, 1)
		require.Len(t, out[0].Answers, 2)
		require.Len(t, out[0].Additionals, 2, "the address records")
		b.advance(2 * time.Second)
	})

	t.Run("any", func(t *testing.T) {
		out := b.receive(&Message{Questions: []Question{{Name: testFull, Type: TypeANY, Class: ClassIN}}}, peer)
		require.Len(t, out[0].Answers, 2)
		b.advance(2 * time.Second)
	})

	t.Run("host addresses", func(t *testing.T) {
		out := b.receive(&Message{Questions: []Question{{Name: "host.local.", Type: TypeA, Class: ClassIN}}}, peer)
		require.Len(t, out, 1)
		require.Len(t, out[0].Answers, 1)
		require.Equal(t, TypeA, out[0].Answers[0].Type)
		out = b.receive(&Message{Questions: []Question{{Name: "host.local.", Type: TypeANY, Class: ClassIN}}}, peer)
		require.Len(t, out[0].Answers, 1, "the A record was sent less than a second ago")
		require.Equal(t, TypeAAAA, out[0].Answers[0].Type)
		b.advance(2 * time.Second)
	})

	t.Run("service enumeration", func(t *testing.T) {
		out := b.receive(&Message{Questions: []Question{{Name: serviceEnumeration, Type: TypePTR, Class: ClassIN}}}, peer)
		require.Len(t, out, 1)
		require.Equal(t, "_opcua-tcp._tcp.local.", out[0].Answers[0].PTR)
		b.advance(2 * time.Second)
	})

	t.Run("not for us", func(t *testing.T) {
		for _, q := range []Question{
			{Name: "_http._tcp.local.", Type: TypePTR, Class: ClassIN},
			{Name: "_opcua-tcp._tcp.local.", Type: TypeSRV, Class: ClassIN},
			{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: 3},
			{Name: testFull, Type: TypeA, Class: ClassIN},
			{Name: "host.local.", Type: TypeTXT, Class: ClassIN},
		} {
			require.Empty(t, b.receive(&Message{Questions: []Question{q}}, peer), "%+v", q)
		}
	})

	t.Run("legacy unicast", func(t *testing.T) {
		src := netip.MustParseAddrPort("192.168.1.30:40000")
		q := ptrQuery()
		q.ID = 0x1234
		require.Empty(t, b.receive(q, src.String()), "the answer is not multicast")
		b.conn.mu.Lock()
		sent := b.conn.uni[src]
		b.conn.mu.Unlock()
		require.Len(t, sent, 1)
		m, err := Unpack(sent[0])
		require.NoError(t, err)
		require.Equal(t, uint16(0x1234), m.ID)
		require.Equal(t, q.Questions, m.Questions)
		for _, r := range append(m.Answers, m.Additionals...) {
			require.LessOrEqual(t, r.TTL, legacyTTL)
			require.False(t, r.CacheFlush)
		}
	})

	t.Run("ignored messages", func(t *testing.T) {
		q := ptrQuery()
		q.Opcode = 2
		require.Empty(t, b.receive(q, peer))
		q = ptrQuery()
		q.RCode = 3
		require.Empty(t, b.receive(q, peer))
		b.receiveRaw([]byte{1, 2, 3}, peer)
		b.receiveRaw(make([]byte, MaxPacketSize+1), peer)
		require.Empty(t, b.step())
		require.Contains(t, b.logs.String(), "dropped malformed packet")
	})
}

// The mdnsd library embedded in open62541 sends its queries and responses
// from an ephemeral port instead of 5353. Its queries carry the id 0 of a
// multicast querier and must be answered by multicast; its responses must be
// accepted. The packets below were captured from open62541 v1.5.9.
func TestOpen62541_Mdnsd(t *testing.T) {
	const src = "172.19.0.2:36585"
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return b
	}

	t.Run("announcement is accepted", func(t *testing.T) {
		b := newBench(t)
		b.browse()
		b.step()
		// SRV, TXT, two A records and two PTR records for "LDS-o62lds".
		b.receiveRaw(unhex("000084000000000600000000"+
			"0a4c44532d6f36326c64730a5f6f706375612d746370045f746370056c6f63616c00"+
			"0021800100000258000f0000000012e8066f36326c6473c027"+
			"c00c0010800100000258001006706174683d2f08636170733d4c4453"+
			"066f36326c6473c02700010001000002580004ac130002"+
			"c00c00010001000002580004ac130002"+
			"c017000c0001000002580002c00c"+
			"095f7365727669636573075f646e732d7364045f756470c027000c0001000002580002c017"), src)
		b.step()
		require.Equal(t, []Event{{Instance: Instance{
			Name: "LDS-o62lds", Type: opcType, Host: "o62lds.local.", Port: 4840, Text: []string{"path=/", "caps=LDS"},
		}}}, b.takeEvents())
	})

	t.Run("answer to a PTR question is accepted", func(t *testing.T) {
		b := newBench(t)
		b.browse()
		b.step()
		// PTR in the answer section; TXT, SRV and A as additional records.
		b.receiveRaw(unhex("000084000001000100000003"+
			"0a5f6f706375612d746370045f746370056c6f63616c00000c0001"+
			"c00c000c000100000258000d0a4c44532d6f36326c6473c00c"+
			"0a4c44532d6f36326c6473c00c0010800100000258001006706174683d2f08636170733d4c4453"+
			"0a4c44532d6f36326c6473c00c0021800100000258000f0000000012e8066f36326c6473c01c"+
			"066f36326c6473c01c00010001000002580004ac130002"), src)
		b.step()
		ev := b.takeEvents()
		require.Len(t, ev, 1)
		require.Equal(t, "LDS-o62lds", ev[0].Instance.Name)
		require.Equal(t, uint16(4840), ev[0].Instance.Port)
	})

	t.Run("queries are answered by multicast", func(t *testing.T) {
		b := newBench(t)
		s := Service{Instance: "GoSrv-gosrv", Type: opcType, Host: "gosrv.local.", Port: 4841,
			Text: []string{"path=/", "caps=DA,HD"}}
		require.NoError(t, b.n.Register(s))
		b.runUntil(5 * time.Second)

		// the PTR question of open62541's browser
		b.receiveRaw(unhex("000000000001000000000000"+"0a5f6f706375612d746370045f746370056c6f63616c00"+"000c0001"), src)
		out := b.step()
		require.Len(t, out, 1, "a multicast response")
		require.Equal(t, "GoSrv-gosrv._opcua-tcp._tcp.local.", out[0].Answers[0].PTR)
		b.conn.mu.Lock()
		require.Empty(t, b.conn.uni, "not a unicast response")
		b.conn.mu.Unlock()

		// Its TXT and SRV questions for the instance, with the records it
		// already has as known answers (TTL 2258 of 4500 and 68 of 120):
		// nothing to say.
		b.advance(2 * time.Second)
		known := unhex("000000000002000200000000" +
			"0b476f5372762d676f7372760a5f6f706375612d746370045f746370056c6f63616c00" + "00100001" +
			"c00c00210001" +
			"c00c00100001000008d2001206706174683d2f0a636170733d44412c4844" +
			"c00c0021000100000044000e0000000012e905676f737276c028")
		b.receiveRaw(known, src)
		require.Empty(t, b.step())

		// Once its copies are in the second half of their lifetime they are
		// sent again.
		m, err := Unpack(known)
		require.NoError(t, err)
		m.Answers[0].TTL, m.Answers[1].TTL = 100, 10
		out = b.receive(m, src)
		require.Len(t, out, 1)
		require.Len(t, out[0].Answers, 2)
	})
}

func TestResponder_Goodbye(t *testing.T) {
	b := newBench(t)
	require.NoError(t, b.n.Register(testService))
	other := testService
	other.Instance = "Second"
	require.NoError(t, b.n.Register(other))
	b.runUntil(5 * time.Second)

	require.False(t, b.n.Unregister("unknown", opcType))
	require.True(t, b.n.Unregister("UA Srv-host", opcType))
	out := b.step()
	require.Len(t, out, 1)
	require.Len(t, out[0].Answers, 3)
	for _, r := range out[0].Answers {
		require.Zero(t, r.TTL)
		require.NotContains(t, []uint16{TypeA, TypeAAAA}, r.Type)
	}
	require.Equal(t, testFull, out[0].Answers[0].PTR)

	// the withdrawn instance is no longer answered for, the other one is
	b.advance(2 * time.Second)
	out = b.receive(ptrQuery(), peer)
	require.Len(t, out[0].Answers, 1)
	require.Equal(t, "Second._opcua-tcp._tcp.local.", out[0].Answers[0].PTR)
}

func TestResponder_RegisterValidation(t *testing.T) {
	b := newBench(t)
	for name, s := range map[string]Service{
		"no instance":   {Type: opcType, Host: "h.local.", Port: 1},
		"long instance": {Instance: strings.Repeat("x", 64), Type: opcType, Host: "h.local.", Port: 1},
		"no port":       {Instance: "a", Type: opcType, Host: "h.local."},
		"bad host":      {Instance: "a", Type: opcType, Host: "h..local.", Port: 1},
		"bare host":     {Instance: "a", Type: opcType, Host: "h", Port: 1},
		"no type":       {Instance: "a", Type: "", Host: "h.local.", Port: 1},
		"long txt":      {Instance: "a", Type: opcType, Host: "h.local.", Port: 1, Text: []string{strings.Repeat("x", 256)}},
	} {
		require.Error(t, b.n.Register(s), name)
	}
	require.Error(t, b.n.Browse("bad..type", func(Event) {}))
}

func TestResponder_SplitsLargeResponses(t *testing.T) {
	b := newBench(t)
	const count = 60
	for i := 0; i < count; i++ {
		s := testService
		s.Instance = fmt.Sprintf("Server number %03d with a rather long instance name", i)
		require.NoError(t, b.n.Register(s))
	}
	b.runUntil(5 * time.Second)

	b.n.mu.Lock()
	b.n.handlePacket(b.now, 0, mustPack(t, ptrQuery()), netip.MustParseAddrPort(peer))
	out := b.n.out
	b.n.out = nil
	b.n.mu.Unlock()
	b.n.send(out)

	b.conn.mu.Lock()
	raw := b.conn.multi
	b.conn.multi = nil
	b.conn.mu.Unlock()
	require.Greater(t, len(raw), 1, "the answers do not fit one packet")
	seen := map[string]bool{}
	for _, p := range raw {
		require.LessOrEqual(t, len(p), maxPayload)
		m, err := Unpack(p)
		require.NoError(t, err)
		for _, a := range m.Answers {
			seen[a.PTR] = true
		}
	}
	require.Len(t, seen, count)
}

func mustPack(t *testing.T, m *Message) []byte {
	t.Helper()
	b, err := m.Pack()
	require.NoError(t, err)
	return b
}

func TestSplitPack(t *testing.T) {
	// A query keeps its question and as many known answers as fit.
	q := ptrQuery()
	for i := 0; i < 200; i++ {
		q.Answers = append(q.Answers, Record{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: ClassIN, TTL: 100,
			PTR: fmt.Sprintf("known answer number %03d._opcua-tcp._tcp.local.", i)})
	}
	out := splitPack(q)
	require.Len(t, out, 1)
	require.LessOrEqual(t, len(out[0]), maxPayload)
	m, err := Unpack(out[0])
	require.NoError(t, err)
	require.Len(t, m.Questions, 1)
	require.NotEmpty(t, m.Answers)
	require.Less(t, len(m.Answers), 200)

	// A single oversized answer is still sent, alone.
	big := &Message{Response: true, Answers: []Record{
		{Name: "a.local.", Type: 99, Class: ClassIN, Data: make([]byte, 3000)},
		{Name: "b.local.", Type: 99, Class: ClassIN, Data: make([]byte, 3000)},
	}}
	require.Len(t, splitPack(big), 2)

	// Records that cannot be encoded are left out.
	require.Empty(t, splitPack(&Message{Response: true, Answers: []Record{{Name: "bad..name"}}}))
	require.Empty(t, splitPack(&Message{Questions: []Question{{Name: "bad..name"}}}))
	mixed := &Message{Response: true}
	for i := 0; i < 3; i++ {
		mixed.Answers = append(mixed.Answers, Record{Name: "a.local.", Type: 99, Class: ClassIN, Data: make([]byte, 30000)})
	}
	mixed.Answers = append(mixed.Answers, Record{Name: "bad..name"})
	require.NotEmpty(t, splitPack(mixed))
}

func TestBrowser_QueryBackoff(t *testing.T) {
	b := newBench(t)
	b.browse()
	start := b.now

	var times []time.Duration
	for i := 0; i < 16; i++ {
		for range b.step() {
			times = append(times, b.now.Sub(start))
		}
		b.now = b.next
	}
	require.Equal(t, []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second, 15 * time.Second}, times[:5])
	// the interval is capped at an hour
	require.Equal(t, time.Hour, times[len(times)-1]-times[len(times)-2])
}

func TestBrowser_FindsUpdatesAndExpires(t *testing.T) {
	b := newBench(t)
	b.browse()
	b.step()

	require.Empty(t, b.receive(announcement("Press 7.A-host1", "host1.local.", 4840, 100, "path=/ua", "caps=DA"), peer))
	require.Equal(t, []Event{{Instance: Instance{
		Name: "Press 7.A-host1", Type: opcType, Host: "host1.local.", Port: 4840, Text: []string{"path=/ua", "caps=DA"},
	}}}, b.takeEvents())

	// the same data again is not reported
	b.receive(announcement("Press 7.A-host1", "HOST1.local.", 4840, 100, "path=/ua", "caps=DA"), peer)
	require.Empty(t, b.takeEvents())

	// changed data is
	b.receive(announcement("Press 7.A-host1", "host1.local.", 4841, 100, "path=/ua", "caps=DA"), peer)
	ev := b.takeEvents()
	require.Len(t, ev, 1)
	require.Equal(t, uint16(4841), ev[0].Instance.Port)

	// known answers are sent with the next query while the record is fresh
	var sawKnown bool
	for _, m := range b.runUntil(20 * time.Second) {
		if !m.Response && len(m.Answers) > 0 {
			require.Equal(t, `Press 7\.A-host1._opcua-tcp._tcp.local.`, m.Answers[0].PTR)
			sawKnown = true
		}
	}
	require.True(t, sawKnown)

	// refresh queries at 80% and 90% of the lifetime, then expiry
	msgs := b.runUntil(71 * time.Second) // 91 s after the last announcement
	var refresh int
	for _, m := range msgs {
		for _, q := range m.Questions {
			if q.Type == TypeSRV {
				refresh++
			}
		}
	}
	require.Equal(t, 2, refresh)
	require.Empty(t, b.takeEvents())

	b.runUntil(10 * time.Second)
	ev = b.takeEvents()
	require.Len(t, ev, 1)
	require.True(t, ev[0].Removed)
	require.Equal(t, "Press 7.A-host1", ev[0].Instance.Name)
	require.Empty(t, b.n.cache)
}

func TestBrowser_ResolvesMissingRecords(t *testing.T) {
	b := newBench(t)
	b.browse()
	b.step()

	const full = "Lone._opcua-tcp._tcp.local."
	ptrOnly := &Message{Response: true, Answers: []Record{
		{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: ClassIN, TTL: 4500, PTR: full},
	}}
	out := b.receive(ptrOnly, peer)
	require.Len(t, out, 1, "asks for the SRV and TXT records")
	require.Equal(t, []Question{
		{Name: full, Type: TypeSRV, Class: ClassIN},
		{Name: full, Type: TypeTXT, Class: ClassIN},
	}, out[0].Questions)
	require.Empty(t, b.takeEvents())

	// retried, with back-off, three times in all
	var resolves int
	for _, m := range b.runUntil(30 * time.Second) {
		if len(m.Questions) == 2 {
			resolves++
		}
	}
	require.Equal(t, 2, resolves)

	// the SRV record alone makes it an instance; the TXT record updates it
	b.receive(&Message{Response: true, Answers: []Record{
		{Name: full, Type: TypeSRV, Class: ClassIN, TTL: 120, SRV: &SRV{Port: 1, Target: "h.local."}},
	}}, peer)
	ev := b.takeEvents()
	require.Len(t, ev, 1)
	require.Empty(t, ev[0].Instance.Text)

	b.receive(&Message{Response: true, Additionals: []Record{
		{Name: full, Type: TypeTXT, Class: ClassIN, TTL: 4500, TXT: []string{"caps=LDS"}},
	}}, peer)
	ev = b.takeEvents()
	require.Len(t, ev, 1)
	require.Equal(t, []string{"caps=LDS"}, ev[0].Instance.Text)
}

func TestBrowser_Goodbye(t *testing.T) {
	b := newBench(t)
	b.browse()
	b.step()
	b.receive(announcement("A-h", "h.local.", 1, 4500), peer)
	require.Len(t, b.takeEvents(), 1)

	bye := announcement("A-h", "h.local.", 1, 0)
	b.receive(bye, peer)
	require.Empty(t, b.takeEvents(), "a goodbye takes effect a second later")
	b.advance(900 * time.Millisecond)
	require.Empty(t, b.takeEvents())
	b.advance(200 * time.Millisecond)
	ev := b.takeEvents()
	require.Len(t, ev, 1)
	require.True(t, ev[0].Removed)

	// a goodbye for an unknown instance is ignored
	b.receive(bye, peer)
	require.Empty(t, b.n.cache)

	// an instance that is announced again within the grace period survives
	b.receive(announcement("B-h", "h.local.", 2, 4500), peer)
	b.takeEvents()
	b.receive(announcement("B-h", "h.local.", 2, 0), peer)
	b.advance(500 * time.Millisecond)
	b.receive(announcement("B-h", "h.local.", 2, 4500), peer)
	b.advance(5 * time.Second)
	require.Empty(t, b.takeEvents())
	require.Len(t, b.n.cache, 1)
}

func TestBrowser_IgnoresWhatItMust(t *testing.T) {
	b := newBench(t, func(c *Config) { c.MaxInstances = 2 })
	b.browse()
	require.NoError(t, b.n.Register(testService))
	b.runUntil(3 * time.Second)

	// our own announcement, looped back
	own := announcement("UA Srv-host", "host.local.", 4840, 100)
	b.receive(own, peer)
	require.Empty(t, b.takeEvents())
	require.NotContains(t, b.logs.String(), "another responder")

	// somebody else using our instance name with other data
	b.receive(announcement("UA Srv-host", "intruder.local.", 4840, 100), peer)
	b.receive(announcement("UA Srv-host", "intruder.local.", 4840, 100), peer)
	require.Empty(t, b.takeEvents())
	require.Equal(t, 1, strings.Count(b.logs.String(), "another responder"), "logged once")

	// other services, other classes, malformed instance names
	other := announcement("X-h", "h.local.", 1, 100)
	for i := range other.Answers {
		other.Answers[i].Name = strings.Replace(other.Answers[i].Name, "_opcua-tcp", "_http", 1)
		other.Answers[i].PTR = strings.Replace(other.Answers[i].PTR, "_opcua-tcp", "_http", 1)
	}
	b.receive(other, peer)
	chaos := announcement("X-h", "h.local.", 1, 100)
	for i := range chaos.Answers {
		chaos.Answers[i].Class = 3
	}
	b.receive(chaos, peer)
	b.receive(&Message{Response: true, Answers: []Record{
		{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: ClassIN, TTL: 100, PTR: "local."},
		{Name: "_opcua-tcp._tcp.local.", Type: TypePTR, Class: ClassIN, TTL: 100, PTR: "x._http._tcp.local."},
		{Name: "local.", Type: TypeSRV, Class: ClassIN, TTL: 100, SRV: &SRV{Port: 1, Target: "h.local."}},
		{Name: "h.local.", Type: TypeA, Class: ClassIN, TTL: 100, Addr: netip.MustParseAddr("1.2.3.4")},
	}}, peer)
	// records in the authority section (probes) are not answers
	probe := announcement("P-h", "h.local.", 1, 100)
	probe.Authorities, probe.Answers = probe.Answers, nil
	b.receive(probe, peer)
	require.Empty(t, b.takeEvents())
	require.Empty(t, b.n.cache)

	// the cache is bounded
	for i := 0; i < 5; i++ {
		b.receive(announcement(fmt.Sprintf("N%d-h", i), "h.local.", 1, 100), peer)
	}
	require.Len(t, b.takeEvents(), 2)
	require.Len(t, b.n.cache, 2)

	// a lifetime is capped
	b.receive(announcement("N0-h", "h.local.", 1, 0xffffffff), peer)
	require.LessOrEqual(t, b.n.cache[canonicalName("N0-h._opcua-tcp._tcp.local.")].lifeEnd().Sub(b.now), maxTTL)

	// registering an instance that was discovered before drops the discovery
	s := testService
	s.Instance = "N1-h"
	require.NoError(t, b.n.Register(s))
	b.step()
	ev := b.takeEvents()
	require.Len(t, ev, 1)
	require.True(t, ev[0].Removed)
}

func TestNode_SendErrorsAreLogged(t *testing.T) {
	b := newBench(t)
	b.conn.failing = true
	require.NoError(t, b.n.Register(testService))
	b.step()
	require.Contains(t, b.logs.String(), "send failed")
}

// --- the node with its goroutines, on an in-memory link -------------------------

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *eventLog) has(name string, removed bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.events {
		if e.Instance.Name == name && e.Removed == removed {
			return true
		}
	}
	return false
}

func TestNode_ResponderAndBrowserOnMemNetwork(t *testing.T) {
	before := runtime.NumGoroutine()
	link := NewMemNetwork()

	responder, err := New(Config{Conns: []PacketConn{link.Conn()}})
	require.NoError(t, err)
	browser, err := New(Config{Conns: []PacketConn{link.Conn()}})
	require.NoError(t, err)

	var log eventLog
	require.NoError(t, browser.Browse(opcType, log.add))

	// registered before and after the browser's first query
	require.NoError(t, responder.Register(testService))
	waitFor(t, "the first instance", func() bool { return log.has("UA Srv-host", false) })

	second := testService
	second.Instance = "Second"
	require.NoError(t, responder.Register(second))
	waitFor(t, "the second instance", func() bool { return log.has("Second", false) })

	// a browser that joins late learns both from the answer to its query
	late, err := New(Config{Conns: []PacketConn{link.Conn()}})
	require.NoError(t, err)
	var lateLog eventLog
	require.NoError(t, late.Browse(opcType, lateLog.add))
	waitFor(t, "the late browser", func() bool { return lateLog.has("UA Srv-host", false) && lateLog.has("Second", false) })

	// a legacy querier gets a unicast answer
	legacy := link.ConnWithPort(40000)
	waitFor(t, "the legacy answer", func() bool {
		q := ptrQuery()
		q.ID = 0x4242
		require.NoError(t, legacy.WriteMulticast(mustPack(t, q)))
		got := make(chan *Message, 1)
		go func() {
			buf := make([]byte, MaxPacketSize)
			for {
				n, _, err := legacy.ReadFrom(buf)
				if err != nil {
					return
				}
				if m, err := Unpack(buf[:n]); err == nil && m.Response && len(m.Questions) == 1 {
					got <- m
					return
				}
			}
		}()
		select {
		case <-got:
			return true
		case <-time.After(2 * time.Second):
			return false
		}
	})
	require.NoError(t, legacy.Close())
	require.ErrorIs(t, legacy.WriteMulticast(nil), net.ErrClosed)

	// withdrawn instances disappear after the goodbye grace period
	require.True(t, responder.Unregister("Second", opcType))
	waitFor(t, "the goodbye of one instance", func() bool { return log.has("Second", true) })
	require.False(t, log.has("UA Srv-host", true))

	// closing the responder says goodbye for the rest
	require.NoError(t, responder.Close())
	require.NoError(t, responder.Close())
	waitFor(t, "the goodbye on close", func() bool { return log.has("UA Srv-host", true) && lateLog.has("UA Srv-host", true) })

	require.Error(t, responder.Register(testService))
	require.Error(t, responder.Browse(opcType, func(Event) {}))
	require.False(t, responder.Unregister("UA Srv-host", opcType))

	require.NoError(t, browser.Close())
	require.NoError(t, late.Close())
	waitFor(t, "the goroutines to stop", func() bool { return runtime.NumGoroutine() <= before })

	_, err = New(Config{})
	require.Error(t, err)
}

func TestMemNetwork(t *testing.T) {
	link := NewMemNetwork()
	a, b, c := link.Conn(), link.Conn(), link.Conn()
	require.NotEqual(t, a.Addrs(), b.Addrs())

	require.NoError(t, a.WriteMulticast([]byte("hello")))
	buf := make([]byte, 16)
	for _, conn := range []PacketConn{b, c} {
		n, src, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "hello", string(buf[:n]))
		require.Equal(t, a.Addrs()[0], src.Addr())
		require.Equal(t, uint16(Port), src.Port())
	}

	require.NoError(t, a.WriteTo([]byte("you"), netip.AddrPortFrom(b.Addrs()[0], Port)))
	n, _, err := b.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "you", string(buf[:n]))

	require.Error(t, a.WriteMulticast(make([]byte, MaxPacketSize+1)))

	link.SetFilter(func(p []byte) bool { return string(p) == "drop" })
	require.NoError(t, a.WriteMulticast([]byte("drop")))
	require.NoError(t, a.WriteMulticast([]byte("keep")))
	n, _, err = b.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "keep", string(buf[:n]))
	link.SetFilter(nil)

	// a receiver that does not read loses datagrams, the sender is not held up
	for i := 0; i < 1000; i++ {
		require.NoError(t, a.WriteMulticast([]byte("flood")))
	}

	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	_, _, err = c.ReadFrom(buf)
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestOnLink(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.168.1.10/24"), netip.MustParsePrefix("2001:db8::10/64")}
	for _, tc := range []struct {
		src  string
		v6   bool
		want bool
	}{
		{"192.168.1.77", false, true},
		{"192.168.2.77", false, false},
		{"8.8.8.8", false, false},
		{"fe80::1", false, false}, // wrong family for this socket
		{"192.168.1.77", true, false},
		{"fe80::1%eth0", true, true},
		{"fe80::1%eth1", true, false},
		{"fe80::1", true, true},
		{"2001:db8::99", true, true},
		{"2001:db9::99", true, false},
	} {
		require.Equal(t, tc.want, onLink(netip.MustParseAddr(tc.src), tc.v6, "eth0", prefixes), tc.src)
	}
}

func TestListen_Errors(t *testing.T) {
	_, errs, err := Listen(ListenOptions{Interfaces: []net.Interface{{Index: 9999, Name: "nope0"}}})
	require.Error(t, err)
	require.Len(t, errs, 1)

	// an interface that claims to be usable but does not exist
	_, _, err = Listen(ListenOptions{Interfaces: []net.Interface{{Index: 9999, Name: "nope0", Flags: net.FlagUp | net.FlagMulticast}}})
	require.Error(t, err)

	ifaces, err := DefaultInterfaces()
	require.NoError(t, err)
	for _, ifi := range ifaces {
		require.Zero(t, ifi.Flags&net.FlagLoopback)
	}
}

// TestNode_RealMulticast runs a responder and a browser over the real network
// stack of this machine. It announces a (fictitious) server on the local
// network, so it only runs on request.
func TestNode_RealMulticast(t *testing.T) {
	if os.Getenv("OPCUA_TEST_MULTICAST") == "" {
		t.Skip("set OPCUA_TEST_MULTICAST=1 to run the mDNS test on the real network interfaces")
	}
	open := func() []PacketConn {
		conns, errs, err := Listen(ListenOptions{})
		if err != nil {
			t.Skipf("multicast is not available on this machine: %v", err)
		}
		for _, e := range errs {
			t.Logf("interface skipped: %v", e)
		}
		return conns
	}

	// Probe: does a multicast datagram sent by one socket reach another one
	// on this host? Without that the test cannot work.
	probeTx, probeRx := open(), open()
	marker := mustPack(t, &Message{Questions: []Question{{Name: "go-opcua-probe.local.", Type: TypeTXT, Class: ClassIN}}})
	seen := make(chan struct{}, len(probeRx))
	for _, c := range probeRx {
		go func() {
			buf := make([]byte, MaxPacketSize)
			for {
				n, _, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				if bytes.Equal(buf[:n], marker) {
					seen <- struct{}{}
					return
				}
			}
		}()
	}
	looped := false
	var sendErr error
	for i := 0; i < 20 && !looped; i++ {
		for _, c := range probeTx {
			if err := c.WriteMulticast(marker); err != nil {
				sendErr = err
			}
		}
		select {
		case <-seen:
			looped = true
		case <-time.After(250 * time.Millisecond):
		}
	}
	for _, c := range append(probeTx, probeRx...) {
		_ = c.Close()
	}
	if !looped {
		t.Skipf("multicast datagrams do not loop back on this machine (last send error: %v)", sendErr)
	}

	responder, err := New(Config{Conns: open()})
	require.NoError(t, err)
	defer func() { _ = responder.Close() }()
	browser, err := New(Config{Conns: open()})
	require.NoError(t, err)
	defer func() { _ = browser.Close() }()

	name := fmt.Sprintf("go-opcua-test-%d", os.Getpid())
	var log eventLog
	require.NoError(t, browser.Browse(opcType, log.add))
	require.NoError(t, responder.Register(Service{
		Instance: name, Type: opcType, Host: name + ".local.", Port: 4840,
		Text: []string{"path=/", "caps=NA"}, LocalHost: true,
	}))
	waitFor(t, "the instance over real multicast", func() bool { return log.has(name, false) })
	require.True(t, responder.Unregister(name, opcType))
	waitFor(t, "the goodbye over real multicast", func() bool { return log.has(name, true) })
}
