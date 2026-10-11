// SPDX-License-Identifier: MIT

package discovery

import (
	stderrors "errors"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

const (
	opcuaType = "_opcua-tcp._tcp.local."

	// mdnsTTL is the TTL, in seconds, of the records the servers of the
	// multicast scenario announce. A server whose goodbye is lost is
	// forgotten by the others when its records expire; the default TTLs (two
	// minutes and more) would make that take longer than the test.
	mdnsTTL = 3
)

// announcement builds the response a responder sends for a service instance:
// PTR, SRV and TXT records with the given TTL (0: a goodbye).
func announcement(instance, host string, port uint16, ttl uint32, text ...string) *mdns.Message {
	full := mdns.EscapeLabel(instance) + "." + opcuaType
	return &mdns.Message{Response: true, Authoritative: true, Answers: []mdns.Record{
		{Name: opcuaType, Type: mdns.TypePTR, Class: mdns.ClassIN, TTL: ttl, PTR: full},
		{Name: full, Type: mdns.TypeSRV, Class: mdns.ClassIN, CacheFlush: true, TTL: ttl, SRV: &mdns.SRV{Port: port, Target: host}},
		{Name: full, Type: mdns.TypeTXT, Class: mdns.ClassIN, CacheFlush: true, TTL: ttl, TXT: text},
	}}
}

// station is a server on the link with what it announces about itself.
type station struct {
	name string // the service instance: "<server name>-<host name>"
	host string
	caps []string
	srv  *server.Server
}

// TestMulticastUnderFaults puts servers with multicast discovery on an
// in-memory link that loses, duplicates, delays (and thereby reorders),
// truncates and corrupts datagrams. A Local Discovery Server announces the
// servers a client registers with and unregisters from it; two servers stay;
// four more are closed and replaced all the time, so that their goodbyes and
// announcements are hit by the faults. A hostile station injects garbage,
// malformed and forged mDNS messages: names that point at themselves, record
// counts that do not fit, announcements of servers that do not exist,
// goodbyes for servers that do, announcements that redirect a live server
// elsewhere, unusable host names and ports, responses with an error code.
//
// Invariants:
//
//   - no panic, no data race, no deadlock; Start and Close never block
//   - a server always has itself as record 0 of its ServerOnNetwork table,
//     and the record ids of the table are strictly increasing
//   - what an unusable announcement, or a message that must be ignored,
//     names never shows in a table
//   - every page of FindServersOnNetwork is consistent (see traverse)
//   - once the faults stop, and somebody on the link asks, the table of every
//     live server converges to the truth: all live servers and the servers
//     registered with the discovery server, with their ports and
//     capabilities; servers that left are gone, with their goodbye or when
//     their records expire, and so are the forged ones
//   - no goroutine is left behind (TestMain)
func TestMulticastUnderFaults(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	dur := chaoskit.Duration(t, 2500*time.Millisecond)
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	defer sink.Report(t)

	link := mdns.NewMemNetwork()
	onLink := testhook.ServerMulticastTransport(link).(server.Option)
	shortTTL := testhook.ServerMulticastTTL(mdnsTTL, mdnsTTL).(server.Option)

	// The names the hostile station announces in ways that must be ignored:
	// they never make it into a table. (Other names that nobody chose do: a
	// corrupted announcement is the announcement of another server, which
	// then expires.)
	never := []string{"Never-rcode", "Never-opcode", "Never-badhost", "Never-port0", "Never-http", "Never-query"}
	isNever := func(name string) bool {
		return slices.ContainsFunc(never, func(n string) bool { return strings.EqualFold(n, name) })
	}

	join := func(name, host string, caps []string, extra ...server.Option) (*station, error) {
		st := &station{name: name + "-" + host, host: host, caps: caps}
		mc := []server.MulticastOption{server.MulticastHostname(host)}
		if caps != nil {
			mc = append(mc, server.MulticastCapabilities(caps...))
		}
		opts := append(serverOpts(
			server.ApplicationURI("urn:chaos:discovery:mdns:"+host),
			server.ServerName(name),
			server.WithMulticastDiscovery(mc...),
			onLink, shortTTL,
		), extra...)
		srv, err := startServer(wd, opts...)
		if err != nil {
			return nil, err
		}
		st.srv = srv
		return st, nil
	}
	mustJoin := func(name, host string, caps []string, extra ...server.Option) *station {
		t.Helper()
		st, err := join(name, host, caps, extra...)
		if err != nil {
			t.Fatalf("discovery chaos: %v", err)
		}
		t.Cleanup(func() { _ = st.srv.Close() })
		return st
	}

	lds := mustJoin("LDS", "lds", nil, server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration()))
	lds.caps = []string{"LDS"} // the default of a discovery server
	stable := []*station{lds, mustJoin("Stable0", "st0", []string{"DA"}), mustJoin("Stable1", "st1", nil)}
	stable[2].caps = []string{"NA"} // the default
	ldsURL := serverURL(lds.srv)

	var (
		stop    = make(chan struct{})
		wg      sync.WaitGroup
		stopped = func() bool {
			select {
			case <-stop:
				return true
			default:
				return false
			}
		}
	)

	// --- faults on the link -------------------------------------------------------
	var (
		delayed  sync.WaitGroup
		frng     = rand.New(rand.NewSource(seed))
		counters = map[string]int{}
	)
	link.SetFault(func(src netip.AddrPort, b []byte) [][]byte {
		// Called with the link locked: one datagram at a time.
		counters["datagrams"]++
		switch r := frng.Intn(100); {
		case r < 25:
			counters["lost"]++
			return nil
		case r < 35:
			counters["duplicated"]++
			return [][]byte{b, b}
		case r < 50:
			// Delivered later: after the datagrams that follow it.
			counters["delayed"]++
			delayed.Add(1)
			time.AfterFunc(time.Duration(5+frng.Intn(150))*time.Millisecond, func() {
				defer delayed.Done()
				link.Inject(src, b)
			})
			return nil
		case r < 56 && len(b) > 0:
			counters["corrupted"]++
			b[frng.Intn(len(b))] ^= 1 << frng.Intn(8)
		case r < 60 && len(b) > 0:
			counters["truncated"]++
			b = b[:frng.Intn(len(b))]
		}
		return [][]byte{b}
	})

	// --- servers that come and go ---------------------------------------------------
	const slots = 4
	var (
		churners []*station
		left     int
		nextNode int
	)
	newNode := func() (*station, error) {
		nextNode++
		n := nextNode
		var caps []string
		switch n % 3 {
		case 0:
			caps = []string{"DA"}
		case 1:
			caps = []string{"HD", "AC"}
		}
		st, err := join(fmt.Sprintf("Node%d", n), fmt.Sprintf("h%d", n), caps)
		if err == nil && caps == nil {
			st.caps = []string{"NA"}
		}
		return st, err
	}
	for i := 0; i < slots; i++ {
		st, err := newNode()
		if err != nil {
			t.Fatalf("discovery chaos: %v", err)
		}
		churners = append(churners, st)
	}
	var liveMu sync.Mutex // guards churners for the readers
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed + 1))
		for !stopped() {
			time.Sleep(time.Duration(60+rng.Intn(240)) * time.Millisecond)
			i := rng.Intn(slots)
			closeServer(sink, wd, churners[i].name, churners[i].srv, closeSlack)
			left++
			st, err := newNode()
			if err != nil {
				sink.Addf("%v", err)
				return
			}
			liveMu.Lock()
			churners[i] = st
			liveMu.Unlock()
		}
	}()
	stations := func() []*station {
		liveMu.Lock()
		defer liveMu.Unlock()
		return append(slices.Clone(stable), churners...)
	}

	// --- servers registered with the discovery server --------------------------------
	const regEntries = 4
	entries := make([]*entry, regEntries)
	registeredNow := make([]bool, regEntries)
	for k := range entries {
		name, host := fmt.Sprintf("Reg%d", k), fmt.Sprintf("rhost%d", k)
		entries[k] = &entry{
			uri:       fmt.Sprintf("urn:chaos:discovery:mdns:registered:%d", k),
			urls:      []string{fmt.Sprintf("opc.tcp://%s:%d/reg", host, 5000+k)},
			instances: []string{name + "-" + host},
			mdnsName:  name,
			caps:      []string{"DA", fmt.Sprintf("X%d", k)},
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed + 2))
		c, err := dial(ldsURL)
		if err != nil {
			sink.Addf("registrar: dial: %v", err)
			return
		}
		defer chaoskit.CloseClient(c, nil)
		for !stopped() {
			k := rng.Intn(regEntries)
			online := !registeredNow[k] || rng.Intn(3) != 0
			if err := registerCall(c, entries[k], online); err != nil {
				sink.Addf("registrar: %s online=%v: %v", entries[k].uri, online, err)
				return
			}
			registeredNow[k] = online
			time.Sleep(time.Duration(rng.Intn(60)) * time.Millisecond)
		}
		// How it ends: the first two are registered, the others are not.
		for k, e := range entries {
			want := k < 2
			if err := registerCall(c, e, want); err != nil && (want || !stderrors.Is(err, ua.StatusBadNothingToDo)) {
				sink.Addf("registrar: final %s online=%v: %v", e.uri, want, err)
			}
			registeredNow[k] = want
		}
	}()

	// --- the hostile station ----------------------------------------------------------
	hostileSrc := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 255, 200, 66}), mdns.Port)
	pack := func(m *mdns.Message) []byte {
		b, err := m.Pack()
		if err != nil {
			sink.Addf("hostile station: pack: %v", err)
			return nil
		}
		return b
	}
	injected := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed + 3))
		for ; !stopped(); injected++ {
			live := stations()
			victim := live[rng.Intn(len(live))]
			var b []byte
			switch rng.Intn(16) {
			case 0: // noise
				b = make([]byte, rng.Intn(300))
				rng.Read(b)
			case 1: // a header that promises more records than there are bytes
				b = []byte{0, 0, 0x84, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
			case 2: // a name that is a compression pointer to itself
				b = []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c}
			case 3: // a pointer that points forward, and a label that runs off the end
				b = []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x20, 0, 12, 0, 1, 0, 0, 0, 60, 0, 3, 63, 'a', 'b'}
			case 4: // a valid announcement, cut short
				b = pack(announcement("Cut-ghost", "ghost.local.", 4840, 1, "path=/"))
				b = b[:rng.Intn(len(b))]
			case 5: // a server that does not exist; its records expire
				name := fmt.Sprintf("Ghost%d-ghost", rng.Intn(4))
				b = pack(announcement(name, "ghost.local.", 4840, 1, "path=/", "caps=DA"))
			case 6: // a goodbye for a server that is alive
				b = pack(announcement(victim.name, "evil.local.", 1, 0))
			case 7: // a live server, redirected; the forgery expires
				b = pack(announcement(victim.name, "evil.local.", 1, 1, "path=/evil", "caps=EVIL"))
			case 8: // a response with an error code is ignored
				m := announcement("Never-rcode", "ghost.local.", 4840, 4500, "path=/")
				m.RCode = 3
				b = pack(m)
			case 9: // so is a message with another opcode
				m := announcement("Never-opcode", "ghost.local.", 4840, 4500, "path=/")
				m.Opcode = 2
				b = pack(m)
			case 10: // a host name that cannot be part of a URL
				b = pack(announcement("Never-badhost", "bad host!.local.", 4840, 2, "path=/"))
			case 11: // no port
				b = pack(announcement("Never-port0", "ghost.local.", 0, 2, "path=/"))
			case 12: // another service type
				full := "Never-http._http._tcp.local."
				b = pack(&mdns.Message{Response: true, Authoritative: true, Answers: []mdns.Record{
					{Name: "_http._tcp.local.", Type: mdns.TypePTR, Class: mdns.ClassIN, TTL: 4500, PTR: full},
					{Name: full, Type: mdns.TypeSRV, Class: mdns.ClassIN, TTL: 120, SRV: &mdns.SRV{Port: 80, Target: "ghost.local."}},
				}})
			case 13: // records in a query are known answers, not announcements
				m := announcement("Never-query", "ghost.local.", 4840, 4500, "path=/")
				m.Response, m.Authoritative = false, false
				m.Questions = []mdns.Question{{Name: opcuaType, Type: mdns.TypeANY, Class: mdns.ClassANY}}
				b = pack(m)
			case 14: // a legacy unicast query from another port
				b = pack(&mdns.Message{ID: uint16(1 + rng.Intn(60000)), Questions: []mdns.Question{
					{Name: opcuaType, Type: mdns.TypePTR, Class: mdns.ClassIN, Unicast: true},
					{Name: mdns.EscapeLabel(victim.name) + "." + opcuaType, Type: mdns.TypeANY, Class: mdns.ClassIN},
				}})
				link.Inject(netip.AddrPortFrom(hostileSrc.Addr(), 40000), b)
				continue
			case 15: // a TXT record with control characters and a datagram that is too large
				m := announcement(victim.name, victim.host+".local.", uint16(victim.srv.Port()), mdnsTTL,
					"path=/\x00\x1b[2J", "caps=\xff\xfe")
				link.Inject(hostileSrc, pack(m))
				b = make([]byte, mdns.MaxPacketSize+1000)
				rng.Read(b)
			}
			link.Inject(hostileSrc, b)
			time.Sleep(time.Duration(rng.Intn(8)) * time.Millisecond)
		}
	}()

	// --- readers -------------------------------------------------------------------------
	// The tables as the servers hand them out.
	checkTable := func(st *station) []*ua.ServerOnNetwork {
		records := st.srv.ServersOnNetwork()
		if len(records) == 0 {
			return records // the server is closed
		}
		if records[0].RecordID != 0 || !strings.EqualFold(records[0].ServerName, st.name) {
			sink.Addf("%s: record 0 is %q (id %d), not the server itself", st.name, records[0].ServerName, records[0].RecordID)
		}
		for i, rec := range records {
			if i > 0 && rec.RecordID <= records[i-1].RecordID {
				sink.Addf("%s: record ids %d, %d: not strictly increasing", st.name, records[i-1].RecordID, rec.RecordID)
			}
			if isNever(rec.ServerName) {
				sink.Addf("%s: the table has %q (%s), which must be ignored", st.name, rec.ServerName, rec.DiscoveryURL)
			}
		}
		return records
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stopped() {
			for _, st := range stations() {
				checkTable(st)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	// Paging through FindServersOnNetwork of the servers that stay.
	for g, st := range stable[:2] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + 10 + int64(g)))
			who := "pager of " + st.name
			c, err := dial(serverURL(st.srv))
			if err != nil {
				sink.Addf("%s: dial: %v", who, err)
				return
			}
			defer chaoskit.CloseClient(c, nil)
			ids := &recordIDs{}
			filters := [][]string{nil, nil, {"DA"}, {"hd", "AC"}, {"LDS"}, {"nope"}}
			for !stopped() {
				filter := filters[rng.Intn(len(filters))]
				records, _, err := traverse(sink, who, c, ids, uint32(rng.Intn(3)), uint32(rng.Intn(5)), filter)
				if err != nil {
					sink.Addf("%s: %v", who, err)
					return
				}
				for _, rec := range records {
					if isNever(rec.ServerName) {
						sink.Addf("%s: returned %q, which must be ignored", who, rec.ServerName)
					}
				}
			}
		}()
	}

	time.Sleep(dur)
	close(stop)
	if !wd.Wait("the multicast churn", &wg) {
		return
	}
	link.SetFault(nil)
	delayed.Wait()
	t.Cleanup(func() {
		for _, st := range churners {
			_ = st.srv.Close()
		}
	})
	t.Logf("link: %v; %d hostile datagrams; %d servers left and were replaced", counters, injected, left)
	if sink.Len() > 0 {
		return
	}

	// --- once the faults have stopped -------------------------------------------------------
	type row struct {
		port string
		caps string
	}
	want := map[string]row{}
	live := stations()
	for _, st := range live {
		want[strings.ToLower(st.name)] = row{port: fmt.Sprint(st.srv.Port()), caps: fmt.Sprint(st.caps)}
	}
	for k, e := range entries {
		if registeredNow[k] {
			want[strings.ToLower(e.instances[0])] = row{port: portOf(e.urls[0]), caps: fmt.Sprint(e.caps)}
		}
	}
	tableOf := func(st *station) map[string]row {
		got := map[string]row{}
		for _, rec := range checkTable(st) {
			got[strings.ToLower(rec.ServerName)] = row{port: portOf(rec.DiscoveryURL), caps: fmt.Sprint(rec.ServerCapabilities)}
		}
		return got
	}
	// A browser that joins the link asks who is there, and everybody who is
	// answers by multicast. That is what repairs the tables of the others
	// after announcements were lost: a browser asks again by itself, but at
	// growing intervals of up to an hour.
	query := pack(&mdns.Message{Questions: []mdns.Question{{Name: opcuaType, Type: mdns.TypePTR, Class: mdns.ClassIN}}})
	asked := time.Time{}
	var diff string
	if !chaoskit.Eventually(settleLimit, func() bool {
		// Not more often than a responder repeats a record (once a second).
		if time.Since(asked) > 1100*time.Millisecond {
			link.Inject(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 255, 200, 1}), mdns.Port), query)
			asked = time.Now()
		}
		for _, st := range live {
			got := tableOf(st)
			if len(got) != len(want) {
				diff = fmt.Sprintf("%s has %d servers, want %d:\n  have: %v\n  want: %v", st.name, len(got), len(want), got, want)
				return false
			}
			for name, w := range want {
				if got[name] != w {
					diff = fmt.Sprintf("%s has %q as %+v, want %+v", st.name, name, got[name], w)
					return false
				}
			}
		}
		return true
	}) {
		t.Fatalf("the ServerOnNetwork tables did not converge after the faults: %s", diff)
	}

	// What clients are told is the same.
	c, err := dial(ldsURL)
	if err != nil {
		t.Fatalf("dial the discovery server: %v", err)
	}
	records, _, err := traverse(sink, "after the faults", c, &recordIDs{}, 0, 3, nil)
	chaoskit.CloseClient(c, nil)
	if err != nil {
		t.Fatalf("FindServersOnNetwork after the faults: %v", err)
	}
	if len(records) != len(want) {
		t.Errorf("FindServersOnNetwork after the faults: %v, want %d servers", names(records), len(want))
	}

	// --- everybody leaves, at the same time ------------------------------------------------
	var closing sync.WaitGroup
	for _, st := range live {
		closing.Add(1)
		go func() {
			defer closing.Done()
			closeServer(sink, wd, st.name, st.srv, closeSlack)
			if n := len(st.srv.ServersOnNetwork()); n != 0 {
				sink.Addf("%s: %d servers on the network after Close", st.name, n)
			}
		}()
	}
	wd.Wait("closing the servers", &closing)
}
