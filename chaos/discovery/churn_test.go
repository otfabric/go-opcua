// SPDX-License-Identifier: MIT

package discovery

import (
	stderrors "errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/mdns"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// registerCall sends one registration (online) or unregistration of e over c,
// with RegisterServer for a legacy entry and RegisterServer2 otherwise.
func registerCall(c *opcua.Client, e *entry, online bool) error {
	rs := &ua.RegisteredServer{
		ServerURI:     e.uri,
		ProductURI:    "urn:chaos:discovery:product",
		ServerNames:   []*ua.LocalizedText{ua.NewLocalizedTextWithLocale(e.mdnsName, "en")},
		ServerType:    ua.ApplicationTypeServer,
		DiscoveryURLs: e.urls,
		IsOnline:      online,
	}
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	if e.legacy {
		_, err := c.RegisterServer(ctx, rs)
		return err
	}
	resp, err := c.RegisterServer2(ctx, rs, &ua.MdnsDiscoveryConfiguration{MdnsServerName: e.mdnsName, ServerCapabilities: e.caps})
	if err != nil {
		return err
	}
	if !slices.Equal(resp.ConfigurationResults, []ua.StatusCode{ua.StatusOK}) {
		return fmt.Errorf("configuration results %v, want [OK]", resp.ConfigurationResults)
	}
	return nil
}

// TestChurnWithReaders has 18 servers come and go at a Local Discovery Server
// with the multicast extension while readers ask it what it knows:
//
//   - 5 servers with a registration loop, which are closed and replaced
//   - 12 servers registered by 4 clients, which renew them, unregister them,
//     or abandon them so that they expire (the registration timeout is short)
//   - one server that two clients register and unregister at the same time
//
// The readers call FindServers and FindServersWithFilter, page through
// FindServersOnNetwork with every page size, starting record id and
// capability filter, and read the tables through the API of the server.
//
// Invariants:
//
//   - no data race, no panic, no deadlock, no goroutine left behind
//   - a reader is only handed servers that were registered at some time
//     while it was reading, with the discovery URLs and capabilities they
//     registered; a server that unregistered is gone at once
//   - a registration is not lost before the registration timeout
//   - every page of FindServersOnNetwork is consistent (see traverse), a
//     record id never stands for two servers, and the traversal ends
//   - once the churn stops, the table, FindServers, FindServersOnNetwork and
//     the ServerOnNetwork table of another server on the link are exactly
//     the servers that are left: what the discovery server announces with
//     mDNS follows its table
func TestChurnWithReaders(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	dur := chaoskit.Duration(t, 2500*time.Millisecond)
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	defer sink.Report(t)

	const (
		ldsURI        = "urn:chaos:discovery:churn:lds"
		ldsTimeout    = 1200 * time.Millisecond
		serverSlots   = 5
		clientWorkers = 4
		perWorker     = 3
		// expirySlack is how late the cleanup of the discovery server may
		// run on a loaded machine.
		expirySlack = 5 * time.Second
	)
	// The cleanup of the discovery server runs every quarter of the timeout.
	m := newModel(ldsTimeout + ldsTimeout/4 + expirySlack)

	link := mdns.NewMemNetwork()
	onLink := testhook.ServerMulticastTransport(link).(server.Option)
	lds := mustStart(t, wd, serverOpts(
		server.ApplicationURI(ldsURI),
		server.ServerName("LDS"),
		server.WithLocalDiscoveryServer(server.LDSAllowInsecureRegistration(), server.LDSRegistrationTimeout(ldsTimeout)),
		server.WithMulticastDiscovery(server.MulticastHostname("lds")),
		onLink,
	)...)
	observer := mustStart(t, wd, serverOpts(
		server.ApplicationURI("urn:chaos:discovery:churn:observer"),
		server.ServerName("Observer"),
		server.WithMulticastDiscovery(server.MulticastHostname("obs")),
		onLink,
	)...)
	ldsURL := serverURL(lds)
	// The rows of the ServerOnNetwork table that are not registered servers.
	fixed := []string{"LDS-lds", "Observer-obs"}

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
		tally chaoskit.ErrorTally
	)

	// --- what a reader is handed ---------------------------------------------
	checkServers := func(who string, from time.Time, servers []*ua.ApplicationDescription, wanted []string) {
		to := time.Now()
		if wanted == nil && (len(servers) == 0 || servers[0] == nil || servers[0].ApplicationURI != ldsURI) {
			sink.Addf("%s: FindServers does not start with the discovery server itself", who)
		}
		for uri, urls := range found(sink, ldsURI, servers) {
			e := m.entry(uri)
			switch {
			case e == nil:
				sink.Addf("%s: FindServers returned the unknown server %q", who, uri)
			case !slices.Equal(urls, e.urls):
				sink.Addf("%s: FindServers returned %s with discovery URLs %v, want %v", who, uri, urls, e.urls)
			case !m.live(uri, from, to):
				sink.Addf("%s: FindServers returned %s, which was not registered while the request ran", who, uri)
			case wanted != nil && !slices.Contains(wanted, uri):
				sink.Addf("%s: FindServers returned %s, which the filter %v excludes", who, uri, wanted)
			}
		}
	}
	checkRecords := func(who string, from, to time.Time, records []*ua.ServerOnNetwork) {
		for _, rec := range records {
			if slices.ContainsFunc(fixed, func(n string) bool { return strings.EqualFold(n, rec.ServerName) }) {
				continue
			}
			e := m.instance(rec.ServerName)
			if e == nil {
				sink.Addf("%s: FindServersOnNetwork returned the unknown server %q (%s)", who, rec.ServerName, rec.DiscoveryURL)
				continue
			}
			i := slices.IndexFunc(e.instances, func(n string) bool { return strings.EqualFold(n, rec.ServerName) })
			switch {
			case rec.DiscoveryURL != e.urls[i]:
				sink.Addf("%s: FindServersOnNetwork returned %q with discovery URL %s, want %s", who, rec.ServerName, rec.DiscoveryURL, e.urls[i])
			case !slices.Equal(rec.ServerCapabilities, e.caps):
				sink.Addf("%s: FindServersOnNetwork returned %q with capabilities %v, want %v", who, rec.ServerName, rec.ServerCapabilities, e.caps)
			case !m.live(e.uri, from, to):
				sink.Addf("%s: FindServersOnNetwork returned %q, which was not registered while the traversal ran", who, rec.ServerName)
			}
		}
	}
	ids := &recordIDs{}

	// --- servers with a registration loop ------------------------------------
	var (
		nextServer int
		servers    []*registrant
		retired    []*registrant
	)
	startRegistrant := func() (*registrant, error) {
		nextServer++
		n := nextServer
		r := &registrant{
			uri:  fmt.Sprintf("urn:chaos:discovery:churn:server:%d", n),
			name: fmt.Sprintf("Server%d", n),
			log:  &eventLog{},
		}
		// The discovery URL is given so that the test knows it before the
		// server, which registers as soon as it is started, has a port.
		e := &entry{
			uri:       r.uri,
			urls:      []string{fmt.Sprintf("opc.tcp://srv-%d:4840/s%d", n, n)},
			instances: []string{fmt.Sprintf("%s-srv-%d", r.name, n)},
			mdnsName:  r.name,
			caps:      []string{"DA", "AC"},
		}
		m.add(e)
		m.begin(r.uri, time.Now())
		srv, err := startServer(wd, serverOpts(
			server.ApplicationURI(r.uri),
			server.ServerName(r.name),
			server.WithDiscoveryRegistration(ldsURL,
				server.RegisterInsecure(),
				server.RegisterInterval(80*time.Millisecond),
				server.RegisterBackoff(10*time.Millisecond, 100*time.Millisecond),
				server.RegisterRequestTimeout(30*time.Second),
				server.RegisterDiscoveryURLs(e.urls...),
				server.RegisterServerCapabilities(e.caps...),
				server.RegisterEventHandler(r.log.handle),
			),
		)...)
		if err != nil {
			return nil, err
		}
		r.srv = srv
		return r, nil
	}
	stopRegistrant := func(r *registrant) {
		closeServer(sink, wd, r.name, r.srv, closeSlack)
		m.end(r.uri, time.Now())
		r.log.markClosed()
		// The discovery server is there: the server unregistered, unless it
		// never registered or was so slow that its registration expired.
		last, ok := r.log.last()
		if !ok {
			return
		}
		expired := stderrors.Is(last.Err, ua.StatusBadNothingToDo) &&
			(r.log.registrations() == 0 || r.log.sinceRegistration() > ldsTimeout/2)
		if last.Online || (last.Err != nil && !expired) {
			sink.Addf("%s: last registration event is %+v, want a successful unregistration", r.name, last)
		}
	}
	for i := 0; i < serverSlots; i++ {
		r, err := startRegistrant()
		if err != nil {
			t.Fatalf("discovery chaos: %v", err)
		}
		t.Cleanup(func() { _ = r.srv.Close() })
		servers = append(servers, r)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(seed))
		for !stopped() {
			time.Sleep(time.Duration(50+rng.Intn(200)) * time.Millisecond)
			i := rng.Intn(len(servers))
			stopRegistrant(servers[i])
			retired = append(retired, servers[i])
			r, err := startRegistrant()
			if err != nil {
				sink.Addf("%v", err)
				return
			}
			servers[i] = r
		}
	}()

	// --- servers registered by clients ----------------------------------------
	// The keeper renews the registrations that are meant to stay when the
	// churn is over.
	var (
		keepMu sync.Mutex
		keep   []*entry
	)
	hold := func(e *entry) {
		m.begin(e.uri, time.Now())
		keepMu.Lock()
		keep = append(keep, e)
		keepMu.Unlock()
	}
	keeperStop := make(chan struct{})
	var keeper sync.WaitGroup
	keeper.Add(1)
	go func() {
		defer keeper.Done()
		c, err := dial(ldsURL)
		if err != nil {
			sink.Addf("keeper: dial: %v", err)
			return
		}
		defer chaoskit.CloseClient(c, nil)
		for {
			select {
			case <-keeperStop:
				return
			case <-time.After(ldsTimeout / 8):
			}
			keepMu.Lock()
			list := slices.Clone(keep)
			keepMu.Unlock()
			for _, e := range list {
				if err := registerCall(c, e, true); err != nil {
					sink.Addf("keeper: renewing %s: %v", e.uri, err)
					return
				}
			}
		}
	}()

	for g := 0; g < clientWorkers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g) + 1))
			who := fmt.Sprintf("client %d", g)
			c, err := dial(ldsURL)
			if err != nil {
				sink.Addf("%s: dial: %v", who, err)
				return
			}
			defer chaoskit.CloseClient(c, nil)

			type state struct {
				e *entry
				// sent is when the last accepted registration was sent: the
				// discovery server keeps it until sent+ldsTimeout at least.
				sent time.Time
			}
			own := make([]*state, perWorker)
			for k := range own {
				name := fmt.Sprintf("Client%dx%d", g, k)
				host := fmt.Sprintf("node-%d-%d", g, k)
				e := &entry{
					uri:       fmt.Sprintf("urn:chaos:discovery:churn:client:%d:%d", g, k),
					urls:      []string{fmt.Sprintf("opc.tcp://%s:4840/ua", host)},
					instances: []string{name + "-" + host},
					mdnsName:  name,
				}
				switch k {
				case 0:
					e.caps = []string{"DA"}
					// A second discovery URL on another host: a second
					// service instance.
					e.urls = append(e.urls, fmt.Sprintf("opc.tcp://alt-%d-%d:4841", g, k))
					e.instances = append(e.instances, fmt.Sprintf("%s-alt-%d-%d", name, g, k))
				case 1:
					e.caps = []string{"DA", "HD"}
				default:
					e.legacy, e.caps = true, []string{"NA"}
				}
				m.add(e)
				own[k] = &state{e: e}
			}
			register := func(s *state) bool {
				sent := time.Now()
				m.begin(s.e.uri, sent)
				err := registerCall(c, s.e, true)
				tally.Add(err)
				if err != nil {
					sink.Addf("%s: registering %s: %v", who, s.e.uri, err)
					return false
				}
				m.renewed(s.e.uri, time.Now())
				s.sent = sent
				return true
			}
			unregister := func(s *state) bool {
				err := registerCall(c, s.e, false)
				done := time.Now()
				tally.Add(err)
				switch {
				case err == nil:
					m.end(s.e.uri, done)
				case stderrors.Is(err, ua.StatusBadNothingToDo) && done.Sub(s.sent) > ldsTimeout:
					// It expired because this goroutine was too slow.
				default:
					sink.Addf("%s: unregistering %s %v after its registration: %v", who, s.e.uri, done.Sub(s.sent), err)
					return false
				}
				s.sent = time.Time{}
				return true
			}
			// fresh says that the registration is safely within its
			// lifetime.
			fresh := func(s *state) bool { return !s.sent.IsZero() && time.Since(s.sent) < ldsTimeout/2 }

			for !stopped() {
				s := own[rng.Intn(len(own))]
				ok := true
				switch r := rng.Intn(10); {
				case !fresh(s) || r < 5:
					ok = register(s) // new, renewed, or back after it expired
				case r < 8:
					ok = unregister(s)
				default:
					s.sent = time.Time{} // abandoned: it expires
				}
				if !ok {
					return
				}
				time.Sleep(time.Duration(rng.Intn(4)) * time.Millisecond)
			}
			// How the churn ends: one server stays, one unregisters, one is
			// left to expire.
			if register(own[0]) {
				hold(own[0].e)
			}
			if fresh(own[1]) {
				unregister(own[1])
			}
		}()
	}

	// Two clients register and unregister the same server at the same time.
	contended := &entry{
		uri:       "urn:chaos:discovery:churn:contended",
		urls:      []string{"opc.tcp://contended:4840"},
		instances: []string{"Contended-contended"},
		mdnsName:  "Contended",
		caps:      []string{"DA", "HD"},
	}
	m.add(contended)
	m.begin(contended.uri, time.Now())
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + 100 + int64(g)))
			c, err := dial(ldsURL)
			if err != nil {
				sink.Addf("contender %d: dial: %v", g, err)
				return
			}
			defer chaoskit.CloseClient(c, nil)
			for !stopped() {
				online := rng.Intn(5) != 0
				err := registerCall(c, contended, online)
				if err != nil && (online || !stderrors.Is(err, ua.StatusBadNothingToDo)) {
					sink.Addf("contender %d: online=%v: %v", g, online, err)
					return
				}
				if rng.Intn(4) == 0 {
					time.Sleep(time.Duration(rng.Intn(3)) * time.Millisecond)
				}
			}
		}()
	}

	// --- readers --------------------------------------------------------------
	reads := 0
	var readsMu sync.Mutex
	countRead := func() {
		readsMu.Lock()
		reads++
		readsMu.Unlock()
	}
	// FindServers and FindServersWithFilter on one SecureChannel.
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + 200 + int64(g)))
			who := fmt.Sprintf("reader %d", g)
			c, err := dial(ldsURL)
			if err != nil {
				sink.Addf("%s: dial: %v", who, err)
				return
			}
			defer chaoskit.CloseClient(c, nil)
			for !stopped() {
				var (
					resp   *ua.FindServersResponse
					wanted []string
				)
				from := time.Now()
				ctx, cancel := chaoskit.OpCtx()
				if rng.Intn(2) == 0 {
					resp, err = c.FindServers(ctx)
				} else {
					wanted = []string{"urn:chaos:discovery:churn:nobody"}
					if rng.Intn(4) == 0 {
						wanted = append(wanted, ldsURI)
					}
					for _, uri := range m.uris() {
						if rng.Intn(3) == 0 {
							wanted = append(wanted, uri)
						}
					}
					resp, err = c.FindServersWithFilter(ctx, []string{"en"}, wanted)
				}
				cancel()
				if err != nil {
					sink.Addf("%s: FindServers: %v", who, err)
					return
				}
				checkServers(who, from, resp.Servers, wanted)
				countRead()
			}
		}()
	}
	// Paging through FindServersOnNetwork on one SecureChannel.
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + 300 + int64(g)))
			who := fmt.Sprintf("pager %d", g)
			c, err := dial(ldsURL)
			if err != nil {
				sink.Addf("%s: dial: %v", who, err)
				return
			}
			defer chaoskit.CloseClient(c, nil)
			filters := [][]string{nil, nil, {"DA"}, {"da", "HD"}, {"NA"}, {"LDS"}, {"AC", "DA"}, {"nope"}}
			var highest uint32
			for !stopped() {
				var start uint32
				if rng.Intn(3) == 0 {
					start = uint32(rng.Intn(int(highest) + 3))
				}
				pageSize := uint32(rng.Intn(6)) // 0: everything at once
				filter := filters[rng.Intn(len(filters))]
				from := time.Now()
				records, to, err := traverse(sink, who, c, ids, start, pageSize, filter)
				if err != nil {
					sink.Addf("%s: FindServersOnNetwork: %v", who, err)
					return
				}
				checkRecords(who, from, to, records)
				if len(filter) == 1 && filter[0] == "nope" && len(records) != 0 {
					sink.Addf("%s: %d records for a capability nobody has", who, len(records))
				}
				for _, rec := range records {
					highest = max(highest, rec.RecordID)
				}
				countRead()
			}
		}()
	}
	// The helpers that open a connection of their own for every call.
	wg.Add(1)
	go func() {
		defer wg.Done()
		const who = "one-shot reader"
		for i := 0; !stopped(); i++ {
			from := time.Now()
			ctx, cancel := chaoskit.OpCtx()
			var err error
			switch i % 3 {
			case 0:
				var apps []*ua.ApplicationDescription
				if apps, err = opcua.FindServers(ctx, ldsURL); err == nil {
					checkServers(who, from, apps, nil)
				}
			case 1:
				var records []*ua.ServerOnNetwork
				if records, err = opcua.FindServersOnNetwork(ctx, ldsURL); err == nil {
					checkRecords(who, from, time.Now(), records)
				}
			case 2:
				var res *opcua.DiscoveryResult
				if res, err = opcua.DiscoverServers(ctx, ldsURL); err == nil {
					if !res.MulticastSupported {
						sink.Addf("%s: DiscoverServers: no multicast extension", who)
					}
					checkServers(who, from, res.Servers, nil)
					checkRecords(who, from, time.Now(), res.ServersOnNetwork)
				}
			}
			cancel()
			if err != nil {
				sink.Addf("%s: call %d: %v", who, i, err)
				return
			}
			countRead()
			// Every call opens a connection (DiscoverServers two). Flat out
			// that is more than a thousand connections per second on a
			// fast machine, which overflows the accept queue of the
			// listener: the system then refuses connections, also the one
			// a server needs to unregister, and that says nothing about
			// the discovery server.
			time.Sleep(5 * time.Millisecond)
		}
	}()
	// The tables as the server hands them out.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stopped() {
			from := time.Now()
			for uri, urls := range registered(sink, lds) {
				if e := m.entry(uri); e == nil || !slices.Equal(urls, e.urls) || !m.live(uri, from, time.Now()) {
					sink.Addf("RegisteredServers has %s %v, which is unknown or was not registered at that time", uri, urls)
				}
			}
			records := lds.ServersOnNetwork()
			checkRecords("ServersOnNetwork", from, time.Now(), records)
			_ = observer.ServersOnNetwork()
			time.Sleep(time.Millisecond)
		}
	}()

	time.Sleep(dur)
	close(stop)
	if !wd.Wait("the churn", &wg) {
		return
	}
	t.Cleanup(func() {
		for _, r := range servers {
			_ = r.srv.Close()
		}
	})
	if sink.Len() > 0 {
		close(keeperStop)
		keeper.Wait()
		return
	}
	t.Logf("%d reads; registrations by clients: %s; %d servers with a registration loop closed", reads, tally.String(), len(retired))

	// --- once the churn has stopped --------------------------------------------
	ctl, err := dial(ldsURL)
	if err != nil {
		t.Fatalf("dial the discovery server: %v", err)
	}
	defer chaoskit.CloseClient(ctl, nil)
	// The contended server is registered once more and stays.
	if err := registerCall(ctl, contended, true); err != nil {
		t.Fatalf("registering the contended server: %v", err)
	}
	hold(contended)

	want := table{}
	wantNames := slices.Clone(fixed)
	var wantDA []string
	keepMu.Lock()
	left := slices.Clone(keep)
	keepMu.Unlock()
	for _, r := range servers {
		left = append(left, m.entry(r.uri))
	}
	for _, e := range left {
		want[e.uri] = e.urls
		wantNames = append(wantNames, e.instances...)
		if slices.Contains(e.caps, "DA") {
			wantDA = append(wantDA, e.instances...)
		}
	}
	slices.Sort(wantNames)
	slices.Sort(wantDA)

	// The abandoned registrations expire. The tables are compared once they
	// have settled, not at one instant: a server with a registration loop
	// renews every 80 ms, but on a starved runner (race detector, other
	// test processes) a renewal can come later than the registration
	// timeout. The discovery server then rightly removes the registration
	// (Part 4 §5.4.5) and the next renewal brings the server back, with a
	// new ServerOnNetwork record. Every answer is still checked against
	// the model (checkServers, checkRecords, the record ids).
	var got table
	if !chaoskit.Eventually(settleLimit, func() bool {
		got = registered(sink, lds)
		return got.equal(want)
	}) {
		t.Fatalf("the table of the discovery server did not converge:\n  have:%v\n  want:%v", got, want)
	}

	var callErr error
	if !chaoskit.Eventually(settleLimit, func() bool {
		from := time.Now()
		ctx, cancel := chaoskit.OpCtx()
		resp, err := ctl.FindServers(ctx)
		cancel()
		if callErr = err; err != nil {
			return true
		}
		checkServers("after the churn", from, resp.Servers, nil)
		got = found(sink, ldsURI, resp.Servers)
		return got.equal(want)
	}) {
		t.Errorf("FindServers after the churn:\n  have:%v\n  want:%v", got, want)
	}
	if callErr != nil {
		t.Fatalf("FindServers: %v", callErr)
	}

	// settledTraversal pages through FindServersOnNetwork until it returns
	// the wanted servers.
	settledTraversal := func(what string, pageSize uint32, filter []string, wanted []string) {
		t.Helper()
		var have []string
		if !chaoskit.Eventually(settleLimit, func() bool {
			from := time.Now()
			records, to, err := traverse(sink, "after the churn", ctl, ids, 0, pageSize, filter)
			if callErr = err; err != nil {
				return true
			}
			checkRecords("after the churn", from, to, records)
			have = names(records)
			return slices.Equal(have, wanted)
		}) {
			t.Errorf("FindServersOnNetwork after the churn, %s:\n  have: %v\n  want: %v", what, have, wanted)
		}
		if callErr != nil {
			t.Fatalf("FindServersOnNetwork: %v", callErr)
		}
	}
	for _, pageSize := range []uint32{1, 4, 0} {
		settledTraversal(fmt.Sprintf("page size %d", pageSize), pageSize, nil, wantNames)
	}
	settledTraversal("filter DA", 2, []string{"da"}, wantDA)

	// What the discovery server announces with mDNS is what it has in its
	// table: another server on the link sees the same servers.
	var seen []string
	if !chaoskit.Eventually(settleLimit, func() bool {
		seen = names(observer.ServersOnNetwork())
		return slices.Equal(seen, wantNames)
	}) {
		t.Errorf("the servers another server on the link sees do not converge:\n  have: %v\n  want: %v", seen, wantNames)
	}
	for _, rec := range observer.ServersOnNetwork() {
		if e := m.instance(rec.ServerName); e != nil && !slices.Equal(rec.ServerCapabilities, e.caps) {
			t.Errorf("the observer sees %q with capabilities %v, want %v", rec.ServerName, rec.ServerCapabilities, e.caps)
		}
	}

	// --- everybody leaves -------------------------------------------------------
	close(keeperStop)
	keeper.Wait()
	for _, r := range servers {
		stopRegistrant(r)
	}
	for _, r := range append(retired, servers...) {
		r.log.check(sink, expectation{name: r.name, url: ldsURL,
			policy: ua.SecurityPolicyURINone, mode: ua.MessageSecurityModeNone})
		if strings.Contains(fmt.Sprint(registered(sink, lds)), r.uri) {
			t.Errorf("%s is still registered after it closed", r.name)
		}
	}
	closeServer(sink, wd, "the observer", observer, closeSlack)
	closeServer(sink, wd, "the discovery server", lds, closeSlack)
}
