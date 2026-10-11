// SPDX-License-Identifier: MIT

package reverse

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// sharedClient is the client of one of the servers that share a listener,
// with its workload.
type sharedClient struct {
	n   *node
	rec *chaoskit.StateRecorder
	c   *opcua.Client
	st  *stream
	rd  *reader

	stopFeed func()
}

// TestChaosSharedReverseListener connects four servers with distinct
// ApplicationUris (two without security, one with Basic256Sha256 and one with
// ECC_nistP256_AesGcm) to one listener that is shared by one client per
// server, plus a fifth server no client waits for. While the clients read and
// receive data changes, the reverse connect targets of the servers are
// removed and added again and the servers are restarted, and further clients
// of the same servers connect, read and disconnect, or fetch the endpoints,
// in a loop.
//
// Whatever happens, a client must only ever talk to its own server: every
// read of the marker node returns the marker of that server and every value
// comes from the range of its counter. Each client must find its way back to
// its server, over a connection of that server's current target. The
// listener must never hold more than one connection per server nobody is
// waiting for, the fifth server must never be used, and nothing may be left
// behind when everything is closed.
func TestChaosSharedReverseListener(t *testing.T) {
	// The certificates are created before the goroutines are counted.
	profiles := []profile{
		noneProfile("urn:otfabric:chaos:reverse:a"),
		rsaProfile(t),
		aeadProfile(t, "urn:otfabric:chaos:reverse:c"),
		noneProfile("urn:otfabric:chaos:reverse:d"),
	}
	verifyLeaks := chaoskit.LeakCheck(t)
	seed := chaoskit.Seed(t)
	dur := chaoskit.Duration(t, defaultDuration)
	wd := chaoskit.NewWatchdog(t)

	l := listen(t, nil)
	url := listenerURL(l)

	nodes := make([]*node, len(profiles))
	for i, prof := range profiles {
		nodes[i] = newNode(t, fmt.Sprintf("s%d-%s", i, prof.name), i, prof, seed+int64(i))
	}
	// Nothing but the ServerUri tells the last server apart for its client.
	nodes[len(nodes)-1].anyEndpoint = true
	stray := newNode(t, "stray", len(profiles), noneProfile("urn:otfabric:chaos:reverse:stray"), seed-1)
	all := append(append([]*node(nil), nodes...), stray)
	for _, n := range all {
		n.up(url)
	}
	directBefore := make([]int64, len(all))
	for i, n := range all {
		directBefore[i] = n.fwd.Accepted()
	}

	var sink chaoskit.ErrSink
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	clients := make([]*sharedClient, len(nodes))
	for i, n := range nodes {
		sc := &sharedClient{n: n, rec: chaoskit.NewStateRecorder(n.name, true)}
		sc.c = n.connect(sc.rec, n.reverseOption(l),
			opcua.RequestTimeout(3*time.Second),
			opcua.DialTimeout(2*time.Second),
			opcua.SessionTimeout(10*time.Second),
		)
		sc.stopFeed = n.feed()
		st, err := openStream(ctx, n, sc.c, n.name)
		if err != nil {
			t.Fatalf("%s: %v", n.name, err)
		}
		sc.st = st
		sc.rd = startReader(n, sc.c, n.name, &sink, 3*time.Second)
		clients[i] = sc
	}

	// served reports whether the client of a server is connected over a
	// connection of the server's current target.
	served := func(sc *sharedClient) bool {
		rc := sc.n.target()
		return sc.c.State() == opcua.Connected && rc != nil && rc.Connections() >= 1
	}

	// Further clients of the same servers come and go: they compete with
	// the long-lived client of their server for its connections.
	var (
		transients     sync.WaitGroup
		transientTally chaoskit.ErrorTally
		stopTransients = make(chan struct{})
	)
	for _, n := range nodes {
		if n.prof.name == "Basic256Sha256" {
			continue // an RSA handshake per connection is too slow for this
		}
		transients.Add(1)
		go func() {
			defer transients.Done()
			name := n.name + " (transient)"
			for i := 0; ; i++ {
				select {
				case <-stopTransients:
					return
				case <-time.After(5 * time.Millisecond):
				}
				if i%4 == 3 {
					// The discovery helpers take a connection of the server
					// from the listener as well.
					dctx, dcancel := chaoskit.OpCtx()
					eps, err := opcua.GetEndpoints(dctx, n.url(), n.reverseOption(l),
						opcua.DialTimeout(time.Second), opcua.RequestTimeout(3*time.Second))
					dcancel()
					transientTally.Add(err)
					if err != nil && !chaoskit.IsConnectionError(err) {
						sink.Addf("%s: GetEndpoints: unexpected error: %v", name, err)
					}
					if err == nil && len(eps) == 0 {
						sink.Addf("%s: GetEndpoints: no endpoints", name)
					}
					for _, ep := range eps {
						if ep.Server == nil || ep.Server.ApplicationURI != n.prof.appURI {
							sink.Addf("%s: WRONG SERVER: GetEndpoints returned an endpoint of %+v, want %q", name, ep.Server, n.prof.appURI)
						}
					}
					continue
				}
				url := n.url()
				if n.anyEndpoint {
					url = ""
				}
				// A client that loses its connection between creating and
				// activating its session cannot close the session: the
				// server keeps it until it times out.
				c, err := opcua.NewClient(url, n.clientOptions(nil, n.reverseOption(l),
					opcua.AutoReconnect(false), opcua.DialTimeout(time.Second), opcua.RequestTimeout(3*time.Second),
					opcua.SessionTimeout(2*time.Second))...)
				if err != nil {
					sink.Addf("%s: %v", name, err)
					return
				}
				cctx, ccancel := chaoskit.OpCtx()
				err = c.Connect(cctx)
				if err == nil {
					var dv *ua.DataValue
					if dv, err = c.ReadValue(cctx, n.markerID()); err == nil && dv.Value.Value() != n.marker {
						sink.Addf("%s: WRONG SERVER: marker is %v, want %q", name, dv.Value.Value(), n.marker)
					}
				}
				ccancel()
				transientTally.Add(err)
				if err != nil && !chaoskit.IsConnectionError(err) {
					sink.Addf("%s: unexpected error: %v", name, err)
				}
				chaoskit.CloseClient(c, nil)
			}
		}()
	}

	// The monitor samples what must hold at every moment.
	var maxPending atomic.Int64
	monitorDone := make(chan struct{})
	stopMonitor := make(chan struct{})
	go func() {
		defer close(monitorDone)
		for {
			select {
			case <-stopMonitor:
				return
			case <-time.After(2 * time.Millisecond):
			}
			if p := int64(l.Pending()); p > maxPending.Load() {
				maxPending.Store(p)
			}
			if rc := stray.target(); rc != nil && rc.Connections() != 0 {
				sink.Addf("WRONG SERVER: a client uses a connection of the server nobody waits for")
			}
		}
	}()

	// Two flappers, each with servers of its own, so that the faults of
	// different servers overlap.
	flap := func(id int, rng *rand.Rand, mine []*sharedClient, deadline time.Time) {
		targets := append([]*node(nil), stray)
		for _, sc := range mine {
			targets = append(targets, sc.n)
		}
		if id != 0 {
			targets = targets[1:] // the stray server belongs to the first flapper
		}
		for step := 0; time.Now().Before(deadline); step++ {
			n := targets[rng.Intn(len(targets))]
			var sc *sharedClient
			for _, x := range mine {
				if x.n == n {
					sc = x
				}
			}
			switch rng.Intn(3) {
			case 0, 1:
				logf(t, "flapper %d: %s: remove the target and add it again", id, n.name)
				srv, rc := n.server(), n.target()
				if rc == nil {
					sink.Addf("%s: server has %d targets, want 1", n.name, len(srv.ReverseConnects()))
					return
				}
				_ = wd.Do("ReverseConnect.Close", rc.Close)
				if st := rc.State(); st != server.ReverseConnectClosed {
					sink.Addf("%s: target is %v after Close", n.name, st)
				}
				sleepRand(rng, 0, 60*time.Millisecond)
				if _, err := srv.AddReverseConnect(url, fastRetry()); err != nil {
					sink.Addf("%s: AddReverseConnect: %v", n.name, err)
				}
			case 2:
				logf(t, "flapper %d: %s: restart", id, n.name)
				_ = wd.Do("server restart", func() error {
					n.stop()
					sleepRand(rng, 0, 60*time.Millisecond)
					n.start()
					return nil
				})
			}
			// Half of the time the next fault hits while the client is still
			// finding its way back.
			if sc != nil && rng.Intn(2) == 0 {
				_ = wd.Do("recover", func() error {
					if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return served(sc) }) {
						sink.Addf("%s: client did not return to its server: state %v, %s", n.name, sc.c.State(), n.describeTarget())
					}
					return nil
				})
			} else {
				sleepRand(rng, 20*time.Millisecond, 120*time.Millisecond)
			}
		}
	}
	var flappers sync.WaitGroup
	deadline := time.Now().Add(dur)
	for id, mine := range [][]*sharedClient{clients[:2], clients[2:]} {
		flappers.Add(1)
		go func() {
			defer flappers.Done()
			flap(id, rand.New(rand.NewSource(seed+int64(100*id))), mine, deadline)
		}()
	}
	wd.Wait("flappers", &flappers)
	close(stopTransients)
	wd.Wait("transient clients", &transients)
	t.Logf("transient clients: %s", transientTally.String())
	if transientTally.OK() == 0 {
		t.Errorf("no transient client ever connected")
	}

	// Every client is back at its own server and its subscription delivers.
	for _, sc := range clients {
		n := sc.n
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return served(sc) }) {
			t.Fatalf("%s: client did not return to its server: state %v, transitions %v, %s\n%s",
				n.name, sc.c.State(), sc.rec.Snapshot(), n.describeTarget(), chaoskit.AllStacks())
		}
		mark := n.counter.Load()
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return sc.st.lastValue() > mark }) {
			t.Fatalf("%s: subscription did not resume: last delivered %d, node at %d; client subscriptions %v, server %+v",
				n.name, sc.st.lastValue(), n.counter.Load(), sc.c.SubscriptionIDs(), n.resources())
		}
		rctx, rcancel := chaoskit.OpCtx()
		dv, err := sc.c.ReadValue(rctx, n.markerID())
		rcancel()
		if err != nil {
			t.Errorf("%s: read marker: %v", n.name, err)
		} else if got := dv.Value.Value(); got != n.marker {
			t.Errorf("%s: WRONG SERVER: marker is %v, want %q", n.name, got, n.marker)
		}
		// The one session the server has is the one of this client.
		var res testhook.ServerResources
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
			res = n.resources()
			return res.Channels == 1 && res.Sessions == 1 && res.Subscriptions == 1
		}) {
			t.Errorf("%s: server holds %+v, want one channel, session and subscription", n.name, res)
		}
		logf(t, "%s: the client is back at its server", n.name)
	}

	// One idle connection per server waits at the listener, and there were
	// never more.
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return l.Pending() == len(all) }) {
		t.Errorf("listener holds %d pending connection(s), want %d", l.Pending(), len(all))
	}
	close(stopMonitor)
	<-monitorDone
	if got := maxPending.Load(); got > int64(len(all)) {
		t.Errorf("listener held %d pending connections of %d servers", got, len(all))
	}
	if res := stray.resources(); res != (testhook.ServerResources{}) {
		t.Errorf("WRONG SERVER: the server nobody waits for holds %+v", res)
	}
	for i, n := range all {
		if got := n.fwd.Accepted(); got != directBefore[i] {
			t.Errorf("%s: %d connection(s) were opened to the server", n.name, got-directBefore[i])
		}
	}

	for _, sc := range clients {
		sc.rec.Check(t, false)
		sc.rd.close()
		sc.stopFeed()
		_ = wd.Do("cancel stream", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return sc.st.sub.Cancel(ctx)
		})
		_ = wd.Do("Close", func() error { chaoskit.CloseClient(sc.c, sc.rec); return nil })
		sc.st.close()
		sc.st.report(t)
		sc.rec.Check(t, true)
		t.Logf("%s: reads: %s", sc.n.name, sc.rd.tally.String())
		if sc.rd.tally.OK() == 0 {
			t.Errorf("%s: no read succeeded", sc.n.name)
		}
		logf(t, "%s: client closed", sc.n.name)
	}
	sink.Report(t)

	// A new client of each server gets that server, and afterwards the
	// servers hold nothing.
	for _, n := range nodes {
		n.requireCleanClient("new reverse client", n.reverseOption(l))
		logf(t, "%s: served a new client", n.name)
		n.requireDrained()
		logf(t, "%s: holds nothing", n.name)
	}

	// The listener notices that the servers and their connections are gone.
	for _, n := range all {
		n.stop()
		n.fwd.Close()
	}
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return l.Pending() == 0 }) {
		t.Errorf("listener still holds %d pending connection(s) of servers that are gone", l.Pending())
	}
	if err := l.Close(); err != nil {
		t.Errorf("close listener: %v", err)
	}
	wd.Close()
	verifyLeaks()
}
