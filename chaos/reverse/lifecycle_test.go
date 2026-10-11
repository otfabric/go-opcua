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
	"github.com/otfabric/go-opcua/uacp"
)

// TestChaosReverseConnectLifecycle runs the whole life of the reverse connect
// targets of a server concurrently, round after round with a new server:
// several goroutines add targets (before, while and after the server starts)
// and close them at once, a little later or never; another one lists the
// targets and looks at each; clients connect through the listener, read and
// disconnect; and at a random moment the server is closed under all of them.
//
// Nothing may deadlock or panic, and Close of a target and of the server
// must return at once. Server.ReverseConnects must be consistent: a target
// is listed from the moment it was added until it is closed and never again
// afterwards, never twice, and not at all once the server is closed. After
// the server is closed every target is Closed, with no connection, and no
// target can be added. A client that connects reaches this server. Nothing
// is left behind: no pending connection at the listener, no resource in the
// server, no goroutine.
func TestChaosReverseConnectLifecycle(t *testing.T) {
	verifyLeaks := chaoskit.LeakCheck(t)
	seed := chaoskit.Seed(t)
	dur := chaoskit.Duration(t, defaultDuration/2)
	wd := chaoskit.NewWatchdog(t)
	l := listen(t, nil)

	var sink chaoskit.ErrSink
	var connects chaoskit.ErrorTally
	var added atomic.Int64
	deadline := time.Now().Add(dur)
	rounds := 0
	for ; rounds < 3 || time.Now().Before(deadline); rounds++ {
		lifecycleRound(t, wd, l, rounds, seed, &sink, &connects, &added)
		if sink.Len() > 0 {
			break
		}
	}
	sink.Report(t)
	t.Logf("%d round(s), %d target(s) added; connects: %s", rounds, added.Load(), connects.String())
	if connects.OK() == 0 {
		t.Errorf("no client ever connected")
	}

	// The connections of the servers that are gone are gone too.
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return l.Pending() == 0 }) {
		t.Errorf("listener still holds %d pending connection(s)", l.Pending())
	}
	logf(t, "listener is empty")
	if err := l.Close(); err != nil {
		t.Errorf("close listener: %v", err)
	}
	wd.Close()
	verifyLeaks()
	logf(t, "no leaks")
}

func lifecycleRound(t *testing.T, wd *chaoskit.Watchdog, l *uacp.ReverseListener, round int, seed int64,
	sink *chaoskit.ErrSink, connects *chaoskit.ErrorTally, added *atomic.Int64) {
	t.Helper()
	seed += int64(1000 * round)
	rng := rand.New(rand.NewSource(seed))
	url := listenerURL(l)
	// A server of its own per round, so that a connection of an earlier
	// server cannot be mistaken for one of this server.
	uri := fmt.Sprintf("urn:otfabric:chaos:reverse:lifecycle:%d", round)
	marker := fmt.Sprintf("marker-of-round-%d", round)

	srv, err := server.New(
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.SetLogger(chaoskit.Logger()),
		server.EndPoint("localhost", 0),
		server.ApplicationURI(uri),
	)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	markerID := ua.NewStringNodeID(populate(t, srv, 0, marker).ID(), "Marker")

	var (
		// closing is set before Server.Close is called and closed is closed
		// when it has returned.
		closing atomic.Bool
		closed  = make(chan struct{})

		mu      sync.Mutex
		handles []*server.ReverseConnect
	)
	// roundCtx ends with the server: nobody waits for it any longer.
	roundCtx, endRound := context.WithCancel(context.Background())
	defer endRound()
	isClosed := func() bool {
		select {
		case <-closed:
			return true
		default:
			return false
		}
	}
	listed := func(rc *server.ReverseConnect) bool {
		for _, x := range srv.ReverseConnects() {
			if x == rc {
				return true
			}
		}
		return false
	}
	// closeTarget closes a target and verifies what must hold afterwards.
	closeTarget := func(rc *server.ReverseConnect) {
		start := time.Now()
		if err := wd.Do("ReverseConnect.Close", rc.Close); err != nil {
			sink.Addf("ReverseConnect.Close: %v", err)
		}
		if d := time.Since(start); d > promptLimit {
			sink.Addf("ReverseConnect.Close took %v", d)
		}
		if st := rc.State(); st != server.ReverseConnectClosed {
			sink.Addf("target is %v after Close", st)
		}
		if n := rc.Connections(); n != 0 {
			sink.Addf("target has %d connection(s) after Close", n)
		}
		if listed(rc) {
			sink.Addf("a closed target is still listed")
		}
	}

	var workers sync.WaitGroup
	// The adders.
	for i := range 3 {
		workers.Add(1)
		rng := rand.New(rand.NewSource(seed + int64(i) + 1))
		go func() {
			defer workers.Done()
			var kept []*server.ReverseConnect
			for !isClosed() {
				wasClosing := closing.Load()
				rc, err := srv.AddReverseConnect(url, server.ReverseConnectRetryInterval(5*time.Millisecond, 40*time.Millisecond))
				if err != nil {
					if !closing.Load() {
						sink.Addf("AddReverseConnect failed on a server that is not being closed: %v", err)
					}
					return
				}
				added.Add(1)
				mu.Lock()
				handles = append(handles, rc)
				mu.Unlock()
				if rc.ClientURL() != url {
					sink.Addf("target for %q, want %q", rc.ClientURL(), url)
				}
				// Nobody else closes this target, except the server.
				if !listed(rc) && !closing.Load() {
					sink.Addf("a target that was added is not listed")
				}
				if wasClosing {
					// Server.Close was already under way when the target was
					// added, so it may have missed it. The target must not
					// keep running: Close returned or returns any moment,
					// and then nothing may be left.
					closeTarget(rc)
					continue
				}
				switch rng.Intn(4) {
				case 0:
					closeTarget(rc)
				case 1:
					sleepRand(rng, time.Millisecond, 30*time.Millisecond)
					closeTarget(rc)
				case 2:
					// Closed twice, concurrently.
					var both sync.WaitGroup
					for range 2 {
						both.Add(1)
						go func() { defer both.Done(); closeTarget(rc) }()
					}
					both.Wait()
				default:
					// Left to the server, unless there are enough of those.
					if kept = append(kept, rc); len(kept) > 3 {
						closeTarget(kept[0])
						kept = kept[1:]
					}
				}
				sleepRand(rng, 0, 5*time.Millisecond)
			}
		}()
	}
	// The lister.
	workers.Add(1)
	go func() {
		defer workers.Done()
		for !isClosed() {
			seen := make(map[*server.ReverseConnect]bool)
			for _, rc := range srv.ReverseConnects() {
				if seen[rc] {
					sink.Addf("a target is listed twice")
				}
				seen[rc] = true
				if n := rc.Connections(); n < 0 || n > server.DefaultReverseConnectMaxConnections {
					sink.Addf("target with %d connections", n)
				}
				_, _ = rc.State(), rc.Err()
			}
			time.Sleep(time.Millisecond)
		}
	}()
	// The clients.
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for !isClosed() {
				c, err := opcua.NewClient("",
					opcua.SecurityMode(ua.MessageSecurityModeNone),
					opcua.ReverseConnectListener(l, opcua.ReverseServerURI(uri)),
					opcua.AutoReconnect(false),
					opcua.DialTimeout(250*time.Millisecond),
					opcua.RequestTimeout(3*time.Second),
				)
				if err != nil {
					sink.Addf("new client: %v", err)
					return
				}
				ctx, cancel := context.WithTimeout(roundCtx, 10*time.Second)
				err = c.Connect(ctx)
				if err == nil {
					var dv *ua.DataValue
					if dv, err = c.ReadValue(ctx, markerID); err == nil && dv.Value.Value() != marker {
						sink.Addf("WRONG SERVER: marker is %v, want %q", dv.Value.Value(), marker)
					}
				}
				cancel()
				connects.Add(err)
				if err != nil && !chaoskit.IsConnectionError(err) {
					sink.Addf("client: unexpected error: %v", err)
				}
				chaoskit.CloseClient(c, nil)
			}
		}()
	}

	// Targets are added before, while and after the server starts.
	sleepRand(rng, 0, 30*time.Millisecond)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start server: %v", err)
	}
	sleepRand(rng, 60*time.Millisecond, 200*time.Millisecond)
	closing.Store(true)
	start := time.Now()
	_ = wd.Do("Server.Close", srv.Close)
	if d := time.Since(start); d > promptLimit {
		sink.Addf("Server.Close took %v with %d target(s)", d, len(srv.ReverseConnects()))
	}
	logf(t, "round %d: Server.Close took %v", round, time.Since(start).Round(time.Millisecond))
	close(closed)
	endRound()
	if !wd.Wait("workers of a closed server", &workers) {
		sink.Addf("round %d: workers did not finish", round)
		return
	}

	logf(t, "round %d: workers done", round)
	// The server is closed: nothing is listed, nothing runs, nothing can be
	// added.
	if rcs := srv.ReverseConnects(); len(rcs) != 0 {
		sink.Addf("a closed server lists %d target(s)", len(rcs))
	}
	if _, err := srv.AddReverseConnect(url); err == nil {
		sink.Addf("AddReverseConnect succeeded on a closed server")
	}
	for _, rc := range handles {
		if st := rc.State(); st != server.ReverseConnectClosed {
			sink.Addf("target is %v after Server.Close", st)
		}
		if n := rc.Connections(); n != 0 {
			sink.Addf("target has %d connection(s) after Server.Close", n)
		}
		_ = wd.Do("ReverseConnect.Close after Server.Close", rc.Close)
	}
	var res testhook.ServerResources
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		res = testhook.ServerResourcesOf(srv)
		return res == testhook.ServerResources{}
	}) {
		sink.Addf("closed server holds %+v", res)
	}
}
