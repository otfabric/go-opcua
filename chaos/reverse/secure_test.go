// SPDX-License-Identifier: MIT

package reverse

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/uacp"
)

// channelLifetime is the secure channel lifetime of the client under faults.
// The client renews the token after three quarters of it, so a window of
// renewalWindow always contains a renewal.
const (
	channelLifetime = 1500 * time.Millisecond
	renewalWindow   = 1250 * time.Millisecond
)

// stormLength is how long the faults of a storm follow each other.
const stormLength = 400 * time.Millisecond

// TestChaosSecureReverseConnect disturbs secured reverse connections under a
// running subscription and a read workload, once with RSA certificates
// (Basic256Sha256) and once with a policy with authenticated encryption
// (ECC_nistP256_AesGcm), both SignAndEncrypt and with a short secure channel
// lifetime.
//
// The chaos proxy sits on the path of the connections the server opens. Every
// pass applies, in random order: a reset, a half-close, a blackhole, a client
// the server cannot reach, a server restart, a truncation in the middle of a
// chunk, a flipped bit, latency across a token renewal, fragmentation, and a
// storm of faults in quick succession that also hits the reconnect itself.
//
// After a fault that breaks the connection the client must return to
// Connected over a new connection the server opens, and the subscription must
// deliver again. The other faults must not be noticed at all. Throughout,
// every value a read or the subscription delivers must be one the writer
// produced and must not be older than the one before: a flipped bit in
// particular is always detected. At the end the state transitions must have
// been legal, the server must hold nothing for the client and serve new ones,
// and no goroutine may be left.
func TestChaosSecureReverseConnect(t *testing.T) {
	// The certificates are created before the goroutines are counted.
	profiles := []profile{rsaProfile(t), aeadProfile(t, "")}
	verifyLeaks := chaoskit.LeakCheck(t)
	seed := chaoskit.Seed(t)
	dur := chaoskit.Duration(t, defaultDuration)

	// The policies run side by side; the group returns when both are done
	// and have cleaned up.
	t.Run("policies", func(t *testing.T) {
		for i, prof := range profiles {
			t.Run(prof.name, func(t *testing.T) {
				t.Parallel()
				runSecureReverse(t, prof, seed+int64(i), dur)
			})
		}
	})
	verifyLeaks()
}

func runSecureReverse(t *testing.T, prof profile, seed int64, dur time.Duration) {
	rng := rand.New(rand.NewSource(seed))
	wd := chaoskit.NewWatchdog(t)
	n := newNode(t, prof.name, 0, prof, seed)

	// The listener admits the one server it expects. A ReverseHello message
	// is not protected by anything: one that the transport garbled would
	// otherwise be kept as the connection of an unknown server, which the
	// server would take for its idle connection.
	l := listen(t, &uacp.ReverseListenerConfig{
		Filter: func(rhe *uacp.ReverseHello) error {
			if rhe.ServerURI != prof.appURI || rhe.EndpointURL != n.url() {
				return fmt.Errorf("unexpected ReverseHello %+v", rhe)
			}
			return nil
		},
	})
	rproxy := testutil.NewChaosProxy(t, l.Addr().String(), seed)
	n.up(rproxy.EndpointURL())
	// Only the endpoints were fetched the usual way.
	directBefore := n.fwd.Accepted()

	rec := chaoskit.NewStateRecorder(prof.name, true)
	c := n.connect(rec, n.reverseOption(l),
		// short timeouts: a request or handshake swallowed by a blackhole
		// must return quickly
		opcua.RequestTimeout(3*time.Second),
		opcua.DialTimeout(2*time.Second),
		opcua.SessionTimeout(10*time.Second),
		opcua.Lifetime(channelLifetime),
	)
	if got := c.SecurityPolicy(); got != prof.policyURI {
		t.Fatalf("client uses %s, want %s", got, prof.policyURI)
	}
	if rc := n.target(); rc == nil || rc.Connections() != 1 {
		t.Fatalf("the client is not connected over a reverse connection: %s", n.describeTarget())
	}

	stopFeed := n.feed()
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	st, err := openStream(ctx, n, c, prof.name)
	if err != nil {
		stopFeed()
		t.Fatal(err)
	}
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return st.received.Load() > 3 }) {
		stopFeed()
		t.Fatal("no data before the faults")
	}
	var sink chaoskit.ErrSink
	rd := startReader(n, c, prof.name, &sink, 3*time.Second)

	// recovered waits for the client to reconnect and the stream to resume.
	recovered := func(fault string, reconnectsBefore int) {
		t.Helper()
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
			return rec.Count(opcua.Reconnecting) > reconnectsBefore && c.State() == opcua.Connected
		}) {
			t.Fatalf("%s: client did not reconnect: state %v, transitions %v, %s\n%s",
				fault, c.State(), rec.Snapshot(), n.describeTarget(), chaoskit.AllStacks())
		}
		mark := n.counter.Load()
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return st.lastValue() > mark }) {
			t.Fatalf("%s: subscription did not resume: last delivered %d, node at %d; client subscriptions %v, server %+v",
				fault, st.lastValue(), n.counter.Load(), c.SubscriptionIDs(), n.resources())
		}
	}
	// steady waits until the client is connected and the server has parked
	// its next idle connection at the listener: from then on the only bytes
	// on the reverse path are those of the secure channel in use.
	steady := func(fault string) {
		t.Helper()
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return c.State() == opcua.Connected && l.Pending() == 1 }) {
			t.Fatalf("%s: no idle connection behind the one in use: client %v, %d pending, %s",
				fault, c.State(), l.Pending(), n.describeTarget())
		}
	}
	// unnoticed runs reads for d under a fault that delays the traffic but
	// loses nothing. Every read must succeed, the subscription must keep
	// delivering and the client must not lose its connection.
	unnoticed := func(fault string, d time.Duration) {
		t.Helper()
		disconnects := rec.Count(opcua.Disconnected)
		mark := st.lastValue()
		var last int64
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			rctx, rcancel := chaoskit.OpCtx()
			dv, err := c.ReadValue(rctx, n.counterID())
			rcancel()
			if err != nil {
				t.Errorf("%s: read failed: %v", fault, err)
				continue
			}
			if why := n.checkCounter(dv.Value.Value()); why != "" {
				t.Errorf("%s: WRONG VALUE: read counter: %s", fault, why)
				continue
			}
			if v := dv.Value.Value().(int64); v < last {
				t.Errorf("%s: WRONG VALUE: read counter %d after %d", fault, v, last)
			} else {
				last = v
			}
		}
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return st.lastValue() > mark }) {
			t.Errorf("%s: the subscription delivered nothing: last value %d", fault, st.lastValue())
		}
		if got := rec.Count(opcua.Disconnected); got != disconnects {
			t.Errorf("%s: the client lost its connection: %v", fault, rec.Snapshot())
		}
	}
	direction := func() testutil.Direction {
		if rng.Intn(2) == 0 {
			return testutil.ClientToServer
		}
		return testutil.ServerToClient
	}

	// In the terms of the proxy the "client" is the OPC UA server, which
	// opens the connections, and the "server" is the listener of the OPC UA
	// client.
	faults := []struct {
		name string
		// breaks tells whether the connection in use is lost.
		breaks bool
		apply  func(name string)
		// corrupts tells whether the fault alters bytes.
		corrupts bool
	}{
		{"drop", true, func(string) {
			// Reset the connection in use and the idle one behind it.
			rproxy.DropAll()
		}, false},
		{"half-close", true, func(name string) {
			d := direction()
			logf(t, "%s: %v", name, d)
			rproxy.HalfClose(d)
		}, false},
		{"blackhole", true, func(name string) {
			// Both directions go silent, for the connection in use and for
			// the idle one behind it. Requests are no longer answered.
			rproxy.SetBlackhole(testutil.ClientToServer, true)
			rproxy.SetBlackhole(testutil.ServerToClient, true)
			rctx, rcancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			_, err := c.ReadValue(rctx, n.scratchID())
			rcancel()
			if err == nil {
				t.Errorf("%s: read succeeded over a silent connection", name)
			} else if !chaoskit.IsConnectionError(err) {
				t.Errorf("%s: read failed with %v, want a connection-class error", name, err)
			}
			rproxy.SetBlackhole(testutil.ClientToServer, false)
			rproxy.SetBlackhole(testutil.ServerToClient, false)
			// Bytes were swallowed, so what is left of the byte streams is
			// cut inside a message. A real network would have lost these
			// connections too.
			rproxy.DropAll()
		}, false},
		{"client unreachable", true, func(name string) {
			// The server cannot reach the client for a while: it retries
			// with back-off and reports why.
			rproxy.SetRefuse(true)
			rproxy.DropAll()
			rc := n.target()
			if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
				return rc.State() == server.ReverseConnectBackoff && rc.Err() != nil
			}) {
				t.Errorf("%s: target is %v (%v), want Backoff with an error", name, rc.State(), rc.Err())
			}
			// The client notices the reset on its own goroutine and in its
			// own time: wait for it instead of looking once. It cannot be
			// back already: nothing gets through to it.
			if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return c.State() != opcua.Connected }) {
				t.Errorf("%s: client still reports Connected", name)
			}
			rproxy.SetRefuse(false)
		}, false},
		{"server restart", true, func(string) {
			// A new server instance: it connects to the client again, with
			// no session and no subscription.
			n.stop()
			time.Sleep(30 * time.Millisecond)
			n.start()
		}, false},
		{"truncation", true, func(name string) {
			// The next chunk of the secure channel is cut after a few bytes
			// and the connection reset.
			steady(name)
			d, keep := direction(), 1+rng.Intn(48)
			logf(t, "%s: %v after %d byte(s)", name, d, keep)
			rproxy.TruncateNext(d, keep)
		}, false},
		{"bit flip", true, func(name string) {
			// One bit of the next piece of a secured chunk is flipped.
			// Whoever receives it must notice and give up the channel.
			steady(name)
			d := direction()
			logf(t, "%s: %v", name, d)
			rproxy.CorruptNext(d, 1)
		}, true},
		{"latency across a renewal", false, func(name string) {
			rproxy.SetLatency(10*time.Millisecond, 10*time.Millisecond)
			unnoticed(name, renewalWindow)
			rproxy.SetLatency(0, 0)
		}, false},
		{"fragmentation", false, func(name string) {
			size := 1 + rng.Intn(7)
			logf(t, "%s: %d byte(s) per segment", name, size)
			rproxy.SetFragment(size)
			unnoticed(name, 250*time.Millisecond)
			rproxy.SetFragment(0)
		}, false},
		{"storm", true, func(name string) {
			// Faults in quick succession, so that they also hit the client
			// and the server while they are finding their way back: in the
			// ReverseHello and Hello exchange, while the channel is opened
			// and while the session and the subscription are restored.
			for end := time.Now().Add(stormLength); time.Now().Before(end); sleepRand(rng, 5*time.Millisecond, 50*time.Millisecond) {
				switch rng.Intn(7) {
				case 0:
					rproxy.DropAll()
				case 1:
					rproxy.HalfClose(direction())
				case 2:
					rproxy.TruncateNext(direction(), rng.Intn(64))
				case 3:
					rproxy.SetRefuse(rng.Intn(2) == 0)
				case 4:
					rproxy.SetBlackhole(direction(), rng.Intn(2) == 0)
				case 5:
					rproxy.SetLatency(time.Duration(rng.Intn(20))*time.Millisecond, time.Duration(1+rng.Intn(20))*time.Millisecond)
				case 6:
					rproxy.SetFragment(rng.Intn(16))
				}
			}
			rproxy.Heal()
			// Bytes may have been swallowed: see the blackhole.
			rproxy.DropAll()
		}, false},
	}

	// Every fault is applied at least once.
	deadline := time.Now().Add(dur)
	for pass := 0; pass == 0 || time.Now().Before(deadline); pass++ {
		for _, i := range rng.Perm(len(faults)) {
			f := faults[i]
			name := fmt.Sprintf("pass %d: %s", pass, f.name)
			_ = wd.Do(name, func() error {
				before := rec.Count(opcua.Reconnecting)
				logf(t, "%s", name)
				n.corrupting.Store(f.corrupts)
				f.apply(name)
				if f.breaks {
					recovered(name, before)
				}
				n.corrupting.Store(false)
				return nil
			})
		}
	}

	// The client ended up on a reverse connection again, and nothing was
	// opened to the server.
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		rc := n.target()
		return rc != nil && rc.Connections() == 1
	}) {
		t.Errorf("after the faults: %s, want 1 connection in use", n.describeTarget())
	}
	if got := n.fwd.Accepted(); got != directBefore {
		t.Errorf("%d connection(s) were opened to the server", got-directBefore)
	}

	rec.Check(t, false)
	rd.close()
	stopFeed()
	_ = wd.Do("cancel stream", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return st.sub.Cancel(ctx)
	})
	_ = wd.Do("Close", func() error { chaoskit.CloseClient(c, rec); return nil })
	st.close()
	st.report(t)
	sink.Report(t)
	t.Logf("reads: %s", rd.tally.String())
	t.Logf("stream: %d value(s), errors: %s", st.received.Load(), st.errs.String())
	if rd.tally.OK() == 0 {
		t.Errorf("no read succeeded")
	}
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last, ok := rec.Last()
		return ok && last == opcua.Closed && c.State() == opcua.Closed
	}) {
		t.Errorf("client is %v after Close, reported %v", c.State(), rec.Snapshot())
	}
	rec.Check(t, true)

	// The server is healthy for a client that connects the usual way and
	// for one more that waits for it, both with the same security.
	n.requireCleanClient("new client")
	n.requireCleanClient("new reverse client", n.reverseOption(l))
	n.requireDrained()

	n.stop()
	n.fwd.Close()
	rproxy.Close()
	if err := l.Close(); err != nil {
		t.Errorf("close listener: %v", err)
	}
	wd.Close()
}
