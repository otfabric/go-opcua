// SPDX-License-Identifier: MIT

package secure

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// The tests in this file inject no faults, except where a test says so.
// Every operation must therefore succeed: any error is a failure, not an
// "expected error".

// parallelDuration is how long the fault-free parallelism tests keep their
// workload running. It follows CHAOS_DURATION for a soak, but does not grow
// beyond what a fault-free run needs to be meaningful.
func parallelDuration(t *testing.T, def time.Duration) time.Duration {
	t.Helper()
	d := chaoskit.Duration(t, def)
	if d > 4*def {
		d = 4 * def
	}
	return d
}

// secureOp performs one randomly chosen service call on c and verifies the
// result. Multi-chunk messages in both directions are part of the mix.
func secureOp(e *env, c *opcua.Client, rng *rand.Rand) error {
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	// Two in three operations are small ones; the others carry a request, a
	// response or both of several chunks.
	op := rng.Intn(15)
	if op >= 8 {
		op = []int{0, 1, 5, 6, 7, 0, 1}[op-8]
	}
	switch op {
	case 0:
		i := rng.Intn(numScratch)
		dv, err := c.ReadValue(ctx, e.scratchID(i))
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if dv.Status != ua.StatusOK || !validScratch(i, dv.Value.Value()) {
			return fmt.Errorf("read of Scratch%d: status %v value %v", i, dv.Status, dv.Value.Value())
		}
	case 1:
		i := rng.Intn(numScratch)
		sc, err := c.WriteNodeValue(ctx, e.scratchID(i), randScratch(rng, i))
		if err != nil || sc != ua.StatusOK {
			return fmt.Errorf("write: status %v: %w", sc, err)
		}
	case 2:
		// a response of several chunks
		dv, err := c.ReadValue(ctx, e.blobID())
		if err != nil {
			return fmt.Errorf("multi-chunk read: %w", err)
		}
		if !validBlob(dv.Value.Value()) {
			return fmt.Errorf("multi-chunk read returned a value that differs from the node's")
		}
	case 3:
		// a request of several chunks
		sc, err := c.WriteNodeValue(ctx, e.bigID(), bigValue(byte(rng.Intn(256))))
		if err != nil || sc != ua.StatusOK {
			return fmt.Errorf("multi-chunk write: status %v: %w", sc, err)
		}
	case 4:
		// request and response of several chunks: the value written by
		// somebody's multi-chunk request comes back whole
		dvs, err := c.ReadValues(ctx, e.bigID(), e.blobID(), e.scratchID(0))
		if err != nil {
			return fmt.Errorf("read values: %w", err)
		}
		if len(dvs) != 3 || !validBig(dvs[0].Value.Value()) || !validBlob(dvs[1].Value.Value()) || !validScratch(0, dvs[2].Value.Value()) {
			return fmt.Errorf("read values returned what no writer produced")
		}
	case 5:
		refs, err := c.BrowseAll(ctx, e.folderID())
		if err != nil {
			return fmt.Errorf("browse: %w", err)
		}
		if n := countLeaves(refs); n != numBrowse {
			return fmt.Errorf("browse: %d leaves, want %d", n, numBrowse)
		}
	case 6:
		n := int32(rng.Intn(1000))
		res, err := c.CallMethod(ctx, e.objectsID(), e.methodID(), n)
		if err != nil {
			return fmt.Errorf("call: %w", err)
		}
		if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != n*n {
			return fmt.Errorf("call(%d) returned %v %v", n, res.StatusCode, res.OutputArguments)
		}
	default:
		n := e.nonce.Add(1)
		res, err := c.CallMethod(ctx, e.objectsID(), e.onceID(), n)
		if err != nil {
			return fmt.Errorf("once: %w", err)
		}
		if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != n {
			return fmt.Errorf("once(%d) returned %v %v", n, res.StatusCode, res.OutputArguments)
		}
	}
	return nil
}

// feed keeps the counters changing until the returned function is called.
func (e *env) feed() (stop func()) {
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				for i := 0; i < numCounters; i++ {
					e.bump(i)
				}
				time.Sleep(3 * time.Millisecond)
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

// runWorkers runs n goroutines that issue secureOp on c until d has passed
// and returns the number of operations. Errors go to sink.
func runWorkers(e *env, wd *chaoskit.Watchdog, c *opcua.Client, name string, n int, d time.Duration, sink *chaoskit.ErrSink) int64 {
	deadline := time.Now().Add(d)
	return runWorkersUntil(e, wd, c, name, n, func() bool { return !time.Now().Before(deadline) }, sink)
}

// runWorkersUntil is runWorkers with a condition that ends the workload.
func runWorkersUntil(e *env, wd *chaoskit.Watchdog, c *opcua.Client, name string, n int, done func() bool, sink *chaoskit.ErrSink) int64 {
	var ops atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(e.seed + int64(w)*7919))
			for !done() {
				if err := wd.Do(name, func() error { return secureOp(e, c, rng) }); err != nil {
					sink.Addf("%s worker %d: %v", name, w, err)
					return
				}
				ops.Add(1)
			}
		}(w)
	}
	wd.Wait(name+" workers", &wg)
	return ops.Load()
}

// awaitFresh waits until st has delivered a value written after the call for
// each of its counters.
func awaitFresh(t *testing.T, e *env, st *stream) {
	t.Helper()
	for _, h := range st.handles() {
		marker := e.counters[h].Load()
		if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return st.lastValue(int(h)) > marker }) {
			t.Errorf("stream %s counter %d does not deliver: last %d, node at %d", st.name, h, st.lastValue(int(h)), e.counters[h].Load())
		}
	}
}

// TestSecureParallelOneClient puts many goroutines on one client per ECC
// policy (the AEAD ones and ECC_nistP256): reads, writes, method calls,
// browses and, above all, requests and responses of several chunks, whose
// chunks must not interleave with those of other messages and whose sequence
// numbers (and, with authenticated encryption, nonces) have to line up
// exactly. A subscription delivers in order at the same time.
func TestSecureParallelOneClient(t *testing.T) {
	t.Parallel()
	e := newEnv(t, chaoskit.Seed(t))
	wd := chaoskit.NewWatchdog(t)
	t.Cleanup(e.feed())
	d := parallelDuration(t, 1500*time.Millisecond)

	for _, pol := range []policy{polAesGcm, polChaChaPoly, polCurve25519, polP256} {
		t.Run(pol.name, func(t *testing.T) {
			t.Parallel()
			var sink chaoskit.ErrSink
			rec := chaoskit.NewStateRecorder(pol.name, true)
			c := e.connect(rec, pol)
			ctx, cancel := chaoskit.OpCtx()
			defer cancel()
			st, err := openStream(ctx, e, c, pol.name, 4, false, 0, 1)
			if err != nil {
				t.Fatal(err)
			}

			ops := runWorkers(e, wd, c, pol.name, 8, d, &sink)
			awaitFresh(t, e, st)
			sink.Report(t)
			t.Logf("%s: %d operations on one client, %d notifications", pol.name, ops, st.received.Load())

			if err := st.sub.Cancel(ctx); err != nil {
				t.Errorf("cancel subscription: %v", err)
			}
			chaoskit.CloseClient(c, rec)
			st.close()
			st.report(t)
			rec.Check(t, true)
			if n := rec.Count(opcua.Connected); n != 1 {
				t.Errorf("client connected %d times, want once: %v", n, rec.Snapshot())
			}
		})
	}
	t.Cleanup(func() { e.reportReplays() })
}

// TestSecureParallelMixedPolicies runs clients of every policy, in both
// secure modes and with both identities, against one server with RSA, ECDSA
// and Ed25519 certificates at once. The server picks keys, certificate and
// message protection per channel; nothing of one channel may leak into
// another.
func TestSecureParallelMixedPolicies(t *testing.T) {
	t.Parallel()
	e := newEnv(t, chaoskit.Seed(t))
	wd := chaoskit.NewWatchdog(t)
	t.Cleanup(e.feed())
	d := parallelDuration(t, 1500*time.Millisecond)

	type variant struct {
		pol  policy
		mode ua.MessageSecurityMode
		auth ua.UserTokenType
	}
	var variants []variant
	for i, pol := range allPolicies {
		variants = append(variants,
			variant{pol, ua.MessageSecurityModeSignAndEncrypt, ua.UserTokenTypeUserName},
			// Sign with the other identity, alternating which one
			variant{pol, ua.MessageSecurityModeSign, []ua.UserTokenType{ua.UserTokenTypeAnonymous, ua.UserTokenTypeUserName}[i%2]},
		)
	}

	var sink chaoskit.ErrSink
	var wg sync.WaitGroup
	var total atomic.Int64
	for i, v := range variants {
		wg.Add(1)
		go func(i int, v variant) {
			defer wg.Done()
			name := fmt.Sprintf("%s/%v", v.pol.name, v.mode)
			opts := append(e.securityOptions(v.pol, v.mode, v.auth),
				opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(60*time.Second), opcua.AutoReconnect(false))
			c, err := e.dialWith(nil, opts)
			if err != nil {
				sink.Addf("%s: connect: %v", name, err)
				return
			}
			if c.SecurityPolicy() != v.pol.uri || c.SecurityMode() != v.mode {
				sink.Addf("%s: connected with %s / %v", name, c.SecurityPolicy(), c.SecurityMode())
			}
			// The server answered with the certificate of the key type the
			// policy needs.
			want := pki(t).ServerCert
			if v.pol.curve != "" {
				want = pki(t).ECC.Server[v.pol.curve].Cert
			}
			if got := c.SecureChannel().RemoteCertificate(); !bytes.Equal(got, want) {
				sink.Addf("%s: the channel carries another server certificate than the one of its key type", name)
			}
			if has := len(c.SecureChannel().ChannelThumbprint()) > 0; has != uapolicy.SecureChannelEnhancements(v.pol.uri) {
				sink.Addf("%s: ChannelThumbprint present: %v", name, has)
			}

			ctx, cancel := chaoskit.OpCtx()
			defer cancel()
			st, err := openStream(ctx, e, c, name, i%3, false, i%numCounters)
			if err != nil {
				sink.Addf("%s: %v", name, err)
				return
			}
			total.Add(runWorkers(e, wd, c, name, 3, d, &sink))
			awaitFresh(t, e, st)
			if err := st.sub.Cancel(ctx); err != nil {
				sink.Addf("%s: cancel subscription: %v", name, err)
			}
			chaoskit.CloseClient(c, nil)
			st.close()
			st.report(t)
		}(i, v)
	}
	wd.Wait("clients", &wg)
	sink.Report(t)
	e.reportReplays()
	t.Logf("%d clients, %d operations", len(variants), total.Load())
	e.requireServerDrained(chaoskit.SettleLimit)
}

// openCounter counts the OpenSecureChannel requests that pass the proxy, per
// connection it cannot tell, in total it can.
type openCounter struct {
	requests  atomic.Int64
	responses atomic.Int64
}

func (o *openCounter) install(p *testutil.ChaosProxy) {
	count := func(n *atomic.Int64) func([]byte) [][]byte {
		return func(m []byte) [][]byte {
			if string(m[:3]) == "OPN" {
				n.Add(1)
			}
			return [][]byte{m}
		}
	}
	p.SetFrameMangle(testutil.ClientToServer, count(&o.requests))
	p.SetFrameMangle(testutil.ServerToClient, count(&o.responses))
}

// renewalStallLimit is the stall of the test binary from which on a failure
// of the fault-free renewal scenarios is not counted: their channels have a
// lifetime of 3 s, and a renewal that the machine delays by more than 1.5 s
// in total costs the channel, see chaoskit.StallMonitor.
const renewalStallLimit = 300 * time.Millisecond

// TestSecureRenewal runs the fault-free scenarios that renew channel tokens
// on a 3 s lifetime. They run next to each other, but before the parallel
// tests of the package start (this test is not parallel): those keep every
// CPU busy, and a renewal that does not get its turn within 1.5 s costs the
// channel.
func TestSecureRenewal(t *testing.T) {
	t.Run("UnderLoad", testRenewalUnderLoad)
	t.Run("DuringSessionActivation", testRenewalDuringSessionActivation)
}

// testRenewalUnderLoad renews the token of every channel again
// and again while requests of several chunks are in flight on it and a
// subscription publishes. A renewal replaces the keys of the channel (with
// fresh ephemeral keys on the ECC policies, chained to the previous ones
// where the policy has SecureChannelEnhancements) between two chunks of
// other messages: a chunk secured with the wrong token, a sequence number
// used twice or a nonce that is off by one fails a request, and no request
// may fail here.
func testRenewalUnderLoad(t *testing.T) {
	t.Parallel()
	e := newEnv(t, chaoskit.Seed(t))
	wd := chaoskit.NewWatchdog(t)
	stalls := chaoskit.WatchStalls(t)
	// What the clients report at the end, once it is known whether the run
	// counts (see renewalStallLimit).
	var (
		reportsMu sync.Mutex
		reports   []func()
	)
	t.Cleanup(e.feed())
	var opens openCounter
	opens.install(e.proxy)

	// A lifetime of 3 s makes the client renew every 2.25 s. The server
	// closes a channel whose token was not renewed 3.75 s after it was
	// issued, so a renewal has 1.5 s to get through: enough on a machine
	// that is busy with other test packages.
	const lifetime = 3 * time.Second
	const renewals = 2
	pols := selectedPolicies(t)
	// The workload runs until every channel had the time to be renewed
	// twice and that many renewals were seen on the wire; a renewal that a
	// busy machine delays delays the end of the test, it does not fail it.
	want := int64(len(pols) * (1 + renewals))
	begin := time.Now()
	d := parallelDuration(t, renewals*lifetime*3/4+500*time.Millisecond)
	renewed := func() bool {
		if time.Since(begin) > chaoskit.SettleLimit {
			return true
		}
		return time.Since(begin) >= d && opens.requests.Load() >= want
	}

	var sink chaoskit.ErrSink
	var wg sync.WaitGroup
	for i, pol := range pols {
		wg.Add(1)
		go func(i int, pol policy) {
			defer wg.Done()
			rec := chaoskit.NewStateRecorder(pol.name, true)
			c, err := e.dial(rec, pol, opcua.Lifetime(lifetime))
			if err != nil {
				sink.Addf("%s: connect: %v", pol.name, err)
				return
			}
			thumbprint := c.SecureChannel().ChannelThumbprint()
			session := c.Session().SessionID().String()

			ctx, cancel := chaoskit.OpCtx()
			defer cancel()
			st, err := openStream(ctx, e, c, pol.name, i%2*8, false, i%numCounters)
			if err != nil {
				sink.Addf("%s: %v", pol.name, err)
				return
			}
			ops := runWorkersUntil(e, wd, c, pol.name, 3, renewed, &sink)
			for _, h := range st.handles() {
				marker := e.counters[h].Load()
				if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return st.lastValue(int(h)) > marker }) {
					sink.Addf("%s: the subscription does not deliver after the renewals", pol.name)
				}
			}
			t.Logf("%s: %d operations across the renewals", pol.name, ops)

			// Still the same channel and session: nothing was lost and
			// recovered behind the scenes.
			if n := rec.Count(opcua.Connected); n != 1 {
				sink.Addf("%s: the client connected %d times, want once: %v", pol.name, n, rec.Snapshot())
			}
			if sc := c.SecureChannel(); sc == nil || !bytes.Equal(sc.ChannelThumbprint(), thumbprint) {
				sink.Addf("%s: the ChannelThumbprint changed with a renewal", pol.name)
			}
			if s := c.Session(); s == nil || s.SessionID().String() != session {
				sink.Addf("%s: session %s was replaced", pol.name, session)
			}
			if err := st.sub.Cancel(ctx); err != nil {
				sink.Addf("%s: cancel subscription: %v", pol.name, err)
			}
			chaoskit.CloseClient(c, rec)
			st.close()
			reportsMu.Lock()
			reports = append(reports, func() { st.report(t); rec.Check(t, true) })
			reportsMu.Unlock()
		}(i, pol)
	}
	wd.Wait("clients", &wg)
	if sink.Len() > 0 || opens.requests.Load() < want {
		stalls.SkipIfStalled(t, renewalStallLimit, "a renewal has 1.5 s before the server gives up the channel")
	}
	for _, report := range reports {
		report()
	}
	sink.Report(t)
	e.reportReplays()

	// Every channel was opened once and the channels were renewed twice
	// each.
	if got := opens.requests.Load(); got < want {
		t.Errorf("%d OpenSecureChannel requests for %d clients, want at least %d: the channels were not renewed", got, len(pols), want)
	}
	if req, resp := opens.requests.Load(), opens.responses.Load(); req != resp {
		t.Errorf("%d OpenSecureChannel requests but %d responses", req, resp)
	}
	e.requireServerDrained(chaoskit.SettleLimit)
}

// TestSecureParallelSessionMovesUnderLoad cuts the connections of clients of
// every policy while their workers and subscriptions are busy. Each client
// has to open a new SecureChannel and activate its session on it: with the
// username identity that means a new EccEncryptedSecret made with the
// ephemeral key the server handed out with the previous activation, and on
// the policies with SecureChannelEnhancements a signature bound to the new
// channel. The session and its subscription survive: the client must not
// fall back to creating new ones.
//
// The cuts are faults, so the calls in flight may fail with a connection
// error. Nothing else may fail, and nothing may return a wrong value.
// slowCall is from when on TestSecureParallelSessionMovesUnderLoad counts a
// call as slow. A call that is under way when the connection is cut normally
// fails at once, with the connection. Now and then (seen on macOS with
// several test binaries running) the reset of the proxy does not reach the
// client's socket: the client then learns of the loss from the TCP keep-alive
// probe, 15 s later, and the call fails then. That is the transport, not the
// client; the test reports how often it happened and allows for the time.
const slowCall = 10 * time.Second

func TestSecureParallelSessionMovesUnderLoad(t *testing.T) {
	t.Parallel()
	e := newEnv(t, chaoskit.Seed(t))
	wd := chaoskit.NewWatchdog(t)
	t.Cleanup(e.feed())
	pols := selectedPolicies(t)
	const cuts = 3

	type client struct {
		pol     policy
		c       *opcua.Client
		rec     *chaoskit.StateRecorder
		st      *stream
		session string
		subID   uint32
	}
	var clients []*client
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	for i, pol := range pols {
		cl := &client{pol: pol, rec: chaoskit.NewStateRecorder(pol.name, true)}
		// A request timeout far above what a healthy request needs, and a
		// session and subscription that outlive every cut by far.
		cl.c = e.connect(cl.rec, pol, opcua.RequestTimeout(30*time.Second), opcua.SessionTimeout(5*time.Minute))
		st, err := openStream(ctx, e, cl.c, pol.name, i%2*8, false, i%numCounters)
		if err != nil {
			t.Fatal(err)
		}
		cl.st = st
		cl.session = cl.c.Session().SessionID().String()
		if ids := cl.c.SubscriptionIDs(); len(ids) == 1 {
			cl.subID = ids[0]
		}
		clients = append(clients, cl)
	}

	var sink chaoskit.ErrSink
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var ok, failed, slow atomic.Int64
	for ci, cl := range clients {
		for w := 0; w < 3; w++ {
			wg.Add(1)
			go func(cl *client, id int) {
				defer wg.Done()
				rng := rand.New(rand.NewSource(e.seed + int64(id)))
				for {
					select {
					case <-stop:
						return
					default:
					}
					begin := time.Now()
					err := wd.Do(cl.pol.name, func() error { return secureOp(e, cl.c, rng) })
					if d := time.Since(begin); d > slowCall {
						slow.Add(1)
					}
					switch {
					case err == nil:
						ok.Add(1)
					case isFaultError(err) && chaoskit.IsConnectionError(err):
						failed.Add(1)
						time.Sleep(2 * time.Millisecond)
					default:
						sink.Addf("%s: unexpected error: %v", cl.pol.name, err)
						return
					}
				}
			}(cl, ci*3+w)
		}
	}

	for n := 1; n <= cuts; n++ {
		time.Sleep(300 * time.Millisecond)
		e.proxy.DropAll()
		for _, cl := range clients {
			if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
				return cl.rec.Count(opcua.Connected) > n && cl.c.State() == opcua.Connected
			}) {
				t.Fatalf("%s: not Connected again after cut %d: %v\n%s", cl.pol.name, n, cl.rec.Snapshot(), chaoskit.AllStacks())
			}
			awaitFresh(t, e, cl.st)
		}
	}
	close(stop)
	wd.Wait("workers", &wg)
	sink.Report(t)
	e.reportReplays()
	t.Logf("%d operations succeeded, %d failed with a connection error across %d cuts; %d took longer than %v",
		ok.Load(), failed.Load(), cuts, slow.Load(), slowCall)
	// The contexts of the set-up may be used up by now (see slowCall).
	ctx, cancel = chaoskit.OpCtx()
	defer cancel()

	for _, cl := range clients {
		if got := cl.c.Session().SessionID().String(); got != cl.session {
			t.Errorf("%s: the session was replaced instead of moved to the new channel: %s became %s", cl.pol.name, cl.session, got)
		}
		if ids := cl.c.SubscriptionIDs(); len(ids) != 1 || ids[0] != cl.subID {
			t.Errorf("%s: subscription %d was replaced: the client now has %v", cl.pol.name, cl.subID, ids)
		}
		if got := cl.c.SecurityPolicy(); got != cl.pol.uri {
			t.Errorf("%s: security policy after the cuts is %q", cl.pol.name, got)
		}
	}
	// The server holds exactly one session and subscription per client: no
	// session was left behind by a failed move.
	want := len(clients)
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		r := e.resources()
		return r.Sessions == want && r.Subscriptions == want && r.Channels == want
	}) {
		t.Errorf("server resources with %d clients connected: %+v", want, e.resources())
	}

	for _, cl := range clients {
		if err := cl.st.sub.Cancel(ctx); err != nil {
			t.Errorf("%s: cancel subscription: %v", cl.pol.name, err)
		}
		chaoskit.CloseClient(cl.c, cl.rec)
		cl.st.close()
		cl.st.report(t)
		cl.rec.Check(t, true)
	}
	e.requireServerDrained(chaoskit.SettleLimit)
}
