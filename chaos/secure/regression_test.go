// SPDX-License-Identifier: MIT

package secure

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/ua"
)

// The tests in this file pin down the product defects the secured chaos
// scenarios found, each with a small deterministic test on a real client and
// server. The unit-level regression tests are next to the code they cover
// (uasc/chunk_size_test.go, uasc/sequence_check_test.go,
// client_activate_token_test.go).

// TestSecureEnvironment is the fault-free baseline: a client of every policy
// connects with its username identity and passes the checks a clean client
// has to pass after a storm.
//
// Regression: with a block cipher (the RSA policies, ECC_nistP256 and
// ECC_nistP384 in SignAndEncrypt mode) every full chunk was one byte longer
// than the send buffer of 65535 bytes, the receiver refused it and reported
// io.EOF, and no multi-chunk message got through. The multi-chunk read of
// this check failed on those three policies.
func TestSecureEnvironment(t *testing.T) {
	verifyLeaks := chaoskit.LeakCheck(t)
	e := newEnv(t, chaoskit.Seed(t))
	for _, pol := range selectedPolicies(t) {
		e.requireCleanClient(pol)
	}
	e.requireServerDrained(chaoskit.SettleLimit)
	e.stopServer()
	e.proxy.Close()
	verifyLeaks()
}

// armed is a one-shot trigger for a fault on the wire.
type armed struct {
	on   atomic.Bool
	hits atomic.Int64
}

// take reports whether the fault is to be applied now, and disarms it.
func (a *armed) take() bool {
	if a.on.CompareAndSwap(true, false) {
		a.hits.Add(1)
		return true
	}
	return false
}

// TestRegressionReplayedRequestIsNotExecuted repeats a request on the wire,
// on every policy: the server must execute it once.
//
// Regression: the sequence numbers of received chunks were not verified. On
// the policies without authenticated encryption the copy passed the
// signature check and the server executed the request a second time.
func TestRegressionReplayedRequestIsNotExecuted(t *testing.T) {
	t.Parallel()
	e := newEnv(t, chaoskit.Seed(t))
	var replay armed
	var mu sync.Mutex // one connection at a time is under attack
	e.proxy.SetFrameMangle(testutil.ClientToServer, func(m []byte) [][]byte {
		if string(m[:3]) == "MSG" && replay.take() {
			return [][]byte{m, m}
		}
		return [][]byte{m}
	})

	for _, pol := range selectedPolicies(t) {
		t.Run(pol.name, func(t *testing.T) {
			rec := chaoskit.NewStateRecorder(pol.name, true)
			c := e.connect(rec, pol)
			ctx, cancel := chaoskit.OpCtx()
			defer cancel()

			for round := 0; round < 3; round++ {
				if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return c.State() == opcua.Connected }) {
					t.Fatalf("round %d: client is %v", round, c.State())
				}
				mu.Lock()
				n := e.nonce.Add(1)
				hits := replay.hits.Load()
				replay.on.Store(true)
				// The request goes out twice. Whether its response still
				// arrives before the server drops the channel is open; that
				// it is not executed twice is not.
				res, err := c.CallMethod(ctx, e.objectsID(), e.onceID(), n)
				replay.on.Store(false)
				mu.Unlock()
				if replay.hits.Load() != hits+1 {
					t.Fatalf("round %d: the request was not repeated on the wire", round)
				}
				if err == nil && (res.StatusCode != ua.StatusOK || res.OutputArguments[0].Value() != n) {
					t.Errorf("round %d: once(%d) returned %v %v", round, n, res.StatusCode, res.OutputArguments)
				}
				if err != nil && !isFaultError(err) {
					t.Errorf("round %d: unexpected error: %v", round, err)
				}
				// The server refuses the copy and gives up the channel; the
				// client comes back on a new one.
				if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return rec.Count(opcua.Connected) >= round+2 }) {
					t.Fatalf("round %d: the channel survived a replayed chunk: %v", round, rec.Snapshot())
				}
			}
			e.reportReplays()
			chaoskit.CloseClient(c, rec)
			rec.Check(t, true)
		})
	}
}

// TestRegressionIncompleteMultiChunkMessageIsRefused takes a chunk out of a
// multi-chunk response, repeats one, and swaps two, on every policy: the
// read must fail, it must never return a value put together from what
// arrived.
//
// Regression: without the sequence number check the client assembled the
// remaining chunks of the policies without authenticated encryption and
// decoded the result.
func TestRegressionIncompleteMultiChunkMessageIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, chaoskit.Seed(t))

	const (
		drop = iota
		repeat
		swap
	)
	var (
		mu     sync.Mutex
		fault  armed
		kind   int
		chunks int // intermediate chunks seen since the fault was armed
		held   []byte
	)
	e.proxy.SetFrameMangle(testutil.ServerToClient, func(m []byte) [][]byte {
		mu.Lock()
		defer mu.Unlock()
		if held != nil {
			out := [][]byte{m, held}
			held = nil
			return out
		}
		// The second intermediate chunk ("MSGC") of a response.
		if string(m[:4]) != "MSGC" || !fault.on.Load() {
			return [][]byte{m}
		}
		if chunks++; chunks != 2 {
			return [][]byte{m}
		}
		chunks = 0
		fault.take()
		switch kind {
		case drop:
			return nil
		case repeat:
			return [][]byte{m, m}
		default:
			held = m
			return nil
		}
	})

	for _, pol := range selectedPolicies(t) {
		t.Run(pol.name, func(t *testing.T) {
			rec := chaoskit.NewStateRecorder(pol.name, true)
			c := e.connect(rec, pol, opcua.RequestTimeout(5*time.Second))
			for k, name := range []string{"lost", "repeated", "swapped"} {
				if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return c.State() == opcua.Connected }) {
					t.Fatalf("%s chunk: client is %v", name, c.State())
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				// healthy first: the value arrives whole
				dv, err := c.ReadValue(ctx, e.blobID())
				if err != nil || !validBlob(dv.Value.Value()) {
					cancel()
					t.Fatalf("%s chunk: fault-free multi-chunk read: %v", name, err)
				}
				mu.Lock()
				kind, chunks = k, 0
				hits := fault.hits.Load()
				fault.on.Store(true)
				mu.Unlock()
				dv, err = c.ReadValue(ctx, e.blobID())
				cancel()
				fault.on.Store(false)
				if fault.hits.Load() != hits+1 {
					t.Fatalf("%s chunk: the fault was not applied", name)
				}
				switch {
				case err == nil && !validBlob(dv.Value.Value()):
					t.Errorf("WRONG VALUE: a multi-chunk response with a %s chunk was delivered", name)
				case err == nil:
					t.Errorf("a multi-chunk response with a %s chunk was accepted", name)
				case !isFaultError(err):
					t.Errorf("%s chunk: unexpected error: %v", name, err)
				}
				// The client gives up the channel and comes back on a new one.
				if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool { return rec.Count(opcua.Connected) >= k+2 }) {
					t.Fatalf("%s chunk: the channel survived: %v", name, rec.Snapshot())
				}
			}
			chaoskit.CloseClient(c, rec)
			rec.Check(t, true)
		})
	}
}

// testRenewalDuringSessionActivation (run by TestSecureRenewal) activates the session of a
// client again and again while its channel renews its token, on every
// policy. The activations must all succeed.
//
// Regression (needs -race): the server stored the security policy and the
// client certificate of a channel again with every renewal, while the
// session services read them from another goroutine to verify the signature
// of an ActivateSession request.
func testRenewalDuringSessionActivation(t *testing.T) {
	t.Parallel()
	e := newEnv(t, chaoskit.Seed(t))
	stalls := chaoskit.WatchStalls(t)
	var opens openCounter
	opens.install(e.proxy)
	pols := selectedPolicies(t)

	var wg sync.WaitGroup
	var sink chaoskit.ErrSink
	want := int64(3 * len(pols)) // every channel opened and renewed twice
	begin := time.Now()
	for _, pol := range pols {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A lifetime of 3 s makes the client renew every 2.25 s, and
			// leaves a renewal 1.5 s before the server gives up the
			// channel: enough on a machine that is busy with other tests
			// (four times that on the slow policies, see policy.lifetime).
			c, err := e.dial(nil, pol, opcua.Lifetime(pol.lifetime(3*time.Second)), opcua.AutoReconnect(false))
			if err != nil {
				sink.Addf("%s: connect: %v", pol.name, err)
				return
			}
			ctx, cancel := chaoskit.OpCtx()
			defer cancel()
			n := 0
			for opens.requests.Load() < want && time.Since(begin) < chaoskit.SettleLimit {
				if err := c.ActivateSession(ctx, c.Session()); err != nil {
					sink.Addf("%s: activation %d: %v", pol.name, n, err)
					return
				}
				n++
				// not flat out: the renewal has to get its turn
				time.Sleep(time.Millisecond)
			}
			if _, err := c.ReadValue(ctx, e.scratchID(0)); err != nil {
				sink.Addf("%s: read after %d activations: %v", pol.name, n, err)
			}
			chaoskit.CloseClient(c, nil)
		}()
	}
	wg.Wait()
	if sink.Len() > 0 || opens.requests.Load() < want {
		stalls.SkipIfStalled(t, renewalStallLimit, "a renewal has 1.5 s before the server gives up the channel")
	}
	sink.Report(t)
	if got := opens.requests.Load(); got < want {
		t.Errorf("%d OpenSecureChannel requests, want %d: the channels were not renewed", got, want)
	}
}
