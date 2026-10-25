// SPDX-License-Identifier: MIT

package chaos

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

// The diagnostics scenarios churn sessions, subscriptions and monitored
// items from several goroutines while an observer reads the server
// diagnostics. They inject no network faults, but the number of operations
// that complete is never asserted: the invariants are about the counters.
//
//   - Cumulated counters never decrease (unless diagnostics are reset).
//   - Cumulated counts are never below the current counts.
//   - At quiescence the current counts are exactly what exists, every live
//     session has its diagnostics object and no other object is left.
//   - Nothing leaks: once every client is gone the server is drained,
//     diagnostics objects included, and no goroutine is left.

// diagChurnOp performs one random operation on c. strict is false while
// diagnostics may be disabled, when the session object may be missing.
func diagChurnOp(e *env, c *opcua.Client, rng *rand.Rand, subs *[]*opcua.Subscription, strict bool) error {
	ctx, cancel := opCtx()
	defer cancel()
	switch rng.Intn(6) {
	case 0, 1:
		if _, err := c.ReadValue(ctx, e.counterID(rng.Intn(numCounters))); err != nil {
			return fmt.Errorf("read: %w", err)
		}
	case 2:
		sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: time.Duration(20+rng.Intn(3)*10) * time.Millisecond}, make(chan *opcua.PublishNotificationData, 64))
		if err != nil {
			return fmt.Errorf("subscribe: %w", err)
		}
		*subs = append(*subs, sub)
		req := opcua.NewMonitoredItemCreateRequestWithDefaults(e.scratchID(rng.Intn(numScratch)), ua.AttributeIDValue, uint32(rng.Intn(1000)))
		req.RequestedParameters.SamplingInterval = float64(10 * (1 + rng.Intn(3)))
		if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, req); err != nil {
			return fmt.Errorf("monitor: %w", err)
		}
	case 3:
		if len(*subs) > 0 {
			i := rng.Intn(len(*subs))
			if err := (*subs)[i].Cancel(ctx); err != nil {
				return fmt.Errorf("cancel: %w", err)
			}
			*subs = append((*subs)[:i], (*subs)[i+1:]...)
		}
	case 4:
		// a rejected request
		_, err := c.Read(ctx, &ua.ReadRequest{
			TimestampsToReturn: ua.TimestampsToReturn(99),
			NodesToRead:        []*ua.ReadValueID{{NodeID: e.counterID(0), AttributeID: ua.AttributeIDValue}},
		})
		if err == nil {
			return fmt.Errorf("invalid TimestampsToReturn accepted")
		}
	case 5:
		if _, err := c.SessionDiagnosticsOf(ctx, nil); err != nil && strict {
			return fmt.Errorf("session diagnostics: %w", err)
		}
	}
	return nil
}

// diagChurn runs workers that each connect clients, churn and disconnect
// until the deadline, and returns when they are done.
func diagChurn(e *env, wd *watchdog, seed int64, workers int, until time.Time, strict bool, sink *errSink) {
	var wg sync.WaitGroup
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed + int64(g)))
			for round := 0; time.Now().Before(until); round++ {
				err := wd.do(fmt.Sprintf("diagnostics churn g%d r%d", g, round), func() error {
					opts := []opcua.Option{opcua.AutoReconnect(false), opcua.SessionName(fmt.Sprintf("churn-%d", g))}
					if rng.Intn(2) == 0 {
						opts = append(opts, opcua.ReturnDiagnostics(ua.ReturnDiagnosticsAll))
					}
					c, err := opcua.NewClient(e.url(), e.clientOptions(nil, opts...)...)
					if err != nil {
						return err
					}
					ctx, cancel := opCtx()
					defer cancel()
					if err := c.Connect(ctx); err != nil {
						return fmt.Errorf("connect: %w", err)
					}
					defer closeClient(c, nil)
					var subs []*opcua.Subscription
					for i, n := 0, 1+rng.Intn(12); i < n; i++ {
						if err := diagChurnOp(e, c, rng, &subs, strict); err != nil {
							return err
						}
					}
					// Half of the clients leave their subscriptions to the
					// CloseSession.
					if rng.Intn(2) == 0 {
						for _, s := range subs {
							if err := s.Cancel(ctx); err != nil {
								return fmt.Errorf("cancel: %w", err)
							}
						}
					}
					return nil
				})
				if err != nil {
					sink.addf("worker %d round %d: %v", g, round, err)
					return
				}
			}
		}(g)
	}
	wd.wait("diagnostics churn", &wg)
}

// cumulated are the counters of ServerDiagnosticsSummary that never
// decrease.
func cumulated(s *ua.ServerDiagnosticsSummaryDataType) map[string]uint32 {
	return map[string]uint32{
		"CumulatedSessionCount":         s.CumulatedSessionCount,
		"CumulatedSubscriptionCount":    s.CumulatedSubscriptionCount,
		"RejectedRequestsCount":         s.RejectedRequestsCount,
		"SecurityRejectedRequestsCount": s.SecurityRejectedRequestsCount,
		"RejectedSessionCount":          s.RejectedSessionCount,
		"SecurityRejectedSessionCount":  s.SecurityRejectedSessionCount,
		"SessionTimeoutCount":           s.SessionTimeoutCount,
		"SessionAbortCount":             s.SessionAbortCount,
	}
}

// checkSummary checks the invariants of one summary against the previous
// one (nil after a reset).
func checkSummary(prev, cur *ua.ServerDiagnosticsSummaryDataType) error {
	if cur.CumulatedSessionCount < cur.CurrentSessionCount {
		return fmt.Errorf("CumulatedSessionCount %d < CurrentSessionCount %d", cur.CumulatedSessionCount, cur.CurrentSessionCount)
	}
	if cur.CumulatedSubscriptionCount < cur.CurrentSubscriptionCount {
		return fmt.Errorf("CumulatedSubscriptionCount %d < CurrentSubscriptionCount %d", cur.CumulatedSubscriptionCount, cur.CurrentSubscriptionCount)
	}
	if prev == nil {
		return nil
	}
	was := cumulated(prev)
	for k, v := range cumulated(cur) {
		if v < was[k] {
			return fmt.Errorf("%s decreased from %d to %d", k, was[k], v)
		}
	}
	return nil
}

// requireQuiescentDiagnostics checks the diagnostics once only the observer
// is connected.
func requireQuiescentDiagnostics(t *testing.T, e *env, obs *opcua.Client) {
	t.Helper()
	srv := e.server()
	var last string
	ok := eventually(settleLimit, func() bool {
		ctx, cancel := opCtx()
		defer cancel()
		sum, err := obs.ServerDiagnosticsSummary(ctx)
		if err != nil {
			last = err.Error()
			return false
		}
		sessions, err := obs.SessionDiagnostics(ctx)
		if err != nil {
			last = err.Error()
			return false
		}
		subs, err := obs.SubscriptionDiagnostics(ctx)
		if err != nil {
			last = err.Error()
			return false
		}
		samp, err := obs.SamplingIntervalDiagnostics(ctx)
		if err != nil {
			last = err.Error()
			return false
		}
		res := e.resources()
		last = fmt.Sprintf("summary %+v, %d session diagnostics, %d subscription diagnostics, %d sampling intervals, resources %+v",
			sum, len(sessions), len(subs), len(samp), res)
		return sum.CurrentSessionCount == 1 && sum.CurrentSubscriptionCount == 0 && sum.PublishingIntervalCount == 0 &&
			len(sessions) == 1 && len(subs) == 0 && len(samp) == 0 &&
			res.Sessions == 1 && res.DiagnosticsSessionObjects == 1 && res.Subscriptions == 0 && res.MonitoredItems == 0 &&
			srv.ServerDiagnosticsSummary().CurrentSessionCount == 1
	})
	if !ok {
		t.Errorf("diagnostics did not settle: %s", last)
	}
	if _, err := obs.SessionDiagnosticsOf(t.Context(), nil); err != nil {
		t.Errorf("observer session diagnostics: %v", err)
	}
}

// TestDiagnosticsChurn churns sessions and subscriptions while an observer
// reads ServerDiagnosticsSummary: the cumulated counters are monotonic and
// the counts are exact at quiescence.
func TestDiagnosticsChurn(t *testing.T) {
	verifyLeaks := leakCheck(t)
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	var sink errSink

	obs := e.connect(nil, opcua.AutoReconnect(false))
	until := time.Now().Add(chaosDuration(t))
	stop := make(chan struct{})
	var samples atomic.Int64
	var obsWG sync.WaitGroup
	obsWG.Add(1)
	go func() {
		defer obsWG.Done()
		var prev *ua.ServerDiagnosticsSummaryDataType
		for {
			select {
			case <-stop:
				return
			default:
			}
			err := wd.do("diagnostics observer", func() error {
				ctx, cancel := opCtx()
				defer cancel()
				sum, err := obs.ServerDiagnosticsSummary(ctx)
				if err != nil {
					return err
				}
				if err := checkSummary(prev, sum); err != nil {
					return err
				}
				prev = sum
				samples.Add(1)
				if _, err := obs.SubscriptionDiagnostics(ctx); err != nil {
					return err
				}
				_, err = obs.SessionDiagnostics(ctx)
				return err
			})
			if err != nil {
				sink.addf("observer: %v", err)
				return
			}
		}
	}()

	diagChurn(e, wd, seed, 6, until, true, &sink)
	close(stop)
	wd.wait("diagnostics observer", &obsWG)
	sink.report(t)
	if t.Failed() {
		return
	}
	t.Logf("%d summary samples", samples.Load())

	requireQuiescentDiagnostics(t, e, obs)
	closeClient(obs, nil)
	e.requireServerDrained(settleLimit)
	e.stopServer()
	e.proxy.Close()
	wd.close()
	verifyLeaks()
}

// TestDiagnosticsToggleChurn flips EnabledFlag while sessions and
// subscriptions churn: the toggling must neither deadlock nor leak session
// objects, and after the final enable the diagnostics are exact again.
func TestDiagnosticsToggleChurn(t *testing.T) {
	verifyLeaks := leakCheck(t)
	seed := seedFor(t)
	e := newEnv(t, seed)
	wd := newWatchdog(t)
	var sink errSink

	obs := e.connect(nil, opcua.AutoReconnect(false))
	until := time.Now().Add(chaosDuration(t))
	stop := make(chan struct{})
	var toggles sync.WaitGroup
	toggles.Add(1)
	go func() {
		defer toggles.Done()
		rng := rand.New(rand.NewSource(seed - 1))
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Duration(rng.Intn(30)) * time.Millisecond):
			}
			on := rng.Intn(2) == 0
			_ = wd.do("toggle diagnostics", func() error {
				srv := e.server()
				srv.SetServerDiagnosticsEnabled(on)
				ctx, cancel := opCtx()
				defer cancel()
				sum, err := obs.ServerDiagnosticsSummary(ctx)
				if err != nil {
					sink.addf("summary: %v", err)
					return nil
				}
				if err := checkSummary(nil, sum); err != nil {
					sink.addf("summary: %v", err)
				}
				return nil
			})
		}
	}()

	diagChurn(e, wd, seed, 6, until, false, &sink)
	close(stop)
	wd.wait("toggle diagnostics", &toggles)
	sink.report(t)
	if t.Failed() {
		return
	}

	e.server().SetServerDiagnosticsEnabled(true)
	requireQuiescentDiagnostics(t, e, obs)
	closeClient(obs, nil)
	e.requireServerDrained(settleLimit)
	e.stopServer()
	e.proxy.Close()
	wd.close()
	verifyLeaks()
}
