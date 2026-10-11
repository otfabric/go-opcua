// SPDX-License-Identifier: MIT

// Package chaoskit holds what the chaos suites below chaos/ share: the knobs
// (CHAOS_SEED, CHAOS_DURATION, CHAOS_LOG), bounded waiting, a deadlock
// watchdog, goroutine leak detection, a validator for the ConnState
// transitions of a client, and the classification of the errors a caller
// must expect while a connection is disturbed.
//
// It is a test helper: it must only be imported by tests.
package chaoskit

import (
	"context"
	stderrors "errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// ---------------------------------------------------------------------------
// knobs
// ---------------------------------------------------------------------------

// Names of the environment variables that control the randomized scenarios.
const (
	EnvSeed     = "CHAOS_SEED"
	EnvDuration = "CHAOS_DURATION"
	EnvLog      = "CHAOS_LOG"
)

const (
	// OpLimit bounds every single operation. An operation that has not
	// returned (with success or an error) after this long is a deadlock.
	OpLimit = 45 * time.Second

	// SettleLimit bounds every "eventually" condition (reconnect, resource
	// release, goroutine exit). It is generous (what it waits for takes a
	// few seconds at most, also under the race detector on a loaded
	// machine) but it is a budget, too: CI gives a package 120 s, and a
	// scenario that fails has to fail with its diagnosis inside that time
	// instead of running into the timeout of the test binary.
	SettleLimit = 30 * time.Second

	// budgetReserve is what the waits leave of the time the test binary may
	// run (-timeout): time for the tests to report and clean up. minWait is
	// the least any wait gets.
	budgetReserve = 15 * time.Second
	minWait       = 3 * time.Second
)

// binaryStart is when this test binary started, binaryDeadline when its
// -timeout expires (zero without one).
var (
	binaryStart    = time.Now()
	deadlineOnce   sync.Once
	binaryDeadline time.Time
)

// withinBudget cuts a wait so that it ends budgetReserve before the test
// binary runs into its -timeout. Several waits that fail one after the other
// (a scenario that is stuck fails its recovery check, then the checks after
// it) would otherwise add up to more than CI gives the package, and the
// diagnosis of the first one would be lost in the timeout panic of the
// binary. Healthy tests never get near the deadline and are not affected.
func withinBudget(limit time.Duration) time.Duration {
	deadlineOnce.Do(func() {
		if f := flag.Lookup("test.timeout"); f != nil {
			if d, err := time.ParseDuration(f.Value.String()); err == nil && d > 0 {
				binaryDeadline = binaryStart.Add(d - budgetReserve)
			}
		}
	})
	if binaryDeadline.IsZero() {
		return limit
	}
	left := time.Until(binaryDeadline)
	if left < minWait {
		left = minWait
	}
	if limit > left {
		return left
	}
	return limit
}

var processSeed = time.Now().UnixNano()

// Seed returns the seed for a scenario and logs it together with the command
// that replays the scenario. CHAOS_SEED overrides the per-process random
// seed.
func Seed(t *testing.T) int64 {
	t.Helper()
	seed := processSeed
	if s := os.Getenv(EnvSeed); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("invalid %s=%q: %v", EnvSeed, s, err)
		}
		seed = v
	}
	// The top-level test is what -run selects; the directory is the one the
	// test binary runs in, i.e. the package.
	name, _, _ := strings.Cut(t.Name(), "/")
	pkg := "."
	if wd, err := os.Getwd(); err == nil {
		if i := strings.LastIndex(wd, "/chaos"); i >= 0 {
			pkg = "." + wd[i:] + "/"
		}
	}
	t.Logf("chaos seed: %d (replay with %s=%d go test -race -run '^%s$' %s)", seed, EnvSeed, seed, name, pkg)
	return seed
}

// Duration returns the length of the fault-injection phase of a randomized
// scenario: CHAOS_DURATION, or def when it is not set.
func Duration(t *testing.T, def time.Duration) time.Duration {
	t.Helper()
	s := os.Getenv(EnvDuration)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		t.Fatalf("invalid %s=%q", EnvDuration, s)
	}
	return d
}

// Logger returns a logger for servers and clients when CHAOS_LOG names a
// level (debug, info, warn, error), and nil otherwise.
func Logger() *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(os.Getenv(EnvLog))); err != nil || os.Getenv(EnvLog) == "" {
		return nil
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// ---------------------------------------------------------------------------
// generic helpers
// ---------------------------------------------------------------------------

// Eventually polls cond until it returns true or limit expires.
//
// A wait never runs past the time budget of the test binary, see
// withinBudget.
func Eventually(limit time.Duration, cond func() bool) bool {
	limit = withinBudget(limit)
	deadline := time.Now().Add(limit)
	for wait := 5 * time.Millisecond; ; {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(wait)
		if wait < 200*time.Millisecond {
			wait *= 2
		}
	}
}

// WaitGroupTimeout waits for wg and reports whether it finished within limit.
func WaitGroupTimeout(wg *sync.WaitGroup, limit time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(withinBudget(limit)):
		return false
	}
}

// AllStacks returns the stacks of all goroutines.
func AllStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// OpCtx is the context for one fault-free operation. The timeout only guards
// against a hang; it is far above anything a healthy request needs.
func OpCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// CloseClient closes c with a bounded context and tells the recorder (which
// may be nil) that the user initiated the shutdown.
func CloseClient(c *opcua.Client, rec *StateRecorder) {
	if rec != nil {
		rec.MarkClosing()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Close(ctx)
}

// ---------------------------------------------------------------------------
// deadlock watchdog
// ---------------------------------------------------------------------------

// Watchdog tracks in-flight operations and fails the test when one of them
// does not return within OpLimit.
type Watchdog struct {
	t     *testing.T
	limit time.Duration

	mu    sync.Mutex
	ops   map[uint64]opInfo
	next  uint64
	fired bool

	stop chan struct{}
	done chan struct{}
}

type opInfo struct {
	name  string
	start time.Time
}

// NewWatchdog starts a watchdog that is stopped when the test ends.
func NewWatchdog(t *testing.T) *Watchdog {
	w := &Watchdog{
		t:     t,
		limit: OpLimit,
		ops:   make(map[uint64]opInfo),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go w.run()
	t.Cleanup(w.Close)
	return w
}

// Close stops the watchdog. It may be called more than once.
func (w *Watchdog) Close() {
	w.mu.Lock()
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	w.mu.Unlock()
	<-w.done
}

func (w *Watchdog) run() {
	defer close(w.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-tick.C:
			w.check()
		}
	}
}

func (w *Watchdog) check() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return
	}
	for _, op := range w.ops {
		if d := time.Since(op.start); d > w.limit {
			w.fired = true
			w.t.Errorf("DEADLOCK: operation %q has not returned after %v\n%s", op.name, d.Round(time.Second), AllStacks())
			return
		}
	}
}

// Do runs fn and registers it with the watchdog while it is in flight.
func (w *Watchdog) Do(name string, fn func() error) error {
	w.mu.Lock()
	w.next++
	k := w.next
	w.ops[k] = opInfo{name: name, start: time.Now()}
	w.mu.Unlock()

	err := fn()

	w.mu.Lock()
	delete(w.ops, k)
	w.mu.Unlock()
	return err
}

// Wait waits for wg and reports a deadlock if it does not finish in time.
func (w *Watchdog) Wait(what string, wg *sync.WaitGroup) bool {
	w.t.Helper()
	if WaitGroupTimeout(wg, w.limit) {
		return true
	}
	w.mu.Lock()
	fired := w.fired
	w.fired = true
	w.mu.Unlock()
	if !fired {
		w.t.Errorf("DEADLOCK: %s did not finish within %v\n%s", what, w.limit, AllStacks())
	}
	return false
}

// ---------------------------------------------------------------------------
// goroutine leak detection (stdlib only)
// ---------------------------------------------------------------------------

const modulePath = "github.com/otfabric/go-opcua"

// ModuleGoroutines returns the stacks of all goroutines that run or were
// created by code of this module, keyed by goroutine id.
func ModuleGoroutines() map[string]string {
	out := make(map[string]string)
	for _, g := range strings.Split(AllStacks(), "\n\n") {
		if !strings.Contains(g, modulePath) {
			continue
		}
		header, _, _ := strings.Cut(g, "\n")
		fields := strings.Fields(header) // "goroutine 12 [running]:"
		if len(fields) < 2 {
			continue
		}
		out[fields[1]] = g
	}
	return out
}

// LeakCheck snapshots the goroutines of this module and returns a function
// that verifies that no additional ones are left. Goroutines are given
// SettleLimit to exit before they are reported.
//
// It must only be used in tests that do not run in parallel with others.
func LeakCheck(t *testing.T) (verify func()) {
	t.Helper()
	baseline := ModuleGoroutines()
	return func() {
		t.Helper()
		var leaked []string
		ok := Eventually(SettleLimit, func() bool {
			leaked = leaked[:0]
			for gid, stack := range ModuleGoroutines() {
				if _, known := baseline[gid]; !known {
					leaked = append(leaked, stack)
				}
			}
			return len(leaked) == 0
		})
		if !ok {
			t.Errorf("GOROUTINE LEAK: %d goroutine(s) still running %v after shutdown:\n\n%s",
				len(leaked), SettleLimit, strings.Join(leaked, "\n\n"))
		}
	}
}

// Main runs the tests of a package and adds a final, process-wide goroutine
// leak check: whatever any test left behind is caught after every test has
// finished and cleaned up. Call it from TestMain:
//
//	func TestMain(m *testing.M) { chaoskit.Main(m) }
func Main(m *testing.M) {
	code := m.Run()
	if code == 0 {
		var leaked []string
		ok := Eventually(SettleLimit, func() bool {
			leaked = leaked[:0]
			for _, stack := range ModuleGoroutines() {
				// the goroutine running TestMain itself
				if strings.Contains(stack, "chaoskit.Main(") {
					continue
				}
				leaked = append(leaked, stack)
			}
			return len(leaked) == 0
		})
		if !ok {
			fmt.Fprintf(os.Stderr, "GOROUTINE LEAK: %d goroutine(s) of this module are still running after all tests finished:\n\n%s\n",
				len(leaked), strings.Join(leaked, "\n\n"))
			code = 1
		}
	}
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// connection state recorder
// ---------------------------------------------------------------------------

// StateRecorder records the ConnState transitions reported through
// WithConnStateHandler and validates them against the legal state machine.
type StateRecorder struct {
	name          string
	autoReconnect bool

	mu      sync.Mutex
	seq     []opcua.ConnState
	closing int // len(seq) when the user started closing the client, or -1
}

// NewStateRecorder returns a recorder for a client with the given name.
func NewStateRecorder(name string, autoReconnect bool) *StateRecorder {
	return &StateRecorder{name: name, autoReconnect: autoReconnect, closing: -1}
}

// Handle is the function to pass to opcua.WithConnStateHandler.
func (r *StateRecorder) Handle(s opcua.ConnState) {
	r.mu.Lock()
	r.seq = append(r.seq, s)
	r.mu.Unlock()
}

// MarkClosing records that the user is about to call Close. Transitions
// reported from then on race with the shutdown and are only required to end
// in Closed.
func (r *StateRecorder) MarkClosing() {
	r.mu.Lock()
	if r.closing < 0 {
		r.closing = len(r.seq)
	}
	r.mu.Unlock()
}

// Last returns the most recently reported state.
func (r *StateRecorder) Last() (opcua.ConnState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seq) == 0 {
		return 0, false
	}
	return r.seq[len(r.seq)-1], true
}

// Snapshot returns the states reported so far.
func (r *StateRecorder) Snapshot() []opcua.ConnState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]opcua.ConnState(nil), r.seq...)
}

// Count returns how often state s was reported.
func (r *StateRecorder) Count(s opcua.ConnState) int {
	n := 0
	for _, x := range r.Snapshot() {
		if x == s {
			n++
		}
	}
	return n
}

// legalNext lists the transitions a client may report while it is in use.
//
//	Closed       -> Connecting
//	Connecting   -> Connected | Closed
//	Connected    -> Disconnected
//	Disconnected -> Reconnecting | Connected | Closed(*)
//	Reconnecting -> Reconnecting | Connected
//
// (*) only without AutoReconnect: with AutoReconnect a client must never give
// up on its own, so Closed is only legal once the user calls Close.
// Disconnected -> Connected happens when only the subscriptions had to be
// repaired and the channel and session survived.
func (r *StateRecorder) legalNext(from, to opcua.ConnState) bool {
	switch from {
	case opcua.Closed:
		return to == opcua.Connecting
	case opcua.Connecting:
		return to == opcua.Connected || to == opcua.Closed
	case opcua.Connected:
		return to == opcua.Disconnected
	case opcua.Disconnected:
		return to == opcua.Reconnecting || to == opcua.Connected || (to == opcua.Closed && !r.autoReconnect)
	case opcua.Reconnecting:
		return to == opcua.Reconnecting || to == opcua.Connected
	}
	return false
}

// Check validates the recorded sequence. If closed is true the client has
// been closed by the user and the final state must be Closed.
func (r *StateRecorder) Check(t *testing.T, closed bool) {
	t.Helper()
	r.mu.Lock()
	seq := append([]opcua.ConnState(nil), r.seq...)
	closing := r.closing
	r.mu.Unlock()

	strict := len(seq)
	if closing >= 0 {
		strict = closing
	}
	prev := opcua.Closed
	for i := 0; i < strict; i++ {
		if !r.legalNext(prev, seq[i]) {
			t.Errorf("client %s: illegal ConnState transition %v -> %v at step %d of %v", r.name, prev, seq[i], i, seq)
			break
		}
		prev = seq[i]
	}
	if closed {
		if len(seq) == 0 || seq[len(seq)-1] != opcua.Closed {
			t.Errorf("client %s: last reported ConnState after Close is not Closed: %v", r.name, seq)
		}
	}
}

// ---------------------------------------------------------------------------
// error classification
// ---------------------------------------------------------------------------

// IsConnectionError reports whether err is an error a caller must expect
// while the transport, secure channel or session is disturbed: the request
// did not complete because the connection, channel, session or subscription
// it was using went away or did not answer in time.
func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}
	// context of the caller
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// transport
	var netErr net.Error
	var uacpErr *uacp.Error
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, net.ErrClosed), errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.ECONNABORTED), errors.Is(err, syscall.ETIMEDOUT),
		stderrors.As(err, &netErr), stderrors.As(err, &uacpErr):
		return true
	}
	// secure channel / client state
	switch {
	case errors.Is(err, errors.ErrSecureChannelClosed), errors.Is(err, errors.ErrNotConnected),
		errors.Is(err, errors.ErrSessionClosed), errors.Is(err, errors.ErrSessionNotActivated):
		return true
	}
	// status codes reported by the server or synthesised by the client
	for _, sc := range []ua.StatusCode{
		ua.StatusBadTimeout,
		ua.StatusBadServerNotConnected,
		ua.StatusBadNotConnected,
		ua.StatusBadConnectionClosed,
		ua.StatusBadCommunicationError,
		ua.StatusBadSecureChannelClosed,
		ua.StatusBadSecureChannelIDInvalid,
		ua.StatusBadSecureChannelTokenUnknown,
		ua.StatusBadSessionIDInvalid,
		ua.StatusBadSessionClosed,
		ua.StatusBadSessionNotActivated,
		ua.StatusBadSubscriptionIDInvalid,
		ua.StatusBadNoSubscription,
		ua.StatusBadServerHalted,
		ua.StatusBadShutdown,
	} {
		if errors.Is(err, sc) {
			return true
		}
	}
	return false
}

var digits = regexp.MustCompile(`[0-9]+`)

// ErrorTally counts errors by class for the scenario summary.
type ErrorTally struct {
	mu sync.Mutex
	m  map[string]int
	ok atomic.Int64
}

// Add counts err; nil counts as a success.
func (e *ErrorTally) Add(err error) {
	if err == nil {
		e.ok.Add(1)
		return
	}
	// Addresses, ids and counts would make every error a class of its own.
	key := digits.ReplaceAllString(err.Error(), "N")
	if len(key) > 80 {
		key = key[:80]
	}
	e.mu.Lock()
	if e.m == nil {
		e.m = make(map[string]int)
	}
	e.m[key]++
	e.mu.Unlock()
}

// OK returns the number of successes.
func (e *ErrorTally) OK() int64 { return e.ok.Load() }

func (e *ErrorTally) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "ok=%d", e.ok.Load())
	for k, v := range e.m {
		fmt.Fprintf(&b, "\n    %6d x %s", v, k)
	}
	return b.String()
}

// ErrSink collects invariant violations from worker goroutines.
type ErrSink struct {
	mu   sync.Mutex
	errs []string
}

// Addf records a violation; only the first 25 are kept.
func (s *ErrSink) Addf(format string, args ...any) {
	s.mu.Lock()
	if len(s.errs) < 25 {
		s.errs = append(s.errs, fmt.Sprintf(format, args...))
	}
	s.mu.Unlock()
}

// Len returns the number of recorded violations.
func (s *ErrSink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.errs)
}

// Report fails the test for every recorded violation.
func (s *ErrSink) Report(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.errs {
		t.Error(e)
	}
}
