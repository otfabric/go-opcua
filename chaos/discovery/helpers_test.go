// SPDX-License-Identifier: MIT

package discovery

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

const (
	// settleLimit bounds every "eventually" condition.
	settleLimit = chaoskit.SettleLimit

	// startBound is what Start may take whatever the state of the discovery
	// server: it never waits for one. The bound is far above what a start
	// needs on a loaded machine under the race detector.
	startBound = 20 * time.Second

	// closeSlack is added to the time Close may spend on unregistering. It
	// absorbs the scheduling noise of a loaded machine.
	closeSlack = 8 * time.Second
)

// TestMain adds a final, process-wide goroutine leak check: the scenarios run
// in parallel, so whatever any of them left behind (registration loops,
// registration cleanup, mDNS readers and timers, channels to the discovery
// server) is caught after all of them have finished.
func TestMain(m *testing.M) { chaoskit.Main(m) }

// serverOpts returns the options every server of the suite has, followed by
// extra.
func serverOpts(extra ...server.Option) []server.Option {
	opts := []server.Option{
		server.EndPoint("localhost", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}
	if l := chaoskit.Logger(); l != nil {
		opts = append(opts, server.SetLogger(l))
	}
	return append(opts, extra...)
}

// startServer creates and starts a server. Start is watched for a deadlock
// and must not take longer than startBound. It may be called from any
// goroutine.
func startServer(wd *chaoskit.Watchdog, opts ...server.Option) (*server.Server, error) {
	srv, err := server.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("new server: %w", err)
	}
	begin := time.Now()
	if err := wd.Do("Server.Start", func() error { return srv.Start(context.Background()) }); err != nil {
		return nil, fmt.Errorf("start server: %w", err)
	}
	if d := time.Since(begin); d > startBound {
		_ = srv.Close()
		return nil, fmt.Errorf("start took %v, more than %v", d, startBound)
	}
	return srv, nil
}

// mustStart is startServer for the goroutine of the test. The server is
// closed when the test ends unless the test closed it before.
func mustStart(t *testing.T, wd *chaoskit.Watchdog, opts ...server.Option) *server.Server {
	t.Helper()
	srv, err := startServer(wd, opts...)
	if err != nil {
		t.Fatalf("discovery chaos: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// closeServer closes a server under the watchdog and reports a violation if
// it takes longer than bound. It returns how long Close took.
func closeServer(sink *chaoskit.ErrSink, wd *chaoskit.Watchdog, name string, srv *server.Server, bound time.Duration) time.Duration {
	begin := time.Now()
	_ = wd.Do("Server.Close "+name, srv.Close)
	d := time.Since(begin)
	if d > bound {
		sink.Addf("Close of %s took %v, more than %v", name, d, bound)
	}
	return d
}

// serverURL is the URL of a server started with serverOpts.
func serverURL(srv *server.Server) string {
	return fmt.Sprintf("opc.tcp://localhost:%d", srv.Port())
}

// dial opens a SecureChannel (no session) to a server: all the discovery
// services need.
func dial(endpoint string, opts ...opcua.Option) (*opcua.Client, error) {
	opts = append(opts, opcua.AutoReconnect(false))
	c, err := opcua.NewClient(endpoint, append([]opcua.Option{opcua.InsecureNoSecurity()}, opts...)...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	if err := c.Dial(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// onFirstRequest returns a function for ChaosProxy.SetMangle that hands the
// first service request it sees to fn and forwards everything else as it is.
// On a channel without security, opened for one registration, that request
// is the registration: the messages before it are the Hello ("HEL") and the
// OpenSecureChannel request ("OPN").
func onFirstRequest(fn func(b []byte) []byte) func(b []byte) []byte {
	var seen atomic.Bool
	return func(b []byte) []byte {
		if bytes.HasPrefix(b, []byte("MSG")) && seen.CompareAndSwap(false, true) {
			return fn(b)
		}
		return b
	}
}

// ---------------------------------------------------------------------------
// registration events
// ---------------------------------------------------------------------------

// eventLog records the events a registration loop reports and checks that
// they are consistent.
type eventLog struct {
	mu     sync.Mutex
	events []server.RegistrationEvent
	closed bool // Close of the server has returned
	late   int  // events reported after that
	// accepted is when the last accepted registration was reported.
	accepted time.Time
}

func (l *eventLog) handle(e server.RegistrationEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		l.late++
		return
	}
	l.events = append(l.events, e)
	if e.Online && e.Err == nil {
		l.accepted = time.Now()
	}
}

// last returns the last event, if there is one.
func (l *eventLog) last() (server.RegistrationEvent, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) == 0 {
		return server.RegistrationEvent{}, false
	}
	return l.events[len(l.events)-1], true
}

// sinceRegistration returns how long ago the last accepted registration was
// reported.
func (l *eventLog) sinceRegistration() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Since(l.accepted)
}

// markClosed is called when Close of the server has returned: no event may
// follow.
func (l *eventLog) markClosed() {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
}

func (l *eventLog) snapshot() []server.RegistrationEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// registrations returns the number of accepted registrations (renewals
// included).
func (l *eventLog) registrations() int {
	n := 0
	for _, e := range l.snapshot() {
		if e.Online && e.Err == nil {
			n++
		}
	}
	return n
}

// expectation is what the events of one registration loop must look like.
type expectation struct {
	name string
	url  string // the discovery server URL of the registration
	// policy and mode are the security every accepted request must have
	// used; an empty policy does not check.
	policy string
	mode   ua.MessageSecurityMode
	// secured accepts Sign and SignAndEncrypt instead of mode: which of the
	// two a server picks depends on the endpoints it is told about, over a
	// channel without security that the faults may corrupt.
	secured bool
	// neverAccepted says that the discovery server must not have accepted
	// anything.
	neverAccepted bool
}

// check validates the events of a registration loop whose server is closed:
//
//   - every event names the discovery server and one of the two services
//   - an unregistration is reported at most once, and it is the last event
//   - a server that was registered reports its unregistration, whether the
//     discovery server answered or not
//   - an accepted RegisterServer2 has one result for the one discovery
//     configuration that was sent
//   - nothing is reported after Close has returned
func (l *eventLog) check(sink *chaoskit.ErrSink, want expectation) {
	l.mu.Lock()
	events, late := slices.Clone(l.events), l.late
	l.mu.Unlock()

	if late > 0 {
		sink.Addf("%s: %d registration event(s) reported after Close returned", want.name, late)
	}
	accepted, offline := 0, 0
	for i, e := range events {
		if e.DiscoveryServerURL != want.url {
			sink.Addf("%s: event %d names discovery server %q, want %q", want.name, i, e.DiscoveryServerURL, want.url)
		}
		if e.Service != "RegisterServer2" && e.Service != "RegisterServer" {
			sink.Addf("%s: event %d has service %q", want.name, i, e.Service)
		}
		if !e.Online {
			offline++
			if i != len(events)-1 {
				sink.Addf("%s: the unregistration is event %d of %d, not the last", want.name, i, len(events))
			}
			continue
		}
		if e.Err != nil {
			continue
		}
		accepted++
		if want.neverAccepted {
			sink.Addf("%s: event %d: the discovery server accepted the registration", want.name, i)
		}
		modeOK := e.SecurityMode == want.mode
		if want.secured {
			modeOK = e.SecurityMode == ua.MessageSecurityModeSign || e.SecurityMode == ua.MessageSecurityModeSignAndEncrypt
		}
		if want.policy != "" && (e.SecurityPolicyURI != want.policy || !modeOK) {
			sink.Addf("%s: event %d: registered over %s/%v, want %s/%v", want.name, i,
				e.SecurityPolicyURI, e.SecurityMode, want.policy, want.mode)
		}
		if e.Service == "RegisterServer2" && len(e.ConfigurationResults) != 1 {
			sink.Addf("%s: event %d: %d configuration results, want 1", want.name, i, len(e.ConfigurationResults))
		}
	}
	if offline > 1 {
		sink.Addf("%s: %d unregistrations reported", want.name, offline)
	}
	if accepted > 0 && offline != 1 {
		sink.Addf("%s: registered %d times but %d unregistrations reported on Close", want.name, accepted, offline)
	}
}

// ---------------------------------------------------------------------------
// the registered servers table
// ---------------------------------------------------------------------------

// table maps the ServerUri of a registered server to its discovery URLs.
type table map[string][]string

func (tb table) String() string {
	uris := make([]string, 0, len(tb))
	for uri := range tb {
		uris = append(uris, uri)
	}
	sort.Strings(uris)
	var b strings.Builder
	for _, uri := range uris {
		fmt.Fprintf(&b, "\n    %s %v", uri, tb[uri])
	}
	if b.Len() == 0 {
		return " (empty)"
	}
	return b.String()
}

func (tb table) equal(other table) bool {
	if len(tb) != len(other) {
		return false
	}
	for uri, urls := range tb {
		o, ok := other[uri]
		if !ok || !slices.Equal(urls, o) {
			return false
		}
	}
	return true
}

// registered returns the table of a discovery server. A ServerUri that is
// listed twice is a violation.
func registered(sink *chaoskit.ErrSink, lds *server.Server) table {
	out := table{}
	for _, rs := range lds.RegisteredServers() {
		if _, dup := out[rs.ServerURI]; dup {
			sink.Addf("server %s is registered twice", rs.ServerURI)
		}
		if !rs.IsOnline {
			sink.Addf("server %s is in the table with IsOnline false", rs.ServerURI)
		}
		out[rs.ServerURI] = rs.DiscoveryURLs
	}
	return out
}

// found turns the result of FindServers into a table, without the discovery
// server itself, which must come first.
func found(sink *chaoskit.ErrSink, ldsURI string, servers []*ua.ApplicationDescription) table {
	out := table{}
	for i, app := range servers {
		if app == nil {
			sink.Addf("FindServers: nil application description")
			continue
		}
		if app.ApplicationURI == ldsURI {
			if i != 0 {
				sink.Addf("FindServers: the discovery server itself is entry %d, not the first", i)
			}
			continue
		}
		if _, dup := out[app.ApplicationURI]; dup {
			sink.Addf("FindServers: server %s is listed twice", app.ApplicationURI)
		}
		out[app.ApplicationURI] = app.DiscoveryURLs
	}
	return out
}

// portOf returns the port of an opc.tcp URL, or "" if it has none.
func portOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Port()
}
