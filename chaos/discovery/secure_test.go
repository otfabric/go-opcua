// SPDX-License-Identifier: MIT

package discovery

import (
	stderrors "errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestSecuredRegistrationECC registers servers with ECC certificates with a
// Local Discovery Server that only accepts secured registrations: two over
// ECC_nistP256 (one of them pinned to it), two with Ed25519 certificates over
// ECC_curve25519 (ChaCha20-Poly1305). Their connections go through the fault
// proxy, which resets, refuses, blackholes, stalls, delays, fragments,
// truncates and corrupts them.
//
// At the same time hostile applications, which hold certificates of their
// own and so can open a secured channel, try to register servers they are
// not: the URI of a registered server with other discovery URLs, a made-up
// URI, the unregistration of a registered server. Another one tries without
// security.
//
// Invariants:
//
//   - every hostile request is refused (BadServerUriInvalid, or
//     BadSecurityModeInsufficient without security), whatever else is going
//     on, and none of it ever shows in the table or reaches the registration
//     callback
//   - a server that is registered stays registered with its own discovery
//     URLs until it closes: nobody else can replace or remove it
//   - every accepted registration used a secured channel of the policy that
//     fits the certificate of the server
//   - after the faults every server registers again, with SignAndEncrypt,
//     and the table is exactly the live servers; a server that closes is
//     gone at once
//   - Start and Close never block; the registration events are consistent;
//     no goroutine is left behind (TestMain)
func TestSecuredRegistrationECC(t *testing.T) {
	t.Parallel()
	seed := chaoskit.Seed(t)
	rng := rand.New(rand.NewSource(seed))
	dur := chaoskit.Duration(t, 2500*time.Millisecond)
	wd := chaoskit.NewWatchdog(t)
	sink := &chaoskit.ErrSink{}
	defer sink.Report(t)

	const reqTimeout = time.Second
	pki, err := testpki.Get()
	if err != nil {
		t.Fatalf("test PKI: %v", err)
	}
	ecc := pki.ECC

	// --- the discovery server -------------------------------------------------
	var (
		legitMu sync.Mutex
		legit   = map[string]bool{}
	)
	isLegit := func(uri string) bool {
		legitMu.Lock()
		defer legitMu.Unlock()
		return legit[uri]
	}
	lds := mustStart(t, wd, serverOpts(
		server.ApplicationIdentity(ecc.Server[testpki.CurveP256].Cert, ecc.Server[testpki.CurveP256].Key),
		server.ApplicationIdentity(ecc.Server[testpki.CurveEd25519].Cert, ecc.Server[testpki.CurveEd25519].Key),
		server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSign),
		server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
		server.EnableSecurity(ua.SecurityPolicyURIECCCurve25519, ua.MessageSecurityModeSignAndEncrypt),
		server.ServerName("LDS"),
		// The defaults: secured registrations only, and only of the server
		// the certificate of the channel belongs to.
		server.WithLocalDiscoveryServer(server.LDSRegistrationCallback(func(rs *ua.RegisteredServer) {
			if !isLegit(rs.ServerURI) {
				sink.Addf("the discovery server accepted a request for %q", rs.ServerURI)
			}
		})),
	)...)
	ldsURL := serverURL(lds)
	proxy := testutil.NewChaosProxy(t, fmt.Sprintf("localhost:%d", lds.Port()), seed)
	regURL := proxy.EndpointURL()

	// --- the registrants ------------------------------------------------------
	type secured struct {
		*registrant
		policy  string
		closing atomic.Bool
	}
	specs := []struct {
		curve  string
		policy string
		pinned bool
	}{
		{testpki.CurveP256, ua.SecurityPolicyURIECCNistP256, false},
		{testpki.CurveP256, ua.SecurityPolicyURIECCNistP256, true},
		{testpki.CurveEd25519, ua.SecurityPolicyURIECCCurve25519, false},
		{testpki.CurveEd25519, ua.SecurityPolicyURIECCCurve25519, true},
	}
	var regs []*secured
	for i, spec := range specs {
		r := &secured{policy: spec.policy, registrant: &registrant{
			uri:  fmt.Sprintf("urn:chaos:discovery:secured:%d", i),
			name: fmt.Sprintf("Secured%d", i),
			log:  &eventLog{},
		}}
		id, err := testpki.NewIdentity(spec.curve, r.name, r.uri, nil, nil)
		if err != nil {
			t.Fatalf("certificate of %s: %v", r.name, err)
		}
		legitMu.Lock()
		legit[r.uri] = true
		legitMu.Unlock()
		opts := []server.RegistrationOption{
			server.RegisterInterval(60 * time.Millisecond),
			server.RegisterBackoff(10*time.Millisecond, 150*time.Millisecond),
			server.RegisterRequestTimeout(reqTimeout),
			server.RegisterEventHandler(r.log.handle),
		}
		if spec.pinned {
			opts = append(opts, server.RegisterSecurity(spec.policy, ua.MessageSecurityModeSignAndEncrypt))
		}
		// The application URI of the server is the one of its certificate.
		r.srv = mustStart(t, wd, serverOpts(
			server.ApplicationIdentity(id.Cert, id.Key),
			server.ServerName(r.name),
			server.WithDiscoveryRegistration(regURL, opts...),
		)...)
		regs = append(regs, r)
	}
	truth := func() table {
		want := table{}
		for _, r := range regs {
			if !r.closing.Load() {
				want[r.uri] = r.srv.URLs()
			}
		}
		return want
	}
	converge := func(phase string) {
		t.Helper()
		want := truth()
		var got table
		if !chaoskit.Eventually(settleLimit, func() bool {
			got = registered(sink, lds)
			return got.equal(want)
		}) {
			t.Fatalf("%s: the table of the discovery server did not converge:\n  have:%v\n  want:%v", phase, got, want)
		}
	}
	converge("before the faults")

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

	// --- the table, all the time -------------------------------------------------
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stopped() {
			// Who is registered for sure, before the table is read.
			must := map[string]bool{}
			for _, r := range regs {
				if r.log.registrations() > 0 && !r.closing.Load() {
					must[r.uri] = true
				}
			}
			got := registered(sink, lds)
			for uri, urls := range got {
				if !isLegit(uri) {
					sink.Addf("the table has the server %q %v, which nobody may register", uri, urls)
				}
				if strings.Contains(fmt.Sprint(urls), "evil") {
					sink.Addf("the registration of %s was replaced: %v", uri, urls)
				}
			}
			for _, r := range regs {
				// closing is read again: Close may have begun meanwhile.
				if must[r.uri] && got[r.uri] == nil && !r.closing.Load() {
					sink.Addf("%s is registered and not closed, but not in the table", r.name)
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// --- hostile applications ----------------------------------------------------
	var refused atomic.Int64
	hostile := func(g int, curve, policy string) {
		defer wg.Done()
		who := fmt.Sprintf("hostile %d", g)
		rng := rand.New(rand.NewSource(seed + 1000 + int64(g)))
		wantErr := ua.StatusBadServerURIInvalid
		var opts []opcua.Option
		if curve == "" {
			// No certificate, no security.
			wantErr = ua.StatusBadSecurityModeInsufficient
		} else {
			id, err := testpki.NewIdentity(curve, who, fmt.Sprintf("urn:chaos:discovery:hostile:%d", g), nil, nil)
			if err != nil {
				sink.Addf("%s: certificate: %v", who, err)
				return
			}
			ctx, cancel := chaoskit.OpCtx()
			eps, err := opcua.GetEndpoints(ctx, ldsURL)
			cancel()
			if err != nil {
				sink.Addf("%s: GetEndpoints: %v", who, err)
				return
			}
			var ep *ua.EndpointDescription
			for _, e := range eps {
				if e.SecurityPolicyURI == policy && e.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
					ep = e
				}
			}
			if ep == nil {
				sink.Addf("%s: the discovery server has no %s endpoint", who, policy)
				return
			}
			opts = []opcua.Option{
				opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
				opcua.Certificate(id.Cert),
				opcua.PrivateKeySigner(id.Key),
				opcua.TrustedCertificates(ecc.Server[testpki.CurveP256].X509, ecc.Server[testpki.CurveEd25519].X509),
			}
		}
		c, err := dial(ldsURL, opts...)
		if err != nil {
			sink.Addf("%s: dial: %v", who, err)
			return
		}
		defer chaoskit.CloseClient(c, nil)
		for i := 0; !stopped(); i++ {
			victim := regs[rng.Intn(len(regs))]
			rs := &ua.RegisteredServer{
				ServerURI:     victim.uri,
				ProductURI:    "urn:chaos:discovery:hostile",
				ServerNames:   []*ua.LocalizedText{ua.NewLocalizedText("Evil")},
				ServerType:    ua.ApplicationTypeServer,
				DiscoveryURLs: []string{"opc.tcp://evil:6666"},
				IsOnline:      true,
			}
			switch rng.Intn(4) {
			case 0: // take over a registered server
			case 1: // remove a registered server
				rs.IsOnline = false
			case 2: // a server that does not exist
				rs.ServerURI = fmt.Sprintf("urn:chaos:discovery:ghost:%d:%d", g, i)
			case 3: // the URI of the discovery server itself
				rs.ServerURI = testpki.ServerAppURI
			}
			ctx, cancel := chaoskit.OpCtx()
			if rng.Intn(2) == 0 {
				_, err = c.RegisterServer(ctx, rs)
			} else {
				_, err = c.RegisterServer2(ctx, rs, &ua.MdnsDiscoveryConfiguration{MdnsServerName: "Evil", ServerCapabilities: []string{"DA"}})
			}
			cancel()
			if !stderrors.Is(err, wantErr) {
				sink.Addf("%s: request for %q (online %v) got %v, want %v", who, rs.ServerURI, rs.IsOnline, err, wantErr)
				return
			}
			refused.Add(1)
			time.Sleep(time.Duration(rng.Intn(3)) * time.Millisecond)
		}
	}
	wg.Add(3)
	go hostile(0, testpki.CurveP256, ua.SecurityPolicyURIECCNistP256)
	go hostile(1, testpki.CurveEd25519, ua.SecurityPolicyURIECCCurve25519)
	go hostile(2, "", "")

	// --- fault phase --------------------------------------------------------------
	faults := map[string]int{}
	fault := func(name string) { faults[name]++ }
	dirOf := func() testutil.Direction { return testutil.Direction(rng.Intn(2)) }
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) && sink.Len() == 0 {
		switch rng.Intn(11) {
		case 0:
			fault("reset")
			proxy.DropAll()
		case 1:
			fault("refuse")
			proxy.SetRefuse(true)
			proxy.DropAll()
		case 2:
			fault("blackhole")
			proxy.SetBlackhole(dirOf(), true)
		case 3:
			fault("stall")
			proxy.SetStall(dirOf(), true)
		case 4:
			fault("latency")
			proxy.SetLatency(time.Duration(rng.Intn(20))*time.Millisecond, time.Duration(1+rng.Intn(30))*time.Millisecond)
		case 5:
			fault("fragment")
			proxy.SetFragment(1 + rng.Intn(9))
		case 6:
			fault("truncate")
			proxy.TruncateNext(dirOf(), 1+rng.Intn(600))
		case 7:
			fault("corrupt")
			proxy.SetCorruption(dirOf(), 0.05+rng.Float64()*0.5)
		case 8:
			fault("corrupt one")
			proxy.CorruptNext(dirOf(), 1+rng.Intn(3))
		case 9:
			fault("half-close")
			proxy.HalfClose(dirOf())
		case 10:
			fault("none")
		}
		time.Sleep(time.Duration(40+rng.Intn(160)) * time.Millisecond)
		if rng.Intn(3) != 0 {
			proxy.Heal()
		}
	}
	proxy.Heal()
	// A connection that was corrupted may still be open.
	proxy.DropAll()
	healed := time.Now()

	// --- after the faults -----------------------------------------------------------
	// Every server registers again, over an encrypted channel.
	base := make([]int, len(regs))
	for i, r := range regs {
		base[i] = len(r.log.snapshot())
	}
	for i, r := range regs {
		var fresh []server.RegistrationEvent
		if !chaoskit.Eventually(settleLimit, func() bool {
			fresh = fresh[:0]
			for _, e := range r.log.snapshot()[base[i]:] {
				if e.Online && e.Err == nil {
					fresh = append(fresh, e)
				}
			}
			// The first attempts may have been on their way through the
			// faults; the later ones were not.
			return len(fresh) >= 4
		}) {
			t.Fatalf("%s does not register any more after the faults: %+v", r.name, r.log.snapshot()[base[i]:])
		}
		if e := fresh[len(fresh)-1]; e.SecurityPolicyURI != r.policy || e.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
			t.Errorf("%s registers over %s/%v after the faults, want %s/SignAndEncrypt", r.name, e.SecurityPolicyURI, e.SecurityMode, r.policy)
		}
	}
	converge("after the faults")
	t.Logf("faults: %v; %d hostile requests refused; recovered %v after the faults", faults, refused.Load(), time.Since(healed).Round(time.Millisecond))

	// Two servers leave while the hostile applications carry on: they are
	// gone at once, the others stay.
	// leave closes a server. The discovery server can be reached, so the
	// server unregisters; only a machine that is too slow for the request
	// timeout keeps it from that, and then the registration stays.
	stay := table{}
	leave := func(r *secured) {
		r.closing.Store(true)
		closeServer(sink, wd, r.name, r.srv, 2*reqTimeout+closeSlack)
		r.log.markClosed()
		last, _ := r.log.last()
		switch {
		case last.Online:
			t.Errorf("%s: no unregistration was reported on Close", r.name)
		case last.Err == nil:
		case chaoskit.IsConnectionError(last.Err):
			t.Logf("%s: the unregistration timed out: %v", r.name, last.Err)
			stay[r.uri] = r.srv.URLs()
		default:
			t.Errorf("%s: unregistration: %v", r.name, last.Err)
		}
	}
	gone := func(phase string) {
		t.Helper()
		want := truth()
		for uri, urls := range stay {
			want[uri] = urls
		}
		if got := registered(sink, lds); !got.equal(want) {
			t.Errorf("%s:\n  have:%v\n  want:%v", phase, got, want)
		}
	}
	for _, r := range regs[:2] {
		leave(r)
	}
	gone("after two servers closed")

	close(stop)
	if !wd.Wait("the hostile applications", &wg) {
		return
	}
	if refused.Load() == 0 {
		t.Errorf("no hostile request was made")
	}
	for _, r := range regs[2:] {
		leave(r)
	}
	gone("after all servers closed")
	for _, r := range regs {
		r.log.check(sink, expectation{name: r.name, url: regURL, policy: r.policy, secured: true})
	}
	closeServer(sink, wd, "the discovery server", lds, closeSlack)
}
