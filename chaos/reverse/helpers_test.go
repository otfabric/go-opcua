// SPDX-License-Identifier: MIT

package reverse

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// defaultDuration is the length of the fault-injection phase of each
// randomized scenario when CHAOS_DURATION is not set.
const defaultDuration = 2 * time.Second

// promptLimit bounds what must happen "at once": an operation that only has
// to notice that something was closed. It is far above what that takes, also
// on a loaded machine under the race detector, and far below the time-outs
// (dial, ReverseHello, request) such an operation must not have to sit out.
const promptLimit = 8 * time.Second

// ---------------------------------------------------------------------------
// security profiles
// ---------------------------------------------------------------------------

// profile is the security configuration of a server and of the clients that
// talk to it: a policy (with SignAndEncrypt) or None, and the certificates.
type profile struct {
	name      string
	policyURI string // empty for None
	appURI    string // ApplicationUri of the server

	serverOpts []server.Option
	// clientOpts are the certificate, key and trust options of a client.
	clientOpts []opcua.Option
}

func (p profile) secured() bool { return p.policyURI != "" }

// Application URIs of the certificates of the suite.
const (
	serverAppURI = "urn:otfabric:chaos:reverse:server"
	clientAppURI = "urn:otfabric:chaos:reverse:client"
)

// certs are the application instance certificates of the suite. They are
// made with the tools of the shared test PKI, but only the few the suite
// needs: generating RSA keys under the race detector is what takes time.
type certs struct {
	rsaServer, rsaClient       []byte
	rsaServerKey, rsaClientKey *rsa.PrivateKey
	rsaServerX509              *x509.Certificate
	eccServer, eccClient       *testpki.Identity
}

var (
	certsOnce sync.Once
	certsVal  *certs
	certsErr  error
)

func pki(t testing.TB) *certs {
	t.Helper()
	certsOnce.Do(func() {
		c := &certs{}
		err := func() (err error) {
			if c.rsaServer, c.rsaServerKey, err = testpki.SelfSigned("chaos reverse server", serverAppURI); err != nil {
				return err
			}
			if c.rsaClient, c.rsaClientKey, err = testpki.SelfSigned("chaos reverse client", clientAppURI); err != nil {
				return err
			}
			if c.rsaServerX509, err = x509.ParseCertificate(c.rsaServer); err != nil {
				return err
			}
			if c.eccServer, err = testpki.NewIdentity(testpki.CurveP256, "chaos reverse server", serverAppURI, nil, nil); err != nil {
				return err
			}
			c.eccClient, err = testpki.NewIdentity(testpki.CurveP256, "chaos reverse client", clientAppURI, nil, nil)
			return err
		}()
		certsVal, certsErr = c, err
	})
	if certsErr != nil {
		t.Fatalf("chaos: test certificates: %v", certsErr)
	}
	return certsVal
}

// noneProfile is a server without security that announces appURI.
func noneProfile(appURI string) profile {
	return profile{
		name:       "None",
		appURI:     appURI,
		serverOpts: []server.Option{server.ApplicationURI(appURI)},
	}
}

// rsaProfile is Basic256Sha256 with RSA certificates. The ApplicationUri of
// the server is the one of its certificate.
func rsaProfile(t testing.TB) profile {
	t.Helper()
	p := pki(t)
	return profile{
		name:      "Basic256Sha256",
		policyURI: ua.SecurityPolicyURIBasic256Sha256,
		appURI:    serverAppURI,
		serverOpts: []server.Option{
			server.Certificate(p.rsaServer),
			server.PrivateKey(p.rsaServerKey),
			server.EnableSecurity(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		},
		clientOpts: []opcua.Option{
			opcua.Certificate(p.rsaClient),
			opcua.PrivateKey(p.rsaClientKey),
			opcua.TrustedCertificates(p.rsaServerX509),
		},
	}
}

// aeadProfile is ECC_nistP256_AesGcm, a policy with authenticated encryption,
// with ECDSA P-256 certificates. An empty appURI selects the server
// certificate all tests share; otherwise the server gets a certificate of
// its own for that ApplicationUri.
func aeadProfile(t testing.TB, appURI string) profile {
	t.Helper()
	p := pki(t)
	srv := p.eccServer
	if appURI == "" {
		appURI = serverAppURI
	} else {
		var err error
		if srv, err = testpki.NewIdentity(testpki.CurveP256, "chaos reverse server", appURI, nil, nil); err != nil {
			t.Fatalf("chaos: server certificate: %v", err)
		}
	}
	cli := p.eccClient
	return profile{
		name:      "ECC_nistP256_AesGcm",
		policyURI: ua.SecurityPolicyURIECCNistP256AesGcm,
		appURI:    appURI,
		serverOpts: []server.Option{
			server.ApplicationIdentity(srv.Cert, srv.Key),
			server.EnableSecurity(ua.SecurityPolicyURIECCNistP256AesGcm, ua.MessageSecurityModeSignAndEncrypt),
		},
		clientOpts: []opcua.Option{
			opcua.Certificate(cli.Cert),
			opcua.PrivateKeySigner(cli.Key),
			opcua.TrustedCertificates(srv.X509),
		},
	}
}

// ---------------------------------------------------------------------------
// node: a server that reverse-connects
// ---------------------------------------------------------------------------

const chaosNamespace = "http://otfabric.com/chaos/reverse"

// fastRetry makes a target retry failed attempts after 20ms, backing off to
// 250ms.
func fastRetry() server.ReverseConnectOption {
	return server.ReverseConnectRetryInterval(20*time.Millisecond, 250*time.Millisecond)
}

// node is a server that opens reverse connections to clientURL. The server
// can be stopped and replaced by a fresh instance: a chaos proxy in front of
// it keeps the endpoint URL (which the server announces in its ReverseHello
// messages) the same for every instance. Nothing but the "clean" clients of
// the tests connects through that proxy.
type node struct {
	t    *testing.T
	name string
	prof profile
	fwd  *testutil.ChaosProxy

	// clientURL is where the server connects to; empty for a server without
	// a configured target.
	clientURL string

	// marker is the value of the Marker node: it tells the servers apart.
	marker string

	// base is the value the counter starts above. Giving every server a
	// range of its own makes a value that comes from another server stand
	// out.
	base int64

	// anyEndpoint makes the clients of this server be created without an
	// endpoint URL: they accept whatever EndpointUrl the server announces,
	// so that nothing but the ServerUri selects their connection.
	anyEndpoint bool

	// ep is the secured endpoint of the server (nil for None).
	ep *ua.EndpointDescription

	mu  sync.Mutex
	srv *server.Server
	nsp *server.NodeNameSpace
	ns  uint16

	// counter is the last value written to the Counter node. Values are
	// only ever written in increasing order, also across restarts.
	counter atomic.Int64

	// corrupting is set while the transport to the clients flips bits.
	// Whoever receives the damaged chunk rejects it for the first thing
	// that is wrong with it (the signature, the channel id, the message
	// type, the size, ...) and a request may fail with just that, so the
	// kind of an error says nothing then. The values that are delivered are
	// checked all the same.
	corrupting atomic.Bool
}

// newNode prepares a server with the given profile; up starts it. index
// selects the range of the counter.
func newNode(t *testing.T, name string, index int, prof profile, seed int64) *node {
	t.Helper()
	n := &node{
		t:      t,
		name:   name,
		prof:   prof,
		marker: "marker-of-" + name,
		base:   int64(index+1) * 1_000_000_000,
	}
	n.counter.Store(n.base)
	n.fwd = testutil.NewChaosProxy(t, "", seed)
	return n
}

// up starts the server, which opens reverse connections to clientURL unless
// that is empty. The server is closed when the test ends.
func (n *node) up(clientURL string) *node {
	n.t.Helper()
	t, name, prof := n.t, n.name, n.prof
	n.clientURL = clientURL
	n.start()
	t.Cleanup(n.stop)

	if prof.secured() {
		ctx, cancel := chaoskit.OpCtx()
		defer cancel()
		eps, err := opcua.GetEndpoints(ctx, n.url(), opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(30*time.Second))
		if err != nil {
			t.Fatalf("chaos: %s: get endpoints: %v", name, err)
		}
		for _, ep := range eps {
			if ep.SecurityPolicyURI == prof.policyURI && ep.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
				n.ep = ep
			}
		}
		if n.ep == nil {
			t.Fatalf("chaos: %s: no %s endpoint", name, prof.name)
		}
	}
	return n
}

// url is the endpoint URL of the server: the one clients are created with
// and the one the server announces.
func (n *node) url() string { return n.fwd.EndpointURL() }

func (n *node) server() *server.Server {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.srv
}

func (n *node) nodeID(name string) *ua.NodeID { return ua.NewStringNodeID(n.ns, name) }
func (n *node) counterID() *ua.NodeID         { return n.nodeID("Counter") }
func (n *node) markerID() *ua.NodeID          { return n.nodeID("Marker") }
func (n *node) scratchID() *ua.NodeID         { return n.nodeID("Scratch") }

// start creates and starts a new server instance.
func (n *node) start() {
	n.t.Helper()
	opts := []server.Option{
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.SetLogger(chaoskit.Logger()),
		server.EndPoint("localhost", n.fwd.Port()),
		server.ListenOn("localhost:0"),
	}
	opts = append(opts, n.prof.serverOpts...)
	if n.clientURL != "" {
		opts = append(opts, server.WithReverseConnect(n.clientURL, fastRetry()))
	}
	srv, err := server.New(opts...)
	if err != nil {
		n.t.Fatalf("chaos: %s: new server: %v", n.name, err)
	}

	// A restarted server continues at the last value written, so that the
	// values a subscriber sees never go backwards.
	nsp := populate(n.t, srv, n.counter.Load(), n.marker)

	if err := srv.Start(context.Background()); err != nil {
		n.t.Fatalf("chaos: %s: start server: %v", n.name, err)
	}
	n.mu.Lock()
	n.srv = srv
	n.nsp = nsp
	if n.ns == 0 {
		// The index is the same for every instance and is read by the
		// workers while a restart is under way: write it only once.
		n.ns = nsp.ID()
	}
	n.mu.Unlock()
	n.fwd.SetBackend(fmt.Sprintf("localhost:%d", srv.Port()))
}

// populate adds the chaos namespace with the nodes Counter, Marker and
// Scratch to srv.
func populate(t *testing.T, srv *server.Server, counter int64, marker string) *server.NodeNameSpace {
	t.Helper()
	root, err := srv.Namespace(0)
	if err != nil {
		t.Fatalf("chaos: namespace 0: %v", err)
	}
	nsp := server.NewNodeNameSpace(srv, chaosNamespace)
	obj := nsp.Objects()
	root.Objects().AddRef(obj, id.HasComponent, true)
	for name, v := range map[string]any{"Counter": counter, "Marker": marker, "Scratch": int32(0)} {
		obj.AddRef(nsp.AddNewVariableStringNode(name, v), id.HasComponent, true)
	}
	return nsp
}

// stop closes the current server instance, if any.
func (n *node) stop() {
	n.mu.Lock()
	srv := n.srv
	n.srv = nil
	n.nsp = nil
	n.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// bump writes the next value of the counter into the address space of the
// running server, as an application embedding the server would. It returns
// the value, or 0 when no server is running.
func (n *node) bump() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.nsp == nil {
		return 0
	}
	v := n.counter.Add(1)
	if sc := n.nsp.SetAttribute(n.counterID(), ua.AttributeIDValue, server.DataValueFromValue(v)); sc != ua.StatusOK {
		n.t.Errorf("%s: server-side write of the counter failed: %v", n.name, sc)
	}
	return v
}

// feed keeps the counter changing until the returned function is called.
func (n *node) feed() (stop func()) {
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
				n.bump()
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }); wg.Wait() }
}

// checkCounter reports why v cannot be a value of the Counter node, or "".
// It must be called after v was received.
func (n *node) checkCounter(v any) string {
	i, ok := v.(int64)
	if !ok {
		return fmt.Sprintf("%T value %v, want int64", v, v)
	}
	if hi := n.counter.Load(); i < n.base || i > hi {
		return fmt.Sprintf("value %d was never written: the writer produced %d..%d", i, n.base, hi)
	}
	return ""
}

// target returns the reverse connect target of the running server if it has
// exactly one.
func (n *node) target() *server.ReverseConnect {
	srv := n.server()
	if srv == nil {
		return nil
	}
	if rcs := srv.ReverseConnects(); len(rcs) == 1 {
		return rcs[0]
	}
	return nil
}

// describeTarget is the state of the target for failure messages.
func (n *node) describeTarget() string {
	rc := n.target()
	if rc == nil {
		return "no target"
	}
	return fmt.Sprintf("target %v, %d connection(s), last error: %v", rc.State(), rc.Connections(), rc.Err())
}

// resources returns the per-client resources held by the running server.
func (n *node) resources() testhook.ServerResources {
	srv := n.server()
	if srv == nil {
		return testhook.ServerResources{}
	}
	return testhook.ServerResourcesOf(srv)
}

// requireDrained waits until the running server holds no channels, sessions,
// subscriptions or monitored items.
func (n *node) requireDrained() {
	n.t.Helper()
	var last testhook.ServerResources
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		last = n.resources()
		return last == testhook.ServerResources{}
	}) {
		n.t.Errorf("%s: server did not release the client resources: %+v", n.name, last)
	}
}

// clientOptions returns the options of a client of this server, with the
// security of the profile. They do not select how the client connects.
func (n *node) clientOptions(rec *chaoskit.StateRecorder, extra ...opcua.Option) []opcua.Option {
	opts := []opcua.Option{
		opcua.DialTimeout(10 * time.Second),
		// Fault-free tests must never fail because the machine is slow, so
		// the default request timeout only guards against a hang.
		opcua.RequestTimeout(30 * time.Second),
		opcua.ReconnectInterval(50 * time.Millisecond),
		opcua.AutoReconnect(true),
	}
	if n.prof.secured() {
		opts = append(opts, opcua.SecurityFromEndpoint(n.ep, ua.UserTokenTypeAnonymous))
		opts = append(opts, n.prof.clientOpts...)
	} else {
		opts = append(opts, opcua.SecurityMode(ua.MessageSecurityModeNone))
	}
	if rec != nil {
		opts = append(opts, opcua.WithConnStateHandler(rec.Handle))
	}
	if l := chaoskit.Logger(); l != nil {
		opts = append(opts, opcua.WithLogger(l.With("side", "client", "server", n.name)))
	}
	return append(opts, extra...)
}

// reverseOption makes a client of this server take its connection from l.
func (n *node) reverseOption(l *uacp.ReverseListener) opcua.Option {
	return opcua.ReverseConnectListener(l, opcua.ReverseServerURI(n.prof.appURI))
}

// dial creates and connects a client. The client is closed when the test
// ends unless the test closed it earlier.
func (n *node) dial(rec *chaoskit.StateRecorder, extra ...opcua.Option) (*opcua.Client, error) {
	url := n.url()
	if n.anyEndpoint {
		url = ""
	}
	c, err := opcua.NewClient(url, n.clientOptions(rec, extra...)...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		chaoskit.CloseClient(c, rec)
		return nil, err
	}
	n.t.Cleanup(func() { chaoskit.CloseClient(c, rec) })
	return c, nil
}

func (n *node) connect(rec *chaoskit.StateRecorder, extra ...opcua.Option) *opcua.Client {
	n.t.Helper()
	c, err := n.dial(rec, extra...)
	if err != nil {
		n.t.Fatalf("chaos: %s: connect: %v (%s)", n.name, err, n.describeTarget())
	}
	return c
}

// requireCleanClient verifies that the server still serves a brand-new
// client correctly: connect, read, write and read back, subscribe and
// receive a data change, then shut down cleanly. The options select how the
// client connects: none connects the usual way.
func (n *node) requireCleanClient(what string, extra ...opcua.Option) {
	n.t.Helper()
	t := n.t

	var c *opcua.Client
	var err error
	if !chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		c, err = n.dial(nil, append([]opcua.Option{opcua.AutoReconnect(false)}, extra...)...)
		return err == nil
	}) {
		t.Errorf("%s: %s could not connect: %v", n.name, what, err)
		return
	}
	defer chaoskit.CloseClient(c, nil)
	ctx, cancel := chaoskit.OpCtx()
	defer cancel()

	if dv, err := c.ReadValue(ctx, n.markerID()); err != nil {
		t.Errorf("%s: %s: read marker: %v", n.name, what, err)
	} else if got := dv.Value.Value(); got != n.marker {
		t.Errorf("%s: %s: WRONG SERVER: marker is %v, want %q", n.name, what, got, n.marker)
	}
	want := rand.Int31()
	if sc, err := c.WriteNodeValue(ctx, n.scratchID(), want); err != nil || sc != ua.StatusOK {
		t.Errorf("%s: %s: write: status=%v err=%v", n.name, what, sc, err)
	}

	ch := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 20 * time.Millisecond}, ch)
	if err != nil {
		t.Errorf("%s: %s: subscribe: %v", n.name, what, err)
		return
	}
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
		opcua.NewMonitoredItemCreateRequestWithDefaults(n.scratchID(), ua.AttributeIDValue, 1))
	if err != nil || res.Results[0].StatusCode != ua.StatusOK {
		t.Errorf("%s: %s: monitor: res=%+v err=%v", n.name, what, res, err)
	}
	deadline := time.After(chaoskit.SettleLimit)
wait:
	for {
		select {
		case nd := <-ch:
			if nd.Error != nil {
				continue
			}
			if dcn, ok := nd.Value.(*ua.DataChangeNotification); ok {
				for _, mi := range dcn.MonitoredItems {
					if mi.Value != nil && mi.Value.Value != nil && mi.Value.Value.Value() == want {
						break wait
					}
				}
			}
		case <-deadline:
			t.Errorf("%s: %s: no data change for the value written", n.name, what)
			break wait
		}
	}
	if err := sub.Cancel(ctx); err != nil {
		t.Errorf("%s: %s: cancel subscription: %v", n.name, what, err)
	}
}

// ---------------------------------------------------------------------------
// stream: a checked subscription on the counter
// ---------------------------------------------------------------------------

// stream is a subscription on the Counter node of a server together with a
// consumer that checks every value it receives: it must be one the writer
// produced, and the values must never go backwards. Equal values are
// tolerated: a re-created monitored item reports the current value again.
type stream struct {
	name string
	n    *node
	sub  *opcua.Subscription
	ch   chan *opcua.PublishNotificationData

	mu       sync.Mutex
	last     int64
	problems []string
	trail    []string // most recent notifications, for diagnostics

	received atomic.Int64
	errs     chaoskit.ErrorTally

	stop chan struct{}
	done chan struct{}
}

// streamParams keeps a subscription alive for 6s without a Publish request.
// A subscription that a fault orphans on the server is gone well inside
// SettleLimit; one that expires because the faults kept its client away for
// longer is recreated by the client.
func streamParams() *opcua.SubscriptionParameters {
	return &opcua.SubscriptionParameters{
		Interval:          20 * time.Millisecond,
		MaxKeepAliveCount: 5,
		LifetimeCount:     300,
	}
}

func openStream(ctx context.Context, n *node, c *opcua.Client, name string) (*stream, error) {
	s := &stream{
		name: name,
		n:    n,
		ch:   make(chan *opcua.PublishNotificationData, 8),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go s.consume()

	sub, err := c.Subscribe(ctx, streamParams(), s.ch)
	if err != nil {
		s.close()
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	s.sub = sub

	req := opcua.NewMonitoredItemCreateRequestWithDefaults(n.counterID(), ua.AttributeIDValue, 1)
	req.RequestedParameters.QueueSize = 100
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, req)
	if err == nil && res.Results[0].StatusCode != ua.StatusOK {
		err = res.Results[0].StatusCode
	}
	if err != nil {
		_ = sub.Cancel(ctx)
		s.close()
		return nil, fmt.Errorf("monitor: %w", err)
	}
	return s, nil
}

func (s *stream) consume() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		case n := <-s.ch:
			s.handle(n)
		}
	}
}

func (s *stream) handle(n *opcua.PublishNotificationData) {
	if n.Error != nil {
		s.errs.Add(n.Error)
		if !chaoskit.IsConnectionError(n.Error) && !s.n.corrupting.Load() {
			s.problem("unexpected error notification: %v", n.Error)
		}
		return
	}
	dcn, ok := n.Value.(*ua.DataChangeNotification)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, mi := range dcn.MonitoredItems {
		if mi == nil || mi.Value == nil || mi.Value.Value == nil {
			s.problems = append(s.problems, fmt.Sprintf("notification without value: %+v", mi))
			continue
		}
		raw := mi.Value.Value.Value()
		if why := s.n.checkCounter(raw); why != "" {
			if len(s.problems) < 20 {
				s.problems = append(s.problems, "WRONG VALUE: "+why)
			}
			continue
		}
		v := raw.(int64)
		s.trail = append(s.trail, fmt.Sprintf("%s sub=%d v=%d", time.Now().Format("05.000"), n.SubscriptionID, v))
		if len(s.trail) > 40 {
			s.trail = s.trail[len(s.trail)-40:]
		}
		if v < s.last && len(s.problems) < 20 {
			s.problems = append(s.problems, fmt.Sprintf("REORDERED: %d delivered after %d; most recent notifications (time, subscription id, value):\n      %s",
				v, s.last, strings.Join(s.trail, "\n      ")))
		}
		s.last = v
		s.received.Add(1)
	}
}

func (s *stream) problem(format string, args ...any) {
	s.mu.Lock()
	if len(s.problems) < 20 {
		s.problems = append(s.problems, fmt.Sprintf(format, args...))
	}
	s.mu.Unlock()
}

// lastValue returns the last value delivered.
func (s *stream) lastValue() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// close stops the consumer. It must be called after the subscription was
// cancelled or the client was closed.
func (s *stream) close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
}

// report fails the test for every problem the consumer observed.
func (s *stream) report(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.problems {
		t.Errorf("stream %s: %s", s.name, p)
	}
}

// ---------------------------------------------------------------------------
// reader: a checked read workload
// ---------------------------------------------------------------------------

// reader reads the Marker and the Counter node of a server in a loop. A read
// either fails with a connection-class error or returns the right value: the
// marker of the server, and a counter value the writer produced that is not
// below the one read before.
type reader struct {
	name string
	n    *node
	c    *opcua.Client
	sink *chaoskit.ErrSink

	tally chaoskit.ErrorTally
	stop  chan struct{}
	done  chan struct{}
}

// expected reports whether err is an error a read may fail with.
func (r *reader) expected(err error) bool {
	return chaoskit.IsConnectionError(err) || r.n.corrupting.Load()
}

// startReader starts the workload. timeout bounds a single read.
func startReader(n *node, c *opcua.Client, name string, sink *chaoskit.ErrSink, timeout time.Duration) *reader {
	r := &reader{name: name, n: n, c: c, sink: sink, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(r.done)
		var last int64
		for i := 0; ; i++ {
			select {
			case <-r.stop:
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			if i%2 == 0 {
				r.tally.Add(r.readMarker(ctx))
			} else {
				v, err := r.readCounter(ctx)
				r.tally.Add(err)
				if err == nil {
					if v < last {
						sink.Addf("%s: WRONG VALUE: read counter %d after %d", name, v, last)
					}
					last = v
				}
			}
			cancel()
			time.Sleep(3 * time.Millisecond)
		}
	}()
	return r
}

// readMarker reads the Marker node and verifies that it is the one of the
// client's own server.
func (r *reader) readMarker(ctx context.Context) error {
	dv, err := r.c.ReadValue(ctx, r.n.markerID())
	if err != nil {
		if !r.expected(err) {
			r.sink.Addf("%s: read marker: unexpected error: %v", r.name, err)
		}
		return err
	}
	var got any
	if dv.Value != nil {
		got = dv.Value.Value()
	}
	if got != r.n.marker {
		r.sink.Addf("%s: WRONG SERVER: marker is %v (status %v), want %q", r.name, got, dv.Status, r.n.marker)
	}
	return nil
}

// readCounter reads the Counter node and verifies the value.
func (r *reader) readCounter(ctx context.Context) (int64, error) {
	dv, err := r.c.ReadValue(ctx, r.n.counterID())
	if err != nil {
		if !r.expected(err) {
			r.sink.Addf("%s: read counter: unexpected error: %v", r.name, err)
		}
		return 0, err
	}
	if dv.Value == nil {
		r.sink.Addf("%s: WRONG VALUE: read counter: no value (status %v)", r.name, dv.Status)
		return 0, nil
	}
	if why := r.n.checkCounter(dv.Value.Value()); why != "" {
		r.sink.Addf("%s: WRONG VALUE: read counter: %s", r.name, why)
		return 0, nil
	}
	return dv.Value.Value().(int64), nil
}

// close stops the workload and waits for the read in flight.
func (r *reader) close() {
	close(r.stop)
	<-r.done
}

// ---------------------------------------------------------------------------
// generic helpers
// ---------------------------------------------------------------------------

// listen opens a reverse listener that is closed when the test ends unless
// the test closed it earlier.
func listen(t *testing.T, cfg *uacp.ReverseListenerConfig) *uacp.ReverseListener {
	t.Helper()
	if cfg == nil {
		cfg = &uacp.ReverseListenerConfig{}
	}
	if cfg.Logger == nil {
		cfg.Logger = chaoskit.Logger()
	}
	l, err := uacp.ListenReverse(context.Background(), "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("chaos: reverse listener: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// listenerURL is the URL servers connect to in order to reach l directly.
func listenerURL(l *uacp.ReverseListener) string { return "opc.tcp://" + l.Addr().String() }

// logf logs a step of a fault schedule with a timestamp.
func logf(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Logf("%s %s", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

// sleepRand sleeps a random duration in [lo, hi).
func sleepRand(rng *rand.Rand, lo, hi time.Duration) {
	time.Sleep(lo + time.Duration(rng.Int63n(int64(hi-lo))))
}
