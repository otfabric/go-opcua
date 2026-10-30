// SPDX-License-Identifier: MIT

package secure

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/chaoskit"
	"github.com/otfabric/go-opcua/internal/testutil/testpki"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// defaultDuration is the length of the fault-injection phase of each
// randomized scenario when CHAOS_DURATION is not set.
const defaultDuration = 3 * time.Second

// envPolicy restricts the randomized scenarios to the security policies
// whose short name contains its value, e.g. CHAOS_POLICY=AesGcm.
const envPolicy = "CHAOS_POLICY"

func TestMain(m *testing.M) { chaoskit.Main(m) }

// ---------------------------------------------------------------------------
// security policies
// ---------------------------------------------------------------------------

// policy is a security policy under test with the key type of the
// application instance certificates that go with it.
type policy struct {
	name  string
	uri   string
	curve string // key of the ECC certificates; empty for RSA
	// slow is set for the Brainpool policies: their curve arithmetic runs on
	// math/big through crypto/elliptic's generic code, which is some 20 to 70
	// times slower than the NIST curves (more so under the race detector), so
	// an OpenSecureChannel takes up to a second on a busy machine.
	slow bool
}

// lifetime scales the SecurityToken lifetime d of a test to the cost of the
// policy's handshake: a renewal must fit in the quarter of the lifetime the
// server grants beyond it (uasc tokenGrace), and on the slow policies it
// takes far longer than on the others.
func (p policy) lifetime(d time.Duration) time.Duration {
	if p.slow {
		return 4 * d
	}
	return d
}

var (
	polRSA          = policy{"Basic256Sha256", ua.SecurityPolicyURIBasic256Sha256, "", false}
	polP256         = policy{"ECC_nistP256", ua.SecurityPolicyURIECCNistP256, testpki.CurveP256, false}
	polP384         = policy{"ECC_nistP384", ua.SecurityPolicyURIECCNistP384, testpki.CurveP384, false}
	polAesGcm       = policy{"ECC_nistP256_AesGcm", ua.SecurityPolicyURIECCNistP256AesGcm, testpki.CurveP256, false}
	polChaChaPoly   = policy{"ECC_nistP256_ChaChaPoly", ua.SecurityPolicyURIECCNistP256ChaChaPoly, testpki.CurveP256, false}
	polCurve25519   = policy{"ECC_curve25519", ua.SecurityPolicyURIECCCurve25519, testpki.CurveEd25519, false}
	polBrainpool256 = policy{"ECC_brainpoolP256r1", ua.SecurityPolicyURIECCBrainpoolP256r1, testpki.CurveBrainpoolP256r1, true}
	polBrainpool384 = policy{"ECC_brainpoolP384r1", ua.SecurityPolicyURIECCBrainpoolP384r1, testpki.CurveBrainpoolP384r1, true}
	polCurve448     = policy{"ECC_curve448", ua.SecurityPolicyURIECCCurve448, testpki.CurveEd448, false}

	// allPolicies is every secured policy the suite covers: one RSA policy,
	// the four ECC policies with CBC and HMAC (NIST and Brainpool curves) and
	// the four ECC policies with authenticated encryption.
	allPolicies = []policy{polRSA, polP256, polP384, polAesGcm, polChaChaPoly, polCurve25519, polBrainpool256, polBrainpool384, polCurve448}
)

// selectedPolicies returns allPolicies, or the ones CHAOS_POLICY selects.
func selectedPolicies(t *testing.T) []policy {
	t.Helper()
	want := os.Getenv(envPolicy)
	if want == "" {
		return allPolicies
	}
	var out []policy
	for _, p := range allPolicies {
		if strings.Contains(p.name, want) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s=%q selects no security policy", envPolicy, want)
	}
	return out
}

// eccCurves are the key types of the ECC application instance certificates,
// in the order the server is given them: it serves a policy with the first
// certificate that fits.
var eccCurves = []string{
	testpki.CurveP256, testpki.CurveP384, testpki.CurveEd25519,
	testpki.CurveBrainpoolP256r1, testpki.CurveBrainpoolP384r1, testpki.CurveEd448,
}

func pki(t testing.TB) *testpki.PKI {
	t.Helper()
	p, err := testpki.Get()
	if err != nil {
		t.Fatalf("chaos: test PKI: %v", err)
	}
	return p
}

const (
	userName     = "alice"
	userPassword = "wonderland"
)

func userValidator(user, pass string) error {
	if user == userName && pass == userPassword {
		return nil
	}
	return ua.StatusBadUserAccessDenied
}

// ---------------------------------------------------------------------------
// environment: server (+ optional chaos proxy)
// ---------------------------------------------------------------------------

const (
	numCounters = 4
	numScratch  = 8
	numBrowse   = 40
	blobSize    = 160 * 1024 // 3 chunks with the default 64k buffers
)

// env is a server that offers every policy under test, behind a chaos proxy.
// The server can be stopped and replaced by a fresh instance while the proxy
// keeps its client-facing port.
type env struct {
	t     *testing.T
	seed  int64
	proxy *testutil.ChaosProxy

	// serverOpts are additional options for every server instance.
	serverOpts []server.Option

	mu  sync.Mutex
	srv *server.Server
	nsp *server.NodeNameSpace // chaos namespace of srv
	eps []*ua.EndpointDescription

	ns uint16 // namespace index of the chaos nodes (stable across restarts)

	// counters holds the last value handed out for each counter node. Values
	// are only ever written in increasing order, see bump.
	counters [numCounters]atomic.Int64

	// stopped servers whose resources must still drain
	old []*server.Server

	// nonce numbers the calls of the Once method; onceSeen holds the numbers
	// the server executed and replays the ones it executed more than once.
	nonce    atomic.Int64
	onceMu   sync.Mutex
	onceSeen map[int64]bool
	replays  []int64
}

func newEnv(t *testing.T, seed int64, serverOpts ...server.Option) *env {
	t.Helper()
	e := &env{t: t, seed: seed, serverOpts: serverOpts}
	e.proxy = testutil.NewChaosProxy(t, "", seed)
	e.startServer()
	t.Cleanup(func() { e.stopServer() })

	ctx, cancel := chaoskit.OpCtx()
	defer cancel()
	eps, err := opcua.GetEndpoints(ctx, e.url(), opcua.DialTimeout(30*time.Second), opcua.RequestTimeout(30*time.Second))
	if err != nil {
		t.Fatalf("chaos: get endpoints: %v", err)
	}
	e.eps = eps
	return e
}

// url is the endpoint clients dial: the chaos proxy.
func (e *env) url() string { return e.proxy.EndpointURL() }

// directAddr is the server's real listen address, bypassing the proxy.
func (e *env) directAddr() string {
	return fmt.Sprintf("localhost:%d", e.server().Port())
}

func (e *env) server() *server.Server {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.srv
}

func (e *env) nodeID(name string) *ua.NodeID { return ua.NewStringNodeID(e.ns, name) }
func (e *env) counterID(i int) *ua.NodeID    { return e.nodeID(fmt.Sprintf("Counter%d", i)) }
func (e *env) scratchID(i int) *ua.NodeID    { return e.nodeID(fmt.Sprintf("Scratch%d", i)) }
func (e *env) blobID() *ua.NodeID            { return e.nodeID("Blob") }
func (e *env) folderID() *ua.NodeID          { return e.nodeID("Folder") }
func (e *env) bigID() *ua.NodeID             { return e.nodeID("Big") }
func (e *env) methodID() *ua.NodeID          { return e.nodeID("Square") }
func (e *env) onceID() *ua.NodeID            { return e.nodeID("Once") }
func (e *env) objectsID() *ua.NodeID         { return ua.NewNumericNodeID(e.ns, id.ObjectsFolder) }

// secureServerOptions returns the options of a server with one application
// instance certificate per key type (RSA, ECC P-256, ECC P-384, Ed25519,
// brainpoolP256r1, brainpoolP384r1, Ed448) that
// offers every policy under test in both secure modes, the None endpoint, and
// anonymous and username identities.
func secureServerOptions(t testing.TB) []server.Option {
	t.Helper()
	p := pki(t)
	opts := []server.Option{
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.WithUsernameValidator(userValidator),
		server.Certificate(p.ServerCert),
		server.PrivateKey(p.ServerKey),
		server.SetLogger(chaoskit.Logger()),
	}
	for _, curve := range eccCurves {
		opts = append(opts, server.ApplicationIdentity(p.ECC.Server[curve].Cert, p.ECC.Server[curve].Key))
	}
	for _, pol := range allPolicies {
		opts = append(opts,
			server.EnableSecurity(pol.uri, ua.MessageSecurityModeSign),
			server.EnableSecurity(pol.uri, ua.MessageSecurityModeSignAndEncrypt),
		)
	}
	return opts
}

// startServer creates and starts a new server instance and points the proxy
// at it. The server advertises the proxy's port as its endpoint and listens
// on an ephemeral port, so the client-visible endpoint is identical for every
// instance.
func (e *env) startServer() {
	e.t.Helper()
	opts := append(secureServerOptions(e.t), e.serverOpts...)
	opts = append(opts, server.EndPoint("localhost", e.proxy.Port()), server.ListenOn("localhost:0"))
	srv, err := server.New(append([]server.Option{server.InsecureNoSecurity()}, opts...)...)
	if err != nil {
		e.t.Fatalf("chaos: new server: %v", err)
	}
	nsp := e.populate(srv)
	if err := srv.Start(context.Background()); err != nil {
		e.t.Fatalf("chaos: start server: %v", err)
	}
	e.mu.Lock()
	e.srv = srv
	e.nsp = nsp
	e.mu.Unlock()
	e.proxy.SetBackend(fmt.Sprintf("localhost:%d", srv.Port()))
}

// stopServer closes the current server instance (if any).
func (e *env) stopServer() {
	e.mu.Lock()
	srv := e.srv
	e.srv = nil
	e.nsp = nil
	if srv != nil {
		e.old = append(e.old, srv)
	}
	e.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// restartServer replaces the server with a brand-new instance: all channels,
// sessions, subscriptions and monitored items are lost, as after a process
// restart. The application instance certificates stay.
func (e *env) restartServer(downtime time.Duration) {
	e.proxy.SetRefuse(true)
	e.stopServer()
	e.proxy.DropAll()
	time.Sleep(downtime)
	e.startServer()
	e.proxy.SetRefuse(false)
}

// populate adds the chaos namespace to srv.
func (e *env) populate(srv *server.Server) *server.NodeNameSpace {
	e.t.Helper()
	root, err := srv.Namespace(0)
	if err != nil {
		e.t.Fatalf("chaos: namespace 0: %v", err)
	}
	ns := server.NewNodeNameSpace(srv, "http://otfabric.com/chaos")
	obj := ns.Objects()
	root.Objects().AddRef(obj, id.HasComponent, true)
	if e.ns == 0 {
		// The index is the same for every server instance. Workers read it
		// while a restart populates the next instance, so write it only once.
		e.ns = ns.ID()
	}

	add := func(parent *server.Node, name string, v any) {
		n := ns.AddNewVariableStringNode(name, v)
		parent.AddRef(n, id.HasComponent, true)
	}
	for i := 0; i < numCounters; i++ {
		// A restarted server continues at the last value handed out so that
		// the values observed by subscribers never go backwards.
		add(obj, fmt.Sprintf("Counter%d", i), e.counters[i].Load())
	}
	for i := 0; i < numScratch; i++ {
		add(obj, fmt.Sprintf("Scratch%d", i), scratchValue(i, 0))
	}
	add(obj, "Blob", blobValue())
	add(obj, "Big", bigValue(0))

	folder := server.NewFolderNode(e.folderID(), "Folder")
	ns.AddNode(folder)
	obj.AddRef(folder, id.HasComponent, true)
	for i := 0; i < numBrowse; i++ {
		add(folder, fmt.Sprintf("Leaf%03d", i), int32(i))
	}

	addMethod := func(name string, argType uint32, fn server.MethodHandler) {
		nodeID := e.nodeID(name)
		method := server.NewFolderNode(nodeID, name)
		method.SetNodeClass(ua.NodeClassMethod)
		ns.AddNode(method)
		obj.AddRef(method, id.HasComponent, true)
		for prop, arg := range map[string]string{"InputArguments": "n", "OutputArguments": "result"} {
			eo := ua.NewExtensionObject(&ua.Argument{
				Name:        arg,
				DataType:    ua.NewNumericNodeID(0, argType),
				ValueRank:   -1,
				Description: ua.NewLocalizedText(arg),
			})
			value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant([]*ua.ExtensionObject{eo})}
			pn := server.NewNode(
				e.nodeID(name+"."+prop),
				map[ua.AttributeID]*ua.DataValue{
					ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
					ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(prop)),
					ua.AttributeIDDataType:   server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
				},
				nil,
				func() *ua.DataValue { return value },
			)
			ns.AddNode(pn)
			method.AddRef(pn, id.HasProperty, true)
		}
		srv.RegisterMethod(obj.ID(), nodeID, fn)
	}
	addMethod("Square", id.Int32,
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 1 || args[0] == nil {
				return nil, ua.StatusBadArgumentsMissing
			}
			n, ok := args[0].Value().(int32)
			if !ok {
				return nil, ua.StatusBadInvalidArgument
			}
			return []*ua.Variant{ua.MustVariant(n * n)}, ua.StatusOK
		})
	// Once records the number it is called with. Every caller passes a
	// number of its own and clients do not retry, so a number that arrives
	// twice is a request the server executed twice.
	addMethod("Once", id.Int64,
		func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			if len(args) != 1 || args[0] == nil {
				return nil, ua.StatusBadArgumentsMissing
			}
			n, ok := args[0].Value().(int64)
			if !ok {
				return nil, ua.StatusBadInvalidArgument
			}
			e.onceMu.Lock()
			if e.onceSeen == nil {
				e.onceSeen = make(map[int64]bool)
			}
			if e.onceSeen[n] {
				e.replays = append(e.replays, n)
			}
			e.onceSeen[n] = true
			e.onceMu.Unlock()
			return []*ua.Variant{ua.MustVariant(n)}, ua.StatusOK
		})
	return ns
}

// The values of the chaos nodes are recognisable, so that a value that was
// not produced by a writer (a forged or damaged message that passed the
// security checks, or the response of another request) is detected.

// scratchValue is the k-th value of scratch node i: the node index is in the
// low bits of every value ever written to the node.
func scratchValue(i int, k int32) int32 { return k<<8 | int32(i) }

// validScratch reports whether v is a value a writer produced for scratch
// node i.
func validScratch(i int, v any) bool {
	n, ok := v.(int32)
	return ok && n >= 0 && n&0xFF == int32(i)
}

// randScratch returns a new value for scratch node i.
func randScratch(rng *rand.Rand, i int) int32 { return scratchValue(i, rng.Int31n(1<<22)) }

// blobValue is the content of the multi-chunk node: every byte is determined
// by its position.
func blobValue() []byte {
	b := make([]byte, blobSize)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

var wantBlob = blobValue()

func validBlob(v any) bool {
	b, ok := v.([]byte)
	return ok && bytes.Equal(b, wantBlob)
}

// bigSize is the size of the values of the node that is written with
// multi-chunk requests: 3 chunks with the default 64k buffers.
const bigSize = 150 * 1024

// bigValue returns a value for the multi-chunk node: the first byte is free,
// every other byte is determined by it and by its position, so a value that
// was put together from the chunks of different requests, or with a chunk
// missing, repeated or out of order, is not a valid one.
func bigValue(first byte) []byte {
	if v, ok := bigValues.Load(first); ok {
		return v.([]byte)
	}
	b := make([]byte, bigSize)
	for i := range b {
		b[i] = first + byte(i*7+i>>8)
	}
	v, _ := bigValues.LoadOrStore(first, b)
	return v.([]byte)
}

// bigValues caches the values by their first byte. They are never modified.
var bigValues sync.Map

func validBig(v any) bool {
	b, ok := v.([]byte)
	if !ok || len(b) != bigSize {
		return false
	}
	return bytes.Equal(b, bigValue(b[0]))
}

// reportReplays fails the test for every request the server executed twice.
func (e *env) reportReplays() {
	e.t.Helper()
	e.onceMu.Lock()
	defer e.onceMu.Unlock()
	if len(e.replays) > 0 {
		e.t.Errorf("REPLAY: the server executed %d request(s) more than once (Once numbers %v)", len(e.replays), e.replays)
	}
}

// validCounter reports whether v is a value the server-side writer produced
// for counter i so far.
func (e *env) validCounter(i int, v any) bool {
	n, ok := v.(int64)
	return ok && n >= 0 && n <= e.counters[i].Load()
}

// bump writes the next value of counter i directly into the address space of
// the running server, as an application embedding the server would. The
// values written to a counter strictly increase, also across restarts. It
// returns the value written, or 0 when no server is running.
func (e *env) bump(i int) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.nsp == nil {
		return 0
	}
	v := e.counters[i].Add(1)
	if sc := e.nsp.SetAttribute(e.counterID(i), ua.AttributeIDValue, server.DataValueFromValue(v)); sc != ua.StatusOK {
		e.t.Errorf("server-side write of Counter%d failed: %v", i, sc)
	}
	return v
}

// endpoint returns the endpoint the server advertises for the policy and mode.
func (e *env) endpoint(pol policy, mode ua.MessageSecurityMode) *ua.EndpointDescription {
	e.t.Helper()
	for _, ep := range e.eps {
		if ep.SecurityPolicyURI == pol.uri && ep.SecurityMode == mode {
			return ep
		}
	}
	e.t.Fatalf("chaos: server does not advertise %s / %v", pol.name, mode)
	return nil
}

// securityOptions returns the client options for a fully validated secured
// connection with the policy and mode, the client application certificate of
// the policy's key type, and the given identity.
func (e *env) securityOptions(pol policy, mode ua.MessageSecurityMode, auth ua.UserTokenType) []opcua.Option {
	e.t.Helper()
	p := pki(e.t)
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(e.endpoint(pol, mode), auth),
		opcua.TrustedCertificates(p.ServerCertX509),
	}
	for _, curve := range eccCurves {
		opts = append(opts, opcua.TrustedCertificates(p.ECC.Server[curve].X509))
	}
	if pol.curve == "" {
		opts = append(opts, opcua.Certificate(p.ClientCert), opcua.PrivateKey(p.ClientKey))
	} else {
		opts = append(opts, opcua.Certificate(p.ECC.Client[pol.curve].Cert), opcua.PrivateKeySigner(p.ECC.Client[pol.curve].Key))
	}
	if auth == ua.UserTokenTypeUserName {
		// RSA policies encrypt the password with the server certificate, the
		// ECC policies put it in an EccEncryptedSecret made with the
		// ephemeral key of the session.
		opts = append(opts, opcua.AuthUsername(userName, userPassword))
	}
	return opts
}

// clientOptions returns the options for a client that talks through the
// proxy with the given policy in SignAndEncrypt mode and a username identity.
func (e *env) clientOptions(rec *chaoskit.StateRecorder, pol policy, extra ...opcua.Option) []opcua.Option {
	opts := e.securityOptions(pol, ua.MessageSecurityModeSignAndEncrypt, ua.UserTokenTypeUserName)
	opts = append(opts,
		opcua.DialTimeout(10*time.Second),
		// Fault-free tests must never fail because the machine is slow, so
		// the default request timeout only guards against a hang. Scenarios
		// that inject faults pass a short timeout instead.
		opcua.RequestTimeout(60*time.Second),
		opcua.ReconnectInterval(50*time.Millisecond),
		opcua.AutoReconnect(true),
	)
	if rec != nil {
		opts = append(opts, opcua.WithConnStateHandler(rec.Handle))
	}
	if l := chaoskit.Logger(); l != nil {
		opts = append(opts, opcua.WithLogger(l.With("side", "client", "policy", pol.name)))
	}
	return append(opts, extra...)
}

// connect creates and connects a client through the proxy. The client is
// closed when the test ends unless the test closed it earlier.
func (e *env) connect(rec *chaoskit.StateRecorder, pol policy, extra ...opcua.Option) *opcua.Client {
	e.t.Helper()
	c, err := e.dial(rec, pol, extra...)
	if err != nil {
		e.t.Fatalf("chaos: connect with %s: %v", pol.name, err)
	}
	return c
}

func (e *env) dial(rec *chaoskit.StateRecorder, pol policy, extra ...opcua.Option) (*opcua.Client, error) {
	return e.dialWith(rec, e.clientOptions(rec, pol, extra...))
}

// dialWith connects a client with exactly the given options.
func (e *env) dialWith(rec *chaoskit.StateRecorder, opts []opcua.Option) (*opcua.Client, error) {
	c, err := opcua.NewClient(e.url(), append([]opcua.Option{opcua.InsecureNoSecurity()}, opts...)...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		chaoskit.CloseClient(c, rec)
		return nil, err
	}
	e.t.Cleanup(func() { chaoskit.CloseClient(c, rec) })
	return c, nil
}

// resources returns the per-client resources held by the current server.
func (e *env) resources() testhook.ServerResources {
	srv := e.server()
	if srv == nil {
		return testhook.ServerResources{}
	}
	return testhook.ServerResourcesOf(srv)
}

// requireServerDrained waits until the current server holds no channels,
// sessions, subscriptions or monitored items.
func (e *env) requireServerDrained(limit time.Duration) {
	e.t.Helper()
	var last testhook.ServerResources
	start := time.Now()
	ok := chaoskit.Eventually(limit, func() bool {
		now := e.resources()
		if now != last {
			e.t.Logf("[%6.2fs] server resources: %+v", time.Since(start).Seconds(), now)
		}
		last = now
		return last == testhook.ServerResources{}
	})
	if !ok {
		e.t.Errorf("server did not release client resources within %v: %+v", limit, last)
	}
}

// requireCleanClient verifies that the server still serves a brand-new
// secured client correctly: connect, read, write/read-back, multi-chunk
// read, browse, call, subscribe and receive a data change, then shut down
// cleanly.
func (e *env) requireCleanClient(pol policy) {
	e.t.Helper()
	t := e.t

	var c *opcua.Client
	var err error
	// The listener backlog may still hold connections that were queued during
	// the storm, so allow a few attempts; each one is individually bounded.
	ok := chaoskit.Eventually(chaoskit.SettleLimit, func() bool {
		c, err = e.dial(nil, pol, opcua.AutoReconnect(false), opcua.RequestTimeout(30*time.Second))
		return err == nil
	})
	if !ok {
		t.Errorf("clean %s client could not connect after the storm: %v", pol.name, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if got := c.SecurityPolicy(); got != pol.uri {
		t.Errorf("clean %s client: security policy %q", pol.name, got)
	}
	want := randScratch(rand.New(rand.NewSource(time.Now().UnixNano())), 0)
	if sc, err := c.WriteNodeValue(ctx, e.scratchID(0), want); err != nil || sc != ua.StatusOK {
		t.Errorf("clean %s client: write: status=%v err=%v", pol.name, sc, err)
	}
	dv, err := c.ReadValue(ctx, e.scratchID(0))
	if err != nil {
		t.Errorf("clean %s client: read: %v", pol.name, err)
	} else if got, _ := dv.Value.Value().(int32); got != want {
		t.Errorf("clean %s client: read back %v, want %v", pol.name, dv.Value.Value(), want)
	}

	blob, err := c.ReadValue(ctx, e.blobID())
	if err != nil {
		t.Errorf("clean %s client: read blob: %v", pol.name, err)
	} else if !validBlob(blob.Value.Value()) {
		t.Errorf("clean %s client: blob content differs", pol.name)
	}

	refs, err := c.BrowseAll(ctx, e.folderID())
	if err != nil {
		t.Errorf("clean %s client: browse: %v", pol.name, err)
	} else if n := countLeaves(refs); n != numBrowse {
		t.Errorf("clean %s client: browse returned %d leaves, want %d", pol.name, n, numBrowse)
	}

	res, err := c.CallMethod(ctx, e.objectsID(), e.methodID(), int32(7))
	if err != nil {
		t.Errorf("clean %s client: call: %v", pol.name, err)
	} else if res.StatusCode != ua.StatusOK || len(res.OutputArguments) != 1 || res.OutputArguments[0].Value() != int32(49) {
		t.Errorf("clean %s client: call result %+v", pol.name, res)
	}

	ch := make(chan *opcua.PublishNotificationData, 16)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 20 * time.Millisecond}, ch)
	if err != nil {
		t.Errorf("clean %s client: subscribe: %v", pol.name, err)
	} else {
		mres, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth,
			opcua.NewMonitoredItemCreateRequestWithDefaults(e.scratchID(1), ua.AttributeIDValue, 1))
		if err != nil || mres.Results[0].StatusCode != ua.StatusOK {
			t.Errorf("clean %s client: monitor: res=%+v err=%v", pol.name, mres, err)
		}
		marker := randScratch(rand.New(rand.NewSource(time.Now().UnixNano())), 1)
		if _, err := c.WriteNodeValue(ctx, e.scratchID(1), marker); err != nil {
			t.Errorf("clean %s client: write marker: %v", pol.name, err)
		}
		deadline := time.After(chaoskit.SettleLimit)
	wait:
		for {
			select {
			case n := <-ch:
				if n.Error != nil {
					continue
				}
				if dcn, ok := n.Value.(*ua.DataChangeNotification); ok {
					for _, mi := range dcn.MonitoredItems {
						if mi.Value != nil && mi.Value.Value != nil && mi.Value.Value.Value() == marker {
							break wait
						}
					}
				}
			case <-deadline:
				t.Errorf("clean %s client: no data change for the marker value within %v", pol.name, chaoskit.SettleLimit)
				break wait
			}
		}
		if err := sub.Cancel(ctx); err != nil {
			t.Errorf("clean %s client: cancel subscription: %v", pol.name, err)
		}
	}
	chaoskit.CloseClient(c, nil)
}

// countLeaves returns the number of the static LeafNNN children among refs.
func countLeaves(refs []*ua.ReferenceDescription) int {
	n := 0
	for _, r := range refs {
		if r != nil && r.BrowseName != nil && strings.HasPrefix(r.BrowseName.Name, "Leaf") {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// error classification
// ---------------------------------------------------------------------------

// isFaultError reports whether err is an error a caller must expect while the
// transport is disturbed or the bytes of a secured message are altered,
// replayed or lost: the request did not complete because the connection,
// channel, session or subscription it was using went away, did not answer in
// time, or failed its security checks.
func isFaultError(err error) bool {
	if chaoskit.IsConnectionError(err) {
		return true
	}
	for _, sc := range []ua.StatusCode{
		// a signature, tag, padding or sequence number that does not verify
		ua.StatusBadSecurityChecksFailed,
		ua.StatusBadSequenceNumberInvalid,
		// a damaged chunk header or OpenSecureChannel message; the policy
		// URI and the certificate are in its header
		ua.StatusBadSecurityPolicyRejected,
		ua.StatusBadCertificateInvalid,
		ua.StatusBadDecodingError,
		ua.StatusBadTCPMessageTypeInvalid,
		ua.StatusBadTCPMessageTooLarge,
		ua.StatusBadTCPSecureChannelUnknown,
		ua.StatusBadTCPInternalError,
	} {
		if errors.Is(err, sc) {
			return true
		}
	}
	// a chunk whose size or type field was altered
	if errors.Is(err, errors.ErrMessageTooLarge) || errors.Is(err, errors.ErrMessageTooSmall) || errors.Is(err, errors.ErrInvalidMessageType) {
		return true
	}
	// A message that was repeated on the wire is refused for what it is: an
	// OpenSecureChannel message while the receiver is neither opening nor
	// renewing the channel, or a message of another channel.
	return errors.Is(err, errors.ErrInvalidState) &&
		(strings.Contains(err.Error(), "openingInstance is nil") || strings.Contains(err.Error(), "SecureChannelID="))
}
