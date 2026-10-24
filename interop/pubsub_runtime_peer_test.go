//go:build interop

// SPDX-License-Identifier: MIT

// The go-opcua PubSub runtime (package pubsub, server.WithPubSub) against
// open62541 as publisher and subscriber.
// COVERAGE.md: pubsub / pubsub.runtime.publisher, pubsub.runtime.subscriber,
// pubsub.runtime.target-variables, pubsub.runtime.sks-pull,
// pubsub.keepalive, pubsub.receive-timeout
//
//   - go-opcua publisher: a go-opcua server with WithPubSub publishes its
//     PubSub.* variables (the address space is the DataSource); the open62541
//     subscriber writes them into its TargetVariables, read over OPC UA.
//   - go-opcua subscriber: a runtime (pubsub.New) hands the DataSets of the
//     open62541 publisher to a DataSetHandler, or a go-opcua server with
//     WithPubSub writes them into its PubSub.* variables (TargetVariables).
//
// The transports, mappings, field encodings and static-key security of the
// wire path are those of pubsub_live_peer_test.go.

package interop

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/sks"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// goPubSubServer is a go-opcua server with WithPubSub and the PubSub.*
// variables of the baseline fixture.
type goPubSubServer struct {
	endpoint string
	srv      *server.Server
	ns       uint16
	// close closes the server once, before the end of the test if need be.
	close func()
}

type goPubSubOpts struct {
	pubsubOpts []pubsub.Option
	// secure adds the go-server certificate, Basic256Sha256 endpoints,
	// UserName login and the trust list of the test PKI.
	secure bool
	// ks, if set, is published as Security Key Service.
	ks *security.KeyService
}

// startGoPubSubServer starts the server; configure then adds the PubSub
// components (they need the namespace index of the variables).
func startGoPubSubServer(t *testing.T, o goPubSubOpts, configure func(p *pubsub.PubSub, ns uint16)) *goPubSubServer {
	t.Helper()
	opts := []server.Option{
		server.ListenOn("0.0.0.0:0"),
		server.EndPoint("host.docker.internal", 0),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.WithPubSub(nil, o.pubsubOpts...),
	}
	if o.secure {
		opts = append(opts,
			server.Certificate(loadGoServerCert(t)),
			server.PrivateKey(loadGoServerKey(t)),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSign),
			server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
			server.EnableAuthMode(ua.UserTokenTypeUserName),
			server.WithUsernameValidator(func(user, pass string) error {
				if user == psSKSUser && pass == psSKSPassword {
					return nil
				}
				return ua.StatusBadUserAccessDenied
			}),
			server.WithClientCertificateTrustList(loadCACertDER(t)))
	}
	s, err := server.New(opts...)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ns := server.NewNodeNameSpace(s, interopNamespaceURI)
	s.AddNamespace(ns)
	initial := map[string]any{
		"Boolean": false, "Int32": int32(0), "Int64": int64(0), "UInt64": uint64(0), "Double": 0.0, "String": "",
		"DateTime": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "ByteString": []byte{}, "Int32Array": []int32{0, 0, 0},
		"DoubleArray": []float64{0, 0, 0},
	}
	for _, v := range psVars {
		n := ns.AddNewVariableStringNode("PubSub."+v.name, initial[v.name])
		ns.Objects().AddRef(n, server.RefTypeIDHasComponent, true)
	}
	if o.ks != nil {
		if _, err := s.EnableSecurityKeyService(o.ks); err != nil {
			t.Fatalf("EnableSecurityKeyService: %v", err)
		}
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	var once sync.Once
	closeServer := func() { once.Do(func() { _ = s.Close() }) }
	t.Cleanup(closeServer)
	if configure != nil {
		configure(s.PubSub(), ns.ID())
	}
	return &goPubSubServer{endpoint: fmt.Sprintf("opc.tcp://localhost:%d%s", s.Port(), endpointPath), srv: s, ns: ns.ID(), close: closeServer}
}

// psRuntimeDataSet is the PublishedDataItems of the PubSub.* variables of
// a go-opcua server, with the DataSetMetaData of the open62541 reader.
func psRuntimeDataSet(vars []psVar, ns uint16, maxStringLength uint32) *ua.PublishedDataSetDataType {
	var fields []pubsub.PublishedField
	for _, v := range vars {
		fields = append(fields, pubsub.PublishedField{
			Field:  pubsub.Field{Name: v.name, Type: ua.TypeID(v.typ), Array: v.rank == 1},
			NodeID: ua.NewStringNodeID(ns, "PubSub."+v.name),
		})
	}
	pds := pubsub.PublishedDataItems("InteropDataSet", fields...)
	md := psMetaData(vars, maxStringLength)
	pds.DataSetMetaData = md
	return pds
}

// mustOK returns a function that fails the test on an error and returns
// the value otherwise: mustOK[T](t)(f()).
func mustOK[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// psRuntimeCase is a transport / encoding / security combination of the
// runtime tests.
type psRuntimeCase struct {
	psLiveCase
	mqtt bool
	json bool
}

func psRuntimeCases() []psRuntimeCase {
	var out []psRuntimeCase
	for _, c := range psUDPCases() {
		if c.mode == ua.MessageSecurityModeSign {
			continue // the static-key Sign path is pubsub_live_peer_test.go's
		}
		out = append(out, psRuntimeCase{psLiveCase: c})
	}
	return append(out,
		psRuntimeCase{psLiveCase: psLiveCase{name: "mqtt-uadp", vars: psVars}, mqtt: true},
		psRuntimeCase{psLiveCase: psLiveCase{name: "mqtt-json", vars: psVars}, mqtt: true, json: true})
}

func (c psRuntimeCase) profile() string {
	switch {
	case c.json:
		return psProfileMQTTJSON
	case c.mqtt:
		return psProfileMQTTUADP
	}
	return psProfileUDP
}

// ---------------------------------------------------------------------------
// go-opcua publishes
// ---------------------------------------------------------------------------

// TestPubSubRuntime_GoPublishes_Open62541Subscribes: a go-opcua server with
// WithPubSub publishes its PubSub.* variables; the open62541 subscriber
// writes them into its TargetVariables.
func TestPubSubRuntime_GoPublishes_Open62541Subscribes(t *testing.T) {
	psRuntimeGoPublishes(t, psOpen62541)
}

// psRuntimeGoPublishes: a go-opcua server with WithPubSub publishes its
// PubSub.* variables over every transport of psRuntimeCases; the peer
// subscriber writes them into its TargetVariables.
func psRuntimeGoPublishes(t *testing.T, p *psPeer) {
	p.requireServer(t)
	broker := 0
	for _, c := range psRuntimeCases() {
		if c.mqtt && broker == 0 {
			broker = startMosquitto(t)
		}
	}
	for _, c := range psRuntimeCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			topic := fmt.Sprintf("go-opcua-interop/runtime/%s/%d", c.name, psFresh())
			var sub *pubsubServer
			var connURL string
			if c.mqtt {
				sub = startPubSubServer(t, pubsubServerOpts{peer: p, mqtt311: true, config: psSubscriberConfig(c.psLiveCase, c.profile(),
					fmt.Sprintf("mqtt://host.docker.internal:%d", broker), eo("i=15670", jobj{"QueueName": topic}), c.json)})
				connURL = fmt.Sprintf("mqtt://127.0.0.1:%d", broker)
			} else {
				port := freeUDPPort(t)
				sub = startPubSubServer(t, pubsubServerOpts{peer: p,
					config:   psSubscriberConfig(c.psLiveCase, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false),
					udpPorts: []int{port},
				})
				connURL = fmt.Sprintf("opc.udp://127.0.0.1:%d", sub.udpPort(t, port))
			}

			var popts []pubsub.Option
			if keys := c.keys(t); keys != nil {
				popts = append(popts, pubsub.WithKeySource("InteropGroup", keys))
			}
			pub := startGoPubSubServer(t, goPubSubOpts{pubsubOpts: popts}, func(p *pubsub.PubSub, ns uint16) {
				mustOK[pubsub.ComponentID](t)(p.AddPublishedDataSet(psRuntimeDataSet(c.vars, ns, c.maxStrLn)))
				w := pubsub.DataSetWriter("InteropWriter", psWriterID, "InteropDataSet")
				w.DataSetFieldContentMask = c.fcm
				var conn *ua.PubSubConnectionDataType
				var wg *ua.WriterGroupDataType
				switch {
				case c.json:
					conn = pubsub.MQTTConnection("InteropPublisher", connURL, uint16(psPubID), pubsub.MappingJSON)
					wg = pubsub.JSONWriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, topic, w)
				case c.mqtt:
					conn = pubsub.MQTTConnection("InteropPublisher", connURL, uint16(psPubID), pubsub.MappingUADP)
					wg = pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, pubsub.SetWriterQueue(w, topic, ""))
				default:
					conn = pubsub.UDPConnection("InteropPublisher", connURL, uint16(psPubID))
					wg = pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, w)
				}
				if c.mode > ua.MessageSecurityModeNone {
					wg = pubsub.Secure(wg, c.mode, "InteropGroup")
				}
				mustOK[pubsub.ComponentID](t)(p.AddConnection(pubsub.AttachWriterGroups(conn, wg)))
			})
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
		})
	}
}

// ---------------------------------------------------------------------------
// go-opcua subscribes
// ---------------------------------------------------------------------------

// psDataSets collects the DataSets a runtime receives.
type psDataSets struct {
	mu  sync.Mutex
	got []*pubsub.ReceivedDataSet
	ch  chan struct{}
}

func newPSDataSets() *psDataSets { return &psDataSets{ch: make(chan struct{}, 1)} }

func (d *psDataSets) handle(ds *pubsub.ReceivedDataSet) {
	d.mu.Lock()
	d.got = append(d.got, ds)
	if len(d.got) > 200 {
		d.got = d.got[100:]
	}
	d.mu.Unlock()
	select {
	case d.ch <- struct{}{}:
	default:
	}
}

// wait returns the first DataSet whose fields (by name) hold values.
func (d *psDataSets) wait(t *testing.T, vars []psVar, values []any, timeout time.Duration) *pubsub.ReceivedDataSet {
	t.Helper()
	want := make([]string, len(values))
	for i, v := range values {
		want[i] = variantKey(t, ua.MustVariant(v))
	}
	deadline := time.After(timeout)
	var last string
	for {
		d.mu.Lock()
		for _, ds := range d.got {
			match := ds.Complete
			var got []string
			for i, v := range vars {
				f := ds.Field(v.name)
				var val *ua.Variant
				if f != nil {
					val = f.Value
				}
				got = append(got, fmt.Sprint(val))
				if variantKey(t, val) != want[i] {
					match = false
				}
			}
			last = strings.Join(got, ", ")
			if match {
				d.mu.Unlock()
				return ds
			}
		}
		n := len(d.got)
		d.mu.Unlock()
		select {
		case <-d.ch:
		case <-deadline:
			t.Fatalf("no DataSet with %v within %v (%d received, last %s)", values, timeout, n, last)
		}
	}
}

// psRuntimeReader is the go-opcua reader of the adapter's writer.
func psRuntimeReader(c psRuntimeCase, topic string, timeout time.Duration) *ua.ReaderGroupDataType {
	// open62541 1.5.9 ignores the configured ConfigurationVersion of a
	// PublishedDataSet and sends one it generates (contract §14.3), so the
	// reader cannot know the MajorVersion: without one (0) the go-opcua
	// reader does not compare it. With the configured 1.1 every message
	// is discarded as a version mismatch.
	md := psMetaData(c.vars, c.maxStrLn)
	md.ConfigurationVersion = nil
	r := pubsub.DataSetReader("InteropReader", uint16(psPubID), psWriterGroupID, psWriterID, md)
	r.DataSetFieldContentMask = c.fcm
	r.MessageReceiveTimeout = float64(timeout.Milliseconds())
	if c.mqtt {
		r = pubsub.SetReaderQueue(r, topic, "")
	}
	rg := pubsub.ReaderGroup("InteropReaderGroup", r)
	if c.mode > ua.MessageSecurityModeNone {
		rg = pubsub.Secure(rg, c.mode, "InteropGroup")
	}
	return rg
}

func psRuntimeSubConnection(c psRuntimeCase, url string) *ua.PubSubConnectionDataType {
	switch {
	case c.json:
		return pubsub.MQTTConnection("InteropSubscriber", url, nil, pubsub.MappingJSON)
	case c.mqtt:
		return pubsub.MQTTConnection("InteropSubscriber", url, nil, pubsub.MappingUADP)
	}
	return pubsub.UDPConnection("InteropSubscriber", url, nil)
}

// psGoSubscriber starts a go-opcua subscriber whose connection
// "InteropSubscriber" receives on url, and returns its runtime and a
// function that stops it.
type psGoSubscriber func(url string) (*pubsub.PubSub, func())

// psRuntimeSubscriber is the psGoSubscriber of a runtime (startRuntime)
// with cfg(url); started receives the runtime.
func psRuntimeSubscriber(t *testing.T, cfg func(url string) *ua.PubSubConfigurationDataType, started *(*pubsub.PubSub), opts ...pubsub.Option) psGoSubscriber {
	return func(url string) (*pubsub.PubSub, func()) {
		p := startRuntime(t, cfg(url), opts...)
		if started != nil {
			*started = p
		}
		return p, func() { _ = p.Close() }
	}
}

// psStartAdapterPublisher starts the go-opcua subscriber sub and the
// open62541 publisher of case c, and returns the publisher.
func psStartAdapterPublisher(t *testing.T, c psRuntimeCase, broker int, topic string, sub psGoSubscriber) *pubsubServer {
	t.Helper()
	return psStartPeerPublisher(t, psOpen62541, c, broker, topic, sub)
}

// psStartPeerPublisher starts the go-opcua subscriber sub and the publisher
// of case c on the peer (MQTT 3.1.1 unless psPeer.mqtt5Publisher), and
// returns the publisher.
func psStartPeerPublisher(t *testing.T, p *psPeer, c psRuntimeCase, broker int, topic string, sub psGoSubscriber) *pubsubServer {
	t.Helper()
	return psStartPeerPublisherOn(t, p, c, broker, topic, !p.mqtt5Publisher, sub)
}

// psStartPeerPublisherOn is psStartPeerPublisher with MQTT 3.1.1 (mqtt311) or
// the peer's default MQTT version.
//
// Over UDP the subscriber is started first and the publisher is told its
// port only once it receives on it (psBindRuntimeUDP).
func psStartPeerPublisherOn(t *testing.T, p *psPeer, c psRuntimeCase, broker int, topic string, mqtt311 bool, sub psGoSubscriber) *pubsubServer {
	t.Helper()
	if c.mqtt {
		sub(fmt.Sprintf("mqtt://127.0.0.1:%d", broker))
		return startPubSubServer(t, pubsubServerOpts{peer: p, mqtt311: mqtt311, config: psPublisherConfig(c.psLiveCase, c.profile(),
			fmt.Sprintf("mqtt://host.docker.internal:%d", broker), eo("i=15667", jobj{"QueueName": topic}), c.json)})
	}
	port := psBindRuntimeUDP(t, sub)
	return startPubSubServer(t, pubsubServerOpts{peer: p, config: psUDPPublisherConfig(c.psLiveCase, port)})
}

// psPingPublisherID is the PublisherId of the datagrams psBindRuntimeUDP
// sends: no reader of the suite matches it, so the runtime drops them
// after counting them (uadp.ErrFiltered).
const psPingPublisherID = 0xFFFE

// psBindRuntimeUDP starts the go-opcua subscriber sub on
// opc.udp://localhost:<port> and returns the port once the subscriber
// receives on it: a peer configured with the port afterwards cannot lose it
// to another socket. The runtime binds the port asynchronously and retries a
// failed bind, so a port taken since testport found it free shows as the
// connection's LastError; the subscriber is then stopped and started again
// on another port, before any peer knows the port.
func psBindRuntimeUDP(t *testing.T, sub psGoSubscriber) int {
	t.Helper()
	ping := psGoMessage(psLiveCase{vars: psVars}, 1, psValues(psVars, 0))
	ping.PublisherID = message.NewPublisherID(message.PublisherIDUInt16, psPingPublisherID)
	b, err := uadp.Encode(ping, &uadp.EncodeOptions{MetaData: psLookup(psMetaData(psVars, 0))})
	if err != nil {
		t.Fatalf("encode the ping: %v", err)
	}
	snd, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = snd.Close() }()
	for range 10 {
		port := freeUDPPort(t)
		p, stop := sub(fmt.Sprintf("opc.udp://localhost:%d", port))
		conn, ok := p.Lookup(pubsub.KindConnection, pubsub.Root, "InteropSubscriber")
		if !ok {
			t.Fatal("no connection InteropSubscriber")
		}
		dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
		deadline := time.Now().Add(15 * time.Second)
		for {
			st, err := p.Status(conn)
			if err != nil {
				t.Fatal(err)
			}
			if st.Counters.NetworkMessagesReceived > 0 {
				return port
			}
			if testport.InUse(st.LastError) {
				t.Logf("UDP port %d was taken (%v): another one", port, st.LastError)
				stop()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the go-opcua subscriber does not receive on UDP port %d: %+v", port, st)
			}
			_, _ = snd.WriteToUDP(b, dst)
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Fatal("no UDP port the go-opcua subscriber could bind")
	return 0
}

func startRuntime(t *testing.T, cfg *ua.PubSubConfigurationDataType, opts ...pubsub.Option) *pubsub.PubSub {
	t.Helper()
	p, err := pubsub.New(cfg, opts...)
	if err != nil {
		t.Fatalf("pubsub.New: %v", err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// TestPubSubRuntime_Open62541Publishes_GoSubscribes: a go-opcua runtime
// receives the DataSets of the open62541 publisher (DataSetHandler).
func TestPubSubRuntime_Open62541Publishes_GoSubscribes(t *testing.T) {
	psRuntimePeerPublishes(t, psOpen62541)
}

// psRuntimePeerPublishes: a go-opcua runtime receives the DataSets of the
// peer publisher (DataSetHandler).
func psRuntimePeerPublishes(t *testing.T, p *psPeer) {
	p.requireServer(t)
	broker := startMosquitto(t)
	for _, c := range psRuntimeCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			topic := fmt.Sprintf("go-opcua-interop/runtime-sub/%s/%d", c.name, psFresh())
			rec := newPSDataSets()
			opts := []pubsub.Option{pubsub.WithDataSetHandler(rec.handle)}
			if keys := c.keys(t); keys != nil {
				opts = append(opts, pubsub.WithKeySource("InteropGroup", keys))
			}
			pub := psStartPeerPublisher(t, p, c, broker, topic, psRuntimeSubscriber(t, func(url string) *ua.PubSubConfigurationDataType {
				return pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(psRuntimeSubConnection(c, url), psRuntimeReader(c, topic, 0)))
			}, nil, opts...))
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			ds := rec.wait(t, c.vars, values, psReceiveTimeout)
			if ds.DataSetWriterID != psWriterID || ds.MessageType != message.DataSetMessageKeyFrame {
				t.Errorf("DataSet from writer %d type %v", ds.DataSetWriterID, ds.MessageType)
			}
			if ds.PublisherID.String() != fmt.Sprint(psPubID) {
				t.Errorf("PublisherId %v", ds.PublisherID)
			}
		})
	}
}

// TestPubSubRuntime_Open62541Publishes_GoTargetVariables: a go-opcua server
// with WithPubSub writes the DataSet of the open62541 publisher into its
// PubSub.* variables (TargetVariables).
func TestPubSubRuntime_Open62541Publishes_GoTargetVariables(t *testing.T) {
	psRuntimePeerPublishesTargetVariables(t, psOpen62541)
}

// psRuntimePeerPublishesTargetVariables: a go-opcua server with WithPubSub
// writes the DataSet of the peer's publisher into its PubSub.* variables.
func psRuntimePeerPublishesTargetVariables(t *testing.T, p *psPeer) {
	p.requireServer(t)
	c := psRuntimeCase{psLiveCase: psLiveCase{name: "target-variables", vars: psVars}}
	var sub *goPubSubServer
	pub := psStartPeerPublisher(t, p, c, 0, "", func(url string) (*pubsub.PubSub, func()) {
		sub = startGoPubSubServer(t, goPubSubOpts{}, func(ps *pubsub.PubSub, ns uint16) {
			rg := psRuntimeReader(c, "", 0)
			var targets []*ua.FieldTargetDataType
			for _, v := range c.vars {
				targets = append(targets, pubsub.Target(ua.NewStringNodeID(ns, "PubSub."+v.name)))
			}
			pubsub.SetTargetVariables(rg.DataSetReaders[0], targets...)
			mustOK[pubsub.ComponentID](t)(ps.AddConnection(pubsub.AttachReaderGroups(psRuntimeSubConnection(c, url), rg)))
		})
		return sub.srv.PubSub(), sub.close
	})
	values := psValues(c.vars, psFresh())
	writePubSubVars(t, pub.endpoint, c.vars, values)
	waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
}

// ---------------------------------------------------------------------------
// SKS pull with the runtime
// ---------------------------------------------------------------------------

// TestPubSubRuntime_GoSubscriberPullsKeys_Open62541SKS: the open62541
// publisher is the SKS of its SecurityGroup; the go-opcua runtime subscriber
// gets the keys with a pubsub/sks KeySource.
func TestPubSubRuntime_GoSubscriberPullsKeys_Open62541SKS(t *testing.T) {
	requirePubSubServer(t)
	c := psRuntimeCase{psLiveCase: psLiveCase{name: "sks", mode: ua.MessageSecurityModeSignAndEncrypt, policy: security.Aes256CTR(), vars: psVars}}
	// The runtime receives on its port before the publisher is told it
	// (psBindRuntimeUDP); the keys come from the publisher, so they are
	// handed to the runtime once it runs.
	keys := &psLateKeys{policy: c.policy}
	rec := newPSDataSets()
	port := psBindRuntimeUDP(t, psRuntimeSubscriber(t, func(url string) *ua.PubSubConfigurationDataType {
		return pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(psRuntimeSubConnection(c, url), psRuntimeReader(c, "", 0)))
	}, nil, pubsub.WithDataSetHandler(rec.handle), pubsub.WithKeySource(psSKSGroup, keys)))
	pub := startPubSubServer(t, pubsubServerOpts{config: psSKSConfig(c.policy.URI(), psUDPPublisherConfig(c.psLiveCase, port)), secure: true})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ks, err := sks.NewKeySource(ctx, sks.Config{SecurityGroupID: psSKSGroup, Dial: func(context.Context) (*opcua.Client, error) {
		return dialSecureUserClient(t, pub.endpoint, "Basic256Sha256", "SignAndEncrypt", psSKSUser, psSKSPassword), nil
	}})
	if err != nil {
		t.Fatalf("NewKeySource: %v", err)
	}
	t.Cleanup(func() { _ = ks.Close() })
	keys.ks.Store(ks)
	values := psValues(c.vars, psFresh())
	writePubSubVars(t, pub.endpoint, c.vars, values)
	rec.wait(t, c.vars, values, psReceiveTimeout)
}

// psLateKeys is a KeySource whose keys come from ks once it is set; until
// then it has none.
type psLateKeys struct {
	policy security.Policy
	ks     atomic.Pointer[sks.KeySource]
}

func (k *psLateKeys) Policy() security.Policy { return k.policy }

func (k *psLateKeys) CurrentKeys() (*security.Keys, error) {
	if ks := k.ks.Load(); ks != nil {
		return ks.CurrentKeys()
	}
	return nil, security.ErrNoKeys
}

func (k *psLateKeys) KeysForToken(tokenID uint32) (*security.Keys, error) {
	if ks := k.ks.Load(); ks != nil {
		return ks.KeysForToken(tokenID)
	}
	return nil, security.ErrNoKeys
}

// TestPubSubRuntime_Open62541SubscriberPullsKeys_GoSKS: a go-opcua server is
// the SKS and publishes with WithPubSub, secured with the keys of its
// KeyService; the open62541 subscriber pulls the keys from it (sksClient).
func TestPubSubRuntime_Open62541SubscriberPullsKeys_GoSKS(t *testing.T) {
	requirePubSubServer(t)
	c := psRuntimeCase{psLiveCase: psLiveCase{name: "sks", mode: ua.MessageSecurityModeSignAndEncrypt, policy: security.Aes128CTR(), vars: psVars}}
	ks := security.NewKeyService()
	if err := ks.AddSecurityGroup(security.SecurityGroupConfig{SecurityGroupID: psSKSGroup, SecurityPolicyURI: c.policy.URI(),
		KeyLifetime: psSKSKeyLifetime, MaxFutureKeyCount: 2, MaxPastKeyCount: 1}); err != nil {
		t.Fatal(err)
	}
	keys := mustOK[security.KeySource](t)(ks.KeySource(psSKSGroup))
	port := freeUDPPort(t)
	// The publisher is configured once the subscriber container (and its
	// published UDP port) runs: Docker Desktop's UDP port forwarding is
	// unreliable for a flow that started before the port was published.
	pub := startGoPubSubServer(t, goPubSubOpts{secure: true, ks: ks, pubsubOpts: []pubsub.Option{pubsub.WithKeySource(psSKSGroup, keys)}}, nil)
	var sub *pubsubServer
	configure := func() {
		p := pub.srv.PubSub()
		mustOK[pubsub.ComponentID](t)(p.AddPublishedDataSet(psRuntimeDataSet(c.vars, pub.ns, 0)))
		wg := pubsub.Secure(pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond,
			pubsub.DataSetWriter("InteropWriter", psWriterID, "InteropDataSet")), c.mode, psSKSGroup)
		mustOK[pubsub.ComponentID](t)(p.AddConnection(pubsub.AttachWriterGroups(
			pubsub.UDPConnection("InteropPublisher", fmt.Sprintf("opc.udp://127.0.0.1:%d", sub.udpPort(t, port)), uint16(psPubID)), wg)))
	}
	cfg := psSubscriberConfig(c.psLiveCase, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false)
	cfg["securityGroups"] = []jobj{psSecurityGroupJSON(psSKSGroup, c.policy.URI(), 0, nil)}
	cfg["sksClient"] = jobj{
		"endpointUrl":       strings.ReplaceAll(pub.endpoint, "localhost", "host.docker.internal"),
		"securityPolicyUri": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
		"securityMode":      "SignAndEncrypt", "username": psSKSUser, "password": psSKSPassword,
	}
	sub = startPubSubServer(t, pubsubServerOpts{config: cfg, udpPorts: []int{port}, secure: true})
	configure()
	values := psValues(c.vars, psFresh())
	writePubSubVars(t, pub.endpoint, c.vars, values)
	waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
}

// ---------------------------------------------------------------------------
// Keep-alive and MessageReceiveTimeout
// ---------------------------------------------------------------------------

// adapterReaderState reads Status.State of the DataSetReader of an
// open62541 subscriber through its information model (pubsub/remote).
func adapterReaderState(t *testing.T, endpoint string) ua.PubSubState {
	t.Helper()
	c := dialClient(t, endpoint)
	r := remote.New(c)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conns := mustOK[[]remote.Component](t)(r.Connections(ctx))
	for _, conn := range conns {
		for _, rg := range mustOK[[]remote.Component](t)(r.ReaderGroups(ctx, conn.NodeID)) {
			for _, rd := range mustOK[[]remote.Component](t)(r.DataSetReaders(ctx, rg.NodeID)) {
				if rd.Name == "InteropReader" {
					return mustOK[ua.PubSubState](t)(r.State(ctx, rd.NodeID))
				}
			}
		}
	}
	t.Fatalf("no DataSetReader InteropReader in %v", conns)
	return 0
}

func waitState(t *testing.T, what string, want ua.PubSubState, timeout time.Duration, state func() ua.PubSubState) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := state()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: state %v, want %v within %v", what, got, want, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestPubSubRuntime_ReceiveTimeout_Open62541Reader: the open62541 reader
// (MessageReceiveTimeout 1 s) is Operational while the go-opcua runtime
// publishes and goes to Error once the go-opcua WriterGroup is disabled.
func TestPubSubRuntime_ReceiveTimeout_Open62541Reader(t *testing.T) {
	requirePubSubServer(t)
	c := psLiveCase{name: "timeout", vars: psVars}
	port := freeUDPPort(t)
	cfg := psSubscriberConfig(c, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false)
	psReaderOf(cfg)["MessageReceiveTimeout"] = 1000
	sub := startPubSubServer(t, pubsubServerOpts{config: cfg, udpPorts: []int{port}})
	var wgID pubsub.ComponentID
	pub := startGoPubSubServer(t, goPubSubOpts{}, func(p *pubsub.PubSub, ns uint16) {
		mustOK[pubsub.ComponentID](t)(p.AddPublishedDataSet(psRuntimeDataSet(c.vars, ns, 0)))
		conn := mustOK[pubsub.ComponentID](t)(p.AddConnection(pubsub.AttachWriterGroups(
			pubsub.UDPConnection("InteropPublisher", fmt.Sprintf("opc.udp://127.0.0.1:%d", sub.udpPort(t, port)), uint16(psPubID)),
			pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, pubsub.DataSetWriter("InteropWriter", psWriterID, "InteropDataSet")))))
		var ok bool
		wgID, ok = p.Lookup(pubsub.KindWriterGroup, conn, "InteropWriterGroup")
		if !ok {
			t.Fatal("no writer group")
		}
	})
	values := psValues(c.vars, psFresh())
	writePubSubVars(t, pub.endpoint, c.vars, values)
	waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
	waitState(t, "open62541 reader while data arrives", ua.PubSubStateOperational, 5*time.Second, func() ua.PubSubState { return adapterReaderState(t, sub.endpoint) })

	if err := pub.srv.PubSub().Disable(wgID); err != nil {
		t.Fatalf("Disable the WriterGroup: %v", err)
	}
	waitState(t, "open62541 reader after the publisher stopped", ua.PubSubStateError, 10*time.Second, func() ua.PubSubState { return adapterReaderState(t, sub.endpoint) })
}

// psReaderOf returns the DataSetReader of a psSubscriberConfig document.
func psReaderOf(cfg jobj) jobj {
	conn := cfg["configuration"].(jobj)["Connections"].([]jobj)[0]
	return conn["ReaderGroups"].([]jobj)[0]["DataSetReaders"].([]jobj)[0]
}

// TestPubSubRuntime_ReceiveTimeout_GoReader: the go-opcua reader
// (MessageReceiveTimeout 1 s) is Operational while the open62541 publisher
// publishes, goes to Error when its WriterGroup is disabled (through the
// open62541 information model with pubsub/remote) and recovers when it is
// enabled again.
func TestPubSubRuntime_ReceiveTimeout_GoReader(t *testing.T) {
	requirePubSubServer(t)
	c := psRuntimeCase{psLiveCase: psLiveCase{name: "timeout", vars: psVars}}
	rec := newPSDataSets()
	var p *pubsub.PubSub
	pub := psStartAdapterPublisher(t, c, 0, "", psRuntimeSubscriber(t, func(url string) *ua.PubSubConfigurationDataType {
		return pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(psRuntimeSubConnection(c, url), psRuntimeReader(c, "", time.Second)))
	}, &p, pubsub.WithDataSetHandler(rec.handle)))
	conn, _ := p.Lookup(pubsub.KindConnection, pubsub.Root, "InteropSubscriber")
	rg, _ := p.Lookup(pubsub.KindReaderGroup, conn, "InteropReaderGroup")
	reader, ok := p.Lookup(pubsub.KindDataSetReader, rg, "InteropReader")
	if !ok {
		t.Fatal("no reader")
	}
	state := func() ua.PubSubState { return mustOK[ua.PubSubState](t)(p.State(reader)) }

	values := psValues(c.vars, psFresh())
	writePubSubVars(t, pub.endpoint, c.vars, values)
	rec.wait(t, c.vars, values, psReceiveTimeout)
	waitState(t, "go-opcua reader while data arrives", ua.PubSubStateOperational, 5*time.Second, state)

	cl := dialClient(t, pub.endpoint)
	r := remote.New(cl)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wg := adapterWriterGroup(t, ctx, r)
	if err := r.Disable(ctx, wg); err != nil {
		t.Fatalf("Disable the open62541 WriterGroup: %v", err)
	}
	waitState(t, "go-opcua reader after the publisher stopped", ua.PubSubStateError, 10*time.Second, state)
	if st, err := p.Status(reader); err != nil || st.Counters.Timeouts == 0 {
		t.Errorf("reader status %+v (%v): no timeout counted", st, err)
	}

	if err := r.Enable(ctx, wg); err != nil {
		t.Fatalf("Enable the open62541 WriterGroup: %v", err)
	}
	waitState(t, "go-opcua reader after the publisher resumed", ua.PubSubStateOperational, 10*time.Second, state)
}

// adapterWriterGroup finds InteropWriterGroup in the open62541 information model.
func adapterWriterGroup(t *testing.T, ctx context.Context, r *remote.Client) *ua.NodeID {
	t.Helper()
	for _, conn := range mustOK[[]remote.Component](t)(r.Connections(ctx)) {
		for _, wg := range mustOK[[]remote.Component](t)(r.WriterGroups(ctx, conn.NodeID)) {
			if wg.Name == "InteropWriterGroup" {
				return wg.NodeID
			}
		}
	}
	t.Fatal("no InteropWriterGroup in the open62541 information model")
	return nil
}

// TestPubSubRuntime_KeepAlive_GoPublishes: a go-opcua WriterGroup whose
// writer has no DataSet sends only keep-alive messages (KeepAliveTime
// 200 ms). The open62541 reader of that writer decodes them, matches them to
// itself (PublisherId, WriterGroupId, DataSetWriterId) and leaves
// PreOperational for Operational, which it does only for a message of its
// writer.
//
// open62541 1.5.9 then discards the KeepAlive DataSetMessage ("Only
// keyframes are supported") and does not arm or refresh its
// MessageReceiveTimeout with it: whether keep-alive messages keep an idle
// reader out of Error cannot be observed on this peer.
func TestPubSubRuntime_KeepAlive_GoPublishes(t *testing.T) {
	requirePubSubServer(t)
	c := psLiveCase{name: "keepalive", vars: psVars}
	port := freeUDPPort(t)
	cfg := psSubscriberConfig(c, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false)
	psReaderOf(cfg)["MessageReceiveTimeout"] = 1000
	sub := startPubSubServer(t, pubsubServerOpts{config: cfg, udpPorts: []int{port}})
	if got := adapterReaderState(t, sub.endpoint); got != ua.PubSubStatePreOperational {
		t.Fatalf("open62541 reader before any message: %v, want PreOperational", got)
	}
	var wgID pubsub.ComponentID
	pub := startGoPubSubServer(t, goPubSubOpts{}, func(p *pubsub.PubSub, ns uint16) {
		wg := pubsub.WriterGroup("InteropWriterGroup", psWriterGroupID, 100*time.Millisecond, pubsub.DataSetWriter("InteropWriter", psWriterID, ""))
		wg.KeepAliveTime = 200
		conn := mustOK[pubsub.ComponentID](t)(p.AddConnection(pubsub.AttachWriterGroups(
			pubsub.UDPConnection("InteropPublisher", fmt.Sprintf("opc.udp://127.0.0.1:%d", sub.udpPort(t, port)), uint16(psPubID)), wg)))
		wgID, _ = p.Lookup(pubsub.KindWriterGroup, conn, "InteropWriterGroup")
	})
	waitState(t, "open62541 reader receiving keep-alive messages", ua.PubSubStateOperational, 10*time.Second,
		func() ua.PubSubState { return adapterReaderState(t, sub.endpoint) })
	st := mustOK[pubsub.Status](t)(pub.srv.PubSub().Status(wgID))
	if st.Counters.KeepAlivesSent == 0 || st.Counters.DataSetMessagesSent != 0 {
		t.Fatalf("the go-opcua WriterGroup sent %d keep-alive and %d data messages, want only keep-alive messages",
			st.Counters.KeepAlivesSent, st.Counters.DataSetMessagesSent)
	}
}
