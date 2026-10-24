// SPDX-License-Identifier: MIT

package conformance

import (
	"context"
	"crypto/rand"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/id"
	iamqp "github.com/otfabric/go-opcua/internal/amqp"
	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/amqpbroker"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// PubSub over the broker transports of v1.9.0, end to end between servers:
// MQTT 5.0 (content type, UAMessageType, QoS 2, connection properties,
// BestAvailable) and AMQP 1.0 (subject, content type, open frame), with
// the UADP and the JSON mapping and with SignAndEncrypt, the publisher
// configured through the PubSub methods of its information model
// (pubsub/remote), the subscribers in code: a server writing target
// variables and a standalone runtime that learns the DataSetMetaData from
// the metadata queues.

// psRing returns a KeyRing of SecurityGroup g with one random Aes256-CTR key.
func psRing(t *testing.T, g string) *security.KeyRing {
	t.Helper()
	policy := security.Aes256CTR()
	ring := security.NewKeyRing(g, policy)
	key := make([]byte, policy.KeyLength())
	_, err := rand.Read(key)
	require.NoError(t, err)
	require.NoError(t, ring.SetKeys(policy.URI(), 1, [][]byte{key}, time.Hour, time.Hour))
	return ring
}

func psAMQPBroker(t *testing.T, opts amqpbroker.Options) *amqpbroker.Broker {
	t.Helper()
	b := amqpbroker.New(opts)
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	return b
}

// psWire records what the brokers saw of the messages and connections.
type psWire struct {
	mu       sync.Mutex
	mqtt     map[string]psSeen // by topic
	amqp     map[string]psSeen // by address
	connects []imqtt.Connect
	opens    []iamqp.Open
}

type psSeen struct {
	ct, mt string // content type; UAMessageType (MQTT) or subject (AMQP)
	qos    byte
}

func newPSWire() *psWire {
	return &psWire{mqtt: map[string]psSeen{}, amqp: map[string]psSeen{}}
}

func (w *psWire) onPublish(_ string, p *imqtt.Publish) {
	s := psSeen{qos: p.QoS}
	if p.Props.ContentType != nil {
		s.ct = *p.Props.ContentType
	}
	for _, u := range p.Props.User {
		if u.Key == transport.UAMessageTypeProperty {
			s.mt = u.Value
		}
	}
	w.mu.Lock()
	w.mqtt[p.Topic] = s
	w.mu.Unlock()
}

func (w *psWire) onConnect(p *imqtt.Connect) {
	w.mu.Lock()
	w.connects = append(w.connects, *p)
	w.mu.Unlock()
}

func (w *psWire) onMessage(address string, m *iamqp.Message, _ bool) {
	s := psSeen{}
	if m.Properties != nil {
		s.ct, s.mt = string(m.Properties.ContentType), m.Properties.Subject
	}
	w.mu.Lock()
	w.amqp[address] = s
	w.mu.Unlock()
}

func (w *psWire) onOpen(o *iamqp.Open) {
	w.mu.Lock()
	w.opens = append(w.opens, *o)
	w.mu.Unlock()
}

// connect returns the last CONNECT of a client id.
func (w *psWire) connect(clientID string) (imqtt.Connect, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := len(w.connects) - 1; i >= 0; i-- {
		if w.connects[i].ClientID == clientID {
			return w.connects[i], true
		}
	}
	return imqtt.Connect{}, false
}

// psBrokerRoute is one writer group of the broker test and the readers of
// its data.
type psBrokerRoute struct {
	name    string
	conn    string // connection name
	amqp    bool
	mapping pubsub.MessageMapping
	mode    ua.MessageSecurityMode
	qos     ua.BrokerTransportQoS

	gid, wid     uint16
	data, meta   string
	i32, str     *server.Node // published variables
	ti32, tstr   *server.Node // target variables
	md           *ua.DataSetMetaDataType
	standaloneID pubsub.ComponentID
}

func (r *psBrokerRoute) readerName() string { return "r-" + r.name }

func (r *psBrokerRoute) contentType() string {
	if r.mapping == pubsub.MappingJSON {
		return transport.ContentTypeJSON
	}
	return transport.ContentTypeUADP
}

// psBrokerConn returns the connection of the broker test of a name, for
// the publisher (publisherID set) or a subscriber.
func psBrokerConn(name string, amqpURL, mqttURL string, mapping pubsub.MessageMapping, publisherID any, version string) *ua.PubSubConnectionDataType {
	if amqpURL != "" {
		return pubsub.AMQPConnection(name, amqpURL, publisherID, mapping)
	}
	return pubsub.SetMQTTVersion(pubsub.MQTTConnection(name, mqttURL, publisherID, mapping), version)
}

// TestPubSub_BrokerTransportsServerToServer publishes variables of a server
// over MQTT 5.0 and AMQP 1.0, with the UADP and the JSON mapping and
// SignAndEncrypt, configured by an OPC UA client with the PubSub methods
// of the server (AddConnection with the TransportProfileUri and the
// connection properties, AddPublishedDataItems, AddWriterGroup,
// AddDataSetWriter). Another server writes them to target variables; a
// standalone runtime without DataSetMetaData learns it from the metadata
// queues. The brokers see the content types, UAMessageTypes and subjects
// of Part 14 §7.3.4.8 and Annex B.3, QoS 2 for ExactlyOnce, and the
// connection properties in the CONNECT and the open frame.
func TestPubSub_BrokerTransportsServerToServer(t *testing.T) {
	parallel(t)
	wire := newPSWire()
	mb := mqttbroker.New(mqttbroker.Options{OnPublish: wire.onPublish, OnConnect: wire.onConnect})
	require.NoError(t, mb.Start())
	t.Cleanup(mb.Close)
	ab := psAMQPBroker(t, amqpbroker.Options{OnMessage: wire.onMessage, OnOpen: wire.onOpen})
	ring := psRing(t, "sg")

	pubSrv, pubURL := newServer(t, server.WithPubSub(nil, pubsub.WithKeySource("sg", ring)))
	subSrv, subURL := newServer(t, server.WithPubSub(nil, pubsub.WithKeySource("sg", ring)))
	pubNS := server.NewNodeNameSpace(pubSrv, "urn:pubsub:brokers:pub")
	subNS := server.NewNodeNameSpace(subSrv, "urn:pubsub:brokers:sub")
	ctx := context.Background()

	routes := []*psBrokerRoute{
		{name: "mqtt5-uadp", conn: "mqtt5-uadp", mapping: pubsub.MappingUADP, qos: ua.BrokerTransportQoSExactlyOnce},
		{name: "mqtt5-uadp-sec", conn: "mqtt5-uadp", mapping: pubsub.MappingUADP, mode: ua.MessageSecurityModeSignAndEncrypt, qos: ua.BrokerTransportQoSAtLeastOnce},
		{name: "mqtt5-json", conn: "mqtt5-json", mapping: pubsub.MappingJSON, qos: ua.BrokerTransportQoSExactlyOnce},
		{name: "amqp-uadp", conn: "amqp-uadp", amqp: true, mapping: pubsub.MappingUADP, qos: ua.BrokerTransportQoSAtLeastOnce},
		{name: "amqp-uadp-sec", conn: "amqp-uadp", amqp: true, mapping: pubsub.MappingUADP, mode: ua.MessageSecurityModeSignAndEncrypt, qos: ua.BrokerTransportQoSAtLeastOnce},
		{name: "amqp-json", conn: "amqp-json", amqp: true, mapping: pubsub.MappingJSON, qos: ua.BrokerTransportQoSAtLeastOnce},
	}
	urls := func(r *psBrokerRoute) (string, string) {
		if r.amqp {
			return ab.URL(), ""
		}
		return "", mb.URL()
	}
	for i, r := range routes {
		r.gid, r.wid = uint16(i+1), uint16(10+i)
		if r.amqp {
			// Data to a topic, which every subscriber gets; metadata to a
			// queue, which only the standalone runtime consumes.
			r.data, r.meta = "/exchanges/amq.topic/conf."+r.name, "/queues/conf."+r.name+".meta"
		} else {
			r.data, r.meta = "conf5/"+r.name, "conf5/"+r.name+"/meta"
		}
		r.i32 = pubNS.AddNewVariableStringNode(r.name+".i32", int32(1))
		r.str = pubNS.AddNewVariableStringNode(r.name+".str", "first")
		r.ti32 = subNS.AddNewVariableStringNode(r.name+".i32", int32(0))
		r.tstr = subNS.AddNewVariableStringNode(r.name+".str", "")
	}

	// The publisher, configured through its information model.
	pc := newClient(t, pubURL)
	rc := remote.New(pc)
	pubConns := map[string]*ua.NodeID{}
	for _, r := range routes {
		if pubConns[r.conn] != nil {
			continue
		}
		au, mu := urls(r)
		c := psBrokerConn(r.conn, au, mu, r.mapping, uint16(77), pubsub.MQTTVersion5)
		if r.amqp {
			pubsub.SetConnectionProperty(c, "connection-max-frame-size", uint32(32768))
		} else {
			pubsub.SetConnectionProperty(c, "connection-ClientID", "pub-"+r.conn)
			pubsub.SetConnectionProperty(c, "connection-Receive Maximum", uint16(10))
			pubsub.SetConnectionProperty(c, "connection-Session Expiry Interval", uint32(30))
		}
		n, err := rc.AddConnection(ctx, c)
		require.NoError(t, err, r.conn)
		pubConns[r.conn] = n
	}
	for _, r := range routes {
		res, err := rc.AddPublishedDataItems(ctx, r.name, []string{"i32", "str"}, nil, []*ua.PublishedVariableDataType{
			{PublishedVariable: r.i32.ID(), AttributeID: ua.AttributeIDValue},
			{PublishedVariable: r.str.ID(), AttributeID: ua.AttributeIDValue},
		})
		require.NoError(t, err, r.name)
		require.Equal(t, []ua.StatusCode{ua.StatusOK, ua.StatusOK}, res.AddResults)
		v, err := rc.Property(ctx, res.DataSetNodeID, "DataSetMetaData")
		require.NoError(t, err)
		eo, ok := v.Value().(*ua.ExtensionObject)
		require.True(t, ok, "DataSetMetaData is %T", v.Value())
		r.md = eo.Value.(*ua.DataSetMetaDataType)
		require.Len(t, r.md.Fields, 2)

		var wg *ua.WriterGroupDataType
		if r.mapping == pubsub.MappingJSON {
			wg = pubsub.JSONWriterGroup(r.name, r.gid, psInterval, r.data)
		} else {
			wg = pubsub.WriterGroup(r.name, r.gid, psInterval)
		}
		if r.mode != ua.MessageSecurityModeNone {
			pubsub.Secure(wg, r.mode, "sg")
		}
		gn, err := rc.AddWriterGroup(ctx, pubConns[r.conn], wg)
		require.NoError(t, err, r.name)
		w := pubsub.SetWriterQueue(pubsub.DataSetWriter("w", r.wid, r.name), r.data, r.meta)
		w.TransportSettings.Value.(*ua.BrokerDataSetWriterTransportDataType).RequestedDeliveryGuarantee = r.qos
		_, err = rc.AddDataSetWriter(ctx, gn, w)
		require.NoError(t, err, r.name)
	}

	// The subscriber server: readers with the DataSetMetaData and target
	// variables, MQTT with BestAvailable.
	sub := subSrv.PubSub()
	subConns := map[string]pubsub.ComponentID{}
	for _, r := range routes {
		if _, ok := subConns[r.conn]; !ok {
			au, mu := urls(r)
			cid, err := sub.AddConnection(psBrokerConn(r.conn, au, mu, r.mapping, nil, pubsub.MQTTVersionBestAvailable))
			require.NoError(t, err)
			subConns[r.conn] = cid
		}
		gid := r.gid
		if r.mapping == pubsub.MappingJSON {
			gid = 0 // JSON NetworkMessages carry the group by name only
		}
		rd := pubsub.SetTargetVariables(pubsub.DataSetReader(r.readerName(), uint16(77), gid, r.wid, r.md),
			pubsub.Target(r.ti32.ID()), pubsub.Target(r.tstr.ID()))
		pubsub.SetReaderQueue(rd, r.data, "")
		rg := pubsub.ReaderGroup(r.name, rd)
		if r.mode != ua.MessageSecurityModeNone {
			pubsub.Secure(rg, r.mode, "sg")
		}
		_, err := sub.AddReaderGroup(subConns[r.conn], rg)
		require.NoError(t, err)
	}

	// The standalone subscriber: no DataSetMetaData, MQTT 5.0.
	saConns := map[string]*ua.PubSubConnectionDataType{}
	var saList []*ua.PubSubConnectionDataType
	for _, r := range routes {
		c := saConns[r.conn]
		if c == nil {
			au, mu := urls(r)
			c = psBrokerConn(r.conn, au, mu, r.mapping, nil, pubsub.MQTTVersion5)
			saConns[r.conn] = c
			saList = append(saList, c)
		}
		// WriterGroupId 0: a UADP metadata announcement carries none.
		rd := pubsub.SetReaderQueue(pubsub.DataSetReader(r.readerName(), uint16(77), 0, r.wid, nil), r.data, r.meta)
		rg := pubsub.ReaderGroup(r.name, rd)
		if r.mode != ua.MessageSecurityModeNone {
			pubsub.Secure(rg, r.mode, "sg")
		}
		pubsub.AttachReaderGroups(c, rg)
	}
	rec := newPSRecorder()
	sa := psRuntime(t, pubsub.NewConfiguration(nil, saList...), pubsub.WithDataSetHandler(rec.handle), pubsub.WithKeySource("sg", ring))
	for _, r := range routes {
		cid := psComponent(t, sa, pubsub.KindConnection, r.conn)
		gid, ok := sa.Lookup(pubsub.KindReaderGroup, cid, r.name)
		require.True(t, ok)
		r.standaloneID, ok = sa.Lookup(pubsub.KindDataSetReader, gid, r.readerName())
		require.True(t, ok)
	}

	sc := newClient(t, subURL)
	expect := func(t *testing.T, r *psBrokerRoute, i32 int32, str string) {
		t.Helper()
		eventually(t, func() bool {
			a, err1 := sc.Node(r.ti32.ID()).Value(ctx)
			b, err2 := sc.Node(r.tstr.ID()).Value(ctx)
			return err1 == nil && err2 == nil && a != nil && b != nil && a.Value() == i32 && b.Value() == str
		}, r.name+": the target variables take the published values")
		rec.waitFor(t, r.readerName(), func(d *pubsub.ReceivedDataSet) bool {
			fi, fs := d.Field("i32"), d.Field("str")
			return fi != nil && fs != nil && fi.Value != nil && fs.Value != nil && fi.Value.Value() == i32 && fs.Value.Value() == str
		})
	}
	for _, r := range routes {
		t.Run(r.name+"/initial", func(t *testing.T) { expect(t, r, 1, "first") })
	}
	for _, r := range routes {
		require.NoError(t, r.i32.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(int32(-42))))
		require.NoError(t, r.str.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue("zweite ✓")))
	}
	for _, r := range routes {
		t.Run(r.name+"/changed", func(t *testing.T) { expect(t, r, -42, "zweite ✓") })
	}

	for _, r := range routes {
		t.Run(r.name+"/wire", func(t *testing.T) {
			// The standalone reader learned the DataSetMetaData from the
			// metadata queue.
			cfg, err := sa.DataSetReaderConfig(r.standaloneID)
			require.NoError(t, err)
			require.NotNil(t, cfg.DataSetMetaData)
			var names []string
			for _, f := range cfg.DataSetMetaData.Fields {
				names = append(names, f.Name)
			}
			require.Equal(t, []string{"i32", "str"}, names)

			wire.mu.Lock()
			defer wire.mu.Unlock()
			if r.amqp {
				require.Equal(t, psSeen{ct: r.contentType(), mt: transport.MessageTypeData}, wire.amqp[r.data])
				require.Equal(t, psSeen{ct: r.contentType(), mt: transport.MessageTypeMetaData}, wire.amqp[r.meta])
				return
			}
			qos := byte(1)
			if r.qos == ua.BrokerTransportQoSExactlyOnce {
				qos = 2
			}
			require.Equal(t, psSeen{ct: r.contentType(), mt: transport.MessageTypeData, qos: qos}, wire.mqtt[r.data])
			require.Equal(t, transport.MessageTypeMetaData, wire.mqtt[r.meta].mt)
			require.Equal(t, r.contentType(), wire.mqtt[r.meta].ct)
		})
	}

	// The connection properties reached the brokers.
	for _, name := range []string{"mqtt5-uadp", "mqtt5-json"} {
		c, ok := wire.connect("pub-" + name)
		require.True(t, ok, "CONNECT of pub-%s", name)
		require.Equal(t, imqtt.Version5, c.ProtocolLevel)
		require.NotNil(t, c.Props.ReceiveMaximum)
		require.Equal(t, uint16(10), *c.Props.ReceiveMaximum)
		require.NotNil(t, c.Props.SessionExpiry)
		require.Equal(t, uint32(30), *c.Props.SessionExpiry)
	}
	wire.mu.Lock()
	frameSizes := map[uint32]bool{}
	for _, o := range wire.opens {
		frameSizes[o.MaxFrameSize] = true
	}
	wire.mu.Unlock()
	require.True(t, frameSizes[32768], "an open frame with max-frame-size 32768: %v", frameSizes)

	// The publisher's configuration as the server shows it keeps the
	// TransportProfileUris.
	conns, err := rc.Connections(ctx)
	require.NoError(t, err)
	require.Len(t, conns, 4)
	for _, c := range conns {
		v, err := rc.Property(ctx, c.NodeID, "TransportProfileUri")
		require.NoError(t, err)
		want := map[string]string{"mqtt5-uadp": transport.ProfileMQTTUADP, "mqtt5-json": transport.ProfileMQTTJSON, "amqp-uadp": transport.ProfileAMQPUADP, "amqp-json": transport.ProfileAMQPJSON}[c.Name]
		require.Equal(t, want, v.Value(), c.Name)
	}

	for _, rt := range []*pubsub.PubSub{sub, sa} {
		for _, c := range rt.Components() {
			if c.Kind != pubsub.KindDataSetReader {
				continue
			}
			st, err := rt.Status(c.ID)
			require.NoError(t, err)
			require.Equal(t, ua.PubSubStateOperational, st.State, c.Name)
			require.Zero(t, st.Counters.DecodeErrors, c.Name)
			require.Zero(t, st.Counters.TargetWriteErrors, c.Name)
		}
	}
}

// TestPubSub_RemoteConnectionValidation adds connections with invalid
// transport settings through the PubSub methods: they are refused and leave
// nothing behind. The server lists the transport profiles it supports,
// and an MQTT connection with MqttVersion BestAvailable connects to a
// broker without MQTT 5.0 with 3.1.1 and publishes.
func TestPubSub_RemoteConnectionValidation(t *testing.T) {
	parallel(t)
	wire := newPSWire()
	mb := mqttbroker.New(mqttbroker.Options{DisableV5: true, OnConnect: wire.onConnect})
	require.NoError(t, mb.Start())
	t.Cleanup(mb.Close)
	srv, url := newServer(t, server.WithPubSub(nil))
	ns := server.NewNodeNameSpace(srv, "urn:pubsub:remote-validation")
	c := newClient(t, url)
	rc := remote.New(c)
	ctx := context.Background()

	v, err := c.Node(ua.NewNumericNodeID(0, id.PublishSubscribeSupportedTransportProfiles)).Value(ctx)
	require.NoError(t, err)
	profiles, ok := v.Value().([]string)
	require.True(t, ok, "%T", v.Value())
	for _, p := range []string{transport.ProfileUDPUADP, transport.ProfileMQTTUADP, transport.ProfileMQTTJSON, transport.ProfileAMQPUADP, transport.ProfileAMQPJSON} {
		require.True(t, slices.Contains(profiles, p), p)
	}

	for _, bad := range []struct {
		name string
		conn *ua.PubSubConnectionDataType
	}{
		{"mqtt-version", pubsub.SetMQTTVersion(pubsub.MQTTConnection("bad", mb.URL(), uint16(1), pubsub.MappingUADP), "4.0")},
		{"receive-maximum-0", pubsub.SetConnectionProperty(pubsub.MQTTConnection("bad", mb.URL(), uint16(1), pubsub.MappingUADP), "connection-Receive Maximum", uint16(0))},
		{"request-problem-info", pubsub.SetConnectionProperty(pubsub.MQTTConnection("bad", mb.URL(), uint16(1), pubsub.MappingJSON), "connection-Request Problem Information", "maybe")},
		{"ethernet-without-interface", pubsub.EthernetConnection("bad", "opc.eth://01-00-5e-00-00-01", "", uint16(1))},
		{"profile-address-mismatch", func() *ua.PubSubConnectionDataType {
			c := pubsub.AMQPConnection("bad", "amqp://127.0.0.1:1", uint16(1), pubsub.MappingUADP)
			c.TransportProfileURI = transport.ProfileMQTTUADP
			return c
		}()},
		{"unknown-profile", func() *ua.PubSubConnectionDataType {
			c := pubsub.UDPConnection("bad", "opc.udp://127.0.0.1:4840", uint16(1))
			c.TransportProfileURI = "http://opcfoundation.org/UA-Profile/Transport/pubsub-carrier-pigeon"
			return c
		}()},
	} {
		t.Run(bad.name, func(t *testing.T) {
			_, err := rc.AddConnection(ctx, bad.conn)
			require.Error(t, err)
			conns, err := rc.Connections(ctx)
			require.NoError(t, err)
			require.Empty(t, conns)
			require.Empty(t, srv.PubSub().Components())
		})
	}

	// BestAvailable against a broker that speaks only 3.1.1.
	n := ns.AddNewVariableStringNode("fallback.i32", int32(5))
	pds := pubsub.PublishedDataItems("fallback", pubsub.Var("i32", n.ID(), ua.TypeIDInt32))
	conn := pubsub.SetMQTTVersion(pubsub.MQTTConnection("best", mb.URL(), uint16(9), pubsub.MappingJSON), pubsub.MQTTVersionBestAvailable)
	pubsub.SetConnectionProperty(conn, "connection-ClientID", "best-available")
	cn, err := rc.AddConnection(ctx, conn)
	require.NoError(t, err)
	_, err = srv.PubSub().AddPublishedDataSet(pds)
	require.NoError(t, err)
	gn, err := rc.AddWriterGroup(ctx, cn, pubsub.JSONWriterGroup("wg", 1, psInterval, "fallback/data"))
	require.NoError(t, err)
	_, err = rc.AddDataSetWriter(ctx, gn, pubsub.SetWriterQueue(pubsub.DataSetWriter("w", 1, "fallback"), "fallback/data", ""))
	require.NoError(t, err)

	rec := newPSRecorder()
	psRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(
		pubsub.SetMQTTVersion(pubsub.MQTTConnection("sub", mb.URL(), nil, pubsub.MappingJSON), pubsub.MQTTVersion311),
		pubsub.ReaderGroup("rg", pubsub.SetReaderQueue(pubsub.DataSetReader("r", uint16(9), 0, 1, pubsub.DataSetMetaDataOf(pds)), "fallback/data", "")))),
		pubsub.WithDataSetHandler(rec.handle))
	rec.waitFor(t, "r", func(d *pubsub.ReceivedDataSet) bool {
		f := d.Field("i32")
		return f != nil && f.Value != nil && f.Value.Value() == int32(5)
	})
	wire.mu.Lock()
	var levels []byte
	for _, cc := range wire.connects {
		if cc.ClientID == "best-available" {
			levels = append(levels, cc.ProtocolLevel)
		}
	}
	wire.mu.Unlock()
	require.GreaterOrEqual(t, len(levels), 2, "%v", levels)
	require.Equal(t, imqtt.Version5, levels[0], "BestAvailable tries 5.0 first")
	require.Equal(t, imqtt.Version311, levels[len(levels)-1], "and falls back to 3.1.1")
	st, err := rc.State(ctx, cn)
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStateOperational, st)
}
