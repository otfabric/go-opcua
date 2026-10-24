// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func validCfg() *ua.PubSubConfigurationDataType {
	return NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachReaderGroups(AttachWriterGroups(UDPConnection("c", "opc.udp://239.0.0.1:4840", uint16(1)),
			WriterGroup("wg", 1, time.Second, DataSetWriter("w", 1, "pds"))),
			ReaderGroup("rg", SetTargetVariables(DataSetReader("r", uint16(1), 1, 1, MetaData("x", Field{Name: "a"})), Target(nodeA)))))
}

func TestValidate(t *testing.T) {
	t.Parallel()
	require.NoError(t, Validate(validCfg()))
	type mod func(c *ua.PubSubConfigurationDataType)
	conn := func(c *ua.PubSubConfigurationDataType) *ua.PubSubConnectionDataType { return c.Connections[0] }
	wg := func(c *ua.PubSubConfigurationDataType) *ua.WriterGroupDataType { return conn(c).WriterGroups[0] }
	w := func(c *ua.PubSubConfigurationDataType) *ua.DataSetWriterDataType { return wg(c).DataSetWriters[0] }
	rg := func(c *ua.PubSubConfigurationDataType) *ua.ReaderGroupDataType { return conn(c).ReaderGroups[0] }
	r := func(c *ua.PubSubConfigurationDataType) *ua.DataSetReaderDataType { return rg(c).DataSetReaders[0] }
	items := func(c *ua.PubSubConfigurationDataType) *ua.PublishedDataItemsDataType {
		return c.PublishedDataSets[0].DataSetSource.Value.(*ua.PublishedDataItemsDataType)
	}
	cases := map[string]mod{
		"nil pds":  func(c *ua.PubSubConfigurationDataType) { c.PublishedDataSets[0] = nil },
		"pds name": func(c *ua.PubSubConfigurationDataType) { c.PublishedDataSets[0].Name = "" },
		"pds dup": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets = append(c.PublishedDataSets, testPDS("pds"))
		},
		"pds no var": func(c *ua.PubSubConfigurationDataType) { items(c).PublishedData[0].PublishedVariable = nil },
		"pds attr":   func(c *ua.PubSubConfigurationDataType) { items(c).PublishedData[0].AttributeID = 0 },
		"pds range":  func(c *ua.PubSubConfigurationDataType) { items(c).PublishedData[0].IndexRange = "x" },
		"pds md count": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0].DataSetMetaData.Fields = c.PublishedDataSets[0].DataSetMetaData.Fields[:1]
		},
		"pds md dup": func(c *ua.PubSubConfigurationDataType) { c.PublishedDataSets[0].DataSetMetaData.Fields[1].Name = "a" },
		"pds md nil": func(c *ua.PubSubConfigurationDataType) { c.PublishedDataSets[0].DataSetMetaData.Fields[1] = nil },
		"pds source": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0].DataSetSource = ua.NewExtensionObject(&ua.KeyValuePair{})
		},
		"pds empty with md": func(c *ua.PubSubConfigurationDataType) { c.PublishedDataSets[0].DataSetSource = nil },
		"events no notifier": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0].DataSetSource = ua.NewExtensionObject(&ua.PublishedEventsDataType{})
		},
		"events no fields": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0].DataSetSource = ua.NewExtensionObject(&ua.PublishedEventsDataType{EventNotifier: nodeA})
		},
		"events md": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0].DataSetSource = ua.NewExtensionObject(&ua.PublishedEventsDataType{EventNotifier: nodeA, SelectedFields: []*ua.SimpleAttributeOperand{{}}})
		},
		"nil conn":  func(c *ua.PubSubConfigurationDataType) { c.Connections[0] = nil },
		"conn name": func(c *ua.PubSubConfigurationDataType) { conn(c).Name = "" },
		"conn dup": func(c *ua.PubSubConfigurationDataType) {
			c.Connections = append(c.Connections, UDPConnection("c", "opc.udp://x:1", nil))
		},
		"conn pubid type": func(c *ua.PubSubConfigurationDataType) { conn(c).PublisherID = ua.MustVariant(1.5) },
		"conn no pubid":   func(c *ua.PubSubConfigurationDataType) { conn(c).PublisherID = nil },
		"profile empty":   func(c *ua.PubSubConfigurationDataType) { conn(c).TransportProfileURI = "" },
		"profile eth":     func(c *ua.PubSubConfigurationDataType) { conn(c).TransportProfileURI = transport.ProfileEthUADP },
		"profile unknown": func(c *ua.PubSubConfigurationDataType) { conn(c).TransportProfileURI = "x" },
		"eth no iface": func(c *ua.PubSubConfigurationDataType) {
			conn(c).TransportProfileURI = transport.ProfileEthUADP
			conn(c).Address = ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "opc.eth://01-00-5e-00-00-01"})
		},
		"eth bad url": func(c *ua.PubSubConfigurationDataType) {
			conn(c).TransportProfileURI = transport.ProfileEthUADP
			conn(c).Address = ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "opc.eth://01-00-5e-00-00-01:5000", NetworkInterface: "eth0"})
		},
		"eth json": func(c *ua.PubSubConfigurationDataType) {
			*conn(c) = *AttachWriterGroups(EthernetConnection("c", "opc.eth://01-00-5e-00-00-01", "eth0", uint16(1)),
				JSONWriterGroup("wg", 1, time.Second, "", DataSetWriter("w", 1, "pds")))
		},
		"no address": func(c *ua.PubSubConfigurationDataType) { conn(c).Address = nil },
		"no scheme": func(c *ua.PubSubConfigurationDataType) {
			conn(c).Address = ua.NewExtensionObject(&ua.NetworkAddressURLDataType{URL: "noscheme"})
		},
		"nil wg":          func(c *ua.PubSubConfigurationDataType) { conn(c).WriterGroups[0] = nil },
		"wg name":         func(c *ua.PubSubConfigurationDataType) { wg(c).Name = "" },
		"wg id":           func(c *ua.PubSubConfigurationDataType) { wg(c).WriterGroupID = 0 },
		"wg interval":     func(c *ua.PubSubConfigurationDataType) { wg(c).PublishingInterval = 0 },
		"wg interval inf": func(c *ua.PubSubConfigurationDataType) { wg(c).PublishingInterval = math.Inf(1) },
		"wg keepalive":    func(c *ua.PubSubConfigurationDataType) { wg(c).KeepAliveTime = -1 },
		"wg dup name": func(c *ua.PubSubConfigurationDataType) {
			conn(c).WriterGroups = append(conn(c).WriterGroups, WriterGroup("wg", 2, time.Second))
		},
		"wg dup id": func(c *ua.PubSubConfigurationDataType) {
			conn(c).WriterGroups = append(conn(c).WriterGroups, WriterGroup("wg2", 1, time.Second))
		},
		"wg ms": func(c *ua.PubSubConfigurationDataType) {
			wg(c).MessageSettings = ua.NewExtensionObject(&ua.KeyValuePair{})
		},
		"wg json udp": func(c *ua.PubSubConfigurationDataType) {
			wg(c).MessageSettings = ua.NewExtensionObject(&ua.JSONWriterGroupMessageDataType{})
		},
		"wg broker ts": func(c *ua.PubSubConfigurationDataType) {
			wg(c).TransportSettings = ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{})
		},
		"wg ts": func(c *ua.PubSubConfigurationDataType) {
			wg(c).TransportSettings = ua.NewExtensionObject(&ua.KeyValuePair{})
		},
		"wg sec no id":   func(c *ua.PubSubConfigurationDataType) { wg(c).SecurityMode = ua.MessageSecurityModeSign },
		"wg sec invalid": func(c *ua.PubSubConfigurationDataType) { wg(c).SecurityMode = 9 },
		"nil w":          func(c *ua.PubSubConfigurationDataType) { wg(c).DataSetWriters[0] = nil },
		"w name":         func(c *ua.PubSubConfigurationDataType) { w(c).Name = "" },
		"w id":           func(c *ua.PubSubConfigurationDataType) { w(c).DataSetWriterID = 0 },
		"w pds":          func(c *ua.PubSubConfigurationDataType) { w(c).DataSetName = "nosuch" },
		"w dup name": func(c *ua.PubSubConfigurationDataType) {
			wg(c).DataSetWriters = append(wg(c).DataSetWriters, DataSetWriter("w", 2, ""))
		},
		"w dup id": func(c *ua.PubSubConfigurationDataType) {
			wg(c).DataSetWriters = append(wg(c).DataSetWriters, DataSetWriter("w2", 1, ""))
		},
		"w json ms": func(c *ua.PubSubConfigurationDataType) {
			w(c).MessageSettings = ua.NewExtensionObject(&ua.JSONDataSetWriterMessageDataType{})
		},
		"w ms": func(c *ua.PubSubConfigurationDataType) {
			w(c).MessageSettings = ua.NewExtensionObject(&ua.KeyValuePair{})
		},
		"w broker ts": func(c *ua.PubSubConfigurationDataType) {
			w(c).TransportSettings = ua.NewExtensionObject(&ua.BrokerDataSetWriterTransportDataType{})
		},
		"w ts": func(c *ua.PubSubConfigurationDataType) {
			w(c).TransportSettings = ua.NewExtensionObject(&ua.KeyValuePair{})
		},
		"nil rg":  func(c *ua.PubSubConfigurationDataType) { conn(c).ReaderGroups[0] = nil },
		"rg name": func(c *ua.PubSubConfigurationDataType) { rg(c).Name = "" },
		"rg dup": func(c *ua.PubSubConfigurationDataType) {
			conn(c).ReaderGroups = append(conn(c).ReaderGroups, ReaderGroup("rg"))
		},
		"rg sec": func(c *ua.PubSubConfigurationDataType) { rg(c).SecurityMode = ua.MessageSecurityModeSign },
		"nil r":  func(c *ua.PubSubConfigurationDataType) { rg(c).DataSetReaders[0] = nil },
		"r name": func(c *ua.PubSubConfigurationDataType) { r(c).Name = "" },
		"r dup": func(c *ua.PubSubConfigurationDataType) {
			rg(c).DataSetReaders = append(rg(c).DataSetReaders, DataSetReader("r", nil, 0, 0, nil))
		},
		"r pubid":   func(c *ua.PubSubConfigurationDataType) { r(c).PublisherID = ua.MustVariant(1.5) },
		"r timeout": func(c *ua.PubSubConfigurationDataType) { r(c).MessageReceiveTimeout = -1 },
		"r sec":     func(c *ua.PubSubConfigurationDataType) { r(c).SecurityMode = ua.MessageSecurityModeSign },
		"r ms": func(c *ua.PubSubConfigurationDataType) {
			r(c).MessageSettings = ua.NewExtensionObject(&ua.KeyValuePair{})
		},
		"r ts": func(c *ua.PubSubConfigurationDataType) {
			r(c).TransportSettings = ua.NewExtensionObject(&ua.KeyValuePair{})
		},
		"r broker ts": func(c *ua.PubSubConfigurationDataType) { SetReaderQueue(r(c), "q", "") },
		"r md": func(c *ua.PubSubConfigurationDataType) {
			r(c).DataSetMetaData.Fields = append(r(c).DataSetMetaData.Fields, &ua.FieldMetaData{Name: "a"})
		},
		"r target nil": func(c *ua.PubSubConfigurationDataType) {
			r(c).SubscribedDataSet.Value.(*ua.TargetVariablesDataType).TargetVariables[0].TargetNodeID = nil
		},
		"r target attr": func(c *ua.PubSubConfigurationDataType) {
			r(c).SubscribedDataSet.Value.(*ua.TargetVariablesDataType).TargetVariables[0].AttributeID = 0
		},
		"r target range": func(c *ua.PubSubConfigurationDataType) {
			r(c).SubscribedDataSet.Value.(*ua.TargetVariablesDataType).TargetVariables[0].WriteIndexRange = "x"
		},
		"r target count": func(c *ua.PubSubConfigurationDataType) { SetTargetVariables(r(c), Target(nodeA), Target(nodeB)) },
		"r mirror":       func(c *ua.PubSubConfigurationDataType) { SetMirror(r(c), " ") },
		"r sds": func(c *ua.PubSubConfigurationDataType) {
			r(c).SubscribedDataSet = ua.NewExtensionObject(&ua.KeyValuePair{})
		},
	}
	for name, m := range cases {
		cfg := validCfg()
		m(cfg)
		err := Validate(cfg)
		require.Error(t, err, name)
		require.ErrorIs(t, err, ua.StatusBadConfigurationError, name)
		var ce *ConfigError
		require.ErrorAs(t, err, &ce, name)
		_, err = New(cfg)
		require.Error(t, err, name)
	}
	require.Error(t, Validate(nil))
}

func TestValidateEthernet(t *testing.T) {
	t.Parallel()
	c := EthernetConnection("eth", "opc.eth://01-00-5e-00-00-01:100.3", "eth0", uint16(1))
	require.Equal(t, transport.ProfileEthUADP, c.TransportProfileURI)
	addr := c.Address.Value.(*ua.NetworkAddressURLDataType)
	require.Equal(t, "eth0", addr.NetworkInterface)
	cfg := NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachReaderGroups(AttachWriterGroups(c, WriterGroup("wg", 1, time.Second, DataSetWriter("w", 1, "pds"))),
			ReaderGroup("rg", DataSetReader("r", uint16(1), 1, 1, MetaData("x", Field{Name: "a"})))))
	require.NoError(t, Validate(cfg))

	// JSON is not defined over Ethernet (Part 14 §7.3.3: UADP only).
	c.WriterGroups[0].MessageSettings = ua.NewExtensionObject(&ua.JSONWriterGroupMessageDataType{})
	require.ErrorContains(t, Validate(cfg), "the JSON message mapping needs a broker transport")
}

func TestPublisherIDVariant(t *testing.T) {
	t.Parallel()
	for in, want := range map[any]any{
		byte(1): byte(1), uint16(2): uint16(2), uint32(3): uint32(3), uint64(4): uint64(4), "x": "x",
		int(5): uint16(5), int(70000): uint32(70000), int64(1 << 40): uint64(1 << 40), int32(6): uint16(6),
	} {
		v, err := PublisherIDVariant(in)
		require.NoError(t, err)
		require.Equal(t, want, v.Value())
	}
	v, err := PublisherIDVariant(nil)
	require.NoError(t, err)
	require.Nil(t, v)
	v, err = PublisherIDVariant(ua.MustVariant(uint16(1)))
	require.NoError(t, err)
	require.Equal(t, uint16(1), v.Value())
	v, err = PublisherIDVariant(message.StringPublisherID("p"))
	require.NoError(t, err)
	require.Equal(t, "p", v.Value())
	for _, bad := range []any{-1, int32(-1), int64(-1), 1.5, ua.MustVariant(1.5)} {
		_, err := PublisherIDVariant(bad)
		require.Error(t, err)
	}
	require.Panics(t, func() { UDPConnection("c", "opc.udp://x:1", 1.5) })
	require.Panics(t, func() {
		PublishedDataItems("x", PublishedField{Field: Field{Name: "a"}, NodeID: nodeA, Substitute: struct{}{}})
	})
}

func TestBuilders(t *testing.T) {
	t.Parallel()
	c := MQTTConnection("m", "mqtt://broker:1883", "pub", MappingUADP)
	require.Equal(t, transport.ProfileMQTTUADP, c.TransportProfileURI)
	j := MQTTConnection("m", "mqtt://broker:1883", "pub", MappingJSON)
	require.Equal(t, transport.ProfileMQTTJSON, j.TransportProfileURI)
	rg := Secure(ReaderGroup("rg"), ua.MessageSecurityModeSign, "g")
	require.Equal(t, "g", rg.SecurityGroupID)
	r := SetMirror(DataSetReader("r", nil, 0, 0, nil), "Mirror")
	require.Equal(t, "Mirror", r.SubscribedDataSet.Value.(*ua.SubscribedDataSetMirrorDataType).ParentNodeName)
	md := MetaData("m", Field{Name: "x"}, Field{Name: "y", Type: ua.TypeIDDouble, Array: true})
	require.Equal(t, uint8(ua.TypeIDVariant), md.Fields[0].BuiltInType)
	require.Equal(t, int32(1), md.Fields[1].ValueRank)
	require.Equal(t, uint32(11), md.Fields[1].DataType.IntID())
	require.Equal(t, 2.0, millis(2*time.Millisecond))
	require.Equal(t, time.Duration(0), duration(math.NaN()))
	require.Equal(t, byte(1), qosOf(ua.BrokerTransportQoSAtLeastOnce, 0))
	require.Equal(t, byte(2), qosOf(ua.BrokerTransportQoSExactlyOnce, 0))
	require.Equal(t, byte(0), qosOf(ua.BrokerTransportQoSAtMostOnce, 1))
	require.Equal(t, byte(1), qosOf(ua.BrokerTransportQoSNotSpecified, 1))
	require.Equal(t, byte(1), qosOf(77, 1))
	require.Equal(t, uint32(1), versionTime(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)))
	require.Equal(t, encJSON, readerEncoding(transport.ProfileMQTTJSON, nil))
	require.Equal(t, encJSON, readerEncoding("", ua.NewExtensionObject(&ua.JSONDataSetReaderMessageDataType{})))
	require.Equal(t, encUADP, readerEncoding("", ua.NewExtensionObject(&ua.UADPDataSetReaderMessageDataType{})))
	require.Equal(t, encJSON, groupEncoding(transport.ProfileMQTTJSON, nil))
	require.Equal(t, encUADP, payloadEncoding([]byte{0xf1, 0x01}))
	require.Equal(t, encJSON, payloadEncoding([]byte(" [1]")))
	require.False(t, sameGUID(nil, &ua.GUID{}))
	require.False(t, sameGUID(&ua.GUID{Data4: []byte{1}}, &ua.GUID{Data4: []byte{2}}))
	require.True(t, hasFieldID(&ua.GUID{Data4: []byte{0, 1}}))
	require.False(t, hasFieldID(&ua.GUID{Data4: []byte{0, 0}}))
	require.True(t, sameVersion(nil, nil))
	require.False(t, sameVersion(nil, &ua.ConfigurationVersionDataType{}))
	require.True(t, sameValue(nil, nil))
	require.False(t, sameValue(nil, &ua.DataValue{}))
}

func TestMemoryDataSource(t *testing.T) {
	t.Parallel()
	m := NewMemoryDataSource()
	require.NoError(t, m.Set(nodeA, []int32{1, 2, 3}))
	require.NoError(t, m.Set(nodeB, ua.MustVariant("x")))
	require.NoError(t, m.Set(nodeC, &ua.DataValue{Value: ua.MustVariant(1.5), SourceTimestamp: time.Unix(1, 0)}))
	require.Error(t, m.Set(nodeA, struct{}{}))
	out := m.ReadPublishedData(context.Background(), []*ua.PublishedVariableDataType{
		{PublishedVariable: nodeA, AttributeID: ua.AttributeIDValue, IndexRange: "1"},
		{PublishedVariable: nodeA, AttributeID: ua.AttributeIDValue, IndexRange: "9"},
		{PublishedVariable: nodeB, AttributeID: ua.AttributeIDDisplayName},
		{PublishedVariable: nodeC, AttributeID: ua.AttributeIDValue},
		{PublishedVariable: ua.NewStringNodeID(1, "x"), AttributeID: ua.AttributeIDValue},
	})
	require.Equal(t, []int32{2}, out[0].Value.Value())
	require.True(t, isBad(out[1].Status))
	require.Equal(t, ua.StatusBadAttributeIDInvalid, out[2].Status)
	require.Equal(t, time.Unix(1, 0), out[3].SourceTimestamp)
	require.Equal(t, ua.StatusBadNodeIDUnknown, out[4].Status)
	f := m.FieldMetaData(&ua.PublishedVariableDataType{PublishedVariable: nodeA})
	require.Equal(t, int32(1), f.ValueRank)
	require.Equal(t, uint8(ua.TypeIDInt32), f.BuiltInType)
	require.Nil(t, m.FieldMetaData(&ua.PublishedVariableDataType{PublishedVariable: nodeA, IndexRange: "1"}))

	// The runtime completes metadata through the resolver.
	p, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{{
		Name:          "auto",
		DataSetSource: ua.NewExtensionObject(&ua.PublishedDataItemsDataType{PublishedData: []*ua.PublishedVariableDataType{{PublishedVariable: nodeA, AttributeID: ua.AttributeIDValue}, {PublishedVariable: ua.NewStringNodeID(1, "x"), AttributeID: ua.AttributeIDValue}}}),
	}}), WithDataSource(m), WithLogger(nil))
	require.NoError(t, err)
	cfg, err := p.PublishedDataSetConfig(mustID(t, p, KindPublishedDataSet, Root, "auto"))
	require.NoError(t, err)
	require.Equal(t, "Field0", cfg.DataSetMetaData.Fields[0].Name)
	require.Equal(t, uint8(ua.TypeIDInt32), cfg.DataSetMetaData.Fields[0].BuiltInType)
	require.Equal(t, uint8(ua.TypeIDVariant), cfg.DataSetMetaData.Fields[1].BuiltInType)
	require.True(t, hasFieldID(cfg.DataSetMetaData.Fields[0].DataSetFieldID))
	require.NotZero(t, cfg.DataSetMetaData.ConfigurationVersion.MajorVersion)
	require.NoError(t, p.Close())
}

func TestFuncAdaptersAndTransportConfig(t *testing.T) {
	t.Parallel()
	var called bool
	ds := DataSourceFunc(func(_ context.Context, vars []*ua.PublishedVariableDataType) []*ua.DataValue {
		called = true
		return []*ua.DataValue{nil}
	})
	require.Len(t, ds.ReadPublishedData(context.Background(), nil), 1)
	require.True(t, called)
	tw := TargetWriterFunc(func(_ context.Context, w []TargetWrite) []error { return make([]error, len(w)) })
	require.Len(t, tw.WriteTargets(context.Background(), []TargetWrite{{}}), 1)

	url := memURL(t)
	cfgs := make(chan transport.Config, 1)
	c := memConnection("c", url, nil)
	c.ConnectionProperties = []*ua.KeyValuePair{{Key: &ua.QualifiedName{Name: "k"}, Value: ua.MustVariant("v")}, nil, {Key: &ua.QualifiedName{Name: "n"}, Value: ua.MustVariant(int32(1))}}
	start(t, NewConfiguration(nil, c), WithTransportConfig(func(conn *ua.PubSubConnectionDataType, cfg *transport.Config) {
		cfg.Username = "u"
		cfgs <- *cfg
	}))
	got := <-cfgs
	require.Equal(t, "u", got.Username)
	require.Equal(t, map[string]string{"k": "v"}, got.Properties)
	require.Equal(t, url, got.URL)
	require.Empty(t, got.ClientID, "the connection name is no MQTT client identifier")
}

func TestRealCodecsRegistered(t *testing.T) {
	t.Parallel()
	require.IsType(t, uadpCodec{}, defaultCodecs(encUADP))
	require.IsType(t, jsonCodec{}, defaultCodecs(encJSON))
	_, err := uadpCodec{}.EncodeMetaData(nil)
	require.ErrorIs(t, err, errNoJSONMetaData)
	_, err = uadpCodec{}.DecodeMetaData(nil, nil)
	require.ErrorIs(t, err, errNoJSONMetaData)
	// The JSON mapping is wired to package jsonmsg; until it is implemented
	// it reports errors, which the runtime counts.
	_, _ = jsonCodec{}.Encode(&message.NetworkMessage{}, nil)
	_, _ = jsonCodec{}.Decode([]byte("{}"), nil)
	_, _ = jsonCodec{}.EncodeMetaData(&jsonmsg.MetaDataMessage{})
	_, _ = jsonCodec{}.DecodeMetaData([]byte("{}"), nil)
	require.True(t, isJSONMetaData([]byte(`{"MessageType":"ua-metadata"}`)))
	require.False(t, isJSONMetaData(append(make([]byte, 600), []byte(`"ua-metadata"`)...)))
}
