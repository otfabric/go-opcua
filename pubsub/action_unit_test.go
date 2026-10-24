// SPDX-License-Identifier: MIT

package pubsub

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
)

func TestActionValidate(t *testing.T) {
	ok := func() *ua.PubSubConfigurationDataType {
		return responderConfig("opc.udp://127.0.0.1:4840", 0, ua.MessageSecurityModeNone)
	}
	require.NoError(t, Validate(ok()))
	mqttCfg, _, _ := brokerActionConfigs("mqtt://localhost:1883", MappingJSON)
	require.NoError(t, Validate(mqttCfg))
	method := ok()
	method.PublishedDataSets[0].DataSetSource = ua.NewExtensionObject(&ua.PublishedActionMethodDataType{
		ActionTargets: []*ua.ActionTargetDataType{ActionTargetOf(1, "M")},
		ActionMethods: []*ua.ActionMethodDataType{{ObjectID: ua.NewNumericNodeID(1, 1), MethodID: ua.NewNumericNodeID(1, 2)}},
	})
	require.NoError(t, Validate(method))

	for name, tweak := range map[string]func(c *ua.PubSubConfigurationDataType){
		"no targets": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0] = PublishedActions("Calc", nil, nil)
		},
		"nil target": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0] = PublishedActions("Calc", nil, nil, nil)
		},
		"duplicate target": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0] = PublishedActions("Calc", nil, nil, ActionTargetOf(1, "a"), ActionTargetOf(1, "b"))
		},
		"duplicate request field": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0] = PublishedActions("Calc", []Field{{Name: "A"}, {Name: "A"}}, nil, ActionTargetOf(1, "a"))
		},
		"duplicate response field": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets[0] = PublishedActions("Calc", nil, []Field{{Name: "A"}, {Name: "A"}}, ActionTargetOf(1, "a"))
		},
		"interval 0 with data writers": func(c *ua.PubSubConfigurationDataType) {
			c.PublishedDataSets = append(c.PublishedDataSets, PublishedDataItems("Data", Var("a", nodeA, ua.TypeIDInt32)))
			g := c.Connections[0].WriterGroups[0]
			g.DataSetWriters = append(g.DataSetWriters, DataSetWriter("DataWriter", 101, "Data"))
		},
		"broker without queue": func(c *ua.PubSubConfigurationDataType) {
			c.Connections[0] = AttachWriterGroups(MQTTConnection("Responder", "mqtt://localhost:1883", uint16(1), MappingUADP),
				WriterGroup("Actions", 10, 0, DataSetWriter("CalcWriter", 100, "Calc")))
		},
	} {
		c := ok()
		tweak(c)
		require.Error(t, Validate(c), name)
	}
}

func TestActionRuntimeConfig(t *testing.T) {
	// A data writer cannot join a group of PublishingInterval 0, an
	// Action writer on a broker needs the queue of its group.
	p := startReal(t, responderConfig(memURL(t), 0, ua.MessageSecurityModeNone))
	gid := mustID(t, p, KindWriterGroup, mustID(t, p, KindConnection, Root, "Responder"), "Actions")
	_, err := p.AddPublishedDataSet(PublishedDataItems("Data", Var("a", nodeA, ua.TypeIDInt32)))
	require.NoError(t, err)
	_, err = p.AddDataSetWriter(gid, DataSetWriter("DataWriter", 101, "Data"))
	require.Error(t, err)
	_, err = p.AddDataSetWriter(gid, DataSetWriter("CalcWriter2", 102, "Calc"))
	require.NoError(t, err)

	cid, err := p.AddConnection(MQTTConnection("Broker", memURL(t)+"b", uint16(3), MappingUADP))
	require.NoError(t, err)
	_ = cid
	bg, err := p.AddWriterGroup(cid, WriterGroup("Data", 11, time.Second))
	require.NoError(t, err)
	_, err = p.AddDataSetWriter(bg, DataSetWriter("CalcWriter3", 103, "Calc"))
	require.Error(t, err)
}

func TestActionHelpers(t *testing.T) {
	require.Equal(t, "p/json/action-request/r/g", ActionRequestTopic("p", MappingJSON, "r", "g"))
	require.Equal(t, "p/uadp/action-response/r/g", ActionResponseTopic("p", MappingUADP, "r", "g"))
	require.Equal(t, "a/x/action-response/b", defaultResponseTopic("a/x/action-request/b"))
	require.Empty(t, defaultResponseTopic("a/b"))

	o := ActionOptions{}.normalized()
	require.Equal(t, ActionOptions{MaxConcurrent: 64, Rate: 50, Burst: 50, MaxTimeout: time.Minute, DefaultTimeout: 10 * time.Second}, o)

	var b tokenBucket
	now := time.Now()
	require.True(t, b.allow(now, 1, 2))
	require.True(t, b.allow(now, 1, 2))
	require.False(t, b.allow(now, 1, 2))
	require.True(t, b.allow(now.Add(time.Second), 1, 2))
	require.True(t, b.allow(now.Add(-time.Second), 1, 2)) // clock going back refills

	md := completeActionMetaData(&ua.DataSetMetaDataType{Fields: []*ua.FieldMetaData{{}}}, "X", nil)
	require.Equal(t, "X", md.Name)
	require.Equal(t, "Field0", md.Fields[0].Name)
	require.NotNil(t, md.Fields[0].DataType)
	require.NotNil(t, md.ConfigurationVersion)
	require.Equal(t, "Y", completeActionMetaData(nil, "Y", nil).Name)
	// The version of the response.
	v := &ua.ConfigurationVersionDataType{MajorVersion: 7, MinorVersion: 8}
	require.Equal(t, v, completeActionMetaData(nil, "Z", v).ConfigurationVersion)

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}
	require.True(t, replyAllowed("opc.udp://10.0.0.1:4840", src))
	require.False(t, replyAllowed("opc.udp://10.0.0.2:4840", src))
	require.True(t, replyAllowed("opc.udp://239.0.0.1:4840", src))
	require.True(t, replyAllowed("opc.udp://10.0.0.2:4840", nil))
	require.False(t, replyAllowed("opc.udp://host-name:4840", src))
	require.False(t, replyAllowed("opc.udp://bad", src))
	require.False(t, replyAllowed("opc.udp://10.0.0.1:4840", &net.TCPAddr{}))
	require.False(t, replyAllowed("::bad", src))
	require.False(t, replyAllowed("mem://x", src))
	require.True(t, replyAllowed("mem://x", nil))

	// Inputs against the request DataSetMetaData.
	req := MetaData("R", Field{Name: "A", Type: ua.TypeIDInt32}, Field{Name: "B"})
	dsm := func(vs ...any) *message.DataSetMessage {
		m := &message.DataSetMessage{}
		for i, v := range vs {
			m.Fields = append(m.Fields, &message.Field{Index: uint16(i), Value: &ua.DataValue{Value: ua.MustVariant(v)}})
		}
		return m
	}
	in, st := actionInputs(req, dsm(int32(1), "x"))
	require.Equal(t, ua.StatusGood, st)
	require.Len(t, in, 2)
	_, st = actionInputs(req, dsm(int32(1)))
	require.Equal(t, ua.StatusBadArgumentsMissing, st)
	_, st = actionInputs(req, dsm(int32(1), int32(2), int32(3)))
	require.Equal(t, ua.StatusBadTooManyArguments, st)
	_, st = actionInputs(req, &message.DataSetMessage{Fields: []*message.Field{{Index: 5}}})
	require.Equal(t, ua.StatusBadTooManyArguments, st)
	_, st = actionInputs(req, dsm(1.5, int32(2)))
	require.Equal(t, ua.StatusBadTypeMismatch, st)
	in, st = actionInputs(nil, dsm(int32(1), int32(2), int32(3)))
	require.Equal(t, ua.StatusGood, st)
	require.Len(t, in, 3)

	// Outputs: placed by index with metadata, else as received.
	resp := MetaData("S", Field{Name: "X"}, Field{Name: "Y"})
	out := actionOutputs(resp, &message.DataSetMessage{Fields: []*message.Field{
		{Index: 1, Value: &ua.DataValue{Value: ua.MustVariant(int32(2))}}, {Index: 0, Value: &ua.DataValue{Value: ua.MustVariant(int32(1))}}}})
	require.Equal(t, []any{int32(1), int32(2)}, []any{out[0].Value(), out[1].Value()})
	out = actionOutputs(resp, &message.DataSetMessage{Fields: []*message.Field{
		{Index: 1, Value: &ua.DataValue{Value: ua.MustVariant(int32(2))}}, {Index: 5}}})
	require.Len(t, out, 2)
	require.Nil(t, out[0])
	out = actionOutputs(nil, dsm(int32(7)))
	require.Equal(t, int32(7), out[0].Value())
	require.Nil(t, actionOutputs(nil, &message.DataSetMessage{}))

	// A result that does not match the response DataSetMetaData.
	ex := &exchange{}
	ex.finish(ua.StatusGood, int32s(1), resp)
	require.Equal(t, ua.StatusBadInternalError, ex.status)
	ex.finish(ua.StatusBadUserAccessDenied, int32s(1, 2), resp)
	require.Equal(t, ua.StatusBadUserAccessDenied, ex.status)
	require.Empty(t, ex.outputs)
	ex.finish(ua.StatusUncertain, int32s(1, 2), resp)
	require.Len(t, ex.outputs, 2)

	f := namedFields([]*ua.Variant{nil, ua.MustVariant(int32(1))}, MetaData("S", Field{Name: "X"}))
	require.Equal(t, "X", f[0].Name)
	require.Equal(t, "Field1", f[1].Name)
}
