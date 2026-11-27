// SPDX-License-Identifier: MIT

package fxcm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// commFixture is a configuration with one writer and one reader, with
// their ids set, and the communication an AC with exactly that
// configuration shows (Part 14 §9.1.4 to §9.1.8).
func commFixture() (*ua.PubSubConfiguration2DataType, *uafx.PubSubCommunicationLinkConfiguration, *commActual) {
	pds := pubsub.PublishedDataItems("PDS", pubsub.Var("x", ua.NewNumericNodeID(1, 10), ua.TypeIDDouble))
	w := pubsub.DataSetWriter("W", 7, "PDS")
	w.KeyFrameCount = 2
	wg := pubsub.WriterGroup("G", 5, 10*time.Millisecond, w)
	wg.KeepAliveTime = 100
	wg.Priority = 3
	md := pubsub.MetaData("m", pubsub.Field{Name: "x", Type: ua.TypeIDDouble})
	pub := ua.MustVariant(uint16(42))
	r := pubsub.SetTargetVariables(pubsub.DataSetReader("R", pub, 5, 7, md), pubsub.Target(ua.NewNumericNodeID(1, 11)))
	r.MessageReceiveTimeout = 50
	wconn := pubsub.AttachWriterGroups(pubsub.UDPConnection("Pub", "opc.udp://127.0.0.1:4840", pub), wg)
	rconn := pubsub.AttachReaderGroups(pubsub.UDPConnection("Sub", "opc.udp://127.0.0.1:4841", nil), pubsub.ReaderGroup("RG", r))
	cfg := &ua.PubSubConfiguration2DataType{
		PublishedDataSets: []*ua.PublishedDataSetDataType{pds},
		Connections:       []*ua.PubSubConnectionDataType{wconn, rconn},
	}
	l := &uafx.PubSubCommunicationLinkConfiguration{
		DataSetWriterRef: &ua.PubSubConfigurationRefDataType{},
		DataSetReaderRef: &ua.PubSubConfigurationRefDataType{ConnectionIndex: 1},
	}
	v := ua.MustVariant
	conn := func(c *ua.PubSubConnectionDataType) map[string]*ua.Variant {
		return map[string]*ua.Variant{
			"PublisherId":         c.PublisherID,
			"TransportProfileUri": v(c.TransportProfileURI),
			"Address/Url":         v(c.Address.Value.(*ua.NetworkAddressURLDataType).URL),
		}
	}
	c := &commActual{
		writer: map[string]*ua.Variant{
			"DataSetWriterId":         v(w.DataSetWriterID),
			"DataSetFieldContentMask": v(uint32(w.DataSetFieldContentMask)),
			"KeyFrameCount":           v(w.KeyFrameCount),
		},
		group: map[string]*ua.Variant{
			"WriterGroupId":      v(wg.WriterGroupID),
			"PublishingInterval": v(wg.PublishingInterval),
			"KeepAliveTime":      v(wg.KeepAliveTime),
			"Priority":           v(wg.Priority),
			"HeaderLayoutUri":    v(wg.HeaderLayoutURI),
			"SecurityMode":       v(int32(wg.SecurityMode)),
			"SecurityGroupId":    v(wg.SecurityGroupID),
		},
		wconn:     conn(wconn),
		published: pds.DataSetSource.Value.(*ua.PublishedDataItemsDataType).PublishedData,
		reader: map[string]*ua.Variant{
			"PublisherId":             r.PublisherID,
			"WriterGroupId":           v(r.WriterGroupID),
			"DataSetWriterId":         v(r.DataSetWriterID),
			"DataSetFieldContentMask": v(uint32(r.DataSetFieldContentMask)),
			"MessageReceiveTimeout":   v(r.MessageReceiveTimeout),
			"KeyFrameCount":           v(r.KeyFrameCount),
			"HeaderLayoutUri":         v(r.HeaderLayoutURI),
			"SecurityMode":            v(int32(r.SecurityMode)),
			"SecurityGroupId":         v(r.SecurityGroupID),
		},
		rconn:   conn(rconn),
		targets: r.SubscribedDataSet.Value.(*ua.TargetVariablesDataType).TargetVariables,
	}
	return cfg, l, c
}

// TestSameComm: adoption compares every property of the writer, reader,
// groups and connections of an endpoint with its configuration (design
// §6.6, C3-D6); one that differs refuses the endpoint and says which.
func TestSameComm(t *testing.T) {
	t.Parallel()
	cfg, l, c := commFixture()
	ok, why := sameCommAt(cfg, l, c)
	assert.True(t, ok, why)
	ok, _ = sameCommAt(nil, l, c)
	assert.True(t, ok, "no configuration: nothing to compare")

	v := ua.MustVariant
	for _, tc := range []struct {
		el, prop string
		val      *ua.Variant
		want     string
	}{
		{"writer", "DataSetWriterId", v(uint16(8)), "its DataSetWriterId"},
		{"writer", "DataSetFieldContentMask", v(uint32(99)), "the DataSetFieldContentMask of its DataSetWriter"},
		{"writer", "KeyFrameCount", v(uint32(9)), "the KeyFrameCount of its DataSetWriter"},
		{"group", "WriterGroupId", v(uint16(6)), "its WriterGroupId"},
		{"group", "PublishingInterval", v(float64(11)), "the PublishingInterval of its WriterGroup"},
		{"group", "KeepAliveTime", v(float64(1)), "the KeepAliveTime of its WriterGroup"},
		{"group", "Priority", v(uint8(4)), "the Priority of its WriterGroup"},
		{"group", "HeaderLayoutUri", v("urn:other"), "the HeaderLayoutUri of its WriterGroup"},
		{"group", "SecurityMode", v(int32(3)), "the SecurityMode of its WriterGroup"},
		{"group", "SecurityGroupId", v("sg"), "the SecurityGroupId of its WriterGroup"},
		{"wconn", "PublisherId", v(uint16(43)), "the PublisherId of its PubSubConnection"},
		{"wconn", "Address/Url", v("opc.udp://127.0.0.1:1"), "the transport of its PubSubConnection"},
		{"reader", "PublisherId", v(uint16(43)), "the PublisherId of its DataSetReader"},
		{"reader", "WriterGroupId", v(uint16(6)), "the WriterGroupId of its DataSetReader"},
		{"reader", "DataSetWriterId", v(uint16(8)), "the DataSetWriterId of its DataSetReader"},
		{"reader", "DataSetFieldContentMask", v(uint32(99)), "the DataSetFieldContentMask of its DataSetReader"},
		{"reader", "MessageReceiveTimeout", v(float64(1)), "the MessageReceiveTimeout of its DataSetReader"},
		{"reader", "KeyFrameCount", v(uint32(9)), "the KeyFrameCount of its DataSetReader"},
		{"reader", "HeaderLayoutUri", v("urn:other"), "the HeaderLayoutUri of its DataSetReader"},
		{"reader", "SecurityMode", v(int32(3)), "the SecurityMode of its DataSetReader"},
		{"reader", "SecurityGroupId", v("sg"), "the SecurityGroupId of its DataSetReader"},
		{"rconn", "TransportProfileUri", v("urn:other"), "the transport of the PubSubConnection of its DataSetReader"},
	} {
		cfg, l, c := commFixture()
		m := map[string]map[string]*ua.Variant{"writer": c.writer, "group": c.group, "wconn": c.wconn, "reader": c.reader, "rconn": c.rconn}[tc.el]
		m[tc.prop] = tc.val
		ok, why := sameCommAt(cfg, l, c)
		assert.False(t, ok, "%s %s", tc.el, tc.prop)
		assert.Equal(t, tc.want, why, "%s %s", tc.el, tc.prop)
	}

	t.Run("absent properties", func(t *testing.T) {
		// An optional Property the AC does not have is no value: an
		// empty string is not compared, anything else differs.
		cfg, l, c := commFixture()
		delete(c.group, "HeaderLayoutUri")
		delete(c.reader, "SecurityGroupId")
		ok, why := sameCommAt(cfg, l, c)
		assert.True(t, ok, why)
		delete(c.writer, "KeyFrameCount")
		_, why = sameCommAt(cfg, l, c)
		assert.Equal(t, "the KeyFrameCount of its DataSetWriter", why)
		cfg, l, c = commFixture()
		delete(c.reader, "PublisherId")
		_, why = sameCommAt(cfg, l, c)
		assert.Equal(t, "the PublisherId of its DataSetReader", why)
	})
	t.Run("published", func(t *testing.T) {
		cfg, l, c := commFixture()
		c.published = nil
		_, why := sameCommAt(cfg, l, c)
		assert.Equal(t, "the PublishedData of its PublishedDataSet", why)
		assert.False(t, samePublished(cfg, "other", c.published), "no such PublishedDataSet")
	})
	t.Run("targets", func(t *testing.T) {
		cfg, l, c := commFixture()
		tv := *c.targets[0]
		tv.AttributeID = ua.AttributeIDDescription
		c.targets = []*ua.FieldTargetDataType{&tv}
		_, why := sameCommAt(cfg, l, c)
		assert.Equal(t, "the TargetVariables of its DataSetReader", why)
		c.targets = nil
		_, why = sameCommAt(cfg, l, c)
		assert.Equal(t, "the TargetVariables of its DataSetReader", why, "missing")
		c.targets = []*ua.FieldTargetDataType{nil}
		_, why = sameCommAt(cfg, l, c)
		assert.Equal(t, "the TargetVariables of its DataSetReader", why, "nil")
	})
	t.Run("no element in the configuration", func(t *testing.T) {
		cfg, l, c := commFixture()
		l.DataSetWriterRef = &ua.PubSubConfigurationRefDataType{GroupIndex: 9}
		_, why := sameCommAt(cfg, l, c)
		assert.Equal(t, "the configuration has no DataSetWriter for it", why)
		cfg, l, c = commFixture()
		l.DataSetReaderRef = &ua.PubSubConfigurationRefDataType{ConnectionIndex: 1, ElementIndex: 9}
		_, why = sameCommAt(cfg, l, c)
		assert.Equal(t, "the configuration has no DataSetReader for it", why)
	})
	t.Run("allocated ids are not compared with the configuration", func(t *testing.T) {
		cfg, l, c := commFixture()
		_, g, w := writerAt(cfg, l.DataSetWriterRef)
		w.DataSetWriterID, g.WriterGroupID = 0, 0
		cfg.Connections[0].PublisherID = nil
		c.writer["DataSetWriterId"], c.group["WriterGroupId"], c.wconn["PublisherId"] = v(uint16(100)), v(uint16(101)), v(uint16(102))
		ok, why := sameCommAt(cfg, l, c)
		assert.True(t, ok, why)
	})
}

func TestSameScalars(t *testing.T) {
	t.Parallel()
	v := ua.MustVariant
	assert.True(t, sameGUID(nil, &ua.GUID{}), "absent is null")
	g := ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63")
	assert.False(t, sameGUID(nil, g))
	assert.True(t, sameGUID(g, ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63")))
	assert.False(t, sameGUID(g, ua.NewGUID("72962B91-FA75-4AE6-8D28-B404DC7DAF64")))
	assert.False(t, sameU16(v(uint32(1)), 1), "another type")
	assert.True(t, sameStr(nil, ""), "absent is empty")
	assert.False(t, sameStr(v(int32(1)), "1"))
	assert.False(t, sameConn(nil, nil))
}
