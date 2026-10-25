// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/remote"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// Chunked UADP NetworkMessages (Part 14 §7.2.4.4.4) and UADP discovery
// (§7.2.4.6.12) between servers and standalone runtimes over UDP.

// psBig returns a string of n bytes that tells its tag.
func psBig(tag string, n int) string {
	return strings.Repeat(tag+"|", n/(len(tag)+1)+1)[:n]
}

// TestPubSub_ChunkedUDPServerToServer publishes a value larger than the
// MaxNetworkMessageSize of the writer group, unsecured and with
// SignAndEncrypt, from one server to the target variables of another: the
// NetworkMessages go as chunks and are reassembled. A standalone subscriber
// whose reassembly accepts smaller messages takes none of them, counts the
// discarded chunks and delivers again once the value is small.
func TestPubSub_ChunkedUDPServerToServer(t *testing.T) {
	parallel(t)
	ring := psRing(t, "sg")
	pubSrv, _ := newServer(t, server.WithPubSub(nil, pubsub.WithKeySource("sg", ring)))
	subSrv, subURL := newServer(t, server.WithPubSub(nil, pubsub.WithKeySource("sg", ring)))
	pubNS := server.NewNodeNameSpace(pubSrv, "urn:pubsub:chunks:pub")
	subNS := server.NewNodeNameSpace(subSrv, "urn:pubsub:chunks:sub")
	pub, sub := pubSrv.PubSub(), subSrv.PubSub()
	toSub, toLimited := psUDPURL(t), psUDPURL(t)
	ctx := context.Background()

	first := psBig("first", 20000)
	big := pubNS.AddNewVariableStringNode("big", first)
	n := pubNS.AddNewVariableStringNode("n", int32(1))
	pds := pubsub.PublishedDataItems("big", pubsub.Var("n", n.ID(), ua.TypeIDInt32), pubsub.Var("big", big.ID(), ua.TypeIDString))
	_, err := pub.AddPublishedDataSet(pds)
	require.NoError(t, err)

	type route struct {
		name   string
		gid    uint16
		mode   ua.MessageSecurityMode
		tn, tb *server.Node
	}
	routes := []*route{{name: "none", gid: 1}, {name: "sign-and-encrypt", gid: 2, mode: ua.MessageSecurityModeSignAndEncrypt}}
	pc, err := pub.AddConnection(pubsub.UDPConnection("udp", toSub, uint16(7)))
	require.NoError(t, err)
	sc, err := sub.AddConnection(pubsub.UDPConnection("udp", toSub, nil))
	require.NoError(t, err)
	for _, r := range routes {
		wg := pubsub.WriterGroup(r.name, r.gid, psInterval, pubsub.DataSetWriter("w", 1, "big"))
		wg.MaxNetworkMessageSize = 1400
		r.tn = subNS.AddNewVariableStringNode(r.name+".n", int32(0))
		r.tb = subNS.AddNewVariableStringNode(r.name+".big", "")
		rg := pubsub.ReaderGroup(r.name, pubsub.SetTargetVariables(
			pubsub.DataSetReader("r", uint16(7), r.gid, 1, pubsub.DataSetMetaDataOf(pds)), pubsub.Target(r.tn.ID()), pubsub.Target(r.tb.ID())))
		if r.mode != ua.MessageSecurityModeNone {
			pubsub.Secure(wg, r.mode, "sg")
			pubsub.Secure(rg, r.mode, "sg")
		}
		_, err = pub.AddWriterGroup(pc, wg)
		require.NoError(t, err)
		_, err = sub.AddReaderGroup(sc, rg)
		require.NoError(t, err)
	}

	// The same data set to a standalone runtime that reassembles at most
	// 4 KiB.
	lc, err := pub.AddConnection(pubsub.UDPConnection("limited", toLimited, uint16(7)))
	require.NoError(t, err)
	lwg := pubsub.WriterGroup("limited", 3, psInterval, pubsub.DataSetWriter("w", 1, "big"))
	lwg.MaxNetworkMessageSize = 1400
	_, err = pub.AddWriterGroup(lc, lwg)
	require.NoError(t, err)
	rec := newPSRecorder()
	limited := psRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("udp", toLimited, nil),
		pubsub.ReaderGroup("rg", pubsub.DataSetReader("r", uint16(7), 3, 1, pubsub.DataSetMetaDataOf(pds))))),
		pubsub.WithDataSetHandler(rec.handle), pubsub.WithChunkReassembly(uadp.ReassemblerOptions{MaxMessageSize: 4096}))

	c := newClient(t, subURL)
	expect := func(t *testing.T, r *route, wantN int32, wantBig string) {
		t.Helper()
		eventually(t, func() bool {
			a, err1 := c.Node(r.tn.ID()).Value(ctx)
			b, err2 := c.Node(r.tb.ID()).Value(ctx)
			return err1 == nil && err2 == nil && a != nil && b != nil && a.Value() == wantN && b.Value() == wantBig
		}, r.name+": the targets take the chunked value")
	}
	for _, r := range routes {
		t.Run(r.name+"/first", func(t *testing.T) { expect(t, r, 1, first) })
	}
	second := psBig("second", 30000)
	require.NoError(t, big.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(second)))
	require.NoError(t, n.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue(int32(2))))
	for _, r := range routes {
		t.Run(r.name+"/second", func(t *testing.T) { expect(t, r, 2, second) })
	}

	pst, err := pub.Status(pc)
	require.NoError(t, err)
	require.NotZero(t, pst.Counters.ChunksSent)
	require.Zero(t, pst.Counters.EncodeErrors)
	sst, err := sub.Status(sc)
	require.NoError(t, err)
	require.NotZero(t, sst.Counters.ChunkedMessagesReceived)
	require.Zero(t, sst.Counters.DecodeErrors)

	// The limited subscriber: chunks discarded, nothing delivered.
	eventually(t, func() bool {
		st, err := limited.Status(pubsub.Root)
		return err == nil && st.Counters.ChunksDiscarded > 0
	}, "the limited reassembly discards chunks")
	require.Empty(t, rec.of("r"))
	st, err := limited.Status(pubsub.Root)
	require.NoError(t, err)
	require.Zero(t, st.Counters.ChunkedMessagesReceived)
	// A value that fits into one NetworkMessage gets through.
	require.NoError(t, big.SetAttribute(ua.AttributeIDValue, server.DataValueFromValue("small")))
	rec.waitFor(t, "r", func(d *pubsub.ReceivedDataSet) bool {
		f := d.Field("big")
		return f != nil && f.Value != nil && f.Value.Value() == "small"
	})
}

// TestPubSub_DiscoveryServerPublisher: readers without DataSetMetaData, in
// a standalone runtime and in a server configured through its PubSub
// methods, learn it with UADP discovery probes from a publishing server
// (Part 14 §7.2.4.6.12), deliver the fields by name, and the reader of the
// server shows the learned DataSetMetaData in its information model.
func TestPubSub_DiscoveryServerPublisher(t *testing.T) {
	parallel(t)
	pubSrv, _ := newServer(t, server.WithPubSub(nil))
	_, subURL := newServer(t, server.WithPubSub(nil))
	ns := server.NewNodeNameSpace(pubSrv, "urn:pubsub:discovery:pub")
	pub := pubSrv.PubSub()
	ctx := context.Background()
	// Probes and announcements go to the address of the connection, a
	// segment that publisher and subscriber share as they would a
	// multicast group (psMemURL: also on hosts without multicast).
	toSA, toSrv := psMemURL(t), psMemURL(t)

	i32 := ns.AddNewVariableStringNode("i32", int32(11))
	str := ns.AddNewVariableStringNode("str", "discovered")
	pds := pubsub.PublishedDataItems("disc", pubsub.Var("i32", i32.ID(), ua.TypeIDInt32), pubsub.Var("str", str.ID(), ua.TypeIDString))
	_, err := pub.AddPublishedDataSet(pds)
	require.NoError(t, err)
	for i, url := range []string{toSA, toSrv} {
		cid, err := pub.AddConnection(pubsub.UDPConnection("udp"+string(rune('a'+i)), url, uint16(21)))
		require.NoError(t, err)
		_, err = pub.AddWriterGroup(cid, pubsub.WriterGroup("wg", 4, psInterval, pubsub.DataSetWriter("w", 5, "disc")))
		require.NoError(t, err)
	}

	rec := newPSRecorder()
	sa := psRuntime(t, pubsub.NewConfiguration(nil, pubsub.AttachReaderGroups(pubsub.UDPConnection("udp", toSA, nil),
		pubsub.ReaderGroup("rg", pubsub.DataSetReader("r", uint16(21), 4, 5, nil)))),
		pubsub.WithDataSetHandler(rec.handle))

	// The subscribing server, configured by a client.
	rc := remote.New(newClient(t, subURL))
	cn, err := rc.AddConnection(ctx, pubsub.UDPConnection("udp", toSrv, nil))
	require.NoError(t, err)
	gn, err := rc.AddReaderGroup(ctx, cn, pubsub.ReaderGroup("rg"))
	require.NoError(t, err)
	rn, err := rc.AddDataSetReader(ctx, gn, pubsub.DataSetReader("r", uint16(21), 4, 5, nil))
	require.NoError(t, err)

	rec.waitFor(t, "r", func(d *pubsub.ReceivedDataSet) bool {
		fi, fs := d.Field("i32"), d.Field("str")
		return fi != nil && fs != nil && fi.Value != nil && fs.Value != nil && fi.Value.Value() == int32(11) && fs.Value.Value() == "discovered"
	})
	eventually(t, func() bool {
		v, err := rc.Property(ctx, rn, "DataSetMetaData")
		if err != nil || v == nil {
			return false
		}
		eo, _ := v.Value().(*ua.ExtensionObject)
		if eo == nil {
			return false
		}
		md, _ := eo.Value.(*ua.DataSetMetaDataType)
		return md != nil && len(md.Fields) == 2 && md.Fields[0].Name == "i32" && md.Fields[1].Name == "str"
	}, "the reader of the server shows the learned DataSetMetaData")
	eventually(t, func() bool {
		st, err := rc.State(ctx, rn)
		return err == nil && st == ua.PubSubStateOperational
	}, "the reader of the server is Operational")

	sst, err := sa.Status(pubsub.Root)
	require.NoError(t, err)
	require.NotZero(t, sst.Counters.DiscoveryRequestsSent)
	require.NotZero(t, sst.Counters.DiscoveryResponsesReceived)
	require.Zero(t, sst.Counters.DecodeErrors)
	// The publisher counts a response once the send returned, which can
	// be after the subscriber took it.
	eventually(t, func() bool {
		pst, err := pub.Status(pubsub.Root)
		return err == nil && pst.Counters.DiscoveryRequestsReceived > 0 && pst.Counters.DiscoveryResponsesSent > 0
	}, "the publisher counts the probe and its answer")
}
