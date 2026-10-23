// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func regressKeys(t *testing.T, groups ...string) *security.KeyService {
	t.Helper()
	ks := security.NewKeyService()
	for _, g := range groups {
		require.NoError(t, ks.AddSecurityGroup(security.SecurityGroupConfig{
			SecurityGroupID: g, SecurityPolicyURI: security.PolicyURIAes128CTR, KeyLifetime: time.Hour, MaxFutureKeyCount: 1,
		}))
	}
	return ks
}

func regressSource(t *testing.T, ks *security.KeyService, g string) security.KeySource {
	t.Helper()
	src, err := ks.KeySource(g)
	require.NoError(t, err)
	return src
}

// Regression (chaos/pubsub fuzz): the JSON mapping has no message
// security, yet a reader that requires SignAndEncrypt took the DataSets
// and the DataSetMetaData of unsecured JSON messages from anybody.
func TestRegressionJSONBypassesReaderSecurity(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ks := regressKeys(t, "sg")
	md := MetaData("pds", Field{Name: "a", Type: ua.TypeIDInt32})
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		Secure(ReaderGroup("rg", DataSetReader("r", uint16(8), 0, 1, md)), ua.MessageSecurityModeSignAndEncrypt, "sg"))),
		WithDataSetHandler(rec.handler), WithKeySource("sg", regressSource(t, ks, "sg")))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	cid := mustID(t, sub, KindConnection, Root, "sub")
	rid := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, cid, "rg"), "r")
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)

	pub := message.NewPublisherID(message.PublisherIDUInt16, 8)
	data, err := jsonmsg.Encode(&message.NetworkMessage{
		Type:        message.NetworkMessageDataSet,
		PublisherID: pub,
		JSONMask:    DefaultJSONNetworkMessageContentMask,
		MessageID:   "forged",
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: 1,
			Type:            message.DataSetMessageKeyFrame,
			Valid:           true,
			JSONMask:        DefaultJSONDataSetMessageContentMask,
			SequenceNumber:  1,
			Status:          ua.StatusGood,
			Fields:          []*message.Field{{Name: "a", Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(666))}}},
		}},
	}, &jsonmsg.EncodeOptions{})
	require.NoError(t, err)
	meta, err := jsonmsg.EncodeMetaData(&jsonmsg.MetaDataMessage{
		MessageID: "forged-meta", PublisherID: pub, DataSetWriterID: 1,
		MetaData: MetaData("evil", Field{Name: "x", Type: ua.TypeIDString}, Field{Name: "y", Type: ua.TypeIDString}),
	}, &jsonmsg.EncodeOptions{})
	require.NoError(t, err)

	for range 5 {
		bus.inject(url, "", meta)
		bus.inject(url, "", data)
	}
	require.Eventually(t, func() bool {
		st, err := sub.Status(cid)
		return err == nil && st.Counters.DecodeErrors >= 10
	}, 3*time.Second, time.Millisecond)
	require.Empty(t, rec.dataSets(), "a SignAndEncrypt reader took an unsecured JSON message")
	cfg, err := sub.DataSetReaderConfig(rid)
	require.NoError(t, err)
	require.Len(t, cfg.DataSetMetaData.Fields, 1, "an unsecured JSON metadata message replaced the metadata of a secured reader")
	require.Equal(t, "a", cfg.DataSetMetaData.Fields[0].Name)
	st, err := sub.State(rid)
	require.NoError(t, err)
	require.Equal(t, ua.PubSubStatePreOperational, st)
}

// Regression (chaos/pubsub): a message verified with the keys of one
// SecurityGroup was also delivered to a secured reader of another
// SecurityGroup, which does not trust those keys.
func TestRegressionReaderOfOtherSecurityGroup(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ks := regressKeys(t, "A", "B")
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(5)))
	pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32))
	md := DataSetMetaDataOf(pds)
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		Secure(ReaderGroup("rgA", DataSetReader("ra", uint16(8), 1, 1, md)), ua.MessageSecurityModeSign, "A"),
		Secure(ReaderGroup("rgB", DataSetReader("rb", nil, 0, 0, md)), ua.MessageSecurityModeSign, "B"))),
		WithDataSetHandler(rec.handler), WithKeySource("A", regressSource(t, ks, "A")), WithKeySource("B", regressSource(t, ks, "B")))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	pub, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(memConnection("pub", url, uint16(8)),
		Secure(WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds")), ua.MessageSecurityModeSign, "A"))),
		WithDataSource(ds), WithKeySource("A", regressSource(t, ks, "A")))
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })

	require.Eventually(t, func() bool { return len(rec.dataSets()) >= 10 }, 3*time.Second, time.Millisecond)
	for _, d := range rec.dataSets() {
		require.Equal(t, "ra", d.ReaderName, "the reader of SecurityGroup B took a message signed with the keys of A")
	}
}

// Regression (conformance PubSub tests): the decoder required the security
// of the strictest reader that matched a message, so a SignAndEncrypt
// reader of a writer made a Sign reader (or a None reader) of the same
// writer lose every message.
func TestRegressionReadersOfDifferentSecurity(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ks := regressKeys(t, "A")
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(5)))
	pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32))
	md := DataSetMetaDataOf(pds)
	rec := &recorder{}
	sub, err := New(NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		Secure(ReaderGroup("sign", DataSetReader("sign", uint16(8), 1, 1, md)), ua.MessageSecurityModeSign, "A"),
		Secure(ReaderGroup("encrypt", DataSetReader("encrypt", uint16(8), 1, 1, md)), ua.MessageSecurityModeSignAndEncrypt, "A"),
		ReaderGroup("none", DataSetReader("none", uint16(8), 1, 1, md)))),
		WithDataSetHandler(rec.handler), WithKeySource("A", regressSource(t, ks, "A")))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	pub, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(memConnection("pub", url, uint16(8)),
		Secure(WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds")), ua.MessageSecurityModeSign, "A"))),
		WithDataSource(ds), WithKeySource("A", regressSource(t, ks, "A")))
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })

	require.Eventually(t, func() bool {
		n := map[string]int{}
		for _, d := range rec.dataSets() {
			n[d.ReaderName]++
		}
		return n["sign"] >= 5 && n["none"] >= 5
	}, 3*time.Second, time.Millisecond, "the Sign and None readers took nothing because a SignAndEncrypt reader of the same writer exists")
	for _, d := range rec.dataSets() {
		require.NotEqual(t, "encrypt", d.ReaderName, "the SignAndEncrypt reader took a Sign message")
	}
}
