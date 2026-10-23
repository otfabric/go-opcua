// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// These tests run the real UADP codec (package uadp) over the in-memory
// transport.

func realPair(t *testing.T, adjust func(pub, sub *ua.PubSubConfigurationDataType), opts ...Option) (*PubSub, *recorder) {
	t.Helper()
	url := memURL(t)
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(1)))
	require.NoError(t, ds.Set(nodeB, "hello"))
	require.NoError(t, ds.Set(nodeC, []float64{1.5, 2.5}))
	pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32), Var("b", nodeB, ua.TypeIDString),
		PublishedField{Field: Field{Name: "c", Type: ua.TypeIDDouble, Array: true}, NodeID: nodeC})
	w := DataSetWriter("w", 20, "pds")
	w.KeyFrameCount = 3
	pubCfg := NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		AttachWriterGroups(memConnection("pub", url, uint32(70000)), WriterGroup("wg", 10, 5*time.Millisecond, w, DataSetWriter("hb", 21, ""))))
	subCfg := NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		ReaderGroup("rg", DataSetReader("r", uint32(70000), 10, 20, DataSetMetaDataOf(pds)))))
	if adjust != nil {
		adjust(pubCfg, subCfg)
	}
	rec := &recorder{}
	sub, err := New(subCfg, append([]Option{WithDataSetHandler(rec.handler)}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	pub, err := New(pubCfg, append([]Option{WithDataSource(ds)}, opts...)...)
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })
	go func() {
		for i := range 1000 {
			if pub.Running() {
				_ = ds.Set(nodeA, int32(i))
			}
			time.Sleep(2 * time.Millisecond)
			if !pub.Running() {
				return
			}
		}
	}()
	return sub, rec
}

func checkReceived(t *testing.T, rec *recorder) {
	t.Helper()
	require.Eventually(t, func() bool {
		var key, delta bool
		for _, d := range rec.dataSets() {
			if !d.Complete {
				continue
			}
			require.Equal(t, "hello", d.Field("b").Value.Value())
			require.Equal(t, []float64{1.5, 2.5}, d.Field("c").Value.Value())
			require.Equal(t, uint32(70000), uint32(d.PublisherID.Num))
			if d.MessageType == 0 {
				key = true
			} else {
				delta = true
			}
		}
		return key && delta
	}, 3*time.Second, time.Millisecond)
}

func TestRealUADPVariant(t *testing.T) {
	t.Parallel()
	_, rec := realPair(t, nil)
	checkReceived(t, rec)
}

func TestRealUADPDataValueAndRawData(t *testing.T) {
	t.Parallel()
	for name, mask := range map[string]ua.DataSetFieldContentMask{
		"datavalue": ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp,
		"rawdata":   ua.DataSetFieldContentMaskRawData,
	} {
		t.Run(name, func(t *testing.T) { testRealMask(t, mask) })
	}
}

func testRealMask(t *testing.T, mask ua.DataSetFieldContentMask) {
	t.Parallel()
	{
		_, rec := realPair(t, func(pub, _ *ua.PubSubConfigurationDataType) {
			pub.Connections[0].WriterGroups[0].DataSetWriters[0].DataSetFieldContentMask = mask
		})
		checkReceived(t, rec)
	}
}

func TestRealUADPWithoutPayloadHeader(t *testing.T) {
	t.Parallel()
	_, rec := realPair(t, func(pub, _ *ua.PubSubConfigurationDataType) {
		wg := pub.Connections[0].WriterGroups[0]
		wg.MessageSettings.Value.(*ua.UADPWriterGroupMessageDataType).NetworkMessageContentMask &^= ua.UADPNetworkMessageContentMaskPayloadHeader
		wg.DataSetWriters = wg.DataSetWriters[:1]
	})
	checkReceived(t, rec)
}

func TestRealUADPSecured(t *testing.T) {
	t.Parallel()
	for _, mode := range []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt} {
		t.Run(mode.String(), func(t *testing.T) { testRealSecured(t, mode) })
	}
}

func testRealSecured(t *testing.T, mode ua.MessageSecurityMode) {
	t.Parallel()
	{
		policy := security.Aes256CTR()
		ring := security.NewKeyRing("sg", policy)
		key := make([]byte, policy.KeyLength())
		_, err := rand.Read(key)
		require.NoError(t, err)
		require.NoError(t, ring.SetKeys(policy.URI(), 1, [][]byte{key}, time.Hour, time.Hour))
		sub, rec := realPair(t, func(pub, sub *ua.PubSubConfigurationDataType) {
			Secure(pub.Connections[0].WriterGroups[0], mode, "sg")
			Secure(sub.Connections[0].ReaderGroups[0], mode, "sg")
		}, WithKeySource("sg", ring))
		checkReceived(t, rec)
		st, err := sub.Status(Root)
		require.NoError(t, err)
		require.Zero(t, st.Counters.DecodeErrors, errString(sub))
	}
}
