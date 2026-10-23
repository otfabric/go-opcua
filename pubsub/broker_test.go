// SPDX-License-Identifier: MIT

package pubsub

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func TestBrokerJSONWithMetaData(t *testing.T) {
	t.Parallel()
	for _, mapping := range []MessageMapping{MappingJSON, MappingUADP} {
		t.Run(map[MessageMapping]string{MappingJSON: "json", MappingUADP: "uadp"}[mapping], func(t *testing.T) {
			t.Parallel()
			url := memURL(t)
			ds := NewMemoryDataSource()
			require.NoError(t, ds.Set(nodeA, int32(1)))
			require.NoError(t, ds.Set(nodeB, int32(2)))
			require.NoError(t, ds.Set(nodeC, int32(3)))
			own := SetWriterQueue(DataSetWriter("own", 2, "pds"), "plant/own", "plant/own/meta")
			own.TransportSettings.Value.(*ua.BrokerDataSetWriterTransportDataType).MetaDataUpdateTime = 30
			var wg *ua.WriterGroupDataType
			if mapping == MappingJSON {
				wg = JSONWriterGroup("wg", 1, 10*time.Millisecond, "plant/data", DataSetWriter("shared", 1, "pds"), own)
			} else {
				wg = WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("shared", 1, "pds"), own)
				wg.TransportSettings = ua.NewExtensionObject(&ua.BrokerWriterGroupTransportDataType{QueueName: "plant/data", RequestedDeliveryGuarantee: ua.BrokerTransportQoSBestEffort})
			}
			pub := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")}, AttachWriterGroups(brokerConnection("pub", url, "publisher-1", mapping), wg)),
				WithDataSource(ds))
			require.Eventually(t, func() bool {
				var meta, data, ownq bool
				for _, s := range bus.sentTo(url) {
					switch s.Topic {
					case "plant/own/meta":
						meta = s.Retain && s.QoS == 1
					case "plant/data":
						data = true
						if mapping == MappingUADP {
							require.Zero(t, s.QoS)
						} else {
							require.Equal(t, byte(1), s.QoS)
						}
					case "plant/own":
						ownq = true
					}
				}
				return meta && data && ownq
			}, 2*time.Second, time.Millisecond)

			// A late subscriber without metadata learns it from the retained
			// announcement.
			rec := &recorder{}
			sub := start(t, NewConfiguration(nil, AttachReaderGroups(brokerConnection("sub", url, nil, mapping),
				ReaderGroup("rg",
					SetReaderQueue(DataSetReader("r", "publisher-1", 0, 2, nil), "plant/+", "plant/own/meta"),
					SetReaderQueue(DataSetReader("other", "publisher-2", 0, 0, nil), "plant/data", ""),
				))), WithDataSetHandler(rec.handler))
			require.Eventually(t, func() bool {
				for _, d := range rec.dataSets() {
					if d.ReaderName == "r" && d.Fields[0].Name == "a" && d.Complete {
						return true
					}
				}
				return false
			}, 2*time.Second, time.Millisecond)
			for _, d := range rec.dataSets() {
				require.Equal(t, "r", d.ReaderName)
				require.Equal(t, uint16(2), d.DataSetWriterID)
				require.Equal(t, "publisher-1", d.PublisherID.Str)
			}
			rid := mustID(t, sub, KindDataSetReader, mustID(t, sub, KindReaderGroup, mustID(t, sub, KindConnection, Root, "sub"), "rg"), "r")
			cfg, err := sub.DataSetReaderConfig(rid)
			require.NoError(t, err)
			require.Len(t, cfg.DataSetMetaData.Fields, 3)
			st, err := sub.Status(rid)
			require.NoError(t, err)
			require.Positive(t, st.Counters.MetaDataReceived)
			pst, err := pub.Status(Root)
			require.NoError(t, err)
			require.GreaterOrEqual(t, pst.Counters.MetaDataSent, uint64(1))
		})
	}
}

func TestBrokerValidation(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	p := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")}, brokerConnection("c", url, uint16(1), MappingJSON)))
	conn := mustID(t, p, KindConnection, Root, "c")
	wg, err := p.AddWriterGroup(conn, WriterGroup("nq", 1, time.Second))
	require.NoError(t, err)
	_, err = p.AddDataSetWriter(wg, DataSetWriter("w", 1, "pds"))
	require.ErrorContains(t, err, "QueueName")
	rg, err := p.AddReaderGroup(conn, ReaderGroup("rg"))
	require.NoError(t, err)
	_, err = p.AddDataSetReader(rg, DataSetReader("r", nil, 0, 0, nil))
	require.ErrorContains(t, err, "QueueName")
}
