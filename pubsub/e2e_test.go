// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// End-to-end tests with the real codecs and transports.

func runPair(t *testing.T, pubCfg, subCfg *ua.PubSubConfigurationDataType, ds *MemoryDataSource) *recorder {
	t.Helper()
	rec := &recorder{}
	sub, err := New(subCfg, WithDataSetHandler(rec.handler))
	require.NoError(t, err)
	require.NoError(t, sub.Start(context.Background()))
	t.Cleanup(func() { _ = sub.Close() })
	pub, err := New(pubCfg, WithDataSource(ds))
	require.NoError(t, err)
	require.NoError(t, pub.Start(context.Background()))
	t.Cleanup(func() { _ = pub.Close() })
	return rec
}

func e2eData(t *testing.T) (*MemoryDataSource, *ua.PublishedDataSetDataType) {
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(11)))
	require.NoError(t, ds.Set(nodeB, "text"))
	return ds, PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32), Var("b", nodeB, ua.TypeIDString))
}

func waitData(t *testing.T, rec *recorder) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, d := range rec.dataSets() {
			if d.Complete && d.Field("a") != nil && d.Field("a").Value.Value() == int32(11) && d.Field("b").Value.Value() == "text" {
				return true
			}
		}
		return false
	}, 5*time.Second, 2*time.Millisecond)
}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func TestE2EUDP(t *testing.T) {
	t.Parallel()
	ds, pds := e2eData(t)
	url := fmt.Sprintf("opc.udp://127.0.0.1:%d", freeUDPPort(t))
	pubCfg := NewConfiguration([]*ua.PublishedDataSetDataType{pds},
		AttachWriterGroups(UDPConnection("pub", url, uint16(5)), WriterGroup("wg", 1, 10*time.Millisecond, DataSetWriter("w", 1, "pds"))))
	subCfg := NewConfiguration(nil, AttachReaderGroups(UDPConnection("sub", url, nil),
		ReaderGroup("rg", DataSetReader("r", uint16(5), 1, 1, DataSetMetaDataOf(pds)))))
	waitData(t, runPair(t, pubCfg, subCfg, ds))
}

func TestE2EMQTT(t *testing.T) {
	t.Parallel()
	b := mqttbroker.New(mqttbroker.Options{})
	require.NoError(t, b.Start())
	t.Cleanup(b.Close)
	for _, m := range []MessageMapping{MappingJSON, MappingUADP} {
		t.Run(fmt.Sprint(m), func(t *testing.T) {
			t.Parallel()
			ds, pds := e2eData(t)
			q := fmt.Sprintf("test/%d", m)
			w := SetWriterQueue(DataSetWriter("w", 1, "pds"), q, q+"/meta")
			var wg *ua.WriterGroupDataType
			if m == MappingJSON {
				wg = JSONWriterGroup("wg", 1, 10*time.Millisecond, q, w)
			} else {
				wg = WriterGroup("wg", 1, 10*time.Millisecond, w)
			}
			pubCfg := NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(MQTTConnection("pub", b.URL(), uint16(5), m), wg))
			// The subscriber learns the DataSetMetaData from the broker.
			subCfg := NewConfiguration(nil, AttachReaderGroups(MQTTConnection("sub", b.URL(), nil, m),
				ReaderGroup("rg", SetReaderQueue(DataSetReader("r", uint16(5), 0, 1, nil), q, q+"/meta"))))
			waitData(t, runPair(t, pubCfg, subCfg, ds))
		})
	}
}
