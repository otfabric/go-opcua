// SPDX-License-Identifier: MIT

package pubsub

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Regression (chaos/pubsub MQTT outage): a writer that sends delta frames
// counted a change as sent when it built the delta frame. When the message
// could not be sent (an MQTT QoS 0 publication while the broker is down, a
// send error), the change was gone until the next key frame - with a
// KeyFrameCount of 1000, ten seconds at 10 ms. A writer whose message was
// not sent now sends a key frame next.
func TestRegressionChangeLostWithFailedSend(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	ds := NewMemoryDataSource()
	require.NoError(t, ds.Set(nodeA, int32(1)))
	pds := PublishedDataItems("pds", Var("a", nodeA, ua.TypeIDInt32))
	w := DataSetWriter("w", 1, "pds")
	w.KeyFrameCount = 1000
	rec := &recorder{}
	start(t, NewConfiguration(nil, AttachReaderGroups(memConnection("sub", url, nil),
		ReaderGroup("rg", DataSetReader("r", uint16(7), 1, 1, DataSetMetaDataOf(pds))))), WithDataSetHandler(rec.handler))
	require.Eventually(t, func() bool { return bus.subscribers(url) > 0 }, 3*time.Second, time.Millisecond)
	pub := start(t, NewConfiguration([]*ua.PublishedDataSetDataType{pds}, AttachWriterGroups(memConnection("pub", url, uint16(7)),
		WriterGroup("wg", 1, 5*time.Millisecond, w))), WithDataSource(ds))
	require.Eventually(t, func() bool { return len(rec.dataSets()) > 0 }, 3*time.Second, time.Millisecond)

	wgid := mustID(t, pub, KindWriterGroup, mustID(t, pub, KindConnection, Root, "pub"), "wg")
	bus.mu.Lock()
	bus.failSend[url] = true
	bus.mu.Unlock()
	require.NoError(t, ds.Set(nodeA, int32(2)))
	require.Eventually(t, func() bool {
		st, err := pub.Status(wgid)
		return err == nil && st.Counters.SendErrors >= 1
	}, 3*time.Second, time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	bus.mu.Lock()
	bus.failSend[url] = false
	bus.mu.Unlock()

	require.Eventually(t, func() bool {
		ds := rec.dataSets()
		return int32Values(ds[len(ds)-1])[0] == 2
	}, time.Second, time.Millisecond, "the change made while sending failed was not delivered")
	ds2 := rec.dataSets()
	require.Equal(t, message.DataSetMessageKeyFrame, ds2[len(ds2)-1].MessageType)
}
