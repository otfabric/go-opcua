// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

func rootCounters(t *testing.T, p *PubSub) Counters {
	t.Helper()
	st, err := p.Status(Root)
	require.NoError(t, err)
	return st.Counters
}

// A panicking DataSetHandler must not take the program down: the panic is
// counted, the other handlers and later messages are still served.
func TestRecoversHandlerPanic(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	f := subscriberOnly(t, nil, WithDataSetHandler(func(*ReceivedDataSet) {
		if calls.Add(1) == 1 {
			panic("application bug")
		}
	}))
	f.sendSync(msg(message.DataSetMessageKeyFrame, 1, 1, 2, 3))
	f.sendSync(msg(message.DataSetMessageKeyFrame, 2, 4, 5, 6))
	require.Eventually(t, func() bool { return len(f.rec.dataSets()) == 2 && calls.Load() == 2 }, 2*time.Second, time.Millisecond)
	require.Equal(t, uint64(1), rootCounters(t, f.p).Panics)
}

// A panicking DataSource yields Bad fields; publishing goes on.
func TestRecoversDataSourcePanic(t *testing.T) {
	t.Parallel()
	f := publisherOnly(t, func(url string) *ua.PubSubConnectionDataType {
		return AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 20*time.Millisecond, DataSetWriter("w", 1, "pds")))
	}, []*ua.PublishedDataSetDataType{testPDS("pds")},
		WithDataSource(DataSourceFunc(func(context.Context, []*ua.PublishedVariableDataType) []*ua.DataValue {
			panic("data source bug")
		})))
	nms := f.waitSent(3)
	require.NotEmpty(t, nms[0].Msgs)
	require.GreaterOrEqual(t, rootCounters(t, f.p).Panics, uint64(3))
}

// panicCodec panics while decoding.
type panicCodec struct{ fakeCodec }

func (panicCodec) Decode([]byte, *decodeOptions) (*message.NetworkMessage, error) {
	panic("decoder bug")
}

// A decoder that panics on a received message costs that message only.
func TestRecoversDecodePanic(t *testing.T) {
	t.Parallel()
	f := subscriberOnly(t, nil, func(o *options) { o.codecs = func(e encoding) codec { return panicCodec{fakeCodec{enc: e}} } })
	f.send(msg(message.DataSetMessageKeyFrame, 1, 1, 2, 3))
	f.send(msg(message.DataSetMessageKeyFrame, 2, 1, 2, 3))
	require.Eventually(t, func() bool {
		c := rootCounters(t, f.p)
		return c.Panics == 2 && c.DecodeErrors == 2
	}, 2*time.Second, time.Millisecond)
	require.Empty(t, f.rec.dataSets())
}
