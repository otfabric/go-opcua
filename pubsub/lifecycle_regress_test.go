// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// Regression (chaos/pubsub): Start right after the context of the previous
// Start was cancelled returned nil without starting anything: the runtime
// still counted as running until the goroutine that watches the old
// context stopped it a moment later, and then it stayed stopped.
func TestRegressionStartAfterCancel(t *testing.T) {
	t.Parallel()
	url := memURL(t)
	p, err := New(NewConfiguration([]*ua.PublishedDataSetDataType{testPDS("pds")},
		AttachWriterGroups(memConnection("c", url, uint16(1)), WriterGroup("wg", 1, 5*time.Millisecond, DataSetWriter("w", 1, "pds")))),
		withFakeCodec())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	conn := mustID(t, p, KindConnection, Root, "c")
	for i := range 50 {
		ctx, cancel := context.WithCancel(context.Background())
		require.NoError(t, p.Start(ctx))
		cancel()
		ctx2, cancel2 := context.WithCancel(context.Background())
		require.NoError(t, p.Start(ctx2))
		time.Sleep(time.Millisecond)
		require.True(t, p.Running(), "iteration %d: the runtime stopped after Start", i)
		waitState(t, p, conn, ua.PubSubStateOperational)
		cancel2()
		require.Eventually(t, func() bool { return !p.Running() }, 3*time.Second, time.Millisecond)
	}
}
