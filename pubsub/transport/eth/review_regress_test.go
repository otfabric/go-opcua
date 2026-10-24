// SPDX-License-Identifier: MIT

package eth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// Regression: Close waited for the receive goroutine, so a handler that
// closed the connection waited for itself forever.
func TestCloseFromHandler(t *testing.T) {
	env := useFakes(t)
	c := openFake(t, transport.Config{URL: "opc.eth://ff-ff-ff-ff-ff-ff"})
	closed := make(chan error, 1)
	_, err := c.Subscribe(context.Background(), "", 0, func(*transport.Message) { closed <- c.Close() })
	require.NoError(t, err)
	env.link(t, true).in <- fakeFrame{b: frameTo(broadcastMAC(), Address{}, "x")}
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close called from a handler did not return")
	}
	require.ErrorIs(t, c.Send(context.Background(), []byte("x"), transport.PublishOptions{}), transport.ErrClosed)
}

func broadcastMAC() []byte { return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} }
