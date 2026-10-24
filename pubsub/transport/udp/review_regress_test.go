// SPDX-License-Identifier: MIT

package udp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/pubsub/transport"
)

// Regression: Close waited for the receive goroutine, so a handler that
// closed the connection waited for itself forever.
func TestCloseFromHandler(t *testing.T) {
	closed := make(chan error, 1)
	var sub *Conn
	ready := make(chan struct{})
	sub, port, _ := listen(t, loopback, func(*transport.Message) {
		<-ready
		closed <- sub.Close()
	})
	close(ready)
	pub := open(t, transport.Config{URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port)})
	require.NoError(t, pub.Send(context.Background(), []byte("x"), transport.PublishOptions{}))
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close called from a handler did not return")
	}
}
