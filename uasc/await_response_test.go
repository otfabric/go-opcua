// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// When the peer answers a request with an Error message and closes the
// connection, the dispatcher hands the error to the waiting handler and then
// marks the channel disconnected. Both are observable at the same moment; the
// caller must get the peer's status code, never a bare io.EOF.
func TestAwaitResponse_DeliveredErrorWinsOverDisconnect(t *testing.T) {
	for i := 0; i < 500; i++ {
		s := &SecureChannel{
			disconnected: make(chan struct{}),
			handlers:     map[uint32]chan *MessageBody{},
		}
		ch := make(chan *MessageBody, 1)
		ch <- &MessageBody{Err: ua.StatusBadSecurityPolicyRejected}
		close(s.disconnected)

		err := s.awaitResponse(context.Background(), 1, ch, time.Minute, func(ua.Response) error { return nil })
		require.ErrorIs(t, err, ua.StatusBadSecurityPolicyRejected, "iteration %d", i)
	}
}

// The same holds when the caller's context ends at the moment the response
// arrives: a response that was delivered is not thrown away.
func TestAwaitResponse_DeliveredResponseWinsOverCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 500; i++ {
		s := &SecureChannel{
			disconnected: make(chan struct{}),
			handlers:     map[uint32]chan *MessageBody{},
		}
		ch := make(chan *MessageBody, 1)
		ch <- &MessageBody{Err: ua.StatusBadNonceInvalid}

		err := s.awaitResponse(ctx, 1, ch, time.Minute, func(ua.Response) error { return nil })
		require.ErrorIs(t, err, ua.StatusBadNonceInvalid, "iteration %d", i)
	}
}
