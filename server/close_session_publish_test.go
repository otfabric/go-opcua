// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// TestCloseSession_AnswersQueuedPublishRequests: the Publish requests that
// are queued for a session when it is closed are answered.
//
// Regression (found with chaos TestRegressionReactivatedSessionKeepsSubscriptions):
// they stayed in the queue of the closed session. A client that went on in
// another session waited for its request timeout before it sent the next
// Publish request, and received nothing from any subscription until then.
func TestCloseSession_AnswersQueuedPublishRequests(t *testing.T) {
	srv, err := New(
		EndPoint("localhost", 0),
		EnableSecurity("None", ua.MessageSecurityModeNone),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	defer func() { _ = srv.Close() }()

	sessions := &SessionService{srv: srv}
	resp, err := sessions.CreateSession(context.Background(), scNone(), &ua.CreateSessionRequest{
		RequestHeader:           reqHeader(),
		EndpointURL:             "opc.tcp://localhost:4840",
		RequestedSessionTimeout: 60000,
		ClientNonce:             make([]byte, 32),
	}, 1)
	require.NoError(t, err)
	token := resp.(*ua.CreateSessionResponse).AuthenticationToken
	sess := srv.sb.peek(token)
	require.NotNil(t, sess)

	for id := uint32(10); id < 13; id++ {
		sess.PublishRequests <- PubReq{Req: &ua.PublishRequest{RequestHeader: reqHeader()}, ID: id}
	}

	hdr := reqHeader()
	hdr.AuthenticationToken = token
	_, err = sessions.CloseSession(context.Background(), scNone(), &ua.CloseSessionRequest{RequestHeader: hdr, DeleteSubscriptions: true}, 2)
	require.NoError(t, err)
	require.Empty(t, sess.PublishRequests, "no Publish request is left waiting in a closed session")
	require.Nil(t, srv.sb.peek(token))
}
