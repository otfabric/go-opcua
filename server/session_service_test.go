// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionService_Cancel(t *testing.T) {
	srv := newTestServer()
	svc := &SessionService{srv: srv}

	// Create a session for the cancel tests.
	sess := srv.sb.NewSession()
	hdr := &ua.RequestHeader{
		RequestHandle:       1,
		AuthenticationToken: sess.AuthTokenID,
	}

	t.Run("cancel with no outstanding requests", func(t *testing.T) {
		req := &ua.CancelRequest{
			RequestHeader: hdr,
			RequestHandle: 42,
		}
		resp, err := svc.Cancel(context.Background(), nil, req, 1)
		require.NoError(t, err)

		cancelResp := resp.(*ua.CancelResponse)
		assert.Equal(t, ua.StatusOK, cancelResp.ResponseHeader.ServiceResult)
		assert.Equal(t, uint32(0), cancelResp.CancelCount)
	})

	t.Run("cancel matching publish request", func(t *testing.T) {
		// Queue a publish request with handle 99.
		sess.PublishRequests <- PubReq{
			Req: &ua.PublishRequest{
				RequestHeader: &ua.RequestHeader{RequestHandle: 99},
			},
			ID: 10,
		}
		// Queue another with handle 100.
		sess.PublishRequests <- PubReq{
			Req: &ua.PublishRequest{
				RequestHeader: &ua.RequestHeader{RequestHandle: 100},
			},
			ID: 11,
		}

		req := &ua.CancelRequest{
			RequestHeader: hdr,
			RequestHandle: 99,
		}
		resp, err := svc.Cancel(context.Background(), nil, req, 2)
		require.NoError(t, err)

		cancelResp := resp.(*ua.CancelResponse)
		assert.Equal(t, ua.StatusOK, cancelResp.ResponseHeader.ServiceResult)
		assert.Equal(t, uint32(1), cancelResp.CancelCount)

		// The non-matching request should remain.
		assert.Len(t, sess.PublishRequests, 1)
		remaining := <-sess.PublishRequests
		assert.Equal(t, uint32(100), remaining.Req.RequestHeader.RequestHandle)
	})

	t.Run("wrong request type", func(t *testing.T) {
		_, err := svc.Cancel(context.Background(), nil, &ua.ReadRequest{RequestHeader: reqHeader()}, 1)
		assert.Error(t, err)
	})
}
