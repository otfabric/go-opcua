// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
	"github.com/stretchr/testify/require"
)

// TestServe_ServiceFaultCarriesRequestHandle: every ServiceFault of the
// dispatcher carries "The requestHandle given by the Client to the
// request" (Part 4 §7.33): a request without an activated session, a
// handler that fails with a StatusCode or with another error, and a
// service the server does not have.
func TestServe_ServiceFaultCarriesRequestHandle(t *testing.T) {
	s := newTestServer()
	failWith := func(err error) Handler {
		return func(context.Context, *uasc.SecureChannel, ua.Request, uint32) (ua.Response, error) { return nil, err }
	}
	findServers := ua.ServiceTypeID(&ua.FindServersRequest{})
	delete(s.handlers, ua.ServiceTypeID(&ua.QueryNextRequest{}))
	s.handlers[ua.ServiceTypeID(&ua.ReadRequest{})] = failWith(nil) // never called: no session
	hdr := func(handle uint32) *ua.RequestHeader { return &ua.RequestHeader{RequestHandle: handle} }
	for _, tc := range []struct {
		name    string
		handler Handler
		req     ua.Request
		status  ua.StatusCode
	}{
		{"no session", nil, &ua.ReadRequest{RequestHeader: hdr(11)}, ua.StatusBadSessionIDInvalid},
		{"handler StatusCode", failWith(ua.StatusBadOutOfRange), &ua.FindServersRequest{RequestHeader: hdr(12)}, ua.StatusBadOutOfRange},
		{"handler error", failWith(errors.New("not a StatusCode")), &ua.FindServersRequest{RequestHeader: hdr(13)}, ua.StatusBadUnexpectedError},
		{"unknown service", nil, &ua.QueryNextRequest{RequestHeader: hdr(14)}, ua.StatusBadServiceUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.handler != nil {
				s.handlers[findServers] = tc.handler
			}
			resp := s.serve(context.Background(), nil, 1, tc.req)
			fault, ok := resp.(*ua.ServiceFault)
			require.True(t, ok, "%T", resp)
			require.Equal(t, tc.status, fault.ResponseHeader.ServiceResult)
			require.Equal(t, requestHandle(tc.req), fault.ResponseHeader.RequestHandle)
		})
	}
}
