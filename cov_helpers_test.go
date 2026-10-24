// SPDX-License-Identifier: MIT

package opcua_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/internal/testutil/testport"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
	"github.com/otfabric/go-opcua/uasc"
)

// newScriptedServer starts an in-process server whose service handlers for
// the given type ids are replaced by the given ones (fault injection: a
// server that answers with malformed or unexpected responses). It returns
// the server and its endpoint URL.
func newScriptedServer(t *testing.T, handlers map[uint16]server.Handler, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	port := testport.TCP(t)
	srv := startScriptedServer(t, handlers, append([]server.Option{server.EndPoint("localhost", port)}, opts...)...)
	return srv, fmt.Sprintf("opc.tcp://localhost:%d", port)
}

// newProxiedServer is newScriptedServer for a server behind proxy: it
// advertises the proxy's endpoint and listens on a port of its own. It
// returns the address to give the proxy as backend.
func newProxiedServer(t *testing.T, proxy *testutil.ChaosProxy, handlers map[uint16]server.Handler) string {
	t.Helper()
	srv := startScriptedServer(t, handlers, server.EndPoint("localhost", proxy.Port()), server.ListenOn("localhost:0"))
	return fmt.Sprintf("localhost:%d", srv.Port())
}

func startScriptedServer(t *testing.T, handlers map[uint16]server.Handler, opts ...server.Option) *server.Server {
	t.Helper()
	all := append([]server.Option{
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}, opts...)
	srv, err := server.New(all...)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	// RegisterHandler keeps the first handler registered for a type id, and
	// the built-in handlers are registered by Start: register ours first.
	for typeID, h := range handlers {
		srv.RegisterHandler(typeID, h)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// newCovClient returns a client for url that is not connected yet and is
// closed when the test ends. Auto reconnect is off unless opts turn it on.
func newCovClient(t *testing.T, url string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	all := append([]opcua.Option{
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.AutoReconnect(false),
		opcua.DialTimeout(30 * time.Second),
		opcua.RequestTimeout(30 * time.Second),
		opcua.Dialer(&uacp.Dialer{Dialer: &net.Dialer{}}),
	}, opts...)
	c, err := opcua.NewClient(url, all...)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// connectCovClient is newCovClient followed by Connect.
func connectCovClient(t *testing.T, url string, opts ...opcua.Option) *opcua.Client {
	t.Helper()
	c := newCovClient(t, url, opts...)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return c
}

// okHeader is a ResponseHeader with a Good service result for req.
func okHeader(req ua.Request) *ua.ResponseHeader {
	return &ua.ResponseHeader{
		Timestamp:          time.Now(),
		RequestHandle:      req.Header().RequestHandle,
		ServiceResult:      ua.StatusOK,
		ServiceDiagnostics: &ua.DiagnosticInfo{},
		StringTable:        []string{},
		AdditionalHeader:   ua.NewExtensionObject(nil),
	}
}

// respond returns a handler that answers every request with the response
// built by fn.
func respond(fn func(req ua.Request) ua.Response) server.Handler {
	return func(_ context.Context, _ *uasc.SecureChannel, req ua.Request, _ uint32) (ua.Response, error) {
		return fn(req), nil
	}
}

// readHandler returns a Read handler that answers each ReadValueID with the
// DataValue fn returns for it. The namespace array is always answered
// properly, so that clients can connect.
func readHandler(fn func(rv *ua.ReadValueID) *ua.DataValue) server.Handler {
	return respond(func(r ua.Request) ua.Response {
		req := r.(*ua.ReadRequest)
		res := &ua.ReadResponse{ResponseHeader: okHeader(req)}
		for _, rv := range req.NodesToRead {
			if rv.NodeID.Namespace() == 0 && rv.NodeID.IntID() == id.ServerNamespaceArray {
				res.Results = append(res.Results, &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        ua.MustVariant([]string{"http://opcfoundation.org/UA/"}),
				})
				continue
			}
			res.Results = append(res.Results, fn(rv))
		}
		return res
	})
}

// valueDV is a Good DataValue holding v.
func valueDV(v any) *ua.DataValue {
	return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}
}
