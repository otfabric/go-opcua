// SPDX-License-Identifier: MIT

// Package testutil provides test server and client helpers for OPC UA unit tests.
package testutil

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

func NewTestServer(t *testing.T, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	port := freePort(t)
	url := fmt.Sprintf("opc.tcp://localhost:%d", port)
	defaults := []server.Option{
		server.EndPoint("localhost", port),
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	}
	all := append(defaults, opts...)
	srv, err := server.New(all...)
	if err != nil {
		t.Fatalf("testutil: new server: %v", err)
	}
	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("testutil: start server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, url
}

func NewTestClient(t *testing.T, url string) *opcua.Client {
	t.Helper()
	ctx := context.Background()
	c, err := opcua.NewClient(url,
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.DialTimeout(30*time.Second),    // allow time for server to accept under load (e.g. race detector)
		opcua.RequestTimeout(30*time.Second), // allow handshake to complete under load
		opcua.Dialer(&uacp.Dialer{
			Dialer: &net.Dialer{},
			ClientACK: &uacp.Acknowledge{
				ReceiveBufSize: uacp.DefaultReceiveBufSize,
				SendBufSize:    uacp.DefaultSendBufSize,
				MaxChunkCount:  0,
				MaxMessageSize: 0,
			},
		}),
	)
	if err != nil {
		t.Fatalf("testutil: new client: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("testutil: connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })
	return c
}

func AddTestNodes(t *testing.T, srv *server.Server) *server.NodeNameSpace {
	t.Helper()
	root, err := srv.Namespace(0)
	if err != nil {
		t.Fatalf("testutil: namespace 0: %v", err)
	}
	rootObj := root.Objects()
	ns := server.NewNodeNameSpace(srv, "TestNodes")
	obj := ns.Objects()
	rootObj.AddRef(obj, id.HasComponent, true)
	v1 := ns.AddNewVariableStringNode("IntVar", int32(42))
	obj.AddRef(v1, id.HasComponent, true)
	v2 := ns.AddNewVariableStringNode("FloatVar", float64(3.14))
	obj.AddRef(v2, id.HasComponent, true)
	v3 := ns.AddNewVariableStringNode("StringVar", "hello")
	obj.AddRef(v3, id.HasComponent, true)
	return ns
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("testutil: free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
