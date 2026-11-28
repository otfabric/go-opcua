// SPDX-License-Identifier: MIT

package filetransfer_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/filetransfer"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// TestFileHandleSurvivesChannel: a file handle belongs to the session, not
// to the secure channel or the connection (OPC 10000-20 §4.2.2: "a file
// handle that is valid while the session is open"). It stays valid across a
// renewal of the security token and across a connection that breaks, after
// which the client activates the same session on a new channel, and a
// writer keeps its exclusive lock meanwhile. Closing the session releases
// the handles.
func TestFileHandleSurvivesChannel(t *testing.T) {
	srv, url := testutil.NewTestServer(t)
	ns := server.NewNodeNameSpace(srv, "urn:test:filetransfer:session")
	e := &env{srv: srv, ns: ns, url: url}
	nid, fo := e.addFile(t, "F", server.FileConfig{Backend: server.NewMemoryFile([]byte("0123456789")), Writable: true})
	wid, wo := e.addFile(t, "W", server.FileConfig{Backend: server.NewMemoryFile(nil), Writable: true})

	proxy := testutil.NewChaosProxy(t, strings.TrimPrefix(url, "opc.tcp://"), 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := opcua.NewClient(proxy.EndpointURL(), opcua.InsecureNoSecurity(),
		opcua.AutoReconnect(true), opcua.ReconnectInterval(50*time.Millisecond),
		opcua.RequestTimeout(10*time.Second), opcua.DialTimeout(10*time.Second))
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	other := testutil.NewTestClient(t, url)
	sessionID := c.Session().SessionID()

	f, err := filetransfer.NewObject(c, nid).Open(ctx, ua.OpenFileModeRead)
	require.NoError(t, err)
	w, err := filetransfer.NewObject(c, wid).Open(ctx, ua.OpenFileModeWrite)
	require.NoError(t, err)
	read := func(want string) {
		t.Helper()
		b, err := f.Read(ctx, 3)
		require.NoError(t, err)
		require.Equal(t, want, string(b))
	}
	read("012")

	// A renewal of the security token.
	require.NoError(t, c.SecureChannel().Renew(ctx))
	read("345")

	// The connection breaks; the client reconnects and activates the same
	// session on a new secure channel.
	accepted := proxy.Accepted()
	proxy.DropAll()
	require.Eventually(t, func() bool {
		return proxy.Accepted() > accepted && c.State() == opcua.Connected
	}, 30*time.Second, 20*time.Millisecond, "the client reconnects")
	require.True(t, sessionID.Equal(c.Session().SessionID()), "the session survives")
	read("678")
	require.Equal(t, 1, fo.OpenCount())
	require.Equal(t, 1, wo.OpenCount())
	_, err = filetransfer.NewObject(other, wid).Open(ctx, ua.OpenFileModeWrite)
	require.ErrorIs(t, err, ua.StatusBadNotWritable, "the writer keeps its lock")
	require.NoError(t, w.Write(ctx, []byte("kept")))

	// The end of the session releases them.
	require.NoError(t, c.Close(ctx))
	require.Equal(t, 0, fo.OpenCount())
	require.Equal(t, 0, wo.OpenCount())
	h, err := filetransfer.NewObject(other, wid).Open(ctx, ua.OpenFileModeWrite)
	require.NoError(t, err)
	require.NoError(t, h.Close(ctx))
}
