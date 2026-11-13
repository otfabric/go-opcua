// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// openPair returns a handshaken client and server connection of a listener
// whose connections must open a secure channel within wait.
func openPair(t *testing.T, wait time.Duration) (client, server *Conn) {
	t.Helper()
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	require.NoError(t, err)
	ln.openTimeout = wait
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := ln.Accept(context.Background())
		if err == nil {
			accepted <- c
		}
	}()
	client, err = Dial(context.Background(), "opc.tcp://"+ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	select {
	case server = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("not accepted")
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// rawMessage returns a UACP message of type typ with a body of n bytes.
func rawMessage(typ string, n int) []byte {
	b := make([]byte, hdrlen+n)
	copy(b, typ)
	b[3] = 'F'
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	return b
}

// receiveResult runs Receive in the background.
func receiveResult(c *Conn) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := c.Receive()
		ch <- err
	}()
	return ch
}

func TestListenerOpenDeadline(t *testing.T) {
	const wait = 200 * time.Millisecond

	t.Run("silent after HEL/ACK", func(t *testing.T) {
		_, srv := openPair(t, wait)
		start := time.Now()
		select {
		case err := <-receiveResult(srv):
			require.True(t, errors.Is(err, os.ErrDeadlineExceeded), "got %v", err)
			require.GreaterOrEqual(t, time.Since(start), wait/2)
		case <-time.After(5 * time.Second):
			t.Fatal("a connection without OPN was kept open")
		}
	})

	t.Run("other messages do not count", func(t *testing.T) {
		cli, srv := openPair(t, wait)
		_, err := cli.nc.Write(rawMessage("MSG", 16))
		require.NoError(t, err)
		_, err = srv.Receive()
		require.NoError(t, err)
		select {
		case err := <-receiveResult(srv):
			require.True(t, errors.Is(err, os.ErrDeadlineExceeded), "got %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("the deadline was cleared by a MSG")
		}
	})

	t.Run("cleared by OPN", func(t *testing.T) {
		cli, srv := openPair(t, wait)
		_, err := cli.nc.Write(rawMessage("OPN", 16))
		require.NoError(t, err)
		_, err = srv.Receive()
		require.NoError(t, err)
		ch := receiveResult(srv)
		time.Sleep(3 * wait)
		_, err = cli.nc.Write(rawMessage("MSG", 16))
		require.NoError(t, err)
		select {
		case err := <-ch:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("no message")
		}
	})

	t.Run("dialed connections have no deadline", func(t *testing.T) {
		cli, srv := openPair(t, wait)
		ch := receiveResult(cli)
		time.Sleep(3 * wait)
		_, err := srv.nc.Write(rawMessage("MSG", 16))
		require.NoError(t, err)
		select {
		case err := <-ch:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("no message")
		}
	})
}
