// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/internal/testutil"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// tokenSniffer forwards one client connection to the server and records, in
// wire order, what the server sends back: every OpenSecureChannel response and
// the SecurityToken id of every symmetric message.
type tokenSniffer struct {
	ln net.Listener

	mu       sync.Mutex
	backend  string
	opens    int
	tokenIDs []uint32 // token id of each server MSG chunk, in order
}

func startTokenSniffer(t *testing.T) *tokenSniffer {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	s := &tokenSniffer{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			backend := s.backend
			s.mu.Unlock()
			server, err := net.DialTimeout("tcp", backend, 5*time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			go func() {
				_, _ = io.Copy(server, client)
				_ = server.Close()
			}()
			go func() {
				s.forward(client, server)
				_ = client.Close()
				_ = server.Close()
			}()
		}
	}()
	return s
}

// forward copies server→client one UACP message at a time so the secure
// conversation headers can be inspected.
func (s *tokenSniffer) forward(client, server net.Conn) {
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(server, hdr); err != nil {
			return
		}
		size := binary.LittleEndian.Uint32(hdr[4:])
		if size < 8 || size > 1<<24 {
			return
		}
		body := make([]byte, size-8)
		if _, err := io.ReadFull(server, body); err != nil {
			return
		}

		switch string(hdr[:3]) {
		case "OPN":
			s.mu.Lock()
			s.opens++
			s.mu.Unlock()
		case "MSG":
			// SecureChannelId(4) | TokenId(4) | ...
			if len(body) >= 8 {
				s.mu.Lock()
				s.tokenIDs = append(s.tokenIDs, binary.LittleEndian.Uint32(body[4:8]))
				s.mu.Unlock()
			}
		}

		if _, err := client.Write(append(hdr[:8:8], body...)); err != nil {
			return
		}
	}
}

func (s *tokenSniffer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *tokenSniffer) setBackend(addr string) {
	s.mu.Lock()
	s.backend = addr
	s.mu.Unlock()
}

func (s *tokenSniffer) snapshot() (opens int, tokenIDs []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opens, append([]uint32(nil), s.tokenIDs...)
}

// TestTokenRenewal runs the tests that renew the SecurityToken of a channel
// on a 2 s lifetime. Each of them has to wait for several renewals, so they
// run next to each other; and they run before the parallel tests of the
// package start (the parent is not parallel), because a renewal that is
// starved of CPU for longer than the token's grace period loses the channel.
func TestTokenRenewal(t *testing.T) {
	for name, test := range map[string]func(*testing.T){
		"ServerRotatesSecurityToken": testChannelRenewalServerRotatesSecurityToken,
		"ECC_UnderTraffic":           testECCRenewalUnderTraffic,
		"AEAD_UnderTraffic":          testAEADRenewalUnderTraffic,
	} {
		t.Run(name, func(t *testing.T) {
			parallel(t)
			test(t)
		})
	}
}

// testChannelRenewalServerRotatesSecurityToken pins the server side of
// SecurityToken renewal (Part 4 §5.5.2): each renewal must hand out a new
// TokenId, the server must secure its messages with that token afterwards, and
// traffic — including a running subscription — must not be disturbed.
//
// A server that renews in place (same TokenId, new keys) works against this
// client but breaks every stack that selects keys by TokenId.
func testChannelRenewalServerRotatesSecurityToken(t *testing.T) {
	// The server validates the endpoint URL of the Hello message, so it
	// advertises the sniffer's port while listening on its own.
	sniffer := startTokenSniffer(t)
	srv, err := server.New(
		server.EndPoint("localhost", sniffer.port()),
		server.ListenOn("localhost:0"),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start(context.Background()))
	t.Cleanup(func() { _ = srv.Close() })
	sniffer.setBackend(fmt.Sprintf("localhost:%d", srv.Port()))
	f := testutil.AddFixture(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A 2 s lifetime makes the client renew every second.
	c, err := opcua.NewClient(fmt.Sprintf("opc.tcp://localhost:%d", sniffer.port()),
		opcua.InsecureNoSecurity(),
		opcua.Lifetime(2*time.Second),
		opcua.DialTimeout(30*time.Second),
		opcua.RequestTimeout(30*time.Second),
	)
	require.NoError(t, err)
	require.NoError(t, c.Connect(ctx))
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	sub, notifyCh, err := c.NewSubscription().
		Interval(50 * time.Millisecond).
		Monitor(f.Writable).
		Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })

	// Keep reads, writes and publishes flowing until three renewals happened.
	deadline := time.Now().Add(30 * time.Second)
	var written int32
	for {
		opens, _ := sniffer.snapshot()
		if opens >= 4 { // issue + 3 renewals
			break
		}
		require.True(t, time.Now().Before(deadline), "only %d OpenSecureChannel responses within 30s", opens)

		written++
		status, err := c.WriteValue(ctx, f.Writable, &ua.DataValue{
			EncodingMask: ua.DataValueValue,
			Value:        ua.MustVariant(written),
		})
		require.NoError(t, err)
		require.Equal(t, ua.StatusOK, status)

		dv, err := c.ReadValue(ctx, f.Writable)
		require.NoError(t, err)
		require.Equal(t, written, dv.Value.Value())
		time.Sleep(20 * time.Millisecond)
	}

	// The subscription delivered the last written value across the renewals.
	sawLast := false
	timeout := time.After(15 * time.Second)
	for !sawLast {
		select {
		case msg := <-notifyCh:
			require.NoError(t, msg.Error)
			dcn, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, mi := range dcn.MonitoredItems {
				if mi.Value != nil && mi.Value.Value != nil && mi.Value.Value.Value() == written {
					sawLast = true
				}
			}
		case <-timeout:
			t.Fatalf("subscription never delivered the last written value %d", written)
		}
	}

	_, tokenIDs := sniffer.snapshot()
	require.NotEmpty(t, tokenIDs)

	// Token ids appear in issue order and are never reused: once the server
	// moves to a renewed token it does not fall back to an older one.
	var order []uint32
	seen := map[uint32]bool{}
	for _, id := range tokenIDs {
		if len(order) > 0 && order[len(order)-1] == id {
			continue
		}
		require.False(t, seen[id], "server went back to SecurityToken %d after using a newer one (sequence %v)", id, order)
		seen[id] = true
		order = append(order, id)
	}
	require.GreaterOrEqual(t, len(order), 3,
		"server secured its messages with only %d distinct SecurityTokens across 3 renewals: %v", len(order), order)
}
