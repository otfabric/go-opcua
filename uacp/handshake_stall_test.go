// SPDX-License-Identifier: MIT

package uacp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// silentListener accepts TCP connections and never sends a byte.
func silentListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return fmt.Sprintf("opc.tcp://%s", ln.Addr().String())
}

// A peer that accepts the TCP connection but never answers the HEL used to
// block Dial forever when the context had no deadline: cancelling the
// context had no effect and the dial timeout only covered the TCP connect.
func TestDialHandshakeHonoursContextCancellation(t *testing.T) {
	endpoint := silentListener(t)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		d := &Dialer{Dialer: &net.Dialer{}} // no dial timeout at all
		_, err := d.Dial(ctx, endpoint)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		t.Fatalf("Dial returned before the context was cancelled: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial returned %v, want context.Canceled", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Dial did not return after its context was cancelled")
	}
}

func TestDialHandshakeHonoursDialTimeout(t *testing.T) {
	endpoint := silentListener(t)

	errCh := make(chan error, 1)
	go func() {
		d := &Dialer{Dialer: &net.Dialer{Timeout: 300 * time.Millisecond}}
		_, err := d.Dial(context.Background(), endpoint)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dial returned %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Dial did not return although the dial timeout expired")
	}
}

// A connection that never sends its HEL must not keep the listener from
// accepting the next one, and is dropped when the listener closes.
func TestListenerAcceptNotBlockedBySilentPeer(t *testing.T) {
	ln, err := Listen(context.Background(), "opc.tcp://127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	type result struct {
		c   *Conn
		err error
	}
	accepted := make(chan result, 1)
	go func() {
		c, err := ln.Accept(context.Background())
		accepted <- result{c, err}
	}()

	// give the listener time to pick up the silent connection first
	time.Sleep(100 * time.Millisecond)

	dialed := make(chan error, 1)
	go func() {
		c, err := Dial(context.Background(), "opc.tcp://"+addr)
		if err == nil {
			defer c.Close()
		}
		dialed <- err
	}()

	select {
	case r := <-accepted:
		if r.err != nil {
			t.Fatalf("Accept: %v", r.err)
		}
		defer r.c.Close()
	case <-time.After(30 * time.Second):
		t.Fatal("Accept is blocked by a connection that never sent a HEL")
	}
	if err := <-dialed; err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Closing the listener ends Accept with net.ErrClosed and drops the
	// connection that is still stuck in its handshake.
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ln.Accept(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v, want net.ErrClosed", err)
	}
	_ = silent.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Fatal("the pending connection was not closed with the listener")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the pending connection was left open after the listener closed")
	}
}
