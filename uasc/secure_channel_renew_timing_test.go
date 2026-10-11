// SPDX-License-Identifier: MIT

package uasc

import (
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// A token with a lifetime of about a second must not be renewed right away:
// the renewal delay used to be computed from the lifetime rounded down to
// whole seconds, which is zero for every lifetime below 1.34s and made the
// client renew its token in a tight loop.
func TestScheduleRenewalWaitsForSubSecondLifetimes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 1024)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}
	}()
	tc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	conn, err := uacp.NewConn(tc.(*net.TCPConn), nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		RequestTimeout:    50 * time.Millisecond,
		Logger:            testLogger,
	}
	errCh := make(chan error, 1)
	s, err := NewSecureChannel("opc.tcp://"+ln.Addr().String(), conn, cfg, errCh)
	if err != nil {
		t.Fatal(err)
	}

	instance := newChannelInstance(s)
	instance.revisedLifetime = 1200 * time.Millisecond // renew after 900ms

	done := make(chan struct{})
	go func() {
		s.scheduleRenewal(instance)
		close(done)
	}()

	// With the truncation the renewal starts at once and fails after the
	// 50ms request timeout (nobody answers), long before 600ms.
	select {
	case err := <-errCh:
		t.Fatalf("renewal was attempted immediately: %v", err)
	case <-done:
		t.Fatal("scheduleRenewal returned immediately")
	case <-time.After(600 * time.Millisecond):
	}

	// closing the channel stops the pending renewal
	close(s.closing)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("scheduleRenewal did not stop when the channel was closed")
	}
}
