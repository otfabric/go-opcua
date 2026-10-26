// SPDX-License-Identifier: MIT

package pubsub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// TestReady waits for the receiving socket of a UDP reader: after Ready
// the port is bound, so a datagram sent now is received.
func TestReady(t *testing.T) {
	t.Parallel()
	addr := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	md := MetaData("DS", Field{Name: "A", Type: ua.TypeIDInt32})
	ps, err := New(NewConfiguration(nil, AttachReaderGroups(UDPConnection("sub", "opc.udp://"+addr, nil),
		ReaderGroup("rg", DataSetReader("r", uint16(5), 1, 1, md)))))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := ps.Ready(ctx); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Ready before Start: %v, want ErrNotRunning", err)
	}
	if err := ps.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ps.Ready(ctx); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if c, err := net.ListenPacket("udp4", addr); err == nil {
		_ = c.Close()
		t.Errorf("%s is not bound after Ready", addr)
	}
	if err := ps.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ps.Ready(ctx); !errors.Is(err, ErrClosed) {
		t.Errorf("Ready after Close: %v, want ErrClosed", err)
	}
}

// TestReadyWaitsForTheTransport: a broker that cannot be reached keeps
// Ready waiting until its context ends, or until the runtime stops.
func TestReadyWaitsForTheTransport(t *testing.T) {
	t.Parallel()
	ps, err := New(NewConfiguration(nil, MQTTConnection("sub", "mqtt://127.0.0.1:1", nil, MappingUADP)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ps.Close() }()
	run, stop := context.WithCancel(context.Background())
	if err := ps.Start(run); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := ps.Ready(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Ready: %v, want the deadline", err)
	}

	done := make(chan error, 1)
	go func() { done <- ps.Ready(context.Background()) }()
	stop()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRunning) {
			t.Errorf("Ready while stopping: %v, want ErrNotRunning", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Ready did not return when the runtime stopped")
	}
}
