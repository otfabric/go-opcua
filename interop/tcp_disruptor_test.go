//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// tcpDisruptor is a stack-neutral localhost TCP forwarder that can drop all
// active connections on demand. Peer reconnect tests dial through the proxy
// endpoint so disruption does not depend on adapter-specific APIs.
type tcpDisruptor struct {
	ln      net.Listener
	backend string

	mu    sync.Mutex
	conns []net.Conn
	stop  chan struct{}
}

func startTCPDisruptor(t *testing.T, backend string) *tcpDisruptor {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := &tcpDisruptor{ln: ln, backend: backend, stop: make(chan struct{})}
	go d.acceptLoop()
	t.Cleanup(func() { d.Close() })
	return d
}

func (d *tcpDisruptor) Addr() string { return d.ln.Addr().String() }

func (d *tcpDisruptor) EndpointURL(path string) string {
	hostport := d.Addr()
	return "opc.tcp://" + hostport + path
}

func (d *tcpDisruptor) acceptLoop() {
	for {
		c, err := d.ln.Accept()
		if err != nil {
			select {
			case <-d.stop:
				return
			default:
				return
			}
		}
		d.mu.Lock()
		d.conns = append(d.conns, c)
		d.mu.Unlock()
		go d.pipe(c)
	}
}

func (d *tcpDisruptor) pipe(client net.Conn) {
	backend, err := net.DialTimeout("tcp", d.backend, 5*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	d.mu.Lock()
	d.conns = append(d.conns, backend)
	d.mu.Unlock()

	done := make(chan struct{}, 2)
	copyClose := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyClose(backend, client)
	go copyClose(client, backend)
	<-done
	_ = client.Close()
	_ = backend.Close()
}

// Disrupt closes every tracked connection without stopping the listener so
// subsequent reconnect dials succeed.
func (d *tcpDisruptor) Disrupt() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		_ = c.Close()
	}
	d.conns = nil
}

func (d *tcpDisruptor) Close() {
	select {
	case <-d.stop:
	default:
		close(d.stop)
	}
	_ = d.ln.Close()
	d.Disrupt()
}
