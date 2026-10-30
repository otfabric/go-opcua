// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// startFuzzServer starts the server all inputs of a fuzz target talk to; it
// is closed when the target ends.
func startFuzzServer(f *testing.F) string {
	f.Helper()
	s, err := New(
		EndPoint("localhost", 0),
		ListenOn("127.0.0.1:0"),
		InsecureNoSecurity(),
		EnableAuthMode(ua.UserTokenTypeAnonymous),
	)
	if err != nil {
		f.Fatalf("fuzz server: %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		f.Fatalf("fuzz server: %v", err)
	}
	f.Cleanup(func() { _ = s.Close() })
	return fmt.Sprintf("127.0.0.1:%d", s.Port())
}

// helloMessage returns a valid Hello message for the endpoint url.
func helloMessage(url string) []byte {
	body := new(bytes.Buffer)
	for _, v := range []uint32{0, 1 << 16, 1 << 16, 0, 0} { // version, buffers, limits
		_ = binary.Write(body, binary.LittleEndian, v)
	}
	_ = binary.Write(body, binary.LittleEndian, int32(len(url)))
	body.WriteString(url)
	msg := new(bytes.Buffer)
	msg.WriteString("HELF")
	_ = binary.Write(msg, binary.LittleEndian, uint32(8+body.Len()))
	msg.Write(body.Bytes())
	return msg.Bytes()
}

// healthy reports whether the server answers a Hello with an Acknowledge.
func healthy(addr string) error {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(helloMessage("opc.tcp://" + addr)); err != nil {
		return err
	}
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return fmt.Errorf("no answer to Hello: %w", err)
	}
	if string(hdr[:4]) != "ACKF" {
		return fmt.Errorf("answer to Hello is %q", hdr[:4])
	}
	return nil
}

// FuzzServerRawConnection sends arbitrary bytes on a connection to a running
// server. Whatever arrives, the server must not panic, must end the
// connection or keep waiting (bounded by the client here), and must keep
// serving new connections: after every input a fresh Hello is answered.
func FuzzServerRawConnection(f *testing.F) {
	addr := startFuzzServer(f)
	hello := helloMessage("opc.tcp://" + addr)
	f.Add(hello)
	f.Add(append(append([]byte{}, hello...), "OPNF\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"...))
	f.Add([]byte("MSGF\xff\xff\xff\xff"))
	f.Add([]byte("HELF\x08\x00\x00\x00"))
	f.Add([]byte("ERRF\x10\x00\x00\x00\x00\x00\x00\x80\xff\xff\xff\xff"))
	f.Add([]byte("CLOF\x0c\x00\x00\x00\x00\x00\x00\x00"))
	f.Add(bytes.Repeat([]byte{0}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("server stopped accepting: %v", err)
		}
		_ = c.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = c.Write(data)
		_, _ = io.Copy(io.Discard, c) // until the server closes or the deadline
		_ = c.Close()

		if err := healthy(addr); err != nil {
			t.Fatalf("server unhealthy after input %x: %v", data, err)
		}
	})
}
