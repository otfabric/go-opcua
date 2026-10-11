// SPDX-License-Identifier: MIT

package uasc

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// A response that cannot be encoded is not sent, so it must not use up a
// sequence number either: the numbers a peer sees have to be contiguous.
func TestSendResponse_EncodingFailureKeepsSequenceNumbersContiguous(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	peerCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			peerCh <- c
		}
	}()
	tc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	peer := <-peerCh
	defer func() { _ = peer.Close() }()

	conn, err := uacp.NewConn(tc.(*net.TCPConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		SecurityMode:      ua.MessageSecurityModeNone,
		Logger:            testLogger,
	}
	const firstSeq = 100
	s, err := NewServerSecureChannel("opc.tcp://"+ln.Addr().String(), conn, cfg, make(chan error, 1), 7, firstSeq, 9)
	if err != nil {
		t.Fatal(err)
	}
	// open the channel without a handshake
	s.instancesMu.Lock()
	s.openingInstance.state = channelActive
	s.activeInstance = s.openingInstance
	s.instancesMu.Unlock()

	header := func() *ua.ResponseHeader {
		return &ua.ResponseHeader{
			Timestamp:          time.Now(),
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		}
	}
	good := func() ua.Response {
		return &ua.ReadResponse{ResponseHeader: header(), Results: []*ua.DataValue{}}
	}
	// a nil ExpandedNodeID cannot be encoded
	bad := &ua.BrowseResponse{ResponseHeader: header(), Results: []*ua.BrowseResult{{
		References: []*ua.ReferenceDescription{{
			ReferenceTypeID: ua.NewNumericNodeID(0, 1),
			BrowseName:      &ua.QualifiedName{},
			DisplayName:     &ua.LocalizedText{},
		}},
	}}}

	// readSeq reads one chunk from the peer side and returns its sequence
	// number (offset 16 of a symmetric chunk).
	readSeq := func() uint32 {
		t.Helper()
		_ = peer.SetReadDeadline(time.Now().Add(30 * time.Second))
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(peer, hdr); err != nil {
			t.Fatalf("read chunk header: %v", err)
		}
		body := make([]byte, binary.LittleEndian.Uint32(hdr[4:])-8)
		if _, err := io.ReadFull(peer, body); err != nil {
			t.Fatalf("read chunk body: %v", err)
		}
		return binary.LittleEndian.Uint32(body[8:])
	}

	ctx := context.Background()
	if err := s.SendResponseWithContext(ctx, 1, good()); err != nil {
		t.Fatal(err)
	}
	first := readSeq()

	for i := 0; i < 3; i++ {
		if err := s.SendResponseWithContext(ctx, 2, bad); err == nil {
			t.Fatal("precondition: the bad response was encoded")
		}
	}

	if err := s.SendResponseWithContext(ctx, 3, good()); err != nil {
		t.Fatal(err)
	}
	if next := readSeq(); next != first+1 {
		t.Fatalf("sequence number after failed encodings is %d, want %d", next, first+1)
	}
}
