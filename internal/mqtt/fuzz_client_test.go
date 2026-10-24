// SPDX-License-Identifier: MIT

package mqtt

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"
)

// discardConn is a connection whose writes succeed and go nowhere.
type discardConn struct{ net.Conn }

func (discardConn) Write(b []byte) (int, error)      { return len(b), nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }
func (discardConn) Close() error                     { return nil }

// fuzzClient returns a client on a connection of a protocol version with a
// subscription, QoS 1 and QoS 2 publications in flight (one of them past
// its PUBREC), one waiting for send quota and a SUBSCRIBE waiting for its
// SUBACK: the state the packets of FuzzClientPackets act on.
func fuzzClient(t *testing.T, version byte) (*Client, *link) {
	c, err := newClient(Options{Server: "mqtt://fuzz", ProtocolVersion: version, ReceiveMaximum: 4})
	if err != nil {
		t.Fatal(err)
	}
	close(c.done) // enqueue does not block; nothing is delivered
	l := &link{conn: discardConn{}, version: version, maxQoS: 2, quota: 2}
	c.conn = l
	c.subs["a/#"] = &subEntry{tf: TopicFilter{Filter: "a/#", QoS: 2}, handlers: map[uint64]Handler{1: func(*Message) {}}}
	for i, qos := range []byte{1, 2, 2, 1} {
		id, _ := c.allocID()
		c.seq++
		p := &pending{seq: c.seq, pkt: &Publish{Topic: "a/b", QoS: qos, PacketID: id}, done: make(chan error, 1)}
		switch i {
		case 2:
			p.rel, p.sent, p.written = true, true, true
		case 3:
			c.queue = append(c.queue, p)
		default:
			p.sent, p.written = true, true
		}
		c.inflight[id] = p
	}
	id, _ := c.allocID()
	c.acks[id] = make(chan Packet, 1)
	return c, l
}

// FuzzClientPackets feeds arbitrary packet sequences of MQTT 3.1.1 and 5.0
// to the client's packet handling (acknowledgements of both QoS flows,
// SUBACK, UNSUBACK, PUBLISH with every QoS, DISCONNECT, ...): whatever the
// broker sends, the client must answer or fail the connection, never panic,
// and never hold more unanswered QoS 2 identifiers than it allowed.
func FuzzClientPackets(f *testing.F) {
	for _, v := range []byte{Version311, Version5} {
		var seq []byte
		for _, p := range []Packet{
			&Publish{Topic: "a/b", QoS: 2, PacketID: 7, Payload: []byte("x")},
			&Publish{Topic: "a/b", QoS: 2, PacketID: 7, Dup: true, Payload: []byte("x")},
			&Ack{Kind: TypePubrel, PacketID: 7},
			&Publish{Topic: "z", QoS: 1, PacketID: 8},
			&Ack{Kind: TypePuback, PacketID: 1},
			&Ack{Kind: TypePubrec, PacketID: 2},
			&Ack{Kind: TypePubcomp, PacketID: 3},
			&Ack{Kind: TypePubrec, PacketID: 9, ReasonCode: 0x80},
			&Suback{PacketID: 5, ReturnCodes: []byte{0x80}},
			&Ack{Kind: TypeUnsuback, PacketID: 5, ReasonCodes: []byte{0}},
			&Simple{Kind: TypePingresp},
			&Disconnect{ReasonCode: 0x8b},
		} {
			b, err := EncodeVersion(p, v)
			if err != nil {
				f.Fatal(err)
			}
			seq = append(seq, b...)
			f.Add(v == Version5, seq)
		}
	}
	f.Fuzz(func(t *testing.T, v5 bool, data []byte) {
		version := Version311
		if v5 {
			version = Version5
		}
		c, l := fuzzClient(t, version)
		br := bufio.NewReader(bytes.NewReader(data))
		for {
			p, err := ReadPacketVersion(br, 1<<16, version)
			if err != nil {
				return
			}
			if err := c.handle(l, p); err != nil {
				return
			}
			c.mu.Lock()
			n, quota := len(c.qos2), l.quota
			c.mu.Unlock()
			if v5 && n > c.recvMax {
				t.Fatalf("%d unanswered QoS 2 identifiers, Receive Maximum %d", n, c.recvMax)
			}
			if quota < 0 || quota > 5 { // 2 free and 3 held by sent publications
				t.Fatalf("send quota %d", quota)
			}
		}
	})
}
