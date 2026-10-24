// SPDX-License-Identifier: MIT

package amqp

import (
	"bytes"
	"net"
	"testing"
)

// fuzzClient returns a client with a connection whose session has a sender
// and a receiver link being attached and a delivery under way: the state
// the frames of FuzzClientFrames act on. Nothing is written: the test
// takes the frames the writer would send from the queues.
func fuzzClient(t *testing.T) (*Client, *conn) {
	c, err := newClient(Options{Server: "amqp://fuzz", ContainerID: "c", Credit: 4, MaxMessageSize: 1 << 12})
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	cs := &conn{
		nc: a, dead: make(chan struct{}), writerDone: make(chan struct{}), wake: make(chan struct{}, 1),
		maxFrame: 512, handleMax: 3, remoteIncomingWindow: 10, incomingWindow: sessionWindow,
		handles: map[uint32]*link{}, remote: map[uint32]*link{}, attaching: map[string]*link{},
		unsettled: map[uint32]*outDelivery{},
	}
	c.cs = cs
	snd := c.newLink("q", RoleSender, false)
	c.senders[senderKey{address: "q"}] = snd
	rcv := c.newLink("t", RoleReceiver, false)
	rcv.handler, rcv.active, rcv.confirmed = func(*Message) {}, true, true
	c.receivers[rcv] = struct{}{}
	c.attachLink(cs, rcv) // c-receiver-1, handle 0
	c.attachLink(cs, snd) // c-sender-2, handle 1
	d := &outDelivery{l: snd, payload: bytes.Repeat([]byte{1}, 1000), done: make(chan error, 1)}
	cs.xfers = append(cs.xfers, d)
	snd.queued++
	return c, cs
}

func fuzzFrameSeeds(f *testing.F) {
	tr, zero, one, cr := true, uint32(0), uint32(1), uint32(5)
	var seq []byte
	for _, fr := range []*Frame{
		{Body: &Attach{Name: "c-receiver-1", Handle: 7, Role: RoleSender, Source: &Source{Address: "t"}, Target: &Target{}, InitialDeliveryCount: 3}},
		{Body: &Attach{Name: "c-sender-2", Handle: 8, Role: RoleReceiver, Source: &Source{}, Target: &Target{Address: "q"}, MaxMessageSize: 600}},
		{Body: &Flow{NextIncomingID: &zero, IncomingWindow: 5, Handle: &one, LinkCredit: &cr, DeliveryCount: &zero, Echo: true}},
		{Body: &Flow{NextIncomingID: &zero, IncomingWindow: 5, Handle: u32p(8), LinkCredit: &cr, DeliveryCount: &zero, Drain: true}},
		{Body: &Transfer{Handle: 7, DeliveryID: &zero, DeliveryTag: []byte{1}, More: true}, Payload: []byte{0x00, 0x53, 0x75}},
		{Body: &Transfer{Handle: 7}, Payload: []byte{0xa0, 1, 'x'}},
		{Body: &Transfer{Handle: 7, DeliveryID: &one, DeliveryTag: []byte{2}, Settled: &tr}, Payload: []byte{0x00, 0x53, 0x75, 0xa0, 1, 'y'}},
		{Body: &Transfer{Handle: 7, DeliveryID: u32p(2), Aborted: true}},
		{Body: &Disposition{Role: RoleReceiver, First: 0, Last: u32p(9), Settled: true, State: &Accepted{}}},
		{Body: &Disposition{Role: RoleReceiver, First: 0, State: &Rejected{Error: &Error{Condition: "x"}}}},
		{Body: &Detach{Handle: 7, Closed: true, Error: &Error{Condition: CondDetachForced}}},
		{Body: &Detach{Handle: 8}},
		{Body: &End{}},
	} {
		b, err := AppendFrame(nil, fr)
		if err != nil {
			f.Fatal(err)
		}
		seq = append(seq, b...)
		f.Add(seq)
	}
	b, _ := AppendFrame(nil, &Frame{Body: &Close{Error: &Error{Condition: CondConnectionForced}}})
	f.Add(b)
}

// FuzzClientFrames feeds arbitrary frame sequences to the connection state
// machine of the client (attach, flow, transfer, disposition, detach, end,
// close) and runs the writer's frame selection after each: whatever the
// broker sends, the client must answer or fail the connection, never panic.
func FuzzClientFrames(f *testing.F) {
	fuzzFrameSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		c, cs := fuzzClient(t)
		defer func() {
			close(c.done)
			c.wg.Wait()
		}()
		r := bytes.NewReader(data)
		for {
			fr, err := ReadFrame(r, 1<<16)
			if err != nil {
				return
			}
			if fr.Body == nil {
				continue
			}
			c.mu.Lock()
			_, err = c.handle(cs, fr)
			for range 64 {
				if f, _, _ := c.nextFrame(cs); f == nil {
					break
				}
			}
			c.mu.Unlock()
			if err != nil {
				c.detach(cs)
				return
			}
		}
	})
}
