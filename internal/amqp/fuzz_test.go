// SPDX-License-Identifier: MIT

package amqp

import (
	"bytes"
	"testing"
)

func fuzzSeeds(f *testing.F) {
	tr := true
	for _, fr := range []*Frame{
		{Body: &Open{ContainerID: "c", Hostname: "h", MaxFrameSize: 512, Properties: Map{{Key: Symbol("k"), Value: "v"}}}},
		{Body: &Attach{Name: "n", Role: RoleReceiver, Source: &Source{Address: "a", Capabilities: []Symbol{"topic"}}, Target: &Target{}}},
		{Body: &Flow{NextIncomingID: u32p(1), IncomingWindow: 2, Handle: u32p(0), LinkCredit: u32p(9)}},
		{Body: &Transfer{Handle: 0, DeliveryID: u32p(1), DeliveryTag: []byte{1}, Settled: &tr}, Payload: []byte{0x00, 0x53, 0x75, 0xa0, 1, 'x'}},
		{Body: &Disposition{Role: RoleReceiver, First: 1, Settled: true, State: &Rejected{Error: &Error{Condition: "c"}}}},
		{Body: &Detach{Handle: 1, Closed: true, Error: &Error{Condition: "c", Info: Map{}}}},
		{Type: FrameSASL, Body: &SASLMechanisms{Mechanisms: []Symbol{"PLAIN", "ANONYMOUS"}}},
		{},
	} {
		b, err := AppendFrame(nil, fr)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	m := &Message{Header: &Header{Durable: true}, Properties: &Properties{MessageID: UUID{1}, Subject: "ua-data", ContentType: "application/json"},
		ApplicationProperties: map[string]any{"a": int32(1)}, Data: [][]byte{[]byte("{}")}}
	b, _ := m.MarshalBinary()
	f.Add(b)
	f.Add([]byte{0xe0, 4, 2, 0xa3, 0, 0})
	f.Add([]byte{0xd1, 0, 0, 0, 4, 0, 0, 0, 0})
}

// FuzzReadFrame feeds arbitrary bytes to the frame reader and the message
// decoder: they must fail cleanly, never panic or allocate without bound.
func FuzzReadFrame(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := ReadFrame(bytes.NewReader(data), 1<<16)
		if err == nil && fr.Body != nil {
			// What decodes encodes again.
			if _, err := AppendFrame(nil, fr); err != nil {
				t.Fatalf("re-encode %T: %v", fr.Body, err)
			}
		}
		var m Message
		if m.UnmarshalBinary(data) == nil {
			_ = m.Payload()
		}
	})
}

// FuzzDecodeValue checks that decoded values encode to bytes that decode
// to the same value.
func FuzzDecodeValue(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		v, _, err := DecodeValue(data)
		if err != nil {
			return
		}
		b, err := AppendValue(nil, v)
		if err != nil {
			return // e.g. an array of described values: decoded, not encoded
		}
		v2, rest, err := DecodeValue(b)
		if err != nil || len(rest) != 0 {
			t.Fatalf("re-decode % x: %v", b, err)
		}
		b2, err := AppendValue(nil, v2)
		if err != nil || !bytes.Equal(b, b2) {
			t.Fatalf("not stable: % x vs % x (%v)", b, b2, err)
		}
	})
}
