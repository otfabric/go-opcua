// SPDX-License-Identifier: MIT

package mqtt

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func strp(s string) *string { return &s }

func TestPacketRoundTrip(t *testing.T) {
	packets := []Packet{
		&Connect{ProtocolName: "MQTT", ProtocolLevel: 4, CleanSession: true, KeepAlive: 60, ClientID: "c1"},
		&Connect{ProtocolName: "MQIsdp", ProtocolLevel: 3, KeepAlive: 0, ClientID: "c2",
			Will:     &Will{Topic: "w", Payload: []byte("bye"), QoS: 1, Retain: true},
			Username: strp("u"), Password: []byte("p")},
		&Connect{ProtocolName: "MQTT", ProtocolLevel: 4, Username: strp(""), Password: []byte{}},
		&Connack{SessionPresent: true, ReturnCode: 0},
		&Connack{ReturnCode: ConnRefusedBadCredentials},
		&Publish{Topic: "a/b", Payload: []byte("x")},
		&Publish{Topic: "a/b", Payload: []byte{}, QoS: 1, PacketID: 7, Dup: true, Retain: true},
		&Publish{Topic: "a", Payload: bytes.Repeat([]byte("z"), 300000), QoS: 2, PacketID: 65535},
		&Ack{Kind: TypePuback, PacketID: 1},
		&Ack{Kind: TypePubrec, PacketID: 2},
		&Ack{Kind: TypePubrel, PacketID: 3},
		&Ack{Kind: TypePubcomp, PacketID: 4},
		&Ack{Kind: TypeUnsuback, PacketID: 5},
		&Subscribe{PacketID: 9, Topics: []TopicFilter{{Filter: "a/+/c", QoS: 1}, {Filter: "#", QoS: 0}}},
		&Suback{PacketID: 9, ReturnCodes: []byte{1, 0, SubackFailure}},
		&Unsubscribe{PacketID: 10, Filters: []string{"a/+/c", "#"}},
		&Simple{Kind: TypePingreq},
		&Simple{Kind: TypePingresp},
		&Disconnect{},
	}
	var stream bytes.Buffer
	for _, p := range packets {
		b, err := Encode(p)
		require.NoError(t, err, "%T", p)
		stream.Write(b)
	}
	r := bufio.NewReader(&stream)
	for _, want := range packets {
		got, err := ReadPacket(r, 0)
		require.NoError(t, err)
		if c, ok := want.(*Connect); ok && c.Password != nil && len(c.Password) == 0 {
			require.Equal(t, []byte{}, got.(*Connect).Password)
		}
		require.Equal(t, want, got)
	}
	_, err := ReadPacket(r, 0)
	require.Equal(t, io.EOF, err)
}

func TestEncodeDefaultsAndErrors(t *testing.T) {
	b, err := Encode(&Connect{ClientID: "x"})
	require.NoError(t, err)
	p, err := ReadPacket(bufio.NewReader(bytes.NewReader(b)), 0)
	require.NoError(t, err)
	require.Equal(t, "MQTT", p.(*Connect).ProtocolName)
	require.Equal(t, byte(4), p.(*Connect).ProtocolLevel)

	bad := []Packet{
		&Connect{Will: &Will{Topic: "w", QoS: 3}},
		&Connect{Password: []byte("p")},
		&Publish{Topic: "a", QoS: 3},
		&Publish{Topic: "a/#"},
		&Publish{Topic: ""},
		&Publish{Topic: "a", QoS: 1},
		&Ack{Kind: TypeConnect},
		&Subscribe{PacketID: 1},
		&Subscribe{PacketID: 1, Topics: []TopicFilter{{Filter: "a#"}}},
		&Subscribe{PacketID: 1, Topics: []TopicFilter{{Filter: "a", QoS: 3}}},
		&Unsubscribe{PacketID: 1},
		&Simple{Kind: TypePublish},
		&Publish{Topic: "a", Payload: make([]byte, MaxRemainingLength)},
		nil,
	}
	for _, p := range bad {
		_, err := Encode(p)
		require.ErrorIs(t, err, ErrProtocol, "%#v", p)
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := map[string][]byte{
		"connect flags":      {TypeConnect<<4 | 1},
		"connect short":      {TypeConnect << 4, 0, 4, 'M', 'Q'},
		"connect reserved":   append(append([]byte{TypeConnect << 4}, appendString(nil, "MQTT")...), 4, 0x01, 0, 0, 0, 0),
		"connect will qos3":  append(append([]byte{TypeConnect << 4}, appendString(nil, "MQTT")...), 4, 0x1c, 0, 0, 0, 0),
		"connect will flags": append(append([]byte{TypeConnect << 4}, appendString(nil, "MQTT")...), 4, 0x08, 0, 0, 0, 0),
		"connect pw no user": append(append([]byte{TypeConnect << 4}, appendString(nil, "MQTT")...), 4, 0x40, 0, 0, 0, 0, 0, 0),
		"connack flags":      {TypeConnack<<4 | 2, 0, 0},
		"publish qos3":       {TypePublish<<4 | 6, 0, 1, 'a'},
		"publish id 0":       {TypePublish<<4 | 2, 0, 1, 'a', 0, 0},
		"publish wildcard":   {TypePublish << 4, 0, 1, '#'},
		"publish utf8":       {TypePublish << 4, 0, 1, 0xff},
		"publish nul":        {TypePublish << 4, 0, 1, 0},
		"puback flags":       {TypePuback<<4 | 2, 0, 1},
		"pubrel flags":       {TypePubrel << 4, 0, 1},
		"puback long":        {TypePuback << 4, 0, 1, 2},
		"subscribe flags":    {TypeSubscribe << 4, 0, 1},
		"subscribe empty":    {TypeSubscribe<<4 | 2, 0, 1},
		"subscribe filter":   {TypeSubscribe<<4 | 2, 0, 1, 0, 2, 'a', '#', 0},
		"subscribe qos":      {TypeSubscribe<<4 | 2, 0, 1, 0, 1, 'a', 3},
		"suback flags":       {TypeSuback<<4 | 1, 0, 1},
		"unsubscribe flags":  {TypeUnsubscribe << 4, 0, 1},
		"unsubscribe empty":  {TypeUnsubscribe<<4 | 2, 0, 1},
		"ping flags":         {TypePingreq<<4 | 1},
		"type 0":             {0},
		"type 15":            {15 << 4},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(raw[0], raw[1:])
			require.ErrorIs(t, err, ErrProtocol)
		})
	}
}

func TestReadPacketErrors(t *testing.T) {
	_, err := ReadPacket(bufio.NewReader(bytes.NewReader([]byte{0x30})), 0)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = ReadPacket(bufio.NewReader(bytes.NewReader([]byte{0x30, 0xff, 0xff, 0xff, 0xff})), 0)
	require.ErrorIs(t, err, ErrProtocol)
	_, err = ReadPacket(bufio.NewReader(bytes.NewReader([]byte{0x30, 5, 0})), 0)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)

	// An oversized packet is skipped; the next one is read.
	big, _ := Encode(&Publish{Topic: "t", Payload: make([]byte, 1000)})
	small, _ := Encode(&Simple{Kind: TypePingresp})
	r := bufio.NewReader(bytes.NewReader(append(big, small...)))
	_, err = ReadPacket(r, 100)
	require.ErrorIs(t, err, ErrTooLarge)
	p, err := ReadPacket(r, 100)
	require.NoError(t, err)
	require.Equal(t, TypePingresp, p.Type())
	_, err = ReadPacket(bufio.NewReader(bytes.NewReader(big[:50])), 100)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestVarint(t *testing.T) {
	for _, n := range []int{0, 127, 128, 16383, 16384, 2097151, 2097152, MaxRemainingLength} {
		b := appendVarint(nil, n)
		got, err := readVarint(bytes.NewReader(b))
		require.NoError(t, err)
		require.Equal(t, n, got)
	}
}

func TestTopics(t *testing.T) {
	for _, s := range []string{"a", "a/b", "/", "a//b", "$SYS/x", "ü"} {
		require.True(t, ValidTopicName(s), s)
	}
	for _, s := range []string{"", "a/+", "#", "a\x00", string([]byte{0xff}), strings.Repeat("a", 65536)} {
		require.False(t, ValidTopicName(s), s)
	}
	for _, s := range []string{"a", "#", "+", "a/#", "+/+/c", "a/+/#", "/+", "+/"} {
		require.True(t, ValidTopicFilter(s), s)
	}
	for _, s := range []string{"", "a#", "a/#/b", "a+", "a/b+/c", "a\x00", string([]byte{0xff}), strings.Repeat("a", 65536)} {
		require.False(t, ValidTopicFilter(s), s)
	}
	matches := []struct {
		filter, topic string
		want          bool
	}{
		{"a/b", "a/b", true},
		{"a/b", "a/c", false},
		{"a/+", "a/b", true},
		{"a/+", "a/b/c", false},
		{"a/+", "a", false},
		{"a/#", "a", true},
		{"a/#", "a/b/c", true},
		{"#", "a/b", true},
		{"+/+", "/a", true},
		{"+", "/a", false},
		{"#", "$SYS/x", false},
		{"+/x", "$SYS/x", false},
		{"$SYS/#", "$SYS/x", true},
		{"a/b", "a", false},
		{"a", "a/b", false},
		{"a/+/c", "a//c", true},
		{"opcua/json/data/+/+", "opcua/json/data/pub/wg", true},
	}
	for _, m := range matches {
		require.Equal(t, m.want, MatchTopic(m.filter, m.topic), "%s %s", m.filter, m.topic)
	}
}

func TestConnectError(t *testing.T) {
	for _, code := range []byte{1, 2, 3, 4, 5, 77} {
		e := &ConnectError{ReturnCode: code}
		require.NotEmpty(t, e.Error())
		require.Equal(t, code != ConnRefusedServerUnavailable, e.fatal())
	}
	require.True(t, errors.Is(protoErr("x"), ErrProtocol))
}

func FuzzDecode(f *testing.F) {
	for _, p := range []Packet{
		&Connect{ClientID: "c", Username: strp("u"), Password: []byte("p"), Will: &Will{Topic: "w", QoS: 1}},
		&Publish{Topic: "a/b", QoS: 1, PacketID: 3, Payload: []byte("x")},
		&Subscribe{PacketID: 1, Topics: []TopicFilter{{Filter: "a/#", QoS: 1}}},
		&Suback{PacketID: 1, ReturnCodes: []byte{0}},
		&Unsubscribe{PacketID: 1, Filters: []string{"a"}},
	} {
		b, _ := Encode(p)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ReadPacket(bufio.NewReader(bytes.NewReader(b)), 1<<16)
		if err != nil {
			return
		}
		out, err := Encode(p)
		if err != nil {
			return // e.g. an empty SUBACK body decodes but a client never sends it
		}
		if c, ok := p.(*Connect); ok && c.ProtocolName == "" {
			return // Encode fills in "MQTT" and the level for an empty name
		}
		p2, err := ReadPacket(bufio.NewReader(bytes.NewReader(out)), 0)
		require.NoError(t, err)
		require.Equal(t, p, p2)
	})
}
