// SPDX-License-Identifier: MIT

package mqtt

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// allProps sets every property a packet type allows.
func allProps(pt byte) Properties {
	var p Properties
	set := func(id byte) bool { return allowedProps[id]&(1<<pt) != 0 }
	if set(propPayloadFormat) {
		p.PayloadFormat = Ptr(byte(1))
		p.MessageExpiry = Ptr(uint32(60))
		p.ContentType = Ptr("application/opcua+uadp")
		p.ResponseTopic = Ptr("reply/to")
		p.CorrelationData = []byte{1, 2, 3}
	}
	if set(propSubscriptionID) {
		p.SubscriptionIDs = []uint32{MaxSubscriptionID}
		if pt == TypePublish {
			p.SubscriptionIDs = []uint32{1, 300}
		}
	}
	if set(propSessionExpiry) {
		p.SessionExpiry = Ptr(uint32(0xffffffff))
	}
	if set(propAssignedClientID) {
		p.AssignedClientID = Ptr("auto-1")
		p.ServerKeepAlive = Ptr(uint16(30))
		p.ResponseInfo = Ptr("info")
		p.MaximumQoS = Ptr(byte(1))
		p.RetainAvailable = Ptr(byte(0))
		p.WildcardSubAvailable = Ptr(byte(1))
		p.SubIDAvailable = Ptr(byte(0))
		p.SharedSubAvailable = Ptr(byte(0))
	}
	if set(propAuthMethod) {
		p.AuthMethod = Ptr("SCRAM-SHA-1")
		p.AuthData = []byte{}
	}
	if set(propRequestProblemInfo) {
		p.RequestProblemInfo = Ptr(byte(0))
		p.RequestResponseInfo = Ptr(byte(1))
	}
	if set(propWillDelay) {
		p.WillDelay = Ptr(uint32(5))
	}
	if set(propServerReference) {
		p.ServerReference = Ptr("other:1883")
	}
	if set(propReasonString) {
		p.ReasonString = Ptr("because")
	}
	if set(propReceiveMaximum) {
		p.ReceiveMaximum = Ptr(uint16(10))
		p.TopicAliasMaximum = Ptr(uint16(0))
		p.MaximumPacketSize = Ptr(uint32(1 << 20))
	}
	if set(propTopicAlias) {
		p.TopicAlias = Ptr(uint16(3))
	}
	p.User = []UserProperty{{"k", "v"}, {"k", "w"}, {"", ""}}
	return p
}

func TestPacketRoundTripV5(t *testing.T) {
	packets := []Packet{
		&Connect{ProtocolName: "MQTT", ProtocolLevel: 5, CleanSession: true, KeepAlive: 60, ClientID: "c1", Props: allProps(TypeConnect),
			Will: &Will{Topic: "w", Payload: []byte("bye"), QoS: 1, Retain: true, Props: allProps(typeWill)}},
		&Connect{ProtocolName: "MQTT", ProtocolLevel: 5, Password: []byte("token")}, // password without user name
		&Connack{SessionPresent: true, Props: allProps(TypeConnack)},
		&Connack{ReturnCode: ReasonBanned},
		&Publish{Topic: "a/b", Payload: []byte("x"), Props: allProps(TypePublish)},
		&Publish{Topic: "", QoS: 2, PacketID: 9, Payload: []byte{}, Props: Properties{TopicAlias: Ptr(uint16(1))}},
		&Publish{Topic: "a", Payload: []byte{}, QoS: 1, PacketID: 7, Dup: true, Retain: true},
		&Ack{Kind: TypePuback, PacketID: 1},
		&Ack{Kind: TypePuback, PacketID: 1, ReasonCode: ReasonNoMatchingSubscribers},
		&Ack{Kind: TypePubrec, PacketID: 2, ReasonCode: ReasonQuotaExceeded, Props: allProps(TypePubrec)},
		&Ack{Kind: TypePubrel, PacketID: 3, Props: Properties{ReasonString: Ptr("r")}},
		&Ack{Kind: TypePubcomp, PacketID: 4, ReasonCode: ReasonPacketIdentifierNotFound},
		&Ack{Kind: TypeUnsuback, PacketID: 5, ReasonCodes: []byte{0, ReasonNoSubscriptionExisted}, Props: allProps(TypeUnsuback)},
		&Subscribe{PacketID: 9, Props: allProps(TypeSubscribe), Topics: []TopicFilter{
			{Filter: "a/+/c", QoS: 1, NoLocal: true},
			{Filter: "#", QoS: 2, RetainAsPublished: true, RetainHandling: RetainDoNotSend},
			{Filter: "x", RetainHandling: RetainSendIfNew},
		}},
		&Suback{PacketID: 9, ReturnCodes: []byte{1, 0, ReasonNotAuthorized}, Props: allProps(TypeSuback)},
		&Unsubscribe{PacketID: 10, Filters: []string{"a/+/c", "#"}, Props: allProps(TypeUnsubscribe)},
		&Simple{Kind: TypePingreq},
		&Disconnect{},
		&Disconnect{ReasonCode: ReasonSessionTakenOver},
		&Disconnect{ReasonCode: ReasonServerMoved, Props: allProps(TypeDisconnect)},
		&Auth{},
		&Auth{ReasonCode: ReasonContinueAuthentication, Props: allProps(TypeAuth)},
	}
	var stream bytes.Buffer
	for _, p := range packets {
		b, err := EncodeVersion(p, Version5)
		require.NoError(t, err, "%T", p)
		stream.Write(b)
	}
	r := bufio.NewReader(&stream)
	for _, want := range packets {
		got, err := ReadPacketVersion(r, 0, Version5)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}

	// The short forms: no reason code, no property length.
	b, _ := EncodeVersion(&Ack{Kind: TypePuback, PacketID: 1}, Version5)
	require.Equal(t, []byte{TypePuback << 4, 2, 0, 1}, b)
	b, _ = EncodeVersion(&Ack{Kind: TypePuback, PacketID: 1, ReasonCode: 0x10}, Version5)
	require.Equal(t, []byte{TypePuback << 4, 3, 0, 1, 0x10}, b)
	b, _ = EncodeVersion(&Disconnect{}, Version5)
	require.Equal(t, []byte{TypeDisconnect << 4, 0}, b)

	// 3.1.1 leaves the 5.0 fields out.
	b, err := EncodeVersion(&Publish{Topic: "t", Props: allProps(TypePublish)}, Version311)
	require.NoError(t, err)
	require.Equal(t, []byte{TypePublish << 4, 3, 0, 1, 't'}, b)
	b, _ = EncodeVersion(&Disconnect{ReasonCode: 0x8e}, Version311)
	require.Equal(t, []byte{TypeDisconnect << 4, 0}, b)
	b, _ = EncodeVersion(&Subscribe{PacketID: 1, Topics: []TopicFilter{{Filter: "t", QoS: 1, NoLocal: true, RetainHandling: 2}}}, Version311)
	require.Equal(t, byte(1), b[len(b)-1])

	// A 3.1.1 CONNACK read as 5.0 (a broker refusing the version).
	p, err := DecodeVersion(TypeConnack<<4, []byte{0, ConnRefusedProtocolVersion}, Version5)
	require.NoError(t, err)
	require.Equal(t, &Connack{ReturnCode: ConnRefusedProtocolVersion}, p)
}

func TestEncodeErrorsV5(t *testing.T) {
	bad := []Packet{
		&Publish{Topic: "", Props: Properties{}},
		&Publish{Topic: "a", Props: Properties{SessionExpiry: Ptr(uint32(1))}}, // not allowed in PUBLISH
		&Publish{Topic: "a", Props: Properties{PayloadFormat: Ptr(byte(2))}},
		&Publish{Topic: "a", Props: Properties{TopicAlias: Ptr(uint16(0))}},
		&Publish{Topic: "a", Props: Properties{ContentType: Ptr("a\x00")}},
		&Publish{Topic: "a", Props: Properties{ResponseTopic: Ptr("a/#")}},
		&Publish{Topic: "a", Props: Properties{CorrelationData: make([]byte, 70000)}},
		&Publish{Topic: "a", Props: Properties{SubscriptionIDs: []uint32{0}}},
		&Publish{Topic: "a", Props: Properties{User: []UserProperty{{"k", string([]byte{0xff})}}}},
		&Connack{Props: Properties{ReceiveMaximum: Ptr(uint16(0))}},
		&Connack{Props: Properties{MaximumPacketSize: Ptr(uint32(0))}},
		&Connack{Props: Properties{MaximumQoS: Ptr(byte(2))}},
		&Subscribe{PacketID: 1, Topics: []TopicFilter{{Filter: "a"}}, Props: Properties{SubscriptionIDs: []uint32{1, 2}}},
		&Subscribe{PacketID: 1, Topics: []TopicFilter{{Filter: "a", RetainHandling: 3}}},
		&Subscribe{PacketID: 1, Topics: []TopicFilter{{Filter: "a"}}, Props: Properties{ReasonString: Ptr("x")}},
		&Suback{PacketID: 1, ReturnCodes: []byte{0}, Props: Properties{ContentType: Ptr("x")}},
		&Unsubscribe{PacketID: 1, Filters: []string{"a"}, Props: Properties{ContentType: Ptr("x")}},
		&Unsubscribe{PacketID: 1, Filters: []string{"a#"}},
		&Ack{Kind: TypeUnsuback, PacketID: 1},
		&Ack{Kind: TypePuback, PacketID: 1, Props: Properties{ContentType: Ptr("x")}},
		&Disconnect{Props: Properties{ContentType: Ptr("x")}},
		&Auth{Props: Properties{ContentType: Ptr("x")}},
		&Connect{ProtocolLevel: 5, Props: Properties{ContentType: Ptr("x")}},
		&Connect{ProtocolLevel: 5, Will: &Will{Topic: "w", Props: Properties{SessionExpiry: Ptr(uint32(1))}}},
	}
	for _, p := range bad {
		_, err := EncodeVersion(p, Version5)
		require.ErrorIs(t, err, ErrProtocol, "%#v", p)
	}
	_, err := EncodeVersion(&Auth{}, Version311)
	require.ErrorIs(t, err, ErrProtocol)
	// A CONNECT without protocol name but level 5 is a 5.0 CONNECT.
	b, err := Encode(&Connect{ProtocolLevel: 5, ClientID: "x"})
	require.NoError(t, err)
	p, err := Decode(b[0], b[2:])
	require.NoError(t, err)
	require.Equal(t, Version5, p.(*Connect).ProtocolLevel)
	_, err = appendProps(nil, TypePublish, &Properties{User: []UserProperty{{"k", strings.Repeat("v", 65536)}}})
	require.ErrorIs(t, err, ErrProtocol)
}

func props(b ...byte) []byte { return append(appendVarint(nil, len(b)), b...) }

func TestDecodeErrorsV5(t *testing.T) {
	u16 := func(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
	pub := func(p []byte) []byte {
		return append(append([]byte{TypePublish << 4}, appendString(nil, "t")...), p...)
	}
	var many []byte
	for i := 0; i <= MaxUserProperties; i++ {
		many = append(many, propUser, 0, 0, 0, 0)
	}
	var subIDs []byte
	for i := 0; i <= MaxSubscriptionIDs; i++ {
		subIDs = append(subIDs, propSubscriptionID, 1)
	}
	cases := map[string][]byte{
		"props short":          pub([]byte{5, propPayloadFormat}),
		"props length":         pub([]byte{0xff, 0xff, 0xff, 0xff, 0x7f}),
		"props varint short":   pub([]byte{0x80}),
		"unknown property":     pub(props(0x7f, 0)),
		"not allowed":          pub(props(propSessionExpiry, 0, 0, 0, 1)),
		"twice":                pub(props(propPayloadFormat, 0, propPayloadFormat, 1)),
		"payload format 2":     pub(props(propPayloadFormat, 2)),
		"topic alias 0":        pub(props(propTopicAlias, 0, 0)),
		"subscription id 0":    pub(props(propSubscriptionID, 0)),
		"subscription id long": pub(props(propSubscriptionID, 0x80, 0x80, 0x80, 0x80, 1)),
		"too many sub ids":     pub(props(subIDs...)),
		"response topic":       pub(props(append([]byte{propResponseTopic}, appendString(nil, "a/+")...)...)),
		"content type utf8":    pub(props(propContentType, 0, 1, 0xff)),
		"user short":           pub(props(propUser, 0, 1, 'k')),
		"too many users":       pub(props(many...)),
		"u32 short":            pub(props(propMessageExpiry, 0, 0)),
		"bytes short":          pub(props(propCorrelationData, 0, 5, 1)),
		"empty topic":          append([]byte{TypePublish << 4, 0, 0}, props()...),
		"dup qos0":             append(append([]byte{TypePublish<<4 | 8}, appendString(nil, "t")...), props()...),
		"connack flags":        append([]byte{TypeConnack << 4, 2, 0}, props()...),
		"connack receive 0":    append([]byte{TypeConnack << 4, 0, 0}, props(propReceiveMaximum, 0, 0)...),
		"connack max size 0":   append([]byte{TypeConnack << 4, 0, 0}, props(propMaximumPacketSize, 0, 0, 0, 0)...),
		"connack max qos 2":    append([]byte{TypeConnack << 4, 0, 0}, props(propMaximumQoS, 2)...),
		"unsuback no codes":    append(append([]byte{TypeUnsuback << 4}, u16(1)...), props()...),
		"puback props":         append(append([]byte{TypePuback << 4}, u16(1)...), 0, 3, propContentType, 0, 0),
		"subscribe options":    append(append(append([]byte{TypeSubscribe<<4 | 2}, u16(1)...), props()...), append(appendString(nil, "a"), 0x30)...),
		"subscribe reserved":   append(append(append([]byte{TypeSubscribe<<4 | 2}, u16(1)...), props()...), append(appendString(nil, "a"), 0x40)...),
		"subscribe two ids":    append(append([]byte{TypeSubscribe<<4 | 2}, u16(1)...), props(propSubscriptionID, 1, propSubscriptionID, 2)...),
		"subscribe empty":      append(append([]byte{TypeSubscribe<<4 | 2}, u16(1)...), props()...),
		"unsubscribe filter":   append(append(append([]byte{TypeUnsubscribe<<4 | 2}, u16(1)...), props()...), appendString(nil, "a#")...),
		"disconnect props":     {TypeDisconnect << 4, 0x8e, 1},
		"auth flags":           {TypeAuth<<4 | 1},
		"auth props":           {TypeAuth << 4, 0x18, 2, propContentType, 0},
		"will topic":           connect5([]byte{0x04}, appendString(nil, "c"), props(), appendString(nil, "a/#"), appendString(nil, "")),
		"will props":           connect5([]byte{0x04}, appendString(nil, "c"), props(propSessionExpiry, 0, 0, 0, 0)),
		"connect props":        connect5([]byte{0}, nil),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeVersion(raw[0], raw[1:], Version5)
			require.ErrorIs(t, err, ErrProtocol)
		})
	}
	// AUTH does not exist before 5.0.
	_, err := Decode(TypeAuth<<4, nil)
	require.ErrorIs(t, err, ErrProtocol)
}

// connect5 builds a level 5 CONNECT body after the connect flags; the
// properties of the CONNECT are empty unless parts[0] is nil.
func connect5(flags []byte, parts ...[]byte) []byte {
	b := append([]byte{TypeConnect << 4}, appendString(nil, "MQTT")...)
	b = append(b, 5)
	b = append(b, flags...)
	b = append(b, 0, 0) // keep alive
	if parts[0] == nil {
		return append(b, 3, propContentType, 0, 0) // not allowed in CONNECT
	}
	b = append(b, props()...)
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func TestReasonText(t *testing.T) {
	require.Equal(t, "not authorized", ReasonText(ReasonNotAuthorized))
	require.Equal(t, "reason code 0x7f", ReasonText(0x7f))
	for code := range reasonNames {
		require.NotEmpty(t, ReasonText(code))
	}
}

func FuzzDecodeV5(f *testing.F) {
	for _, p := range []Packet{
		&Connect{ProtocolName: "MQTT", ProtocolLevel: 5, ClientID: "c", Props: allProps(TypeConnect),
			Will: &Will{Topic: "w", Props: allProps(typeWill)}},
		&Connack{Props: allProps(TypeConnack)},
		&Publish{Topic: "a/b", QoS: 1, PacketID: 3, Payload: []byte("x"), Props: allProps(TypePublish)},
		&Ack{Kind: TypePubrec, PacketID: 1, ReasonCode: 0x80, Props: allProps(TypePubrec)},
		&Ack{Kind: TypeUnsuback, PacketID: 1, ReasonCodes: []byte{0}},
		&Subscribe{PacketID: 1, Topics: []TopicFilter{{Filter: "a/#", QoS: 1, NoLocal: true}}, Props: allProps(TypeSubscribe)},
		&Suback{PacketID: 1, ReturnCodes: []byte{0}, Props: allProps(TypeSuback)},
		&Disconnect{ReasonCode: 0x8e, Props: allProps(TypeDisconnect)},
		&Auth{ReasonCode: 0x18, Props: allProps(TypeAuth)},
	} {
		b, err := EncodeVersion(p, Version5)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ReadPacketVersion(bufio.NewReader(bytes.NewReader(b)), 1<<16, Version5)
		if err != nil {
			return
		}
		out, err := EncodeVersion(p, Version5)
		if err != nil {
			return // e.g. an empty SUBACK body decodes but a client never sends it
		}
		p2, err := ReadPacketVersion(bufio.NewReader(bytes.NewReader(out)), 0, Version5)
		require.NoError(t, err)
		require.Equal(t, p, p2)
	})
}

// FuzzProperties feeds arbitrary property blocks to the property decoder
// of every packet type.
func FuzzProperties(f *testing.F) {
	for _, pt := range []byte{TypeConnect, TypeConnack, TypePublish, TypePuback, TypeSubscribe, TypeDisconnect, TypeAuth, typeWill} {
		p := allProps(pt)
		b, err := appendProps(nil, pt, &p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(pt, b)
	}
	f.Fuzz(func(t *testing.T, pt byte, b []byte) {
		pt %= 17
		r := &reader{b: b}
		p := r.props(pt)
		if r.err != nil {
			return
		}
		out, err := appendProps(nil, pt, &p)
		require.NoError(t, err)
		r2 := &reader{b: out}
		require.Equal(t, p, r2.props(pt))
		require.NoError(t, r2.err)
	})
}
