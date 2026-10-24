// SPDX-License-Identifier: MIT

package mqttbroker

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/internal/mqtt"
)

func dial5(t *testing.T, b *Broker) *raw {
	t.Helper()
	r := rawDial(t, b)
	r.v = mqtt.Version5
	return r
}

func strp(s string) *string { return &s }

func TestV5ConnectAndRefusals(t *testing.T) {
	two := uint16(2)
	b := start(t, Options{
		Users:           map[string]string{"u": "p"},
		ReceiveMaximum:  7,
		MaxPacketSize:   1 << 16,
		MaximumQoS:      mqtt.Ptr(byte(1)),
		NoRetain:        true,
		NoWildcard:      true,
		ServerKeepAlive: &two,
	})
	u := "u"
	r := dial5(t, b)
	ack := r.connect(&mqtt.Connect{CleanSession: true, Username: &u, Password: []byte("p")})
	require.Equal(t, mqtt.ReasonSuccess, ack.ReturnCode)
	pr := ack.Props
	require.Equal(t, "auto-1", *pr.AssignedClientID)
	require.Equal(t, uint16(7), *pr.ReceiveMaximum)
	require.Equal(t, uint32(1<<16), *pr.MaximumPacketSize)
	require.Equal(t, byte(1), *pr.MaximumQoS)
	require.Equal(t, byte(0), *pr.RetainAvailable)
	require.Equal(t, byte(0), *pr.WildcardSubAvailable)
	require.Equal(t, byte(0), *pr.SubIDAvailable)
	require.Equal(t, byte(0), *pr.SharedSubAvailable)
	require.Equal(t, uint16(2), *pr.ServerKeepAlive)
	require.Nil(t, pr.TopicAliasMaximum, "no topic aliases")

	bad := "x"
	for _, tc := range []struct {
		c    *mqtt.Connect
		code byte
	}{
		{&mqtt.Connect{CleanSession: true}, mqtt.ReasonNotAuthorized},
		{&mqtt.Connect{CleanSession: true, Username: &u, Password: []byte("x")}, mqtt.ReasonBadUserNameOrPassword},
		{&mqtt.Connect{CleanSession: true, Username: &bad}, mqtt.ReasonBadUserNameOrPassword},
		{&mqtt.Connect{CleanSession: true, Props: mqtt.Properties{AuthMethod: strp("SCRAM")}}, mqtt.ReasonBadAuthenticationMethod},
	} {
		r := dial5(t, b)
		ack := r.connect(tc.c)
		require.Equal(t, tc.code, ack.ReturnCode)
		require.NotEmpty(t, *ack.Props.ReasonString)
		require.True(t, r.closed())
	}

	// A broker without 5.0 answers like a 3.1.1 broker.
	old := start(t, Options{DisableV5: true})
	r = dial5(t, old)
	r.send(&mqtt.Connect{ProtocolName: "MQTT", ProtocolLevel: 5, CleanSession: true})
	r.v = mqtt.Version311
	ack, ok := r.read().(*mqtt.Connack)
	require.True(t, ok)
	require.Equal(t, mqtt.ConnRefusedProtocolVersion, ack.ReturnCode)
}

func TestV5PropertiesAndReasonCodes(t *testing.T) {
	var seen *mqtt.Publish
	b := start(t, Options{
		OnPublish: func(_ string, p *mqtt.Publish) {
			if p.Topic == "props" {
				seen = p
			}
		},
		RefusePublish: func(_, topic string) byte {
			if topic == "denied" {
				return mqtt.ReasonNotAuthorized
			}
			return 0
		},
		RefuseFilter: func(f string) bool { return f == "secret/#" },
	})
	sub5 := dial5(t, b)
	sub5.connect(&mqtt.Connect{ClientID: "s5", CleanSession: true})
	require.Equal(t, []byte{1}, sub5.subscribe(1, "props", 1))
	sub3 := rawDial(t, b)
	sub3.connect(&mqtt.Connect{ClientID: "s3", CleanSession: true})
	require.Equal(t, []byte{0}, sub3.subscribe(1, "props", 0))

	pub := dial5(t, b)
	pub.connect(&mqtt.Connect{ClientID: "p", CleanSession: true})
	props := mqtt.Properties{
		PayloadFormat:   mqtt.Ptr(byte(1)),
		MessageExpiry:   mqtt.Ptr(uint32(3600)),
		ContentType:     strp("application/json"),
		ResponseTopic:   strp("reply/here"),
		CorrelationData: []byte{1, 2},
		User:            []mqtt.UserProperty{{Key: "a", Value: "1"}, {Key: "a", Value: "2"}},
	}
	pub.send(&mqtt.Publish{Topic: "props", QoS: 1, PacketID: 1, Payload: []byte("{}"), Props: props})
	require.Equal(t, &mqtt.Ack{Kind: mqtt.TypePuback, PacketID: 1}, pub.read())
	require.Equal(t, "application/json", *seen.Props.ContentType)

	m := sub5.read().(*mqtt.Publish)
	require.Equal(t, props.ContentType, m.Props.ContentType)
	require.Equal(t, props.User, m.Props.User)
	require.Equal(t, props.CorrelationData, m.Props.CorrelationData)
	require.Equal(t, props.ResponseTopic, m.Props.ResponseTopic)
	require.Equal(t, byte(1), *m.Props.PayloadFormat)
	require.LessOrEqual(t, *m.Props.MessageExpiry, uint32(3600))
	sub5.send(&mqtt.Ack{Kind: mqtt.TypePuback, PacketID: m.PacketID})
	m = sub3.read().(*mqtt.Publish)
	require.Equal(t, mqtt.Properties{}, m.Props, "3.1.1 has no properties")

	// Reason codes: no subscribers is a success, a refusal is not routed.
	pub.send(&mqtt.Publish{Topic: "nobody", QoS: 1, PacketID: 2})
	require.Equal(t, mqtt.ReasonNoMatchingSubscribers, pub.read().(*mqtt.Ack).ReasonCode)
	pub.send(&mqtt.Publish{Topic: "nobody", QoS: 2, PacketID: 3})
	require.Equal(t, mqtt.ReasonNoMatchingSubscribers, pub.read().(*mqtt.Ack).ReasonCode)
	pub.send(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: 3})
	require.Equal(t, &mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: 3}, pub.read())
	pub.send(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: 99})
	require.Equal(t, mqtt.ReasonPacketIdentifierNotFound, pub.read().(*mqtt.Ack).ReasonCode)
	pub.send(&mqtt.Publish{Topic: "denied", QoS: 1, PacketID: 4})
	a := pub.read().(*mqtt.Ack)
	require.Equal(t, mqtt.ReasonNotAuthorized, a.ReasonCode)
	require.NotNil(t, a.Props.ReasonString)

	// SUBACK and UNSUBACK reason codes.
	pub.send(&mqtt.Subscribe{PacketID: 5, Topics: []mqtt.TopicFilter{{Filter: "secret/#"}, {Filter: "ok", QoS: 2}}})
	sa := pub.read().(*mqtt.Suback)
	require.Equal(t, []byte{mqtt.ReasonNotAuthorized, 2}, sa.ReturnCodes)
	require.NotNil(t, sa.Props.ReasonString)
	pub.send(&mqtt.Unsubscribe{PacketID: 6, Filters: []string{"ok", "never"}})
	ua := pub.read().(*mqtt.Ack)
	require.Equal(t, []byte{mqtt.ReasonSuccess, mqtt.ReasonNoSubscriptionExisted}, ua.ReasonCodes)

	// Without problem information: no reason strings.
	quiet := dial5(t, b)
	quiet.connect(&mqtt.Connect{ClientID: "q", CleanSession: true, Props: mqtt.Properties{RequestProblemInfo: mqtt.Ptr(byte(0))}})
	quiet.send(&mqtt.Publish{Topic: "denied", QoS: 1, PacketID: 1})
	a = quiet.read().(*mqtt.Ack)
	require.Equal(t, mqtt.ReasonNotAuthorized, a.ReasonCode)
	require.Nil(t, a.Props.ReasonString)
}

func TestV5QoS2DeliveryAndFlowControl(t *testing.T) {
	b := start(t, Options{})
	sub := dial5(t, b)
	sub.connect(&mqtt.Connect{ClientID: "s", Props: mqtt.Properties{
		SessionExpiry:  mqtt.Ptr(uint32(60)),
		ReceiveMaximum: mqtt.Ptr(uint16(2)),
	}})
	require.Equal(t, []byte{2}, sub.subscribe(1, "q", 2))
	pub := rawDial(t, b)
	pub.connect(&mqtt.Connect{ClientID: "p", CleanSession: true})
	for i := 0; i < 4; i++ {
		pub.send(&mqtt.Publish{Topic: "q", QoS: 2, PacketID: uint16(10 + i), Payload: []byte{byte('a' + i)}})
		require.Equal(t, mqtt.TypePubrec, pub.read().Type())
		pub.send(&mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: uint16(10 + i)})
		require.Equal(t, mqtt.TypePubcomp, pub.read().Type())
	}
	// Receive Maximum 2: two messages, then nothing until one completes.
	m1 := sub.read().(*mqtt.Publish)
	m2 := sub.read().(*mqtt.Publish)
	require.Equal(t, "a", string(m1.Payload))
	require.Equal(t, "b", string(m2.Payload))
	require.Equal(t, byte(2), m1.QoS)
	sub.quiet(100 * time.Millisecond)
	sub.send(&mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: m1.PacketID})
	require.Equal(t, &mqtt.Ack{Kind: mqtt.TypePubrel, PacketID: m1.PacketID}, sub.read())
	sub.quiet(100 * time.Millisecond) // the slot is free only after PUBCOMP
	sub.send(&mqtt.Ack{Kind: mqtt.TypePubcomp, PacketID: m1.PacketID})
	m3 := sub.read().(*mqtt.Publish)
	require.Equal(t, "c", string(m3.Payload))
	// A refused PUBREC also frees the slot; an unknown one gets a PUBREL
	// "not found".
	sub.send(&mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: m2.PacketID, ReasonCode: mqtt.ReasonUnspecifiedError})
	m4 := sub.read().(*mqtt.Publish)
	require.Equal(t, "d", string(m4.Payload))
	sub.send(&mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: 999})
	require.Equal(t, mqtt.ReasonPacketIdentifierNotFound, sub.read().(*mqtt.Ack).ReasonCode)

	// Reconnect: the session has m3 (PUBREC'd: PUBREL again) and m4.
	sub.send(&mqtt.Ack{Kind: mqtt.TypePubrec, PacketID: m3.PacketID})
	require.Equal(t, mqtt.TypePubrel, sub.read().Type())
	require.NoError(t, sub.conn.Close())
	require.Eventually(t, func() bool { return b.ClientCount() == 1 }, 5*time.Second, time.Millisecond)
	sub = dial5(t, b)
	require.True(t, sub.connect(&mqtt.Connect{ClientID: "s", Props: mqtt.Properties{SessionExpiry: mqtt.Ptr(uint32(60))}}).SessionPresent)
	got := map[byte]bool{}
	for i := 0; i < 2; i++ {
		switch p := sub.read().(type) {
		case *mqtt.Ack:
			require.Equal(t, mqtt.TypePubrel, p.Kind)
			require.Equal(t, m3.PacketID, p.PacketID)
			got['r'] = true
		case *mqtt.Publish:
			require.True(t, p.Dup)
			require.Equal(t, "d", string(p.Payload))
			got['p'] = true
		}
	}
	require.Len(t, got, 2)
}

func TestV5Limits(t *testing.T) {
	b := start(t, Options{ReceiveMaximum: 1, MaxPacketSize: 200, NoRetain: true, MaximumQoS: mqtt.Ptr(byte(1)), NoWildcard: true})
	cases := []struct {
		name   string
		p      []mqtt.Packet
		reason byte
	}{
		{"topic alias", []mqtt.Packet{&mqtt.Publish{Topic: "t", Props: mqtt.Properties{TopicAlias: mqtt.Ptr(uint16(1))}}}, mqtt.ReasonTopicAliasInvalid},
		{"retain", []mqtt.Packet{&mqtt.Publish{Topic: "t", Retain: true}}, mqtt.ReasonRetainNotSupported},
		{"qos", []mqtt.Packet{&mqtt.Publish{Topic: "t", QoS: 2, PacketID: 1}}, mqtt.ReasonQoSNotSupported},
		{"too large", []mqtt.Packet{&mqtt.Publish{Topic: "t", Payload: make([]byte, 300)}}, mqtt.ReasonPacketTooLarge},
		{"subscription id", []mqtt.Packet{&mqtt.Subscribe{PacketID: 1, Topics: []mqtt.TopicFilter{{Filter: "x"}},
			Props: mqtt.Properties{SubscriptionIDs: []uint32{1}}}}, mqtt.ReasonSubscriptionIDsNotSupported},
		{"subscription id on publish", []mqtt.Packet{&mqtt.Publish{Topic: "t", Props: mqtt.Properties{SubscriptionIDs: []uint32{1}}}}, mqtt.ReasonProtocolError},
		{"no local shared", []mqtt.Packet{&mqtt.Subscribe{PacketID: 1, Topics: []mqtt.TopicFilter{{Filter: "$share/g/x", NoLocal: true}}}}, mqtt.ReasonProtocolError},
		{"auth", []mqtt.Packet{&mqtt.Auth{ReasonCode: mqtt.ReasonReAuthenticate}}, mqtt.ReasonProtocolError},
		{"pingresp", []mqtt.Packet{&mqtt.Simple{Kind: mqtt.TypePingresp}}, mqtt.ReasonProtocolError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := dial5(t, b)
			r.connect(&mqtt.Connect{CleanSession: true})
			for _, p := range tc.p {
				r.send(p)
			}
			d, ok := r.read().(*mqtt.Disconnect)
			require.True(t, ok)
			require.Equal(t, tc.reason, d.ReasonCode)
			require.True(t, r.closed())
		})
	}

	// Malformed packet: DISCONNECT 0x81.
	r := dial5(t, b)
	r.connect(&mqtt.Connect{CleanSession: true})
	_, err := r.conn.Write([]byte{mqtt.TypePuback << 4, 3, 0, 1, 0})
	require.NoError(t, err)
	_, err = r.conn.Write([]byte{mqtt.TypePuback << 4, 4, 0, 1, 0, 5})
	require.NoError(t, err)
	require.Equal(t, mqtt.ReasonMalformedPacket, r.read().(*mqtt.Disconnect).ReasonCode)

	// The broker's Receive Maximum 1 (with QoS 2 allowed): a second
	// unreleased QoS 2 publication is too many.
	b2 := start(t, Options{ReceiveMaximum: 1})
	r = dial5(t, b2)
	r.connect(&mqtt.Connect{CleanSession: true})
	r.send(&mqtt.Publish{Topic: "t", QoS: 2, PacketID: 1})
	require.Equal(t, mqtt.TypePubrec, r.read().Type())
	r.send(&mqtt.Publish{Topic: "t", QoS: 2, PacketID: 1, Dup: true}) // the same one again is fine
	require.Equal(t, mqtt.TypePubrec, r.read().Type())
	r.send(&mqtt.Publish{Topic: "t", QoS: 2, PacketID: 2})
	require.Equal(t, mqtt.ReasonReceiveMaximumExceeded, r.read().(*mqtt.Disconnect).ReasonCode)

	// Wildcards refused in SUBSCRIBE.
	r = dial5(t, b)
	r.connect(&mqtt.Connect{CleanSession: true})
	require.Equal(t, []byte{mqtt.ReasonWildcardSubsNotSupported}, r.subscribe(1, "a/#", 0))

	// The client's Maximum Packet Size: larger messages are not sent to it.
	b3 := start(t, Options{})
	small := dial5(t, b3)
	small.connect(&mqtt.Connect{CleanSession: true, Props: mqtt.Properties{MaximumPacketSize: mqtt.Ptr(uint32(100))}})
	small.subscribe(1, "s", 1)
	pub := dial5(t, b3)
	pub.connect(&mqtt.Connect{CleanSession: true})
	pub.send(&mqtt.Publish{Topic: "s", Payload: make([]byte, 200)})
	pub.send(&mqtt.Publish{Topic: "s", QoS: 1, PacketID: 1, Payload: make([]byte, 200)})
	pub.read()
	pub.send(&mqtt.Publish{Topic: "s", QoS: 1, PacketID: 2, Payload: []byte("fits")})
	pub.read()
	require.Equal(t, "fits", string(small.read().(*mqtt.Publish).Payload))
}

func TestV5SubscriptionOptions(t *testing.T) {
	b := start(t, Options{})
	c := dial5(t, b)
	c.connect(&mqtt.Connect{ClientID: "c", CleanSession: true})
	c.send(&mqtt.Subscribe{PacketID: 1, Topics: []mqtt.TopicFilter{
		{Filter: "local", QoS: 0, NoLocal: true},
		{Filter: "rap", QoS: 0, RetainAsPublished: true},
		{Filter: "plain", QoS: 0},
	}})
	require.Equal(t, mqtt.TypeSuback, c.read().Type())
	c.send(&mqtt.Publish{Topic: "local", Payload: []byte("mine")})
	c.send(&mqtt.Publish{Topic: "rap", Retain: true, Payload: []byte("r")})
	m := c.read().(*mqtt.Publish)
	require.Equal(t, "r", string(m.Payload), "No Local: not its own message")
	require.True(t, m.Retain, "Retain As Published")
	c.send(&mqtt.Publish{Topic: "plain", Retain: true, Payload: []byte("p")})
	m = c.read().(*mqtt.Publish)
	require.False(t, m.Retain)

	// Retain Handling.
	sub := func(id uint16, rh byte) {
		c.send(&mqtt.Subscribe{PacketID: id, Topics: []mqtt.TopicFilter{{Filter: "plain", RetainHandling: rh}}})
		require.Equal(t, mqtt.TypeSuback, c.read().Type())
	}
	sub(2, mqtt.RetainDoNotSend)
	c.quiet(50 * time.Millisecond)
	sub(3, mqtt.RetainSendIfNew) // not new
	c.quiet(50 * time.Millisecond)
	sub(4, mqtt.RetainSendOnSubscribe)
	require.True(t, c.read().(*mqtt.Publish).Retain)
	c.send(&mqtt.Unsubscribe{PacketID: 5, Filters: []string{"plain"}})
	c.read()
	sub(6, mqtt.RetainSendIfNew) // new again
	require.Equal(t, "p", string(c.read().(*mqtt.Publish).Payload))

	// Message expiry: an expired retained message is not sent.
	c.send(&mqtt.Publish{Topic: "exp", Retain: true, Payload: []byte("e"), Props: mqtt.Properties{MessageExpiry: mqtt.Ptr(uint32(0))}})
	require.Eventually(t, func() bool { return b.Retained("exp") != nil }, 5*time.Second, time.Millisecond)
	require.Equal(t, []byte{0}, c.subscribe(7, "exp", 0))
	c.quiet(50 * time.Millisecond)
	require.Nil(t, b.Retained("exp"))
}

func TestV5SessionsAndDisconnect(t *testing.T) {
	b := start(t, Options{})
	w := dial5(t, b)
	w.connect(&mqtt.Connect{ClientID: "w", CleanSession: true})
	w.subscribe(1, "will/#", 0)

	// Takeover: the old connection gets DISCONNECT Session taken over.
	a := dial5(t, b)
	a.connect(&mqtt.Connect{ClientID: "x", Props: mqtt.Properties{SessionExpiry: mqtt.Ptr(uint32(0xffffffff))}})
	a.subscribe(1, "keep", 1)
	a2 := dial5(t, b)
	require.True(t, a2.connect(&mqtt.Connect{ClientID: "x", Props: mqtt.Properties{SessionExpiry: mqtt.Ptr(uint32(0xffffffff))}}).SessionPresent)
	require.Equal(t, mqtt.ReasonSessionTakenOver, a.read().(*mqtt.Disconnect).ReasonCode)

	// Disconnect by the broker, with a reason.
	require.True(t, b.Disconnect("x", mqtt.ReasonServerShuttingDown, "maintenance"))
	d := a2.read().(*mqtt.Disconnect)
	require.Equal(t, mqtt.ReasonServerShuttingDown, d.ReasonCode)
	require.Equal(t, "maintenance", *d.Props.ReasonString)
	require.False(t, b.Disconnect("nobody", 0, ""))

	// Session expiry 0 on CONNECT: no session afterwards; setting it on
	// DISCONNECT is a protocol error.
	e := dial5(t, b)
	e.connect(&mqtt.Connect{ClientID: "e"})
	e.send(&mqtt.Disconnect{Props: mqtt.Properties{SessionExpiry: mqtt.Ptr(uint32(10))}})
	require.Equal(t, mqtt.ReasonProtocolError, e.read().(*mqtt.Disconnect).ReasonCode)
	require.Eventually(t, func() bool { return b.ClientCount() == 1 }, 5*time.Second, time.Millisecond)
	e = dial5(t, b)
	require.False(t, e.connect(&mqtt.Connect{ClientID: "e"}).SessionPresent)
	// DISCONNECT may lower the expiry to 0: the session ends; a session
	// whose expiry passed while the client was away is gone too.
	f := dial5(t, b)
	f.connect(&mqtt.Connect{ClientID: "f", Props: mqtt.Properties{SessionExpiry: mqtt.Ptr(uint32(1))}})
	f.send(&mqtt.Disconnect{Props: mqtt.Properties{SessionExpiry: mqtt.Ptr(uint32(0))}})
	require.True(t, f.closed())
	require.Eventually(t, func() bool { return b.ClientCount() == 2 }, 5*time.Second, time.Millisecond)
	f = dial5(t, b)
	require.False(t, f.connect(&mqtt.Connect{ClientID: "f"}).SessionPresent)
	g := dial5(t, b)
	g.connect(&mqtt.Connect{ClientID: "g", Props: mqtt.Properties{SessionExpiry: mqtt.Ptr(uint32(0xffffffff))}})
	g.send(&mqtt.Disconnect{})
	require.True(t, g.closed())
	require.Eventually(t, func() bool { return b.ClientCount() == 3 }, 5*time.Second, time.Millisecond)
	b.mu.Lock()
	b.sessions["g"].expiry = 1
	b.sessions["g"].gone = time.Now().Add(-2 * time.Second)
	b.mu.Unlock()
	g = dial5(t, b)
	require.False(t, g.connect(&mqtt.Connect{ClientID: "g"}).SessionPresent, "expired")

	// DISCONNECT with will message publishes the will (with its
	// properties).
	h := dial5(t, b)
	h.connect(&mqtt.Connect{ClientID: "h", CleanSession: true, Will: &mqtt.Will{Topic: "will/h", Payload: []byte("bye"),
		Props: mqtt.Properties{ContentType: strp("text/plain")}}})
	h.send(&mqtt.Disconnect{ReasonCode: mqtt.ReasonDisconnectWithWill})
	m := w.read().(*mqtt.Publish)
	require.Equal(t, "bye", string(m.Payload))
	require.Equal(t, "text/plain", *m.Props.ContentType)
}
