// SPDX-License-Identifier: MIT

package mqtt

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	imqtt "github.com/otfabric/go-opcua/internal/mqtt"
	"github.com/otfabric/go-opcua/internal/testutil/mqttbroker"
	"github.com/otfabric/go-opcua/pubsub/transport"
)

func TestV5ContentTypeAndMessageType(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]*imqtt.Publish{}
	b := startBroker(t, mqttbroker.Options{OnPublish: func(_ string, p *imqtt.Publish) {
		mu.Lock()
		seen[p.Topic] = p
		mu.Unlock()
	}})
	uadp := open(t, transport.Config{URL: b.URL(), ProfileURI: transport.ProfileMQTTUADP, MQTTVersion: Version5})
	json := open(t, transport.Config{URL: b.URL(), ProfileURI: transport.ProfileMQTTJSON,
		Properties: map[string]string{PropMqttVersion: Version5}})
	sub := open(t, transport.Config{URL: b.URL(), MQTTVersion: Version5})
	old := open(t, transport.Config{URL: b.URL()})
	require.Equal(t, Version5, uadp.Version())
	require.Equal(t, Version5, json.Version())
	require.Equal(t, Version311, old.Version())

	in, in3 := make(inbox, 10), make(inbox, 10)
	_, err := sub.Subscribe(bg, "ct/#", 2, in.handle)
	require.NoError(t, err)
	_, err = old.Subscribe(bg, "ct/#", 2, in3.handle)
	require.NoError(t, err)

	require.NoError(t, uadp.Send(bg, []byte{0x11}, transport.PublishOptions{Topic: "ct/uadp", QoS: 2, MessageType: transport.MessageTypeData}))
	m := in.next(t)
	require.Equal(t, transport.ContentTypeUADP, m.ContentType)
	v, ok := m.UserProperty(transport.UAMessageTypeProperty)
	require.True(t, ok)
	require.Equal(t, transport.MessageTypeData, v)
	m3 := in3.next(t)
	require.Empty(t, m3.ContentType, "3.1.1 carries no content type")
	require.Empty(t, m3.UserProperties)

	require.NoError(t, json.Send(bg, []byte(`{}`), transport.PublishOptions{Topic: "ct/json", QoS: 1, Retain: true,
		MessageType: transport.MessageTypeMetaData, MessageExpiry: 1500 * time.Millisecond,
		UserProperties: []transport.Property{{Name: "promoted", Value: "42"}}}))
	m = in.next(t)
	require.Equal(t, transport.ContentTypeJSON, m.ContentType)
	require.Equal(t, []transport.Property{{Name: transport.UAMessageTypeProperty, Value: transport.MessageTypeMetaData},
		{Name: "promoted", Value: "42"}}, m.UserProperties)
	_, ok = m.UserProperty("missing")
	require.False(t, ok)
	in3.next(t)
	mu.Lock()
	require.Equal(t, uint32(2), *seen["ct/json"].Props.MessageExpiry, "rounded up to whole seconds")
	mu.Unlock()

	// An explicit content type wins over the profile's.
	require.NoError(t, uadp.Send(bg, []byte(`{}`), transport.PublishOptions{Topic: "ct/x", ContentType: transport.ContentTypeJSON}))
	require.Equal(t, transport.ContentTypeJSON, in.next(t).ContentType)
	in3.next(t)

	// Without a profile (nor an explicit one) there is no content type.
	require.NoError(t, sub.Send(bg, []byte("x"), transport.PublishOptions{Topic: "ct/none"}))
	require.Empty(t, in.next(t).ContentType)
}

func TestV5ConnectionProperties(t *testing.T) {
	var mu sync.Mutex
	var connects []*imqtt.Connect
	b := startBroker(t, mqttbroker.Options{OnConnect: func(p *imqtt.Connect) {
		mu.Lock()
		connects = append(connects, p)
		mu.Unlock()
	}})
	c := open(t, transport.Config{URL: b.URL(), Properties: map[string]string{
		PropMqttVersion:                Version5,
		PropMqttTopicPrefix:            "plant",
		PropClientID:                   "pubsub-1",
		PropReceiveMaximum:             "10",
		PropMaximumPacketSize:          "100000",
		PropSessionExpiryInterval:      "300",
		PropTopicAliasMaximum:          "5",
		PropRequestResponseInformation: "true",
		PropRequestProblemInformation:  "false",
		"password":                     "",
		"site":                         "berlin",
		"area":                         "a1",
	}})
	require.True(t, c.Connected())
	mu.Lock()
	p := connects[len(connects)-1]
	mu.Unlock()
	require.Equal(t, byte(5), p.ProtocolLevel)
	require.Equal(t, "pubsub-1", p.ClientID)
	require.False(t, p.CleanSession)
	require.Equal(t, uint32(300), *p.Props.SessionExpiry)
	require.Equal(t, uint16(10), *p.Props.ReceiveMaximum)
	require.Equal(t, uint32(100000), *p.Props.MaximumPacketSize)
	require.Nil(t, p.Props.TopicAliasMaximum, "never topic aliases")
	require.Equal(t, byte(1), *p.Props.RequestResponseInfo)
	require.Equal(t, byte(0), *p.Props.RequestProblemInfo)
	require.Equal(t, []imqtt.UserProperty{{Key: "area", Value: "a1"}, {Key: "site", Value: "berlin"}}, p.Props.User,
		"the other properties, without go-opcua's and Part 14's own")

	// 3.1.1 discards them; the client id stays.
	open(t, transport.Config{URL: b.URL(), Properties: map[string]string{PropClientID: "old", PropSessionExpiryInterval: "300", "site": "x"}})
	mu.Lock()
	p = connects[len(connects)-1]
	mu.Unlock()
	require.Equal(t, byte(4), p.ProtocolLevel)
	require.Equal(t, "old", p.ClientID)
	require.True(t, p.CleanSession)

	// BestAvailable falls back to 3.1.1.
	b3 := startBroker(t, mqttbroker.Options{DisableV5: true})
	best := open(t, transport.Config{URL: b3.URL(), MQTTVersion: VersionBestAvailable})
	require.Equal(t, Version311, best.Version())

	for _, props := range []map[string]string{
		{PropMqttVersion: "4"},
		{PropReceiveMaximum: "0"},
		{PropReceiveMaximum: "70000"},
		{PropMaximumPacketSize: "x"},
		{PropSessionExpiryInterval: "-1"},
		{PropRequestProblemInformation: "maybe"},
		{"keep-alive": "x"},
	} {
		_, err := Open(bg, transport.Config{URL: b.URL(), Properties: props})
		require.Error(t, err, "%v", props)
	}
	_, err := Open(bg, transport.Config{URL: b.URL(), MQTTVersion: "6"})
	require.Error(t, err)
}

func TestParseVersionAndContentType(t *testing.T) {
	for s, want := range map[string]byte{"": imqtt.Version311, "3.1.1": imqtt.Version311, "5.0": imqtt.Version5, " 5 ": imqtt.Version5,
		"BestAvailable": imqtt.VersionBestAvailable} {
		v, err := ParseVersion(s)
		require.NoError(t, err)
		require.Equal(t, want, v, s)
	}
	_, err := ParseVersion("3.1")
	require.Error(t, err)
	require.Equal(t, transport.ContentTypeUADP, ContentTypeOf(transport.ProfileMQTTUADP))
	require.Equal(t, transport.ContentTypeJSON, ContentTypeOf(transport.ProfileMQTTJSON))
	require.Empty(t, ContentTypeOf(transport.ProfileUDPUADP))
}
