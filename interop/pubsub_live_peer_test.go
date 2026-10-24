//go:build interop

// SPDX-License-Identifier: MIT

// PubSub (Part 14) live data between go-opcua and open62541 over UDP and MQTT.
// COVERAGE.md: pubsub / pubsub.uadp.udp, pubsub.uadp.mqtt, pubsub.json.mqtt,
// pubsub.field.variant, pubsub.field.datavalue, pubsub.field.rawdata,
// pubsub.security.sign, pubsub.security.aes128-ctr, pubsub.security.aes256-ctr
//
// The PubSub runtime of go-opcua is not used: the go-opcua side is built from
// the message mappings (pubsub/uadp, pubsub/jsonmsg), the message security
// (pubsub/security) and the transports (pubsub/transport/udp, …/mqtt), so
// that the wire path is proven independently of the runtime.
//
//   - open62541 → go-opcua: the adapter publishes the PubSub.* fixture
//     variables (server --pubsub-config, PublishedDataItems), the test writes
//     fresh values into them over OPC UA and waits until a NetworkMessage
//     carrying exactly these values (types and values) arrives.
//   - go-opcua → open62541: the test sends NetworkMessages with fresh values
//     and increasing sequence numbers; the adapter's DataSetReader writes
//     them into its TargetVariables (the PubSub.* variables), which the test
//     reads over OPC UA until they hold exactly the values sent.

package interop

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/transport"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

const (
	psPubID         = 2234
	psWriterGroupID = 100
	psWriterID      = 1
)

// psLiveCase is one configuration of a live test.
type psLiveCase struct {
	name     string
	fcm      ua.DataSetFieldContentMask // DataSetFieldContentMask of writer and reader
	mode     ua.MessageSecurityMode
	policy   security.Policy
	key      []byte
	tokenID  uint32
	vars     []psVar
	maxStrLn uint32
}

func (c psLiveCase) encoding() message.FieldEncoding {
	switch {
	case c.fcm&ua.DataSetFieldContentMaskRawData != 0:
		return message.FieldEncodingRawData
	case c.fcm != 0:
		return message.FieldEncodingDataValue
	}
	return message.FieldEncodingVariant
}

func (c psLiveCase) securityGroups() []jobj {
	if c.mode <= ua.MessageSecurityModeNone {
		return nil
	}
	return []jobj{psSecurityGroupJSON("InteropGroup", c.policy.URI(), c.tokenID, c.key)}
}

func (c psLiveCase) keys(t *testing.T) security.KeySource {
	if c.mode <= ua.MessageSecurityModeNone {
		return nil
	}
	return staticKeyRing(t, c.policy, c.tokenID, c.key)
}

const psDataValueMask = ua.DataSetFieldContentMaskStatusCode | ua.DataSetFieldContentMaskSourceTimestamp |
	ua.DataSetFieldContentMaskServerTimestamp

// psUDPCases are the field encodings and security modes of the UDP tests.
func psUDPCases() []psLiveCase {
	return []psLiveCase{
		{name: "variant", vars: psVars},
		{name: "datavalue", fcm: psDataValueMask, vars: psVars},
		{name: "rawdata", fcm: ua.DataSetFieldContentMaskRawData, vars: psVarsRaw, maxStrLn: psMaxStringLength},
		{name: "sign-aes128-ctr", mode: ua.MessageSecurityModeSign, policy: security.Aes128CTR(), key: psStaticKey128, tokenID: 3, vars: psVars},
		{name: "sign-and-encrypt-aes128-ctr", mode: ua.MessageSecurityModeSignAndEncrypt, policy: security.Aes128CTR(), key: psStaticKey128, tokenID: 7, vars: psVars},
		{name: "sign-and-encrypt-aes256-ctr", mode: ua.MessageSecurityModeSignAndEncrypt, policy: security.Aes256CTR(), key: psStaticKey256, tokenID: 1, vars: psVars},
	}
}

// ---------------------------------------------------------------------------
// open62541 publisher
// ---------------------------------------------------------------------------

// psPublisherConfig is an open62541 publisher of vars. transportSettings
// is the WriterGroup TransportSettings (the UDP destination or the MQTT
// queue).
func psPublisherConfig(c psLiveCase, profile, url string, transportSettings jobj, json bool) jobj {
	wgMsg := eo("i=15645", jobj{"NetworkMessageContentMask": psNetworkMessageMask})
	dswMsg := eo("i=15652", jobj{"DataSetMessageContentMask": psDataSetMessageMask})
	if json {
		wgMsg = eo("i=15657", jobj{"NetworkMessageContentMask": 11})
		dswMsg = eo("i=15664", jobj{"DataSetMessageContentMask": 63})
	}
	wg := psSecure(jobj{
		"Name": "InteropWriterGroup", "Enabled": true, "WriterGroupId": psWriterGroupID, "PublishingInterval": 100,
		"MessageSettings": wgMsg, "TransportSettings": transportSettings,
		"DataSetWriters": []jobj{{
			"Name": "InteropWriter", "Enabled": true, "DataSetWriterId": psWriterID, "DataSetName": "InteropDataSet",
			"KeyFrameCount": 1, "DataSetFieldContentMask": int(c.fcm), "MessageSettings": dswMsg,
		}},
	}, c.mode, "InteropGroup")
	cfg := jobj{"configuration": jobj{
		"PublishedDataSets": []jobj{psPublishedDataSetJSON(c.vars, c.maxStrLn)},
		"Connections": []jobj{{
			"Name": "InteropPublisher", "Enabled": true, "PublisherId": psPublisherIDJSON(5, psPubID),
			"TransportProfileUri": profile, "Address": eo("i=15510", jobj{"Url": url}),
			"WriterGroups": []jobj{wg},
		}},
		"Enabled": true,
	}}
	if sg := c.securityGroups(); sg != nil {
		cfg["securityGroups"] = sg
	}
	return cfg
}

// psUDPPublisherConfig publishes UADP to host.docker.internal:hostPort.
func psUDPPublisherConfig(c psLiveCase, hostPort int) jobj {
	return psPublisherConfig(c, psProfileUDP, "opc.udp://localhost:4840",
		eo("i=23613", jobj{"Address": eo("i=15510", jobj{"Url": fmt.Sprintf("opc.udp://host.docker.internal:%d", hostPort)})}), false)
}

// psDecodeUADP decodes a UADP message of the adapter's writer.
func psDecodeUADP(c psLiveCase, keys security.KeySource) func([]byte) (*message.NetworkMessage, error) {
	md := psMetaData(c.vars, c.maxStrLn)
	return func(b []byte) (*message.NetworkMessage, error) {
		return uadp.Decode(b, &uadp.DecodeOptions{
			MetaData: psLookup(md),
			Security: func(*message.NetworkMessage) (ua.MessageSecurityMode, security.KeySource, error) {
				if keys == nil {
					return ua.MessageSecurityModeNone, nil, nil
				}
				return c.mode, keys, nil
			},
		})
	}
}

// psReceive waits for a NetworkMessage whose first DataSetMessage carries
// values. Messages that do not decode are reported if nothing matches.
func psReceive(t *testing.T, ch <-chan *transport.Message, decode func([]byte) (*message.NetworkMessage, error), values []any, timeout time.Duration) *message.NetworkMessage {
	t.Helper()
	want := make([]string, len(values))
	for i, v := range values {
		want[i] = variantKey(t, ua.MustVariant(v))
	}
	deadline := time.After(timeout)
	var errs []string
	var last string
	received := 0
	for {
		select {
		case m := <-ch:
			received++
			nm, err := decode(m.Payload)
			if err != nil {
				if len(errs) < 5 {
					errs = append(errs, err.Error())
				}
				continue
			}
			if len(nm.Messages) == 0 || len(nm.Messages[0].Fields) != len(values) {
				last = fmt.Sprintf("%d DataSetMessages", len(nm.Messages))
				continue
			}
			match := true
			var got []string
			for i, f := range nm.Messages[0].Fields {
				var v *ua.Variant
				if f.Value != nil {
					v = f.Value.Value
				}
				got = append(got, fmt.Sprint(v))
				if variantKey(t, v) != want[i] {
					match = false
				}
			}
			if match {
				return nm
			}
			last = strings.Join(got, ", ")
		case <-deadline:
			t.Fatalf("no NetworkMessage with the values %v within %v (%d received; last decoded: %s; decode errors: %v)", values, timeout, received, last, errs)
		}
	}
}

// assertPublisherHeaders checks the headers the adapter's writer sends.
func assertPublisherHeaders(t *testing.T, c psLiveCase, nm *message.NetworkMessage) {
	t.Helper()
	if !nm.PublisherID.Equal(message.NewPublisherID(message.PublisherIDUInt16, psPubID)) {
		t.Errorf("PublisherId %v (%v), want UInt16 %d", nm.PublisherID, nm.PublisherID.Type, psPubID)
	}
	if nm.GroupHeader.WriterGroupID != psWriterGroupID {
		t.Errorf("WriterGroupId %d, want %d", nm.GroupHeader.WriterGroupID, psWriterGroupID)
	}
	d := nm.Messages[0]
	if d.DataSetWriterID != psWriterID || d.Type != message.DataSetMessageKeyFrame || !d.Valid {
		t.Errorf("DataSetMessage writer %d type %v valid %v", d.DataSetWriterID, d.Type, d.Valid)
	}
	if d.FieldEncoding != c.encoding() {
		t.Errorf("field encoding %v, want %v", d.FieldEncoding, c.encoding())
	}
	if c.encoding() == message.FieldEncodingDataValue {
		for i, f := range d.Fields {
			if f.Value.Status != ua.StatusOK {
				t.Errorf("field %d status %v", i, f.Value.Status)
			}
			if f.Value.SourceTimestamp.IsZero() || f.Value.ServerTimestamp.IsZero() {
				t.Errorf("field %d without the timestamps the DataSetFieldContentMask selects: %+v", i, f.Value)
			}
		}
	}
	s := nm.Security
	switch {
	case c.mode <= ua.MessageSecurityModeNone && s != nil:
		t.Errorf("unexpected security header %+v", s)
	case c.mode > ua.MessageSecurityModeNone && s == nil:
		t.Errorf("no security header")
	case s != nil:
		if s.SecurityTokenID != c.tokenID || !s.Signed || s.Encrypted != (c.mode == ua.MessageSecurityModeSignAndEncrypt) {
			t.Errorf("security header %+v, want token %d mode %v", s, c.tokenID, c.mode)
		}
	}
}

// TestPubSubUDP_Open62541Publishes_GoReceives: open62541 publishes UADP over
// UDP unicast to the host; go-opcua decodes, verifies and decrypts.
func TestPubSubUDP_Open62541Publishes_GoReceives(t *testing.T) {
	psPeerPublishesUDP(t, psOpen62541)
}

// psPeerPublishesUDP: the peer publishes UADP over UDP unicast to the host;
// go-opcua decodes, verifies and decrypts every case of psUDPCases.
func psPeerPublishesUDP(t *testing.T, p *psPeer) {
	p.requireServer(t)
	for _, c := range psUDPCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			port, ch := psListenUDP(t)
			pub := startPubSubServer(t, pubsubServerOpts{peer: p, config: psUDPPublisherConfig(c, port)})
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			nm := psReceive(t, ch, psDecodeUADP(c, c.keys(t)), values, psReceiveTimeout)
			assertPublisherHeaders(t, c, nm)
			if c.mode > ua.MessageSecurityModeNone {
				assertSecuredRejected(t, c, ch)
			}
		})
	}
}

// assertSecuredRejected: the next secured open62541 message must not decode
// with another key, nor when the receiver accepts only unsecured messages.
func assertSecuredRejected(t *testing.T, c psLiveCase, ch <-chan *transport.Message) {
	t.Helper()
	var m *transport.Message
	select {
	case m = <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no further message")
	}
	wrongKey := append([]byte(nil), c.key...)
	wrongKey[0] ^= 0xFF // another signing key
	wrong := c
	wrong.key = wrongKey
	if _, err := psDecodeUADP(c, wrong.keys(t))(m.Payload); !errors.Is(err, uadp.ErrSecurityChecksFailed) {
		t.Errorf("decode with a wrong signing key: %v, want ErrSecurityChecksFailed", err)
	}
	if _, err := psDecodeUADP(c, nil)(m.Payload); !errors.Is(err, uadp.ErrSecurityMode) {
		t.Errorf("decode of a secured message by a receiver without keys: %v, want ErrSecurityMode", err)
	}
}

// ---------------------------------------------------------------------------
// open62541 subscriber
// ---------------------------------------------------------------------------

// psSubscriberConfig is an open62541 subscriber writing the DataSet into the
// PubSub.* variables. readerTransport is the DataSetReader
// TransportSettings (nil for UDP).
func psSubscriberConfig(c psLiveCase, profile, url string, readerTransport jobj, json bool) jobj {
	msg := eo("i=15653", jobj{"NetworkMessageContentMask": psNetworkMessageMask, "DataSetMessageContentMask": psDataSetMessageMask})
	if json {
		msg = eo("i=15665", jobj{"NetworkMessageContentMask": 11, "DataSetMessageContentMask": 63})
	}
	reader := jobj{
		"Name": "InteropReader", "Enabled": true, "PublisherId": psPublisherIDJSON(5, psPubID),
		"WriterGroupId": psWriterGroupID, "DataSetWriterId": psWriterID,
		"DataSetMetaData": psMetaDataJSON(c.vars, c.maxStrLn), "DataSetFieldContentMask": int(c.fcm),
		"MessageReceiveTimeout": 0, "MessageSettings": msg, "SubscribedDataSet": psTargetVariablesJSON(c.vars),
	}
	if readerTransport != nil {
		reader["TransportSettings"] = readerTransport
	}
	cfg := jobj{"configuration": jobj{
		"Connections": []jobj{{
			"Name": "InteropSubscriber", "Enabled": true, "PublisherId": psPublisherIDJSON(5, 2235),
			"TransportProfileUri": profile, "Address": eo("i=15510", jobj{"Url": url}),
			"ReaderGroups": []jobj{psSecure(jobj{"Name": "InteropReaderGroup", "Enabled": true,
				"DataSetReaders": []jobj{reader}}, c.mode, "InteropGroup")},
		}},
		"Enabled": true,
	}}
	if sg := c.securityGroups(); sg != nil {
		cfg["securityGroups"] = sg
	}
	return cfg
}

// psGoMessage is the NetworkMessage go-opcua sends: the header of the
// adapter examples (NetworkMessageContentMask 231, DataSetMessageContentMask
// 61).
func psGoMessage(c psLiveCase, seq uint16, values []any) *message.NetworkMessage {
	fields := make([]*message.Field, len(values))
	now := time.Now()
	for i, v := range values {
		dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)}
		if c.encoding() == message.FieldEncodingDataValue {
			dv.EncodingMask |= ua.DataValueStatusCode | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp
			dv.Status, dv.SourceTimestamp, dv.ServerTimestamp = ua.StatusOK, now, now
		}
		fields[i] = &message.Field{Index: uint16(i), Name: c.vars[i].name, Value: dv}
	}
	return &message.NetworkMessage{
		UADPMask:    psNetworkMessageMask,
		PublisherID: message.NewPublisherID(message.PublisherIDUInt16, psPubID),
		GroupHeader: message.GroupHeader{WriterGroupID: psWriterGroupID, SequenceNumber: seq},
		Timestamp:   now,
		Messages: []*message.DataSetMessage{{
			DataSetWriterID: psWriterID, Type: message.DataSetMessageKeyFrame, Valid: true,
			UADPMask: psDataSetMessageMask, FieldEncoding: c.encoding(), FieldContentMask: c.fcm,
			SequenceNumber: uint32(seq), Timestamp: now,
			MetaDataVersion: ua.ConfigurationVersionDataType{MajorVersion: 1, MinorVersion: 1},
			Fields:          fields,
		}},
	}
}

// psSendLoop sends the message encode returns every 100 ms (with an
// increasing sequence number) until the test ends. Encoding errors fail the
// test.
func psSendLoop(t *testing.T, conn transport.Connection, opts transport.PublishOptions, encode func(seq uint16) ([]byte, error)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	errc := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		<-done
		select {
		case err := <-errc:
			t.Errorf("send loop: %v", err)
		default:
		}
	})
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for seq := uint16(1); ; seq++ {
			b, err := encode(seq)
			if err != nil {
				errc <- err
				return
			}
			// Send errors are expected while the MQTT connection is still
			// being established; the receiving side decides.
			_ = conn.Send(ctx, b, opts)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}

// uadpEncodeSecured encodes nm with SignAndEncrypt.
func uadpEncodeSecured(nm *message.NetworkMessage, keys security.KeySource, nonce uint32, md message.MetaDataLookup) ([]byte, error) {
	return uadp.Encode(nm, &uadp.EncodeOptions{SecurityMode: ua.MessageSecurityModeSignAndEncrypt, Keys: keys, NonceSequence: nonce, MetaData: md})
}

// psUADPEncoder encodes psGoMessage with the case's security.
func psUADPEncoder(t *testing.T, c psLiveCase, values []any) func(uint16) ([]byte, error) {
	keys := c.keys(t)
	md := psLookup(psMetaData(c.vars, c.maxStrLn))
	var nonce uint32
	return func(seq uint16) ([]byte, error) {
		nonce++
		return uadp.Encode(psGoMessage(c, seq, values), &uadp.EncodeOptions{
			SecurityMode: c.mode, Keys: keys, NonceSequence: nonce, MetaData: md})
	}
}

// TestPubSubUDP_GoPublishes_Open62541Subscribes: go-opcua sends UADP over
// UDP unicast to an open62541 subscriber, which writes the fields into its
// TargetVariables.
func TestPubSubUDP_GoPublishes_Open62541Subscribes(t *testing.T) {
	psGoPublishesUDP(t, psOpen62541)
}

// psGoPublishesUDP: go-opcua sends every case of psUDPCases over UDP unicast
// to the peer subscriber, which writes the fields into its TargetVariables.
func psGoPublishesUDP(t *testing.T, p *psPeer) {
	p.requireServer(t)
	for _, c := range psUDPCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			port := freeUDPPort(t)
			sub := startPubSubServer(t, pubsubServerOpts{peer: p,
				config:   psSubscriberConfig(c, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false),
				udpPorts: []int{port},
			})
			values := psValues(c.vars, psFresh())
			conn := psDial(t, transport.Config{ProfileURI: psProfileUDP, URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port)})
			psSendLoop(t, conn, transport.PublishOptions{}, psUADPEncoder(t, c, values))
			waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
		})
	}
}

// ---------------------------------------------------------------------------
// MQTT
// ---------------------------------------------------------------------------

// TestPubSubMQTT_Open62541Publishes_GoReceives: open62541 publishes UADP and
// JSON NetworkMessages to Mosquitto; go-opcua subscribes the topic.
func TestPubSubMQTT_Open62541Publishes_GoReceives(t *testing.T) {
	psPeerPublishesMQTT(t, psOpen62541)
}

// psPeerPublishesMQTT: the peer publishes UADP and JSON over MQTT 3.1.1 to
// Mosquitto; go-opcua subscribes the topic.
func psPeerPublishesMQTT(t *testing.T, p *psPeer) {
	p.requireServer(t)
	broker := startMosquitto(t)
	for _, json := range []bool{false, true} {
		name, profile := "uadp", psProfileMQTTUADP
		if json {
			name, profile = "json", psProfileMQTTJSON
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := psLiveCase{name: name, vars: psVars}
			topic := fmt.Sprintf("go-opcua-interop/%s/%d", name, psFresh())
			ch := psListen(t, transport.Config{ProfileURI: profile, URL: fmt.Sprintf("mqtt://127.0.0.1:%d", broker)}, topic)
			pub := startPubSubServer(t, pubsubServerOpts{peer: p, mqtt311: !p.mqtt5Publisher, config: psPublisherConfig(c, profile,
				fmt.Sprintf("mqtt://host.docker.internal:%d", broker), eo("i=15667", jobj{"QueueName": topic}), json)})
			values := psValues(c.vars, psFresh())
			writePubSubVars(t, pub.endpoint, c.vars, values)
			if !json {
				nm := psReceive(t, ch, psDecodeUADP(c, nil), values, psReceiveTimeout)
				assertPublisherHeaders(t, c, nm)
				return
			}
			md := psLookup(psMetaData(c.vars, 0))
			nm := psReceive(t, ch, func(b []byte) (*message.NetworkMessage, error) {
				return jsonmsg.Decode(b, &jsonmsg.DecodeOptions{MetaData: md})
			}, values, psReceiveTimeout)
			// open62541 writes numeric PublisherIds as JSON strings.
			if nm.PublisherID.String() != fmt.Sprint(psPubID) {
				t.Errorf("PublisherId %q, want %d", nm.PublisherID, psPubID)
			}
			d := nm.Messages[0]
			if d.DataSetWriterID != psWriterID || d.Type != message.DataSetMessageKeyFrame {
				t.Errorf("DataSetMessage writer %d type %v", d.DataSetWriterID, d.Type)
			}
			for i, f := range d.Fields {
				if f.Name != c.vars[i].name {
					t.Errorf("field %d is %q, want %q", i, f.Name, c.vars[i].name)
				}
			}
		})
	}
}

// TestPubSubMQTT_GoPublishes_Open62541Subscribes: go-opcua publishes UADP
// and JSON NetworkMessages to Mosquitto; open62541 subscribes the topic and
// writes the TargetVariables.
func TestPubSubMQTT_GoPublishes_Open62541Subscribes(t *testing.T) {
	psGoPublishesMQTT(t, psOpen62541)
}

// psGoPublishesMQTT: go-opcua publishes UADP and JSON to Mosquitto; the peer
// subscribes the topic over MQTT 3.1.1 and writes its TargetVariables.
func psGoPublishesMQTT(t *testing.T, p *psPeer) {
	p.requireServer(t)
	broker := startMosquitto(t)
	for _, json := range []bool{false, true} {
		name, profile := "uadp", psProfileMQTTUADP
		if json {
			name, profile = "json", psProfileMQTTJSON
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := psLiveCase{name: name, vars: psVars}
			topic := fmt.Sprintf("go-opcua-interop/%s/%d", name, psFresh())
			sub := startPubSubServer(t, pubsubServerOpts{peer: p, mqtt311: true, config: psSubscriberConfig(c, profile,
				fmt.Sprintf("mqtt://host.docker.internal:%d", broker), eo("i=15670", jobj{"QueueName": topic}), json)})
			values := psValues(c.vars, psFresh())
			conn := psDial(t, transport.Config{ProfileURI: profile, URL: fmt.Sprintf("mqtt://127.0.0.1:%d", broker)})
			encode := psUADPEncoder(t, c, values)
			if json {
				encode = func(seq uint16) ([]byte, error) {
					nm := psGoMessage(c, seq, values)
					nm.JSONMask = ua.JSONNetworkMessageContentMaskNetworkMessageHeader | ua.JSONNetworkMessageContentMaskDataSetMessageHeader |
						ua.JSONNetworkMessageContentMaskPublisherID
					nm.Messages[0].JSONMask = ua.JSONDataSetMessageContentMaskDataSetWriterID | ua.JSONDataSetMessageContentMaskMetaDataVersion |
						ua.JSONDataSetMessageContentMaskSequenceNumber | ua.JSONDataSetMessageContentMaskTimestamp |
						ua.JSONDataSetMessageContentMaskStatus | ua.JSONDataSetMessageContentMaskMessageType
					return jsonmsg.Encode(nm, nil)
				}
			}
			psSendLoop(t, conn, transport.PublishOptions{Topic: topic}, encode)
			waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
		})
	}
}

// TestPubSubUDP_Open62541Subscriber_RejectsInsecure: an open62541 reader
// group with SignAndEncrypt (PubSub-Aes256-CTR, static key) must drop
// go-opcua messages that are unsecured or secured with another key, and
// accept the same values once they are secured with its key.
func TestPubSubUDP_Open62541Subscriber_RejectsInsecure(t *testing.T) {
	psPeerSubscriberRejectsInsecure(t, psOpen62541)
}

// psPeerSubscriberRejectsInsecure: a SignAndEncrypt reader group of the peer
// drops unsecured messages and messages under another key.
func psPeerSubscriberRejectsInsecure(t *testing.T, p *psPeer) {
	p.requireServer(t)
	c := psLiveCase{name: "reject", mode: ua.MessageSecurityModeSignAndEncrypt, policy: security.Aes256CTR(), key: psStaticKey256, tokenID: 1, vars: psVars}
	port := freeUDPPort(t)
	sub := startPubSubServer(t, pubsubServerOpts{peer: p,
		config:   psSubscriberConfig(c, psProfileUDP, fmt.Sprintf("opc.udp://0.0.0.0:%d", port), nil, false),
		udpPorts: []int{port},
	})
	values := psValues(c.vars, psFresh())
	conn := psDial(t, transport.Config{ProfileURI: psProfileUDP, URL: fmt.Sprintf("opc.udp://127.0.0.1:%d", port)})

	wrongKey := append([]byte(nil), psStaticKey256...)
	wrongKey[40] ^= 0xFF // another encrypting key, same token id
	plain, wrong := c, c
	plain.mode = ua.MessageSecurityModeNone
	wrong.key = wrongKey
	encoders := []func(uint16) ([]byte, error){psUADPEncoder(t, plain, values), psUADPEncoder(t, wrong, values)}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for seq := uint16(1); ; seq++ {
			if b, err := encoders[seq%2](seq); err == nil {
				_ = conn.Send(context.Background(), b, transport.PublishOptions{})
			}
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	time.Sleep(3 * time.Second)
	close(stop)
	<-done

	cl := dialClient(t, sub.endpoint)
	ctx, ns := findNS(t, cl)
	v, err := cl.ReadValue(ctx, ua.NewStringNodeID(ns, "PubSub.Int32"))
	if err != nil {
		t.Fatalf("read PubSub.Int32: %v", err)
	}
	if got, _ := v.Value.Value().(int32); got == values[1].(int32) {
		t.Fatalf("the subscriber accepted an unsecured message or one with a wrong key (PubSub.Int32 = %d)", got)
	}

	psSendLoop(t, conn, transport.PublishOptions{}, psUADPEncoder(t, c, values))
	waitPubSubVars(t, sub.endpoint, c.vars, values, psReceiveTimeout)
}
