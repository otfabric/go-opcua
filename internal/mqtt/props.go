// SPDX-License-Identifier: MIT

package mqtt

import (
	"encoding/binary"
	"fmt"
)

// Protocol levels of the CONNECT packet (MQTT 3.1.1 §3.1.2.2, MQTT 5.0
// §3.1.2.2).
const (
	Version31  byte = 3 // MQTT 3.1, protocol name "MQIsdp"
	Version311 byte = 4 // MQTT 3.1.1
	Version5   byte = 5 // MQTT 5.0
)

// Reason codes of MQTT 5.0 (§2.4). The codes below 0x80 report success, the
// others failure. CONNACK, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBACK, UNSUBACK,
// DISCONNECT and AUTH carry them.
const (
	ReasonSuccess                     byte = 0x00 // also Normal disconnection, Granted QoS 0
	ReasonGrantedQoS1                 byte = 0x01
	ReasonGrantedQoS2                 byte = 0x02
	ReasonDisconnectWithWill          byte = 0x04
	ReasonNoMatchingSubscribers       byte = 0x10
	ReasonNoSubscriptionExisted       byte = 0x11
	ReasonContinueAuthentication      byte = 0x18
	ReasonReAuthenticate              byte = 0x19
	ReasonUnspecifiedError            byte = 0x80
	ReasonMalformedPacket             byte = 0x81
	ReasonProtocolError               byte = 0x82
	ReasonImplementationSpecific      byte = 0x83
	ReasonUnsupportedProtocolVersion  byte = 0x84
	ReasonClientIdentifierNotValid    byte = 0x85
	ReasonBadUserNameOrPassword       byte = 0x86
	ReasonNotAuthorized               byte = 0x87
	ReasonServerUnavailable           byte = 0x88
	ReasonServerBusy                  byte = 0x89
	ReasonBanned                      byte = 0x8A
	ReasonServerShuttingDown          byte = 0x8B
	ReasonBadAuthenticationMethod     byte = 0x8C
	ReasonKeepAliveTimeout            byte = 0x8D
	ReasonSessionTakenOver            byte = 0x8E
	ReasonTopicFilterInvalid          byte = 0x8F
	ReasonTopicNameInvalid            byte = 0x90
	ReasonPacketIdentifierInUse       byte = 0x91
	ReasonPacketIdentifierNotFound    byte = 0x92
	ReasonReceiveMaximumExceeded      byte = 0x93
	ReasonTopicAliasInvalid           byte = 0x94
	ReasonPacketTooLarge              byte = 0x95
	ReasonMessageRateTooHigh          byte = 0x96
	ReasonQuotaExceeded               byte = 0x97
	ReasonAdministrativeAction        byte = 0x98
	ReasonPayloadFormatInvalid        byte = 0x99
	ReasonRetainNotSupported          byte = 0x9A
	ReasonQoSNotSupported             byte = 0x9B
	ReasonUseAnotherServer            byte = 0x9C
	ReasonServerMoved                 byte = 0x9D
	ReasonSharedSubscriptionsNotSupp  byte = 0x9E
	ReasonConnectionRateExceeded      byte = 0x9F
	ReasonMaximumConnectTime          byte = 0xA0
	ReasonSubscriptionIDsNotSupported byte = 0xA1
	ReasonWildcardSubsNotSupported    byte = 0xA2
)

var reasonNames = map[byte]string{
	ReasonSuccess:                     "success",
	ReasonGrantedQoS1:                 "granted QoS 1",
	ReasonGrantedQoS2:                 "granted QoS 2",
	ReasonDisconnectWithWill:          "disconnect with will message",
	ReasonNoMatchingSubscribers:       "no matching subscribers",
	ReasonNoSubscriptionExisted:       "no subscription existed",
	ReasonContinueAuthentication:      "continue authentication",
	ReasonReAuthenticate:              "re-authenticate",
	ReasonUnspecifiedError:            "unspecified error",
	ReasonMalformedPacket:             "malformed packet",
	ReasonProtocolError:               "protocol error",
	ReasonImplementationSpecific:      "implementation specific error",
	ReasonUnsupportedProtocolVersion:  "unsupported protocol version",
	ReasonClientIdentifierNotValid:    "client identifier not valid",
	ReasonBadUserNameOrPassword:       "bad user name or password",
	ReasonNotAuthorized:               "not authorized",
	ReasonServerUnavailable:           "server unavailable",
	ReasonServerBusy:                  "server busy",
	ReasonBanned:                      "banned",
	ReasonServerShuttingDown:          "server shutting down",
	ReasonBadAuthenticationMethod:     "bad authentication method",
	ReasonKeepAliveTimeout:            "keep alive timeout",
	ReasonSessionTakenOver:            "session taken over",
	ReasonTopicFilterInvalid:          "topic filter invalid",
	ReasonTopicNameInvalid:            "topic name invalid",
	ReasonPacketIdentifierInUse:       "packet identifier in use",
	ReasonPacketIdentifierNotFound:    "packet identifier not found",
	ReasonReceiveMaximumExceeded:      "receive maximum exceeded",
	ReasonTopicAliasInvalid:           "topic alias invalid",
	ReasonPacketTooLarge:              "packet too large",
	ReasonMessageRateTooHigh:          "message rate too high",
	ReasonQuotaExceeded:               "quota exceeded",
	ReasonAdministrativeAction:        "administrative action",
	ReasonPayloadFormatInvalid:        "payload format invalid",
	ReasonRetainNotSupported:          "retain not supported",
	ReasonQoSNotSupported:             "QoS not supported",
	ReasonUseAnotherServer:            "use another server",
	ReasonServerMoved:                 "server moved",
	ReasonSharedSubscriptionsNotSupp:  "shared subscriptions not supported",
	ReasonConnectionRateExceeded:      "connection rate exceeded",
	ReasonMaximumConnectTime:          "maximum connect time",
	ReasonSubscriptionIDsNotSupported: "subscription identifiers not supported",
	ReasonWildcardSubsNotSupported:    "wildcard subscriptions not supported",
}

// ReasonText returns the name of an MQTT 5.0 reason code.
func ReasonText(code byte) string {
	if s, ok := reasonNames[code]; ok {
		return s
	}
	return fmt.Sprintf("reason code %#02x", code)
}

// Limits on received properties. The protocol has no limits of its own
// beyond the packet size; these keep a hostile peer from making a client
// or broker spend memory and time on thousands of tiny properties.
const (
	// MaxUserProperties is the largest number of User Properties a packet
	// may carry.
	MaxUserProperties = 1024
	// MaxSubscriptionIDs is the largest number of Subscription Identifiers
	// a PUBLISH may carry (one per matching subscription).
	MaxSubscriptionIDs = 64
	// MaxSubscriptionID is the largest Subscription Identifier (§3.8.2.1.2).
	MaxSubscriptionID = MaxRemainingLength
)

// UserProperty is an MQTT 5.0 User Property: a UTF-8 string pair. The same
// name may occur more than once and the order is significant (§3.3.2.3.7).
type UserProperty struct {
	Key, Value string
}

// Properties are the MQTT 5.0 properties of a packet (§2.2.2). A nil
// pointer or slice is an absent property. Each packet type allows only some
// of them; Encode and Decode reject the others. Properties are not encoded
// for MQTT 3.1.1 and 3.1, which have none.
type Properties struct {
	PayloadFormat        *byte          // 0x01 PUBLISH, will: 0 bytes, 1 UTF-8
	MessageExpiry        *uint32        // 0x02 PUBLISH, will: seconds
	ContentType          *string        // 0x03 PUBLISH, will: MIME type
	ResponseTopic        *string        // 0x08 PUBLISH, will
	CorrelationData      []byte         // 0x09 PUBLISH, will
	SubscriptionIDs      []uint32       // 0x0B PUBLISH (several), SUBSCRIBE (one)
	SessionExpiry        *uint32        // 0x11 CONNECT, CONNACK, DISCONNECT: seconds
	AssignedClientID     *string        // 0x12 CONNACK
	ServerKeepAlive      *uint16        // 0x13 CONNACK: seconds
	AuthMethod           *string        // 0x15 CONNECT, CONNACK, AUTH
	AuthData             []byte         // 0x16 CONNECT, CONNACK, AUTH
	RequestProblemInfo   *byte          // 0x17 CONNECT: 0 or 1
	WillDelay            *uint32        // 0x18 will: seconds
	RequestResponseInfo  *byte          // 0x19 CONNECT: 0 or 1
	ResponseInfo         *string        // 0x1A CONNACK
	ServerReference      *string        // 0x1C CONNACK, DISCONNECT
	ReasonString         *string        // 0x1F CONNACK, acks, SUBACK, UNSUBACK, DISCONNECT, AUTH
	ReceiveMaximum       *uint16        // 0x21 CONNECT, CONNACK: not 0
	TopicAliasMaximum    *uint16        // 0x22 CONNECT, CONNACK
	TopicAlias           *uint16        // 0x23 PUBLISH: not 0
	MaximumQoS           *byte          // 0x24 CONNACK: 0 or 1
	RetainAvailable      *byte          // 0x25 CONNACK: 0 or 1
	User                 []UserProperty // 0x26 all packets with properties
	MaximumPacketSize    *uint32        // 0x27 CONNECT, CONNACK: not 0
	WildcardSubAvailable *byte          // 0x28 CONNACK: 0 or 1
	SubIDAvailable       *byte          // 0x29 CONNACK: 0 or 1
	SharedSubAvailable   *byte          // 0x2A CONNACK: 0 or 1
}

// Ptr returns a pointer to v, for the optional fields of [Properties].
func Ptr[T any](v T) *T { return &v }

// Property identifiers (§2.2.2.2).
const (
	propPayloadFormat        = 0x01
	propMessageExpiry        = 0x02
	propContentType          = 0x03
	propResponseTopic        = 0x08
	propCorrelationData      = 0x09
	propSubscriptionID       = 0x0B
	propSessionExpiry        = 0x11
	propAssignedClientID     = 0x12
	propServerKeepAlive      = 0x13
	propAuthMethod           = 0x15
	propAuthData             = 0x16
	propRequestProblemInfo   = 0x17
	propWillDelay            = 0x18
	propRequestResponseInfo  = 0x19
	propResponseInfo         = 0x1A
	propServerReference      = 0x1C
	propReasonString         = 0x1F
	propReceiveMaximum       = 0x21
	propTopicAliasMaximum    = 0x22
	propTopicAlias           = 0x23
	propMaximumQoS           = 0x24
	propRetainAvailable      = 0x25
	propUser                 = 0x26
	propMaximumPacketSize    = 0x27
	propWildcardSubAvailable = 0x28
	propSubIDAvailable       = 0x29
	propSharedSubAvailable   = 0x2A
)

// typeWill stands for the will properties of a CONNECT in the table of
// allowed properties.
const typeWill byte = 16

func bit(types ...byte) uint32 {
	var m uint32
	for _, t := range types {
		m |= 1 << t
	}
	return m
}

var (
	acks = bit(TypePuback, TypePubrec, TypePubrel, TypePubcomp)
	// allowedProps lists the packet types each property may appear in
	// (§2.2.2.2, Table 2-4).
	allowedProps = map[byte]uint32{
		propPayloadFormat:        bit(TypePublish, typeWill),
		propMessageExpiry:        bit(TypePublish, typeWill),
		propContentType:          bit(TypePublish, typeWill),
		propResponseTopic:        bit(TypePublish, typeWill),
		propCorrelationData:      bit(TypePublish, typeWill),
		propSubscriptionID:       bit(TypePublish, TypeSubscribe),
		propSessionExpiry:        bit(TypeConnect, TypeConnack, TypeDisconnect),
		propAssignedClientID:     bit(TypeConnack),
		propServerKeepAlive:      bit(TypeConnack),
		propAuthMethod:           bit(TypeConnect, TypeConnack, TypeAuth),
		propAuthData:             bit(TypeConnect, TypeConnack, TypeAuth),
		propRequestProblemInfo:   bit(TypeConnect),
		propWillDelay:            bit(typeWill),
		propRequestResponseInfo:  bit(TypeConnect),
		propResponseInfo:         bit(TypeConnack),
		propServerReference:      bit(TypeConnack, TypeDisconnect),
		propReasonString:         bit(TypeConnack, TypeSuback, TypeUnsuback, TypeDisconnect, TypeAuth) | acks,
		propReceiveMaximum:       bit(TypeConnect, TypeConnack),
		propTopicAliasMaximum:    bit(TypeConnect, TypeConnack),
		propTopicAlias:           bit(TypePublish),
		propMaximumQoS:           bit(TypeConnack),
		propRetainAvailable:      bit(TypeConnack),
		propUser:                 0xffffffff,
		propMaximumPacketSize:    bit(TypeConnect, TypeConnack),
		propWildcardSubAvailable: bit(TypeConnack),
		propSubIDAvailable:       bit(TypeConnack),
		propSharedSubAvailable:   bit(TypeConnack),
	}
)

// propWriter appends the properties of one packet and checks that the
// packet type allows them.
type propWriter struct {
	b   []byte
	pt  byte
	err error
}

func (w *propWriter) id(id byte) bool {
	if w.err != nil {
		return false
	}
	if allowedProps[id]&(1<<w.pt) == 0 {
		w.err = protoErr("property %#02x is not allowed in packet type %d", id, w.pt)
		return false
	}
	w.b = append(w.b, id)
	return true
}

func (w *propWriter) flag(id byte, v *byte, maxv byte) {
	if v == nil {
		return
	}
	if *v > maxv {
		w.err = protoErr("property %#02x has the value %d", id, *v)
		return
	}
	if w.id(id) {
		w.b = append(w.b, *v)
	}
}

func (w *propWriter) u16(id byte, v *uint16, nonZero bool) {
	if v == nil {
		return
	}
	if nonZero && *v == 0 && w.err == nil {
		w.err = protoErr("property %#02x is 0", id)
		return
	}
	if w.id(id) {
		w.b = binary.BigEndian.AppendUint16(w.b, *v)
	}
}

func (w *propWriter) u32(id byte, v *uint32, nonZero bool) {
	if v == nil {
		return
	}
	if nonZero && *v == 0 && w.err == nil {
		w.err = protoErr("property %#02x is 0", id)
		return
	}
	if w.id(id) {
		w.b = binary.BigEndian.AppendUint32(w.b, *v)
	}
}

func (w *propWriter) str(id byte, v *string) {
	if v == nil {
		return
	}
	if !validString(*v) && w.err == nil {
		w.err = protoErr("property %#02x is not a valid UTF-8 string", id)
		return
	}
	if w.id(id) {
		w.b = appendString(w.b, *v)
	}
}

func (w *propWriter) bin(id byte, v []byte) {
	if v == nil {
		return
	}
	if len(v) > 65535 && w.err == nil {
		w.err = protoErr("property %#02x of %d bytes is too long", id, len(v))
		return
	}
	if w.id(id) {
		w.b = appendBytes(w.b, v)
	}
}

// appendProps appends the property length and the properties of a packet
// of type pt.
func appendProps(b []byte, pt byte, p *Properties) ([]byte, error) {
	w := &propWriter{pt: pt}
	w.flag(propPayloadFormat, p.PayloadFormat, 1)
	w.u32(propMessageExpiry, p.MessageExpiry, false)
	w.str(propContentType, p.ContentType)
	if p.ResponseTopic != nil && !ValidTopicName(*p.ResponseTopic) && w.err == nil {
		w.err = protoErr("invalid response topic %q", *p.ResponseTopic)
	}
	w.str(propResponseTopic, p.ResponseTopic)
	w.bin(propCorrelationData, p.CorrelationData)
	if pt == TypeSubscribe && len(p.SubscriptionIDs) > 1 && w.err == nil {
		w.err = protoErr("SUBSCRIBE with %d subscription identifiers", len(p.SubscriptionIDs))
	}
	for _, id := range p.SubscriptionIDs {
		if (id == 0 || id > MaxSubscriptionID) && w.err == nil {
			w.err = protoErr("subscription identifier %d", id)
		}
		if w.id(propSubscriptionID) {
			w.b = appendVarint(w.b, int(id))
		}
	}
	w.u32(propSessionExpiry, p.SessionExpiry, false)
	w.str(propAssignedClientID, p.AssignedClientID)
	w.u16(propServerKeepAlive, p.ServerKeepAlive, false)
	w.str(propAuthMethod, p.AuthMethod)
	w.bin(propAuthData, p.AuthData)
	w.flag(propRequestProblemInfo, p.RequestProblemInfo, 1)
	w.u32(propWillDelay, p.WillDelay, false)
	w.flag(propRequestResponseInfo, p.RequestResponseInfo, 1)
	w.str(propResponseInfo, p.ResponseInfo)
	w.str(propServerReference, p.ServerReference)
	w.str(propReasonString, p.ReasonString)
	w.u16(propReceiveMaximum, p.ReceiveMaximum, true)
	w.u16(propTopicAliasMaximum, p.TopicAliasMaximum, false)
	w.u16(propTopicAlias, p.TopicAlias, true)
	w.flag(propMaximumQoS, p.MaximumQoS, 1)
	w.flag(propRetainAvailable, p.RetainAvailable, 1)
	for i := range p.User {
		u := &p.User[i]
		if (!validString(u.Key) || !validString(u.Value)) && w.err == nil {
			w.err = protoErr("user property %q is not a valid UTF-8 string pair", u.Key)
		}
		if w.id(propUser) {
			w.b = appendString(appendString(w.b, u.Key), u.Value)
		}
	}
	w.u32(propMaximumPacketSize, p.MaximumPacketSize, true)
	w.flag(propWildcardSubAvailable, p.WildcardSubAvailable, 1)
	w.flag(propSubIDAvailable, p.SubIDAvailable, 1)
	w.flag(propSharedSubAvailable, p.SharedSubAvailable, 1)
	if w.err != nil {
		return nil, w.err
	}
	if len(w.b) > MaxRemainingLength {
		return nil, protoErr("properties of %d bytes are too large", len(w.b))
	}
	b = appendVarint(b, len(w.b))
	return append(b, w.b...), nil
}

// validString reports whether s may be an MQTT UTF-8 string: at most 65535
// bytes of valid UTF-8 without NUL (§1.5.4).
func validString(s string) bool {
	return len(s) <= 65535 && validUTF8(s)
}

// props reads the property length and the properties of a packet of type
// pt (§2.2.2).
func (r *reader) props(pt byte) Properties {
	var p Properties
	n := r.varint()
	if r.err != nil {
		return p
	}
	if n > len(r.b) {
		r.fail()
		return p
	}
	pr := &reader{b: r.b[:n]}
	r.b = r.b[n:]
	seen := uint64(0)
	once := func(id byte) bool {
		if seen&(1<<id) != 0 {
			pr.err = protoErr("property %#02x appears twice", id)
			return false
		}
		seen |= 1 << id
		return true
	}
	flag := func(id byte, maxv byte) *byte {
		if !once(id) {
			return nil
		}
		v := pr.u8()
		if pr.err == nil && v > maxv {
			pr.err = protoErr("property %#02x has the value %d", id, v)
		}
		return &v
	}
	u16 := func(id byte, nonZero bool) *uint16 {
		if !once(id) {
			return nil
		}
		v := pr.u16()
		if pr.err == nil && nonZero && v == 0 {
			pr.err = protoErr("property %#02x is 0", id)
		}
		return &v
	}
	u32 := func(id byte, nonZero bool) *uint32 {
		if !once(id) {
			return nil
		}
		v := pr.u32()
		if pr.err == nil && nonZero && v == 0 {
			pr.err = protoErr("property %#02x is 0", id)
		}
		return &v
	}
	str := func(id byte) *string {
		if !once(id) {
			return nil
		}
		v := pr.str()
		return &v
	}
	bin := func(id byte) []byte {
		if !once(id) {
			return nil
		}
		return pr.bytes()
	}
	for pr.err == nil && len(pr.b) > 0 {
		// Identifiers are variable byte integers; all defined ones fit in
		// one byte, so a longer one is unknown anyway.
		id := pr.u8()
		if pr.err != nil {
			break
		}
		if m, ok := allowedProps[id]; !ok || m&(1<<pt) == 0 {
			pr.err = protoErr("property %#02x is not allowed in packet type %d", id, pt)
			break
		}
		switch id {
		case propPayloadFormat:
			p.PayloadFormat = flag(id, 1)
		case propMessageExpiry:
			p.MessageExpiry = u32(id, false)
		case propContentType:
			p.ContentType = str(id)
		case propResponseTopic:
			p.ResponseTopic = str(id)
			if pr.err == nil && !ValidTopicName(*p.ResponseTopic) {
				pr.err = protoErr("invalid response topic %q", *p.ResponseTopic)
			}
		case propCorrelationData:
			p.CorrelationData = bin(id)
		case propSubscriptionID:
			if pt == TypeSubscribe && len(p.SubscriptionIDs) > 0 {
				pr.err = protoErr("SUBSCRIBE with two subscription identifiers")
				break
			}
			if len(p.SubscriptionIDs) >= MaxSubscriptionIDs {
				pr.err = protoErr("more than %d subscription identifiers", MaxSubscriptionIDs)
				break
			}
			v := pr.varint()
			if pr.err == nil && v == 0 {
				pr.err = protoErr("subscription identifier 0")
			}
			p.SubscriptionIDs = append(p.SubscriptionIDs, uint32(v))
		case propSessionExpiry:
			p.SessionExpiry = u32(id, false)
		case propAssignedClientID:
			p.AssignedClientID = str(id)
		case propServerKeepAlive:
			p.ServerKeepAlive = u16(id, false)
		case propAuthMethod:
			p.AuthMethod = str(id)
		case propAuthData:
			p.AuthData = bin(id)
		case propRequestProblemInfo:
			p.RequestProblemInfo = flag(id, 1)
		case propWillDelay:
			p.WillDelay = u32(id, false)
		case propRequestResponseInfo:
			p.RequestResponseInfo = flag(id, 1)
		case propResponseInfo:
			p.ResponseInfo = str(id)
		case propServerReference:
			p.ServerReference = str(id)
		case propReasonString:
			p.ReasonString = str(id)
		case propReceiveMaximum:
			p.ReceiveMaximum = u16(id, true)
		case propTopicAliasMaximum:
			p.TopicAliasMaximum = u16(id, false)
		case propTopicAlias:
			p.TopicAlias = u16(id, true)
		case propMaximumQoS:
			p.MaximumQoS = flag(id, 1)
		case propRetainAvailable:
			p.RetainAvailable = flag(id, 1)
		case propUser:
			if len(p.User) >= MaxUserProperties {
				pr.err = protoErr("more than %d user properties", MaxUserProperties)
				break
			}
			k := pr.str()
			v := pr.str()
			p.User = append(p.User, UserProperty{Key: k, Value: v})
		case propMaximumPacketSize:
			p.MaximumPacketSize = u32(id, true)
		case propWildcardSubAvailable:
			p.WildcardSubAvailable = flag(id, 1)
		case propSubIDAvailable:
			p.SubIDAvailable = flag(id, 1)
		case propSharedSubAvailable:
			p.SharedSubAvailable = flag(id, 1)
		}
	}
	if pr.err != nil && r.err == nil {
		r.err = pr.err
	}
	return p
}

func (r *reader) u32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

// varint reads a variable byte integer (§1.5.5) of at most four bytes.
func (r *reader) varint() int {
	if r.err != nil {
		return 0
	}
	n, mul := 0, 1
	for i := 0; i < 4; i++ {
		if len(r.b) == 0 {
			r.fail()
			return 0
		}
		c := r.b[0]
		r.b = r.b[1:]
		n += int(c&0x7f) * mul
		if c&0x80 == 0 {
			return n
		}
		mul *= 128
	}
	r.err = protoErr("malformed variable byte integer")
	return 0
}
