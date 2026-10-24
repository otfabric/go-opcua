// SPDX-License-Identifier: MIT

package mqtt

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Packet types of MQTT 3.1.1 (§2.2.1) and MQTT 5.0 (§2.1.2), which adds
// AUTH.
const (
	TypeConnect     byte = 1
	TypeConnack     byte = 2
	TypePublish     byte = 3
	TypePuback      byte = 4
	TypePubrec      byte = 5
	TypePubrel      byte = 6
	TypePubcomp     byte = 7
	TypeSubscribe   byte = 8
	TypeSuback      byte = 9
	TypeUnsubscribe byte = 10
	TypeUnsuback    byte = 11
	TypePingreq     byte = 12
	TypePingresp    byte = 13
	TypeDisconnect  byte = 14
	TypeAuth        byte = 15 // MQTT 5.0 only
)

// CONNACK return codes of MQTT 3.1.1 (§3.2.2.3). MQTT 5.0 uses the reason
// codes (ReasonUnsupportedProtocolVersion, ...) instead.
const (
	ConnAccepted                  byte = 0
	ConnRefusedProtocolVersion    byte = 1
	ConnRefusedIdentifierRejected byte = 2
	ConnRefusedServerUnavailable  byte = 3
	ConnRefusedBadCredentials     byte = 4
	ConnRefusedNotAuthorized      byte = 5
)

// SubackFailure is the SUBACK return code of a refused subscription in
// MQTT 3.1.1; in MQTT 5.0 every code from 0x80 is a refusal.
const SubackFailure byte = 0x80

// MaxRemainingLength is the largest remaining length the protocol can
// express (§2.2.3).
const MaxRemainingLength = 268435455

// ErrProtocol is wrapped by all errors about malformed packets.
var ErrProtocol = errors.New("mqtt: protocol error")

func protoErr(format string, args ...interface{}) error {
	return fmt.Errorf("%w: "+format, append([]interface{}{ErrProtocol}, args...)...)
}

// Packet is one of the packet structs of this file.
type Packet interface {
	// Type is the MQTT control packet type.
	Type() byte
}

// Will is the will message of a CONNECT.
type Will struct {
	Topic   string
	Payload []byte
	QoS     byte
	Retain  bool
	// Props are the will properties (MQTT 5.0 §3.1.3.2).
	Props Properties
}

// Connect is a CONNECT packet.
type Connect struct {
	// ProtocolName is "MQTT" (level 4, 3.1.1, and level 5, 5.0) or
	// "MQIsdp" (level 3, 3.1).
	ProtocolName  string
	ProtocolLevel byte
	// CleanSession is Clean Session in 3.1.1 and Clean Start in 5.0.
	CleanSession bool
	KeepAlive    uint16 // seconds
	ClientID     string
	Will         *Will
	Username     *string
	Password     []byte // nil: no password
	Props        Properties
}

// Connack is a CONNACK packet.
type Connack struct {
	SessionPresent bool
	// ReturnCode is the 3.1.1 return code or the 5.0 reason code.
	ReturnCode byte
	Props      Properties
}

// Publish is a PUBLISH packet.
type Publish struct {
	Dup      bool
	QoS      byte
	Retain   bool
	Topic    string // empty only with a topic alias (5.0)
	PacketID uint16 // QoS 1 and 2 only
	Payload  []byte
	Props    Properties
}

// Ack is a PUBACK, PUBREC, PUBREL, PUBCOMP or UNSUBACK packet: a packet
// that is mostly a packet identifier.
type Ack struct {
	Kind     byte
	PacketID uint16
	// ReasonCode is the reason code of a 5.0 PUBACK, PUBREC, PUBREL or
	// PUBCOMP.
	ReasonCode byte
	// ReasonCodes are the reason codes of a 5.0 UNSUBACK, one per filter.
	ReasonCodes []byte
	Props       Properties
}

// Retain handling options of a subscription (MQTT 5.0 §3.8.3.1).
const (
	RetainSendOnSubscribe byte = 0 // send retained messages on every SUBSCRIBE
	RetainSendIfNew       byte = 1 // only if the subscription is new
	RetainDoNotSend       byte = 2 // never
)

// TopicFilter is one topic filter of a SUBSCRIBE with its subscription
// options. NoLocal, RetainAsPublished and RetainHandling exist only in
// MQTT 5.0 (§3.8.3.1).
type TopicFilter struct {
	Filter            string
	QoS               byte
	NoLocal           bool
	RetainAsPublished bool
	RetainHandling    byte
}

// Subscribe is a SUBSCRIBE packet.
type Subscribe struct {
	PacketID uint16
	Topics   []TopicFilter
	Props    Properties
}

// Suback is a SUBACK packet.
type Suback struct {
	PacketID uint16
	// ReturnCodes are the 3.1.1 return codes or the 5.0 reason codes.
	ReturnCodes []byte
	Props       Properties
}

// Unsubscribe is an UNSUBSCRIBE packet.
type Unsubscribe struct {
	PacketID uint16
	Filters  []string
	Props    Properties
}

// Simple is a PINGREQ or PINGRESP packet. Encode also accepts it for a
// DISCONNECT without reason code; Decode returns a [Disconnect].
type Simple struct{ Kind byte }

// Disconnect is a DISCONNECT packet. Before 5.0 it has no reason code
// and no properties.
type Disconnect struct {
	ReasonCode byte
	Props      Properties
}

// Auth is an AUTH packet (MQTT 5.0 §3.15).
type Auth struct {
	ReasonCode byte
	Props      Properties
}

func (*Connect) Type() byte     { return TypeConnect }
func (*Connack) Type() byte     { return TypeConnack }
func (*Publish) Type() byte     { return TypePublish }
func (a *Ack) Type() byte       { return a.Kind }
func (*Subscribe) Type() byte   { return TypeSubscribe }
func (*Suback) Type() byte      { return TypeSuback }
func (*Unsubscribe) Type() byte { return TypeUnsubscribe }
func (s *Simple) Type() byte    { return s.Kind }
func (*Disconnect) Type() byte  { return TypeDisconnect }
func (*Auth) Type() byte        { return TypeAuth }

// Encode returns the MQTT 3.1.1 wire form of a packet (a CONNECT is
// encoded for its own protocol level).
func Encode(p Packet) ([]byte, error) { return EncodeVersion(p, Version311) }

// EncodeVersion returns the wire form of a packet for a protocol level.
// The MQTT 5.0 fields (properties, reason codes, subscription options) are
// left out for the levels before 5. A CONNECT is encoded for its own
// ProtocolLevel.
func EncodeVersion(p Packet, version byte) ([]byte, error) {
	v5 := version >= Version5
	var body []byte
	var flags byte
	var err error
	switch p := p.(type) {
	case *Connect:
		name, level := p.ProtocolName, p.ProtocolLevel
		if name == "" {
			name, level = "MQTT", Version311
			if p.ProtocolLevel == Version5 {
				level = Version5
			}
		}
		v5 = level >= Version5
		body = appendString(body, name)
		body = append(body, level)
		var cf byte
		if p.CleanSession {
			cf |= 0x02
		}
		if p.Will != nil {
			if p.Will.QoS > 2 {
				return nil, protoErr("will QoS %d", p.Will.QoS)
			}
			cf |= 0x04 | p.Will.QoS<<3
			if p.Will.Retain {
				cf |= 0x20
			}
		}
		if p.Password != nil {
			// 5.0 allows a password without a user name (§3.1.2.9).
			if p.Username == nil && !v5 {
				return nil, protoErr("password without user name")
			}
			cf |= 0x40
		}
		if p.Username != nil {
			cf |= 0x80
		}
		body = append(body, cf)
		body = binary.BigEndian.AppendUint16(body, p.KeepAlive)
		if v5 {
			if body, err = appendProps(body, TypeConnect, &p.Props); err != nil {
				return nil, err
			}
		}
		body = appendString(body, p.ClientID)
		if p.Will != nil {
			if v5 {
				if body, err = appendProps(body, typeWill, &p.Will.Props); err != nil {
					return nil, err
				}
			}
			body = appendString(body, p.Will.Topic)
			body = appendBytes(body, p.Will.Payload)
		}
		if p.Username != nil {
			body = appendString(body, *p.Username)
		}
		if p.Password != nil {
			body = appendBytes(body, p.Password)
		}
	case *Connack:
		if p.SessionPresent {
			body = append(body, 1)
		} else {
			body = append(body, 0)
		}
		body = append(body, p.ReturnCode)
		if v5 {
			if body, err = appendProps(body, TypeConnack, &p.Props); err != nil {
				return nil, err
			}
		}
	case *Publish:
		if p.QoS > 2 {
			return nil, protoErr("QoS %d", p.QoS)
		}
		if !ValidTopicName(p.Topic) && (!v5 || p.Topic != "" || p.Props.TopicAlias == nil) {
			return nil, protoErr("invalid topic name %q", p.Topic)
		}
		flags = p.QoS << 1
		if p.Dup {
			flags |= 0x08
		}
		if p.Retain {
			flags |= 0x01
		}
		body = appendString(body, p.Topic)
		if p.QoS > 0 {
			if p.PacketID == 0 {
				return nil, protoErr("QoS %d PUBLISH without packet identifier", p.QoS)
			}
			body = binary.BigEndian.AppendUint16(body, p.PacketID)
		}
		if v5 {
			if body, err = appendProps(body, TypePublish, &p.Props); err != nil {
				return nil, err
			}
		}
		body = append(body, p.Payload...)
	case *Ack:
		switch p.Kind {
		case TypePuback, TypePubrec, TypePubcomp, TypeUnsuback:
		case TypePubrel:
			flags = 0x02
		default:
			return nil, protoErr("packet type %d is not an acknowledgement", p.Kind)
		}
		body = binary.BigEndian.AppendUint16(body, p.PacketID)
		switch {
		case !v5:
		case p.Kind == TypeUnsuback:
			if len(p.ReasonCodes) == 0 {
				return nil, protoErr("UNSUBACK without reason codes")
			}
			if body, err = appendProps(body, TypeUnsuback, &p.Props); err != nil {
				return nil, err
			}
			body = append(body, p.ReasonCodes...)
		case p.ReasonCode != ReasonSuccess || !p.Props.empty():
			// The short forms of §3.4.2.1: no reason code means Success,
			// no property length means no properties.
			body = append(body, p.ReasonCode)
			if !p.Props.empty() {
				if body, err = appendProps(body, p.Kind, &p.Props); err != nil {
					return nil, err
				}
			}
		}
	case *Subscribe:
		if len(p.Topics) == 0 {
			return nil, protoErr("SUBSCRIBE without topic filters")
		}
		flags = 0x02
		body = binary.BigEndian.AppendUint16(body, p.PacketID)
		if v5 {
			if body, err = appendProps(body, TypeSubscribe, &p.Props); err != nil {
				return nil, err
			}
		}
		for _, s := range p.Topics {
			if !ValidTopicFilter(s.Filter) || s.QoS > 2 || s.RetainHandling > 2 {
				return nil, protoErr("invalid subscription %q QoS %d", s.Filter, s.QoS)
			}
			body = appendString(body, s.Filter)
			o := s.QoS
			if v5 {
				if s.NoLocal {
					o |= 0x04
				}
				if s.RetainAsPublished {
					o |= 0x08
				}
				o |= s.RetainHandling << 4
			}
			body = append(body, o)
		}
	case *Suback:
		body = binary.BigEndian.AppendUint16(body, p.PacketID)
		if v5 {
			if body, err = appendProps(body, TypeSuback, &p.Props); err != nil {
				return nil, err
			}
		}
		body = append(body, p.ReturnCodes...)
	case *Unsubscribe:
		if len(p.Filters) == 0 {
			return nil, protoErr("UNSUBSCRIBE without topic filters")
		}
		flags = 0x02
		body = binary.BigEndian.AppendUint16(body, p.PacketID)
		if v5 {
			if body, err = appendProps(body, TypeUnsubscribe, &p.Props); err != nil {
				return nil, err
			}
		}
		for _, f := range p.Filters {
			if v5 && !ValidTopicFilter(f) {
				return nil, protoErr("invalid topic filter %q", f)
			}
			body = appendString(body, f)
		}
	case *Simple:
		switch p.Kind {
		case TypePingreq, TypePingresp, TypeDisconnect:
		default:
			return nil, protoErr("packet type %d has a body", p.Kind)
		}
	case *Disconnect:
		if body, err = appendReasonProps(body, v5, TypeDisconnect, p.ReasonCode, &p.Props); err != nil {
			return nil, err
		}
	case *Auth:
		if !v5 {
			return nil, protoErr("AUTH before MQTT 5.0")
		}
		if body, err = appendReasonProps(body, v5, TypeAuth, p.ReasonCode, &p.Props); err != nil {
			return nil, err
		}
	default:
		return nil, protoErr("unknown packet %T", p)
	}
	if len(body) > MaxRemainingLength {
		return nil, protoErr("packet of %d bytes is too large", len(body))
	}
	out := make([]byte, 0, len(body)+5)
	out = append(out, p.Type()<<4|flags)
	out = appendVarint(out, len(body))
	return append(out, body...), nil
}

// appendReasonProps appends the body of a DISCONNECT or AUTH (§3.14.2):
// nothing for Success without properties.
func appendReasonProps(b []byte, v5 bool, pt, code byte, p *Properties) ([]byte, error) {
	if !v5 || code == ReasonSuccess && p.empty() {
		return b, nil
	}
	b = append(b, code)
	if p.empty() {
		return b, nil
	}
	return appendProps(b, pt, p)
}

// empty reports whether no property is set.
func (p *Properties) empty() bool {
	return p.PayloadFormat == nil && p.MessageExpiry == nil && p.ContentType == nil &&
		p.ResponseTopic == nil && p.CorrelationData == nil && len(p.SubscriptionIDs) == 0 &&
		p.SessionExpiry == nil && p.AssignedClientID == nil && p.ServerKeepAlive == nil &&
		p.AuthMethod == nil && p.AuthData == nil && p.RequestProblemInfo == nil &&
		p.WillDelay == nil && p.RequestResponseInfo == nil && p.ResponseInfo == nil &&
		p.ServerReference == nil && p.ReasonString == nil && p.ReceiveMaximum == nil &&
		p.TopicAliasMaximum == nil && p.TopicAlias == nil && p.MaximumQoS == nil &&
		p.RetainAvailable == nil && len(p.User) == 0 && p.MaximumPacketSize == nil &&
		p.WildcardSubAvailable == nil && p.SubIDAvailable == nil && p.SharedSubAvailable == nil
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func appendBytes(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func appendVarint(b []byte, n int) []byte {
	for {
		c := byte(n % 128)
		n /= 128
		if n > 0 {
			c |= 0x80
		}
		b = append(b, c)
		if n == 0 {
			return b
		}
	}
}

// ErrTooLarge is returned by ReadPacket for a packet above the limit. The
// packet has been skipped and the stream is still usable.
var ErrTooLarge = errors.New("mqtt: packet too large")

// ReadPacket reads one MQTT 3.1.1 packet. Packets with a remaining length
// above max (if max > 0) are skipped and reported with ErrTooLarge.
func ReadPacket(r *bufio.Reader, max int) (Packet, error) {
	return ReadPacketVersion(r, max, Version311)
}

// ReadPacketVersion reads one packet of a protocol level, like ReadPacket.
func ReadPacketVersion(r *bufio.Reader, max int, version byte) (Packet, error) {
	h, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	n, err := readVarint(r)
	if err != nil {
		return nil, err
	}
	if max > 0 && n > max {
		if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
			return nil, unexpected(err)
		}
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, unexpected(err)
	}
	return DecodeVersion(h, body, version)
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func readVarint(r io.ByteReader) (int, error) {
	n, mul := 0, 1
	for i := 0; i < 4; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, unexpected(err)
		}
		n += int(c&0x7f) * mul
		if c&0x80 == 0 {
			return n, nil
		}
		mul *= 128
	}
	return 0, protoErr("malformed remaining length")
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) u8() byte {
	if r.err != nil || len(r.b) < 1 {
		r.fail()
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *reader) u16() uint16 {
	if r.err != nil || len(r.b) < 2 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *reader) bytes() []byte {
	n := int(r.u16())
	if r.err != nil || len(r.b) < n {
		r.fail()
		return nil
	}
	v := append([]byte{}, r.b[:n]...)
	r.b = r.b[n:]
	return v
}

func (r *reader) str() string {
	b := r.bytes()
	if r.err == nil && !validUTF8(string(b)) {
		r.err = protoErr("string is not valid UTF-8")
	}
	return string(b)
}

// validUTF8 reports whether s is valid UTF-8 without NUL (§1.5.4).
func validUTF8(s string) bool {
	return utf8.ValidString(s) && strings.IndexByte(s, 0) < 0
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = protoErr("packet too short")
	}
}

// Decode decodes an MQTT 3.1.1 packet from its first byte and its body. A
// CONNECT is decoded for its own protocol level.
func Decode(header byte, body []byte) (Packet, error) {
	return DecodeVersion(header, body, Version311)
}

// DecodeVersion decodes a packet of a protocol level from its first byte
// and its body.
func DecodeVersion(header byte, body []byte, version byte) (Packet, error) {
	v5 := version >= Version5
	typ, flags := header>>4, header&0x0f
	r := &reader{b: body}
	wantFlags := func(f byte) error {
		if flags != f {
			return protoErr("packet type %d with flags %#x", typ, flags)
		}
		return nil
	}
	var p Packet
	switch typ {
	case TypeConnect:
		if err := wantFlags(0); err != nil {
			return nil, err
		}
		c := &Connect{ProtocolName: r.str(), ProtocolLevel: r.u8()}
		v5 = c.ProtocolLevel >= Version5
		cf := r.u8()
		c.KeepAlive = r.u16()
		if v5 {
			c.Props = r.props(TypeConnect)
		}
		c.ClientID = r.str()
		if r.err != nil {
			return nil, r.err
		}
		if cf&0x01 != 0 {
			return nil, protoErr("reserved CONNECT flag set")
		}
		c.CleanSession = cf&0x02 != 0
		if cf&0x04 != 0 {
			w := &Will{QoS: cf >> 3 & 3, Retain: cf&0x20 != 0}
			if w.QoS > 2 {
				return nil, protoErr("will QoS 3")
			}
			if v5 {
				w.Props = r.props(typeWill)
			}
			w.Topic = r.str()
			w.Payload = r.bytes()
			if v5 && r.err == nil && !ValidTopicName(w.Topic) {
				return nil, protoErr("invalid will topic %q", w.Topic)
			}
			c.Will = w
		} else if cf&0x38 != 0 {
			return nil, protoErr("will flags without will")
		}
		if cf&0x80 != 0 {
			u := r.str()
			c.Username = &u
		}
		if cf&0x40 != 0 {
			if cf&0x80 == 0 && !v5 {
				return nil, protoErr("password without user name")
			}
			c.Password = r.bytes()
			if c.Password == nil {
				c.Password = []byte{}
			}
		}
		p = c
	case TypeConnack:
		if err := wantFlags(0); err != nil {
			return nil, err
		}
		f := r.u8()
		if v5 && r.err == nil && f&0xfe != 0 {
			return nil, protoErr("reserved CONNACK flags %#x", f)
		}
		c := &Connack{SessionPresent: f&1 != 0, ReturnCode: r.u8()}
		// A broker that does not speak 5.0 refuses with the two bytes of a
		// 3.1.1 CONNACK: no property length.
		if v5 && r.err == nil && len(r.b) > 0 {
			c.Props = r.props(TypeConnack)
		}
		p = c
	case TypePublish:
		pub := &Publish{Dup: flags&0x08 != 0, QoS: flags >> 1 & 3, Retain: flags&0x01 != 0}
		if pub.QoS > 2 {
			return nil, protoErr("PUBLISH with QoS 3")
		}
		if v5 && pub.QoS == 0 && pub.Dup {
			return nil, protoErr("QoS 0 PUBLISH with DUP")
		}
		pub.Topic = r.str()
		if pub.QoS > 0 {
			pub.PacketID = r.u16()
			if r.err == nil && pub.PacketID == 0 {
				return nil, protoErr("PUBLISH with packet identifier 0")
			}
		}
		if v5 {
			pub.Props = r.props(TypePublish)
		}
		if r.err == nil && !ValidTopicName(pub.Topic) && (!v5 || pub.Topic != "" || pub.Props.TopicAlias == nil) {
			return nil, protoErr("invalid topic name %q", pub.Topic)
		}
		pub.Payload = r.b
		r.b = nil
		p = pub
	case TypePuback, TypePubrec, TypePubrel, TypePubcomp, TypeUnsuback:
		f := byte(0)
		if typ == TypePubrel {
			f = 0x02
		}
		if err := wantFlags(f); err != nil {
			return nil, err
		}
		a := &Ack{Kind: typ, PacketID: r.u16()}
		switch {
		case !v5:
		case typ == TypeUnsuback:
			a.Props = r.props(TypeUnsuback)
			a.ReasonCodes = append([]byte{}, r.b...)
			r.b = nil
			if r.err == nil && len(a.ReasonCodes) == 0 {
				return nil, protoErr("UNSUBACK without reason codes")
			}
		case len(r.b) > 0:
			a.ReasonCode = r.u8()
			if len(r.b) > 0 {
				a.Props = r.props(typ)
			}
		}
		p = a
	case TypeSubscribe:
		if err := wantFlags(0x02); err != nil {
			return nil, err
		}
		s := &Subscribe{PacketID: r.u16()}
		if v5 {
			s.Props = r.props(TypeSubscribe)
		}
		for r.err == nil && len(r.b) > 0 {
			f := r.str()
			o := r.u8()
			tf := TopicFilter{Filter: f, QoS: o & 3}
			bad := o > 2
			if v5 {
				tf.NoLocal = o&0x04 != 0
				tf.RetainAsPublished = o&0x08 != 0
				tf.RetainHandling = o >> 4 & 3
				bad = tf.QoS > 2 || tf.RetainHandling > 2 || o&0xc0 != 0
			}
			if r.err == nil && (bad || !ValidTopicFilter(f)) {
				return nil, protoErr("invalid subscription %q options %#x", f, o)
			}
			s.Topics = append(s.Topics, tf)
		}
		if r.err == nil && len(s.Topics) == 0 {
			return nil, protoErr("SUBSCRIBE without topic filters")
		}
		p = s
	case TypeSuback:
		if err := wantFlags(0); err != nil {
			return nil, err
		}
		s := &Suback{PacketID: r.u16()}
		if v5 {
			s.Props = r.props(TypeSuback)
		}
		s.ReturnCodes = append([]byte{}, r.b...)
		r.b = nil
		p = s
	case TypeUnsubscribe:
		if err := wantFlags(0x02); err != nil {
			return nil, err
		}
		u := &Unsubscribe{PacketID: r.u16()}
		if v5 {
			u.Props = r.props(TypeUnsubscribe)
		}
		for r.err == nil && len(r.b) > 0 {
			f := r.str()
			if v5 && r.err == nil && !ValidTopicFilter(f) {
				return nil, protoErr("invalid topic filter %q", f)
			}
			u.Filters = append(u.Filters, f)
		}
		if r.err == nil && len(u.Filters) == 0 {
			return nil, protoErr("UNSUBSCRIBE without topic filters")
		}
		p = u
	case TypePingreq, TypePingresp:
		if err := wantFlags(0); err != nil {
			return nil, err
		}
		p = &Simple{Kind: typ}
	case TypeDisconnect:
		if err := wantFlags(0); err != nil {
			return nil, err
		}
		d := &Disconnect{}
		if v5 && len(r.b) > 0 {
			d.ReasonCode = r.u8()
			if len(r.b) > 0 {
				d.Props = r.props(TypeDisconnect)
			}
		}
		p = d
	case TypeAuth:
		if !v5 {
			return nil, protoErr("unknown packet type %d", typ)
		}
		if err := wantFlags(0); err != nil {
			return nil, err
		}
		a := &Auth{}
		if len(r.b) > 0 {
			a.ReasonCode = r.u8()
			if len(r.b) > 0 {
				a.Props = r.props(TypeAuth)
			}
		}
		p = a
	default:
		return nil, protoErr("unknown packet type %d", typ)
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, protoErr("%d trailing bytes in packet type %d", len(r.b), typ)
	}
	return p, nil
}

// ValidTopicName reports whether s may be the topic of a PUBLISH: not empty,
// valid UTF-8 without NUL, no wildcards, at most 65535 bytes.
func ValidTopicName(s string) bool {
	return s != "" && len(s) <= 65535 && utf8.ValidString(s) &&
		!strings.ContainsAny(s, "+#\x00")
}

// ValidTopicFilter reports whether s is a valid topic filter: '+' fills a
// whole level, '#' is the whole last level.
func ValidTopicFilter(s string) bool {
	if s == "" || len(s) > 65535 || !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return false
	}
	levels := strings.Split(s, "/")
	for i, l := range levels {
		if strings.ContainsAny(l, "+#") && len(l) != 1 {
			return false
		}
		if l == "#" && i != len(levels)-1 {
			return false
		}
	}
	return true
}

// MatchTopic reports whether a topic name matches a topic filter. Wildcards
// in the first level do not match topics that start with '$' (§4.7.2).
func MatchTopic(filter, topic string) bool {
	if strings.HasPrefix(topic, "$") && (strings.HasPrefix(filter, "+") || strings.HasPrefix(filter, "#")) {
		return false
	}
	for {
		fl, frest, fmore := strings.Cut(filter, "/")
		if fl == "#" {
			return true
		}
		tl, trest, tmore := strings.Cut(topic, "/")
		if fl != "+" && fl != tl {
			return false
		}
		switch {
		case !fmore && !tmore:
			return true
		case !tmore:
			// "a/#" matches "a".
			return frest == "#"
		case !fmore:
			return false
		}
		filter, topic = frest, trest
	}
}
