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

// Packet types of MQTT 3.1.1 (§2.2.1).
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
)

// CONNACK return codes (§3.2.2.3).
const (
	ConnAccepted                  byte = 0
	ConnRefusedProtocolVersion    byte = 1
	ConnRefusedIdentifierRejected byte = 2
	ConnRefusedServerUnavailable  byte = 3
	ConnRefusedBadCredentials     byte = 4
	ConnRefusedNotAuthorized      byte = 5
)

// SubackFailure is the SUBACK return code of a refused subscription.
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
}

// Connect is a CONNECT packet.
type Connect struct {
	// ProtocolName is "MQTT" (level 4, 3.1.1) or "MQIsdp" (level 3, 3.1).
	ProtocolName  string
	ProtocolLevel byte
	CleanSession  bool
	KeepAlive     uint16 // seconds
	ClientID      string
	Will          *Will
	Username      *string
	Password      []byte // nil: no password
}

// Connack is a CONNACK packet.
type Connack struct {
	SessionPresent bool
	ReturnCode     byte
}

// Publish is a PUBLISH packet.
type Publish struct {
	Dup      bool
	QoS      byte
	Retain   bool
	Topic    string
	PacketID uint16 // QoS 1 and 2 only
	Payload  []byte
}

// Ack is a PUBACK, PUBREC, PUBREL, PUBCOMP or UNSUBACK packet: a packet
// that is just a packet identifier.
type Ack struct {
	Kind     byte
	PacketID uint16
}

// TopicFilter is one topic filter of a SUBSCRIBE.
type TopicFilter struct {
	Filter string
	QoS    byte
}

// Subscribe is a SUBSCRIBE packet.
type Subscribe struct {
	PacketID uint16
	Topics   []TopicFilter
}

// Suback is a SUBACK packet.
type Suback struct {
	PacketID    uint16
	ReturnCodes []byte
}

// Unsubscribe is an UNSUBSCRIBE packet.
type Unsubscribe struct {
	PacketID uint16
	Filters  []string
}

// Simple is a PINGREQ, PINGRESP or DISCONNECT packet.
type Simple struct{ Kind byte }

func (*Connect) Type() byte     { return TypeConnect }
func (*Connack) Type() byte     { return TypeConnack }
func (*Publish) Type() byte     { return TypePublish }
func (a *Ack) Type() byte       { return a.Kind }
func (*Subscribe) Type() byte   { return TypeSubscribe }
func (*Suback) Type() byte      { return TypeSuback }
func (*Unsubscribe) Type() byte { return TypeUnsubscribe }
func (s *Simple) Type() byte    { return s.Kind }

// Encode returns the wire form of a packet.
func Encode(p Packet) ([]byte, error) {
	var body []byte
	var flags byte
	switch p := p.(type) {
	case *Connect:
		name, level := p.ProtocolName, p.ProtocolLevel
		if name == "" {
			name, level = "MQTT", 4
		}
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
			if p.Username == nil {
				return nil, protoErr("password without user name")
			}
			cf |= 0x40
		}
		if p.Username != nil {
			cf |= 0x80
		}
		body = append(body, cf)
		body = binary.BigEndian.AppendUint16(body, p.KeepAlive)
		body = appendString(body, p.ClientID)
		if p.Will != nil {
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
	case *Publish:
		if p.QoS > 2 {
			return nil, protoErr("QoS %d", p.QoS)
		}
		if !ValidTopicName(p.Topic) {
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
	case *Subscribe:
		if len(p.Topics) == 0 {
			return nil, protoErr("SUBSCRIBE without topic filters")
		}
		flags = 0x02
		body = binary.BigEndian.AppendUint16(body, p.PacketID)
		for _, s := range p.Topics {
			if !ValidTopicFilter(s.Filter) || s.QoS > 2 {
				return nil, protoErr("invalid subscription %q QoS %d", s.Filter, s.QoS)
			}
			body = appendString(body, s.Filter)
			body = append(body, s.QoS)
		}
	case *Suback:
		body = binary.BigEndian.AppendUint16(body, p.PacketID)
		body = append(body, p.ReturnCodes...)
	case *Unsubscribe:
		if len(p.Filters) == 0 {
			return nil, protoErr("UNSUBSCRIBE without topic filters")
		}
		flags = 0x02
		body = binary.BigEndian.AppendUint16(body, p.PacketID)
		for _, f := range p.Filters {
			body = appendString(body, f)
		}
	case *Simple:
		switch p.Kind {
		case TypePingreq, TypePingresp, TypeDisconnect:
		default:
			return nil, protoErr("packet type %d has a body", p.Kind)
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

// ReadPacket reads one packet. Packets with a remaining length above max
// (if max > 0) are skipped and reported with ErrTooLarge.
func ReadPacket(r *bufio.Reader, max int) (Packet, error) {
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
	return Decode(h, body)
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
	if r.err == nil && (!utf8.Valid(b) || strings.IndexByte(string(b), 0) >= 0) {
		r.err = protoErr("string is not valid UTF-8")
	}
	return string(b)
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = protoErr("packet too short")
	}
}

// Decode decodes a packet from its first byte and its body.
func Decode(header byte, body []byte) (Packet, error) {
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
		cf := r.u8()
		c.KeepAlive = r.u16()
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
			w.Topic = r.str()
			w.Payload = r.bytes()
			c.Will = w
		} else if cf&0x38 != 0 {
			return nil, protoErr("will flags without will")
		}
		if cf&0x80 != 0 {
			u := r.str()
			c.Username = &u
		}
		if cf&0x40 != 0 {
			if cf&0x80 == 0 {
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
		p = &Connack{SessionPresent: f&1 != 0, ReturnCode: r.u8()}
	case TypePublish:
		pub := &Publish{Dup: flags&0x08 != 0, QoS: flags >> 1 & 3, Retain: flags&0x01 != 0}
		if pub.QoS > 2 {
			return nil, protoErr("PUBLISH with QoS 3")
		}
		pub.Topic = r.str()
		if pub.QoS > 0 {
			pub.PacketID = r.u16()
			if r.err == nil && pub.PacketID == 0 {
				return nil, protoErr("PUBLISH with packet identifier 0")
			}
		}
		if r.err == nil && !ValidTopicName(pub.Topic) {
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
		p = &Ack{Kind: typ, PacketID: r.u16()}
	case TypeSubscribe:
		if err := wantFlags(0x02); err != nil {
			return nil, err
		}
		s := &Subscribe{PacketID: r.u16()}
		for r.err == nil && len(r.b) > 0 {
			f := r.str()
			q := r.u8()
			if r.err == nil && (q > 2 || !ValidTopicFilter(f)) {
				return nil, protoErr("invalid subscription %q QoS %d", f, q)
			}
			s.Topics = append(s.Topics, TopicFilter{Filter: f, QoS: q})
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
		s.ReturnCodes = append([]byte{}, r.b...)
		r.b = nil
		p = s
	case TypeUnsubscribe:
		if err := wantFlags(0x02); err != nil {
			return nil, err
		}
		u := &Unsubscribe{PacketID: r.u16()}
		for r.err == nil && len(r.b) > 0 {
			u.Filters = append(u.Filters, r.str())
		}
		if r.err == nil && len(u.Filters) == 0 {
			return nil, protoErr("UNSUBSCRIBE without topic filters")
		}
		p = u
	case TypePingreq, TypePingresp, TypeDisconnect:
		if err := wantFlags(0); err != nil {
			return nil, err
		}
		p = &Simple{Kind: typ}
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
