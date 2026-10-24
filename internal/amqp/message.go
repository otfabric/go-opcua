// SPDX-License-Identifier: MIT

package amqp

import (
	"time"
)

// Header is the header section of a message (Part 3 §3.2.1).
type Header struct {
	Durable  bool
	Priority uint8 // the default is 4
	// TTL in milliseconds; 0: none.
	TTL           uint32
	FirstAcquirer bool
	DeliveryCount uint32
}

// Properties is the properties section of a message (§3.2.4).
type Properties struct {
	// MessageID and CorrelationID are a ulong, UUID, []byte or string
	// (§3.2.11 to §3.2.14).
	MessageID          any
	UserID             []byte
	To                 string
	Subject            string
	ReplyTo            string
	CorrelationID      any
	ContentType        Symbol
	ContentEncoding    Symbol
	AbsoluteExpiryTime time.Time
	CreationTime       time.Time
	GroupID            string
	GroupSequence      *uint32
	ReplyToGroupID     string
}

// Message is an AMQP message (§3.2): a bare message with its annotations.
// Delivery annotations and the footer are dropped when decoding.
type Message struct {
	Header *Header
	// MessageAnnotations keeps the entries with symbol keys.
	MessageAnnotations    map[Symbol]any
	Properties            *Properties
	ApplicationProperties map[string]any
	// The body is one of: data sections, amqp-sequence sections or one
	// amqp-value section (§3.2.6 to §3.2.8).
	Data     [][]byte
	Sequence [][]any
	Value    any
	// HasValue tells an amqp-value section holding null from none.
	HasValue bool
}

// Payload returns the body as bytes: the data sections concatenated, or,
// leniently, an amqp-value holding binary or a string, or amqp-sequence
// sections of binary values. It returns nil for other bodies.
func (m *Message) Payload() []byte {
	switch {
	case len(m.Data) == 1:
		return m.Data[0]
	case len(m.Data) > 1:
		var out []byte
		for _, d := range m.Data {
			out = append(out, d...)
		}
		return out
	case m.HasValue:
		switch v := m.Value.(type) {
		case []byte:
			return v
		case string:
			return []byte(v)
		}
	case len(m.Sequence) > 0:
		var out []byte
		for _, s := range m.Sequence {
			for _, e := range s {
				b, ok := e.([]byte)
				if !ok {
					return nil
				}
				out = append(out, b...)
			}
		}
		return out
	}
	return nil
}

func (h *Header) descriptor() uint64 { return descHeader }
func (h *Header) fields() []any {
	var prio any
	if h.Priority != 4 {
		prio = h.Priority
	}
	return []any{nilIfZero(h.Durable), prio, nilIfZero(h.TTL), nilIfZero(h.FirstAcquirer), nilIfZero(h.DeliveryCount)}
}

func (p *Properties) descriptor() uint64 { return descProperties }
func (p *Properties) fields() []any {
	var gs any
	if p.GroupSequence != nil {
		gs = *p.GroupSequence
	}
	return []any{p.MessageID, nilIfEmpty(p.UserID), nilIfEmpty(p.To), nilIfEmpty(p.Subject), nilIfEmpty(p.ReplyTo),
		p.CorrelationID, nilIfEmpty(p.ContentType), nilIfEmpty(p.ContentEncoding), timeField(p.AbsoluteExpiryTime),
		timeField(p.CreationTime), nilIfEmpty(p.GroupID), gs, nilIfEmpty(p.ReplyToGroupID)}
}

// MarshalBinary encodes the message, sections in the order of §3.2.
func (m *Message) MarshalBinary() ([]byte, error) {
	var b []byte
	var err error
	if m.Header != nil {
		if b, err = appendComposite(b, descHeader, m.Header.fields()); err != nil {
			return nil, err
		}
	}
	if len(m.MessageAnnotations) > 0 {
		ann := make(Map, 0, len(m.MessageAnnotations))
		for _, k := range sortedKeys(m.MessageAnnotations) {
			ann = append(ann, KV{Key: Symbol(k), Value: m.MessageAnnotations[Symbol(k)]})
		}
		if b, err = appendDescribed(b, descMessageAnnotations, ann); err != nil {
			return nil, err
		}
	}
	if m.Properties != nil {
		if b, err = appendComposite(b, descProperties, m.Properties.fields()); err != nil {
			return nil, err
		}
	}
	if len(m.ApplicationProperties) > 0 {
		ap := make(Map, 0, len(m.ApplicationProperties))
		for _, k := range sortedKeys(m.ApplicationProperties) {
			ap = append(ap, KV{Key: k, Value: m.ApplicationProperties[k]})
		}
		if b, err = appendDescribed(b, descApplicationProperties, ap); err != nil {
			return nil, err
		}
	}
	for _, d := range m.Data {
		if b, err = appendDescribed(b, descData, orEmpty(d)); err != nil {
			return nil, err
		}
	}
	for _, s := range m.Sequence {
		if b, err = appendDescribed(b, descAMQPSequence, s); err != nil {
			return nil, err
		}
	}
	if m.HasValue || m.Value != nil {
		if b, err = appendDescribed(b, descAMQPValue, m.Value); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func sortedKeys[K ~string, V any](m map[K]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	// Insertion sort: the maps are small, and this keeps sort out of the
	// import list of a hot path.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// UnmarshalBinary decodes a message. Unknown sections are an error, a
// message without a body is not.
func (m *Message) UnmarshalBinary(b []byte) error {
	*m = Message{}
	body := uint64(0)
	for len(b) > 0 {
		v, rest, err := DecodeValue(b)
		if err != nil {
			return err
		}
		b = rest
		d, ok := v.(*Described)
		if !ok {
			return protoErr("message section is a %T", v)
		}
		code, ok := descriptorCode(d.Descriptor)
		if !ok || code < descHeader || code > descFooter {
			return protoErr("unknown message section %v", d.Descriptor)
		}
		// The order of §3.2 is not enforced (a later section wins), but a
		// body is one kind of section.
		if code >= descData && code <= descAMQPValue {
			if body != 0 && (body != code || code == descAMQPValue) {
				return protoErr("message with more than one kind of body or amqp-value")
			}
			body = code
		}
		if err := m.section(code, d.Value); err != nil {
			return err
		}
	}
	return nil
}

func (m *Message) section(code uint64, v any) error {
	switch code {
	case descHeader:
		l, ok := v.([]any)
		if !ok {
			return protoErr("header section is a %T", v)
		}
		f := fieldList(l)
		h := &Header{}
		var err error
		if h.Durable, err = f.boolAt(0, false); err != nil {
			return err
		}
		if h.Priority, err = f.uint8At(1, 4); err != nil {
			return err
		}
		if h.TTL, err = f.uint32At(2, 0); err != nil {
			return err
		}
		if h.FirstAcquirer, err = f.boolAt(3, false); err != nil {
			return err
		}
		if h.DeliveryCount, err = f.uint32At(4, 0); err != nil {
			return err
		}
		m.Header = h
	case descDeliveryAnnotations, descFooter:
		if _, ok := v.(Map); !ok && v != nil {
			return protoErr("annotations section is a %T", v)
		}
	case descMessageAnnotations:
		mp, ok := v.(Map)
		if !ok && v != nil {
			return protoErr("message-annotations section is a %T", v)
		}
		for _, kv := range mp {
			if k, ok := kv.Key.(Symbol); ok {
				if m.MessageAnnotations == nil {
					m.MessageAnnotations = map[Symbol]any{}
				}
				m.MessageAnnotations[k] = kv.Value
			}
		}
	case descProperties:
		l, ok := v.([]any)
		if !ok {
			return protoErr("properties section is a %T", v)
		}
		p, err := decodeProperties(fieldList(l))
		if err != nil {
			return err
		}
		m.Properties = p
	case descApplicationProperties:
		mp, ok := v.(Map)
		if !ok && v != nil {
			return protoErr("application-properties section is a %T", v)
		}
		for _, kv := range mp {
			k, ok := kv.Key.(string)
			if !ok {
				return protoErr("application-properties key of type %T", kv.Key) // §3.2.5
			}
			if m.ApplicationProperties == nil {
				m.ApplicationProperties = map[string]any{}
			}
			m.ApplicationProperties[k] = kv.Value
		}
	case descData:
		b, ok := v.([]byte)
		if !ok {
			return protoErr("data section is a %T", v)
		}
		m.Data = append(m.Data, b)
	case descAMQPSequence:
		l, ok := v.([]any)
		if !ok {
			return protoErr("amqp-sequence section is a %T", v)
		}
		m.Sequence = append(m.Sequence, l)
	case descAMQPValue:
		m.Value, m.HasValue = v, true
	}
	return nil
}

func messageID(f fieldList, i int) (any, error) {
	switch v := f.at(i).(type) {
	case nil, uint64, UUID, []byte, string:
		return v, nil
	case Symbol:
		return string(v), nil // lenient
	}
	return nil, fieldErr(i, "message-id", f.at(i))
}

func decodeProperties(f fieldList) (*Properties, error) {
	p := &Properties{}
	var err error
	if p.MessageID, err = messageID(f, 0); err != nil {
		return nil, err
	}
	if p.UserID, err = f.binaryAt(1); err != nil {
		return nil, err
	}
	if p.To, err = f.stringAt(2); err != nil {
		return nil, err
	}
	if p.Subject, err = f.stringAt(3); err != nil {
		return nil, err
	}
	if p.ReplyTo, err = f.stringAt(4); err != nil {
		return nil, err
	}
	if p.CorrelationID, err = messageID(f, 5); err != nil {
		return nil, err
	}
	if p.ContentType, err = f.symbolAt(6); err != nil {
		return nil, err
	}
	if p.ContentEncoding, err = f.symbolAt(7); err != nil {
		return nil, err
	}
	if p.AbsoluteExpiryTime, err = f.timeAt(8); err != nil {
		return nil, err
	}
	if p.CreationTime, err = f.timeAt(9); err != nil {
		return nil, err
	}
	if p.GroupID, err = f.stringAt(10); err != nil {
		return nil, err
	}
	if f.present(11) {
		gs, err := f.uint32At(11, 0)
		if err != nil {
			return nil, err
		}
		p.GroupSequence = &gs
	}
	if p.ReplyToGroupID, err = f.stringAt(12); err != nil {
		return nil, err
	}
	return p, nil
}
