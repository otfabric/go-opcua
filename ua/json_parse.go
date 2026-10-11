// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// A small strict RFC 8259 parser that produces a tree.
//
// encoding/json is not used for the documents themselves because the decoder
// needs things it does not offer: a hard nesting limit that is enforced
// before anything is allocated for the nested value, rejection of duplicate
// member names (Part 6 §5.4.2.16), the member order, and numbers as text so
// that 64-bit integers and floats keep their exact value.

type jsonKind uint8

const (
	jsonNull jsonKind = iota
	jsonBool
	jsonNumber
	jsonString
	jsonArray
	jsonObject
)

func (k jsonKind) String() string {
	return [...]string{"null", "boolean", "number", "string", "array", "object"}[k]
}

type jsonNode struct {
	kind jsonKind
	b    bool
	s    string // string value or number literal
	arr  []jsonNode
	keys []string // object member names, parallel to arr
}

// get returns the member with the given name.
func (n *jsonNode) get(key string) *jsonNode {
	if n == nil || n.kind != jsonObject {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return &n.arr[i]
		}
	}
	return nil
}

func (n *jsonNode) isNull() bool { return n == nil || n.kind == jsonNull }

type jsonParser struct {
	data     []byte
	pos      int
	depth    int
	maxDepth int
}

func parseJSON(data []byte, maxDepth int) (*jsonNode, error) {
	p := &jsonParser{data: data, maxDepth: maxDepth}
	var n jsonNode
	if err := p.value(&n); err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(p.data) {
		return nil, p.errorf("unexpected data after the value")
	}
	return &n, nil
}

func (p *jsonParser) errorf(format string, args ...interface{}) error {
	return fmt.Errorf("ua: json: offset %d: %s: %w", p.pos, fmt.Sprintf(format, args...), StatusBadDecodingError)
}

func (p *jsonParser) space() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) literal(lit string) bool {
	if len(p.data)-p.pos >= len(lit) && string(p.data[p.pos:p.pos+len(lit)]) == lit {
		p.pos += len(lit)
		return true
	}
	return false
}

func (p *jsonParser) value(n *jsonNode) error {
	p.space()
	if p.pos >= len(p.data) {
		return p.errorf("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(n)
	case c == '[':
		return p.array(n)
	case c == '"':
		s, err := p.string()
		n.kind, n.s = jsonString, s
		return err
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number(n)
	case p.literal("true"):
		n.kind, n.b = jsonBool, true
	case p.literal("false"):
		n.kind = jsonBool
	case p.literal("null"):
		n.kind = jsonNull
	default:
		return p.errorf("unexpected character %q", c)
	}
	return nil
}

func (p *jsonParser) enter() error {
	p.depth++
	if p.depth > p.maxDepth {
		return fmt.Errorf("ua: json: offset %d: nesting exceeds %d levels: %w", p.pos, p.maxDepth, StatusBadEncodingLimitsExceeded)
	}
	return nil
}

func (p *jsonParser) object(n *jsonNode) error {
	if err := p.enter(); err != nil {
		return err
	}
	defer func() { p.depth-- }()
	n.kind = jsonObject
	p.pos++ // {
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return nil
	}
	var seen map[string]struct{}
	for {
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return p.errorf("expected a member name")
		}
		key, err := p.string()
		if err != nil {
			return err
		}
		if seen == nil {
			for _, k := range n.keys {
				if k == key {
					return p.errorf("duplicate member %q", key)
				}
			}
			if len(n.keys) >= 16 { // keep large objects linear
				seen = make(map[string]struct{}, 2*len(n.keys))
				for _, k := range n.keys {
					seen[k] = struct{}{}
				}
			}
		} else if _, dup := seen[key]; dup {
			return p.errorf("duplicate member %q", key)
		}
		if seen != nil {
			seen[key] = struct{}{}
		}
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return p.errorf("expected ':'")
		}
		p.pos++
		n.keys = append(n.keys, key)
		n.arr = append(n.arr, jsonNode{})
		if err := p.value(&n.arr[len(n.arr)-1]); err != nil {
			return err
		}
		p.space()
		if p.pos >= len(p.data) {
			return p.errorf("unexpected end of input")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return nil
		default:
			return p.errorf("expected ',' or '}'")
		}
	}
}

func (p *jsonParser) array(n *jsonNode) error {
	if err := p.enter(); err != nil {
		return err
	}
	defer func() { p.depth-- }()
	n.kind = jsonArray
	n.arr = []jsonNode{}
	p.pos++ // [
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return nil
	}
	for {
		n.arr = append(n.arr, jsonNode{})
		if err := p.value(&n.arr[len(n.arr)-1]); err != nil {
			return err
		}
		p.space()
		if p.pos >= len(p.data) {
			return p.errorf("unexpected end of input")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return nil
		default:
			return p.errorf("expected ',' or ']'")
		}
	}
}

func (p *jsonParser) string() (string, error) {
	start := p.pos
	p.pos++ // opening quote
	simple := true
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		switch {
		case c == '"':
			raw := p.data[start : p.pos+1]
			p.pos++
			if simple && utf8.Valid(raw) {
				return string(raw[1 : len(raw)-1]), nil
			}
			// Escapes, surrogate pairs and invalid UTF-8 are left to the
			// standard library.
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				p.pos = start
				return "", p.errorf("invalid string")
			}
			return s, nil
		case c == '\\':
			simple = false
			p.pos += 2
		case c < 0x20:
			return "", p.errorf("control character in string")
		default:
			p.pos++
		}
	}
	return "", p.errorf("unterminated string")
}

func (p *jsonParser) number(n *jsonNode) error {
	start := p.pos
	digits := func() int {
		i := p.pos
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
		return p.pos - i
	}
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos < len(p.data) && p.data[p.pos] == '0' {
		p.pos++
	} else if digits() == 0 {
		return p.errorf("invalid number")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if digits() == 0 {
			return p.errorf("invalid number")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if digits() == 0 {
			return p.errorf("invalid number")
		}
	}
	n.kind, n.s = jsonNumber, string(p.data[start:p.pos])
	return nil
}
