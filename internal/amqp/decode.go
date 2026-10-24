// SPDX-License-Identifier: MIT

package amqp

import (
	"encoding/binary"
	"math"
	"time"
)

// decoder reads AMQP values (Part 1 §1.2) from a buffer. Everything it
// decodes comes from the network: lengths and counts are checked against
// the bytes that are left before anything is allocated, so a value can
// never claim more memory than its input occupies, and nesting is bounded
// by MaxDepth.
type decoder struct {
	b     []byte
	depth int
}

// DecodeValue decodes one value from b and returns it with the bytes that
// follow it.
func DecodeValue(b []byte) (any, []byte, error) {
	d := &decoder{b: b}
	v, err := d.value()
	if err != nil {
		return nil, nil, err
	}
	return v, d.b, nil
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || n > len(d.b) {
		return nil, protoErr("value needs %d bytes, %d left", n, len(d.b))
	}
	v := d.b[:n:n]
	d.b = d.b[n:]
	return v, nil
}

func (d *decoder) u8() (byte, error) {
	b, err := d.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (d *decoder) u32() (uint32, error) {
	b, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (d *decoder) value() (any, error) {
	c, err := d.u8()
	if err != nil {
		return nil, err
	}
	if c == codeDescribed {
		return d.described()
	}
	return d.body(c)
}

func (d *decoder) enter() error {
	d.depth++
	if d.depth > MaxDepth {
		return protoErr("values nested deeper than %d", MaxDepth)
	}
	return nil
}

// described decodes a described value (§1.2, constructor 0x00) after its
// constructor.
func (d *decoder) described() (any, error) {
	if err := d.enter(); err != nil {
		return nil, err
	}
	defer func() { d.depth-- }()
	desc, err := d.value()
	if err != nil {
		return nil, err
	}
	switch desc.(type) {
	case uint64, Symbol:
	default:
		// §1.5: descriptors are symbols or ulongs; anything else is not
		// worth keeping around.
		return nil, protoErr("descriptor of type %T", desc)
	}
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	return &Described{Descriptor: desc, Value: v}, nil
}

// body decodes the value of constructor c (not described).
func (d *decoder) body(c byte) (any, error) {
	fixed := func(n int) ([]byte, error) { return d.take(n) }
	switch c {
	case codeNull:
		return nil, nil
	case codeTrue:
		return true, nil
	case codeFalse:
		return false, nil
	case codeBool:
		b, err := d.u8()
		if err != nil {
			return nil, err
		}
		if b > 1 {
			return nil, protoErr("boolean value %d", b)
		}
		return b == 1, nil
	case codeUint0:
		return uint32(0), nil
	case codeUlong0:
		return uint64(0), nil
	case codeList0:
		return []any{}, nil
	case codeUbyte:
		return d.u8()
	case codeByte:
		b, err := d.u8()
		return int8(b), err
	case codeSmallUint:
		b, err := d.u8()
		return uint32(b), err
	case codeSmallUlong:
		b, err := d.u8()
		return uint64(b), err
	case codeSmallInt:
		b, err := d.u8()
		return int32(int8(b)), err
	case codeSmallLong:
		b, err := d.u8()
		return int64(int8(b)), err
	case codeUshort, codeShort:
		b, err := fixed(2)
		if err != nil {
			return nil, err
		}
		if c == codeShort {
			return int16(binary.BigEndian.Uint16(b)), nil
		}
		return binary.BigEndian.Uint16(b), nil
	case codeUint, codeInt, codeFloat, codeChar, codeDecimal32:
		b, err := fixed(4)
		if err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(b)
		switch c {
		case codeInt:
			return int32(n), nil
		case codeFloat:
			return math.Float32frombits(n), nil
		case codeChar:
			return Char(n), nil
		case codeDecimal32:
			return Decimal32(b), nil
		}
		return n, nil
	case codeUlong, codeLong, codeDouble, codeTimestamp, codeDecimal64:
		b, err := fixed(8)
		if err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint64(b)
		switch c {
		case codeLong:
			return int64(n), nil
		case codeDouble:
			return math.Float64frombits(n), nil
		case codeTimestamp:
			return time.UnixMilli(int64(n)).UTC(), nil
		case codeDecimal64:
			return Decimal64(b), nil
		}
		return n, nil
	case codeDecimal128, codeUUID:
		b, err := fixed(16)
		if err != nil {
			return nil, err
		}
		if c == codeUUID {
			return UUID(b), nil
		}
		return Decimal128(b), nil
	case codeVbin8, codeStr8, codeSym8, codeVbin32, codeStr32, codeSym32:
		var n uint32
		var err error
		if c&0xf0 == 0xa0 {
			var b byte
			b, err = d.u8()
			n = uint32(b)
		} else {
			n, err = d.u32()
		}
		if err != nil {
			return nil, err
		}
		if uint64(n) > uint64(len(d.b)) {
			return nil, protoErr("variable-width value of %d bytes, %d left", n, len(d.b))
		}
		b, _ := d.take(int(n))
		switch c {
		case codeVbin8, codeVbin32:
			out := make([]byte, len(b))
			copy(out, b)
			return out, nil
		case codeStr8, codeStr32:
			return string(b), nil
		}
		return Symbol(b), nil
	case codeList8, codeList32, codeMap8, codeMap32:
		return d.compound(c)
	case codeArray8, codeArray32:
		return d.array(c)
	}
	return nil, protoErr("unknown constructor 0x%02x", c)
}

// sized reads the size and count of a compound or array (§1.2.3, §1.2.4)
// and returns a decoder for exactly its size. The count is checked against
// the size: every element takes at least one byte, except the elements of
// an array of a zero-width type, whose count is bounded by the size all
// the same, so no input can make the decoder allocate more than a few
// times its own length.
func (d *decoder) sized(wide bool) (*decoder, uint32, error) {
	var size, count uint32
	var err error
	if wide {
		if size, err = d.u32(); err != nil {
			return nil, 0, err
		}
		if uint64(size) > uint64(len(d.b)) || size < 4 {
			return nil, 0, protoErr("compound of %d bytes, %d left", size, len(d.b))
		}
		count = binary.BigEndian.Uint32(d.b)
	} else {
		var s byte
		if s, err = d.u8(); err != nil {
			return nil, 0, err
		}
		size = uint32(s)
		if int(size) > len(d.b) || size < 1 {
			return nil, 0, protoErr("compound of %d bytes, %d left", size, len(d.b))
		}
		count = uint32(d.b[0])
	}
	body, _ := d.take(int(size))
	if wide {
		body = body[4:]
	} else {
		body = body[1:]
	}
	if count > size {
		return nil, 0, protoErr("%d elements in %d bytes", count, size)
	}
	return &decoder{b: body, depth: d.depth}, count, nil
}

func (d *decoder) compound(c byte) (any, error) {
	if err := d.enter(); err != nil {
		return nil, err
	}
	defer func() { d.depth-- }()
	sub, count, err := d.sized(c == codeList32 || c == codeMap32)
	if err != nil {
		return nil, err
	}
	isMap := c == codeMap8 || c == codeMap32
	if isMap && count%2 != 0 {
		return nil, protoErr("map with an odd number (%d) of elements", count)
	}
	vals := make([]any, 0, count)
	for i := uint32(0); i < count; i++ {
		v, err := sub.value()
		if err != nil {
			return nil, err
		}
		vals = append(vals, v)
	}
	if len(sub.b) != 0 {
		return nil, protoErr("%d bytes after the last element of a compound", len(sub.b))
	}
	if !isMap {
		return vals, nil
	}
	m := make(Map, 0, count/2)
	for i := 0; i < len(vals); i += 2 {
		m = append(m, KV{Key: vals[i], Value: vals[i+1]})
	}
	return m, nil
}

func (d *decoder) array(c byte) (any, error) {
	if err := d.enter(); err != nil {
		return nil, err
	}
	defer func() { d.depth-- }()
	sub, count, err := d.sized(c == codeArray32)
	if err != nil {
		return nil, err
	}
	elem, err := sub.u8()
	if err != nil {
		return nil, err
	}
	var desc any
	if elem == codeDescribed {
		if err := sub.enter(); err != nil {
			return nil, err
		}
		if desc, err = sub.value(); err != nil {
			return nil, err
		}
		if elem, err = sub.u8(); err != nil {
			return nil, err
		}
		if elem == codeDescribed {
			return nil, protoErr("array of nested described values")
		}
	}
	vals := make(Array, 0, count)
	for i := uint32(0); i < count; i++ {
		v, err := sub.body(elem)
		if err != nil {
			return nil, err
		}
		if desc != nil {
			v = &Described{Descriptor: desc, Value: v}
		}
		vals = append(vals, v)
	}
	if len(sub.b) != 0 {
		return nil, protoErr("%d bytes after the last element of an array", len(sub.b))
	}
	return vals, nil
}
