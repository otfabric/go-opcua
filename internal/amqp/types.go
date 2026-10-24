// SPDX-License-Identifier: MIT

package amqp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// The AMQP 1.0 type system (OASIS AMQP 1.0 Part 1, §1.2 and §1.6).
//
// Decoded values are Go values:
//
//	null               nil
//	boolean            bool
//	ubyte, ushort      uint8, uint16
//	uint, ulong        uint32, uint64
//	byte, short        int8, int16
//	int, long          int32, int64
//	float, double      float32, float64
//	decimal32/64/128   Decimal32, Decimal64, Decimal128 (opaque)
//	char               Char
//	timestamp          time.Time (UTC, millisecond precision)
//	uuid               UUID
//	binary             []byte
//	string             string
//	symbol             Symbol
//	list               []any
//	map                Map
//	array              Array
//	described          *Described
//
// The encoder takes the same types, plus int (encoded as long) and []Symbol
// (an array of symbols).

// Symbol is an AMQP symbol (§1.6.21): ASCII, used for names and constants.
type Symbol string

// UUID is an AMQP uuid (§1.6.18), RFC 4122 byte order.
type UUID [16]byte

// Char is an AMQP char (§1.6.16): one UTF-32 code point.
type Char rune

// Decimal32, Decimal64 and Decimal128 are IEEE 754 decimals (§1.6.13 to
// §1.6.15), kept as their raw octets.
type (
	Decimal32  [4]byte
	Decimal64  [8]byte
	Decimal128 [16]byte
)

// Described is a described type (§1.1.2): a descriptor (a ulong code or a
// symbol name) and the value it describes.
type Described struct {
	Descriptor any
	Value      any
}

// KV is one entry of a Map.
type KV struct {
	Key   any
	Value any
}

// Map is an AMQP map (§1.6.23) in wire order. Keys can be of any type,
// including types Go cannot use as map keys.
type Map []KV

// Get returns the value of the first entry whose key equals key (compared
// with ==, so only for comparable keys such as Symbol, string or uint64).
func (m Map) Get(key any) (any, bool) {
	for _, kv := range m {
		if comparableEqual(kv.Key, key) {
			return kv.Value, true
		}
	}
	return nil, false
}

func comparableEqual(a, b any) bool {
	switch a.(type) {
	case []byte, []any, Map, Array, *Described:
		return false
	}
	switch b.(type) {
	case []byte, []any, Map, Array, *Described:
		return false
	}
	return a == b
}

// Array is an AMQP array (§1.6.24): values of one type. The encoder takes
// the type of the first element; an empty Array is an array of nulls.
type Array []any

// Constructor codes (§1.6).
const (
	codeDescribed  = 0x00
	codeNull       = 0x40
	codeTrue       = 0x41
	codeFalse      = 0x42
	codeUint0      = 0x43
	codeUlong0     = 0x44
	codeList0      = 0x45
	codeUbyte      = 0x50
	codeByte       = 0x51
	codeSmallUint  = 0x52
	codeSmallUlong = 0x53
	codeSmallInt   = 0x54
	codeSmallLong  = 0x55
	codeBool       = 0x56
	codeUshort     = 0x60
	codeShort      = 0x61
	codeUint       = 0x70
	codeInt        = 0x71
	codeFloat      = 0x72
	codeChar       = 0x73
	codeDecimal32  = 0x74
	codeUlong      = 0x80
	codeLong       = 0x81
	codeDouble     = 0x82
	codeTimestamp  = 0x83
	codeDecimal64  = 0x84
	codeDecimal128 = 0x94
	codeUUID       = 0x98
	codeVbin8      = 0xa0
	codeStr8       = 0xa1
	codeSym8       = 0xa3
	codeVbin32     = 0xb0
	codeStr32      = 0xb1
	codeSym32      = 0xb3
	codeList8      = 0xc0
	codeMap8       = 0xc1
	codeList32     = 0xd0
	codeMap32      = 0xd1
	codeArray8     = 0xe0
	codeArray32    = 0xf0
)

// MaxDepth bounds the nesting of compound and described values the decoder
// accepts. Performatives and messages nest a few levels; deeper input is
// rejected rather than recursed into.
const MaxDepth = 32

// ErrProtocol is wrapped by all errors about malformed input.
var ErrProtocol = errors.New("amqp: protocol error")

func protoErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, args...)...)
}

// ---------------------------------------------------------------------------
// Encoding

// AppendValue appends the encoding of v to b. It picks the most compact
// encoding of each value (§1.2).
func AppendValue(b []byte, v any) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return append(b, codeNull), nil
	case bool:
		if v {
			return append(b, codeTrue), nil
		}
		return append(b, codeFalse), nil
	case uint8:
		return append(b, codeUbyte, v), nil
	case uint16:
		return binary.BigEndian.AppendUint16(append(b, codeUshort), v), nil
	case uint32:
		switch {
		case v == 0:
			return append(b, codeUint0), nil
		case v < 256:
			return append(b, codeSmallUint, byte(v)), nil
		}
		return binary.BigEndian.AppendUint32(append(b, codeUint), v), nil
	case uint64:
		switch {
		case v == 0:
			return append(b, codeUlong0), nil
		case v < 256:
			return append(b, codeSmallUlong, byte(v)), nil
		}
		return binary.BigEndian.AppendUint64(append(b, codeUlong), v), nil
	case int8:
		return append(b, codeByte, byte(v)), nil
	case int16:
		return binary.BigEndian.AppendUint16(append(b, codeShort), uint16(v)), nil
	case int32:
		if v >= -128 && v <= 127 {
			return append(b, codeSmallInt, byte(int8(v))), nil
		}
		return binary.BigEndian.AppendUint32(append(b, codeInt), uint32(v)), nil
	case int64:
		if v >= -128 && v <= 127 {
			return append(b, codeSmallLong, byte(int8(v))), nil
		}
		return binary.BigEndian.AppendUint64(append(b, codeLong), uint64(v)), nil
	case int:
		return AppendValue(b, int64(v))
	case float32:
		return binary.BigEndian.AppendUint32(append(b, codeFloat), math.Float32bits(v)), nil
	case float64:
		return binary.BigEndian.AppendUint64(append(b, codeDouble), math.Float64bits(v)), nil
	case Decimal32:
		return append(append(b, codeDecimal32), v[:]...), nil
	case Decimal64:
		return append(append(b, codeDecimal64), v[:]...), nil
	case Decimal128:
		return append(append(b, codeDecimal128), v[:]...), nil
	case Char:
		return binary.BigEndian.AppendUint32(append(b, codeChar), uint32(v)), nil
	case time.Time:
		return binary.BigEndian.AppendUint64(append(b, codeTimestamp), uint64(v.UnixMilli())), nil
	case UUID:
		return append(append(b, codeUUID), v[:]...), nil
	case []byte:
		return appendVariable(b, codeVbin8, codeVbin32, v), nil
	case string:
		return appendVariable(b, codeStr8, codeStr32, []byte(v)), nil
	case Symbol:
		return appendVariable(b, codeSym8, codeSym32, []byte(v)), nil
	case []any:
		return appendList(b, v)
	case Map:
		return appendMap(b, v)
	case Array:
		return appendArray(b, v)
	case []Symbol:
		a := make(Array, len(v))
		for i, s := range v {
			a[i] = s
		}
		return appendArray(b, a)
	case *Described:
		if v == nil {
			return append(b, codeNull), nil
		}
		return appendDescribed(b, v.Descriptor, v.Value)
	case Described:
		return appendDescribed(b, v.Descriptor, v.Value)
	}
	return b, fmt.Errorf("amqp: cannot encode a value of type %T", v)
}

func appendDescribed(b []byte, descriptor, value any) ([]byte, error) {
	b, err := AppendValue(append(b, codeDescribed), descriptor)
	if err != nil {
		return b, err
	}
	return AppendValue(b, value)
}

func appendVariable(b []byte, c8, c32 byte, v []byte) []byte {
	if len(v) < 256 {
		b = append(b, c8, byte(len(v)))
	} else {
		b = binary.BigEndian.AppendUint32(append(b, c32), uint32(len(v)))
	}
	return append(b, v...)
}

// appendCompound writes a list or map header for count elements whose
// encoding is body.
func appendCompound(b []byte, c8, c32 byte, count int, body []byte) []byte {
	if len(body)+1 <= 255 && count <= 255 {
		b = append(b, c8, byte(len(body)+1), byte(count))
	} else {
		b = binary.BigEndian.AppendUint32(append(b, c32), uint32(len(body)+4))
		b = binary.BigEndian.AppendUint32(b, uint32(count))
	}
	return append(b, body...)
}

func appendList(b []byte, l []any) ([]byte, error) {
	if len(l) == 0 {
		return append(b, codeList0), nil
	}
	var body []byte
	var err error
	for _, v := range l {
		if body, err = AppendValue(body, v); err != nil {
			return b, err
		}
	}
	return appendCompound(b, codeList8, codeList32, len(l), body), nil
}

func appendMap(b []byte, m Map) ([]byte, error) {
	var body []byte
	var err error
	for _, kv := range m {
		if body, err = AppendValue(body, kv.Key); err != nil {
			return b, err
		}
		if body, err = AppendValue(body, kv.Value); err != nil {
			return b, err
		}
	}
	return appendCompound(b, codeMap8, codeMap32, 2*len(m), body), nil
}

// arrayCode returns the constructor used for the elements of an array of
// v's type: always the fixed or 32-bit-length form, which every element can
// use. Arrays of compound or described values are not encoded (AMQP uses
// arrays for symbols and other primitives).
func arrayCode(v any) (byte, bool) {
	switch v.(type) {
	case nil:
		return codeNull, true
	case bool:
		return codeBool, true
	case uint8:
		return codeUbyte, true
	case uint16:
		return codeUshort, true
	case uint32:
		return codeUint, true
	case uint64:
		return codeUlong, true
	case int8:
		return codeByte, true
	case int16:
		return codeShort, true
	case int32:
		return codeInt, true
	case int64, int:
		return codeLong, true
	case float32:
		return codeFloat, true
	case float64:
		return codeDouble, true
	case Char:
		return codeChar, true
	case time.Time:
		return codeTimestamp, true
	case UUID:
		return codeUUID, true
	case []byte:
		return codeVbin32, true
	case string:
		return codeStr32, true
	case Symbol:
		return codeSym32, true
	}
	return 0, false
}

func appendArray(b []byte, a Array) ([]byte, error) {
	var first any
	if len(a) > 0 {
		first = a[0]
	}
	code, ok := arrayCode(first)
	if !ok {
		return b, fmt.Errorf("amqp: cannot encode an array of %T", first)
	}
	body := []byte{code}
	for _, v := range a {
		if c, ok := arrayCode(v); !ok || c != code {
			return b, fmt.Errorf("amqp: array mixes %T and %T", first, v)
		}
		body = appendWide(body, v)
	}
	if len(body)+1 <= 255 && len(a) <= 255 {
		b = append(b, codeArray8, byte(len(body)+1), byte(len(a)))
	} else {
		b = binary.BigEndian.AppendUint32(append(b, codeArray32), uint32(len(body)+4))
		b = binary.BigEndian.AppendUint32(b, uint32(len(a)))
	}
	return append(b, body...), nil
}

// appendWide appends the body of v, without constructor, in the encoding
// arrayCode chose for its type.
func appendWide(b []byte, v any) []byte {
	switch v := v.(type) {
	case nil:
		return b
	case bool:
		if v {
			return append(b, 1)
		}
		return append(b, 0)
	case uint32:
		return binary.BigEndian.AppendUint32(b, v)
	case uint64:
		return binary.BigEndian.AppendUint64(b, v)
	case int32:
		return binary.BigEndian.AppendUint32(b, uint32(v))
	case int64:
		return binary.BigEndian.AppendUint64(b, uint64(v))
	case int:
		return binary.BigEndian.AppendUint64(b, uint64(int64(v)))
	case []byte:
		return appendLen32(b, v)
	case string:
		return appendLen32(b, []byte(v))
	case Symbol:
		return appendLen32(b, []byte(v))
	}
	// The other fixed-width types have a single encoding: drop its
	// constructor.
	enc, _ := AppendValue(nil, v)
	return append(b, enc[1:]...)
}

func appendLen32(b, v []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(v))), v...)
}
