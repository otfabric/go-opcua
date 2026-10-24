// SPDX-License-Identifier: MIT

package amqp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// Protocol headers (Part 2 §2.2, Part 5 §5.2 and §5.3).
var (
	HeaderAMQP = [8]byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0}
	HeaderTLS  = [8]byte{'A', 'M', 'Q', 'P', 2, 1, 0, 0}
	HeaderSASL = [8]byte{'A', 'M', 'Q', 'P', 3, 1, 0, 0}
)

// Frame types (§2.3.1, §5.3.1).
const (
	FrameAMQP byte = 0x00
	FrameSASL byte = 0x01
)

// MinMaxFrameSize is the smallest maximum frame size a peer may announce
// (MIN-MAX-FRAME-SIZE, §2.8.19).
const MinMaxFrameSize = 512

// ErrFrameTooLarge is returned by ReadFrame for a frame above the limit.
var ErrFrameTooLarge = errors.New("amqp: frame too large")

// Descriptor codes of the performatives (§2.7), SASL frames (§5.3.3),
// message sections (§3.2), delivery states (§3.4) and termini (§3.5).
const (
	descOpen        uint64 = 0x10
	descBegin       uint64 = 0x11
	descAttach      uint64 = 0x12
	descFlow        uint64 = 0x13
	descTransfer    uint64 = 0x14
	descDisposition uint64 = 0x15
	descDetach      uint64 = 0x16
	descEnd         uint64 = 0x17
	descClose       uint64 = 0x18
	descError       uint64 = 0x1d

	descReceived uint64 = 0x23
	descAccepted uint64 = 0x24
	descRejected uint64 = 0x25
	descReleased uint64 = 0x26
	descModified uint64 = 0x27
	descSource   uint64 = 0x28
	descTarget   uint64 = 0x29

	descSASLMechanisms uint64 = 0x40
	descSASLInit       uint64 = 0x41
	descSASLChallenge  uint64 = 0x42
	descSASLResponse   uint64 = 0x43
	descSASLOutcome    uint64 = 0x44

	descHeader                uint64 = 0x70
	descDeliveryAnnotations   uint64 = 0x71
	descMessageAnnotations    uint64 = 0x72
	descProperties            uint64 = 0x73
	descApplicationProperties uint64 = 0x74
	descData                  uint64 = 0x75
	descAMQPSequence          uint64 = 0x76
	descAMQPValue             uint64 = 0x77
	descFooter                uint64 = 0x78
)

// symbolic descriptors (§1.5) of the codes above, for peers that send the
// name instead of the code.
var symbolic = map[Symbol]uint64{
	"amqp:open:list": descOpen, "amqp:begin:list": descBegin, "amqp:attach:list": descAttach,
	"amqp:flow:list": descFlow, "amqp:transfer:list": descTransfer, "amqp:disposition:list": descDisposition,
	"amqp:detach:list": descDetach, "amqp:end:list": descEnd, "amqp:close:list": descClose,
	"amqp:error:list": descError, "amqp:received:list": descReceived, "amqp:accepted:list": descAccepted,
	"amqp:rejected:list": descRejected, "amqp:released:list": descReleased, "amqp:modified:list": descModified,
	"amqp:source:list": descSource, "amqp:target:list": descTarget,
	"amqp:sasl-mechanisms:list": descSASLMechanisms, "amqp:sasl-init:list": descSASLInit,
	"amqp:sasl-challenge:list": descSASLChallenge, "amqp:sasl-response:list": descSASLResponse,
	"amqp:sasl-outcome:list": descSASLOutcome,
	"amqp:header:list":       descHeader, "amqp:delivery-annotations:map": descDeliveryAnnotations,
	"amqp:message-annotations:map": descMessageAnnotations, "amqp:properties:list": descProperties,
	"amqp:application-properties:map": descApplicationProperties, "amqp:data:binary": descData,
	"amqp:amqp-sequence:list": descAMQPSequence, "amqp:amqp-value:*": descAMQPValue,
	"amqp:footer:map": descFooter,
}

// descriptorCode returns the numeric code of a descriptor.
func descriptorCode(d any) (uint64, bool) {
	switch d := d.(type) {
	case uint64:
		return d, true
	case Symbol:
		c, ok := symbolic[d]
		return c, ok
	}
	return 0, false
}

// Body is the body of a frame: a performative or a SASL frame.
type Body interface {
	descriptor() uint64
	fields() []any
}

// Frame is one frame (§2.3). A frame without Body is an empty frame, the
// heartbeat of §2.4.5.
type Frame struct {
	Type    byte
	Channel uint16
	Body    Body
	// Payload follows the performative: the message bytes of a transfer.
	Payload []byte
}

// AppendFrame appends the encoding of f to b.
func AppendFrame(b []byte, f *Frame) ([]byte, error) {
	start := len(b)
	b = append(b, 0, 0, 0, 0, 2, f.Type, byte(f.Channel>>8), byte(f.Channel))
	if f.Body != nil {
		var err error
		if b, err = appendComposite(b, f.Body.descriptor(), f.Body.fields()); err != nil {
			return b[:start], err
		}
		b = append(b, f.Payload...)
	}
	size := len(b) - start
	if uint64(size) > math.MaxUint32 {
		return b[:start], fmt.Errorf("amqp: frame of %d bytes", size)
	}
	binary.BigEndian.PutUint32(b[start:], uint32(size))
	return b, nil
}

// appendComposite encodes a composite type (§1.4): its descriptor and its
// fields as a list, without the trailing null fields.
func appendComposite(b []byte, code uint64, fields []any) ([]byte, error) {
	n := len(fields)
	for n > 0 && isNull(fields[n-1]) {
		n--
	}
	return appendDescribed(b, code, fields[:n])
}

// isNull reports whether a field value encodes as null.
func isNull(v any) bool {
	switch v := v.(type) {
	case nil:
		return true
	case *Error:
		return v == nil
	case *Source:
		return v == nil
	case *Target:
		return v == nil
	case *Described:
		return v == nil
	}
	return false
}

// FrameSize returns the length of a frame from its first four bytes.
func FrameSize(hdr []byte) uint32 { return binary.BigEndian.Uint32(hdr) }

// ReadFrame reads one frame. Frames above maxSize bytes (at least
// MinMaxFrameSize) are refused with ErrFrameTooLarge before their body is
// read: the connection cannot continue after that.
func ReadFrame(r io.Reader, maxSize uint32) (*Frame, error) {
	maxSize = max(maxSize, MinMaxFrameSize)
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	doff := uint32(hdr[4])
	if size > maxSize {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, size, maxSize)
	}
	if size < 8 || doff < 2 || doff*4 > size {
		return nil, protoErr("frame of %d bytes with data offset %d", size, doff)
	}
	rest := make([]byte, size-8)
	if _, err := io.ReadFull(r, rest); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	f := &Frame{Type: hdr[5], Channel: binary.BigEndian.Uint16(hdr[6:])}
	if err := DecodeFrameBody(f, rest[doff*4-8:]); err != nil {
		return nil, err
	}
	return f, nil
}

// DecodeFrameBody decodes the body of a frame (after its extended header)
// into f.
func DecodeFrameBody(f *Frame, body []byte) error {
	if len(body) == 0 {
		return nil // empty frame
	}
	v, rest, err := DecodeValue(body)
	if err != nil {
		return err
	}
	d, ok := v.(*Described)
	if !ok {
		return protoErr("frame body is a %T, not a performative", v)
	}
	code, ok := descriptorCode(d.Descriptor)
	if !ok {
		return protoErr("unknown frame body descriptor %v", d.Descriptor)
	}
	l, ok := d.Value.([]any)
	if !ok {
		return protoErr("frame body 0x%02x is a %T, not a list", code, d.Value)
	}
	fl := fieldList(l)
	switch f.Type {
	case FrameAMQP:
		f.Body, err = decodePerformative(code, fl)
	case FrameSASL:
		f.Body, err = decodeSASL(code, fl)
	default:
		return protoErr("unknown frame type 0x%02x", f.Type)
	}
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		if _, ok := f.Body.(*Transfer); !ok {
			return protoErr("%d bytes after a 0x%02x performative", len(rest), code)
		}
		f.Payload = rest
	}
	return nil
}

func decodePerformative(code uint64, f fieldList) (Body, error) {
	switch code {
	case descOpen:
		return decodeOpen(f)
	case descBegin:
		return decodeBegin(f)
	case descAttach:
		return decodeAttach(f)
	case descFlow:
		return decodeFlow(f)
	case descTransfer:
		return decodeTransfer(f)
	case descDisposition:
		return decodeDisposition(f)
	case descDetach:
		return decodeDetach(f)
	case descEnd:
		e, err := f.errorAt(0)
		return &End{Error: e}, err
	case descClose:
		e, err := f.errorAt(0)
		return &Close{Error: e}, err
	}
	return nil, protoErr("unknown performative 0x%02x", code)
}

// ---------------------------------------------------------------------------
// Field access

// fieldList holds the fields of a composite value. Absent and null fields
// take their default; a field of the wrong type is a protocol error.
type fieldList []any

func (f fieldList) at(i int) any {
	if i < len(f) {
		return f[i]
	}
	return nil
}

func (f fieldList) present(i int) bool { return f.at(i) != nil }

func fieldErr(i int, want string, v any) error {
	return protoErr("field %d: want %s, got %T", i, want, v)
}

func (f fieldList) uint32At(i int, def uint32) (uint32, error) {
	switch v := f.at(i).(type) {
	case nil:
		return def, nil
	case uint32:
		return v, nil
	case uint8:
		return uint32(v), nil
	case uint16:
		return uint32(v), nil
	case uint64:
		if v <= math.MaxUint32 {
			return uint32(v), nil
		}
	}
	return 0, fieldErr(i, "uint", f.at(i))
}

func (f fieldList) uint64At(i int, def uint64) (uint64, error) {
	switch v := f.at(i).(type) {
	case nil:
		return def, nil
	case uint64:
		return v, nil
	case uint32:
		return uint64(v), nil
	case uint16:
		return uint64(v), nil
	case uint8:
		return uint64(v), nil
	}
	return 0, fieldErr(i, "ulong", f.at(i))
}

func (f fieldList) uint16At(i int, def uint16) (uint16, error) {
	n, err := f.uint32At(i, uint32(def))
	if err == nil && n > math.MaxUint16 {
		err = fieldErr(i, "ushort", f.at(i))
	}
	return uint16(n), err
}

func (f fieldList) uint8At(i int, def uint8) (uint8, error) {
	n, err := f.uint32At(i, uint32(def))
	if err == nil && n > math.MaxUint8 {
		err = fieldErr(i, "ubyte", f.at(i))
	}
	return uint8(n), err
}

func (f fieldList) boolAt(i int, def bool) (bool, error) {
	switch v := f.at(i).(type) {
	case nil:
		return def, nil
	case bool:
		return v, nil
	}
	return false, fieldErr(i, "boolean", f.at(i))
}

func (f fieldList) stringAt(i int) (string, error) {
	switch v := f.at(i).(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	case Symbol:
		return string(v), nil
	}
	return "", fieldErr(i, "string", f.at(i))
}

func (f fieldList) symbolAt(i int) (Symbol, error) {
	s, err := f.stringAt(i)
	return Symbol(s), err
}

func (f fieldList) binaryAt(i int) ([]byte, error) {
	switch v := f.at(i).(type) {
	case nil:
		return nil, nil
	case []byte:
		return v, nil
	}
	return nil, fieldErr(i, "binary", f.at(i))
}

func (f fieldList) timeAt(i int) (time.Time, error) {
	switch v := f.at(i).(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		return v, nil
	}
	return time.Time{}, fieldErr(i, "timestamp", f.at(i))
}

// symbolsAt decodes a multiple="true" symbol field (§1.3.4): a single value
// or an array (some peers send a list).
func (f fieldList) symbolsAt(i int) ([]Symbol, error) {
	var vs []any
	switch v := f.at(i).(type) {
	case nil:
		return nil, nil
	case Symbol:
		return []Symbol{v}, nil
	case string:
		return []Symbol{Symbol(v)}, nil
	case Array:
		vs = v
	case []any:
		vs = v
	default:
		return nil, fieldErr(i, "symbol[]", v)
	}
	out := make([]Symbol, 0, len(vs))
	for _, e := range vs {
		switch e := e.(type) {
		case Symbol:
			out = append(out, e)
		case string:
			out = append(out, Symbol(e))
		default:
			return nil, fieldErr(i, "symbol[]", e)
		}
	}
	return out, nil
}

func (f fieldList) mapAt(i int) (Map, error) {
	switch v := f.at(i).(type) {
	case nil:
		return nil, nil
	case Map:
		return v, nil
	}
	return nil, fieldErr(i, "map", f.at(i))
}

// composite returns the fields of a described list value with descriptor
// code want (nil, nil for null).
func composite(v any, want ...uint64) (uint64, fieldList, error) {
	if v == nil {
		return 0, nil, nil
	}
	d, ok := v.(*Described)
	if !ok {
		return 0, nil, protoErr("want a described value, got %T", v)
	}
	code, ok := descriptorCode(d.Descriptor)
	if !ok {
		return 0, nil, protoErr("unknown descriptor %v", d.Descriptor)
	}
	match := false
	for _, w := range want {
		match = match || w == code
	}
	if !match {
		return 0, nil, protoErr("unexpected descriptor 0x%02x", code)
	}
	l, ok := d.Value.([]any)
	if !ok {
		return 0, nil, protoErr("descriptor 0x%02x on a %T, not a list", code, d.Value)
	}
	return code, fieldList(l), nil
}

func (f fieldList) errorAt(i int) (*Error, error) {
	_, l, err := composite(f.at(i), descError)
	if err != nil || l == nil {
		return nil, err
	}
	return decodeError(l)
}

// ---------------------------------------------------------------------------
// Error (§2.8.14)

// Error conditions used by this package (§2.8.15 to §2.8.18, §3.4).
const (
	CondInternalError       Symbol = "amqp:internal-error"
	CondNotFound            Symbol = "amqp:not-found"
	CondUnauthorizedAccess  Symbol = "amqp:unauthorized-access"
	CondDecodeError         Symbol = "amqp:decode-error"
	CondResourceLimit       Symbol = "amqp:resource-limit-exceeded"
	CondNotAllowed          Symbol = "amqp:not-allowed"
	CondInvalidField        Symbol = "amqp:invalid-field"
	CondNotImplemented      Symbol = "amqp:not-implemented"
	CondPreconditionFailed  Symbol = "amqp:precondition-failed"
	CondConnectionForced    Symbol = "amqp:connection:forced"
	CondFramingError        Symbol = "amqp:connection:framing-error"
	CondUnattachedHandle    Symbol = "amqp:session:unattached-handle"
	CondDetachForced        Symbol = "amqp:link:detach-forced"
	CondMessageSizeExceeded Symbol = "amqp:link:message-size-exceeded"
	CondTransferLimit       Symbol = "amqp:link:transfer-limit-exceeded"
)

// Error is the error of a close, end, detach or rejected outcome.
type Error struct {
	Condition   Symbol
	Description string
	Info        Map
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Condition, e.Description)
	}
	return string(e.Condition)
}

func (e *Error) descriptor() uint64 { return descError }
func (e *Error) fields() []any {
	var info any
	if e.Info != nil {
		info = e.Info
	}
	return []any{e.Condition, nilIfEmpty(e.Description), info}
}

func decodeError(f fieldList) (*Error, error) {
	if !f.present(0) {
		return nil, protoErr("error without condition")
	}
	e := &Error{}
	var err error
	if e.Condition, err = f.symbolAt(0); err != nil {
		return nil, err
	}
	if e.Description, err = f.stringAt(1); err != nil {
		return nil, err
	}
	if e.Info, err = f.mapAt(2); err != nil {
		return nil, err
	}
	return e, nil
}

// composite fields of a Body nested in another (error in close, ...)
func nested(b interface {
	descriptor() uint64
	fields() []any
}) any {
	if isNull(b) {
		return nil
	}
	l := b.fields()
	n := len(l)
	for n > 0 && isNull(l[n-1]) {
		n--
	}
	return &Described{Descriptor: b.descriptor(), Value: l[:n]}
}

func nilIfEmpty[T ~string | ~[]byte](v T) any {
	if len(v) == 0 {
		return nil
	}
	return v
}

func nilIfZero[T comparable](v T) any {
	var zero T
	if v == zero {
		return nil
	}
	return v
}

func symbolsField(s []Symbol) any {
	if len(s) == 0 {
		return nil
	}
	return s
}

func mapField(m Map) any {
	if len(m) == 0 {
		return nil
	}
	return m
}

func timeField(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
