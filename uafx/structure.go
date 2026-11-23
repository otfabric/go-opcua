// SPDX-License-Identifier: MIT

package uafx

import (
	"fmt"
	"math"
	"reflect"

	"github.com/otfabric/go-opcua/ua"
)

// The structures of the UAFX namespaces (types_gen.go) are generated from
// the NodeSets of OPC 10000-81 by cmd/uafx, with their binary encoding
// (codec_gen.go, Part 6 §5.2.6 to §5.2.8): the fields in the order of the
// definition, those of a supertype first; an optional field after the
// EncodingMask that tells which are present; a union as its SwitchField and
// the selected field. A field whose DataType is abstract, or that allows
// subtypes, is an ExtensionObject (Part 6 §5.2.2.15) whose encoding NodeId
// has the namespace index the server has for the namespace of the
// structure. Package ua cannot register them for that reason: the
// functions here take the indexes.

// Structure is a structure of a UAFX namespace: a value of one of the
// generated structure types of this package (a pointer to it).
type Structure interface {
	encodingID() encodingID
	encode(w *wbuf)
	decode(r *rbuf)
}

// NamespaceIndexes are the indexes a server has for the UAFX namespaces
// (its NamespaceArray, Part 5 §6.3.1); 0 for a namespace it does not have.
type NamespaceIndexes struct {
	Data uint16 // http://opcfoundation.org/UA/FX/Data/
	AC   uint16 // http://opcfoundation.org/UA/FX/AC/
	CM   uint16 // http://opcfoundation.org/UA/FX/CM/
}

// nsKind is a UAFX namespace.
type nsKind uint8

const (
	nsData nsKind = iota + 1
	nsAC
	nsCM
)

var nsNames = map[nsKind]string{nsData: "Data", nsAC: "AC", nsCM: "CM"}

// encodingID is the Default Binary encoding of a structure.
type encodingID struct {
	ns nsKind
	id uint32
}

// codec encodes and decodes the structures with the namespace indexes of a
// server.
type codec struct{ ns NamespaceIndexes }

func (c codec) index(k nsKind) uint16 {
	switch k {
	case nsData:
		return c.ns.Data
	case nsAC:
		return c.ns.AC
	case nsCM:
		return c.ns.CM
	}
	return 0
}

// kind returns the UAFX namespace of the index idx, 0 for none.
func (c codec) kind(idx uint16) nsKind {
	if idx == 0 {
		return 0
	}
	for _, k := range []nsKind{nsData, nsAC, nsCM} {
		if c.index(k) == idx {
			return k
		}
	}
	return 0
}

// EncodeStructure returns v in an ExtensionObject in the binary encoding,
// for a server with the namespace indexes ns.
func EncodeStructure(v Structure, ns NamespaceIndexes) (*ua.ExtensionObject, error) {
	return codec{ns}.encode(v)
}

// DecodeStructure decodes the ExtensionObject eo, a structure of a UAFX
// namespace in the binary encoding, for a server with the namespace
// indexes ns. It returns nil for a null ExtensionObject. The body must
// hold exactly the structure.
func DecodeStructure(eo *ua.ExtensionObject, ns NamespaceIndexes) (Structure, error) {
	if isNull(eo) {
		return nil, nil
	}
	return codec{ns}.decodeEO(eo, nil)
}

func (c codec) encode(v Structure) (*ua.ExtensionObject, error) {
	if isNil(v) {
		return nil, fmt.Errorf("%w: a nil structure", ErrCodec)
	}
	id := v.encodingID()
	idx := c.index(id.ns)
	if idx == 0 {
		return nil, fmt.Errorf("%w: %T: the namespace index of UAFX %s is not known", ErrCodec, v, nsNames[id.ns])
	}
	w := &wbuf{Buffer: ua.NewBuffer(nil), c: c}
	v.encode(w)
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("%w: %T: %w", ErrCodec, v, err)
	}
	return &ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID:       ua.NewNumericExpandedNodeID(idx, id.id),
		Value:        w.Bytes(),
	}, nil
}

// decodeEO decodes eo, which is not null. When accept is not nil, a
// structure accept rejects is an error before its body is decoded: a field
// takes only the structures of its DataType, so the nesting of the
// structures the generator checked bounds the depth of the decoding.
func (c codec) decodeEO(eo *ua.ExtensionObject, accept func(Structure) bool) (Structure, error) {
	id, b, err := c.body(eo)
	if err != nil {
		return nil, err
	}
	mk := structures[id]
	if mk == nil {
		return nil, fmt.Errorf("%w: the encoding ns=%d;i=%d is not a structure of UAFX %s", ErrCodec, c.index(id.ns), id.id, nsNames[id.ns])
	}
	v := mk()
	if accept != nil && !accept(v) {
		return nil, fmt.Errorf("%w: a %T is not allowed here", ErrCodec, v)
	}
	r := &rbuf{Buffer: ua.NewBuffer(b), c: c}
	v.decode(r)
	if err := r.Error(); err != nil {
		return nil, fmt.Errorf("%w: %T: %w", ErrCodec, v, err)
	}
	if n := r.Len(); n != 0 {
		return nil, fmt.Errorf("%w: %T: %d bytes after the structure", ErrCodec, v, n)
	}
	return v, nil
}

// body returns the encoding and the binary body of eo, a structure of a
// UAFX namespace.
func (c codec) body(eo *ua.ExtensionObject) (encodingID, []byte, error) {
	if eo == nil || eo.TypeID == nil || eo.TypeID.NodeID == nil {
		return encodingID{}, nil, fmt.Errorf("%w: an ExtensionObject without a type", ErrCodec)
	}
	id := eo.TypeID.NodeID
	k := c.kind(id.Namespace())
	if eo.TypeID.NamespaceURI != "" || k == 0 || id.Type() != ua.NodeIDTypeNumeric && id.Type() != ua.NodeIDTypeFourByte && id.Type() != ua.NodeIDTypeTwoByte {
		return encodingID{}, nil, fmt.Errorf("%w: the encoding %v is not in a UAFX namespace", ErrCodec, eo.TypeID)
	}
	if eo.EncodingMask != ua.ExtensionObjectBinary {
		return encodingID{}, nil, fmt.Errorf("%w: %v is not in the binary encoding", ErrCodec, id)
	}
	switch b := eo.Value.(type) {
	case nil:
		return encodingID{k, id.IntID()}, eo.RawBody, nil
	case []byte:
		return encodingID{k, id.IntID()}, b, nil
	}
	return encodingID{}, nil, fmt.Errorf("%w: %v decoded as a %T", ErrCodec, id, eo.Value)
}

// decodeAs decodes eo, which must be a T, a pointer to a structure type.
func decodeAs[T Structure](c codec, eo *ua.ExtensionObject) (T, error) {
	var zero T
	if isNull(eo) {
		return zero, fmt.Errorf("%w: a null %T", ErrCodec, zero)
	}
	s, err := c.decodeEO(eo, func(s Structure) bool { _, ok := s.(T); return ok })
	if err != nil {
		return zero, err
	}
	return s.(T), nil
}

// nullEO is the null ExtensionObject of an abstract field that is not set.
func nullEO() *ua.ExtensionObject {
	return &ua.ExtensionObject{TypeID: ua.NewTwoByteExpandedNodeID(0), EncodingMask: ua.ExtensionObjectEmpty}
}

// isNull reports whether eo is a null ExtensionObject.
func isNull(eo *ua.ExtensionObject) bool {
	return eo == nil || eo.EncodingMask == ua.ExtensionObjectEmpty && (eo.TypeID == nil || eo.TypeID.NodeID == nil || eo.TypeID.NodeID.Equal(ua.NewTwoByteNodeID(0)))
}

// isNil reports whether v is nil or a nil pointer.
func isNil(v Structure) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// wbuf is the buffer the generated encoders write to.
type wbuf struct {
	*ua.Buffer
	c   codec
	err error
}

func (w *wbuf) fail(format string, args ...any) {
	if w.err == nil {
		w.err = fmt.Errorf(format, args...)
	}
}

// Error returns the first error of the encoding.
func (w *wbuf) Error() error {
	if w.err != nil {
		return w.err
	}
	return w.Buffer.Error()
}

// length writes the length of an array, -1 for a null one, and reports
// whether the elements follow.
func (w *wbuf) length(n int, null bool) bool {
	switch {
	case null:
		w.WriteInt32(-1)
		return false
	case n > math.MaxInt32:
		w.fail("an array of %d elements", n)
		return false
	}
	w.WriteInt32(int32(n))
	return true
}

// extensionObject writes v in an ExtensionObject, the null one for nil.
func (w *wbuf) extensionObject(v Structure) {
	if isNil(v) {
		w.WriteStruct(nullEO())
		return
	}
	eo, err := w.c.encode(v)
	if err != nil {
		w.fail("%w", err)
		return
	}
	w.WriteStruct(eo)
}

// rbuf is the buffer the generated decoders read from.
type rbuf struct {
	*ua.Buffer
	c   codec
	err error
}

func (r *rbuf) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, args...)
	}
}

// Error returns the first error of the decoding.
func (r *rbuf) Error() error {
	if r.err != nil {
		return r.err
	}
	return r.Buffer.Error()
}

// length reads the length of an array and reports whether it is not null.
// The length is the sender's claim: every element takes at least one byte,
// so a length beyond the bytes that are left is an error, not an
// allocation.
func (r *rbuf) length() (int, bool) {
	n := r.ReadInt32()
	switch {
	case r.Error() != nil || n == -1:
		return 0, false
	case n < -1:
		r.fail("an array of length %d", n)
		return 0, false
	case int(n) > r.Len():
		r.fail("an array of %d elements in %d bytes", n, r.Len())
		return 0, false
	}
	return int(n), true
}

// extensionObject reads an ExtensionObject that holds a structure of a
// UAFX namespace that accept takes, nil for the null ExtensionObject.
func (r *rbuf) extensionObject(accept func(Structure) bool) Structure {
	if r.Error() != nil {
		return nil
	}
	eo := new(ua.ExtensionObject)
	r.ReadStruct(eo)
	if r.Error() != nil || isNull(eo) {
		return nil
	}
	s, err := r.c.decodeEO(eo, accept)
	if err != nil {
		r.fail("%w", err)
		return nil
	}
	return s
}
