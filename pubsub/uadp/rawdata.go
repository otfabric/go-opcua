// SPDX-License-Identifier: MIT

package uadp

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// The RawData field encoding (Part 14 §7.2.4.5.4 in 1.05) writes the field
// values without type information, typed by the FieldMetaData of the
// DataSetMetaData. The rules are those of open62541
// (ua_pubsub_networkmessage_binary.c, UA_DataSetMessage_keyFrame_raw_*,
// decodeRawField):
//
//   - a scalar is its value in the binary encoding of its DataType;
//   - an array is the length of every dimension (UInt32) followed by the
//     elements, without the Int32 array length of a Variant;
//   - a String or ByteString with a MaxStringLength is padded with zero
//     bytes after its value up to MaxStringLength bytes;
//   - a Structure (BuiltInType ExtensionObject) is the body of the
//     structure, without the ExtensionObject header.

// maxRawDimensions bounds the dimensions of a RawData array, as the ua
// decoder bounds those of a Variant.
const maxRawDimensions = 32

// rawField is the wire type of a RawData field.
type rawField struct {
	id      ua.TypeID
	dims    int      // 0 for a scalar
	maxDims []uint32 // upper bounds of the dimensions, 0 = unbounded; nil or len dims
	maxLen  uint32   // MaxStringLength of String and ByteString
	// structType is the Go type of a Structure field (an ExtensionObject
	// body), nil if unknown.
	structType reflect.Type
}

func rawFieldOf(md *ua.DataSetMetaDataType, i int) (*rawField, error) {
	if md == nil {
		return &rawField{}, nil // typed by the value (encode only)
	}
	if i < 0 || i >= len(md.Fields) || md.Fields[i] == nil {
		return nil, malformed("RawData field %d is not in the DataSetMetaData", i)
	}
	f := md.Fields[i]
	rf := &rawField{id: ua.TypeID(f.BuiltInType), maxLen: f.MaxStringLength}
	if rf.id == ua.TypeIDNull && f.DataType != nil && f.DataType.Namespace() == 0 && f.DataType.IntID() <= uint32(ua.TypeIDDiagnosticInfo) {
		rf.id = ua.TypeID(f.DataType.IntID())
	}
	if rf.id == ua.TypeIDNull || rf.id > ua.TypeIDDiagnosticInfo {
		return nil, unsupported("RawData field %q of built-in type %d", f.Name, f.BuiltInType)
	}
	switch {
	case len(f.ArrayDimensions) > 0:
		if f.ValueRank > 0 && int(f.ValueRank) != len(f.ArrayDimensions) {
			return nil, malformed("RawData field %q: ValueRank %d with %d ArrayDimensions", f.Name, f.ValueRank, len(f.ArrayDimensions))
		}
		rf.dims = len(f.ArrayDimensions)
		rf.maxDims = f.ArrayDimensions
	case f.ValueRank == -1:
	case f.ValueRank > 0:
		rf.dims = int(f.ValueRank)
	default:
		// Any, ScalarOrOneDimension, OneOrMoreDimensions: the reader
		// cannot know the shape.
		return nil, unsupported("RawData field %q with ValueRank %d", f.Name, f.ValueRank)
	}
	if rf.dims > maxRawDimensions {
		return nil, malformed("RawData field %q with %d dimensions", f.Name, rf.dims)
	}
	if rf.id == ua.TypeIDExtensionObject {
		rf.structType = structTypeOf(md, f.DataType)
	}
	return rf, nil
}

// writeRawField writes the RawData encoding of field i. md may be nil.
func writeRawField(b *ua.Buffer, md *ua.DataSetMetaDataType, i int, v *ua.Variant) error {
	rf, err := rawFieldOf(md, i)
	if err != nil {
		return err
	}
	if err := rf.write(b, v); err != nil {
		return wrapField(i, err)
	}
	return nil
}

func (rf *rawField) write(b *ua.Buffer, v *ua.Variant) error {
	if v == nil || v.Type() == ua.TypeIDNull {
		return malformed("RawData cannot encode a null value")
	}
	if rf.id == ua.TypeIDNull {
		// No metadata: the value says what it is.
		rf.id = v.Type()
		if v.IsArray() {
			rf.dims = max(len(v.ArrayDimensions()), 1)
		}
	}
	if rf.id == ua.TypeIDVariant && rf.dims == 0 {
		// A field of DataType BaseDataType is a Variant.
		b.WriteStruct(v)
		return nil
	}
	if v.Type() != rf.id {
		return malformed("RawData field of type %d with a value of type %d", rf.id, v.Type())
	}
	if rf.dims == 0 {
		if v.IsArray() {
			return malformed("RawData scalar field with an array value")
		}
		return rf.writeLeaf(b, v.Value())
	}
	if !v.IsArray() {
		return malformed("RawData array field with a scalar value")
	}
	dims := v.ArrayDimensions()
	if len(dims) == 0 {
		dims = []int32{v.ArrayLength()}
	}
	if len(dims) != rf.dims {
		return malformed("RawData field with %d dimensions, the value has %d", rf.dims, len(dims))
	}
	for i, d := range dims {
		if d < 0 {
			return malformed("RawData cannot encode a null array")
		}
		if rf.maxDims != nil && rf.maxDims[i] != 0 && uint32(d) > rf.maxDims[i] {
			return malformed("dimension %d of %d elements, at most %d", i, d, rf.maxDims[i])
		}
		b.WriteUint32(uint32(d))
	}
	leaves, err := flatten(reflect.ValueOf(v.Value()), len(dims), nil)
	if err != nil {
		return err
	}
	if len(leaves) != int(v.ArrayLength()) {
		return malformed("array of %d elements for dimensions %v", len(leaves), dims)
	}
	for _, x := range leaves {
		if err := rf.writeLeaf(b, x); err != nil {
			return err
		}
	}
	return nil
}

// flatten returns the elements of a (nested) slice of depth dimensions.
func flatten(v reflect.Value, depth int, out []any) ([]any, error) {
	if depth == 0 {
		return append(out, v.Interface()), nil
	}
	if v.Kind() != reflect.Slice {
		return nil, malformed("array value of %s", v.Type())
	}
	var err error
	for i := 0; i < v.Len(); i++ {
		if out, err = flatten(v.Index(i), depth-1, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// writeLeaf writes one value; its type matches rf.id (checked on the Variant).
func (rf *rawField) writeLeaf(b *ua.Buffer, x any) error {
	switch v := x.(type) {
	case bool:
		b.WriteBool(v)
	case int8:
		b.WriteInt8(v)
	case uint8:
		b.WriteUint8(v)
	case int16:
		b.WriteInt16(v)
	case uint16:
		b.WriteUint16(v)
	case int32:
		b.WriteInt32(v)
	case uint32:
		b.WriteUint32(v)
	case int64:
		b.WriteInt64(v)
	case uint64:
		b.WriteUint64(v)
	case float32:
		b.WriteFloat32(v)
	case float64:
		b.WriteFloat64(v)
	case ua.StatusCode:
		b.WriteUint32(uint32(v))
	case time.Time:
		b.WriteTime(v)
	case string:
		b.WriteString(v)
		return rf.pad(b, len(v))
	case ua.XMLElement:
		b.WriteString(string(v))
	case []byte:
		b.WriteByteString(v)
		return rf.pad(b, len(v))
	case *ua.ExtensionObject:
		if v == nil || v.Value == nil {
			return malformed("RawData structure without a value")
		}
		if body, ok := v.Value.([]byte); ok {
			b.Write(body) // an opaque body of an unknown type
		} else {
			b.WriteStruct(v.Value)
		}
	case *ua.GUID, *ua.NodeID, *ua.ExpandedNodeID, *ua.QualifiedName, *ua.LocalizedText,
		*ua.DataValue, *ua.Variant, *ua.DiagnosticInfo:
		b.WriteStruct(v)
	default:
		return malformed("RawData value of type %T", x)
	}
	return nil
}

// pad writes the zero padding of a String or ByteString up to
// MaxStringLength.
func (rf *rawField) pad(b *ua.Buffer, n int) error {
	if rf.maxLen == 0 {
		return nil
	}
	if n > int(rf.maxLen) {
		return malformed("RawData string of %d bytes, MaxStringLength is %d", n, rf.maxLen)
	}
	b.Write(make([]byte, int(rf.maxLen)-n))
	return nil
}

// readRawField reads field i of the DataSetMetaData.
func readRawField(b *ua.Buffer, md *ua.DataSetMetaDataType, i int) (*ua.Variant, error) {
	rf, err := rawFieldOf(md, i)
	if err != nil {
		return nil, err
	}
	v, err := rf.read(b)
	if err != nil {
		return nil, wrapField(i, err)
	}
	return v, nil
}

// read reads a RawData value. It rebuilds the binary encoding of the value
// as a Variant and decodes that, so that RawData fields decode to exactly the
// values the Variant encoding produces.
func (rf *rawField) read(b *ua.Buffer) (*ua.Variant, error) {
	if rf.id == ua.TypeIDVariant && rf.dims == 0 {
		v := new(ua.Variant)
		b.ReadStruct(v)
		if b.Error() != nil {
			return nil, malformed("%v", b.Error())
		}
		return v, nil
	}

	vb := ua.NewBuffer(make([]byte, 0, 16))
	count := 1
	var dims []int32
	if rf.dims == 0 {
		vb.WriteUint8(uint8(rf.id))
	} else {
		dims = make([]int32, rf.dims)
		total := uint64(1)
		for i := range dims {
			d := b.ReadUint32()
			if b.Error() != nil {
				return nil, malformed("truncated array dimensions")
			}
			if rf.maxDims != nil && rf.maxDims[i] != 0 && d > rf.maxDims[i] {
				return nil, malformed("dimension %d of %d elements, at most %d", i, d, rf.maxDims[i])
			}
			// Every element takes at least one byte.
			if total *= uint64(d); total > uint64(min(b.Len(), ua.MaxVariantArrayLength)) {
				return nil, malformed("array of more than %d elements", min(b.Len(), ua.MaxVariantArrayLength))
			}
			dims[i] = int32(d)
		}
		count = int(total)
		mask := uint8(rf.id) | ua.VariantArrayValues
		if rf.dims > 1 {
			mask |= ua.VariantArrayDimensions
		}
		vb.WriteUint8(mask)
		vb.WriteInt32(int32(count))
	}
	for range count {
		if err := rf.readLeaf(b, vb); err != nil {
			return nil, err
		}
	}
	if rf.dims > 1 {
		vb.WriteInt32(int32(len(dims)))
		for _, d := range dims {
			vb.WriteInt32(d)
		}
	}
	if vb.Error() != nil {
		return nil, malformed("%v", vb.Error())
	}
	v := new(ua.Variant)
	if _, err := v.Decode(vb.Bytes()); err != nil {
		return nil, malformed("%v", err)
	}
	return v, nil
}

// readLeaf reads one element and appends its Variant encoding to vb.
func (rf *rawField) readLeaf(b *ua.Buffer, vb *ua.Buffer) error {
	if rf.id == ua.TypeIDExtensionObject {
		if rf.structType == nil {
			return unsupported("RawData structure of unknown DataType")
		}
		v := reflect.New(rf.structType).Interface()
		n, err := ua.Decode(b.Bytes(), v)
		if err != nil || b.Error() != nil {
			return malformed("RawData structure: %v", err)
		}
		b.ReadN(n)
		vb.WriteStruct(ua.NewExtensionObject(v))
		return nil
	}

	rest := b.Bytes()
	start := b.Pos()
	var strLen int
	switch rf.id {
	case ua.TypeIDBoolean, ua.TypeIDSByte, ua.TypeIDByte:
		b.ReadN(1)
	case ua.TypeIDInt16, ua.TypeIDUint16:
		b.ReadN(2)
	case ua.TypeIDInt32, ua.TypeIDUint32, ua.TypeIDFloat, ua.TypeIDStatusCode:
		b.ReadN(4)
	case ua.TypeIDInt64, ua.TypeIDUint64, ua.TypeIDDouble, ua.TypeIDDateTime:
		b.ReadN(8)
	case ua.TypeIDGUID:
		b.ReadN(16)
	case ua.TypeIDString, ua.TypeIDByteString, ua.TypeIDXMLElement:
		if n := b.ReadUint32(); n != 0xffffffff {
			if n > uint32(b.Len()) {
				return malformed("string of %d bytes, %d left", n, b.Len())
			}
			b.ReadN(int(n))
			strLen = int(n)
		}
	case ua.TypeIDNodeID:
		b.ReadStruct(new(ua.NodeID))
	case ua.TypeIDExpandedNodeID:
		b.ReadStruct(new(ua.ExpandedNodeID))
	case ua.TypeIDQualifiedName:
		b.ReadStruct(new(ua.QualifiedName))
	case ua.TypeIDLocalizedText:
		b.ReadStruct(new(ua.LocalizedText))
	case ua.TypeIDDataValue:
		b.ReadStruct(new(ua.DataValue))
	case ua.TypeIDVariant:
		b.ReadStruct(new(ua.Variant))
	case ua.TypeIDDiagnosticInfo:
		b.ReadStruct(new(ua.DiagnosticInfo))
	default:
		return unsupported("RawData of built-in type %d", rf.id)
	}
	if b.Error() != nil {
		return malformed("RawData value: %v", b.Error())
	}
	vb.Write(rest[:b.Pos()-start])
	if rf.maxLen != 0 && (rf.id == ua.TypeIDString || rf.id == ua.TypeIDByteString) {
		if strLen > int(rf.maxLen) {
			return malformed("RawData string of %d bytes, MaxStringLength is %d", strLen, rf.maxLen)
		}
		if b.ReadN(int(rf.maxLen)-strLen); b.Error() != nil {
			return malformed("RawData string without its padding")
		}
	}
	return nil
}

// structTypes caches the Go type of Structure DataTypes by NodeId.
var structTypes sync.Map // string -> reflect.Type (nil if unknown)

// structTypeOf returns the Go type of the structure DataType dt: the type
// registered for the DataType NodeId, or for the DefaultEncodingId given in
// the StructureDataTypes of the DataSetMetaData.
func structTypeOf(md *ua.DataSetMetaDataType, dt *ua.NodeID) reflect.Type {
	if dt == nil {
		return nil
	}
	ids := []*ua.NodeID{dt}
	for _, sd := range md.StructureDataTypes {
		if sd != nil && sd.DataTypeID != nil && sd.DataTypeID.String() == dt.String() &&
			sd.StructureDefinition != nil && sd.StructureDefinition.DefaultEncodingID != nil {
			ids = append(ids, sd.StructureDefinition.DefaultEncodingID)
		}
	}
	for _, id := range ids {
		if t := lookupStructType(id); t != nil {
			return t
		}
	}
	return nil
}

// lookupStructType finds the Go type registered for a DataType or encoding
// NodeId. The ua package resolves both kinds of NodeId for the JSON
// ExtensionObject (UaTypeId); an empty JSON ExtensionObject of that type is
// the only exported way to ask it.
func lookupStructType(id *ua.NodeID) reflect.Type {
	key := id.String()
	if t, ok := structTypes.Load(key); ok {
		rt, _ := t.(reflect.Type)
		return rt
	}
	var t reflect.Type
	var eo ua.ExtensionObject
	if err := ua.DecodeJSON(fmt.Appendf(nil, `{"UaTypeId":%q}`, key), &eo); err == nil && eo.Value != nil {
		if rt := reflect.TypeOf(eo.Value); rt.Kind() == reflect.Pointer && rt.Elem().Kind() == reflect.Struct {
			t = rt.Elem()
		}
	}
	structTypes.Store(key, t)
	return t
}
