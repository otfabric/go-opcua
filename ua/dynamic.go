// SPDX-License-Identifier: MIT

package ua

import (
	"fmt"
	"math"
	"reflect"
	"sync"

	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/id"
)

// This file decodes and encodes, in the OPC UA Binary DataEncoding, the
// values of Structures and Unions a program has no Go type for, from the
// DataTypeDefinition Attribute of their DataType (OPC 10000-3 §5.8.3): the
// StructureDefinition of a Structure or Union and the EnumDefinition of an
// Enumeration or OptionSet. "Structures are sequences of name value pairs
// defined by the DataTypeDefinition Attribute ... Each DataEncoding
// describes how to use the DataTypeDefinition to serialize Structures"
// (OPC 10000-6 §5.1.7).

// DynamicTypes is a set of DataTypes described by their DataTypeDefinition,
// with which [DynamicTypes.DecodeExtensionObject] decodes the body of an
// ExtensionObject whose type has no Go type registered with
// [RegisterExtensionObject]. Its NodeIds are those of one server's
// namespace table: a set belongs to one session. It is safe for
// concurrent use.
//
// The opcua client builds such a set from the server, by namespace URI, with
// the DynamicTypeDecoding option or LoadDataTypes; see Client.DynamicTypes.
type DynamicTypes struct {
	mu        sync.RWMutex
	types     map[string]*DynamicType // by DataType NodeId
	encodings map[string]*DynamicType // by DefaultEncodingId
}

// NewDynamicTypes returns an empty set.
func NewDynamicTypes() *DynamicTypes {
	return &DynamicTypes{types: map[string]*DynamicType{}, encodings: map[string]*DynamicType{}}
}

// DynamicType is a DataType of a [DynamicTypes] set. It must not be
// modified once it is added.
type DynamicType struct {
	// DataTypeID is the NodeId of the DataType.
	DataTypeID *NodeID
	// Name is the Name of the BrowseName of the DataType; it is
	// informational.
	Name string
	// Definition is the value of the DataTypeDefinition Attribute: a
	// *StructureDefinition for a Structure or Union, an *EnumDefinition for
	// an Enumeration or an OptionSet, nil for a DataType without one.
	Definition any
	// BuiltIn is how a value of a DataType that is no Structure is
	// encoded: TypeIDInt32 for an Enumeration ("Enumerations are encoded
	// as Int32 values", OPC 10000-6 §5.2.4); the UInteger of an OptionSet
	// of one; the built-in supertype of a simple DataType, which is
	// "handled on the wire like the Built-in DataType" (OPC 10000-3
	// §5.8.2); TypeIDVariant for an abstract DataType that is no
	// Structure, such as a subtype of Number ("the field value is encoded
	// as a Variant", OPC 10000-6 §5.1.6); and TypeIDExtensionObject for a
	// subtype of OptionSet, which is encoded as the OptionSet Structure
	// (OPC 10000-3 §5.8.2), and for an abstract Structure. It is ignored
	// for a DataType with a StructureDefinition.
	BuiltIn TypeID
	// IsAbstract is the IsAbstract Attribute of the DataType.
	IsAbstract bool
}

// structure returns the StructureDefinition of t, nil if it has none.
func (t *DynamicType) structure() *StructureDefinition {
	sd, _ := t.Definition.(*StructureDefinition)
	return sd
}

// valueRankScalar is the ValueRank of a scalar field (OPC 10000-3 §8.51).
const valueRankScalar = -1

// The largest number of optional fields of a Structure: "A maximum of 32
// optional fields can appear within a single Structure" (OPC 10000-6
// §5.2.7).
const maxOptionalFields = 32

// Add adds the DataType t to the set, or replaces the DataType with its
// NodeId. A StructureDefinition must be usable: a StructureType of OPC
// 10000-3 §8.49, fields with a DataType and a ValueRank that is Scalar or
// a fixed rank ("It shall be Scalar (-1) or a fixed rank Array (>=1)",
// §8.51), and at most 32 optional fields.
func (s *DynamicTypes) Add(t *DynamicType) error {
	if t == nil || t.DataTypeID == nil {
		return fmt.Errorf("ua: dynamic type without a DataType NodeId: %w", StatusBadInvalidArgument)
	}
	switch d := t.Definition.(type) {
	case nil, *EnumDefinition:
	case *StructureDefinition:
		if err := checkStructureDefinition(d); err != nil {
			return fmt.Errorf("ua: DataType %s: %w", t.DataTypeID, err)
		}
	default:
		return fmt.Errorf("ua: DataType %s: definition %T: %w", t.DataTypeID, t.Definition, StatusBadInvalidArgument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := t.DataTypeID.String()
	if old := s.types[key]; old != nil {
		if sd := old.structure(); sd != nil && sd.DefaultEncodingID != nil {
			delete(s.encodings, sd.DefaultEncodingID.String())
		}
	}
	s.types[key] = t
	if sd := t.structure(); sd != nil && !nullNodeID(sd.DefaultEncodingID) {
		s.encodings[sd.DefaultEncodingID.String()] = t
	}
	return nil
}

func nullNodeID(n *NodeID) bool {
	return n == nil || (n.Namespace() == 0 && n.Type() == NodeIDTypeTwoByte && n.IntID() == 0)
}

func checkStructureDefinition(d *StructureDefinition) error {
	if d.StructureType > StructureTypeUnionWithSubtypedValues {
		return fmt.Errorf("StructureType %d: %w", d.StructureType, StatusBadInvalidArgument)
	}
	optional := 0
	for i, f := range d.Fields {
		if f == nil || f.DataType == nil {
			return fmt.Errorf("field %d without a DataType: %w", i, StatusBadInvalidArgument)
		}
		if f.ValueRank != valueRankScalar && f.ValueRank < 1 {
			return fmt.Errorf("field %q: ValueRank %d: %w", f.Name, f.ValueRank, StatusBadInvalidArgument)
		}
		if f.IsOptional && d.StructureType == StructureTypeStructureWithOptionalFields {
			optional++
		}
	}
	if optional > maxOptionalFields {
		return fmt.Errorf("%d optional fields: %w", optional, StatusBadInvalidArgument)
	}
	return nil
}

// Type returns the DataType with the NodeId dataTypeID, nil if the set has
// none.
func (s *DynamicTypes) Type(dataTypeID *NodeID) *DynamicType {
	if dataTypeID == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.types[dataTypeID.String()]
}

// TypeByEncoding returns the Structure whose DefaultEncodingId is
// encodingID, nil if the set has none.
func (s *DynamicTypes) TypeByEncoding(encodingID *NodeID) *DynamicType {
	if encodingID == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.encodings[encodingID.String()]
}

// New returns a value of the Structure or Union dataTypeID with every
// field absent (nil), to fill with [DynamicStructure.Set] and send in an
// ExtensionObject ([NewExtensionObject]).
func (s *DynamicTypes) New(dataTypeID *NodeID) (*DynamicStructure, error) {
	t := s.Type(dataTypeID)
	if t == nil || t.structure() == nil {
		return nil, fmt.Errorf("ua: no StructureDefinition for DataType %v: %w", dataTypeID, StatusBadDataTypeIDUnknown)
	}
	return &DynamicStructure{Type: t, Fields: make([]any, len(t.structure().Fields)), types: s}, nil
}

// DecodeExtensionObject decodes the binary body of eo, which the binary
// decoder kept in RawBody because no Go type is registered for its TypeId
// (the JSON and XML decoders keep a binary body as a []byte Value), with
// the Structure of the set whose DefaultEncodingId is the TypeId, and sets
// Value to the [*DynamicStructure]. It does nothing for an ExtensionObject
// that has a Value. An ExtensionObject of a type the set does not have, or
// whose body does not match the definition, is left as it is and the
// error says why: StatusBadDataTypeIDUnknown or StatusBadDecodingError.
func (s *DynamicTypes) DecodeExtensionObject(eo *ExtensionObject) error {
	body, ok := UndecodedBody(eo)
	if !ok {
		return nil
	}
	t := s.TypeByEncoding(eo.TypeID.NodeID)
	if t == nil {
		return fmt.Errorf("ua: no DataType for encoding %s: %w", eo.TypeID.NodeID, StatusBadDataTypeIDUnknown)
	}
	v, n, err := s.decodeStructure(t, body, 1)
	if err != nil {
		var sc StatusCode
		if !errors.As(err, &sc) {
			// A short body, or a length beyond the input.
			err = fmt.Errorf("%w: %w", err, StatusBadDecodingError)
		}
		return err
	}
	if n != len(body) {
		// The definition does not describe the body.
		return fmt.Errorf("ua: %d of the %d bytes of the body of %s decoded: %w", n, len(body), eo.TypeID.NodeID, StatusBadDecodingError)
	}
	eo.Value = v
	eo.RawBody = nil
	return nil
}

// UndecodedBody returns the binary body of an ExtensionObject that no Go
// type decoded: the RawBody the binary decoder keeps, or the []byte Value
// the JSON and XML decoders keep. It returns false for an ExtensionObject
// that has a decoded Value, no TypeId or no binary body.
func UndecodedBody(eo *ExtensionObject) ([]byte, bool) {
	if eo == nil || eo.EncodingMask != ExtensionObjectBinary || eo.TypeID == nil || eo.TypeID.NodeID == nil {
		return nil, false
	}
	switch v := eo.Value.(type) {
	case nil:
		return eo.RawBody, true
	case []byte:
		return v, true
	}
	return nil, false
}

// DynamicStructure is the value of a Structure or Union decoded with its
// DataTypeDefinition ([DynamicTypes]). It encodes itself in the OPC UA
// Binary DataEncoding, so it can be written and passed as a Method
// argument in an ExtensionObject.
//
// Fields holds a value per field of the StructureDefinition, in its order.
// The value of a field is
//
//   - of a built-in DataType: the Go type a [Variant] holds for it (int32,
//     string, *LocalizedText, time.Time, ...);
//   - of an Enumeration: int32; of an OptionSet of a UInteger or of a
//     simple DataType: the Go type of its built-in type;
//   - of a Structure or Union: a pointer to its Go type when one is
//     registered for its DefaultEncodingId, a *DynamicStructure otherwise,
//     and *OptionSet for a subtype of OptionSet;
//   - of DataType Structure or Decimal, or of a field that allows subtypes
//     of a Structure: *ExtensionObject ("A field is serialized as an
//     ExtensionObject if a field has a DataType set explicitly to
//     Structure", OPC 10000-6 §5.1.7, §5.1.10);
//   - of BaseDataType, Number, Integer, UInteger and other abstract
//     DataTypes that are no Structure, and of a field that allows subtypes
//     of one: *Variant (§5.1.6, §F.12);
//   - an array (ValueRank 1): a slice of these; a matrix (ValueRank 2 or
//     more): a *DynamicMatrix.
//
// An ExtensionObject of a field that no Go type and no DataType of the set
// decodes keeps its binary body as a []byte Value, so that the Structure
// encodes back unchanged.
//
// An optional field that is absent is nil; so is every field of a Union
// but the one Switch selects. A mandatory field that is nil is encoded
// with the default value of its DataType, an array as a null array: "the
// encoder shall create a new instance with DefaultValues for all fields
// and serialize that" (§5.2.6).
type DynamicStructure struct {
	// Type is the DataType, with its StructureDefinition.
	Type *DynamicType
	// Fields are the field values in the order of the definition.
	Fields []any
	// Switch selects the field of a Union, 1 for the first; 0 is a Union
	// without a field ("If the switch field is 0 then no field is
	// present", OPC 10000-6 §5.2.8). It is 0 for a Structure.
	Switch uint32

	types *DynamicTypes
}

// DynamicMatrix is the value of a field that is an array of two or more
// dimensions, which OPC 10000-6 §5.2.5 encodes as an inline matrix.
type DynamicMatrix struct {
	// Dimensions is the length of each dimension.
	Dimensions []int32
	// Values is a slice of the element type with the values in the order
	// of the encoding, "Higher rank dimensions are serialized first"
	// (OPC 10000-6 §5.2.2.16).
	Values any
}

// Field returns the value of the field name and whether the Structure has
// a field of that name.
func (d *DynamicStructure) Field(name string) (any, bool) {
	i := d.fieldIndex(name)
	if i < 0 {
		return nil, false
	}
	return d.Fields[i], true
}

func (d *DynamicStructure) fieldIndex(name string) int {
	if d == nil || d.Type == nil || d.Type.structure() == nil {
		return -1
	}
	for i, f := range d.Type.structure().Fields {
		if f.Name == name {
			return i
		}
	}
	return -1
}

// Set sets the field name to v. For a Union it selects the field (and
// clears the others). It does not check v; Encode does.
func (d *DynamicStructure) Set(name string, v any) error {
	i := d.fieldIndex(name)
	if i < 0 {
		return fmt.Errorf("ua: no field %q: %w", name, StatusBadInvalidArgument)
	}
	if len(d.Fields) != len(d.Type.structure().Fields) {
		d.Fields = make([]any, len(d.Type.structure().Fields))
	}
	if isUnion(d.Type.structure()) {
		clear(d.Fields)
		d.Switch = uint32(i + 1) // i < len(Fields), a slice length
	}
	d.Fields[i] = v
	return nil
}

func isUnion(sd *StructureDefinition) bool {
	return sd.StructureType == StructureTypeUnion || sd.StructureType == StructureTypeUnionWithSubtypedValues
}

// subtyped tells whether IsOptional of a field of sd means "allows
// subtypes" (OPC 10000-3 §8.51).
func subtyped(sd *StructureDefinition) bool {
	return sd.StructureType == StructureTypeStructureWithSubtypedValues || sd.StructureType == StructureTypeUnionWithSubtypedValues
}

// encodingID returns the DefaultEncodingId of the Structure of d, the
// TypeId of its ExtensionObject.
func (d *DynamicStructure) encodingID() *ExpandedNodeID {
	if d == nil || d.Type == nil || d.Type.structure() == nil || nullNodeID(d.Type.structure().DefaultEncodingID) {
		return NewTwoByteExpandedNodeID(0)
	}
	return &ExpandedNodeID{NodeID: d.Type.structure().DefaultEncodingID}
}

// Encode encodes d in the OPC UA Binary DataEncoding.
func (d *DynamicStructure) Encode() ([]byte, error) { return d.encodeDepth(0) }

func (d *DynamicStructure) encodeDepth(depth int) ([]byte, error) {
	if d == nil || d.Type == nil || d.Type.structure() == nil {
		return nil, fmt.Errorf("ua: dynamic structure without a StructureDefinition: %w", StatusBadEncodingError)
	}
	types := d.types
	if types == nil {
		types = NewDynamicTypes()
	}
	return types.encodeStructure(d.Type, d, depth)
}

// --- the codec of a field ------------------------------------------------

type dynCodecKind uint8

const (
	codecBuiltIn   dynCodecKind = iota + 1 // a built-in type, builtIn
	codecDynamic                           // a Structure of the set, dyn
	codecGo                                // a registered Go type, goType (a pointer type)
	codecOptionSet                         // the OptionSet Structure
)

type fieldCodec struct {
	kind    dynCodecKind
	builtIn TypeID
	dyn     *DynamicType
	goType  reflect.Type
}

var optionSetType = reflect.TypeOf(new(OptionSet))

// codecOf returns how a value of the DataType dataType is encoded in a
// field; allowSubTypes is set for a field whose IsOptional means "allows
// subtypes": "all subtypes of Structure are encoded as an ExtensionObject
// (see 5.1.6) and all DataTypes that are not subtypes of Structure are
// encoded as a Variant" (OPC 10000-6 §F.13, AllowSubTypes).
func (s *DynamicTypes) codecOf(dataType *NodeID, allowSubTypes bool) (fieldCodec, error) {
	if dataType.Namespace() == 0 && dataType.Type() != NodeIDTypeString && dataType.Type() != NodeIDTypeGUID && dataType.Type() != NodeIDTypeByteString {
		switch n := dataType.IntID(); {
		case n >= uint32(TypeIDBoolean) && n <= uint32(TypeIDDiagnosticInfo):
			// The NodeIds of the built-in DataTypes are their TypeIds
			// (OPC 10000-6 Table 1); Structure (22) is an
			// ExtensionObject and BaseDataType (24) a Variant.
			b := TypeID(n)
			if allowSubTypes && b != TypeIDExtensionObject {
				b = TypeIDVariant
			}
			return fieldCodec{kind: codecBuiltIn, builtIn: b}, nil
		case n == id.Number || n == id.Integer || n == id.UInteger:
			return fieldCodec{kind: codecBuiltIn, builtIn: TypeIDVariant}, nil
		case n == id.Decimal:
			// "Decimals are encoded as described in 5.1.10" (OPC
			// 10000-6 §5.2.3): TypeId, Encoding and Length as an
			// ExtensionObject.
			return fieldCodec{kind: codecBuiltIn, builtIn: TypeIDExtensionObject}, nil
		}
	}
	if c, ok := ns0GoCodec(dataType); ok {
		// A registered Go type comes first, whatever the server says of
		// its DataType.
		if allowSubTypes {
			return fieldCodec{kind: codecBuiltIn, builtIn: TypeIDExtensionObject}, nil
		}
		return c, nil
	}
	t := s.Type(dataType)
	if t == nil {
		return fieldCodec{}, fmt.Errorf("ua: DataType %s of a field is not known: %w", dataType, StatusBadDataTypeIDUnknown)
	}
	sd := t.structure()
	_, isEnum := t.Definition.(*EnumDefinition)
	structure := sd != nil || (t.BuiltIn == TypeIDExtensionObject && !isEnum)
	// AllowSubTypes "shall be TRUE for all abstract DataTypes except for
	// BaseDataType, Structure, Number, Integer or UInteger ... If TRUE,
	// all subtypes of Structure are encoded as an ExtensionObject" (OPC
	// 10000-6 Table F.14): a field of an abstract Structure carries the
	// subtype in an ExtensionObject.
	if allowSubTypes || (structure && t.IsAbstract) {
		if structure {
			return fieldCodec{kind: codecBuiltIn, builtIn: TypeIDExtensionObject}, nil
		}
		return fieldCodec{kind: codecBuiltIn, builtIn: TypeIDVariant}, nil
	}
	if sd != nil {
		if !nullNodeID(sd.DefaultEncodingID) {
			if v := eotypes.New(sd.DefaultEncodingID); v != nil {
				return fieldCodec{kind: codecGo, goType: reflect.TypeOf(v)}, nil
			}
		}
		return fieldCodec{kind: codecDynamic, dyn: t}, nil
	}
	if isEnum && t.BuiltIn == TypeIDExtensionObject {
		return fieldCodec{kind: codecOptionSet, goType: optionSetType}, nil
	}
	if structure {
		// A concrete Structure is encoded in the field itself (OPC
		// 10000-6 §5.2.6): without its definition it cannot be read.
		return fieldCodec{}, fmt.Errorf("ua: no StructureDefinition for the DataType %s of a field: %w", dataType, StatusBadDataTypeIDUnknown)
	}
	if t.BuiltIn < TypeIDBoolean || t.BuiltIn > TypeIDDiagnosticInfo {
		return fieldCodec{}, fmt.Errorf("ua: DataType %s is encoded as built-in type %d: %w", dataType, t.BuiltIn, StatusBadDataTypeIDUnknown)
	}
	return fieldCodec{kind: codecBuiltIn, builtIn: t.BuiltIn}, nil
}

// ns0GoCodec returns the codec of a Structure of namespace 0 whose Default
// Binary encoding, "<Name>_Encoding_DefaultBinary" (OPC 10000-6 §A.3), has
// a registered Go type.
func ns0GoCodec(dataType *NodeID) (fieldCodec, bool) {
	if dataType.Namespace() != 0 || dataType.Type() == NodeIDTypeString || dataType.Type() == NodeIDTypeGUID || dataType.Type() == NodeIDTypeByteString {
		return fieldCodec{}, false
	}
	name := id.DataTypeName(dataType.IntID())
	if name == "" {
		return fieldCodec{}, false
	}
	enc, ok := id.NodeIDByName(name + "_Encoding_DefaultBinary")
	if !ok {
		return fieldCodec{}, false
	}
	v := eotypes.New(NewNumericNodeID(0, enc))
	if v == nil {
		return fieldCodec{}, false
	}
	return fieldCodec{kind: codecGo, goType: reflect.TypeOf(v)}, true
}

// goType returns the Go type of a value of the codec.
func (c fieldCodec) valueType() reflect.Type {
	switch c.kind {
	case codecBuiltIn:
		return variantTypeIDToType[c.builtIn]
	case codecDynamic:
		return dynamicStructureType
	default:
		return c.goType
	}
}

var (
	dynamicStructureType = reflect.TypeOf(new(DynamicStructure))
	extensionObjectType  = reflect.TypeOf(new(ExtensionObject))
)

// minSize returns the fewest bytes a value of the codec takes, which bounds
// the length of an array the input can hold. depth stops a definition that
// contains itself.
func (s *DynamicTypes) minSize(c fieldCodec, depth int) int {
	switch c.kind {
	case codecBuiltIn:
		return builtInMinSize[c.builtIn]
	case codecOptionSet:
		return 8 // two ByteStrings
	case codecGo:
		if emptyStruct(c.goType) {
			return 0
		}
		return 1
	case codecDynamic:
	}
	sd := c.dyn.structure()
	if sd.StructureType != StructureTypeStructure && sd.StructureType != StructureTypeStructureWithSubtypedValues {
		return 4 // the EncodingMask or the SwitchField
	}
	if depth > 8 {
		return 0
	}
	n := 0
	for _, f := range sd.Fields {
		if f.ValueRank != valueRankScalar {
			n += 4
			continue
		}
		fc, err := s.codecOf(f.DataType, subtyped(sd) && f.IsOptional)
		if err != nil {
			continue
		}
		n += s.minSize(fc, depth+1)
	}
	return n
}

// builtInMinSize is the size of the shortest encoding of each built-in
// type (OPC 10000-6 §5.2.2).
var builtInMinSize = map[TypeID]int{
	TypeIDBoolean: 1, TypeIDSByte: 1, TypeIDByte: 1, TypeIDInt16: 2, TypeIDUint16: 2,
	TypeIDInt32: 4, TypeIDUint32: 4, TypeIDInt64: 8, TypeIDUint64: 8, TypeIDFloat: 4,
	TypeIDDouble: 8, TypeIDString: 4, TypeIDDateTime: 8, TypeIDGUID: 16, TypeIDByteString: 4,
	TypeIDXMLElement: 4, TypeIDNodeID: 2, TypeIDExpandedNodeID: 2, TypeIDStatusCode: 4,
	TypeIDQualifiedName: 6, TypeIDLocalizedText: 1, TypeIDExtensionObject: 3,
	TypeIDDataValue: 1, TypeIDVariant: 1, TypeIDDiagnosticInfo: 1,
}

// --- decoding ------------------------------------------------------------

// decodeStructure decodes a value of the Structure t from b and returns it
// with the number of bytes it took. depth is the nesting level of the
// value (see MaxBinaryNestingDepth).
func (s *DynamicTypes) decodeStructure(t *DynamicType, b []byte, depth int) (*DynamicStructure, int, error) {
	if depth > MaxBinaryNestingDepth {
		return nil, 0, fmt.Errorf("ua: binary: nesting exceeds %d levels: %w", MaxBinaryNestingDepth, StatusBadEncodingLimitsExceeded)
	}
	sd := t.structure()
	d := &DynamicStructure{Type: t, Fields: make([]any, len(sd.Fields)), types: s}
	pos := 0
	readUint32 := func() (uint32, error) {
		if len(b)-pos < 4 {
			return 0, fmt.Errorf("ua: %s: %w", t.DataTypeID, StatusBadDecodingError)
		}
		v := uint32(b[pos]) | uint32(b[pos+1])<<8 | uint32(b[pos+2])<<16 | uint32(b[pos+3])<<24
		pos += 4
		return v, nil
	}
	field := func(i int) error {
		f := sd.Fields[i]
		v, n, err := s.decodeField(f, subtyped(sd) && f.IsOptional, b[pos:], depth)
		if err != nil {
			return fmt.Errorf("ua: %s.%s: %w", t.Name, f.Name, err)
		}
		d.Fields[i] = v
		pos += n
		return nil
	}
	switch sd.StructureType {
	case StructureTypeStructure, StructureTypeStructureWithSubtypedValues:
		// "Structures are encoded as a sequence of fields in the order
		// that they appear in the definition" (OPC 10000-6 §5.2.6).
		for i := range sd.Fields {
			if err := field(i); err != nil {
				return nil, pos, err
			}
		}
	case StructureTypeStructureWithOptionalFields:
		// "The EncodingMask is a 32-bit unsigned integer. Each optional
		// field is assigned exactly one bit. The first optional field is
		// assigned bit '0' ... Decoders shall report an error if
		// unassigned bits are not 0" (OPC 10000-6 §5.2.7).
		mask, err := readUint32()
		if err != nil {
			return nil, pos, err
		}
		bit := uint(0)
		for i, f := range sd.Fields {
			if f.IsOptional {
				present := mask&(1<<bit) != 0
				bit++
				if !present {
					continue
				}
			}
			if err := field(i); err != nil {
				return nil, pos, err
			}
		}
		if bit < 32 && mask>>bit != 0 {
			return nil, pos, fmt.Errorf("ua: %s: EncodingMask 0x%08x sets bits of no optional field: %w", t.DataTypeID, mask, StatusBadDecodingError)
		}
	default: // a Union (checkStructureDefinition)
		// "The switch field is the index of the available union fields
		// starting with 1. If the switch field is 0 then no field is
		// present. For any value greater than the number of defined
		// union fields the encoders or decoders shall report an error"
		// (OPC 10000-6 §5.2.8).
		sw, err := readUint32()
		if err != nil {
			return nil, pos, err
		}
		if uint64(sw) > uint64(len(sd.Fields)) {
			return nil, pos, fmt.Errorf("ua: %s: SwitchField %d of %d fields: %w", t.DataTypeID, sw, len(sd.Fields), StatusBadDecodingError)
		}
		d.Switch = sw
		if sw > 0 {
			if err := field(int(sw - 1)); err != nil {
				return nil, pos, err
			}
		}
	}
	return d, pos, nil
}

// decodeField decodes the value of the field f from b.
func (s *DynamicTypes) decodeField(f *StructureField, allowSubTypes bool, b []byte, depth int) (any, int, error) {
	c, err := s.codecOf(f.DataType, allowSubTypes)
	if err != nil {
		return nil, 0, err
	}
	switch f.ValueRank {
	case valueRankScalar:
		return s.decodeValue(c, b, depth)
	case 1:
		n, pos, err := readLength(b)
		if err != nil || n < 0 {
			return nil, pos, err // a null array
		}
		v, m, err := s.decodeValues(c, int(n), b[pos:], depth)
		return v, pos + m, err
	}
	// "When a multi-dimensional Array is a field of a Structure ... it
	// shall be encoded with the inline matrix representation": the
	// Dimensions, an Int32 array of at least two, and the values. "If any
	// dimension has a length <= 0, then no values are encoded" (OPC
	// 10000-6 §5.2.5, Table 28).
	var dims []int32
	pos, err := decode(b, reflect.ValueOf(&dims), "Dimensions", depth)
	if err != nil {
		return nil, pos, err
	}
	if len(dims) == 0 {
		// The null matrix, as encodeField writes it.
		return nil, pos, nil
	}
	if len(dims) != int(f.ValueRank) {
		return nil, pos, fmt.Errorf("%d dimensions for ValueRank %d: %w", len(dims), f.ValueRank, StatusBadDecodingError)
	}
	total := int64(1)
	for _, d := range dims {
		if d <= 0 {
			total = 0
			break
		}
		total *= int64(d)
		if total > math.MaxInt32 {
			return nil, pos, fmt.Errorf("%w: a matrix of %v", errors.ErrArrayTooLarge, dims)
		}
	}
	v, m, err := s.decodeValues(c, int(total), b[pos:], depth)
	if err != nil {
		return nil, pos + m, err
	}
	return &DynamicMatrix{Dimensions: dims, Values: v}, pos + m, nil
}

// readLength reads the Int32 length of an array; -1 is a null array.
func readLength(b []byte) (int32, int, error) {
	if len(b) < 4 {
		return 0, 0, fmt.Errorf("array length: %w", StatusBadDecodingError)
	}
	n := int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
	if n < -1 {
		return 0, 4, fmt.Errorf("array length %d: %w", n, StatusBadDecodingError)
	}
	return n, 4, nil
}

// decodeValues decodes n values of the codec into a slice. The length is
// the sender's claim: it is checked against the input before the slice is
// allocated, every value taking at least minSize bytes.
func (s *DynamicTypes) decodeValues(c fieldCodec, n int, b []byte, depth int) (any, int, error) {
	if min := s.minSize(c, 0); min > 0 {
		if n > len(b)/min {
			return nil, 0, fmt.Errorf("%w: %d elements, %d bytes of input", errors.ErrArrayTooLarge, n, len(b))
		}
	} else if n > MaxVariantArrayLength {
		return nil, 0, fmt.Errorf("%w: %d elements", errors.ErrArrayTooLarge, n)
	}
	out := reflect.MakeSlice(reflect.SliceOf(c.valueType()), n, n)
	pos := 0
	for i := range n {
		v, m, err := s.decodeValue(c, b[pos:], depth)
		if err != nil {
			return nil, pos, err
		}
		pos += m
		if v != nil {
			out.Index(i).Set(reflect.ValueOf(v))
		}
	}
	return out.Interface(), pos, nil
}

// decodeValue decodes one value of the codec from b.
func (s *DynamicTypes) decodeValue(c fieldCodec, b []byte, depth int) (any, int, error) {
	switch c.kind {
	case codecDynamic:
		return s.decodeStructure(c.dyn, b, depth+1)
	case codecBuiltIn:
		t := variantTypeIDToType[c.builtIn]
		v := reflect.New(t).Elem()
		if t.Kind() == reflect.Pointer {
			v.Set(reflect.New(t.Elem()))
		}
		n, err := decode(b, v, t.String(), depth)
		if err != nil {
			return nil, n, err
		}
		if eo, ok := v.Interface().(*ExtensionObject); ok {
			// A nested ExtensionObject of a type of the set. One that
			// stays undecoded keeps its body as a []byte Value, as the
			// JSON and XML decoders keep it, so that the Structure
			// encodes back unchanged (ExtensionObject.Encode does not
			// write a RawBody).
			if s.DecodeExtensionObject(eo) != nil && eo.Value == nil && eo.RawBody != nil {
				eo.Value, eo.RawBody = eo.RawBody, nil
			}
		}
		return v.Interface(), n, nil
	default: // codecGo, codecOptionSet
		v := reflect.New(c.goType.Elem())
		n, err := decode(b, v, c.goType.String(), depth)
		if err != nil {
			return nil, n, err
		}
		return v.Interface(), n, nil
	}
}

// --- encoding ------------------------------------------------------------

func (s *DynamicTypes) encodeStructure(t *DynamicType, d *DynamicStructure, depth int) ([]byte, error) {
	if depth >= MaxBinaryNestingDepth {
		return nil, fmt.Errorf("ua: binary: nesting exceeds %d levels: %w", MaxBinaryNestingDepth, StatusBadEncodingLimitsExceeded)
	}
	sd := t.structure()
	var fields []any
	var sw uint32
	if d != nil {
		fields, sw = d.Fields, d.Switch
	}
	value := func(i int) any {
		if i < len(fields) {
			return fields[i]
		}
		return nil
	}
	buf := NewBuffer(nil)
	field := func(i int) error {
		f := sd.Fields[i]
		b, err := s.encodeField(f, subtyped(sd) && f.IsOptional, value(i), depth)
		if err != nil {
			return fmt.Errorf("ua: %s.%s: %w", t.Name, f.Name, err)
		}
		buf.Write(b)
		return nil
	}
	switch sd.StructureType {
	case StructureTypeStructure, StructureTypeStructureWithSubtypedValues:
		for i := range sd.Fields {
			if err := field(i); err != nil {
				return nil, err
			}
		}
	case StructureTypeStructureWithOptionalFields:
		// An optional field is present when its value is not nil; the
		// mask has a bit per optional field, in order (OPC 10000-6
		// §5.2.7).
		var mask uint32
		bit := uint(0)
		for i, f := range sd.Fields {
			if f.IsOptional {
				if value(i) != nil {
					mask |= 1 << bit
				}
				bit++
			}
		}
		buf.WriteUint32(mask)
		for i, f := range sd.Fields {
			if f.IsOptional && value(i) == nil {
				continue
			}
			if err := field(i); err != nil {
				return nil, err
			}
		}
	default: // a Union
		if uint64(sw) > uint64(len(sd.Fields)) {
			return nil, fmt.Errorf("ua: %s: SwitchField %d of %d fields: %w", t.DataTypeID, sw, len(sd.Fields), StatusBadEncodingError)
		}
		buf.WriteUint32(sw)
		if sw > 0 {
			if err := field(int(sw - 1)); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), buf.Error()
}

func (s *DynamicTypes) encodeField(f *StructureField, allowSubTypes bool, v any, depth int) ([]byte, error) {
	c, err := s.codecOf(f.DataType, allowSubTypes)
	if err != nil {
		return nil, err
	}
	switch f.ValueRank {
	case valueRankScalar:
		return s.encodeValue(c, v, depth)
	case 1:
		if v == nil {
			return nullArray(), nil
		}
		return s.encodeValues(c, v, true, depth)
	}
	m, ok := v.(*DynamicMatrix)
	if v == nil || (ok && m == nil) {
		// A null matrix: the Dimensions as a null array.
		return nullArray(), nil
	}
	if !ok {
		return nil, fmt.Errorf("%T for a matrix field: %w", v, StatusBadEncodingError)
	}
	if len(m.Dimensions) != int(f.ValueRank) {
		return nil, fmt.Errorf("%d dimensions for ValueRank %d: %w", len(m.Dimensions), f.ValueRank, StatusBadEncodingError)
	}
	total := int64(1)
	for _, d := range m.Dimensions {
		if d <= 0 {
			total = 0
			break
		}
		total *= int64(d)
		if total > math.MaxInt32 {
			return nil, fmt.Errorf("%w: a matrix of %v", errors.ErrArrayTooLarge, m.Dimensions)
		}
	}
	buf := NewBuffer(nil)
	buf.WriteStruct(m.Dimensions)
	values := reflect.ValueOf(m.Values)
	if m.Values == nil {
		values = reflect.MakeSlice(reflect.SliceOf(c.valueType()), 0, 0)
	}
	if values.Kind() != reflect.Slice || int64(values.Len()) != total {
		return nil, fmt.Errorf("%d values for a matrix of %v: %w", sliceLen(values), m.Dimensions, StatusBadEncodingError)
	}
	b, err := s.encodeValues(c, values.Interface(), false, depth)
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	return buf.Bytes(), buf.Error()
}

func sliceLen(v reflect.Value) int {
	if v.Kind() != reflect.Slice {
		return -1
	}
	return v.Len()
}

// nullArray returns the encoding of a null array: "If an Array is null,
// then its length is encoded as -1" (OPC 10000-6 §5.2.5).
func nullArray() []byte { return []byte{0xff, 0xff, 0xff, 0xff} }

// encodeValues encodes a slice of values of the codec, with its length
// when withLength.
func (s *DynamicTypes) encodeValues(c fieldCodec, v any, withLength bool, depth int) ([]byte, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice || rv.Type().Elem() != c.valueType() {
		return nil, fmt.Errorf("%T for an array of %v: %w", v, c.valueType(), StatusBadEncodingError)
	}
	if rv.Len() > math.MaxInt32 {
		return nil, fmt.Errorf("%w: %d elements", errors.ErrArrayTooLarge, rv.Len())
	}
	buf := NewBuffer(nil)
	if withLength {
		buf.WriteInt32(int32(rv.Len())) // checked above
	}
	for i := range rv.Len() {
		b, err := s.encodeValue(c, rv.Index(i).Interface(), depth)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		buf.Write(b)
	}
	return buf.Bytes(), buf.Error()
}

// encodeValue encodes one value of the codec; nil is the default value.
func (s *DynamicTypes) encodeValue(c fieldCodec, v any, depth int) ([]byte, error) {
	if c.kind == codecDynamic {
		d, ok := v.(*DynamicStructure)
		if v != nil && !ok {
			return nil, fmt.Errorf("%T for a field of DataType %s: %w", v, c.dyn.DataTypeID, StatusBadEncodingError)
		}
		if d != nil && d.Type != nil && d.Type != c.dyn && !d.Type.DataTypeID.Equal(c.dyn.DataTypeID) {
			return nil, fmt.Errorf("a %s for a field of DataType %s: %w", d.Type.DataTypeID, c.dyn.DataTypeID, StatusBadEncodingError)
		}
		// A nil nested Structure is encoded with its default values
		// (OPC 10000-6 §5.2.6).
		return s.encodeStructure(c.dyn, d, depth+1)
	}
	t := c.valueType()
	rv := reflect.ValueOf(v)
	switch {
	case t == extensionObjectType && (v == nil || (rv.Type() == t && rv.IsNil())):
		// The null ExtensionObject: TypeId i=0 and no body (OPC
		// 10000-6 §5.2.2.15).
		rv = reflect.ValueOf(NewExtensionObject(nil))
	case v == nil || (rv.Kind() == reflect.Pointer && rv.IsNil() && rv.Type() == t):
		rv = reflect.New(t).Elem()
		if t.Kind() == reflect.Pointer {
			rv.Set(reflect.New(t.Elem()))
		}
	case rv.Type() != t:
		return nil, fmt.Errorf("%T for a field of %v: %w", v, t, StatusBadEncodingError)
	}
	return encode(rv, t.String(), depth)
}
