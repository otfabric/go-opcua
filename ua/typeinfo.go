// SPDX-License-Identifier: MIT

package ua

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// This file holds the type metadata shared by the JSON and XML DataEncodings.
//
// The binary codec only needs the Go types: fields are written in declaration
// order and nothing is named on the wire. JSON and XML name every field, type
// and enumeration value with the spelling of the specification, which differs
// from the reformatted Go identifiers (NodeId vs NodeID), and identify
// structures by their DataType / DefaultXml NodeId rather than by the
// DefaultBinary NodeId the extension object registry is keyed on. That extra
// information is generated into typeinfo_gen.go from Opc.Ua.Types.bsd and
// NodeIds.csv.

// DataTypeInfo describes how a structure registered with
// [RegisterExtensionObject] appears in the JSON and XML DataEncodings.
// Every field is optional.
type DataTypeInfo struct {
	// Name is the name of the DataType. It is the element name of the
	// structure in an XML ExtensionObject body. It defaults to the name of
	// the Go type.
	Name string

	// DataTypeID is the NodeId of the DataType node. JSON identifies the
	// body of an ExtensionObject with it (UaTypeId).
	DataTypeID *NodeID

	// XMLEncodingID is the NodeId of the "Default XML" encoding node. XML
	// identifies the body of an ExtensionObject with it.
	XMLEncodingID *NodeID

	// JSONEncodingID is the NodeId of the "Default JSON" encoding node. It
	// is only accepted when decoding.
	JSONEncodingID *NodeID
}

// RegisterDataTypeInfo attaches JSON/XML metadata to a structure type that is
// (or will be) registered with [RegisterExtensionObject]. v is a pointer to
// the structure, exactly as passed to RegisterExtensionObject.
//
// Without it a custom structure still round-trips through [EncodeJSON] and
// [EncodeXML]: fields are named after the Go fields (or their `opcua:"Name"`
// struct tag) and the body is identified by the NodeId passed to
// RegisterExtensionObject. Registering the DataType NodeId is what makes the
// documents portable to other stacks.
//
// The two registrations may come in either order and at any time, also while
// other goroutines encode and decode. A document can name the type by the
// NodeIds given here once the type is registered as an extension object as
// well; until then the decoders treat it as unknown.
func RegisterDataTypeInfo(v interface{}, info DataTypeInfo) {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	codecTypes.structInfo(t) // describes the type on first use

	codecTypes.mu.Lock()
	defer codecTypes.mu.Unlock()
	// A published structInfo is never modified: the codecs read it without
	// holding the lock, also while this function runs. The metadata is
	// attached to a copy, which then replaces the description everywhere,
	// so that a reader sees either all of the new metadata or none of it.
	cur := codecTypes.byType[t]
	next := new(structInfo)
	*next = *cur
	if info.Name != "" {
		next.name = info.Name
	}
	if info.DataTypeID != nil {
		next.dataTypeID = info.DataTypeID
	}
	if info.XMLEncodingID != nil {
		next.xmlID = info.XMLEncodingID
	}
	if info.JSONEncodingID != nil {
		next.jsonID = info.JSONEncodingID
	}
	codecTypes.byType[t] = next
	for k, si := range codecTypes.byID {
		if si == cur {
			codecTypes.byID[k] = next
		}
	}
	for k, si := range codecTypes.byName {
		if si == cur {
			codecTypes.byName[k] = next
		}
	}
	if info.Name != "" {
		codecTypes.byName[info.Name] = next
	}
	for _, id := range []*NodeID{info.DataTypeID, info.XMLEncodingID, info.JSONEncodingID} {
		if id != nil {
			codecTypes.byID[id.String()] = next
		}
	}
}

// structInfo is the JSON/XML view of a structure type. It is immutable once
// it is in the registry; see RegisterDataTypeInfo.
type structInfo struct {
	name string
	typ  reflect.Type // the struct type, never a pointer

	// generated is set for the structures of the specification. They can
	// be the body of an ExtensionObject whether or not the extension
	// object registry has a binary encoding id for them.
	generated bool

	dataTypeID *NodeID
	binaryID   *NodeID
	xmlID      *NodeID
	jsonID     *NodeID

	fields []string       // specification name of every Go field, in order
	byName map[string]int // specification name -> field index
}

type enumValue struct {
	name  string
	value int64
}

// enumInfo is the JSON/XML view of an enumeration type.
type enumInfo struct {
	name      string
	optionSet bool
	values    []enumValue
}

func (e *enumInfo) symbol(v int64) (string, bool) {
	if e == nil || e.optionSet {
		return "", false
	}
	for _, ev := range e.values {
		if ev.value == v {
			return ev.name, true
		}
	}
	return "", false
}

type typeInfoRegistry struct {
	mu     sync.RWMutex
	byType map[reflect.Type]*structInfo
	byID   map[string]*structInfo // DataType and every encoding NodeId
	byName map[string]*structInfo
	enums  map[reflect.Type]*enumInfo

	// pending holds the structures that were registered as extension
	// objects and are not described yet. They are described - and with
	// that found by name - when a name is looked up that nothing answers
	// to. describing serialises that, so that nobody misses a name while
	// another goroutine is still working through the list.
	pending    []reflect.Type
	describing sync.Mutex
}

var codecTypes = &typeInfoRegistry{
	byType: map[reflect.Type]*structInfo{},
	byID:   map[string]*structInfo{},
	byName: map[string]*structInfo{},
	enums:  map[reflect.Type]*enumInfo{},
}

// registerStructType is called from the generated init function.
func registerStructType(v interface{}, name string, dataType, binary, xml, json uint32, fields ...string) {
	t := reflect.TypeOf(v).Elem()
	si := &structInfo{name: name, typ: t, generated: true, fields: fields, byName: make(map[string]int, len(fields))}
	for i, f := range fields {
		si.byName[f] = i
	}
	set := func(dst **NodeID, id uint32) {
		if id == 0 {
			return
		}
		*dst = NewNumericNodeID(0, id)
		codecTypes.byID[(*dst).String()] = si
	}
	set(&si.dataTypeID, dataType)
	set(&si.binaryID, binary)
	set(&si.xmlID, xml)
	set(&si.jsonID, json)
	codecTypes.byType[t] = si
	codecTypes.byName[name] = si
}

// registerEnumType is called from the generated init function.
func registerEnumType(t reflect.Type, name string, optionSet bool, values []enumValue) {
	codecTypes.enums[t] = &enumInfo{name: name, optionSet: optionSet, values: values}
}

// structInfo returns the metadata of a struct type. Types that are not part
// of the generated set (custom structures) are described by reflection.
func (r *typeInfoRegistry) structInfo(t reflect.Type) *structInfo {
	r.mu.RLock()
	si := r.byType[t]
	r.mu.RUnlock()
	if si != nil {
		return si
	}

	si = &structInfo{name: t.Name(), typ: t, byName: map[string]int{}}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := f.Name
		if tag := f.Tag.Get("opcua"); tag != "" {
			name = tag
		}
		si.fields = append(si.fields, name)
		si.byName[name] = i
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.byType[t]; cur != nil {
		return cur
	}
	r.byType[t] = si
	// Only types that can be the body of an ExtensionObject are found by
	// name; any other struct is merely described. The registry is asked
	// under the lock: a registration that comes later finds the
	// description stored above, see extensionObjectRegistered.
	if _, taken := r.byName[si.name]; !taken && si.name != "" && eotypes.registered(reflect.PointerTo(t)) {
		r.byName[si.name] = si
	}
	return si
}

// extensionObjectRegistered is called by RegisterExtensionObject. Whether a
// structure is found by its name must not depend on what happened first, the
// registration or the first use of the type by a codec - nor on whether the
// type has been used at all. A structure that is described already becomes
// known by its name now; any other is noted and described when a name is
// looked up, see describePending. (It cannot be described here: the generated
// structures are registered as extension objects before their generated
// description is installed.)
func (r *typeInfoRegistry) extensionObjectRegistered(t reflect.Type) {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	si := r.byType[t]
	if si == nil {
		r.pending = append(r.pending, t)
		return
	}
	if _, taken := r.byName[si.name]; !taken && si.name != "" {
		r.byName[si.name] = si
	}
}

// describePending describes the registered structures no codec has used yet.
func (r *typeInfoRegistry) describePending() {
	r.describing.Lock()
	defer r.describing.Unlock()
	r.mu.Lock()
	pending := r.pending
	r.pending = nil
	r.mu.Unlock()
	for _, t := range pending {
		r.structInfo(t)
	}
}

// usable reports whether a structure can be the body of an ExtensionObject:
// it is generated, or registered with RegisterExtensionObject. Metadata that
// RegisterDataTypeInfo attached to a type that is not registered yet does not
// count: an ExtensionObject of that type would have no binary encoding id,
// and writing it in the binary encoding would produce an object without a
// type.
func (r *typeInfoRegistry) usable(si *structInfo) bool {
	return si != nil && (si.generated || eotypes.registered(reflect.PointerTo(si.typ)))
}

// structByName returns the structure with the given DataType name that can
// be the body of an ExtensionObject, or nil.
func (r *typeInfoRegistry) structByName(name string) *structInfo {
	r.mu.RLock()
	si := r.byName[name]
	r.mu.RUnlock()
	if si == nil {
		r.describePending()
		r.mu.RLock()
		si = r.byName[name]
		r.mu.RUnlock()
	}
	if !r.usable(si) {
		return nil
	}
	return si
}

// newByTypeID returns a new value of the type identified by a DataType or
// encoding NodeId, or nil if the id is unknown. It falls back to the
// extension object registry so that custom types work without further
// registration.
func (r *typeInfoRegistry) newByTypeID(id *NodeID) interface{} {
	if id == nil {
		return nil
	}
	r.mu.RLock()
	si := r.byID[id.String()]
	r.mu.RUnlock()
	if r.usable(si) {
		return reflect.New(si.typ).Interface()
	}
	return eotypes.New(id)
}

func (r *typeInfoRegistry) enumInfo(t reflect.Type) *enumInfo {
	return r.enums[t] // written during init only
}

// registeredStructs returns a new zero value of every generated or registered
// structure type, sorted by name. Used by the tests.
func (r *typeInfoRegistry) registeredStructs() []interface{} {
	r.describePending()
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.byName))
	for n := range r.byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]interface{}, 0, len(names))
	for _, n := range names {
		out = append(out, reflect.New(r.byName[n].typ).Interface())
	}
	return out
}

// codecKind classifies a Go type for the JSON and XML codecs. The values
// 1..25 are the built-in type ids of Part 6 Table 1.
type codecKind uint8

const (
	kindInvalid codecKind = 0
	kindEnum    codecKind = 100 + iota
	kindStruct
	kindStructPtr
	kindArray
)

var (
	typeBytes          = reflect.TypeOf([]byte(nil))
	typeByteArray      = reflect.TypeOf(ByteArray(nil))
	typeGUIDPtr        = reflect.TypeOf((*GUID)(nil))
	typeXMLElement     = reflect.TypeOf(XMLElement(""))
	typeXMLElementPtr  = reflect.TypeOf((*XMLElement)(nil))
	typeNodeIDPtr      = reflect.TypeOf((*NodeID)(nil))
	typeExpNodeIDPtr   = reflect.TypeOf((*ExpandedNodeID)(nil))
	typeStatusCode     = reflect.TypeOf(StatusCode(0))
	typeQualifiedName  = reflect.TypeOf((*QualifiedName)(nil))
	typeLocalizedText  = reflect.TypeOf((*LocalizedText)(nil))
	typeExtObjPtr      = reflect.TypeOf((*ExtensionObject)(nil))
	typeDataValuePtr   = reflect.TypeOf((*DataValue)(nil))
	typeVariantPtr     = reflect.TypeOf((*Variant)(nil))
	typeDiagInfoPtr    = reflect.TypeOf((*DiagnosticInfo)(nil))
	builtinStructKinds = map[reflect.Type]codecKind{
		typeGUIDPtr.Elem():       codecKind(TypeIDGUID),
		typeNodeIDPtr.Elem():     codecKind(TypeIDNodeID),
		typeExpNodeIDPtr.Elem():  codecKind(TypeIDExpandedNodeID),
		typeQualifiedName.Elem(): codecKind(TypeIDQualifiedName),
		typeLocalizedText.Elem(): codecKind(TypeIDLocalizedText),
		typeExtObjPtr.Elem():     codecKind(TypeIDExtensionObject),
		typeDataValuePtr.Elem():  codecKind(TypeIDDataValue),
		typeVariantPtr.Elem():    codecKind(TypeIDVariant),
		typeDiagInfoPtr.Elem():   codecKind(TypeIDDiagnosticInfo),
	}
	kindCache sync.Map // reflect.Type -> codecKind
)

// kindOf classifies t. Built-in structures are reported with their built-in
// id whether t is the struct or a pointer to it; the codecs normalise the
// value with [builtinPtr].
func kindOf(t reflect.Type) codecKind {
	if k, ok := kindCache.Load(t); ok {
		return k.(codecKind)
	}
	k := classify(t)
	kindCache.Store(t, k)
	return k
}

func classify(t reflect.Type) codecKind {
	switch t {
	case timeType:
		return codecKind(TypeIDDateTime)
	case typeBytes:
		return codecKind(TypeIDByteString)
	case typeXMLElement, typeXMLElementPtr:
		return codecKind(TypeIDXMLElement)
	case typeStatusCode:
		return codecKind(TypeIDStatusCode)
	}
	if k, ok := builtinStructKinds[t]; ok {
		return k
	}
	switch t.Kind() {
	case reflect.Pointer:
		e := t.Elem()
		if k, ok := builtinStructKinds[e]; ok {
			return k
		}
		if e.Kind() == reflect.Struct && e != timeType {
			return kindStructPtr
		}
		return kindInvalid
	case reflect.Struct:
		return kindStruct
	case reflect.Slice:
		if kindOf(t.Elem()) == kindInvalid {
			return kindInvalid
		}
		return kindArray
	default:
	}
	var k codecKind
	switch t.Kind() {
	case reflect.Bool:
		return codecKind(TypeIDBoolean)
	case reflect.String:
		return codecKind(TypeIDString)
	case reflect.Float32:
		return codecKind(TypeIDFloat)
	case reflect.Float64:
		return codecKind(TypeIDDouble)
	case reflect.Int8:
		k = codecKind(TypeIDSByte)
	case reflect.Uint8:
		k = codecKind(TypeIDByte)
	case reflect.Int16:
		k = codecKind(TypeIDInt16)
	case reflect.Uint16:
		k = codecKind(TypeIDUint16)
	case reflect.Int32:
		k = codecKind(TypeIDInt32)
	case reflect.Uint32:
		k = codecKind(TypeIDUint32)
	case reflect.Int64:
		k = codecKind(TypeIDInt64)
	case reflect.Uint64:
		k = codecKind(TypeIDUint64)
	default:
		return kindInvalid
	}
	if t.PkgPath() != "" { // a named integer type is an enumeration or option set
		return kindEnum
	}
	return k
}

// builtinPtr returns v as a pointer when v is a built-in structure held by
// value, so that the codecs only deal with one representation.
func builtinPtr(v reflect.Value) reflect.Value {
	if v.Kind() != reflect.Struct {
		return v
	}
	if v.CanAddr() {
		return v.Addr()
	}
	p := reflect.New(v.Type())
	p.Elem().Set(v)
	return p
}

// builtinTypeNames are the names of the built-in types in the XML encoding
// and in the specification (Part 6 Table 1), indexed by TypeID.
var builtinTypeNames = [...]string{
	TypeIDNull:            "Null",
	TypeIDBoolean:         "Boolean",
	TypeIDSByte:           "SByte",
	TypeIDByte:            "Byte",
	TypeIDInt16:           "Int16",
	TypeIDUint16:          "UInt16",
	TypeIDInt32:           "Int32",
	TypeIDUint32:          "UInt32",
	TypeIDInt64:           "Int64",
	TypeIDUint64:          "UInt64",
	TypeIDFloat:           "Float",
	TypeIDDouble:          "Double",
	TypeIDString:          "String",
	TypeIDDateTime:        "DateTime",
	TypeIDGUID:            "Guid",
	TypeIDByteString:      "ByteString",
	TypeIDXMLElement:      "XmlElement",
	TypeIDNodeID:          "NodeId",
	TypeIDExpandedNodeID:  "ExpandedNodeId",
	TypeIDStatusCode:      "StatusCode",
	TypeIDQualifiedName:   "QualifiedName",
	TypeIDLocalizedText:   "LocalizedText",
	TypeIDExtensionObject: "ExtensionObject",
	TypeIDDataValue:       "DataValue",
	TypeIDVariant:         "Variant",
	TypeIDDiagnosticInfo:  "DiagnosticInfo",
}

func builtinTypeByName(name string) (TypeID, bool) {
	for id, n := range builtinTypeNames {
		if n == name && id != 0 {
			return TypeID(id), true
		}
	}
	return 0, false
}

// typeName returns the specification name of a Go type: the name of the
// element that holds a value of the type in an XML array.
func typeName(t reflect.Type) string {
	k := kindOf(t)
	switch k {
	case kindEnum:
		if ei := codecTypes.enumInfo(t); ei != nil {
			return ei.name
		}
		return t.Name()
	case kindStruct:
		return codecTypes.structInfo(t).name
	case kindStructPtr:
		return codecTypes.structInfo(t.Elem()).name
	case kindArray:
		return "ListOf" + typeName(t.Elem())
	case kindInvalid:
		return t.String()
	}
	return builtinTypeNames[k]
}

// parseEnum reads the "Name_Value" form of the verbose JSON and the XML
// encoding as well as a plain number.
func parseEnum(s string, ei *enumInfo) (int64, bool) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '_'); i >= 0 {
		if v, err := strconv.ParseInt(s[i+1:], 10, 64); err == nil {
			return v, true
		}
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v, true
	}
	if ei != nil {
		for _, ev := range ei.values {
			if ev.name == s {
				return ev.value, true
			}
		}
	}
	return 0, false
}
