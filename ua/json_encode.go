// SPDX-License-Identifier: MIT

package ua

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"
)

// EncodeJSON encodes v in the OPC UA JSON DataEncoding (Part 6 §5.4).
//
// v is a value of a built-in type (bool, int32, string, time.Time, *NodeID,
// *Variant, *DataValue, *ExtensionObject, ...), a pointer to a generated or
// registered structure, an enumeration, or a slice of any of these.
//
// The default output is the Compact encoding of OPC UA 1.05.04, the form
// open62541 1.5 emits and accepts; see [WithJSONForm] for the other forms.
// The result is unrelated to what encoding/json produces for the same value
// through the MarshalJSON methods of this package, which is a display format.
func EncodeJSON(v interface{}, opts ...CodecOption) ([]byte, error) {
	e := &jsonEncoder{o: newCodecOptions(opts)}
	if v == nil {
		e.buf = append(e.buf, "null"...)
	} else if err := e.value(reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	if e.o.indent == "" {
		return e.buf, nil
	}
	var out bytes.Buffer
	if err := json.Indent(&out, e.buf, "", e.o.indent); err != nil {
		return nil, codecError(StatusBadEncodingError, "json", "", "%v", err)
	}
	return out.Bytes(), nil
}

type jsonEncoder struct {
	buf   []byte
	o     *codecOptions
	depth int
}

func (e *jsonEncoder) legacy() bool {
	return e.o.form == JSONLegacyReversible || e.o.form == JSONLegacyNonReversible
}

// symbolic reports whether enumerations are written as "Name_Value" and
// status codes carry their symbol.
func (e *jsonEncoder) symbolic() bool {
	return e.o.form == JSONVerbose || e.o.form == JSONLegacyNonReversible
}

func (e *jsonEncoder) raw(s string)  { e.buf = append(e.buf, s...) }
func (e *jsonEncoder) null()         { e.buf = append(e.buf, "null"...) }
func (e *jsonEncoder) uint(n uint64) { e.buf = strconv.AppendUint(e.buf, n, 10) }
func (e *jsonEncoder) int(n int64)   { e.buf = strconv.AppendInt(e.buf, n, 10) }

const jsonHex = "0123456789abcdef"

func (e *jsonEncoder) str(s string) {
	b := append(e.buf, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' && c != 0x7f {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			case '\b':
				b = append(b, '\\', 'b')
			case '\f':
				b = append(b, '\\', 'f')
			default:
				b = append(b, '\\', 'u', '0', '0', jsonHex[c>>4], jsonHex[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// JSON text must be valid UTF-8.
			b = append(b, s[start:i]...)
			b = append(b, `�`...)
			i++
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	e.buf = append(b, '"')
}

// obj writes the members of a JSON object and keeps track of the commas.
type jsonObj struct {
	e     *jsonEncoder
	first bool
}

func (e *jsonEncoder) object() *jsonObj {
	e.buf = append(e.buf, '{')
	return &jsonObj{e: e, first: true}
}

func (o *jsonObj) key(k string) {
	if !o.first {
		o.e.buf = append(o.e.buf, ',')
	}
	o.first = false
	o.e.buf = append(o.e.buf, '"')
	o.e.buf = append(o.e.buf, k...)
	o.e.buf = append(o.e.buf, '"', ':')
}

func (o *jsonObj) end() { o.e.buf = append(o.e.buf, '}') }

func (e *jsonEncoder) enter() error {
	e.depth++
	if e.depth > e.o.maxDepth {
		return codecError(StatusBadEncodingLimitsExceeded, "json", "", "nesting exceeds %d levels", e.o.maxDepth)
	}
	return nil
}

func (e *jsonEncoder) leave() { e.depth-- }

// value writes v. It never omits anything: omission of default values is
// decided by the structure that holds the field.
func (e *jsonEncoder) value(v reflect.Value) error {
	k := kindOf(v.Type())
	switch k {
	case kindInvalid:
		if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
			if v.IsNil() {
				e.null()
				return nil
			}
			return e.value(v.Elem())
		}
		return codecError(StatusBadEncodingError, "json", "", "unsupported type %s", v.Type())
	case kindEnum:
		return e.enum(v)
	case kindStructPtr:
		if v.IsNil() {
			e.null()
			return nil
		}
		return e.structure(v.Elem(), nil)
	case kindStruct:
		return e.structure(v, nil)
	case kindArray:
		if v.IsNil() {
			e.null()
			return nil
		}
		if err := e.enter(); err != nil {
			return err
		}
		defer e.leave()
		e.buf = append(e.buf, '[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			if err := e.value(v.Index(i)); err != nil {
				return err
			}
		}
		e.buf = append(e.buf, ']')
		return nil
	}
	return e.builtin(TypeID(k), v)
}

func (e *jsonEncoder) enum(v reflect.Value) error {
	var n int64
	if v.CanInt() {
		n = v.Int()
	} else {
		n = int64(v.Uint())
	}
	if e.symbolic() {
		if name, ok := codecTypes.enumInfo(v.Type()).symbol(n); ok {
			e.str(name + "_" + strconv.FormatInt(n, 10))
			return nil
		}
	}
	e.int(n)
	return nil
}

func (e *jsonEncoder) float(f float64, bits int) {
	switch {
	case math.IsNaN(f):
		e.raw(`"NaN"`)
	case math.IsInf(f, 1):
		e.raw(`"Infinity"`)
	case math.IsInf(f, -1):
		e.raw(`"-Infinity"`)
	default:
		e.raw(formatFloat(f, bits))
	}
}

func (e *jsonEncoder) builtin(typ TypeID, v reflect.Value) error {
	switch typ {
	case TypeIDBoolean:
		e.buf = strconv.AppendBool(e.buf, v.Bool())
	case TypeIDSByte, TypeIDInt16, TypeIDInt32:
		e.int(v.Int())
	case TypeIDByte, TypeIDUint16, TypeIDUint32:
		e.uint(v.Uint())
	case TypeIDInt64:
		e.str(strconv.FormatInt(v.Int(), 10))
	case TypeIDUint64:
		e.str(strconv.FormatUint(v.Uint(), 10))
	case TypeIDFloat:
		e.float(v.Float(), 32)
	case TypeIDDouble:
		e.float(v.Float(), 64)
	case TypeIDString:
		e.str(v.String())
	case TypeIDDateTime:
		e.str(formatDateTime(v.Interface().(time.Time)))
	case TypeIDByteString:
		if v.IsNil() {
			e.null()
		} else {
			e.buf = append(e.buf, '"')
			e.buf = base64.StdEncoding.AppendEncode(e.buf, v.Bytes())
			e.buf = append(e.buf, '"')
		}
	case TypeIDXMLElement:
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				e.null()
				return nil
			}
			v = v.Elem()
		}
		e.str(v.String())
	case TypeIDStatusCode:
		e.statusCode(StatusCode(v.Uint()))
	default:
		v = builtinPtr(v)
		if v.IsNil() {
			if typ == TypeIDGUID {
				e.str(guidString(zeroGUID()))
			} else {
				e.null()
			}
			return nil
		}
		if err := e.enter(); err != nil {
			return err
		}
		defer e.leave()
		switch x := v.Interface().(type) {
		case *GUID:
			e.str(guidString(x))
		case *NodeID:
			e.nodeID(x)
		case *ExpandedNodeID:
			e.expandedNodeID(x)
		case *QualifiedName:
			e.qualifiedName(x)
		case *LocalizedText:
			e.localizedText(x)
		case *ExtensionObject:
			return e.extensionObject(x)
		case *DataValue:
			return e.dataValue(x)
		case *Variant:
			return e.variant(x)
		case *DiagnosticInfo:
			return e.diagnosticInfo(x)
		}
	}
	return nil
}

// statusSymbol returns the name of a StatusCode in the specification. The
// info bits in the lower 16 bits are not part of the code that is looked up
// (Part 6 §5.4.2.12).
func statusSymbol(s StatusCode) (string, bool) {
	d, ok := StatusCodes[s&0xFFFF0000]
	return d.Symbol, ok && d.Symbol != ""
}

func (e *jsonEncoder) statusCode(s StatusCode) {
	if e.o.form == JSONLegacyReversible {
		e.uint(uint64(s))
		return
	}
	o := e.object()
	if s != StatusOK || e.o.form == JSONLegacyNonReversible {
		o.key("Code")
		e.uint(uint64(s))
	}
	if e.symbolic() && s != StatusOK {
		if sym, ok := statusSymbol(s); ok {
			o.key("Symbol")
			e.str(sym)
		}
	}
	o.end()
}

// legacyNodeID writes the members of the 1.04 NodeId object.
func (e *jsonEncoder) legacyNodeID(o *jsonObj, n *NodeID, nsURI string) {
	if n == nil {
		n = NewTwoByteNodeID(0)
	}
	switch n.Type() {
	case NodeIDTypeString:
		o.key("IdType")
		e.raw("1")
		o.key("Id")
		e.str(string(n.bid))
	case NodeIDTypeGUID:
		o.key("IdType")
		e.raw("2")
		o.key("Id")
		g := n.gid
		if g == nil {
			g = zeroGUID()
		}
		e.str(guidString(g))
	case NodeIDTypeByteString:
		o.key("IdType")
		e.raw("3")
		o.key("Id")
		e.str(base64.StdEncoding.EncodeToString(n.bid))
	default:
		o.key("Id")
		e.uint(uint64(n.nid))
	}
	e.legacyNamespace(o, "Namespace", n.ns, nsURI)
}

// legacyNamespace writes a namespace index, or the namespace URI where the
// 1.04 encoding asks for it: always for an ExpandedNodeId that carries one,
// and in the non-reversible form for every index above 1.
func (e *jsonEncoder) legacyNamespace(o *jsonObj, key string, ns uint16, uri string) {
	if uri == "" && e.o.form == JSONLegacyNonReversible && ns > 1 {
		uri, _ = e.o.namespaceURI(ns)
	}
	switch {
	case uri != "":
		o.key(key)
		e.str(uri)
	case ns != 0:
		o.key(key)
		e.uint(uint64(ns))
	}
}

func (e *jsonEncoder) nodeID(n *NodeID) {
	if !e.legacy() {
		e.str(e.o.formatNodeID(n))
		return
	}
	o := e.object()
	e.legacyNodeID(o, n, "")
	o.end()
}

func (e *jsonEncoder) expandedNodeID(x *ExpandedNodeID) {
	if !e.legacy() {
		e.str(e.o.formatExpandedNodeID(x))
		return
	}
	o := e.object()
	e.legacyNodeID(o, x.NodeID, x.NamespaceURI)
	if x.ServerIndex != 0 {
		o.key("ServerUri")
		if e.o.form == JSONLegacyNonReversible && int64(x.ServerIndex) < int64(len(e.o.servers)) {
			e.str(e.o.servers[x.ServerIndex])
		} else {
			e.uint(uint64(x.ServerIndex))
		}
	}
	o.end()
}

func (e *jsonEncoder) qualifiedName(q *QualifiedName) {
	if !e.legacy() {
		e.str(e.o.formatQualifiedName(q))
		return
	}
	o := e.object()
	o.key("Name")
	e.str(q.Name)
	e.legacyNamespace(o, "Uri", q.NamespaceIndex, "")
	o.end()
}

func (e *jsonEncoder) localizedText(l *LocalizedText) {
	if e.o.form == JSONLegacyNonReversible {
		e.str(l.Text)
		return
	}
	o := e.object()
	if l.Locale != "" {
		o.key("Locale")
		e.str(l.Locale)
	}
	if l.Text != "" {
		o.key("Text")
		e.str(l.Text)
	}
	o.end()
}

func (e *jsonEncoder) extensionObject(x *ExtensionObject) error {
	if x.Value == nil {
		e.null()
		return nil
	}
	keyType, keyEnc, keyBody := "UaTypeId", "UaEncoding", "UaBody"
	if e.legacy() {
		keyType, keyEnc, keyBody = "TypeId", "Encoding", "Body"
	}
	typeID := func(o *jsonObj, id *NodeID) {
		o.key(keyType)
		e.nodeID(id)
	}
	var wireID *NodeID
	if x.TypeID != nil {
		wireID = x.TypeID.NodeID
	}

	// Bodies that are not JSON: an XML element or an opaque binary blob.
	switch body := x.Value.(type) {
	case *XMLElement, XMLElement, []byte:
		o := e.object()
		typeID(o, wireID)
		o.encodedBody(keyEnc, keyBody, body)
		o.end()
		return nil
	}

	rv := reflect.ValueOf(x.Value)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			e.null()
			return nil
		}
		rv = rv.Elem()
	}
	var info *structInfo
	id := wireID
	if rv.Kind() == reflect.Struct && kindOf(rv.Type()) == kindStruct {
		info = codecTypes.structInfo(rv.Type())
		switch {
		case e.legacy() && info.jsonID != nil:
			id = info.jsonID // 1.04 identifies the body by its encoding node
		case info.dataTypeID != nil:
			id = info.dataTypeID
		}
	}

	if e.o.form == JSONLegacyNonReversible {
		return e.value(rv) // the body only
	}
	if info != nil && !e.legacy() {
		// 1.05: the structure is encoded in place, next to UaTypeId.
		return e.structure(rv, func(o *jsonObj) { typeID(o, id) })
	}
	o := e.object()
	typeID(o, id)
	o.key(keyBody)
	if err := e.value(rv); err != nil {
		return err
	}
	o.end()
	return nil
}

// encodedBody writes the encoding marker (1 = binary, 2 = XML) and the body
// of an ExtensionObject whose body is not a JSON structure.
func (o *jsonObj) encodedBody(encKey, bodyKey string, body interface{}) {
	e := o.e
	marker, text := "2", ""
	switch b := body.(type) {
	case []byte:
		marker, text = "1", base64.StdEncoding.EncodeToString(b)
	case *XMLElement:
		text = string(*b)
	case XMLElement:
		text = string(b)
	}
	o.key(encKey)
	e.raw(marker)
	o.key(bodyKey)
	e.str(text)
}

// variantMembers writes the members of a Variant into an open object. The
// 1.05 DataValue shares them with its own members.
func (e *jsonEncoder) variantMembers(o *jsonObj, m *Variant) error {
	if m == nil || m.Type() == TypeIDNull {
		return nil
	}
	keyType, keyValue := "UaType", "Value"
	if e.legacy() {
		keyType, keyValue = "Type", "Body"
	}
	o.key(keyType)
	e.uint(uint64(m.Type()))
	o.key(keyValue)
	if err := e.variantValue(m, false); err != nil {
		return err
	}
	if m.Has(VariantArrayDimensions) {
		o.key("Dimensions")
		e.buf = append(e.buf, '[')
		for i, d := range m.arrayDimensions {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			e.int(int64(d))
		}
		e.buf = append(e.buf, ']')
	}
	return nil
}

// variantValue writes the value of a Variant: a scalar, a flat array, or -
// in the non-reversible form - nested arrays for a matrix.
func (e *jsonEncoder) variantValue(m *Variant, nested bool) error {
	rv := reflect.ValueOf(m.value)
	if !m.Has(VariantArrayValues) {
		if !rv.IsValid() {
			e.null()
			return nil
		}
		return e.value(rv)
	}
	if nested {
		return e.nestedArray(rv)
	}
	e.buf = append(e.buf, '[')
	if rv.IsValid() {
		for i, el := range flattenVariant(rv, nil) {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			if err := e.value(el); err != nil {
				return err
			}
		}
	}
	e.buf = append(e.buf, ']')
	return nil
}

func (e *jsonEncoder) nestedArray(rv reflect.Value) error {
	if !rv.IsValid() {
		e.raw("[]")
		return nil
	}
	if rv.Kind() != reflect.Slice || rv.Type() == typeBytes {
		return e.value(rv)
	}
	if err := e.enter(); err != nil {
		return err
	}
	defer e.leave()
	e.buf = append(e.buf, '[')
	for i := 0; i < rv.Len(); i++ {
		if i > 0 {
			e.buf = append(e.buf, ',')
		}
		if err := e.nestedArray(rv.Index(i)); err != nil {
			return err
		}
	}
	e.buf = append(e.buf, ']')
	return nil
}

func (e *jsonEncoder) variant(m *Variant) error {
	if m.Type() == TypeIDNull {
		e.null()
		return nil
	}
	if e.o.form == JSONLegacyNonReversible {
		return e.variantValue(m, true)
	}
	o := e.object()
	if err := e.variantMembers(o, m); err != nil {
		return err
	}
	o.end()
	return nil
}

func (e *jsonEncoder) dataValue(d *DataValue) error {
	o := e.object()
	if d.Has(DataValueValue) && d.Value != nil && d.Value.Type() != TypeIDNull {
		if e.legacy() {
			o.key("Value")
			if err := e.variant(d.Value); err != nil {
				return err
			}
		} else if err := e.variantMembers(o, d.Value); err != nil {
			return err
		}
	}
	if d.Has(DataValueStatusCode) {
		o.key("Status")
		e.statusCode(d.Status)
	}
	if d.Has(DataValueSourceTimestamp) {
		o.key("SourceTimestamp")
		e.str(formatDateTime(d.SourceTimestamp))
	}
	if d.Has(DataValueSourcePicoseconds) {
		o.key("SourcePicoseconds")
		e.uint(uint64(d.SourcePicoseconds))
	}
	if d.Has(DataValueServerTimestamp) {
		o.key("ServerTimestamp")
		e.str(formatDateTime(d.ServerTimestamp))
	}
	if d.Has(DataValueServerPicoseconds) {
		o.key("ServerPicoseconds")
		e.uint(uint64(d.ServerPicoseconds))
	}
	o.end()
	return nil
}

func (e *jsonEncoder) diagnosticInfo(d *DiagnosticInfo) error {
	o := e.object()
	if d.Has(DiagnosticInfoSymbolicID) {
		o.key("SymbolicId")
		e.int(int64(d.SymbolicID))
	}
	if d.Has(DiagnosticInfoNamespaceURI) {
		o.key("NamespaceUri")
		e.int(int64(d.NamespaceURI))
	}
	if d.Has(DiagnosticInfoLocale) {
		o.key("Locale")
		e.int(int64(d.Locale))
	}
	if d.Has(DiagnosticInfoLocalizedText) {
		o.key("LocalizedText")
		e.int(int64(d.LocalizedText))
	}
	if d.Has(DiagnosticInfoAdditionalInfo) {
		o.key("AdditionalInfo")
		e.str(d.AdditionalInfo)
	}
	if d.Has(DiagnosticInfoInnerStatusCode) {
		o.key("InnerStatusCode")
		e.statusCode(d.InnerStatusCode)
	}
	if d.Has(DiagnosticInfoInnerDiagnosticInfo) && d.InnerDiagnosticInfo != nil {
		o.key("InnerDiagnosticInfo")
		if err := e.enter(); err != nil {
			return err
		}
		err := e.diagnosticInfo(d.InnerDiagnosticInfo)
		e.leave()
		if err != nil {
			return err
		}
	}
	o.end()
	return nil
}

// structure writes a structure as a JSON object. head, if set, writes
// members that precede the fields (the UaTypeId of an ExtensionObject).
func (e *jsonEncoder) structure(v reflect.Value, head func(*jsonObj)) error {
	if err := e.enter(); err != nil {
		return err
	}
	defer e.leave()
	info := codecTypes.structInfo(v.Type())
	o := e.object()
	if head != nil {
		head(o)
	}
	for i, name := range info.fields {
		f := v.Field(i)
		if e.o.form == JSONCompact && isDefaultValue(f) {
			continue
		}
		o.key(name)
		if err := e.value(f); err != nil {
			return err
		}
	}
	o.end()
	return nil
}

// isDefaultValue reports whether v holds the default value of its type, which
// the compact JSON encoding and the XML encoding leave out of structures.
// An empty but non-nil array or ByteString is not the default (null) value.
func isDefaultValue(v reflect.Value) bool {
	k := kindOf(v.Type())
	switch k {
	case kindInvalid:
		return v.IsZero()
	case kindEnum:
		return v.IsZero()
	case kindStructPtr:
		return v.IsNil() || isDefaultValue(v.Elem())
	case kindStruct:
		for i := 0; i < v.NumField(); i++ {
			if !isDefaultValue(v.Field(i)) {
				return false
			}
		}
		return true
	case kindArray:
		return v.IsNil()
	}
	switch TypeID(k) {
	case TypeIDDateTime:
		return isNullDateTime(v.Interface().(time.Time))
	case TypeIDByteString:
		return v.IsNil()
	case TypeIDXMLElement:
		if v.Kind() == reflect.Pointer {
			return v.IsNil() || v.Elem().Len() == 0
		}
		return v.Len() == 0
	case TypeIDFloat, TypeIDDouble:
		// -0 and NaN are not the default and must survive.
		return math.Float64bits(v.Float()) == 0
	default:
	}
	if v.Kind() != reflect.Pointer && v.Kind() != reflect.Struct {
		return v.IsZero()
	}
	v = builtinPtr(v)
	if v.IsNil() {
		return true
	}
	switch x := v.Interface().(type) {
	case *GUID:
		return isZeroGUID(x)
	case *NodeID:
		return isNullNodeID(x)
	case *ExpandedNodeID:
		return isNullExpandedNodeID(x)
	case *QualifiedName:
		return x.NamespaceIndex == 0 && x.Name == ""
	case *LocalizedText:
		return x.Locale == "" && x.Text == ""
	case *ExtensionObject:
		return x.Value == nil
	case *DataValue:
		return x.EncodingMask == 0
	case *Variant:
		return x.Type() == TypeIDNull
	case *DiagnosticInfo:
		return x.EncodingMask == 0
	}
	return false
}
