// SPDX-License-Identifier: MIT

package ua

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// XMLTypesNamespace is the XML namespace of the OPC UA XML DataEncoding
// (Part 6 §5.3). NodeSet2 files use it for the content of <Value> elements,
// usually with the prefix "uax".
const XMLTypesNamespace = "http://opcfoundation.org/UA/2008/02/Types.xsd"

const xmlSchemaInstanceNamespace = "http://www.w3.org/2001/XMLSchema-instance"

// EncodeXML encodes v in the OPC UA XML DataEncoding (Part 6 §5.3). It
// accepts the same values as [EncodeJSON].
//
// The result is a single element named after the type of v (see
// [WithXMLRootName]) that declares [XMLTypesNamespace] as its default
// namespace:
//
//	<Variant xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd"><Value><Int32>42</Int32></Value></Variant>
//
// Structure fields holding a null value (a nil pointer, array or ByteString)
// are left out, as the schema allows; all other fields are written in the
// order of the structure definition. An ExtensionObject body is identified by
// the NodeId of the DefaultXml encoding node of its DataType.
func EncodeXML(v interface{}, opts ...CodecOption) ([]byte, error) {
	e := &xmlEncoder{o: newCodecOptions(opts)}
	rv := reflect.ValueOf(v)
	name := e.o.xmlRoot
	if name == "" {
		name = "Null"
		if rv.IsValid() {
			t := rv.Type()
			for t.Kind() == reflect.Pointer && kindOf(t) == kindInvalid {
				t = t.Elem() // a pointer to a value is encoded as the value
			}
			name = typeName(t)
		}
	}
	root := &xmlElem{name: name}
	if rv.IsValid() {
		if err := e.content(root, rv); err != nil {
			return nil, err
		}
	}
	if !e.o.xmlNoNS {
		root.attrs = append(root.attrs, [2]string{"xmlns", XMLTypesNamespace})
	}
	if e.usedNil {
		root.attrs = append(root.attrs, [2]string{"xmlns:xsi", xmlSchemaInstanceNamespace})
	}
	var buf bytes.Buffer
	root.write(&buf, e.o.indent, 0)
	return buf.Bytes(), nil
}

// xmlElem is the output tree. Building it first keeps indentation and the
// late xmlns:xsi declaration simple.
type xmlElem struct {
	name  string
	attrs [][2]string
	text  string
	raw   bool // text is markup and must not be escaped
	kids  []*xmlElem
}

func (x *xmlElem) add(name string) *xmlElem {
	k := &xmlElem{name: name}
	x.kids = append(x.kids, k)
	return k
}

func (x *xmlElem) addText(name, text string) {
	x.add(name).text = text
}

func (x *xmlElem) write(b *bytes.Buffer, indent string, level int) {
	pad := func(n int) {
		if indent == "" {
			return
		}
		b.WriteByte('\n')
		for i := 0; i < n; i++ {
			b.WriteString(indent)
		}
	}
	b.WriteByte('<')
	b.WriteString(x.name)
	for _, a := range x.attrs {
		b.WriteByte(' ')
		b.WriteString(a[0])
		b.WriteString(`="`)
		_ = xml.EscapeText(b, []byte(a[1]))
		b.WriteByte('"')
	}
	b.WriteByte('>')
	if x.raw {
		b.WriteString(x.text)
	} else if x.text != "" {
		_ = xml.EscapeText(b, []byte(x.text))
	}
	for _, k := range x.kids {
		pad(level + 1)
		k.write(b, indent, level+1)
	}
	if len(x.kids) > 0 {
		pad(level)
	}
	b.WriteString("</")
	b.WriteString(x.name)
	b.WriteByte('>')
}

type xmlEncoder struct {
	o       *codecOptions
	depth   int
	usedNil bool
}

func (e *xmlEncoder) enter() error {
	e.depth++
	if e.depth > e.o.maxDepth {
		return codecError(StatusBadEncodingLimitsExceeded, "xml", "", "nesting exceeds %d levels", e.o.maxDepth)
	}
	return nil
}

func (e *xmlEncoder) setNil(x *xmlElem) {
	x.attrs = append(x.attrs, [2]string{"xsi:nil", "true"})
	e.usedNil = true
}

// content fills the element x with the encoding of v.
func (e *xmlEncoder) content(x *xmlElem, v reflect.Value) error {
	if err := e.enter(); err != nil {
		return err
	}
	defer func() { e.depth-- }()

	k := kindOf(v.Type())
	switch k {
	case kindInvalid:
		if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && !v.IsNil() {
			return e.content(x, v.Elem())
		}
		if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
			return nil
		}
		return codecError(StatusBadEncodingError, "xml", "", "unsupported type %s", v.Type())
	case kindEnum:
		var n int64
		if v.CanInt() {
			n = v.Int()
		} else {
			n = int64(v.Uint())
		}
		x.text = strconv.FormatInt(n, 10)
		if name, ok := codecTypes.enumInfo(v.Type()).symbol(n); ok {
			x.text = name + "_" + x.text
		}
		return nil
	case kindStructPtr:
		// A structure has no null in XML (an array element or the
		// document root always decodes to a value), so a nil pointer
		// is written as the zero structure, as the binary encoding does.
		if v.IsNil() {
			return e.structure(x, reflect.New(v.Type().Elem()).Elem())
		}
		return e.structure(x, v.Elem())
	case kindStruct:
		return e.structure(x, v)
	case kindArray:
		if v.IsNil() {
			e.setNil(x)
			return nil
		}
		name := typeName(v.Type().Elem())
		for i := 0; i < v.Len(); i++ {
			if err := e.content(x.add(name), v.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}
	return e.builtin(x, TypeID(k), v)
}

func xmlFloat(f float64, bits int) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "INF"
	case math.IsInf(f, -1):
		return "-INF"
	}
	return formatFloat(f, bits)
}

func (e *xmlEncoder) builtin(x *xmlElem, typ TypeID, v reflect.Value) error {
	switch typ {
	case TypeIDBoolean:
		x.text = strconv.FormatBool(v.Bool())
	case TypeIDSByte, TypeIDInt16, TypeIDInt32, TypeIDInt64:
		x.text = strconv.FormatInt(v.Int(), 10)
	case TypeIDByte, TypeIDUint16, TypeIDUint32, TypeIDUint64:
		x.text = strconv.FormatUint(v.Uint(), 10)
	case TypeIDFloat:
		x.text = xmlFloat(v.Float(), 32)
	case TypeIDDouble:
		x.text = xmlFloat(v.Float(), 64)
	case TypeIDString:
		x.text = v.String()
	case TypeIDDateTime:
		x.text = formatDateTime(v.Interface().(time.Time))
	case TypeIDByteString:
		if v.IsNil() {
			e.setNil(x)
		} else {
			x.text = base64.StdEncoding.EncodeToString(v.Bytes())
		}
	case TypeIDXMLElement:
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil
			}
			v = v.Elem()
		}
		x.text, x.raw = v.String(), true
		if !e.o.xmlNoNS {
			x.text = xmlFragmentOutsideDefaultNamespace(x.text)
		}
	case TypeIDStatusCode:
		x.addText("Code", strconv.FormatUint(v.Uint(), 10))
	default:
		v = builtinPtr(v)
		if v.IsNil() {
			if typ == TypeIDGUID {
				x.addText("String", guidString(zeroGUID()))
			}
			return nil
		}
		switch p := v.Interface().(type) {
		case *GUID:
			x.addText("String", guidString(p))
		case *NodeID:
			x.addText("Identifier", e.o.formatNodeID(p))
		case *ExpandedNodeID:
			x.addText("Identifier", e.o.formatExpandedNodeID(p))
		case *QualifiedName:
			x.addText("NamespaceIndex", strconv.FormatUint(uint64(p.NamespaceIndex), 10))
			x.addText("Name", p.Name)
		case *LocalizedText:
			if p.Locale != "" {
				x.addText("Locale", p.Locale)
			}
			if p.Text != "" {
				x.addText("Text", p.Text)
			}
		case *ExtensionObject:
			return e.extensionObject(x, p)
		case *DataValue:
			return e.dataValue(x, p)
		case *Variant:
			return e.variant(x, p)
		case *DiagnosticInfo:
			return e.diagnosticInfo(x, p)
		}
	}
	return nil
}

func (e *xmlEncoder) extensionObject(x *xmlElem, p *ExtensionObject) error {
	if p.Value == nil {
		return nil
	}
	var wireID *NodeID
	if p.TypeID != nil {
		wireID = p.TypeID.NodeID
	}
	typeID := func(id *NodeID) {
		x.add("TypeId").addText("Identifier", e.o.formatNodeID(id))
	}
	switch body := p.Value.(type) {
	case []byte:
		typeID(wireID)
		x.add("Body").addText("ByteString", base64.StdEncoding.EncodeToString(body))
		return nil
	case XMLElement:
		typeID(wireID)
		b := x.add("Body")
		b.text, b.raw = string(body), true
		return nil
	case *XMLElement:
		typeID(wireID)
		b := x.add("Body")
		b.text, b.raw = string(*body), true
		return nil
	}

	rv := reflect.ValueOf(p.Value)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	id := wireID
	name := ""
	if kindOf(rv.Type()) == kindStruct {
		// The type id and the element name come from one description of
		// the type: RegisterDataTypeInfo may replace it at any time, and a
		// second lookup could pair the id of one with the name of the other.
		info := codecTypes.structInfo(rv.Type())
		switch {
		case info.xmlID != nil:
			id = info.xmlID
		case info.dataTypeID != nil:
			id = info.dataTypeID
		}
		name = info.name
	} else {
		name = typeName(rv.Type())
	}
	typeID(id)
	return e.content(x.add("Body").add(name), rv)
}

func (e *xmlEncoder) dataValue(x *xmlElem, d *DataValue) error {
	if d.Has(DataValueValue) && d.Value != nil && d.Value.Type() != TypeIDNull {
		if err := e.variant(x.add("Value"), d.Value); err != nil {
			return err
		}
	}
	if d.Has(DataValueStatusCode) {
		x.add("StatusCode").addText("Code", strconv.FormatUint(uint64(d.Status), 10))
	}
	if d.Has(DataValueSourceTimestamp) {
		x.addText("SourceTimestamp", formatDateTime(d.SourceTimestamp))
	}
	if d.Has(DataValueSourcePicoseconds) {
		x.addText("SourcePicoseconds", strconv.FormatUint(uint64(d.SourcePicoseconds), 10))
	}
	if d.Has(DataValueServerTimestamp) {
		x.addText("ServerTimestamp", formatDateTime(d.ServerTimestamp))
	}
	if d.Has(DataValueServerPicoseconds) {
		x.addText("ServerPicoseconds", strconv.FormatUint(uint64(d.ServerPicoseconds), 10))
	}
	return nil
}

// variant writes <Value><Type>..</Type></Value>, <Value><ListOfType>.. or,
// for a matrix, <Value><Matrix><Dimensions>..<Elements>..
func (e *xmlEncoder) variant(x *xmlElem, m *Variant) error {
	typ := m.Type()
	if typ == TypeIDNull {
		return nil
	}
	val := x.add("Value")
	name := builtinTypeNames[typ]
	rv := reflect.ValueOf(m.value)
	if !m.Has(VariantArrayValues) {
		if !rv.IsValid() {
			return nil
		}
		return e.content(val.add(name), rv)
	}
	elements := func(parent *xmlElem) error {
		if !rv.IsValid() {
			return nil
		}
		for _, el := range flattenVariant(rv, nil) {
			if err := e.content(parent.add(name), el); err != nil {
				return err
			}
		}
		return nil
	}
	if m.Has(VariantArrayDimensions) {
		matrix := val.add("Matrix")
		dims := matrix.add("Dimensions")
		for _, d := range m.arrayDimensions {
			dims.addText("Int32", strconv.FormatInt(int64(d), 10))
		}
		return elements(matrix.add("Elements"))
	}
	list := val.add("ListOf" + name)
	if m.arrayLength < 0 || !rv.IsValid() || (rv.Kind() == reflect.Slice && rv.IsNil()) {
		e.setNil(list)
		return nil
	}
	return elements(list)
}

func (e *xmlEncoder) diagnosticInfo(x *xmlElem, d *DiagnosticInfo) error {
	i32 := func(name string, v int32) { x.addText(name, strconv.FormatInt(int64(v), 10)) }
	if d.Has(DiagnosticInfoSymbolicID) {
		i32("SymbolicId", d.SymbolicID)
	}
	if d.Has(DiagnosticInfoNamespaceURI) {
		i32("NamespaceUri", d.NamespaceURI)
	}
	if d.Has(DiagnosticInfoLocale) {
		i32("Locale", d.Locale)
	}
	if d.Has(DiagnosticInfoLocalizedText) {
		i32("LocalizedText", d.LocalizedText)
	}
	if d.Has(DiagnosticInfoAdditionalInfo) {
		x.addText("AdditionalInfo", d.AdditionalInfo)
	}
	if d.Has(DiagnosticInfoInnerStatusCode) {
		x.add("InnerStatusCode").addText("Code", strconv.FormatUint(uint64(d.InnerStatusCode), 10))
	}
	if d.Has(DiagnosticInfoInnerDiagnosticInfo) && d.InnerDiagnosticInfo != nil {
		if err := e.enter(); err != nil {
			return err
		}
		defer func() { e.depth-- }()
		return e.diagnosticInfo(x.add("InnerDiagnosticInfo"), d.InnerDiagnosticInfo)
	}
	return nil
}

func (e *xmlEncoder) structure(x *xmlElem, v reflect.Value) error {
	info := codecTypes.structInfo(v.Type())
	for i, name := range info.fields {
		f := v.Field(i)
		if isNullValue(f) {
			continue
		}
		if err := e.content(x.add(name), f); err != nil {
			return err
		}
	}
	return nil
}

// isNullValue reports whether a structure field holds a null: a nil pointer,
// array or ByteString. Such fields are left out of XML structures.
func isNullValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}

// xmlFragmentOutsideDefaultNamespace prepares the content of an XmlElement
// for a document that declares [XMLTypesNamespace] as its default namespace.
// Written as it is, an unprefixed element of the fragment would inherit that
// declaration and silently become an element of the OPC UA types namespace
// for every namespace-aware reader. Each top-level element of the fragment
// that has no prefix and no default namespace declaration of its own gets
// xmlns="", which keeps it (and its unprefixed descendants) in no namespace.
// [DecodeXML] removes the declaration again. A fragment that is not
// well-formed is returned unchanged.
func xmlFragmentOutsideDefaultNamespace(fragment string) string {
	if !strings.Contains(fragment, "<") {
		return fragment
	}
	dec := xml.NewDecoder(strings.NewReader(fragment))
	dec.Strict = true
	var (
		inserts []int // offsets just behind the names of the elements to fix
		depth   int
		prev    int64
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fragment
		}
		off := dec.InputOffset()
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if at, ok := xmlUndeclaredNameEnd(fragment[prev:off], t); ok {
					inserts = append(inserts, int(prev)+at)
				}
			}
			depth++
		case xml.EndElement:
			depth--
		}
		prev = off
	}
	if depth != 0 || len(inserts) == 0 {
		return fragment
	}
	var b strings.Builder
	b.Grow(len(fragment) + len(inserts)*len(xmlNoNamespaceAttr))
	last := 0
	for _, at := range inserts {
		b.WriteString(fragment[last:at])
		b.WriteString(xmlNoNamespaceAttr)
		last = at
	}
	b.WriteString(fragment[last:])
	return b.String()
}

// xmlNoNamespaceAttr undeclares the default namespace.
const xmlNoNamespaceAttr = ` xmlns=""`

// xmlUndeclaredNameEnd returns the offset behind the element name in the
// start tag, if the element is unprefixed and declares no default namespace.
func xmlUndeclaredNameEnd(tag string, t xml.StartElement) (int, bool) {
	for _, a := range t.Attr {
		if a.Name.Space == "" && a.Name.Local == "xmlns" {
			return 0, false
		}
	}
	if !strings.HasPrefix(tag, "<") {
		return 0, false
	}
	end := 1
	for end < len(tag) && !strings.ContainsRune(" \t\r\n/>", rune(tag[end])) {
		end++
	}
	if name := tag[1:end]; name == "" || strings.Contains(name, ":") {
		return 0, false
	}
	return end, true
}
