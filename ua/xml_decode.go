// SPDX-License-Identifier: MIT

package ua

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

// DecodeXML decodes an element in the OPC UA XML DataEncoding (Part 6 §5.3)
// into v, which must be a non-nil pointer as for [DecodeJSON].
//
// The name of the outermost element is not checked, and elements are matched
// by their local name whatever their namespace prefix, so the content of a
// NodeSet2 <Value> element can be handed over as it is:
//
//	var v ua.Variant
//	err := ua.DecodeXML([]byte(`<Value><uax:Int32>42</uax:Int32></Value>`), &v)
//
// Both the bare form above and the form [EncodeXML] writes
// (<Variant><Value><Int32>..) are accepted for a Variant.
//
// Unknown child elements of a structure are ignored and missing ones keep
// their default value. An ExtensionObject whose type is not registered is
// kept with its body as an [XMLElement]. Documents nested deeper than the
// configured limit (see [WithMaxDepth]) are rejected. DTDs are not processed
// and entities other than the five predefined ones are errors.
func DecodeXML(data []byte, v interface{}, opts ...CodecOption) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return codecError(StatusBadDecodingError, "xml", "", "DecodeXML needs a non-nil pointer, got %T", v)
	}
	o := newCodecOptions(opts)
	root, err := parseXML(data, o.maxDepth)
	if err != nil {
		return err
	}
	d := &xmlDecoder{o: o}
	return decodeTop(rv, func(dst reflect.Value) error { return d.value(root, dst) })
}

// xmlNode is an element of the parsed document.
type xmlNode struct {
	name  string // local name
	text  string // character data of an element without child elements
	inner string // raw content, used for XmlElement values
	null  bool   // xsi:nil="true"
	kids  []*xmlNode
}

func (n *xmlNode) child(name string) *xmlNode {
	if n == nil {
		return nil
	}
	for _, k := range n.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

func parseXML(data []byte, maxDepth int) (*xmlNode, error) {
	fail := func(off int64, format string, args ...interface{}) error {
		return fmt.Errorf("ua: xml: offset %d: %s: %w", off, fmt.Sprintf(format, args...), StatusBadDecodingError)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	// No charset conversion and no external entities: anything but UTF-8
	// and the predefined entities is an error.
	dec.CharsetReader = func(label string, _ io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("unsupported charset %q", label)
	}

	type frame struct {
		node  *xmlNode
		start int64
		text  strings.Builder
	}
	var (
		stack []*frame
		root  *xmlNode
		prev  int64
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fail(dec.InputOffset(), "%v", err)
		}
		off := dec.InputOffset()
		switch t := tok.(type) {
		case xml.StartElement:
			if root != nil && len(stack) == 0 {
				return nil, fail(off, "more than one root element")
			}
			if len(stack) >= maxDepth {
				return nil, fmt.Errorf("ua: xml: offset %d: nesting exceeds %d levels: %w", off, maxDepth, StatusBadEncodingLimitsExceeded)
			}
			n := &xmlNode{name: t.Name.Local}
			for _, a := range t.Attr {
				if a.Name.Local == "nil" && (a.Value == "true" || a.Value == "1") {
					n.null = true
				}
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1].node
				p.kids = append(p.kids, n)
			} else {
				root = n
			}
			stack = append(stack, &frame{node: n, start: off})
		case xml.EndElement:
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(f.node.kids) == 0 {
				f.node.text = f.text.String()
			}
			if prev >= f.start && prev <= int64(len(data)) {
				f.node.inner = string(data[f.start:prev])
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}
		}
		prev = off
	}
	if root == nil {
		return nil, fail(int64(len(data)), "no element found")
	}
	return root, nil
}

type xmlDecoder struct {
	o *codecOptions
}

func (d *xmlDecoder) errorf(n *xmlNode, format string, args ...interface{}) error {
	return codecError(StatusBadDecodingError, "xml", "<"+n.name+">", format, args...)
}

func (d *xmlDecoder) value(n *xmlNode, dst reflect.Value) error {
	t := dst.Type()
	k := kindOf(t)
	switch k {
	case kindInvalid:
		return d.errorf(n, "unsupported type %s", t)
	case kindEnum:
		v, ok := parseEnum(n.text, codecTypes.enumInfo(t))
		if !ok {
			return d.errorf(n, "%q is not a value of %s", n.text, t)
		}
		if dst.CanInt() {
			if dst.OverflowInt(v) {
				return d.errorf(n, "%d overflows %s", v, t)
			}
			dst.SetInt(v)
		} else {
			if v < 0 || dst.OverflowUint(uint64(v)) {
				return d.errorf(n, "%d overflows %s", v, t)
			}
			dst.SetUint(uint64(v))
		}
		return nil
	case kindStructPtr:
		if n.null {
			dst.Set(zeroElement(t))
			return nil
		}
		p := reflect.New(t.Elem())
		if err := d.structure(n, p.Elem()); err != nil {
			return err
		}
		dst.Set(p)
		return nil
	case kindStruct:
		return d.structure(n, dst)
	case kindArray:
		if n.null {
			dst.SetZero()
			return nil
		}
		s := reflect.MakeSlice(t, len(n.kids), len(n.kids))
		for i, kid := range n.kids {
			if err := d.value(kid, s.Index(i)); err != nil {
				return err
			}
		}
		dst.Set(s)
		return nil
	}
	return d.builtin(TypeID(k), n, dst)
}

func (d *xmlDecoder) builtin(typ TypeID, n *xmlNode, dst reflect.Value) error {
	name := builtinTypeNames[typ]
	text := strings.TrimSpace(n.text)
	bad := func() error { return d.errorf(n, "%q is not a valid %s", n.text, name) }
	switch typ {
	case TypeIDBoolean:
		switch text {
		case "true", "1":
			dst.SetBool(true)
		case "false", "0":
			dst.SetBool(false)
		default:
			return bad()
		}
	case TypeIDSByte, TypeIDInt16, TypeIDInt32, TypeIDInt64:
		v, err := strconv.ParseInt(text, 10, dst.Type().Bits())
		if err != nil {
			return bad()
		}
		dst.SetInt(v)
	case TypeIDByte, TypeIDUint16, TypeIDUint32, TypeIDUint64:
		v, err := strconv.ParseUint(text, 10, dst.Type().Bits())
		if err != nil {
			return bad()
		}
		dst.SetUint(v)
	case TypeIDFloat, TypeIDDouble:
		f, ok := parseFloatText(text, dst.Type().Bits())
		if !ok {
			return bad()
		}
		dst.SetFloat(f)
	case TypeIDString:
		dst.SetString(n.text)
	case TypeIDDateTime:
		t, ok := parseDateTime(text)
		if !ok {
			return bad()
		}
		dst.Set(reflect.ValueOf(t))
	case TypeIDByteString:
		if n.null {
			dst.SetZero()
			return nil
		}
		b, err := decodeBase64Text(n.text)
		if err != nil {
			return d.errorf(n, "invalid base64 in ByteString")
		}
		dst.SetBytes(b)
	case TypeIDXMLElement:
		inner := xmlFragmentWithoutNamespaceReset(n.inner)
		if dst.Kind() == reflect.Pointer {
			x := XMLElement(inner)
			dst.Set(reflect.ValueOf(&x))
		} else {
			dst.SetString(inner)
		}
	case TypeIDStatusCode:
		sc, err := d.statusCode(n)
		if err != nil {
			return err
		}
		dst.SetUint(uint64(sc))
	case TypeIDGUID:
		g := zeroGUID()
		if s := n.child("String"); s != nil {
			if g = parseGUID(s.text); g == nil {
				return d.errorf(n, "%q is not a valid Guid", s.text)
			}
		} else if text != "" {
			if g = parseGUID(text); g == nil {
				return bad()
			}
		}
		setBuiltin(dst, g)
	case TypeIDNodeID:
		setBuiltin(dst, d.nodeID(n))
	case TypeIDExpandedNodeID:
		x := NewTwoByteExpandedNodeID(0)
		if id := n.child("Identifier"); id != nil {
			x = d.identifier(id.text)
		}
		setBuiltin(dst, x)
	case TypeIDQualifiedName:
		q := &QualifiedName{}
		if ns := n.child("NamespaceIndex"); ns != nil {
			v, err := strconv.ParseUint(strings.TrimSpace(ns.text), 10, 16)
			if err != nil {
				return d.errorf(ns, "%q is not a valid namespace index", ns.text)
			}
			q.NamespaceIndex = uint16(v)
		}
		if nm := n.child("Name"); nm != nil {
			q.Name = nm.text
		}
		setBuiltin(dst, q)
	case TypeIDLocalizedText:
		l := &LocalizedText{}
		if c := n.child("Locale"); c != nil {
			l.Locale = c.text
		}
		if c := n.child("Text"); c != nil {
			l.Text = c.text
		}
		l.UpdateMask()
		setBuiltin(dst, l)
	case TypeIDExtensionObject:
		x, err := d.extensionObject(n)
		if err != nil {
			return err
		}
		setBuiltin(dst, x)
	case TypeIDDataValue:
		x, err := d.dataValue(n)
		if err != nil {
			return err
		}
		setBuiltin(dst, x)
	case TypeIDVariant:
		x, err := d.variant(n)
		if err != nil {
			return err
		}
		setBuiltin(dst, x)
	case TypeIDDiagnosticInfo:
		x, err := d.diagnosticInfo(n)
		if err != nil {
			return err
		}
		setBuiltin(dst, x)
	default:
		return d.errorf(n, "unsupported built-in type %d", typ)
	}
	return nil
}

// decodeBase64Text decodes xs:base64Binary, which may contain white space.
func decodeBase64Text(s string) ([]byte, error) {
	if strings.ContainsAny(s, " \t\r\n") {
		s = strings.Join(strings.Fields(s), "")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if b == nil {
		b = []byte{}
	}
	return b, nil
}

func (d *xmlDecoder) nodeID(n *xmlNode) *NodeID {
	id := n.child("Identifier")
	if id == nil {
		return NewTwoByteNodeID(0)
	}
	e := d.identifier(id.text)
	if e.NamespaceURI != "" || e.ServerIndex != 0 {
		return NewStringNodeID(0, id.text)
	}
	return e.NodeID
}

// identifier parses the text of an <Identifier> element. White space is
// significant in String identifiers, so the surrounding white space a pretty
// printer may have added is only dropped if the text is not a NodeId as is.
func (d *xmlDecoder) identifier(text string) *ExpandedNodeID {
	if e, ok := d.o.parseExpandedNodeID(text); ok {
		return e
	}
	if e, ok := d.o.parseExpandedNodeID(strings.TrimSpace(text)); ok {
		return e
	}
	return &ExpandedNodeID{NodeID: NewStringNodeID(0, text)}
}

func (d *xmlDecoder) statusCode(n *xmlNode) (StatusCode, error) {
	text := n.text
	if c := n.child("Code"); c != nil {
		text = c.text
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return StatusOK, nil
	}
	v, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, d.errorf(n, "%q is not a valid StatusCode", text)
	}
	return StatusCode(v), nil
}

func (d *xmlDecoder) extensionObject(n *xmlNode) (*ExtensionObject, error) {
	body := n.child("Body")
	if body == nil || len(body.kids) == 0 {
		return NewExtensionObject(nil), nil
	}
	if len(body.kids) != 1 {
		return nil, d.errorf(body, "an ExtensionObject body holds exactly one element")
	}
	typeID := NewTwoByteNodeID(0)
	if t := n.child("TypeId"); t != nil {
		typeID = d.nodeID(t)
	}
	content := body.kids[0]
	if content.name == "ByteString" {
		raw, err := decodeBase64Text(content.text)
		if err != nil {
			return nil, d.errorf(content, "invalid base64 in ExtensionObject body")
		}
		return binaryExtensionObject(typeID, raw)
	}
	v := codecTypes.newByTypeID(typeID)
	if v == nil {
		// Unknown type: keep the body as it is.
		x := XMLElement(body.inner)
		return &ExtensionObject{EncodingMask: ExtensionObjectXML, TypeID: &ExpandedNodeID{NodeID: typeID}, Value: &x}, nil
	}
	if err := d.value(content, reflect.ValueOf(v).Elem()); err != nil {
		return nil, err
	}
	return NewExtensionObject(v), nil
}

func (d *xmlDecoder) dataValue(n *xmlNode) (*DataValue, error) {
	dv := &DataValue{}
	for _, kid := range n.kids {
		switch kid.name {
		case "Value":
			m, err := d.variant(kid)
			if err != nil {
				return nil, err
			}
			if m.Type() != TypeIDNull {
				dv.Value = m
				dv.EncodingMask |= DataValueValue
			}
		case "StatusCode":
			sc, err := d.statusCode(kid)
			if err != nil {
				return nil, err
			}
			dv.Status = sc
			dv.EncodingMask |= DataValueStatusCode
		case "SourceTimestamp", "ServerTimestamp":
			t, ok := parseDateTime(kid.text)
			if !ok {
				return nil, d.errorf(kid, "%q is not a valid DateTime", kid.text)
			}
			if kid.name == "SourceTimestamp" {
				dv.SourceTimestamp = t
				dv.EncodingMask |= DataValueSourceTimestamp
			} else {
				dv.ServerTimestamp = t
				dv.EncodingMask |= DataValueServerTimestamp
			}
		case "SourcePicoseconds", "ServerPicoseconds":
			v, err := strconv.ParseUint(strings.TrimSpace(kid.text), 10, 16)
			if err != nil {
				return nil, d.errorf(kid, "%q is not a valid UInt16", kid.text)
			}
			if kid.name == "SourcePicoseconds" {
				dv.SourcePicoseconds = uint16(v)
				dv.EncodingMask |= DataValueSourcePicoseconds
			} else {
				dv.ServerPicoseconds = uint16(v)
				dv.EncodingMask |= DataValueServerPicoseconds
			}
		}
	}
	return dv, nil
}

// variant decodes the content of an element of type Variant. The value sits
// in a <Value> child; a NodeSet2 <Value> element is that child itself.
func (d *xmlDecoder) variant(n *xmlNode) (*Variant, error) {
	if len(n.kids) == 1 && n.kids[0].name == "Value" {
		n = n.kids[0]
	}
	switch len(n.kids) {
	case 0:
		return &Variant{}, nil
	case 1:
	default:
		return nil, d.errorf(n, "a Variant holds exactly one value element, got %d", len(n.kids))
	}
	val := n.kids[0]

	if val.name == "Matrix" {
		dimsNode, elems := val.child("Dimensions"), val.child("Elements")
		if dimsNode == nil || elems == nil {
			return nil, d.errorf(val, "a Matrix needs Dimensions and Elements")
		}
		dims := make([]int32, len(dimsNode.kids))
		for i, k := range dimsNode.kids {
			v, err := strconv.ParseInt(strings.TrimSpace(k.text), 10, 32)
			if err != nil {
				return nil, d.errorf(k, "%q is not a valid dimension", k.text)
			}
			dims[i] = int32(v)
		}
		if len(elems.kids) == 0 {
			return nil, d.errorf(val, "cannot determine the type of an empty Matrix")
		}
		return d.variantArray(elems, elems.kids[0].name, dims)
	}
	if strings.HasPrefix(val.name, "ListOf") {
		return d.variantArray(val, strings.TrimPrefix(val.name, "ListOf"), nil)
	}

	typ, ok := d.variantType(val.name)
	if !ok {
		return nil, d.errorf(val, "unknown Variant type")
	}
	et := variantTypeIDToType[typ]
	out := reflect.New(et).Elem()
	if err := d.variantElement(val, typ, out); err != nil {
		return nil, err
	}
	return &Variant{mask: byte(typ), value: out.Interface()}, nil
}

// variantType maps an element name to the built-in type that carries it.
// A structure may appear under its own name, without the ExtensionObject
// wrapper; open62541 accepts that as well.
func (d *xmlDecoder) variantType(name string) (TypeID, bool) {
	if typ, ok := builtinTypeByName(name); ok {
		return typ, true
	}
	return TypeIDExtensionObject, codecTypes.structByName(name) != nil
}

func (d *xmlDecoder) variantElement(n *xmlNode, typ TypeID, dst reflect.Value) error {
	if typ == TypeIDExtensionObject && n.name != "ExtensionObject" {
		info := codecTypes.structByName(n.name)
		if info == nil {
			return d.errorf(n, "unknown structure")
		}
		p := reflect.New(info.typ)
		if err := d.structure(n, p.Elem()); err != nil {
			return err
		}
		dst.Set(reflect.ValueOf(NewExtensionObject(p.Interface())))
		return nil
	}
	if n.null {
		dst.Set(zeroBuiltin(dst.Type()))
		return nil
	}
	return d.value(n, dst)
}

func (d *xmlDecoder) variantArray(list *xmlNode, elemName string, dims []int32) (*Variant, error) {
	typ, ok := d.variantType(elemName)
	if !ok {
		return nil, d.errorf(list, "unknown Variant type")
	}
	st, ok := variantSliceType(typ)
	if !ok {
		return nil, d.errorf(list, "unknown Variant type")
	}
	if list.null && dims == nil {
		m := &Variant{}
		if err := m.set(reflect.Zero(st).Interface()); err != nil {
			return nil, err
		}
		return m, nil
	}
	if len(list.kids) > d.o.maxArray {
		return nil, codecError(StatusBadEncodingLimitsExceeded, "xml", "<"+list.name+">", "array of %d elements exceeds the limit of %d", len(list.kids), d.o.maxArray)
	}
	vals := reflect.MakeSlice(st, len(list.kids), len(list.kids))
	for i, k := range list.kids {
		if err := d.variantElement(k, typ, vals.Index(i)); err != nil {
			return nil, err
		}
	}
	m, err := newArrayVariant(typ, vals, dims)
	if err != nil {
		return nil, d.errorf(list, "%v", err)
	}
	return m, nil
}

func (d *xmlDecoder) diagnosticInfo(n *xmlNode) (*DiagnosticInfo, error) {
	di := &DiagnosticInfo{}
	for _, kid := range n.kids {
		var i32 *int32
		var mask uint8
		switch kid.name {
		case "SymbolicId":
			i32, mask = &di.SymbolicID, DiagnosticInfoSymbolicID
		case "NamespaceUri":
			i32, mask = &di.NamespaceURI, DiagnosticInfoNamespaceURI
		case "Locale":
			i32, mask = &di.Locale, DiagnosticInfoLocale
		case "LocalizedText":
			i32, mask = &di.LocalizedText, DiagnosticInfoLocalizedText
		case "AdditionalInfo":
			di.AdditionalInfo = kid.text
			di.EncodingMask |= DiagnosticInfoAdditionalInfo
		case "InnerStatusCode":
			sc, err := d.statusCode(kid)
			if err != nil {
				return nil, err
			}
			di.InnerStatusCode = sc
			di.EncodingMask |= DiagnosticInfoInnerStatusCode
		case "InnerDiagnosticInfo":
			inner, err := d.diagnosticInfo(kid)
			if err != nil {
				return nil, err
			}
			di.InnerDiagnosticInfo = inner
			di.EncodingMask |= DiagnosticInfoInnerDiagnosticInfo
		}
		if i32 != nil {
			v, err := strconv.ParseInt(strings.TrimSpace(kid.text), 10, 32)
			if err != nil {
				return nil, d.errorf(kid, "%q is not a valid Int32", kid.text)
			}
			*i32 = int32(v)
			di.EncodingMask |= mask
		}
	}
	return di, nil
}

func (d *xmlDecoder) structure(n *xmlNode, dst reflect.Value) error {
	info := codecTypes.structInfo(dst.Type())
	for _, kid := range n.kids {
		idx, ok := info.byName[kid.name]
		if !ok {
			continue
		}
		if err := d.value(kid, dst.Field(idx)); err != nil {
			return fmt.Errorf("%s.%s: %w", info.name, kid.name, err)
		}
	}
	fillRequired(dst)
	return nil
}

// xmlFragmentWithoutNamespaceReset is the inverse of
// xmlFragmentOutsideDefaultNamespace: it removes xmlns="" from the top-level
// elements of the content of an XmlElement. The declaration only says that
// the element is in no namespace, which is what the fragment says on its own.
func xmlFragmentWithoutNamespaceReset(fragment string) string {
	if !strings.Contains(fragment, xmlNoNamespaceAttr) {
		return fragment
	}
	dec := xml.NewDecoder(strings.NewReader(fragment))
	dec.Strict = true
	var (
		cuts  []int
		depth int
		prev  int64
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
		switch tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				tag := fragment[prev:off]
				end := 1
				for end < len(tag) && !strings.ContainsRune(" \t\r\n/>", rune(tag[end])) {
					end++
				}
				if strings.HasPrefix(tag[end:], xmlNoNamespaceAttr) {
					cuts = append(cuts, int(prev)+end)
				}
			}
			depth++
		case xml.EndElement:
			depth--
		}
		prev = off
	}
	if len(cuts) == 0 {
		return fragment
	}
	var b strings.Builder
	last := 0
	for _, at := range cuts {
		b.WriteString(fragment[last:at])
		last = at + len(xmlNoNamespaceAttr)
	}
	b.WriteString(fragment[last:])
	return b.String()
}
