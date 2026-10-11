// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
	"sync"
)

// DecodeJSON decodes a document in the OPC UA JSON DataEncoding (Part 6 §5.4)
// into v, which must be a non-nil pointer to a value [EncodeJSON] accepts:
// *int32, *string, *ua.Variant, *ua.DataValue, *ua.ReadRequest, *[]*ua.NodeID,
// **ua.NodeID, ...
//
// The decoder accepts the Compact and Verbose encodings of OPC UA 1.05.04
// and the reversible encoding of OPC UA 1.04 without being told which one it
// is given; the forms can even be mixed. The 1.04 non-reversible encoding
// drops type information and cannot be decoded.
//
// Unknown members of a structure are ignored and missing members keep their
// default value. Duplicate members, values of the wrong JSON type, numbers
// outside of the range of the target type and documents nested deeper than
// the configured limit (see [WithMaxDepth]) are errors. All errors wrap a
// [StatusCode], usually [StatusBadDecodingError].
func DecodeJSON(data []byte, v interface{}, opts ...CodecOption) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return codecError(StatusBadDecodingError, "json", "", "DecodeJSON needs a non-nil pointer, got %T", v)
	}
	o := newCodecOptions(opts)
	root, err := parseJSON(data, o.maxDepth)
	if err != nil {
		return err
	}
	d := &jsonDecoder{o: o}
	return decodeTop(rv, func(dst reflect.Value) error { return d.value(root, dst) })
}

// decodeTop lets the caller pass a pointer to a structure (*Variant,
// *ReadRequest) where the codecs produce such pointers themselves.
func decodeTop(rv reflect.Value, decode func(dst reflect.Value) error) error {
	t := rv.Type()
	if k := kindOf(t); t.Elem().Kind() == reflect.Struct && k != kindInvalid && t.Elem() != timeType {
		tmp := reflect.New(t).Elem()
		if err := decode(tmp); err != nil {
			return err
		}
		if tmp.IsNil() {
			// null: the null value of the type, in a form the binary
			// encoder accepts.
			if z := zeroElement(t); !z.IsNil() {
				rv.Elem().Set(z.Elem())
			} else {
				rv.Elem().SetZero()
			}
		} else {
			rv.Elem().Set(tmp.Elem())
		}
		return nil
	}
	return decode(rv.Elem())
}

type jsonDecoder struct {
	o *codecOptions
}

func (d *jsonDecoder) errorf(format string, args ...interface{}) error {
	return codecError(StatusBadDecodingError, "json", "", format, args...)
}

func (d *jsonDecoder) mismatch(n *jsonNode, want string) error {
	return d.errorf("cannot decode JSON %s as %s", n.kind, want)
}

// zeroBuiltin returns the value that stands for "null" where the binary
// encoding has no notion of an absent value (array elements, Variant bodies).
// Pointer types get an empty object so that the result can always be encoded.
func zeroBuiltin(t reflect.Type) reflect.Value {
	switch t {
	case typeGUIDPtr:
		return reflect.ValueOf(zeroGUID())
	case typeNodeIDPtr:
		return reflect.ValueOf(NewTwoByteNodeID(0))
	case typeExpNodeIDPtr:
		return reflect.ValueOf(NewTwoByteExpandedNodeID(0))
	case typeExtObjPtr:
		return reflect.ValueOf(NewExtensionObject(nil))
	case typeQualifiedName, typeLocalizedText, typeDataValuePtr, typeVariantPtr, typeDiagInfoPtr:
		return reflect.New(t.Elem())
	}
	return reflect.Zero(t)
}

// setBuiltin stores a pointer to a built-in structure into dst, which is
// either of the pointer type or of the structure type.
func setBuiltin(dst reflect.Value, p interface{}) {
	v := reflect.ValueOf(p)
	if dst.Kind() == reflect.Struct {
		dst.Set(v.Elem())
		return
	}
	dst.Set(v)
}

// The binary encoder refuses a nil *ExpandedNodeID, the one built-in type it
// has no null encoding for. A document may leave such a field out, so the
// decoders fill it in with the null ExpandedNodeId - also in nested
// structures that were left out as a whole, which the binary encoder writes
// field by field.

var needsFillCache sync.Map // reflect.Type (struct) -> bool

// needsFill reports whether the struct type t has, directly or through
// nested structures, an ExpandedNodeId field.
func needsFill(t reflect.Type) bool {
	if v, ok := needsFillCache.Load(t); ok {
		return v.(bool)
	}
	// Only the finished answer is cached. A placeholder for the type that
	// is being walked (as a guard against recursive types) would be handed
	// to every goroutine that asks in the meantime.
	need := walkNeedsFill(t, map[reflect.Type]struct{}{})
	needsFillCache.Store(t, need)
	return need
}

// walkNeedsFill is the uncached search behind needsFill. visiting holds the
// types of the current walk, which guards against recursive types.
func walkNeedsFill(t reflect.Type, visiting map[reflect.Type]struct{}) bool {
	if v, ok := needsFillCache.Load(t); ok {
		return v.(bool)
	}
	if _, seen := visiting[t]; seen {
		return false // nothing that the first visit does not find
	}
	visiting[t] = struct{}{}
	for i := 0; i < t.NumField(); i++ {
		ft := t.Field(i).Type
		need := false
		switch kindOf(ft) {
		case codecKind(TypeIDExpandedNodeID):
			need = ft.Kind() == reflect.Pointer
		case kindStruct:
			need = walkNeedsFill(ft, visiting)
		case kindStructPtr:
			need = walkNeedsFill(ft.Elem(), visiting)
		default:
		}
		if need {
			return true
		}
	}
	return false
}

// fillRequired completes a decoded structure as described above.
func fillRequired(v reflect.Value) {
	if !needsFill(v.Type()) {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch kindOf(f.Type()) {
		case codecKind(TypeIDExpandedNodeID):
			if f.Kind() == reflect.Pointer && f.IsNil() {
				f.Set(zeroBuiltin(typeExpNodeIDPtr))
			}
		case kindStruct:
			fillRequired(f)
		case kindStructPtr:
			if f.IsNil() && needsFill(f.Type().Elem()) {
				f.Set(reflect.New(f.Type().Elem()))
			}
			if !f.IsNil() {
				fillRequired(f.Elem())
			}
		default:
		}
	}
}

// zeroElement returns the value of an array element that is null in the
// document.
func zeroElement(t reflect.Type) reflect.Value {
	if kindOf(t) == kindStructPtr && needsFill(t.Elem()) {
		p := reflect.New(t.Elem())
		fillRequired(p.Elem())
		return p
	}
	return zeroBuiltin(t)
}

func (d *jsonDecoder) value(n *jsonNode, dst reflect.Value) error {
	t := dst.Type()
	k := kindOf(t)
	if k == kindInvalid {
		return d.errorf("unsupported type %s", t)
	}
	if n.isNull() {
		dst.SetZero()
		if k == kindStruct {
			fillRequired(dst)
		}
		return nil
	}
	switch k {
	case kindEnum:
		return d.enum(n, dst)
	case kindStructPtr:
		p := reflect.New(t.Elem())
		if err := d.structure(n, p.Elem()); err != nil {
			return err
		}
		dst.Set(p)
		return nil
	case kindStruct:
		return d.structure(n, dst)
	case kindArray:
		if n.kind != jsonArray {
			return d.mismatch(n, t.String())
		}
		s := reflect.MakeSlice(t, len(n.arr), len(n.arr))
		for i := range n.arr {
			if n.arr[i].isNull() {
				s.Index(i).Set(zeroElement(t.Elem()))
				continue
			}
			if err := d.value(&n.arr[i], s.Index(i)); err != nil {
				return err
			}
		}
		dst.Set(s)
		return nil
	default:
		return d.builtin(TypeID(k), n, dst)
	}
}

func (d *jsonDecoder) intText(n *jsonNode, want string) (string, error) {
	if n.kind != jsonNumber && n.kind != jsonString {
		return "", d.mismatch(n, want)
	}
	return n.s, nil
}

func (d *jsonDecoder) setInt(n *jsonNode, dst reflect.Value) error {
	s, err := d.intText(n, dst.Type().String())
	if err != nil {
		return err
	}
	if dst.CanInt() {
		v, err := strconv.ParseInt(s, 10, dst.Type().Bits())
		if err != nil {
			return d.errorf("%q is not a valid %s", s, dst.Type())
		}
		dst.SetInt(v)
		return nil
	}
	v, err := strconv.ParseUint(s, 10, dst.Type().Bits())
	if err != nil {
		return d.errorf("%q is not a valid %s", s, dst.Type())
	}
	dst.SetUint(v)
	return nil
}

func (d *jsonDecoder) enum(n *jsonNode, dst reflect.Value) error {
	if n.kind == jsonNumber {
		return d.setInt(n, dst)
	}
	if n.kind != jsonString {
		return d.mismatch(n, dst.Type().String())
	}
	v, ok := parseEnum(n.s, codecTypes.enumInfo(dst.Type()))
	if !ok {
		return d.errorf("%q is not a value of %s", n.s, dst.Type())
	}
	if dst.CanInt() {
		if dst.OverflowInt(v) {
			return d.errorf("%d overflows %s", v, dst.Type())
		}
		dst.SetInt(v)
	} else {
		if v < 0 || dst.OverflowUint(uint64(v)) {
			return d.errorf("%d overflows %s", v, dst.Type())
		}
		dst.SetUint(uint64(v))
	}
	return nil
}

func (d *jsonDecoder) text(n *jsonNode, want string) (string, error) {
	if n.kind != jsonString {
		return "", d.mismatch(n, want)
	}
	return n.s, nil
}

func (d *jsonDecoder) builtin(typ TypeID, n *jsonNode, dst reflect.Value) error {
	name := builtinTypeNames[typ]
	switch typ {
	case TypeIDBoolean:
		if n.kind != jsonBool {
			return d.mismatch(n, name)
		}
		dst.SetBool(n.b)
	case TypeIDSByte, TypeIDByte, TypeIDInt16, TypeIDUint16, TypeIDInt32, TypeIDUint32, TypeIDInt64, TypeIDUint64:
		return d.setInt(n, dst)
	case TypeIDFloat, TypeIDDouble:
		if n.kind != jsonNumber && n.kind != jsonString {
			return d.mismatch(n, name)
		}
		f, ok := parseFloatText(n.s, dst.Type().Bits())
		if !ok {
			return d.errorf("%q is not a valid %s", n.s, name)
		}
		dst.SetFloat(f)
	case TypeIDString:
		s, err := d.text(n, name)
		if err != nil {
			return err
		}
		dst.SetString(s)
	case TypeIDDateTime:
		s, err := d.text(n, name)
		if err != nil {
			return err
		}
		t, ok := parseDateTime(s)
		if !ok {
			return d.errorf("%q is not a valid DateTime", s)
		}
		dst.Set(reflect.ValueOf(t))
	case TypeIDByteString:
		s, err := d.text(n, name)
		if err != nil {
			return err
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return d.errorf("invalid base64 in ByteString")
		}
		if b == nil {
			b = []byte{}
		}
		dst.SetBytes(b)
	case TypeIDXMLElement:
		s, err := d.text(n, name)
		if err != nil {
			return err
		}
		if dst.Kind() == reflect.Pointer {
			x := XMLElement(s)
			dst.Set(reflect.ValueOf(&x))
		} else {
			dst.SetString(s)
		}
	case TypeIDStatusCode:
		sc, err := d.statusCode(n)
		if err != nil {
			return err
		}
		dst.SetUint(uint64(sc))
	case TypeIDGUID:
		s, err := d.text(n, name)
		if err != nil {
			return err
		}
		g := parseGUID(s)
		if g == nil {
			return d.errorf("%q is not a valid Guid", s)
		}
		setBuiltin(dst, g)
	case TypeIDNodeID:
		x, err := d.expandedNodeID(n, false)
		if err != nil {
			return err
		}
		setBuiltin(dst, x.NodeID)
	case TypeIDExpandedNodeID:
		x, err := d.expandedNodeID(n, true)
		if err != nil {
			return err
		}
		setBuiltin(dst, x)
	case TypeIDQualifiedName:
		x, err := d.qualifiedName(n)
		if err != nil {
			return err
		}
		setBuiltin(dst, x)
	case TypeIDLocalizedText:
		x, err := d.localizedText(n)
		if err != nil {
			return err
		}
		setBuiltin(dst, x)
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
		return d.errorf("unsupported built-in type %d", typ)
	}
	return nil
}

func (d *jsonDecoder) uint(n *jsonNode, bits int, want string) (uint64, error) {
	s, err := d.intText(n, want)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		return 0, d.errorf("%q is not a valid %s", s, want)
	}
	return v, nil
}

func (d *jsonDecoder) int32(n *jsonNode, want string) (int32, error) {
	s, err := d.intText(n, want)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, d.errorf("%q is not a valid %s", s, want)
	}
	return int32(v), nil
}

// statusCode reads {"Code":n,"Symbol":s} (1.05) or a number (1.04).
func (d *jsonDecoder) statusCode(n *jsonNode) (StatusCode, error) {
	switch n.kind {
	case jsonNumber:
		v, err := d.uint(n, 32, "StatusCode")
		return StatusCode(v), err
	case jsonObject:
		c := n.get("Code")
		if c.isNull() {
			return StatusOK, nil
		}
		v, err := d.uint(c, 32, "StatusCode")
		return StatusCode(v), err
	default:
		return 0, d.mismatch(n, "StatusCode")
	}
}

// expandedNodeID reads a NodeId or ExpandedNodeId: a string (1.05) or an
// object with IdType, Id, Namespace and ServerUri (1.04).
func (d *jsonDecoder) expandedNodeID(n *jsonNode, expanded bool) (*ExpandedNodeID, error) {
	switch n.kind {
	case jsonString:
		if !expanded {
			return &ExpandedNodeID{NodeID: d.o.parseNodeID(n.s)}, nil
		}
		if e, ok := d.o.parseExpandedNodeID(n.s); ok {
			return e, nil
		}
		// Part 6 §5.4.2.11: keep what cannot be mapped as a String NodeId.
		return &ExpandedNodeID{NodeID: NewStringNodeID(0, n.s)}, nil
	case jsonObject:
	default:
		return nil, d.mismatch(n, "NodeId")
	}

	var (
		ns  uint16
		nsu string
	)
	if nsNode := n.get("Namespace"); !nsNode.isNull() {
		switch nsNode.kind {
		case jsonNumber:
			v, err := d.uint(nsNode, 16, "namespace index")
			if err != nil {
				return nil, err
			}
			ns = uint16(v)
		case jsonString:
			if idx, ok := d.o.namespaceIndex(nsNode.s); ok {
				ns = idx
			} else if expanded {
				nsu = nsNode.s
			} else {
				return nil, d.errorf("unknown namespace URI %q", nsNode.s)
			}
		default:
			return nil, d.mismatch(nsNode, "namespace")
		}
	}
	idType := uint64(0)
	if t := n.get("IdType"); !t.isNull() {
		v, err := d.uint(t, 8, "IdType")
		if err != nil {
			return nil, err
		}
		idType = v
	}
	id := n.get("Id")
	var node *NodeID
	switch idType {
	case 0:
		v := uint64(0)
		if !id.isNull() {
			var err error
			if v, err = d.uint(id, 32, "numeric NodeId"); err != nil {
				return nil, err
			}
		}
		node = newNumericNodeIDCompact(ns, uint32(v))
	case 1, 2, 3:
		if id.isNull() || id.kind != jsonString {
			return nil, d.errorf("NodeId of IdType %d needs a string Id", idType)
		}
		switch idType {
		case 1:
			node = NewStringNodeID(ns, id.s)
		case 2:
			g := parseGUID(id.s)
			if g == nil {
				return nil, d.errorf("%q is not a valid Guid", id.s)
			}
			node = &NodeID{mask: NodeIDTypeGUID, ns: ns, gid: g}
		default:
			b, err := base64.StdEncoding.DecodeString(id.s)
			if err != nil {
				return nil, d.errorf("invalid base64 in NodeId")
			}
			node = NewByteStringNodeID(ns, b)
		}
	default:
		return nil, d.errorf("invalid IdType %d", idType)
	}
	e := &ExpandedNodeID{NodeID: node, NamespaceURI: nsu}
	if nsu != "" {
		node.SetURIFlag()
	}
	if su := n.get("ServerUri"); expanded && !su.isNull() {
		switch su.kind {
		case jsonNumber:
			v, err := d.uint(su, 32, "server index")
			if err != nil {
				return nil, err
			}
			e.ServerIndex = uint32(v)
		case jsonString:
			found := false
			for i, u := range d.o.servers {
				if u == su.s {
					e.ServerIndex, found = uint32(i), true
					break
				}
			}
			if !found {
				return nil, d.errorf("unknown server URI %q", su.s)
			}
		default:
			return nil, d.mismatch(su, "server index")
		}
		if e.ServerIndex != 0 {
			node.SetIndexFlag()
		}
	}
	return e, nil
}

// qualifiedName reads "1:Name" (1.05) or {"Name":..,"Uri":..} (1.04).
func (d *jsonDecoder) qualifiedName(n *jsonNode) (*QualifiedName, error) {
	switch n.kind {
	case jsonString:
		return d.o.parseQualifiedName(n.s), nil
	case jsonObject:
	default:
		return nil, d.mismatch(n, "QualifiedName")
	}
	q := &QualifiedName{}
	if name := n.get("Name"); !name.isNull() {
		s, err := d.text(name, "String")
		if err != nil {
			return nil, err
		}
		q.Name = s
	}
	if uri := n.get("Uri"); !uri.isNull() {
		switch uri.kind {
		case jsonNumber:
			v, err := d.uint(uri, 16, "namespace index")
			if err != nil {
				return nil, err
			}
			q.NamespaceIndex = uint16(v)
		case jsonString:
			idx, ok := d.o.namespaceIndex(uri.s)
			if !ok {
				return nil, d.errorf("unknown namespace URI %q", uri.s)
			}
			q.NamespaceIndex = idx
		default:
			return nil, d.mismatch(uri, "namespace")
		}
	}
	return q, nil
}

func (d *jsonDecoder) localizedText(n *jsonNode) (*LocalizedText, error) {
	l := &LocalizedText{}
	switch n.kind {
	case jsonString: // 1.04 non-reversible: only the text survived
		l.Text = n.s
	case jsonObject:
		for _, f := range []struct {
			key string
			dst *string
		}{{"Locale", &l.Locale}, {"Text", &l.Text}} {
			if m := n.get(f.key); !m.isNull() {
				s, err := d.text(m, "String")
				if err != nil {
					return nil, err
				}
				*f.dst = s
			}
		}
	default:
		return nil, d.mismatch(n, "LocalizedText")
	}
	l.UpdateMask()
	return l, nil
}

func (d *jsonDecoder) extensionObject(n *jsonNode) (*ExtensionObject, error) {
	if n.kind != jsonObject {
		return nil, d.mismatch(n, "ExtensionObject")
	}
	if len(n.keys) == 0 {
		return NewExtensionObject(nil), nil
	}
	keyType, keyEnc, keyBody := "UaTypeId", "UaEncoding", "UaBody"
	inPlace := true
	if n.get(keyType) == nil && n.get("TypeId") != nil {
		keyType, keyEnc, keyBody = "TypeId", "Encoding", "Body"
		inPlace = false
	}
	typeNode := n.get(keyType)
	if typeNode.isNull() {
		return nil, d.errorf("ExtensionObject without %s", keyType)
	}
	xid, err := d.expandedNodeID(typeNode, false)
	if err != nil {
		return nil, err
	}
	typeID := xid.NodeID
	encoding := uint64(0)
	if en := n.get(keyEnc); !en.isNull() {
		if encoding, err = d.uint(en, 8, "encoding"); err != nil {
			return nil, err
		}
	}
	body := n.get(keyBody)

	switch encoding {
	case 0:
	case 1:
		raw := []byte{}
		if !body.isNull() {
			s, err := d.text(body, "ByteString")
			if err != nil {
				return nil, err
			}
			if raw, err = base64.StdEncoding.DecodeString(s); err != nil {
				return nil, d.errorf("invalid base64 in ExtensionObject body")
			}
		}
		return binaryExtensionObject(typeID, raw)
	case 2:
		s := ""
		if !body.isNull() {
			if s, err = d.text(body, "XmlElement"); err != nil {
				return nil, err
			}
		}
		x := XMLElement(s)
		return &ExtensionObject{EncodingMask: ExtensionObjectXML, TypeID: &ExpandedNodeID{NodeID: typeID}, Value: &x}, nil
	default:
		return nil, d.errorf("invalid ExtensionObject encoding %d", encoding)
	}

	v := codecTypes.newByTypeID(typeID)
	if v == nil {
		return nil, d.errorf("ExtensionObject of unknown type %s", typeID)
	}
	rv := reflect.ValueOf(v).Elem()
	switch {
	case body != nil:
		err = d.value(body, rv)
	case inPlace && kindOf(rv.Type()) == kindStruct:
		err = d.structure(n, rv)
	default:
		return nil, d.errorf("ExtensionObject without %s", keyBody)
	}
	if err != nil {
		return nil, err
	}
	return NewExtensionObject(v), nil
}

// binaryExtensionObject builds the ExtensionObject for a body that is given
// in the binary encoding, which is how JSON and XML carry opaque bodies.
func binaryExtensionObject(typeID *NodeID, raw []byte) (*ExtensionObject, error) {
	v := codecTypes.newByTypeID(typeID)
	if v == nil {
		// Unknown type: keep the encoded body as it is. ExtensionObject
		// writes a []byte body back unchanged in every encoding.
		return &ExtensionObject{EncodingMask: ExtensionObjectBinary, TypeID: &ExpandedNodeID{NodeID: typeID}, Value: raw}, nil
	}
	if _, err := Decode(raw, v); err != nil {
		// Like every error of the JSON and XML decoders this one wraps
		// a StatusCode; the error of the binary decoder stays visible.
		return nil, fmt.Errorf("ua: binary body of ExtensionObject %s: %w: %w", typeID, err, StatusBadDecodingError)
	}
	return NewExtensionObject(v), nil
}

func (d *jsonDecoder) dims(n *jsonNode) ([]int32, error) {
	if n.isNull() {
		return nil, nil
	}
	if n.kind != jsonArray {
		return nil, d.mismatch(n, "Dimensions")
	}
	dims := make([]int32, len(n.arr))
	for i := range n.arr {
		v, err := d.int32(&n.arr[i], "dimension")
		if err != nil {
			return nil, err
		}
		dims[i] = v
	}
	return dims, nil
}

// variantOf builds a Variant from its type, value and dimensions members.
func (d *jsonDecoder) variantOf(typeNode, value, dimsNode *jsonNode) (*Variant, error) {
	if typeNode.isNull() {
		if value.isNull() {
			return &Variant{}, nil
		}
		return nil, d.errorf("Variant value without a type")
	}
	t, err := d.uint(typeNode, 8, "built-in type")
	if err != nil {
		return nil, err
	}
	typ := TypeID(t)
	if typ == TypeIDNull {
		return &Variant{}, nil
	}
	et, ok := variantTypeIDToType[typ]
	if !ok {
		return nil, d.errorf("invalid built-in type %d", t)
	}
	dims, err := d.dims(dimsNode)
	if err != nil {
		return nil, err
	}

	if value != nil && value.kind == jsonArray {
		if len(value.arr) > d.o.maxArray {
			return nil, codecError(StatusBadEncodingLimitsExceeded, "json", "", "array of %d elements exceeds the limit of %d", len(value.arr), d.o.maxArray)
		}
		st, _ := variantSliceType(typ)
		vals := reflect.MakeSlice(st, len(value.arr), len(value.arr))
		for i := range value.arr {
			if value.arr[i].isNull() {
				vals.Index(i).Set(zeroBuiltin(et))
				continue
			}
			if err := d.value(&value.arr[i], vals.Index(i)); err != nil {
				return nil, err
			}
		}
		m, err := newArrayVariant(typ, vals, dims)
		if err != nil {
			return nil, codecError(StatusBadDecodingError, "json", "", "%v", err)
		}
		return m, nil
	}

	if dims != nil {
		return nil, d.errorf("scalar Variant with Dimensions")
	}
	val := reflect.New(et).Elem()
	if value.isNull() {
		val.Set(zeroBuiltin(et))
	} else if err := d.value(value, val); err != nil {
		return nil, err
	}
	return &Variant{mask: byte(typ), value: val.Interface()}, nil
}

func (d *jsonDecoder) variant(n *jsonNode) (*Variant, error) {
	if n.kind != jsonObject {
		return nil, d.mismatch(n, "Variant")
	}
	if t := n.get("UaType"); t != nil {
		return d.variantOf(t, n.get("Value"), n.get("Dimensions"))
	}
	if n.get("Type") == nil && !n.get("Value").isNull() {
		return nil, d.errorf("Variant value without a type")
	}
	return d.variantOf(n.get("Type"), n.get("Body"), n.get("Dimensions"))
}

func (d *jsonDecoder) dataValue(n *jsonNode) (*DataValue, error) {
	if n.kind != jsonObject {
		return nil, d.mismatch(n, "DataValue")
	}
	dv := &DataValue{}
	var err error
	value := n.get("Value")
	switch t := n.get("UaType"); {
	case t != nil: // 1.05: the Variant members are part of the DataValue
		dv.Value, err = d.variantOf(t, value, n.get("Dimensions"))
	case !value.isNull(): // 1.04: the Variant is a member
		dv.Value, err = d.variant(value)
	}
	if err != nil {
		return nil, err
	}
	if dv.Value != nil && dv.Value.Type() != TypeIDNull {
		dv.EncodingMask |= DataValueValue
	} else {
		dv.Value = nil
	}
	if m := n.get("Status"); m != nil {
		dv.EncodingMask |= DataValueStatusCode
		if !m.isNull() {
			if dv.Status, err = d.statusCode(m); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range []struct {
		key  string
		mask byte
		ts   bool
	}{
		{"SourceTimestamp", DataValueSourceTimestamp, true},
		{"SourcePicoseconds", DataValueSourcePicoseconds, false},
		{"ServerTimestamp", DataValueServerTimestamp, true},
		{"ServerPicoseconds", DataValueServerPicoseconds, false},
	} {
		m := n.get(f.key)
		if m.isNull() {
			continue
		}
		dv.EncodingMask |= f.mask
		if !f.ts {
			v, err := d.uint(m, 16, "UInt16")
			if err != nil {
				return nil, err
			}
			if f.mask == DataValueSourcePicoseconds {
				dv.SourcePicoseconds = uint16(v)
			} else {
				dv.ServerPicoseconds = uint16(v)
			}
			continue
		}
		s, err := d.text(m, "DateTime")
		if err != nil {
			return nil, err
		}
		t, ok := parseDateTime(s)
		if !ok {
			return nil, d.errorf("%q is not a valid DateTime", s)
		}
		if f.mask == DataValueSourceTimestamp {
			dv.SourceTimestamp = t
		} else {
			dv.ServerTimestamp = t
		}
	}
	return dv, nil
}

func (d *jsonDecoder) diagnosticInfo(n *jsonNode) (*DiagnosticInfo, error) {
	if n.kind != jsonObject {
		return nil, d.mismatch(n, "DiagnosticInfo")
	}
	di := &DiagnosticInfo{}
	for _, f := range []struct {
		key  string
		mask uint8
		dst  *int32
	}{
		{"SymbolicId", DiagnosticInfoSymbolicID, &di.SymbolicID},
		{"NamespaceUri", DiagnosticInfoNamespaceURI, &di.NamespaceURI},
		{"Locale", DiagnosticInfoLocale, &di.Locale},
		{"LocalizedText", DiagnosticInfoLocalizedText, &di.LocalizedText},
	} {
		if m := n.get(f.key); !m.isNull() {
			v, err := d.int32(m, "Int32")
			if err != nil {
				return nil, err
			}
			*f.dst = v
			di.EncodingMask |= f.mask
		}
	}
	if m := n.get("AdditionalInfo"); !m.isNull() {
		s, err := d.text(m, "String")
		if err != nil {
			return nil, err
		}
		di.AdditionalInfo = s
		di.EncodingMask |= DiagnosticInfoAdditionalInfo
	}
	if m := n.get("InnerStatusCode"); !m.isNull() {
		sc, err := d.statusCode(m)
		if err != nil {
			return nil, err
		}
		di.InnerStatusCode = sc
		di.EncodingMask |= DiagnosticInfoInnerStatusCode
	}
	if m := n.get("InnerDiagnosticInfo"); !m.isNull() {
		inner, err := d.diagnosticInfo(m)
		if err != nil {
			return nil, err
		}
		di.InnerDiagnosticInfo = inner
		di.EncodingMask |= DiagnosticInfoInnerDiagnosticInfo
	}
	return di, nil
}

// structure decodes the members of a JSON object into the fields of a
// structure. In an ExtensionObject the members sit next to the UaTypeId,
// which is skipped like any other member that is not a field.
func (d *jsonDecoder) structure(n *jsonNode, dst reflect.Value) error {
	if n.kind != jsonObject {
		return d.mismatch(n, dst.Type().String())
	}
	info := codecTypes.structInfo(dst.Type())
	for i, key := range n.keys {
		idx, ok := info.byName[key]
		if !ok {
			continue // unknown members are ignored, incl. UaTypeId
		}
		if err := d.value(&n.arr[i], dst.Field(idx)); err != nil {
			return fmt.Errorf("%s.%s: %w", info.name, key, err)
		}
	}
	fillRequired(dst)
	return nil
}
