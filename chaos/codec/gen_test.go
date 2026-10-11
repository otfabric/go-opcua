// SPDX-License-Identifier: MIT

package codec

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/internal/testhook"
	"github.com/otfabric/go-opcua/internal/testutil/customtypes"
	"github.com/otfabric/go-opcua/ua"
)

// This file builds the values the scenarios share. It only uses the public
// API of package ua, and - on purpose - nothing of the JSON and XML codecs:
// building the values must not populate the caches whose first use the
// scenarios want to happen concurrently.

var (
	typTime     = reflect.TypeOf(time.Time{})
	typBytes    = reflect.TypeOf([]byte(nil))
	typXML      = reflect.TypeOf(ua.XMLElement(""))
	typStatus   = reflect.TypeOf(ua.StatusCode(0))
	typGUID     = reflect.TypeOf(ua.GUID{})
	typNodeID   = reflect.TypeOf(ua.NodeID{})
	typExpID    = reflect.TypeOf(ua.ExpandedNodeID{})
	typQName    = reflect.TypeOf(ua.QualifiedName{})
	typLText    = reflect.TypeOf(ua.LocalizedText{})
	typExtObj   = reflect.TypeOf(ua.ExtensionObject{})
	typDataVal  = reflect.TypeOf(ua.DataValue{})
	typVariant  = reflect.TypeOf(ua.Variant{})
	typDiagInfo = reflect.TypeOf(ua.DiagnosticInfo{})
)

// valueGen produces deterministic pseudo-random values in the canonical form
// of the library (the form a value has after binary decoding), which is the
// precondition of the binary -> JSON/XML -> binary identity the scenarios
// check.
type valueGen struct {
	r        *rand.Rand
	maxDepth int
}

var genRunes = []rune("abcXYZ019 _-.:;=/\\\"'<>&{}[]\t\näöü€日本語🙂")

func (g *valueGen) str() string {
	out := make([]rune, g.r.Intn(8))
	for i := range out {
		out[i] = genRunes[g.r.Intn(len(genRunes))]
	}
	return string(out)
}

func (g *valueGen) bytes() []byte {
	b := make([]byte, 1+g.r.Intn(9))
	for i := range b {
		b[i] = byte(g.r.Uint64())
	}
	return b
}

func (g *valueGen) time() time.Time {
	if g.r.Intn(5) == 0 {
		return time.Time{}
	}
	secs := int64(g.r.Uint64() % (4 * 365 * 24 * 3600 * 25))
	return time.Unix(secs, int64(g.r.Intn(1e7))*100).UTC()
}

func (g *valueGen) guid() *ua.GUID {
	return ua.NewGUID(fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		g.r.Uint32(), g.r.Intn(1<<16), g.r.Intn(1<<16), g.r.Intn(1<<16), g.r.Int63n(1<<48)))
}

// numericNodeID returns the smallest binary form that holds the id: JSON and
// XML do not carry the binary form and decode to the compact one.
func numericNodeID(ns uint16, id uint32) *ua.NodeID {
	switch {
	case ns == 0 && id < 256:
		return ua.NewTwoByteNodeID(uint8(id))
	case ns < 256 && id < math.MaxUint16:
		return ua.NewFourByteNodeID(uint8(ns), uint16(id))
	}
	return ua.NewNumericNodeID(ns, id)
}

func (g *valueGen) nodeID(ns uint16) *ua.NodeID {
	switch g.r.Intn(5) {
	case 0:
		return ua.NewStringNodeID(ns, "s"+g.str())
	case 1:
		return ua.NewGUIDNodeID(ns, g.guid().String())
	case 2:
		return ua.NewByteStringNodeID(ns, g.bytes())
	case 3:
		return numericNodeID(ns, g.r.Uint32())
	}
	return numericNodeID(ns, uint32(g.r.Intn(70000)))
}

func (g *valueGen) namespace() uint16 {
	if g.r.Intn(2) == 0 {
		return 0
	}
	return uint16(g.r.Intn(4))
}

func (g *valueGen) expandedNodeID() *ua.ExpandedNodeID {
	uri, idx := "", uint32(0)
	ns := g.namespace()
	if g.r.Intn(3) == 0 {
		// A namespace URI replaces the index (Part 6 §5.2.2.10).
		uri, ns = "urn:test:"+string(rune('a'+g.r.Intn(5))), 0
	}
	if g.r.Intn(3) == 0 {
		idx = uint32(1 + g.r.Intn(5))
	}
	return ua.NewExpandedNodeID(g.nodeID(ns), uri, idx)
}

func (g *valueGen) float(bits int) float64 {
	switch g.r.Intn(8) {
	case 0:
		return math.NaN()
	case 1:
		return math.Inf(1)
	case 2:
		return math.Inf(-1)
	case 3:
		return math.Copysign(0, -1)
	case 4:
		return 0
	}
	if bits == 32 {
		return float64(float32(g.r.NormFloat64() * 1e6))
	}
	return g.r.NormFloat64() * 1e12
}

func (g *valueGen) localizedText() *ua.LocalizedText {
	l := &ua.LocalizedText{}
	if g.r.Intn(2) == 0 {
		l.Locale = "en-US"
	}
	if g.r.Intn(4) != 0 {
		l.Text = g.str()
	}
	l.UpdateMask()
	return l
}

func (g *valueGen) diagnosticInfo(depth int) *ua.DiagnosticInfo {
	d := &ua.DiagnosticInfo{
		SymbolicID:      int32(g.r.Intn(3)),
		NamespaceURI:    int32(g.r.Intn(3)),
		Locale:          int32(g.r.Intn(3)),
		LocalizedText:   int32(g.r.Intn(3)) - 1,
		AdditionalInfo:  g.str(),
		InnerStatusCode: ua.StatusCode(g.r.Intn(2)) * ua.StatusBadInternalError,
	}
	if depth < 2 && g.r.Intn(2) == 0 {
		d.InnerDiagnosticInfo = g.diagnosticInfo(depth + 1)
	}
	d.UpdateMask()
	return d
}

func (g *valueGen) dataValue(depth int) *ua.DataValue {
	d := &ua.DataValue{
		Status:            ua.StatusCode(g.r.Intn(2)) * ua.StatusBadNodeIDUnknown,
		SourceTimestamp:   g.time(),
		ServerTimestamp:   g.time(),
		SourcePicoseconds: uint16(g.r.Intn(3)),
		ServerPicoseconds: uint16(g.r.Intn(3)),
	}
	if v := g.variant(depth + 1); v.Type() != ua.TypeIDNull && g.r.Intn(4) != 0 {
		d.Value = v
	}
	d.UpdateMask()
	return d
}

// extensionObjectBodies are the structures used as ExtensionObject bodies:
// generated ones and the custom ones of internal/testutil/customtypes.
var extensionObjectBodies = []reflect.Type{
	reflect.TypeOf(ua.Argument{}),
	reflect.TypeOf(ua.EUInformation{}),
	reflect.TypeOf(ua.Range{}),
	reflect.TypeOf(ua.KeyValuePair{}),
	reflect.TypeOf(ua.EnumValueType{}),
	reflect.TypeOf(ua.ServerStatusDataType{}),
	reflect.TypeOf(ua.BuildInfo{}),
	reflect.TypeOf(ua.UserTokenPolicy{}),
	reflect.TypeOf(customtypes.FlatStruct{}),
	reflect.TypeOf(customtypes.ArrayStruct{}),
	reflect.TypeOf(customtypes.NestedStruct{}),
}

func (g *valueGen) extensionObject(depth int) *ua.ExtensionObject {
	if depth >= g.maxDepth || g.r.Intn(6) == 0 {
		return ua.NewExtensionObject(nil)
	}
	p := reflect.New(extensionObjectBodies[g.r.Intn(len(extensionObjectBodies))])
	g.fill(p.Elem(), depth+1)
	return ua.NewExtensionObject(p.Interface())
}

// variantTypes are the built-in types a random Variant holds.
var variantTypes = []ua.TypeID{
	ua.TypeIDBoolean, ua.TypeIDSByte, ua.TypeIDByte, ua.TypeIDInt16, ua.TypeIDUint16, ua.TypeIDInt32,
	ua.TypeIDUint32, ua.TypeIDInt64, ua.TypeIDUint64, ua.TypeIDFloat, ua.TypeIDDouble, ua.TypeIDString,
	ua.TypeIDDateTime, ua.TypeIDGUID, ua.TypeIDByteString, ua.TypeIDXMLElement, ua.TypeIDNodeID,
	ua.TypeIDExpandedNodeID, ua.TypeIDStatusCode, ua.TypeIDQualifiedName, ua.TypeIDLocalizedText,
	ua.TypeIDExtensionObject, ua.TypeIDDataValue, ua.TypeIDVariant, ua.TypeIDDiagnosticInfo,
}

// scalar returns a random value of a built-in type as a Variant holds it.
func (g *valueGen) scalar(typ ua.TypeID, depth int) any {
	switch typ {
	case ua.TypeIDBoolean:
		return g.r.Intn(2) == 0
	case ua.TypeIDSByte:
		return int8(g.r.Uint64())
	case ua.TypeIDByte:
		return uint8(g.r.Uint64())
	case ua.TypeIDInt16:
		return int16(g.r.Uint64())
	case ua.TypeIDUint16:
		return uint16(g.r.Uint64())
	case ua.TypeIDInt32:
		return int32(g.r.Uint64())
	case ua.TypeIDUint32:
		return uint32(g.r.Uint64())
	case ua.TypeIDInt64:
		return int64(g.r.Uint64())
	case ua.TypeIDUint64:
		return g.r.Uint64()
	case ua.TypeIDFloat:
		return float32(g.float(32))
	case ua.TypeIDDouble:
		return g.float(64)
	case ua.TypeIDString:
		return g.str()
	case ua.TypeIDDateTime:
		return g.time()
	case ua.TypeIDGUID:
		return g.guid()
	case ua.TypeIDByteString:
		return g.bytes()
	case ua.TypeIDXMLElement:
		if g.r.Intn(3) == 0 {
			return ua.XMLElement("")
		}
		return ua.XMLElement("<a x=\"1\"><b>t &amp; u</b><c/></a>")
	case ua.TypeIDNodeID:
		return g.nodeID(g.namespace())
	case ua.TypeIDExpandedNodeID:
		return g.expandedNodeID()
	case ua.TypeIDStatusCode:
		return ua.StatusCode(g.r.Uint32())
	case ua.TypeIDQualifiedName:
		return &ua.QualifiedName{NamespaceIndex: uint16(g.r.Intn(3)), Name: g.str()}
	case ua.TypeIDLocalizedText:
		return g.localizedText()
	case ua.TypeIDExtensionObject:
		return g.extensionObject(depth)
	case ua.TypeIDDataValue:
		return g.dataValue(depth)
	case ua.TypeIDVariant:
		return g.variant(depth + 1)
	default:
		return g.diagnosticInfo(0)
	}
}

// variant returns a random scalar, array or matrix Variant. Null arrays are
// not generated: JSON cannot tell them from empty arrays.
func (g *valueGen) variant(depth int) *ua.Variant {
	if depth > g.maxDepth || g.r.Intn(12) == 0 {
		return ua.MustVariant(nil)
	}
	typ := variantTypes[g.r.Intn(len(variantTypes))]
	shape := g.r.Intn(4)
	if typ == ua.TypeIDVariant && shape == 0 {
		shape = 1 // a Variant cannot directly hold a Variant
	}
	if typ == ua.TypeIDByte && shape != 0 {
		typ = ua.TypeIDUint16 // []byte is a ByteString
	}
	return g.variantOf(typ, shape, depth)
}

func (g *valueGen) variantOf(typ ua.TypeID, shape, depth int) *ua.Variant {
	if shape == 0 {
		return ua.MustVariant(g.scalar(typ, depth))
	}
	dims := []int{g.r.Intn(4)}
	if shape == 3 {
		dims = []int{1 + g.r.Intn(2), 1 + g.r.Intn(3)}
		if g.r.Intn(3) == 0 {
			dims = append(dims, 1+g.r.Intn(2))
		}
	}
	return ua.MustVariant(g.array(typ, dims, depth).Interface())
}

func (g *valueGen) array(typ ua.TypeID, dims []int, depth int) reflect.Value {
	if len(dims) == 1 {
		var s reflect.Value
		for i := 0; i < dims[0] || i == 0; i++ {
			el := reflect.ValueOf(g.scalar(typ, depth))
			if i == 0 {
				s = reflect.MakeSlice(reflect.SliceOf(el.Type()), dims[0], dims[0])
			}
			if i < dims[0] {
				s.Index(i).Set(el)
			}
		}
		return s
	}
	var out reflect.Value
	for i := 0; i < dims[0]; i++ {
		inner := g.array(typ, dims[1:], depth)
		if i == 0 {
			out = reflect.MakeSlice(reflect.SliceOf(inner.Type()), dims[0], dims[0])
		}
		out.Index(i).Set(inner)
	}
	return out
}

// builtinOf returns the built-in type a Go type stands for, held by pointer
// (ptr) or by value.
func builtinOf(t reflect.Type) (typ ua.TypeID, ptr, ok bool) {
	e := t
	if t.Kind() == reflect.Pointer {
		e, ptr = t.Elem(), true
	}
	switch e {
	case typGUID:
		return ua.TypeIDGUID, ptr, true
	case typNodeID:
		return ua.TypeIDNodeID, ptr, true
	case typExpID:
		return ua.TypeIDExpandedNodeID, ptr, true
	case typQName:
		return ua.TypeIDQualifiedName, ptr, true
	case typLText:
		return ua.TypeIDLocalizedText, ptr, true
	case typExtObj:
		return ua.TypeIDExtensionObject, ptr, true
	case typDataVal:
		return ua.TypeIDDataValue, ptr, true
	case typVariant:
		return ua.TypeIDVariant, ptr, true
	case typDiagInfo:
		return ua.TypeIDDiagnosticInfo, ptr, true
	}
	return 0, false, false
}

// fill sets v, a settable value of any type the codecs support, to a random
// value.
func (g *valueGen) fill(v reflect.Value, depth int) {
	t := v.Type()
	switch t {
	case typTime:
		v.Set(reflect.ValueOf(g.time()))
		return
	case typBytes:
		// Unlike in a Variant, a null or empty ByteString field survives
		// the binary encoding and must survive JSON and XML as well.
		switch g.r.Intn(6) {
		case 0:
			v.SetBytes([]byte{})
		case 1:
		default:
			v.SetBytes(g.bytes())
		}
		return
	case typXML:
		v.Set(reflect.ValueOf(g.scalar(ua.TypeIDXMLElement, depth)))
		return
	case typStatus:
		v.SetUint(uint64(g.r.Uint32()))
		return
	}
	if typ, ptr, ok := builtinOf(t); ok {
		val := reflect.ValueOf(g.scalar(typ, depth))
		if !ptr {
			val = val.Elem()
		}
		v.Set(val)
		return
	}
	switch t.Kind() {
	case reflect.Pointer:
		if t.Elem().Kind() != reflect.Struct {
			return
		}
		// Always allocated: the binary encoder writes a nil structure as
		// its zero value, but refuses the nil ExpandedNodeId that may hide
		// in it.
		p := reflect.New(t.Elem())
		g.fill(p.Elem(), depth+1)
		v.Set(p)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				g.fill(v.Field(i), depth)
			}
		}
	case reflect.Slice:
		n := g.r.Intn(4) - 1
		if n < 0 || depth >= g.maxDepth+2 {
			return // null array
		}
		s := reflect.MakeSlice(t, n, n)
		for i := 0; i < n; i++ {
			g.fill(s.Index(i), depth+1)
		}
		v.Set(s)
	case reflect.Bool:
		v.SetBool(g.r.Intn(2) == 0)
	case reflect.String:
		v.SetString(g.str())
	case reflect.Float32:
		v.SetFloat(g.float(32))
	case reflect.Float64:
		v.SetFloat(g.float(64))
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if t.PkgPath() != "" { // an enumeration
			v.SetInt(int64(g.r.Intn(4)))
			return
		}
		v.SetInt(int64(g.r.Uint64()) >> (64 - t.Bits()))
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if t.PkgPath() != "" { // an enumeration or option set
			v.SetUint(uint64(g.r.Intn(4)))
			return
		}
		v.SetUint(g.r.Uint64() >> (64 - t.Bits()))
	default:
	}
}

// item is one shared value: every goroutine of a scenario reads it, none may
// change it.
type item struct {
	name string
	// val is what the encoders are given: a pointer to a structure
	// (generated, custom or built-in) or a plain value (slice, scalar,
	// enumeration).
	val any
	// bin is the binary encoding of val. Two values are the same if their
	// binary encodings are; that comparison is exact and independent of
	// the codecs under test.
	bin []byte
}

func newItem(name string, val any) (*item, error) {
	bin, err := ua.Encode(val)
	if err != nil {
		return nil, fmt.Errorf("%s: binary encode: %w", name, err)
	}
	return &item{name: name, val: val, bin: bin}, nil
}

// target returns a pointer to a new value of the type of the item, for the
// decoders.
func (it *item) target() any {
	t := reflect.TypeOf(it.val)
	if t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct {
		return reflect.New(t.Elem()).Interface()
	}
	return reflect.New(t).Interface()
}

// binaryOf returns the binary encoding of a decoded target.
func (it *item) binaryOf(target any) ([]byte, error) {
	t := reflect.TypeOf(it.val)
	if t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct {
		return ua.Encode(target)
	}
	return ua.Encode(reflect.ValueOf(target).Elem().Interface())
}

// canonical returns v (a pointer to a structure) the way the binary decoder
// produces it.
func canonical(v any) (any, error) {
	bin, err := ua.Encode(v)
	if err != nil {
		return nil, err
	}
	out := reflect.New(reflect.TypeOf(v).Elem()).Interface()
	if _, err := ua.Decode(bin, out); err != nil {
		return nil, err
	}
	return out, nil
}

// buildItems returns the shared values for a seed: one filled instance of
// every structure the codecs know (several hundred distinct types), Variants
// of every built-in type as scalar, array and matrix, DataValues,
// ExtensionObjects with generated and custom bodies, and top-level arrays,
// scalars and enumerations. The result is the same for the same seed in
// every process.
func buildItems(seed int64) ([]*item, error) {
	var items []*item
	add := func(name string, val any) error {
		it, err := newItem(name, val)
		if err != nil {
			return err
		}
		items = append(items, it)
		return nil
	}
	addStruct := func(name string, val any) error {
		c, err := canonical(val)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return add(name, c)
	}

	for _, zero := range testhook.CodecStructs() {
		t := reflect.TypeOf(zero).Elem()
		// Only the types every process has: other tests of this package
		// register types of their own while they run.
		if pkg := t.PkgPath(); !strings.HasSuffix(pkg, "/ua") && !strings.HasSuffix(pkg, "/customtypes") {
			continue
		}
		// Seeded by the name, not by the position in a list that grows
		// with every registration.
		h := fnv.New64a()
		_, _ = h.Write([]byte(t.String()))
		g := &valueGen{r: rand.New(rand.NewSource(seed ^ int64(h.Sum64()))), maxDepth: 1}
		v := reflect.New(t)
		g.fill(v.Elem(), 0)
		if err := addStruct("struct/"+t.Name(), v.Interface()); err != nil {
			return nil, err
		}
	}

	g := &valueGen{r: rand.New(rand.NewSource(seed ^ 0x5eed)), maxDepth: 2}
	for _, typ := range variantTypes {
		for shape, name := range []string{"scalar", "array", "", "matrix"} {
			if name == "" || (typ == ua.TypeIDVariant && shape == 0) || (typ == ua.TypeIDByte && shape != 0) {
				continue
			}
			if err := addStruct(fmt.Sprintf("variant/%d/%s", typ, name), g.variantOf(typ, shape, 0)); err != nil {
				return nil, err
			}
		}
	}
	for i := 0; i < 12; i++ {
		if err := addStruct(fmt.Sprintf("datavalue/%d", i), g.dataValue(0)); err != nil {
			return nil, err
		}
		eo := g.extensionObject(0)
		if eo.Value == nil {
			continue
		}
		if err := addStruct(fmt.Sprintf("extobj/%d", i), eo); err != nil {
			return nil, err
		}
	}

	// Top-level arrays (also nested ones), scalars and enumerations.
	nested := [][]int32{{1, 2, 3}, {}, {-4}}
	variants := []*ua.Variant{g.variantOf(ua.TypeIDInt32, 3, 0), g.variantOf(ua.TypeIDString, 1, 0), g.variantOf(ua.TypeIDExtensionObject, 1, 0)}
	for i, v := range variants {
		c, err := canonical(v)
		if err != nil {
			return nil, err
		}
		variants[i] = c.(*ua.Variant)
	}
	enum := customtypes.MyEnumRunning
	for name, val := range map[string]any{
		"top/int32s":     []int32{1, -2, math.MaxInt32},
		"top/nested":     nested,
		"top/strings":    []string{"a", "", g.str()},
		"top/nodeids":    []*ua.NodeID{g.nodeID(0), g.nodeID(2), numericNodeID(0, 0)},
		"top/variants":   variants,
		"top/string":     "x<&>\"y",
		"top/double":     math.Inf(-1),
		"top/time":       g.time(),
		"top/status":     ua.StatusBadNodeIDUnknown,
		"top/bytes":      []byte{0, 1, 2, 0xff},
		"top/enum":       ua.NodeClassVariable,
		"top/customenum": enum,
		"top/enums":      []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt},
	} {
		if err := add(name, val); err != nil {
			return nil, err
		}
	}
	// A map has no order; the list must be the same in every process.
	sortItems(items)
	return items, nil
}
