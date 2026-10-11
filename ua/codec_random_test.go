// SPDX-License-Identifier: MIT

package ua

import (
	"math"
	"math/rand"
	"reflect"
	"time"

	"pgregory.net/rapid"
)

// randSource abstracts the source of randomness so that the same value
// generator serves rapid (shrinking property tests) and math/rand (the
// deterministic sweep over every registered structure).
type randSource interface {
	intn(n int) int // [0, n)
	u64() uint64
}

type mathRand struct{ r *rand.Rand }

func (m mathRand) intn(n int) int { return m.r.Intn(n) }
func (m mathRand) u64() uint64    { return m.r.Uint64() }

type rapidRand struct{ t *rapid.T }

func (r rapidRand) intn(n int) int { return rapid.IntRange(0, n-1).Draw(r.t, "n") }
func (r rapidRand) u64() uint64    { return rapid.Uint64().Draw(r.t, "u64") }

// valueGen produces random values in the canonical form of this library:
// the form a value has after it was decoded from the binary encoding. That
// is the precondition of the binary -> JSON/XML -> binary identity.
type valueGen struct {
	src randSource
	// xmlSafe restricts XmlElement values to well-formed markup.
	maxDepth int
}

var genRunes = []rune("abcXYZ019 _-.:;=/\\\"'<>&{}[]\t\n\räöü€日本語🙂")

func (g *valueGen) str() string {
	n := g.src.intn(8)
	out := make([]rune, n)
	for i := range out {
		out[i] = genRunes[g.src.intn(len(genRunes))]
	}
	return string(out)
}

func (g *valueGen) bytes() []byte {
	if g.src.intn(5) == 0 {
		return nil
	}
	b := make([]byte, 1+g.src.intn(9))
	for i := range b {
		b[i] = byte(g.src.u64())
	}
	return b
}

func (g *valueGen) time() time.Time {
	switch g.src.intn(6) {
	case 0:
		return time.Time{}
	case 1: // far outside of the int64 nanosecond range
		return time.Date(9000+g.src.intn(999), 3, 4, 5, 6, 7, 800, time.UTC)
	case 2:
		return time.Date(1601+g.src.intn(80), 1, 2, 3, 4, 5, 600, time.UTC)
	}
	secs := int64(g.src.u64() % (4 * 365 * 24 * 3600 * 25))
	return time.Unix(secs, int64(g.src.intn(1e7))*100).UTC()
}

func (g *valueGen) guid() *GUID {
	d4 := make([]byte, 8)
	for i := range d4 {
		d4[i] = byte(g.src.u64())
	}
	return &GUID{Data1: uint32(g.src.u64()), Data2: uint16(g.src.u64()), Data3: uint16(g.src.u64()), Data4: d4}
}

func (g *valueGen) nodeID() *NodeID {
	ns := uint16(0)
	if g.src.intn(2) == 0 {
		ns = uint16(g.src.intn(4))
	}
	switch g.src.intn(5) {
	case 0:
		return NewStringNodeID(ns, "s"+g.str())
	case 1:
		return &NodeID{mask: NodeIDTypeGUID, ns: ns, gid: g.guid()}
	case 2:
		b := g.bytes()
		if b == nil {
			b = []byte{1}
		}
		return NewByteStringNodeID(ns, b)
	case 3:
		return newNumericNodeIDCompact(ns, uint32(g.src.u64()))
	}
	return newNumericNodeIDCompact(ns, uint32(g.src.intn(70000)))
}

func (g *valueGen) expandedNodeID() *ExpandedNodeID {
	uri, idx := "", uint32(0)
	if g.src.intn(3) == 0 {
		uri = "urn:test:" + string(rune('a'+g.src.intn(5)))
	}
	if g.src.intn(3) == 0 {
		idx = uint32(1 + g.src.intn(5))
	}
	n := g.nodeID()
	if uri != "" {
		// A namespace URI replaces the index (Part 6 §5.2.2.10).
		n.ns = 0
		if n.Type() == NodeIDTypeFourByte || n.Type() == NodeIDTypeNumeric {
			n = newNumericNodeIDCompact(0, n.nid)
		}
	}
	return NewExpandedNodeID(n, uri, idx)
}

func (g *valueGen) float(bits int) float64 {
	switch g.src.intn(8) {
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
		f := math.Float32frombits(uint32(g.src.u64()))
		if f != f {
			return math.NaN()
		}
		return float64(f)
	}
	f := math.Float64frombits(g.src.u64())
	if f != f {
		return math.NaN()
	}
	return f
}

func (g *valueGen) localizedText() *LocalizedText {
	l := &LocalizedText{}
	if g.src.intn(2) == 0 {
		l.Locale = "en-US"
	}
	if g.src.intn(4) != 0 {
		l.Text = g.str()
	}
	l.UpdateMask()
	return l
}

func (g *valueGen) diagnosticInfo(depth int) *DiagnosticInfo {
	d := &DiagnosticInfo{
		SymbolicID:      int32(g.src.intn(3)),
		NamespaceURI:    int32(g.src.intn(3)),
		Locale:          int32(g.src.intn(3)),
		LocalizedText:   int32(g.src.intn(3)) - 1,
		AdditionalInfo:  g.str(),
		InnerStatusCode: StatusCode(g.src.intn(2)) * StatusBadInternalError,
	}
	if depth < 2 && g.src.intn(2) == 0 {
		d.InnerDiagnosticInfo = g.diagnosticInfo(depth + 1)
	}
	d.UpdateMask()
	return d
}

func (g *valueGen) dataValue(depth int) *DataValue {
	d := &DataValue{
		Status:            StatusCode(g.src.intn(2)) * StatusBadNodeIDUnknown,
		SourceTimestamp:   g.time(),
		ServerTimestamp:   g.time(),
		SourcePicoseconds: uint16(g.src.intn(3)),
		ServerPicoseconds: uint16(g.src.intn(3)),
	}
	// The binary encoding cannot hold a DateTime before 1601.
	if isNullDateTime(d.SourceTimestamp) {
		d.SourceTimestamp = time.Time{}
	}
	if isNullDateTime(d.ServerTimestamp) {
		d.ServerTimestamp = time.Time{}
	}
	if v := g.variant(depth + 1); v.Type() != TypeIDNull && g.src.intn(4) != 0 {
		d.Value = v
	}
	d.UpdateMask()
	return d
}

// extensionObjectBodies are the structures used as ExtensionObject bodies in
// random Variants. They cover nesting, arrays, enumerations and Variants.
var extensionObjectBodies = []reflect.Type{
	reflect.TypeOf(Argument{}),
	reflect.TypeOf(EUInformation{}),
	reflect.TypeOf(Range{}),
	reflect.TypeOf(KeyValuePair{}),
	reflect.TypeOf(EnumValueType{}),
	reflect.TypeOf(ServerStatusDataType{}),
	reflect.TypeOf(BuildInfo{}),
	reflect.TypeOf(UserTokenPolicy{}),
}

func (g *valueGen) extensionObject(depth int) *ExtensionObject {
	if depth >= g.maxDepth || g.src.intn(6) == 0 {
		return NewExtensionObject(nil)
	}
	p := reflect.New(extensionObjectBodies[g.src.intn(len(extensionObjectBodies))])
	if eotypes.Lookup(p.Interface()) == nil {
		panic("not a registered extension object: " + p.Type().String())
	}
	g.fill(p.Elem(), depth+1)
	return NewExtensionObject(p.Interface())
}

// scalar returns a random value of a built-in type as a Variant holds it.
func (g *valueGen) scalar(typ TypeID, depth int) interface{} {
	switch typ {
	case TypeIDBoolean:
		return g.src.intn(2) == 0
	case TypeIDSByte:
		return int8(g.src.u64())
	case TypeIDByte:
		return uint8(g.src.u64())
	case TypeIDInt16:
		return int16(g.src.u64())
	case TypeIDUint16:
		return uint16(g.src.u64())
	case TypeIDInt32:
		return int32(g.src.u64())
	case TypeIDUint32:
		return uint32(g.src.u64())
	case TypeIDInt64:
		return int64(g.src.u64())
	case TypeIDUint64:
		return g.src.u64()
	case TypeIDFloat:
		return float32(g.float(32))
	case TypeIDDouble:
		return g.float(64)
	case TypeIDString:
		return g.str()
	case TypeIDDateTime:
		t := g.time()
		if isNullDateTime(t) {
			return time.Time{}
		}
		return t
	case TypeIDGUID:
		return g.guid()
	case TypeIDByteString:
		return g.bytes()
	case TypeIDXMLElement:
		if g.src.intn(3) == 0 {
			return XMLElement("")
		}
		return XMLElement("<a x=\"1\"><b>t &amp; u</b><c/></a>")
	case TypeIDNodeID:
		return g.nodeID()
	case TypeIDExpandedNodeID:
		return g.expandedNodeID()
	case TypeIDStatusCode:
		return StatusCode(g.src.u64())
	case TypeIDQualifiedName:
		return &QualifiedName{NamespaceIndex: uint16(g.src.intn(3)), Name: g.str()}
	case TypeIDLocalizedText:
		return g.localizedText()
	case TypeIDExtensionObject:
		return g.extensionObject(depth)
	case TypeIDDataValue:
		return g.dataValue(depth)
	case TypeIDVariant:
		return g.variant(depth + 1)
	case TypeIDDiagnosticInfo:
		return g.diagnosticInfo(0)
	default:
		panic("unreachable")
	}
}

// variant returns a random scalar, array or matrix Variant. Null arrays are
// not generated: JSON cannot tell them from empty arrays.
func (g *valueGen) variant(depth int) *Variant {
	if depth > g.maxDepth || g.src.intn(12) == 0 {
		return &Variant{}
	}
	typ := TypeID(1 + g.src.intn(25))
	shape := g.src.intn(4)
	if typ == TypeIDVariant && shape == 0 {
		shape = 1 // a Variant cannot directly hold a Variant
	}
	if shape == 0 {
		return MustVariant(g.scalar(typ, depth))
	}
	dims := []int{g.src.intn(4)}
	if shape == 3 {
		dims = []int{1 + g.src.intn(2), 1 + g.src.intn(3)}
		if g.src.intn(3) == 0 {
			dims = append(dims, 1+g.src.intn(2))
		}
	}
	return MustVariant(g.array(typ, dims, depth).Interface())
}

func (g *valueGen) array(typ TypeID, dims []int, depth int) reflect.Value {
	if len(dims) == 1 {
		st, _ := variantSliceType(typ)
		s := reflect.MakeSlice(st, dims[0], dims[0])
		for i := 0; i < dims[0]; i++ {
			s.Index(i).Set(reflect.ValueOf(g.scalar(typ, depth)))
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

// fill sets v, a settable value of any type the codecs support, to a random
// value.
func (g *valueGen) fill(v reflect.Value, depth int) {
	t := v.Type()
	k := kindOf(t)
	switch k {
	case kindInvalid:
		return
	case kindEnum:
		n := g.src.u64()
		if ei := codecTypes.enumInfo(t); ei != nil && len(ei.values) > 0 && g.src.intn(4) != 0 {
			n = uint64(ei.values[g.src.intn(len(ei.values))].value)
		}
		if v.CanInt() {
			v.SetInt(int64(n) % (1 << (t.Bits() - 1)))
		} else {
			v.SetUint(n & (1<<t.Bits() - 1))
		}
		return
	case kindStructPtr:
		if depth >= g.maxDepth+2 {
			v.Set(zeroElement(t)) // nil unless the binary encoder needs it
			return
		}
		p := reflect.New(t.Elem())
		g.fill(p.Elem(), depth+1)
		v.Set(p)
		return
	case kindStruct:
		for i := 0; i < v.NumField(); i++ {
			g.fill(v.Field(i), depth)
		}
		return
	case kindArray:
		n := g.src.intn(4) - 1
		if n < 0 || depth >= g.maxDepth+2 {
			return // null array
		}
		s := reflect.MakeSlice(t, n, n)
		for i := 0; i < n; i++ {
			g.fill(s.Index(i), depth+1)
		}
		v.Set(s)
		return
	}
	typ := TypeID(k)
	if typ == TypeIDByteString && v.Kind() == reflect.Slice {
		// Unlike in a Variant, an empty ByteString field survives the
		// binary encoding and must survive JSON and XML as well.
		switch g.src.intn(6) {
		case 0:
			v.SetBytes([]byte{})
		default:
			v.SetBytes(g.bytes())
		}
		return
	}
	val := reflect.ValueOf(g.scalar(typ, depth))
	if v.Kind() == reflect.Struct && val.Kind() == reflect.Pointer {
		v.Set(val.Elem())
		return
	}
	if val.Type() != t {
		val = val.Convert(t)
	}
	v.Set(val)
}
