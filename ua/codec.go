// SPDX-License-Identifier: MIT

package ua

import (
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// This file holds what the JSON (Part 6 §5.4) and XML (Part 6 §5.3)
// DataEncodings share: options, limits, and the textual forms of the built-in
// types that are identical in both encodings (NodeId, DateTime, Guid, ...).
//
// Both encodings are DataEncodings only. The transport of this library stays
// OPC UA TCP with the binary encoding; JSON and XML are for tooling, PubSub
// style payloads, NodeSet2 values and gateways.

// JSONForm selects one of the JSON DataEncoding variants of Part 6 §5.4.
type JSONForm int

const (
	// JSONCompact is the Compact encoding of OPC UA 1.05.04 and later. It is
	// the default and what open62541 1.5 reads and writes. Structure fields
	// holding their default value are omitted, enumerations are numbers and
	// a StatusCode carries no symbol.
	JSONCompact JSONForm = iota

	// JSONVerbose is the Verbose encoding of OPC UA 1.05.04 and later: every
	// structure field is written, enumerations are "Name_Value" strings and
	// a StatusCode carries its symbol.
	JSONVerbose

	// JSONLegacyReversible is the reversible encoding of OPC UA 1.04
	// (Part 6 Annex H in 1.05): NodeIds, QualifiedNames, Variants and
	// ExtensionObjects are JSON objects ({"IdType":..}, {"Type":..,"Body":..})
	// and a StatusCode is a number.
	JSONLegacyReversible

	// JSONLegacyNonReversible is the non-reversible encoding of OPC UA 1.04.
	// It drops type information (a Variant is just its value, a
	// LocalizedText just its text) and therefore cannot be decoded.
	JSONLegacyNonReversible
)

// Default limits applied by [DecodeJSON] and [DecodeXML].
const (
	// DefaultCodecMaxDepth bounds the nesting of JSON values / XML elements
	// and of the decoded value. It matches open62541's recursion limit.
	DefaultCodecMaxDepth = 100
)

// CodecOption configures [EncodeJSON], [DecodeJSON], [EncodeXML] and
// [DecodeXML].
type CodecOption func(*codecOptions)

type codecOptions struct {
	form       JSONForm
	namespaces []string
	servers    []string
	indent     string
	maxDepth   int
	maxArray   int
	xmlRoot    string
	xmlNoNS    bool
}

func newCodecOptions(opts []CodecOption) *codecOptions {
	o := &codecOptions{maxDepth: DefaultCodecMaxDepth, maxArray: MaxVariantArrayLength}
	for _, fn := range opts {
		if fn != nil {
			fn(o)
		}
	}
	return o
}

// WithJSONForm selects the JSON variant written by [EncodeJSON]. The default
// is [JSONCompact]. [DecodeJSON] ignores it: it accepts the compact, verbose
// and legacy reversible forms without being told which one it is given.
func WithJSONForm(f JSONForm) CodecOption {
	return func(o *codecOptions) { o.form = f }
}

// WithNamespaceArray provides the NamespaceArray of the server the values
// belong to (index 0 is "http://opcfoundation.org/UA/").
//
// With it the encoders write namespace URIs ("nsu=urn:x;i=1") instead of
// indexes ("ns=2;i=1") for NodeIds, ExpandedNodeIds and QualifiedNames, as
// Part 6 §5.1.12 asks for, and the decoders map the URIs back to indexes.
// Without it namespace indexes are written as they are.
func WithNamespaceArray(uris []string) CodecOption {
	return func(o *codecOptions) { o.namespaces = uris }
}

// WithServerArray provides the ServerArray used to map the ServerIndex of an
// ExpandedNodeId to a server URI ("svu=urn:srv;...") and back.
func WithServerArray(uris []string) CodecOption {
	return func(o *codecOptions) { o.servers = uris }
}

// WithIndent makes the encoders pretty-print with the given indentation.
func WithIndent(indent string) CodecOption {
	return func(o *codecOptions) { o.indent = indent }
}

// WithMaxDepth overrides [DefaultCodecMaxDepth].
func WithMaxDepth(n int) CodecOption {
	return func(o *codecOptions) {
		if n > 0 {
			o.maxDepth = n
		}
	}
}

// WithMaxArrayLength overrides the maximum number of elements of an array in
// a Variant. The default is [MaxVariantArrayLength], the limit of the binary
// decoder.
func WithMaxArrayLength(n int) CodecOption {
	return func(o *codecOptions) {
		if n > 0 {
			o.maxArray = n
		}
	}
}

// WithXMLRootName sets the name of the outermost element written by
// [EncodeXML]. The default is the name of the type ("Int32", "Variant",
// "ReadRequest", ...).
func WithXMLRootName(name string) CodecOption {
	return func(o *codecOptions) { o.xmlRoot = name }
}

// WithoutXMLNamespace makes [EncodeXML] omit the xmlns declaration of
// http://opcfoundation.org/UA/2008/02/Types.xsd on the outermost element, for
// documents that are embedded in an element which already declares it.
func WithoutXMLNamespace() CodecOption {
	return func(o *codecOptions) { o.xmlNoNS = true }
}

func (o *codecOptions) namespaceURI(idx uint16) (string, bool) {
	if idx == 0 || int(idx) >= len(o.namespaces) || o.namespaces[idx] == "" {
		return "", false
	}
	return o.namespaces[idx], true
}

func (o *codecOptions) namespaceIndex(uri string) (uint16, bool) {
	for i, u := range o.namespaces {
		if u == uri && i <= math.MaxUint16 {
			return uint16(i), true
		}
	}
	if uri == "http://opcfoundation.org/UA/" {
		return 0, true
	}
	return 0, false
}

// codecError builds the error returned by the JSON and XML codecs. They all
// wrap a StatusCode so that callers can use errors.Is.
func codecError(code StatusCode, enc, path, format string, args ...interface{}) error {
	if path == "" {
		path = "$"
	}
	return fmt.Errorf("ua: %s: %s: %s: %w", enc, path, fmt.Sprintf(format, args...), code)
}

// ---------------------------------------------------------------------------
// NodeId, ExpandedNodeId, QualifiedName (Part 6 §5.1.12)
// ---------------------------------------------------------------------------

func nodeIDIdentifier(n *NodeID) string {
	switch n.Type() {
	case NodeIDTypeString:
		return "s=" + string(n.bid)
	case NodeIDTypeGUID:
		if n.gid == nil {
			return "g=" + zeroGUID().String()
		}
		return "g=" + guidString(n.gid)
	case NodeIDTypeByteString:
		return "b=" + base64.StdEncoding.EncodeToString(n.bid)
	default:
		return "i=" + strconv.FormatUint(uint64(n.nid), 10)
	}
}

// formatNodeID writes a NodeId in the string form of Part 6 §5.1.12. A nil
// NodeId is the null NodeId "i=0".
func (o *codecOptions) formatNodeID(n *NodeID) string {
	if n == nil {
		return "i=0"
	}
	return o.namespacePrefix(n.ns, "") + nodeIDIdentifier(n)
}

func (o *codecOptions) namespacePrefix(ns uint16, uri string) string {
	if uri == "" {
		uri, _ = o.namespaceURI(ns)
	}
	switch {
	case uri != "":
		return "nsu=" + uri + ";"
	case ns != 0:
		return "ns=" + strconv.FormatUint(uint64(ns), 10) + ";"
	}
	return ""
}

func (o *codecOptions) formatExpandedNodeID(e *ExpandedNodeID) string {
	if e == nil || e.NodeID == nil {
		return "i=0"
	}
	var b strings.Builder
	if e.ServerIndex != 0 {
		if int64(e.ServerIndex) < int64(len(o.servers)) && o.servers[e.ServerIndex] != "" {
			b.WriteString("svu=" + o.servers[e.ServerIndex] + ";")
		} else {
			b.WriteString("svr=" + strconv.FormatUint(uint64(e.ServerIndex), 10) + ";")
		}
	}
	b.WriteString(o.namespacePrefix(e.NodeID.ns, e.NamespaceURI))
	b.WriteString(nodeIDIdentifier(e.NodeID))
	return b.String()
}

// parseExpandedNodeID reads the string form of Part 6 §5.1.12:
//
//	[svr=<index>;|svu=<uri>;][ns=<index>;|nsu=<uri>;]<i|s|g|b>=<identifier>
//
// A namespace URI that is not in the NamespaceArray is kept in the
// NamespaceURI field. ok is false if the text is not a NodeId at all.
func (o *codecOptions) parseExpandedNodeID(s string) (e *ExpandedNodeID, ok bool) {
	var (
		ns     uint16
		nsu    string
		server uint32
	)
	rest := s
	cut := func(prefix string) (string, bool) {
		if !strings.HasPrefix(rest, prefix) {
			return "", false
		}
		i := strings.IndexByte(rest, ';')
		if i < 0 {
			return "", false
		}
		v := rest[len(prefix):i]
		rest = rest[i+1:]
		return v, true
	}
	if v, found := cut("svr="); found {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, false
		}
		server = uint32(n)
	} else if v, found := cut("svu="); found {
		idx := -1
		for i, u := range o.servers {
			if u == v {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, false
		}
		server = uint32(idx)
	}
	if v, found := cut("ns="); found {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, false
		}
		ns = uint16(n)
	} else if v, found := cut("nsu="); found {
		if idx, known := o.namespaceIndex(v); known {
			ns = idx
		} else {
			nsu = v
		}
	}
	if len(rest) < 2 || rest[1] != '=' {
		return nil, false
	}
	var n *NodeID
	val := rest[2:]
	switch rest[0] {
	case 'i':
		v, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, false
		}
		n = newNumericNodeIDCompact(ns, uint32(v))
	case 's':
		n = NewStringNodeID(ns, val)
	case 'g':
		g := parseGUID(val)
		if g == nil {
			return nil, false
		}
		n = &NodeID{mask: NodeIDTypeGUID, ns: ns, gid: g}
	case 'b':
		b, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, false
		}
		n = NewByteStringNodeID(ns, b)
	default:
		return nil, false
	}
	e = &ExpandedNodeID{NodeID: n, NamespaceURI: nsu, ServerIndex: server}
	if nsu != "" {
		n.SetURIFlag()
	}
	if server != 0 {
		n.SetIndexFlag()
	}
	return e, true
}

// newNumericNodeIDCompact returns the smallest binary form that can hold the
// id, like ParseNodeID does. JSON and XML do not carry the binary form.
func newNumericNodeIDCompact(ns uint16, id uint32) *NodeID {
	switch {
	case ns == 0 && id < 256:
		return NewTwoByteNodeID(uint8(id))
	case ns < 256 && id < math.MaxUint16:
		return NewFourByteNodeID(uint8(ns), uint16(id))
	}
	return NewNumericNodeID(ns, id)
}

// parseNodeID reads a NodeId. If the text is not a NodeId or names a
// namespace URI that cannot be mapped to an index, Part 6 §5.4.2.10 asks for
// a String NodeId in namespace 0 that holds the whole text.
func (o *codecOptions) parseNodeID(s string) *NodeID {
	e, ok := o.parseExpandedNodeID(s)
	if !ok || e.NamespaceURI != "" || e.ServerIndex != 0 {
		return NewStringNodeID(0, s)
	}
	return e.NodeID
}

func isNullNodeID(n *NodeID) bool {
	if n == nil {
		return true
	}
	switch n.Type() {
	case NodeIDTypeTwoByte, NodeIDTypeFourByte, NodeIDTypeNumeric:
		return n.ns == 0 && n.nid == 0
	default:
		return false
	}
}

func isNullExpandedNodeID(e *ExpandedNodeID) bool {
	return e == nil || (isNullNodeID(e.NodeID) && e.NamespaceURI == "" && e.ServerIndex == 0)
}

// formatQualifiedName writes "<index>:<name>", "nsu=<uri>;<name>" or just
// the name for namespace 0.
func (o *codecOptions) formatQualifiedName(q *QualifiedName) string {
	if uri, ok := o.namespaceURI(q.NamespaceIndex); ok {
		return "nsu=" + uri + ";" + q.Name
	}
	if q.NamespaceIndex == 0 && !ambiguousName(q.Name) {
		return q.Name
	}
	return strconv.FormatUint(uint64(q.NamespaceIndex), 10) + ":" + q.Name
}

// ambiguousName reports whether a name in namespace 0 would be read back
// with a namespace if it were written without the "0:" prefix.
func ambiguousName(name string) bool {
	if strings.HasPrefix(name, "nsu=") {
		return true
	}
	i := strings.IndexByte(name, ':')
	if i <= 0 {
		return false
	}
	_, err := strconv.ParseUint(name[:i], 10, 16)
	return err == nil
}

func (o *codecOptions) parseQualifiedName(s string) *QualifiedName {
	if strings.HasPrefix(s, "nsu=") {
		if i := strings.IndexByte(s, ';'); i > 0 {
			if idx, ok := o.namespaceIndex(s[4:i]); ok {
				return &QualifiedName{NamespaceIndex: idx, Name: s[i+1:]}
			}
		}
		return &QualifiedName{Name: s}
	}
	if i := strings.IndexByte(s, ':'); i > 0 {
		if n, err := strconv.ParseUint(s[:i], 10, 16); err == nil {
			return &QualifiedName{NamespaceIndex: uint16(n), Name: s[i+1:]}
		}
	}
	return &QualifiedName{Name: s}
}

// ---------------------------------------------------------------------------
// Guid, DateTime, floating point
// ---------------------------------------------------------------------------

func zeroGUID() *GUID { return &GUID{Data4: make([]byte, 8)} }

func guidString(g *GUID) string {
	d4 := make([]byte, 8)
	copy(d4, g.Data4)
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X", g.Data1, g.Data2, g.Data3, d4[:2], d4[2:])
}

func isZeroGUID(g *GUID) bool {
	if g == nil {
		return true
	}
	if g.Data1 != 0 || g.Data2 != 0 || g.Data3 != 0 {
		return false
	}
	for _, b := range g.Data4 {
		if b != 0 {
			return false
		}
	}
	return true
}

// parseGUID reads the 8-4-4-4-12 form of Part 6 §5.1.3, optionally in braces.
func parseGUID(s string) *GUID {
	s = strings.TrimSpace(s)
	if len(s) == 38 && s[0] == '{' && s[37] == '}' {
		s = s[1:37]
	}
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil
	}
	return NewGUID(s)
}

const (
	dateTimeLayout = "2006-01-02T15:04:05.9999999Z"
	dateTimeMax    = "9999-12-31T23:59:59Z"

	// dateTimeMin is what the null DateTime (DateTime.MinValue, binary 0)
	// is written as: the start of the OPC UA epoch, which is the exact
	// value of binary 0 and therefore decodes to the same binary value in
	// every stack. Part 6 §5.4.2.6 names "0001-01-01T00:00:00Z" for values
	// below the range of the platform; that text is accepted when decoding,
	// but open62541 reads it as year 1 - a negative DateTime - instead of
	// the null DateTime, so it is not written.
	dateTimeMin = "1601-01-01T00:00:00Z"
)

var (
	// dateTimeEpoch is the start of the OPC UA DateTime range. Earlier
	// values cannot be told apart from DateTime.MinValue in the binary
	// encoding and are treated as the null DateTime (Part 6 §5.4.2.6).
	dateTimeEpoch = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	dateTimeLimit = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

func isNullDateTime(t time.Time) bool { return !t.After(dateTimeEpoch) }

// formatDateTime writes ISO 8601 with 100ns resolution. Values outside of
// the representable range are clamped as required by Part 6 §5.4.2.6.
func formatDateTime(t time.Time) string {
	switch {
	case isNullDateTime(t):
		return dateTimeMin
	case !t.Before(dateTimeLimit):
		return dateTimeMax
	}
	return t.UTC().Format(dateTimeLayout)
}

func parseDateTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		// xs:dateTime allows the time zone to be left out.
		t, err = time.Parse("2006-01-02T15:04:05.999999999", s)
		if err != nil {
			return time.Time{}, false
		}
	}
	if isNullDateTime(t) {
		return time.Time{}, true
	}
	return t.UTC().Truncate(100 * time.Nanosecond), true
}

// formatFloat writes the shortest decimal that round-trips. The special
// values have no JSON or XML number form and are handled by the callers.
func formatFloat(f float64, bits int) string {
	return strconv.FormatFloat(f, 'g', -1, bits)
}

func parseFloatText(s string, bits int) (float64, bool) {
	switch strings.TrimSpace(s) {
	case "NaN", "-NaN":
		return math.NaN(), true
	case "Infinity", "INF", "+INF":
		return math.Inf(1), true
	case "-Infinity", "-INF":
		return math.Inf(-1), true
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), bits)
	if err != nil {
		// Out of range values saturate to infinity, which is what a
		// decimal beyond the range of the type means.
		if ne, ok := err.(*strconv.NumError); !ok || ne.Err != strconv.ErrRange {
			return 0, false
		}
	}
	return f, true
}

// ---------------------------------------------------------------------------
// Variant helpers
// ---------------------------------------------------------------------------

// flattenVariant returns the elements of a (multi-dimensional) variant array
// in row-major order.
func flattenVariant(v reflect.Value, out []reflect.Value) []reflect.Value {
	if v.Kind() != reflect.Slice || v.Type() == typeBytes {
		return append(out, v)
	}
	for i := 0; i < v.Len(); i++ {
		out = flattenVariant(v.Index(i), out)
	}
	return out
}

// newArrayVariant builds a Variant from a flat slice value and optional
// dimensions, mirroring what Variant.Decode does for the binary encoding.
func newArrayVariant(typ TypeID, vals reflect.Value, dims []int32) (*Variant, error) {
	m := &Variant{mask: byte(typ) | VariantArrayValues, arrayLength: int32(vals.Len())}
	if len(dims) == 0 {
		m.value = vals.Interface()
		return m, nil
	}
	if len(dims) > maxVariantArrayDimensions {
		return nil, StatusBadEncodingLimitsExceeded
	}
	total := int64(1)
	for _, d := range dims {
		if d < 1 {
			return nil, StatusBadEncodingLimitsExceeded
		}
		total *= int64(d)
		if total > math.MaxInt32 {
			return nil, StatusBadEncodingLimitsExceeded
		}
	}
	if total != int64(vals.Len()) {
		return nil, errUnbalancedSlice
	}
	m.mask |= VariantArrayDimensions
	m.arrayDimensionsLength = int32(len(dims))
	m.arrayDimensions = dims
	if len(dims) < 2 {
		m.value = vals.Interface()
		return m, nil
	}
	idims := make([]int, len(dims))
	for i := range dims {
		idims[i] = int(dims[i])
	}
	m.value = split(0, 0, vals.Len(), idims, vals).Interface()
	return m, nil
}

// variantSliceType returns the Go slice type that holds an array of the
// built-in type in a Variant.
func variantSliceType(typ TypeID) (reflect.Type, bool) {
	if typ == TypeIDByte {
		return typeByteArray, true
	}
	et, ok := variantTypeIDToType[typ]
	if !ok || typ == TypeIDNull {
		return nil, false
	}
	return reflect.SliceOf(et), true
}
