// SPDX-License-Identifier: MIT

package server

import (
	"reflect"
	"regexp"
	"strings"

	"github.com/otfabric/go-opcua/ua"
)

// tvl is a three-valued logic result (TRUE / FALSE / NULL) as required by the
// OPC UA ContentFilter evaluation rules (Part 4, §7.4).
type tvl uint8

const (
	tvlFalse tvl = iota
	tvlTrue
	tvlNull
)

func boolTVL(b bool) tvl {
	if b {
		return tvlTrue
	}
	return tvlFalse
}

// filterEvaluator evaluates a ContentFilter against a single candidate node.
//
// Every element evaluates to a *ua.Variant. A nil variant represents the NULL
// result; a Boolean variant represents TRUE/FALSE for the logical operators.
type filterEvaluator struct {
	srv      *Server
	node     *Node
	nodeID   *ua.NodeID
	typeDef  *ua.NodeID
	elements []*ua.ContentFilterElement
	visiting []bool // cycle detection over the element tree
}

// operandArity maps each operator to its required operand count. A negative
// value means "at least abs(n) operands".
var operandArity = map[ua.FilterOperator]int{
	ua.FilterOperatorEquals:             2,
	ua.FilterOperatorIsNull:             1,
	ua.FilterOperatorGreaterThan:        2,
	ua.FilterOperatorLessThan:           2,
	ua.FilterOperatorGreaterThanOrEqual: 2,
	ua.FilterOperatorLessThanOrEqual:    2,
	ua.FilterOperatorLike:               2,
	ua.FilterOperatorNot:                1,
	ua.FilterOperatorBetween:            3,
	ua.FilterOperatorInList:             -2,
	ua.FilterOperatorAnd:                2,
	ua.FilterOperatorOr:                 2,
	ua.FilterOperatorCast:               2,
	ua.FilterOperatorInView:             1,
	ua.FilterOperatorOfType:             1,
	ua.FilterOperatorRelatedTo:          -3,
	ua.FilterOperatorBitwiseAnd:         2,
	ua.FilterOperatorBitwiseOr:          2,
}

// evalFilter evaluates the WhereClause of a Query for one node. A nil or empty
// filter matches every node (TRUE).
func evalFilter(srv *Server, node *Node, filter *ua.ContentFilter) tvl {
	if filter == nil || len(filter.Elements) == 0 {
		return tvlTrue
	}
	ev := &filterEvaluator{
		srv:      srv,
		node:     node,
		nodeID:   node.ID(),
		typeDef:  nodeTypeDefinition(node),
		elements: filter.Elements,
		visiting: make([]bool, len(filter.Elements)),
	}
	v, _ := ev.evalElement(0)
	return variantTVL(v)
}

// validateFilter performs a structural validation pass without evaluating the
// filter against any node. It returns a ContentFilterResult with a per-element
// and per-operand status, and a boolean indicating whether the filter is sound
// enough to be evaluated.
func validateFilter(filter *ua.ContentFilter) (*ua.ContentFilterResult, bool) {
	if filter == nil || len(filter.Elements) == 0 {
		return nil, true
	}

	ok := true
	res := &ua.ContentFilterResult{
		ElementResults:         make([]*ua.ContentFilterElementResult, len(filter.Elements)),
		ElementDiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	for i, el := range filter.Elements {
		er := &ua.ContentFilterElementResult{StatusCode: ua.StatusGood}

		if _, known := operandArity[el.FilterOperator]; !known {
			er.StatusCode = ua.StatusBadFilterOperatorInvalid
			ok = false
		} else if !validArity(el.FilterOperator, len(el.FilterOperands)) {
			er.StatusCode = ua.StatusBadFilterOperandCountMismatch
			ok = false
		}

		er.OperandStatusCodes = make([]ua.StatusCode, len(el.FilterOperands))
		er.OperandDiagnosticInfos = []*ua.DiagnosticInfo{}
		for j, op := range el.FilterOperands {
			st := validateOperand(filter, i, op)
			er.OperandStatusCodes[j] = st
			if st != ua.StatusGood {
				if er.StatusCode == ua.StatusGood {
					er.StatusCode = ua.StatusBadFilterOperandInvalid
				}
				ok = false
			}
		}
		res.ElementResults[i] = er
	}

	return res, ok
}

func validArity(op ua.FilterOperator, n int) bool {
	want := operandArity[op]
	if want < 0 {
		return n >= -want
	}
	return n == want
}

// validateOperand checks that an operand decodes to a known operand type and,
// for element operands, references a valid forward element (no cycles).
func validateOperand(filter *ua.ContentFilter, elemIdx int, op *ua.ExtensionObject) ua.StatusCode {
	if op == nil || op.Value == nil {
		return ua.StatusBadFilterOperandInvalid
	}
	switch v := operandConcrete(op).(type) {
	case *ua.LiteralOperand:
		if v.Value == nil {
			return ua.StatusBadFilterLiteralInvalid
		}
		return ua.StatusGood
	case *ua.ElementOperand:
		if int(v.Index) >= len(filter.Elements) || int(v.Index) <= elemIdx {
			// Element operands must reference a later element to keep the
			// tree acyclic and forward-only.
			return ua.StatusBadFilterElementInvalid
		}
		return ua.StatusGood
	case *ua.AttributeOperand:
		return ua.StatusGood
	case *ua.SimpleAttributeOperand:
		return ua.StatusGood
	default:
		return ua.StatusBadFilterOperandInvalid
	}
}

// operandConcrete normalizes an operand ExtensionObject value to a pointer to
// its concrete operand type, handling both pointer and value forms.
func operandConcrete(op *ua.ExtensionObject) interface{} {
	switch v := op.Value.(type) {
	case *ua.LiteralOperand:
		return v
	case ua.LiteralOperand:
		return &v
	case *ua.ElementOperand:
		return v
	case ua.ElementOperand:
		return &v
	case *ua.AttributeOperand:
		return v
	case ua.AttributeOperand:
		return &v
	case *ua.SimpleAttributeOperand:
		return v
	case ua.SimpleAttributeOperand:
		return &v
	default:
		return nil
	}
}

// evalElement evaluates element i and returns its value (nil = NULL) and a
// status describing evaluation problems.
func (ev *filterEvaluator) evalElement(i int) (*ua.Variant, ua.StatusCode) {
	if i < 0 || i >= len(ev.elements) {
		return nil, ua.StatusBadFilterElementInvalid
	}
	if ev.visiting[i] {
		return nil, ua.StatusBadFilterElementInvalid
	}
	ev.visiting[i] = true
	defer func() { ev.visiting[i] = false }()

	el := ev.elements[i]
	if !validArity(el.FilterOperator, len(el.FilterOperands)) {
		return nil, ua.StatusBadFilterOperandCountMismatch
	}

	switch el.FilterOperator {
	case ua.FilterOperatorAnd:
		a := variantTVL(ev.operand(el, 0))
		b := variantTVL(ev.operand(el, 1))
		return tvlVariant(andTVL(a, b)), ua.StatusGood
	case ua.FilterOperatorOr:
		a := variantTVL(ev.operand(el, 0))
		b := variantTVL(ev.operand(el, 1))
		return tvlVariant(orTVL(a, b)), ua.StatusGood
	case ua.FilterOperatorNot:
		return tvlVariant(notTVL(variantTVL(ev.operand(el, 0)))), ua.StatusGood

	case ua.FilterOperatorEquals:
		return ev.compareEq(el)
	case ua.FilterOperatorGreaterThan:
		return ev.compareOrd(el, func(c int) bool { return c > 0 })
	case ua.FilterOperatorLessThan:
		return ev.compareOrd(el, func(c int) bool { return c < 0 })
	case ua.FilterOperatorGreaterThanOrEqual:
		return ev.compareOrd(el, func(c int) bool { return c >= 0 })
	case ua.FilterOperatorLessThanOrEqual:
		return ev.compareOrd(el, func(c int) bool { return c <= 0 })

	case ua.FilterOperatorIsNull:
		return tvlVariant(boolTVL(ev.operand(el, 0) == nil)), ua.StatusGood

	case ua.FilterOperatorLike:
		return ev.evalLike(el)

	case ua.FilterOperatorBetween:
		return ev.evalBetween(el)

	case ua.FilterOperatorInList:
		return ev.evalInList(el)

	case ua.FilterOperatorCast:
		return ev.evalCast(el)

	case ua.FilterOperatorOfType:
		return ev.evalOfType(el)

	case ua.FilterOperatorInView:
		return ev.evalInView(el)

	case ua.FilterOperatorRelatedTo:
		return ev.evalRelatedTo(el)

	case ua.FilterOperatorBitwiseAnd:
		return ev.evalBitwise(el, true)
	case ua.FilterOperatorBitwiseOr:
		return ev.evalBitwise(el, false)

	default:
		return nil, ua.StatusBadFilterOperatorUnsupported
	}
}

// operand resolves operand j of element el to a *ua.Variant (nil = NULL).
func (ev *filterEvaluator) operand(el *ua.ContentFilterElement, j int) *ua.Variant {
	if j >= len(el.FilterOperands) {
		return nil
	}
	v, _ := ev.resolveOperand(el.FilterOperands[j])
	return v
}

func (ev *filterEvaluator) resolveOperand(op *ua.ExtensionObject) (*ua.Variant, ua.StatusCode) {
	if op == nil {
		return nil, ua.StatusBadFilterOperandInvalid
	}
	switch v := operandConcrete(op).(type) {
	case *ua.LiteralOperand:
		return v.Value, ua.StatusGood
	case *ua.ElementOperand:
		return ev.evalElement(int(v.Index))
	case *ua.AttributeOperand:
		return ev.resolveAttributeOperand(v), ua.StatusGood
	case *ua.SimpleAttributeOperand:
		return ev.resolveSimpleAttributeOperand(v), ua.StatusGood
	default:
		return nil, ua.StatusBadFilterOperandInvalid
	}
}

func (ev *filterEvaluator) resolveAttributeOperand(op *ua.AttributeOperand) *ua.Variant {
	start := ev.nodeID
	if op.NodeID != nil && !op.NodeID.Equal(ua.NewTwoByteNodeID(0)) {
		start = op.NodeID
	}
	target := start
	if op.BrowsePath != nil && len(op.BrowsePath.Elements) > 0 {
		resolved, st := ev.srv.resolveRelativePath(start, op.BrowsePath)
		if st != ua.StatusGood {
			return nil
		}
		target = resolved
	}
	return ev.readAttribute(target, op.AttributeID)
}

func (ev *filterEvaluator) resolveSimpleAttributeOperand(op *ua.SimpleAttributeOperand) *ua.Variant {
	target := ev.nodeID
	if len(op.BrowsePath) > 0 {
		rp := &ua.RelativePath{Elements: make([]*ua.RelativePathElement, len(op.BrowsePath))}
		for i, qn := range op.BrowsePath {
			rp.Elements[i] = &ua.RelativePathElement{
				IncludeSubtypes: true,
				TargetName:      qn,
			}
		}
		resolved, st := ev.srv.resolveRelativePath(target, rp)
		if st != ua.StatusGood {
			return nil
		}
		target = resolved
	}
	attr := op.AttributeID
	if attr == 0 {
		attr = ua.AttributeIDValue
	}
	return ev.readAttribute(target, attr)
}

func (ev *filterEvaluator) readAttribute(nodeID *ua.NodeID, attr ua.AttributeID) *ua.Variant {
	if nodeID == nil {
		return nil
	}
	ns, err := ev.srv.Namespace(int(nodeID.Namespace()))
	if err != nil {
		return nil
	}
	dv := ns.Attribute(nodeID, attr)
	if dv == nil || dv.Value == nil {
		return nil
	}
	if dv.Status != ua.StatusOK && dv.Status != ua.StatusGood {
		return nil
	}
	return dv.Value
}

// --- comparison operators -------------------------------------------------

func (ev *filterEvaluator) compareEq(el *ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	a := ev.operand(el, 0)
	b := ev.operand(el, 1)
	eq, ok := variantEquals(a, b)
	if !ok {
		return nil, ua.StatusGood // NULL
	}
	return tvlVariant(boolTVL(eq)), ua.StatusGood
}

func (ev *filterEvaluator) compareOrd(el *ua.ContentFilterElement, keep func(int) bool) (*ua.Variant, ua.StatusCode) {
	a := ev.operand(el, 0)
	b := ev.operand(el, 1)
	c, ok := variantOrder(a, b)
	if !ok {
		return nil, ua.StatusGood // NULL
	}
	return tvlVariant(boolTVL(keep(c))), ua.StatusGood
}

func (ev *filterEvaluator) evalBetween(el *ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	a := ev.operand(el, 0)
	lo := ev.operand(el, 1)
	hi := ev.operand(el, 2)
	cLo, ok1 := variantOrder(a, lo)
	cHi, ok2 := variantOrder(a, hi)
	if !ok1 || !ok2 {
		return nil, ua.StatusGood // NULL
	}
	return tvlVariant(boolTVL(cLo >= 0 && cHi <= 0)), ua.StatusGood
}

func (ev *filterEvaluator) evalInList(el *ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	a := ev.operand(el, 0)
	if a == nil {
		return nil, ua.StatusGood
	}
	sawNull := false
	for j := 1; j < len(el.FilterOperands); j++ {
		b := ev.operand(el, j)
		eq, ok := variantEquals(a, b)
		if !ok {
			sawNull = true
			continue
		}
		if eq {
			return tvlVariant(tvlTrue), ua.StatusGood
		}
	}
	if sawNull {
		return nil, ua.StatusGood
	}
	return tvlVariant(tvlFalse), ua.StatusGood
}

func (ev *filterEvaluator) evalLike(el *ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	a := ev.operand(el, 0)
	pat := ev.operand(el, 1)
	if a == nil || pat == nil {
		return nil, ua.StatusGood
	}
	s, ok1 := stringOf(a)
	p, ok2 := stringOf(pat)
	if !ok1 || !ok2 {
		return nil, ua.StatusGood
	}
	re, err := likeToRegexp(p)
	if err != nil {
		return nil, ua.StatusGood
	}
	return tvlVariant(boolTVL(re.MatchString(s))), ua.StatusGood
}

func (ev *filterEvaluator) evalCast(el *ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	src := ev.operand(el, 0)
	typ := ev.operand(el, 1)
	if src == nil || typ == nil {
		return nil, ua.StatusGood
	}
	nid := typ.NodeID()
	if nid == nil {
		return nil, ua.StatusGood
	}
	out := castVariant(src, nid.IntID())
	return out, ua.StatusGood
}

func (ev *filterEvaluator) evalOfType(el *ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	typ := ev.operand(el, 0)
	if typ == nil {
		return tvlVariant(tvlFalse), ua.StatusGood
	}
	nid := typ.NodeID()
	if nid == nil {
		return tvlVariant(tvlFalse), ua.StatusGood
	}
	if ev.typeDef == nil {
		return tvlVariant(tvlFalse), ua.StatusGood
	}
	return tvlVariant(boolTVL(ev.srv.isSubtypeOf(ev.typeDef, nid))), ua.StatusGood
}

func (ev *filterEvaluator) evalInView(el *ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	view := ev.operand(el, 0)
	// Views are not maintained by this server. A null view means "the whole
	// address space", so every node is in view; a specific view matches
	// nothing.
	if view == nil {
		return tvlVariant(tvlTrue), ua.StatusGood
	}
	nid := view.NodeID()
	if nid == nil || nid.Equal(ua.NewTwoByteNodeID(0)) {
		return tvlVariant(tvlTrue), ua.StatusGood
	}
	return tvlVariant(tvlFalse), ua.StatusGood
}

// evalRelatedTo returns TRUE when the candidate node is of the source type
// (operand 0) and can reach a node of the target type (operand 2) via the
// reference type (operand 1) within the given number of hops (operand 3,
// default 1).
func (ev *filterEvaluator) evalRelatedTo(el *ua.ContentFilterElement) (*ua.Variant, ua.StatusCode) {
	srcType := nodeIDOperand(ev.operand(el, 0))
	refType := nodeIDOperand(ev.operand(el, 1))
	tgtType := nodeIDOperand(ev.operand(el, 2))
	if srcType == nil || refType == nil || tgtType == nil {
		return nil, ua.StatusGood
	}
	hops := 1
	if len(el.FilterOperands) > 3 {
		if h := ev.operand(el, 3); h != nil {
			if n, ok := intOf(h); ok && n > 0 {
				hops = int(n)
			}
		}
	}
	if ev.typeDef == nil || !ev.srv.isSubtypeOf(ev.typeDef, srcType) {
		return tvlVariant(tvlFalse), ua.StatusGood
	}
	found := ev.relatedReach(ev.nodeID, refType, tgtType, hops, map[string]bool{})
	return tvlVariant(boolTVL(found)), ua.StatusGood
}

func (ev *filterEvaluator) relatedReach(from *ua.NodeID, refType, tgtType *ua.NodeID, hops int, seen map[string]bool) bool {
	if hops <= 0 || from == nil {
		return false
	}
	if seen[from.String()] {
		return false
	}
	seen[from.String()] = true

	node := ev.srv.Node(from)
	if node == nil {
		return false
	}
	node.mu.RLock()
	refs := make([]*ua.ReferenceDescription, len(node.refs))
	copy(refs, node.refs)
	node.mu.RUnlock()

	for _, r := range refs {
		if r == nil || r.NodeID == nil || !r.IsForward {
			continue
		}
		if !suitableRefType(ev.srv, refType, r.ReferenceTypeID, true) {
			continue
		}
		target := ev.srv.Node(r.NodeID.NodeID)
		if td := nodeTypeDefinition(target); td != nil && ev.srv.isSubtypeOf(td, tgtType) {
			return true
		}
		if ev.relatedReach(r.NodeID.NodeID, refType, tgtType, hops-1, seen) {
			return true
		}
	}
	return false
}

func (ev *filterEvaluator) evalBitwise(el *ua.ContentFilterElement, and bool) (*ua.Variant, ua.StatusCode) {
	a := ev.operand(el, 0)
	b := ev.operand(el, 1)
	if a == nil || b == nil {
		return nil, ua.StatusGood
	}
	ai, ok1 := intOf(a)
	bi, ok2 := intOf(b)
	if !ok1 || !ok2 {
		return nil, ua.StatusGood
	}
	if and {
		return ua.MustVariant(ai & bi), ua.StatusGood
	}
	return ua.MustVariant(ai | bi), ua.StatusGood
}

// --- three-valued logic ---------------------------------------------------

func andTVL(a, b tvl) tvl {
	if a == tvlFalse || b == tvlFalse {
		return tvlFalse
	}
	if a == tvlNull || b == tvlNull {
		return tvlNull
	}
	return tvlTrue
}

func orTVL(a, b tvl) tvl {
	if a == tvlTrue || b == tvlTrue {
		return tvlTrue
	}
	if a == tvlNull || b == tvlNull {
		return tvlNull
	}
	return tvlFalse
}

func notTVL(a tvl) tvl {
	switch a {
	case tvlTrue:
		return tvlFalse
	case tvlFalse:
		return tvlTrue
	default:
		return tvlNull
	}
}

// variantTVL interprets a variant as a three-valued logic result.
func variantTVL(v *ua.Variant) tvl {
	if v == nil || v.Value() == nil {
		return tvlNull
	}
	b, ok := v.Value().(bool)
	if !ok {
		return tvlNull
	}
	return boolTVL(b)
}

// tvlVariant converts a three-valued result back to a variant (NULL -> nil).
func tvlVariant(t tvl) *ua.Variant {
	switch t {
	case tvlTrue:
		return ua.MustVariant(true)
	case tvlFalse:
		return ua.MustVariant(false)
	default:
		return nil
	}
}

// --- value helpers --------------------------------------------------------

// variantEquals compares two operands for equality with implicit conversion.
// ok is false when the comparison is undefined (NULL result).
func variantEquals(a, b *ua.Variant) (bool, bool) {
	if a == nil || b == nil || a.Value() == nil || b.Value() == nil {
		return false, false
	}
	if fa, ok1 := floatOf(a); ok1 {
		if fb, ok2 := floatOf(b); ok2 {
			return fa == fb, true
		}
	}
	if sa, ok1 := a.Value().(string); ok1 {
		if sb, ok2 := b.Value().(string); ok2 {
			return sa == sb, true
		}
	}
	if ba, ok1 := a.Value().(bool); ok1 {
		if bb, ok2 := b.Value().(bool); ok2 {
			return ba == bb, true
		}
	}
	return reflect.DeepEqual(a.Value(), b.Value()), true
}

// variantOrder returns -1/0/1 for a<b / a==b / a>b. ok is false when the
// ordering is undefined (NULL result).
func variantOrder(a, b *ua.Variant) (int, bool) {
	if a == nil || b == nil || a.Value() == nil || b.Value() == nil {
		return 0, false
	}
	if fa, ok1 := floatOf(a); ok1 {
		if fb, ok2 := floatOf(b); ok2 {
			switch {
			case fa < fb:
				return -1, true
			case fa > fb:
				return 1, true
			default:
				return 0, true
			}
		}
	}
	if sa, ok1 := a.Value().(string); ok1 {
		if sb, ok2 := b.Value().(string); ok2 {
			return strings.Compare(sa, sb), true
		}
	}
	return 0, false
}

func floatOf(v *ua.Variant) (float64, bool) {
	switch x := v.Value().(type) {
	case int8:
		return float64(x), true
	case int16:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint8:
		return float64(x), true
	case uint16:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	default:
		return 0, false
	}
}

func intOf(v *ua.Variant) (int64, bool) {
	switch x := v.Value().(type) {
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		return int64(x), true
	default:
		return 0, false
	}
}

func stringOf(v *ua.Variant) (string, bool) {
	s, ok := v.Value().(string)
	return s, ok
}

func nodeIDOperand(v *ua.Variant) *ua.NodeID {
	if v == nil {
		return nil
	}
	if nid := v.NodeID(); nid != nil {
		return nid
	}
	if en := v.ExpandedNodeID(); en != nil {
		return en.NodeID
	}
	return nil
}

// castVariant converts a value to the numeric datatype identified by the
// built-in datatype id. It handles the common built-in scalar types and
// returns nil when the conversion is undefined.
func castVariant(src *ua.Variant, dataType uint32) *ua.Variant {
	switch dataType {
	case 1: // Boolean
		if b, ok := src.Value().(bool); ok {
			return ua.MustVariant(b)
		}
		if f, ok := floatOf(src); ok {
			return ua.MustVariant(f != 0)
		}
	case 6: // Int32
		if f, ok := floatOf(src); ok {
			return ua.MustVariant(int32(f))
		}
	case 8: // Int64
		if f, ok := floatOf(src); ok {
			return ua.MustVariant(int64(f))
		}
	case 7: // UInt32
		if f, ok := floatOf(src); ok {
			return ua.MustVariant(uint32(f))
		}
	case 9: // UInt64
		if f, ok := floatOf(src); ok {
			return ua.MustVariant(uint64(f))
		}
	case 10: // Float
		if f, ok := floatOf(src); ok {
			return ua.MustVariant(float32(f))
		}
	case 11: // Double
		if f, ok := floatOf(src); ok {
			return ua.MustVariant(f)
		}
	case 12: // String
		return ua.MustVariant(src.String())
	}
	return nil
}

// likeToRegexp translates an OPC UA Like pattern into a Go regular expression.
//
// Grammar (Part 4, §7.4.1, Table): % matches zero or more chars, _ matches a
// single char, [] a character set, [^] a negated set, and \ escapes the next
// character.
func likeToRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		case '\\':
			if i+1 < len(runes) {
				i++
				b.WriteString(regexp.QuoteMeta(string(runes[i])))
			} else {
				b.WriteString(regexp.QuoteMeta(string(c)))
			}
		case '[':
			// Copy the character class verbatim, converting a leading ^ into
			// a negated Go class. Find the matching ].
			j := i + 1
			b.WriteString("[")
			if j < len(runes) && runes[j] == '^' {
				b.WriteString("^")
				j++
			}
			for j < len(runes) && runes[j] != ']' {
				if runes[j] == '\\' && j+1 < len(runes) {
					b.WriteString(regexp.QuoteMeta(string(runes[j+1])))
					j += 2
					continue
				}
				b.WriteString(string(runes[j]))
				j++
			}
			b.WriteString("]")
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
