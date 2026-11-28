// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/otfabric/go-opcua/internal/goname"
	"github.com/otfabric/go-opcua/internal/nodeset"
)

// objectType is an ObjectType of a family with its Methods.
type objectType struct {
	name    string // BrowseName
	goName  string
	id      uint32
	methods []*method
}

type method struct {
	name      string // BrowseName without the namespace
	goName    string // type name + method name
	id        uint32
	clause    string
	mandatory bool
	in, out   []*arg
}

// arg is a declared Argument with the Go form of its value.
type arg struct {
	name     string
	field    string // Go field name
	dataType uint32 // in namespace 0
	// dataTypeName is the BrowseName of the DataType.
	dataTypeName string
	valueRank    int32
	description  string
	kind         *kind
	// structure is the Go type of a structure DataType ("ua.TrustListDataType").
	structure string
}

// kind is how the generated code holds and checks a value of a built-in
// type (Part 6 §5.1.2).
type kind struct {
	typeID string // the ua.TypeID constant, "" for any
	goType string // the Go type of a scalar
	// get is the generic helper that returns a scalar: scalar, pointer or
	// variant (uamethod/method.go).
	get string
	// pack wraps the field into a Variant, %s is the field.
	pack string
	// array is the Go type of a one-dimensional array, "" if not supported.
	array string
}

// builtinTypes are the built-in types of Part 6 §5.1.2 by the NodeId of
// their DataType. A DataType that is a subtype of one is encoded as it
// (Part 3 §8: UtcTime is a DateTime). A built-in type that is not here, or
// whose array is "", fails the generator for an argument of it: add it when
// a family needs it.
var builtinTypes = map[uint32]*kind{
	1:  {typeID: "ua.TypeIDBoolean", goType: "bool", get: "scalar", pack: "ua.MustVariant(%s)", array: "bool"},
	2:  {typeID: "ua.TypeIDSByte", goType: "int8", get: "scalar", pack: "ua.MustVariant(%s)", array: "int8"},
	3:  {typeID: "ua.TypeIDByte", goType: "uint8", get: "scalar", pack: "ua.MustVariant(%s)"},
	4:  {typeID: "ua.TypeIDInt16", goType: "int16", get: "scalar", pack: "ua.MustVariant(%s)", array: "int16"},
	5:  {typeID: "ua.TypeIDUint16", goType: "uint16", get: "scalar", pack: "ua.MustVariant(%s)", array: "uint16"},
	6:  {typeID: "ua.TypeIDInt32", goType: "int32", get: "scalar", pack: "ua.MustVariant(%s)", array: "int32"},
	7:  {typeID: "ua.TypeIDUint32", goType: "uint32", get: "scalar", pack: "ua.MustVariant(%s)", array: "uint32"},
	8:  {typeID: "ua.TypeIDInt64", goType: "int64", get: "scalar", pack: "ua.MustVariant(%s)", array: "int64"},
	9:  {typeID: "ua.TypeIDUint64", goType: "uint64", get: "scalar", pack: "ua.MustVariant(%s)", array: "uint64"},
	10: {typeID: "ua.TypeIDFloat", goType: "float32", get: "scalar", pack: "ua.MustVariant(%s)", array: "float32"},
	11: {typeID: "ua.TypeIDDouble", goType: "float64", get: "scalar", pack: "ua.MustVariant(%s)", array: "float64"},
	12: {typeID: "ua.TypeIDString", goType: "string", get: "scalar", pack: "ua.MustVariant(%s)", array: "string"},
	13: {typeID: "ua.TypeIDDateTime", goType: "time.Time", get: "scalar", pack: "ua.MustVariant(%s)", array: "time.Time"},
	15: {typeID: "ua.TypeIDByteString", goType: "[]byte", get: "scalar", pack: "ua.MustVariant(%s)", array: "[]byte"},
	17: {typeID: "ua.TypeIDNodeID", goType: "*ua.NodeID", get: "pointer", pack: "ua.MustVariant(nodeID(%s))", array: "*ua.NodeID"},
	19: {typeID: "ua.TypeIDStatusCode", goType: "ua.StatusCode", get: "scalar", pack: "ua.MustVariant(%s)", array: "ua.StatusCode"},
	24: {goType: "*ua.Variant", get: "variant", pack: "orNull(%s)"},
}

// The DataTypes of namespace 0 a DataType can derive from without being
// a subtype of a built-in type of builtinTypes.
const (
	dtStructure   = 22
	dtEnumeration = 29
)

// enumeration is how an enumeration DataType is encoded: an Int32 (Part 6
// §5.2.4).
var enumeration = builtinTypes[6]

// structure is how a structure DataType is encoded: an ExtensionObject
// (Part 6 §5.2.2.15) whose body is the structure.
var structure = &kind{typeID: "ua.TypeIDExtensionObject", get: "structure"}

// abstract is an abstract structure DataType: any ExtensionObject.
var abstract = &kind{typeID: "ua.TypeIDExtensionObject", goType: "*ua.ExtensionObject", get: "pointer", pack: "ua.MustVariant(orNullObject(%s))", array: "*ua.ExtensionObject"}

// load reads the NodeSet of a family and resolves its types.
func load(f family) ([]*objectType, error) {
	raw, err := os.ReadFile(f.NodeSet)
	if err != nil {
		return nil, err
	}
	set, err := nodeset.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.NodeSet, err)
	}
	return resolve(set, f)
}

// resolve finds the ObjectTypes of a family in set.
func resolve(set *nodeset.Set, f family) ([]*objectType, error) {
	byName := map[string]*nodeset.Node{}
	for _, n := range set.OfClass(nodeset.ObjectType) {
		if _, dup := byName[n.BrowseName]; !dup {
			byName[n.BrowseName] = n
		}
	}
	prefix := ""
	if f.Namespace != "" {
		i := indexOf(set.NamespaceURIs, f.Namespace)
		if i < 0 {
			return nil, fmt.Errorf("%s: no namespace %s", f.NodeSet, f.Namespace)
		}
		prefix = strconv.Itoa(i+1) + ":"
	}
	var out []*objectType
	for _, name := range f.Types {
		n := byName[prefix+name]
		if n == nil {
			return nil, fmt.Errorf("%s: no ObjectType %s", f.NodeSet, name)
		}
		t := &objectType{name: name, goName: goname.Format(name)}
		var err error
		if t.id, err = numericID(set, n.NodeID, f.Namespace); err != nil {
			return nil, err
		}
		for _, c := range set.Related(n, nodeset.HasComponent, true) {
			mn := set.Node(c)
			if mn == nil || mn.Class != nodeset.Method {
				continue
			}
			m, err := resolveMethod(set, f, t, mn)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", name, mn.BrowseName, err)
			}
			t.methods = append(t.methods, m)
		}
		if len(t.methods) == 0 {
			return nil, fmt.Errorf("%s: ObjectType %s has no Methods", f.NodeSet, name)
		}
		out = append(out, t)
	}
	return out, nil
}

func resolveMethod(set *nodeset.Set, f family, t *objectType, n *nodeset.Node) (*method, error) {
	name := localName(n.BrowseName)
	m := &method{
		name:      name,
		goName:    t.goName + goname.Format(name),
		clause:    clause(n.Documentation),
		mandatory: set.ModellingRule(n) == nodeset.ModellingRuleMandatory,
	}
	var err error
	if m.id, err = numericID(set, n.NodeID, f.Namespace); err != nil {
		return nil, err
	}
	in, out, err := set.MethodArguments(n)
	if err != nil {
		return nil, err
	}
	for _, x := range []struct {
		src []nodeset.Argument
		dst *[]*arg
	}{{in, &m.in}, {out, &m.out}} {
		seen := map[string]bool{}
		for _, a := range x.src {
			r, err := resolveArg(set, a)
			if err != nil {
				return nil, fmt.Errorf("argument %s: %w", a.Name, err)
			}
			if seen[r.field] {
				return nil, fmt.Errorf("argument %s: field %s twice", a.Name, r.field)
			}
			seen[r.field] = true
			*x.dst = append(*x.dst, r)
		}
	}
	return m, nil
}

func resolveArg(set *nodeset.Set, a nodeset.Argument) (*arg, error) {
	r := &arg{name: a.Name, field: goname.Format(a.Name), valueRank: a.ValueRank, description: a.Description.Text}
	if !goname.IsValidIdent(r.field) {
		return nil, fmt.Errorf("no Go name for %q", a.Name)
	}
	dt, ok := ns0ID(set.Resolve(a.DataType))
	if !ok {
		return nil, fmt.Errorf("DataType %s is not of namespace 0", a.DataType)
	}
	r.dataType = dt
	r.dataTypeName = "i=" + strconv.FormatUint(uint64(dt), 10)
	if n := set.Node(r.dataTypeName); n != nil {
		r.dataTypeName = localName(n.BrowseName)
	}
	k, st, err := kindOf(set, dt)
	if err != nil {
		return nil, err
	}
	r.kind, r.structure = k, st
	switch a.ValueRank {
	case -1:
	case 1:
		if k.array == "" && k != structure {
			return nil, fmt.Errorf("arrays of DataType i=%d are not supported", dt)
		}
	default:
		// Any, ScalarOrOneDimension, OneOrMoreDimensions and more
		// dimensions: the Variant itself.
		r.kind = &kind{typeID: k.typeID, goType: "*ua.Variant", get: "variant", pack: "orNull(%s)"}
		r.structure = ""
	}
	return r, nil
}

// kindOf returns how a value of the DataType dt of namespace 0 is held:
// its built-in type, or for a structure the Go type of package ua.
func kindOf(set *nodeset.Set, dt uint32) (*kind, string, error) {
	seen := map[uint32]bool{}
	for cur := dt; ; {
		if k := builtinTypes[cur]; k != nil {
			return k, "", nil
		}
		switch cur {
		case dtEnumeration:
			return enumeration, "", nil
		case dtStructure:
			n := set.Node("i=" + strconv.FormatUint(uint64(dt), 10))
			if dt == dtStructure || n == nil || n.IsAbstract {
				return abstract, "", nil
			}
			return structure, "ua." + goname.Format(localName(n.BrowseName)), nil
		}
		if seen[cur] {
			return nil, "", fmt.Errorf("DataType i=%d: the supertypes form a loop", dt)
		}
		seen[cur] = true
		n := set.Node("i=" + strconv.FormatUint(uint64(cur), 10))
		if n == nil {
			return nil, "", fmt.Errorf("DataType i=%d is not supported", cur)
		}
		sup, ok := ns0ID(set.SuperType(n))
		if !ok {
			return nil, "", fmt.Errorf("DataType i=%d is not supported", cur)
		}
		cur = sup
	}
}

// numericID returns the numeric identifier of a NodeId of the namespace of
// the family.
func numericID(set *nodeset.Set, nodeID, namespace string) (uint32, error) {
	id := set.Resolve(nodeID)
	want := 0
	if namespace != "" {
		want = indexOf(set.NamespaceURIs, namespace) + 1
	}
	ns := 0
	if rest, ok := strings.CutPrefix(id, "ns="); ok {
		i := strings.IndexByte(rest, ';')
		if i < 0 {
			return 0, fmt.Errorf("NodeId %s", nodeID)
		}
		n, err := strconv.Atoi(rest[:i])
		if err != nil {
			return 0, fmt.Errorf("NodeId %s", nodeID)
		}
		ns, id = n, rest[i+1:]
	}
	s, ok := strings.CutPrefix(id, "i=")
	if !ok || ns != want {
		return 0, fmt.Errorf("NodeId %s is not a numeric NodeId of the namespace", nodeID)
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("NodeId %s: %w", nodeID, err)
	}
	return uint32(n), nil
}

// ns0ID returns the identifier of a numeric NodeId of namespace 0.
func ns0ID(id string) (uint32, bool) {
	id = strings.TrimPrefix(id, "ns=0;")
	s, ok := strings.CutPrefix(id, "i=")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil
}

func indexOf(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

// localName returns a BrowseName without its namespace index.
func localName(bn string) string {
	if i := strings.IndexByte(bn, ':'); i > 0 {
		if _, err := strconv.ParseUint(bn[:i], 10, 16); err == nil {
			return bn[i+1:]
		}
	}
	return bn
}

// docURL matches the Documentation of a node of the NodeSets of the OPC
// Foundation: https://reference.opcfoundation.org/v105/Core/docs/Part20/4.2.2.
var docURL = regexp.MustCompile(`/Part(\d+)/(\d+(?:\.\d+)*)/?$`)

// clause returns "OPC 10000-<part> §<clause>" for the Documentation URL of
// a node, "" when it names none.
func clause(doc string) string {
	m := docURL.FindStringSubmatch(strings.TrimSpace(doc))
	if m == nil {
		return ""
	}
	return "OPC 10000-" + m[1] + " §" + m[2]
}
