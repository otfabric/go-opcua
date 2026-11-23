// SPDX-License-Identifier: MIT

package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/otfabric/go-opcua/internal/goname"
)

// The namespaces of the UAFX model, by the key the generated code uses.
var namespaces = []struct{ key, uri, file string }{
	{"data", "http://opcfoundation.org/UA/FX/Data/", "opc.ua.fx.data.nodeset2.xml"},
	{"ac", "http://opcfoundation.org/UA/FX/AC/", "opc.ua.fx.ac.nodeset2.xml"},
	{"cm", "http://opcfoundation.org/UA/FX/CM/", "opc.ua.fx.cm.nodeset2.xml"},
}

const uaURI = "http://opcfoundation.org/UA/"

// --- NodeSet2 XML (Part 6 Annex F) ------------------------------------------

type xmlNodeSet struct {
	NamespaceURIs []string   `xml:"NamespaceUris>Uri"`
	Aliases       []xmlAlias `xml:"Aliases>Alias"`
	DataTypes     []xmlType  `xml:"UADataType"`
	Objects       []xmlNode  `xml:"UAObject"`
}

type xmlAlias struct {
	Alias string `xml:"Alias,attr"`
	ID    string `xml:",chardata"`
}

type xmlNode struct {
	NodeID     string `xml:"NodeId,attr"`
	BrowseName string `xml:"BrowseName,attr"`
}

type xmlType struct {
	NodeID        string         `xml:"NodeId,attr"`
	BrowseName    string         `xml:"BrowseName,attr"`
	IsAbstract    bool           `xml:"IsAbstract,attr"`
	Documentation string         `xml:"Documentation"`
	References    []xmlReference `xml:"References>Reference"`
	Definition    *xmlDefinition `xml:"Definition"`
}

type xmlReference struct {
	Type      string `xml:"ReferenceType,attr"`
	IsForward string `xml:"IsForward,attr"`
	Target    string `xml:",chardata"`
}

type xmlDefinition struct {
	IsUnion     bool       `xml:"IsUnion,attr"`
	IsOptionSet bool       `xml:"IsOptionSet,attr"`
	Fields      []xmlField `xml:"Field"`
}

type xmlField struct {
	Name          string `xml:"Name,attr"`
	DataType      string `xml:"DataType,attr"`
	ValueRank     string `xml:"ValueRank,attr"`
	IsOptional    bool   `xml:"IsOptional,attr"`
	AllowSubTypes bool   `xml:"AllowSubTypes,attr"`
	Value         *int64 `xml:"Value,attr"`
}

// --- model ------------------------------------------------------------------

// ref names a DataType: the URI of its namespace and its numeric id.
type ref struct {
	uri string
	id  uint32
}

func (r ref) String() string { return fmt.Sprintf("nsu=%s;i=%d", r.uri, r.id) }

type kind int

const (
	kEnum kind = iota
	kOptionSet
	kStruct
	kUnion
)

type dataType struct {
	ns       string // data, ac or cm
	id       uint32
	name     string // BrowseName without the namespace prefix
	abstract bool
	base     ref
	kind     kind
	doc      string // the clause of Part 81, from Documentation
	own      []*field
	values   []value
	binary   uint32 // the Default Binary encoding, 0 for none
	optBits  int    // the number of optional fields (structures with optional fields)
	cfg      typeConfig
	goName   string
	subtypes []*dataType
	super    *dataType // FX supertype, nil if the supertype is of namespace 0
}

type field struct {
	name     string
	dt       ref
	array    bool
	optional bool
	allowSub bool
	cfg      fieldConfig
}

type value struct {
	name string
	v    int64
}

type model struct {
	types  map[ref]*dataType
	byName map[string]*dataType // ns:BrowseName
	order  []*dataType
}

var clauseRE = regexp.MustCompile(`OPC-10000-81/([0-9.]+)$`)

// load reads the NodeSets of dir.
func load(dir string) (*model, error) {
	m := &model{types: map[ref]*dataType{}, byName: map[string]*dataType{}}
	for _, n := range namespaces {
		raw, err := os.ReadFile(dir + "/" + n.file)
		if err != nil {
			return nil, err
		}
		var doc xmlNodeSet
		if err := xml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", n.file, err)
		}
		if len(doc.NamespaceURIs) == 0 || doc.NamespaceURIs[0] != n.uri {
			return nil, fmt.Errorf("%s: the first namespace is not %s", n.file, n.uri)
		}
		r := resolver{uris: doc.NamespaceURIs, aliases: map[string]string{}}
		for _, a := range doc.Aliases {
			r.aliases[a.Alias] = strings.TrimSpace(a.ID)
		}
		binary := map[string]bool{}
		for _, o := range doc.Objects {
			if o.BrowseName == "Default Binary" {
				binary[o.NodeID] = true
			}
		}
		for _, x := range doc.DataTypes {
			id, err := r.resolve(x.NodeID)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", n.file, x.BrowseName, err)
			}
			t := &dataType{ns: n.key, id: id.id, name: stripPrefix(x.BrowseName), abstract: x.IsAbstract}
			if c := clauseRE.FindStringSubmatch(strings.TrimSpace(x.Documentation)); c != nil {
				t.doc = c[1]
			}
			for _, rf := range x.References {
				switch {
				case rf.Type == "HasSubtype" && rf.IsForward == "false":
					if t.base, err = r.resolve(strings.TrimSpace(rf.Target)); err != nil {
						return nil, err
					}
				case rf.Type == "HasEncoding" && binary[strings.TrimSpace(rf.Target)]:
					enc, err := r.resolve(strings.TrimSpace(rf.Target))
					if err != nil {
						return nil, err
					}
					t.binary = enc.id
				}
			}
			d := x.Definition
			switch {
			case d == nil:
				return nil, fmt.Errorf("%s: %s has no Definition", n.file, t.name)
			case t.base == (ref{uaURI, 29}): // Enumeration
				t.kind = kEnum
			case d.IsOptionSet:
				t.kind = kOptionSet
			case d.IsUnion:
				t.kind = kUnion
			default:
				t.kind = kStruct
			}
			for _, f := range d.Fields {
				if t.kind == kEnum || t.kind == kOptionSet {
					if f.Value == nil {
						return nil, fmt.Errorf("%s: %s.%s has no Value", n.file, t.name, f.Name)
					}
					t.values = append(t.values, value{f.Name, *f.Value})
					continue
				}
				dt := f.DataType
				if dt == "" {
					dt = "i=24" // BaseDataType (Part 6 §F.12)
				}
				fr, err := r.resolve(dt)
				if err != nil {
					return nil, fmt.Errorf("%s: %s.%s: %w", n.file, t.name, f.Name, err)
				}
				switch f.ValueRank {
				case "", "-1", "1":
				default:
					return nil, fmt.Errorf("%s: %s.%s: ValueRank %s is not supported", n.file, t.name, f.Name, f.ValueRank)
				}
				t.own = append(t.own, &field{name: f.Name, dt: fr, array: f.ValueRank == "1", optional: f.IsOptional, allowSub: f.AllowSubTypes})
			}
			key := n.key + ":" + t.name
			t.cfg = config[key]
			m.types[ref{n.uri, t.id}] = t
			m.byName[key] = t
			m.order = append(m.order, t)
		}
	}
	for key := range config {
		if m.byName[key] == nil {
			return nil, fmt.Errorf("config names %s, which no NodeSet defines", key)
		}
	}
	return m, m.link()
}

func stripPrefix(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[i+1:]
	}
	return s
}

type resolver struct {
	uris    []string
	aliases map[string]string
}

// resolve resolves an alias or a NodeId of the NodeSet (ns=k refers to
// NamespaceUris[k-1]) to a ref. Only numeric NodeIds are used by the UAFX
// NodeSets.
func (r resolver) resolve(s string) (ref, error) {
	if a, ok := r.aliases[s]; ok {
		s = a
	}
	uri := uaURI
	rest := s
	if strings.HasPrefix(s, "ns=") {
		i := strings.IndexByte(s, ';')
		if i < 0 {
			return ref{}, fmt.Errorf("bad NodeId %q", s)
		}
		k, err := strconv.Atoi(s[3:i])
		if err != nil || k < 1 || k > len(r.uris) {
			return ref{}, fmt.Errorf("bad namespace in %q", s)
		}
		uri = r.uris[k-1]
		rest = s[i+1:]
	}
	if !strings.HasPrefix(rest, "i=") {
		return ref{}, fmt.Errorf("unknown DataType or non-numeric NodeId %q", s)
	}
	id, err := strconv.ParseUint(rest[2:], 10, 32)
	if err != nil {
		return ref{}, fmt.Errorf("bad NodeId %q: %w", s, err)
	}
	return ref{uri, uint32(id)}, nil
}

// link resolves the supertypes and names of the types and checks what the
// generator supports.
func (m *model) link() error {
	for _, t := range m.order {
		if s := m.types[t.base]; s != nil {
			t.super = s
			s.subtypes = append(s.subtypes, t)
		}
		t.goName = t.cfg.Go
		if t.goName == "" {
			n := t.name
			for _, suf := range []string{"DataType", "OptionSet", "Enum"} {
				if s, ok := strings.CutSuffix(n, suf); ok && s != "" {
					n = s
					break
				}
			}
			t.goName = goname.Format(n)
		}
	}
	seen := map[string]string{}
	for _, t := range m.order {
		if other, ok := seen[t.goName]; ok {
			return fmt.Errorf("%s:%s and %s have the Go name %s", t.ns, t.name, other, t.goName)
		}
		seen[t.goName] = t.ns + ":" + t.name
		if t.kind == kStruct || t.kind == kUnion {
			for _, f := range t.fields() {
				if f.dt.uri == uaURI {
					if _, ok := builtins[f.dt.id]; !ok {
						return fmt.Errorf("%s:%s.%s: the namespace 0 DataType i=%d is not in the table of the generator", t.ns, t.name, f.name, f.dt.id)
					}
					continue
				}
				if m.types[f.dt] == nil {
					return fmt.Errorf("%s:%s.%s: unknown DataType %v", t.ns, t.name, f.name, f.dt)
				}
			}
			if !t.abstract && t.binary == 0 {
				return fmt.Errorf("%s:%s has no Default Binary encoding", t.ns, t.name)
			}
			if t.kind == kStruct {
				for _, f := range t.fields() {
					if f.optional {
						t.optBits++
					}
				}
				if t.optBits > 32 {
					return fmt.Errorf("%s:%s has %d optional fields; the EncodingMask has 32 bits", t.ns, t.name, t.optBits)
				}
			}
		}
		if t.kind == kEnum || t.kind == kOptionSet {
			if t.base.uri != uaURI {
				return fmt.Errorf("%s:%s: the supertype %v is not supported", t.ns, t.name, t.base)
			}
			if t.kind == kOptionSet {
				if _, ok := optionSetBases[t.base.id]; !ok {
					return fmt.Errorf("%s:%s: OptionSet of i=%d is not supported", t.ns, t.name, t.base.id)
				}
			}
		}
		if t.kind == kStruct && t.super == nil && t.base != (ref{uaURI, 22}) {
			return fmt.Errorf("%s:%s: the supertype %v is not supported", t.ns, t.name, t.base)
		}
		if t.kind == kUnion && t.base != (ref{uaURI, 12756}) {
			return fmt.Errorf("%s:%s: a union with the supertype %v is not supported", t.ns, t.name, t.base)
		}
		for name, fc := range t.cfg.Fields {
			var f *field
			for _, x := range t.fields() {
				if x.name == name {
					f = x
				}
			}
			if f == nil {
				return fmt.Errorf("config names the field %s of %s:%s, which it does not have", name, t.ns, t.name)
			}
			f.cfg = fc
			if fc.Concrete != "" {
				c := m.byName[t.ns+":"+fc.Concrete]
				if c == nil || !c.isSubtypeOf(m.types[f.dt]) || c.abstract {
					return fmt.Errorf("%s:%s.%s: %s is not a concrete subtype of the DataType of the field", t.ns, t.name, name, fc.Concrete)
				}
			}
		}
	}
	for _, t := range m.order {
		if err := m.checkRecursion(t, map[*dataType]bool{}); err != nil {
			return err
		}
		sort.Slice(t.subtypes, func(i, j int) bool { return t.subtypes[i].goName < t.subtypes[j].goName })
	}
	return nil
}

// fields returns the fields of t in the order of the encoding: those of
// its supertypes first (Part 6 §5.2.6; the NodeSet does not repeat them).
func (t *dataType) fields() []*field {
	if t.super == nil {
		return t.own
	}
	return append(append([]*field(nil), t.super.fields()...), t.own...)
}

func (t *dataType) isSubtypeOf(base *dataType) bool {
	for x := t; x != nil; x = x.super {
		if x == base {
			return true
		}
	}
	return false
}

// concrete returns the concrete types t stands for: itself and its
// subtypes that are not abstract.
func (t *dataType) concrete() []*dataType {
	var out []*dataType
	if !t.abstract {
		out = append(out, t)
	}
	for _, s := range t.subtypes {
		out = append(out, s.concrete()...)
	}
	return out
}

// checkRecursion fails for a structure that contains itself, which the
// generated decoder would follow without a depth limit.
func (m *model) checkRecursion(t *dataType, path map[*dataType]bool) error {
	if path[t] {
		return fmt.Errorf("%s:%s contains itself", t.ns, t.name)
	}
	path[t] = true
	defer delete(path, t)
	for _, f := range t.fields() {
		ft := m.types[f.dt]
		if ft == nil {
			continue
		}
		for _, c := range append([]*dataType{ft}, ft.concrete()...) {
			if err := m.checkRecursion(c, path); err != nil {
				return err
			}
		}
	}
	return nil
}
