// SPDX-License-Identifier: MIT

package nodeset

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// NodeIds of the ReferenceTypes of namespace 0 a generator follows
// (schema/NodeIds.csv). The transitions of a state machine are its
// components; FromState, ToState, HasCause and HasEffect relate a
// Transition to its States and to the Methods and events (OPC 10000-16).
const (
	HasModellingRule     = "i=37"
	HasEncoding          = "i=38"
	HasTypeDefinition    = "i=40"
	GeneratesEvent       = "i=41"
	HasSubtype           = "i=45"
	HasProperty          = "i=46"
	HasComponent         = "i=47"
	FromState            = "i=51"
	ToState              = "i=52"
	HasCause             = "i=53"
	HasEffect            = "i=54"
	AlwaysGeneratesEvent = "i=3065"

	// The ModellingRules of Part 3 §6.4.4.
	ModellingRuleMandatory            = "i=78"
	ModellingRuleOptional             = "i=80"
	ModellingRuleExposesItsArray      = "i=83"
	ModellingRuleOptionalPlaceholder  = "i=11508"
	ModellingRuleMandatoryPlaceholder = "i=11510"

	// argumentXML is the NodeId of Argument_Encoding_DefaultXml, the
	// TypeId of an Argument in the XML DataEncoding.
	argumentXML = "i=297"
)

// Node returns the node of the set with the NodeId id as the document
// writes it (an alias is resolved), nil if the set has none.
func (s *Set) Node(id string) *Node {
	s.buildIndexes()
	if n := s.byID[id]; n != nil {
		return n
	}
	return s.byID[s.Resolve(id)]
}

// OfClass returns the nodes of a class in the order of the document. The
// slice is shared: it must not be modified.
func (s *Set) OfClass(c NodeClass) []*Node {
	if int(c) >= len(s.classes) {
		return nil
	}
	return slices.Clip(s.classes[c])
}

// Resolve returns the NodeId an alias stands for, or s itself (without
// surrounding space) when it is not an alias of the set.
func (s *Set) Resolve(id string) string {
	id = strings.TrimSpace(id)
	if a, ok := s.aliases[id]; ok {
		return a
	}
	return id
}

// referenceTypeNames are the BrowseNames of the ReferenceTypes the
// queries use. A NodeSet names them by aliases; a ReferenceType written
// as such a name without an alias is taken as that ReferenceType.
var referenceTypeNames = map[string]string{
	"HasModellingRule":     HasModellingRule,
	"HasEncoding":          HasEncoding,
	"HasTypeDefinition":    HasTypeDefinition,
	"GeneratesEvent":       GeneratesEvent,
	"HasSubtype":           HasSubtype,
	"HasProperty":          HasProperty,
	"HasComponent":         HasComponent,
	"FromState":            FromState,
	"ToState":              ToState,
	"HasCause":             HasCause,
	"HasEffect":            HasEffect,
	"AlwaysGeneratesEvent": AlwaysGeneratesEvent,
}

// canonical returns the NodeId an alias or NodeId stands for, with the
// namespace index 0 left out ("ns=0;i=46" and "i=46" are one NodeId,
// Part 6 §5.3.1.10).
func (s *Set) canonical(id string) string {
	r := s.Resolve(id)
	if n, ok := referenceTypeNames[r]; ok {
		return n
	}
	return strings.TrimPrefix(r, "ns=0;")
}

// Related returns the NodeIds n is related to by a reference of type
// refType (an alias or a NodeId; subtypes are not followed) in the
// direction forward, whether the set declares the reference on n or, in
// the other direction, on the node at its other end (a NodeSet may write a
// reference on either end, OPC 10000-6 §F.3). Each NodeId is returned once,
// in the order the references are declared, those on n first.
func (s *Set) Related(n *Node, refType string, forward bool) []string {
	s.buildIndexes()
	typ := s.canonical(refType)
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if c := s.canonical(id); !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, r := range n.References {
		if r.IsForward == forward && s.canonical(r.Type) == typ {
			add(r.Target)
		}
	}
	for _, d := range s.inverse[s.canonical(n.NodeID)] {
		if d.ref.IsForward != forward && s.canonical(d.ref.Type) == typ {
			add(d.from.NodeID)
		}
	}
	return out
}

// buildIndexes builds the indexes of the queries once; a Set may be
// queried concurrently. A NodeId the set declares twice is the first node.
func (s *Set) buildIndexes() {
	s.indexOnce.Do(func() {
		s.byID = make(map[string]*Node, len(s.Nodes))
		s.inverse = map[string][]declared{}
		for _, n := range s.Nodes {
			if _, dup := s.byID[n.NodeID]; !dup {
				s.byID[n.NodeID] = n
			}
			for _, r := range n.References {
				t := s.canonical(r.Target)
				s.inverse[t] = append(s.inverse[t], declared{from: n, ref: r})
			}
		}
	})
}

// first returns the first NodeId of Related, "" if there is none.
func (s *Set) first(n *Node, refType string, forward bool) string {
	if ids := s.Related(n, refType, forward); len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// ModellingRule returns the NodeId of the ModellingRule of n (the target
// of its HasModellingRule reference, Part 3 §6.4.4), "" if it has none.
func (s *Set) ModellingRule(n *Node) string { return s.first(n, HasModellingRule, true) }

// TypeDefinition returns the NodeId of the type of an instance (the
// target of its HasTypeDefinition reference), "" if it has none.
func (s *Set) TypeDefinition(n *Node) string { return s.first(n, HasTypeDefinition, true) }

// SuperType returns the NodeId of the supertype of a type (the source of
// the HasSubtype reference to it), "" if it has none.
func (s *Set) SuperType(n *Node) string { return s.first(n, HasSubtype, false) }

// Children returns the nodes of the set that n has a HasComponent or
// HasProperty reference to, in the order of Related.
func (s *Set) Children(n *Node) []*Node {
	var out []*Node
	for _, typ := range []string{HasComponent, HasProperty} {
		for _, id := range s.Related(n, typ, true) {
			if c := s.Node(id); c != nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// Argument is an Argument of a Method (Part 3 §8.6), read from the value
// of its InputArguments or OutputArguments Property.
type Argument struct {
	Name            string
	DataType        string // a NodeId, as the value writes it
	ValueRank       int32
	ArrayDimensions []uint32
	Description     LocalizedText
}

// MethodArguments returns the InputArguments and OutputArguments of a
// Method: the values of its Properties of these names (Part 3 §5.7.1),
// nil for a Property it does not have.
func (s *Set) MethodArguments(m *Node) (in, out []Argument, err error) {
	for _, id := range s.Related(m, HasProperty, true) {
		p := s.Node(id)
		if p == nil || p.Class != Variable {
			continue
		}
		var dst *[]Argument
		switch localName(p.BrowseName) {
		case "InputArguments":
			dst = &in
		case "OutputArguments":
			dst = &out
		default:
			continue
		}
		if p.Value == nil {
			continue
		}
		args, err := p.Value.Arguments()
		if err != nil {
			return nil, nil, fmt.Errorf("nodeset: %s %s: %w", m.NodeID, p.BrowseName, err)
		}
		*dst = args
	}
	return in, out, nil
}

// localName returns a BrowseName without its namespace index.
func localName(browseName string) string {
	if i := strings.IndexByte(browseName, ':'); i > 0 {
		if _, err := strconv.ParseUint(browseName[:i], 10, 16); err == nil {
			return browseName[i+1:]
		}
	}
	return browseName
}

type xmlExtensionObject struct {
	TypeID string `xml:"TypeId>Identifier"`
	Body   struct {
		Argument *struct {
			Name            string   `xml:"Name"`
			DataType        string   `xml:"DataType>Identifier"`
			ValueRank       int32    `xml:"ValueRank"`
			ArrayDimensions []uint32 `xml:"ArrayDimensions>UInt32"`
			Description     struct {
				Locale string `xml:"Locale"`
				Text   string `xml:"Text"`
			} `xml:"Description"`
		} `xml:"Argument"`
	} `xml:"Body"`
}

// Arguments decodes a value of Arguments in the XML DataEncoding (Part 6
// §5.3.1.16): a ListOfExtensionObject, or one ExtensionObject, whose
// bodies are Arguments. A field the body leaves out is zero.
func (v *Value) Arguments() ([]Argument, error) {
	dec := xml.NewDecoder(bytes.NewReader([]byte(v.XML)))
	var out []Argument
	list := false
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "ListOfExtensionObject":
			list = true
			continue
		case "ExtensionObject":
		default:
			return nil, fmt.Errorf("a value of %s, not of Arguments", se.Name.Local)
		}
		var x xmlExtensionObject
		if err := dec.DecodeElement(&x, &se); err != nil {
			return nil, err
		}
		if strings.TrimSpace(x.TypeID) != argumentXML || x.Body.Argument == nil {
			return nil, fmt.Errorf("an ExtensionObject of %s, not an Argument", strings.TrimSpace(x.TypeID))
		}
		a := x.Body.Argument
		arg := Argument{
			Name:            strings.TrimSpace(a.Name),
			DataType:        strings.TrimSpace(a.DataType),
			ValueRank:       a.ValueRank,
			ArrayDimensions: a.ArrayDimensions,
			Description:     LocalizedText{Locale: a.Description.Locale, Text: a.Description.Text},
		}
		out = append(out, arg)
		if !list {
			break
		}
	}
	return out, nil
}
