// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/ua"
)

// This file sets the DataTypeDefinition Attribute (AttributeId 23) of the
// DataTypes of a NodeSet from their Definition element.
//
// The Attribute "shall be mandatory for DataTypes derived from Structure
// and Union. For such DataTypes, the Attribute shall contain a structure of
// the DataType StructureDefinition", and it "shall be mandatory for
// DataTypes derived from Enumeration, OptionSet and subtypes of UInteger
// representing an OptionSet", with an EnumDefinition (OPC 10000-3 §5.8.3,
// Table 16). For every other DataType it is optional, and this server
// leaves it out: Read of it on a built-in, simple or abstract DataType that
// is not derived from Structure or Enumeration (BaseDataType, Number,
// Int32, Duration, and Structure and Enumeration themselves) returns
// Bad_AttributeIdInvalid.
//
// "The DataTypeDefinition Attribute can be populated from the
// DataTypeDefinition belonging to a UADataType" (OPC 10000-6 §F.12), whose
// Fields do "not include fields inherited from a base DataType. When
// Applications ingest a UANodeSet they follow the HasSubtype References
// between DataType Nodes to collect all of the fields needed to fill in
// the DataTypeDefinition Attribute." The supertype is found through the
// HasSubtype Reference in the address space, so a DataType of a companion
// model inherits the fields of a supertype of namespace 0 or of a model
// imported before.

// dataTypeKind is what a DataType derives from.
type dataTypeKind uint8

const (
	kindOther       dataTypeKind = iota // BaseDataType, a built-in or simple type
	kindStructure                       // Structure or a subtype
	kindEnumeration                     // Enumeration or a subtype
)

// maxTypeDepth bounds the walk up a DataType hierarchy, which a malformed
// address space could make a cycle.
const maxTypeDepth = 64

// supertypeOf returns the DataType n is a subtype of: the source of the
// inverse HasSubtype Reference, which "the subtype provides ... to its
// supertype" (OPC 10000-3 §5.8.3). It returns nil for a node without one.
func supertypeOf(n *Node) *ua.NodeID {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, r := range n.refs {
		if r == nil || r.IsForward || r.NodeID == nil || r.ReferenceTypeID == nil {
			continue
		}
		if r.ReferenceTypeID.Namespace() == 0 && r.ReferenceTypeID.IntID() == id.HasSubtype {
			return r.NodeID.NodeID
		}
	}
	return nil
}

// kindOf tells whether the DataType nid is (a subtype of) Structure or
// Enumeration, and whether it is (a subtype of) Union.
func (s *Server) kindOf(nid *ua.NodeID) (kind dataTypeKind, union bool) {
	for range maxTypeDepth {
		if nid == nil {
			return kindOther, false
		}
		if nid.Namespace() == 0 {
			switch nid.IntID() {
			case id.Union:
				union = true
			case id.Structure:
				return kindStructure, union
			case id.Enumeration:
				return kindEnumeration, false
			case id.BaseDataType:
				return kindOther, false
			}
		}
		n := s.Node(nid)
		if n == nil {
			return kindOther, false
		}
		nid = supertypeOf(n)
	}
	return kindOther, false
}

// defaultBinaryEncoding returns the DataTypeEncoding of n with the
// BrowseName 0:"Default Binary" (OPC 10000-3 §5.8.3: "Each concrete
// Structured DataType shall point to at least one DataTypeEncoding Object
// with the BrowseName "Default Binary" or "Default XML" having the
// NamespaceIndex 0"), nil if it has none.
func (s *Server) defaultBinaryEncoding(n *Node) *ua.NodeID {
	n.mu.RLock()
	var targets []*ua.NodeID
	for _, r := range n.refs {
		if r == nil || !r.IsForward || r.NodeID == nil || r.ReferenceTypeID == nil {
			continue
		}
		if r.ReferenceTypeID.Namespace() == 0 && r.ReferenceTypeID.IntID() == id.HasEncoding {
			targets = append(targets, r.NodeID.NodeID)
		}
	}
	n.mu.RUnlock()
	for _, t := range targets {
		enc := s.Node(t)
		if enc == nil {
			continue
		}
		if bn := enc.BrowseName(); bn != nil && bn.NamespaceIndex == 0 && bn.Name == "Default Binary" {
			return t
		}
	}
	return nil
}

// definitionImport builds the DataTypeDefinitions of the DataTypes of one
// NodeSet.
type definitionImport struct {
	s       *Server
	set     *nodeset.Set
	aliases map[string]string
	byID    map[string]*nodeset.Node // the DataTypes of the set by NodeId
	done    map[string]*ua.ExtensionObject
}

// importDataTypeDefinitions sets the DataTypeDefinition Attribute of the
// DataTypes of nodes that have one (see the comment of this file). It runs
// after the references of the set are imported. A Definition this server
// cannot map is logged and left out; it does not fail the import.
func (s *Server) importDataTypeDefinitions(nodes *nodeset.Set) {
	d := &definitionImport{
		s:       s,
		set:     nodes,
		aliases: nodeSetAliases(nodes),
		byID:    map[string]*nodeset.Node{},
		done:    map[string]*ua.ExtensionObject{},
	}
	var ids []*ua.NodeID
	for _, dt := range nodes.OfClass(nodeset.DataType) {
		// nodesImportNodeSet refused a NodeId that does not parse.
		if nid, err := ua.ParseNodeID(dt.NodeID); err == nil {
			d.byID[nid.String()] = dt
			ids = append(ids, nid)
		}
	}
	for _, nid := range ids {
		d.definition(nid)
	}
}

// definition returns the DataTypeDefinition of the DataType nid and sets
// it on its node: built from the Definition of the set for a DataType of
// the set, the value of its Attribute for another one. It returns nil if
// the DataType has none. It recurses into the supertype only for a
// DataType whose supertypes reach Structure or Enumeration (kindOf), a
// chain without a cycle.
func (d *definitionImport) definition(nid *ua.NodeID) *ua.ExtensionObject {
	key := nid.String()
	if eo, ok := d.done[key]; ok {
		return eo
	}
	dt := d.byID[key]
	if dt == nil {
		return attributeDefinition(d.s.Node(nid))
	}
	eo, err := d.build(nid, dt)
	if err != nil {
		d.s.cfg.logger.Warn("nodeset import: DataTypeDefinition left out", "node_id", dt.NodeID, "error", err)
	}
	d.done[key] = eo
	if eo != nil {
		if n := d.s.Node(nid); n != nil {
			_ = n.SetAttribute(ua.AttributeIDDataTypeDefinition, DataValueFromValue(eo))
		}
	}
	return eo
}

// attributeDefinition returns the DataTypeDefinition Attribute of n, nil
// if it has none.
func attributeDefinition(n *Node) *ua.ExtensionObject {
	if n == nil {
		return nil
	}
	v, err := n.Attribute(ua.AttributeIDDataTypeDefinition)
	if err != nil || v == nil || v.Value == nil || v.Value.Value == nil {
		return nil
	}
	eo, _ := v.Value.Value.Value().(*ua.ExtensionObject)
	return eo
}

// build returns the DataTypeDefinition of the DataType dt of the set.
func (d *definitionImport) build(nid *ua.NodeID, dt *nodeset.Node) (*ua.ExtensionObject, error) {
	n := d.s.Node(nid)
	if n == nil {
		// Not in the address space: a NameSpace of the program that
		// does not keep the nodes added to it.
		return nil, nil
	}
	super := supertypeOf(n)
	kind, union := d.s.kindOf(super)
	def := dt.Definition
	switch {
	case def != nil && def.IsOptionSet:
		// "This flag indicates that the data type defines the
		// OptionSetValues Property" (OPC 10000-6 §F.12): a subtype of
		// UInteger or of OptionSet, whose Attribute is an EnumDefinition
		// (OPC 10000-3 §5.8.3).
		return d.enumDefinition(def)
	case kind == kindEnumeration:
		if def == nil {
			// A subtype of an Enumeration without fields of its own
			// has the values of its supertype.
			return d.definition(super), nil
		}
		return d.enumDefinition(def)
	case kind == kindStructure:
		if nid.Namespace() == 0 && nid.IntID() == id.Union {
			union = true
		}
		return d.structureDefinition(n, nid, dt, super, union)
	case def != nil && len(def.Fields) > 0:
		// "This is only used to define subtypes of the Structure,
		// Enumeration or UInteger DataTypes" (OPC 10000-6 §F.11).
		return nil, fmt.Errorf("a Definition with fields on a DataType that is no Structure, Enumeration or OptionSet")
	}
	return nil, nil
}

// enumDefinition maps the Definition of an Enumeration or an OptionSet to
// an EnumDefinition (OPC 10000-3 §8.50): an EnumField per Field, with its
// Name, Value, DisplayName and Description (§8.52, derived from
// EnumValueType, §8.39). For an OptionSet "the corresponding Value in the
// base type contains the number of the bit associated with the field"
// (§8.52), which is the Value of the Field of an OptionSet in a NodeSet.
func (d *definitionImport) enumDefinition(def *nodeset.Definition) (*ua.ExtensionObject, error) {
	out := &ua.EnumDefinition{Fields: make([]*ua.EnumField, 0, len(def.Fields))}
	for _, f := range def.Fields {
		out.Fields = append(out.Fields, &ua.EnumField{
			Name:        f.Name,
			Value:       f.Value,
			DisplayName: firstText(f.DisplayName),
			Description: firstText(f.Description),
		})
	}
	return ua.NewExtensionObject(out), nil
}

// structureDefinition maps the Definition of a Structure to a
// StructureDefinition (OPC 10000-3 §8.48): the fields of the supertype
// followed by its own ("For Structures derived from another Structure
// DataType this list shall begin with the fields of the baseDataType
// followed by the fields of this StructureDefinition"), the StructureType
// of OPC 10000-6 §F.12 Table F.13, the direct supertype as BaseDataType,
// and the Default Binary DataTypeEncoding as DefaultEncodingId, null for an
// abstract DataType ("If the DataType is abstract the DefaultEncodingId
// shall be null").
func (d *definitionImport) structureDefinition(n *Node, nid *ua.NodeID, dt *nodeset.Node, super *ua.NodeID, union bool) (*ua.ExtensionObject, error) {
	out := &ua.StructureDefinition{BaseDataType: super}
	if !dt.IsAbstract {
		out.DefaultEncodingID = d.s.defaultBinaryEncoding(n)
	}

	// The flags of Table F.13 over the inherited fields and the own ones.
	// "If a Structure with optional fields is subtyped, the subtypes
	// extend the EncodingMask defined for the parent" (OPC 10000-6
	// §5.2.7): a subtype of a StructureWithOptionalFields has optional
	// fields too.
	type field struct {
		f                       *ua.StructureField
		optional, allowSubTypes bool
	}
	var fields []field
	if super != nil && !isStructureRoot(super) {
		parent := d.definition(super)
		if parent == nil {
			return nil, fmt.Errorf("supertype %s has no DataTypeDefinition", super)
		}
		ps, ok := parent.Value.(*ua.StructureDefinition)
		if !ok {
			return nil, fmt.Errorf("the DataTypeDefinition of supertype %s is no StructureDefinition", super)
		}
		for _, pf := range ps.Fields {
			if pf == nil {
				continue
			}
			// IsOptional means optional in a StructureWithOptionalFields
			// and "allows subtyping" in a StructureWithSubtypedValues or
			// UnionWithSubtypedValues (OPC 10000-3 §8.51).
			f := field{f: pf}
			switch ps.StructureType {
			case ua.StructureTypeStructureWithOptionalFields:
				f.optional = pf.IsOptional
			case ua.StructureTypeStructureWithSubtypedValues, ua.StructureTypeUnionWithSubtypedValues:
				f.allowSubTypes = pf.IsOptional
			case ua.StructureTypeStructure, ua.StructureTypeUnion:
				// "this field shall be FALSE and shall be ignored"
			}
			c := *pf
			c.ArrayDimensions = slices.Clone(pf.ArrayDimensions)
			f.f = &c
			fields = append(fields, f)
		}
	}
	isUnion := union
	if def := dt.Definition; def != nil {
		isUnion = isUnion || def.IsUnion
		for _, nf := range def.Fields {
			sf, err := d.structureField(nf)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", nf.Name, err)
			}
			fields = append(fields, field{f: sf, optional: nf.IsOptional, allowSubTypes: nf.AllowSubTypes})
		}
	}
	var optional, allowSubTypes bool
	for _, f := range fields {
		optional = optional || f.optional
		allowSubTypes = allowSubTypes || f.allowSubTypes
	}
	// OPC 10000-6 §F.12, Table F.13. "Any combination of flags that does
	// not have a mapping is invalid and an error should be raised."
	switch {
	case optional && (isUnion || allowSubTypes):
		return nil, fmt.Errorf("optional fields in a union or beside fields that allow subtypes (OPC 10000-6 Table F.13)")
	case optional:
		out.StructureType = ua.StructureTypeStructureWithOptionalFields
	case isUnion && allowSubTypes:
		out.StructureType = ua.StructureTypeUnionWithSubtypedValues
	case isUnion:
		out.StructureType = ua.StructureTypeUnion
	case allowSubTypes:
		out.StructureType = ua.StructureTypeStructureWithSubtypedValues
	default:
		out.StructureType = ua.StructureTypeStructure
	}
	// IsOptional of a StructureField (OPC 10000-3 §8.51): "If the
	// structureType is StructureWithOptionalFields this field indicates
	// if a data type field in a Structure is optional ... If the
	// structureType is Structure or Union this field shall be FALSE ...
	// If the structureType is StructureWithSubtypedValues, or
	// UnionWithSubtypedValues this field is used to indicate if the data
	// type field allows subtyping."
	out.Fields = make([]*ua.StructureField, len(fields))
	for i, f := range fields {
		switch out.StructureType {
		case ua.StructureTypeStructureWithOptionalFields:
			f.f.IsOptional = f.optional
		case ua.StructureTypeStructureWithSubtypedValues, ua.StructureTypeUnionWithSubtypedValues:
			f.f.IsOptional = f.allowSubTypes
		default:
			f.f.IsOptional = false
		}
		out.Fields[i] = f.f
	}
	return ua.NewExtensionObject(out), nil
}

// isStructureRoot tells whether nid is Structure or Union, which have no
// fields to inherit.
func isStructureRoot(nid *ua.NodeID) bool {
	return nid.Namespace() == 0 && (nid.IntID() == id.Structure || nid.IntID() == id.Union)
}

// structureField maps a Field of a Structure Definition to a StructureField
// (OPC 10000-3 §8.51, OPC 10000-6 §F.13). IsOptional is set by the caller.
func (d *definitionImport) structureField(f nodeset.Field) (*ua.StructureField, error) {
	dataType := ua.NewNumericNodeID(0, id.BaseDataType) // DataType absent: BaseDataType (UANodeSet.xsd)
	if f.DataType != "" {
		text := f.DataType
		if target, ok := d.aliases[text]; ok {
			text = target
		}
		parsed, err := ua.ParseNodeID(strings.TrimSpace(text))
		// ParseNodeID reads anything without a type prefix as a String
		// NodeId, which an unresolved alias must not become.
		if err != nil || !strings.Contains(text, "=") {
			return nil, fmt.Errorf("unknown DataType %q", f.DataType)
		}
		dataType = parsed
	}
	// "It shall be Scalar (-1) or a fixed rank Array (>=1)" (OPC 10000-3
	// §8.51, OPC 10000-6 §F.13).
	if f.ValueRank != -1 && (f.ValueRank < 1 || f.ValueRank > math.MaxInt32) {
		return nil, fmt.Errorf("ValueRank %d is neither Scalar nor a fixed rank", f.ValueRank)
	}
	var dims []uint32
	if f.ValueRank >= 1 {
		// "The number of elements shall be equal to the value of the
		// valueRank field. This field shall be null if valueRank ≤ 0";
		// "If the maximum is unknown the value shall be 0" (OPC 10000-3
		// §8.51): a NodeSet that leaves ArrayDimensions out does not know
		// the maximum of any dimension.
		if f.ArrayDimensions == "" {
			if f.ValueRank > maxFieldRank {
				return nil, fmt.Errorf("ValueRank %d", f.ValueRank)
			}
			dims = make([]uint32, f.ValueRank)
		} else {
			parts := strings.Split(f.ArrayDimensions, ",")
			if int64(len(parts)) != f.ValueRank {
				return nil, fmt.Errorf("ArrayDimensions %q for ValueRank %d", f.ArrayDimensions, f.ValueRank)
			}
			dims = make([]uint32, len(parts))
			for i, p := range parts {
				v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("ArrayDimensions %q: %w", f.ArrayDimensions, err)
				}
				dims[i] = uint32(v)
			}
		}
	}
	return &ua.StructureField{
		Name:            f.Name,
		Description:     firstText(f.Description),
		DataType:        dataType,
		ValueRank:       int32(f.ValueRank),
		ArrayDimensions: dims,
		MaxStringLength: f.MaxStringLength,
	}, nil
}

// maxFieldRank bounds the ArrayDimensions a NodeSet field without them
// gets: a rank this large is no array a structure can hold (the inline
// matrix of OPC 10000-6 §5.2.5 has an Int32 per dimension).
const maxFieldRank = 1 << 10

// firstText returns the first of the localized texts of a NodeSet element
// (a DisplayName or Description "in multiple locales", OPC 10000-6 §F.13),
// the null LocalizedText when there is none.
func firstText(t []nodeset.LocalizedText) *ua.LocalizedText {
	if len(t) == 0 {
		return &ua.LocalizedText{}
	}
	return ua.NewLocalizedTextWithLocale(t[0].Text, t[0].Locale)
}
