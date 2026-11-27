// SPDX-License-Identifier: MIT

package nodeset

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// This file reads a NodeSet2 document into a model: the structure of
// UANodeSet.xsd (OPC 10000-6 Annex F) with the defaults of the schema
// applied, so a reader of the model does not have to know them. It is the
// one reader of the code generators and of the server import.

// NodeClass is the class of a node of a NodeSet, by its element
// (OPC 10000-6 §F.4 to §F.11).
type NodeClass uint8

// The node classes, in the order of the UANodeSet elements.
const (
	Object NodeClass = iota + 1
	Variable
	Method
	View
	ObjectType
	VariableType
	DataType
	ReferenceType
)

var classElements = map[string]NodeClass{
	"UAObject":        Object,
	"UAVariable":      Variable,
	"UAMethod":        Method,
	"UAView":          View,
	"UAObjectType":    ObjectType,
	"UAVariableType":  VariableType,
	"UADataType":      DataType,
	"UAReferenceType": ReferenceType,
}

// String returns the element name of the class, "UAObject" for Object.
func (c NodeClass) String() string {
	for name, k := range classElements {
		if k == c {
			return name
		}
	}
	return "NodeClass(" + strconv.Itoa(int(c)) + ")"
}

// Set is a NodeSet2 document (OPC 10000-6 §F.2).
type Set struct {
	LastModified  string
	NamespaceURIs []string // NamespaceUris: index 1 is the first entry
	ServerURIs    []string
	Models        []Model
	Aliases       []Alias
	// Extensions is the inner XML of each Extension of the document.
	Extensions []string
	// Nodes are the nodes in the order of the document.
	Nodes []*Node

	classes [ReferenceType + 1][]*Node
	aliases map[string]string

	// The indexes of the queries, built on the first (the server import
	// does not need them): the nodes by NodeId, and, by target NodeId,
	// the references declared on other nodes of the set that point at it.
	indexOnce sync.Once
	byID      map[string]*Node
	inverse   map[string][]declared
}

type declared struct {
	from *Node
	ref  Reference
}

// Model is a ModelTableEntry (OPC 10000-6 §F.2, Table F.1).
type Model struct {
	ModelURI           string
	XMLSchemaURI       string
	Version            string
	ModelVersion       string
	PublicationDate    string
	AccessRestrictions uint16
	RolePermissions    []RolePermission
	RequiredModels     []Model
}

// Alias is an entry of the Aliases table (OPC 10000-6 §F.2).
type Alias struct {
	Alias  string
	NodeID string
}

// LocalizedText is a LocalizedText of a node or a field.
type LocalizedText struct {
	Locale string `xml:"Locale,attr"`
	Text   string `xml:",chardata"`
}

// Reference is a reference declared on a node (OPC 10000-6 §F.3). Type is
// the ReferenceType as written, an alias or a NodeId; Target the NodeId of
// the other end.
type Reference struct {
	Type      string
	IsForward bool
	Target    string
}

// RolePermission is a RolePermission of a node or a model: the role, a
// NodeId or alias, and the permissions.
type RolePermission struct {
	Role        string `xml:",chardata"`
	Permissions uint32 `xml:"Permissions,attr"`
}

// Node is a node of a NodeSet with the attributes of its class; the
// attributes of the other classes are zero. Defaults are those of
// UANodeSet.xsd.
type Node struct {
	Class NodeClass

	// UANode (OPC 10000-6 §F.3).
	NodeID             string
	BrowseName         string // "Name" or "<index>:Name"
	SymbolicName       string
	WriteMask          uint32
	UserWriteMask      uint32
	AccessRestrictions uint16
	HasNoPermissions   bool
	ReleaseStatus      string // default Released
	DisplayName        []LocalizedText
	Description        []LocalizedText
	Category           []string
	Documentation      string
	References         []Reference
	RolePermissions    []RolePermission
	Extensions         []string // the inner XML of each Extension

	// UAInstance: Object, Variable, Method, View (§F.4).
	ParentNodeID   string
	DesignToolOnly bool

	// Object and View: EventNotifier; View: ContainsNoLoops (§F.6, §F.10).
	EventNotifier   uint8
	ContainsNoLoops bool

	// Variable and VariableType (§F.7, §F.9). DataType is as written, an
	// alias or a NodeId, and empty when the attribute is absent, which
	// means i=24 (BaseDataType, DefaultDataType). ValueRank defaults to -1
	// (Scalar). The Value is the inner XML of the element, in the XML
	// DataEncoding (Part 6 §5.3), nil when the node has none.
	DataType        string
	ValueRank       int64
	ArrayDimensions string
	Value           *Value

	// Variable only. AccessLevel and UserAccessLevel default to 1
	// (CurrentRead).
	AccessLevel             uint32
	UserAccessLevel         uint32
	MinimumSamplingInterval float64
	Historizing             bool
	Translation             []Translation

	// Method (§F.8). Executable and UserExecutable default to true.
	Executable          bool
	UserExecutable      bool
	MethodDeclarationID string
	ArgumentDescription []ArgumentDescription

	// ObjectType, VariableType, DataType, ReferenceType (§F.5).
	IsAbstract bool

	// DataType (§F.11). Purpose defaults to Normal.
	Purpose    string
	Definition *Definition

	// ReferenceType (§F.12).
	Symmetric   bool
	InverseName []LocalizedText
}

// Value is the content of a Value element.
type Value struct {
	XML string
}

// Translation is a Translation of a Variable's value (§F.7).
type Translation struct {
	Text   []LocalizedText
	Fields []FieldTranslation
}

// FieldTranslation is the translation of a field of a structure value.
type FieldTranslation struct {
	Name string
	Text []LocalizedText
}

// ArgumentDescription is an ArgumentDescription of a Method (§F.8).
type ArgumentDescription struct {
	Name        string
	Description []LocalizedText
}

// Definition is a DataTypeDefinition (§F.12).
type Definition struct {
	Name         string
	SymbolicName string
	IsUnion      bool
	IsOptionSet  bool
	BaseType     string
	Fields       []Field
}

// Field is a DataTypeField (§F.12). DataType is empty when the attribute
// is absent, which means i=24 (DefaultDataType); ValueRank and Value
// default to -1.
type Field struct {
	Name            string
	SymbolicName    string
	DataType        string
	ValueRank       int64
	ArrayDimensions string
	MaxStringLength uint32
	Value           int64
	IsOptional      bool
	AllowSubTypes   bool
	DisplayName     []LocalizedText
	Description     []LocalizedText
}

// --- XML ----------------------------------------------------------------

// The elements read into the types of the model as they are.
type (
	xmlText = LocalizedText
	xmlPerm = RolePermission
)

type xmlRef struct {
	Type      string `xml:"ReferenceType,attr"`
	IsForward *bool  `xml:"IsForward,attr"`
	Target    string `xml:",chardata"`
}

type xmlInner struct {
	XML string `xml:",innerxml"`
}

type xmlModel struct {
	ModelURI           string     `xml:"ModelUri,attr"`
	XMLSchemaURI       string     `xml:"XmlSchemaUri,attr"`
	Version            string     `xml:"Version,attr"`
	ModelVersion       string     `xml:"ModelVersion,attr"`
	PublicationDate    string     `xml:"PublicationDate,attr"`
	AccessRestrictions uint16     `xml:"AccessRestrictions,attr"`
	RolePermissions    []xmlPerm  `xml:"RolePermissions>RolePermission"`
	RequiredModels     []xmlModel `xml:"RequiredModel"`
}

type xmlField struct {
	Name            string    `xml:"Name,attr"`
	SymbolicName    string    `xml:"SymbolicName,attr"`
	DataType        string    `xml:"DataType,attr"`
	ValueRank       *int64    `xml:"ValueRank,attr"`
	ArrayDimensions string    `xml:"ArrayDimensions,attr"`
	MaxStringLength uint32    `xml:"MaxStringLength,attr"`
	Value           *int64    `xml:"Value,attr"`
	IsOptional      bool      `xml:"IsOptional,attr"`
	AllowSubTypes   bool      `xml:"AllowSubTypes,attr"`
	DisplayName     []xmlText `xml:"DisplayName"`
	Description     []xmlText `xml:"Description"`
}

type xmlDefinition struct {
	Name         string     `xml:"Name,attr"`
	SymbolicName string     `xml:"SymbolicName,attr"`
	IsUnion      bool       `xml:"IsUnion,attr"`
	IsOptionSet  bool       `xml:"IsOptionSet,attr"`
	BaseType     string     `xml:"BaseType,attr"`
	Fields       []xmlField `xml:"Field"`
}

type xmlTranslation struct {
	Text   []xmlText `xml:"Text"`
	Fields []struct {
		Name string    `xml:"Name,attr"`
		Text []xmlText `xml:"Text"`
	} `xml:"Field"`
}

// xmlNode holds the attributes and elements of every node class.
type xmlNode struct {
	NodeID             string     `xml:"NodeId,attr"`
	BrowseName         string     `xml:"BrowseName,attr"`
	SymbolicName       string     `xml:"SymbolicName,attr"`
	WriteMask          uint32     `xml:"WriteMask,attr"`
	UserWriteMask      uint32     `xml:"UserWriteMask,attr"`
	AccessRestrictions uint16     `xml:"AccessRestrictions,attr"`
	HasNoPermissions   bool       `xml:"HasNoPermissions,attr"`
	ReleaseStatus      string     `xml:"ReleaseStatus,attr"`
	DisplayName        []xmlText  `xml:"DisplayName"`
	Description        []xmlText  `xml:"Description"`
	Category           []string   `xml:"Category"`
	Documentation      string     `xml:"Documentation"`
	References         []xmlRef   `xml:"References>Reference"`
	RolePermissions    []xmlPerm  `xml:"RolePermissions>RolePermission"`
	Extensions         []xmlInner `xml:"Extensions>Extension"`

	ParentNodeID   string `xml:"ParentNodeId,attr"`
	DesignToolOnly bool   `xml:"DesignToolOnly,attr"`

	EventNotifier   uint8 `xml:"EventNotifier,attr"`
	ContainsNoLoops bool  `xml:"ContainsNoLoops,attr"`

	DataType        string    `xml:"DataType,attr"`
	ValueRank       *int64    `xml:"ValueRank,attr"`
	ArrayDimensions string    `xml:"ArrayDimensions,attr"`
	Value           *xmlInner `xml:"Value"`

	AccessLevel             *uint32          `xml:"AccessLevel,attr"`
	UserAccessLevel         *uint32          `xml:"UserAccessLevel,attr"`
	MinimumSamplingInterval float64          `xml:"MinimumSamplingInterval,attr"`
	Historizing             bool             `xml:"Historizing,attr"`
	Translation             []xmlTranslation `xml:"Translation"`

	Executable          *bool  `xml:"Executable,attr"`
	UserExecutable      *bool  `xml:"UserExecutable,attr"`
	MethodDeclarationID string `xml:"MethodDeclarationId,attr"`
	ArgumentDescription []struct {
		Name        string    `xml:"Name"`
		Description []xmlText `xml:"Description"`
	} `xml:"ArgumentDescription"`

	IsAbstract bool `xml:"IsAbstract,attr"`

	Purpose    string         `xml:"Purpose,attr"`
	Definition *xmlDefinition `xml:"Definition"`

	Symmetric   bool      `xml:"Symmetric,attr"`
	InverseName []xmlText `xml:"InverseName"`
}

// Parse reads a NodeSet2 document: the children of its root element, in
// order, the nodes into Nodes; elements of other names are skipped. The
// name of the root element (UANodeSet) is not checked: the server import
// has always read the children of any.
func Parse(data []byte) (*Set, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	root, err := rootElement(dec)
	if err != nil {
		return nil, err
	}
	s := &Set{aliases: map[string]string{}}
	scratch := new(xmlNode) // reused: its slices go to the nodes, it is zeroed for each
	for _, a := range root.Attr {
		if a.Name.Local == "LastModified" {
			s.LastModified = a.Value
		}
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("nodeset: %w", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			s.index()
			return s, nil
		case xml.StartElement:
			if err := s.element(dec, &t, scratch); err != nil {
				return nil, fmt.Errorf("nodeset: %s: %w", t.Name.Local, err)
			}
		}
	}
}

func rootElement(dec *xml.Decoder) (*xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, errors.New("nodeset: no root element")
		}
		if err != nil {
			return nil, fmt.Errorf("nodeset: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			return &se, nil
		}
	}
}

func (s *Set) element(dec *xml.Decoder, se *xml.StartElement, x *xmlNode) error {
	if class, ok := classElements[se.Name.Local]; ok {
		*x = xmlNode{}
		if err := dec.DecodeElement(x, se); err != nil {
			return err
		}
		s.Nodes = append(s.Nodes, x.node(class))
		return nil
	}
	switch se.Name.Local {
	case "NamespaceUris", "ServerUris":
		var x struct {
			URIs []string `xml:"Uri"`
		}
		if err := dec.DecodeElement(&x, se); err != nil {
			return err
		}
		if se.Name.Local == "NamespaceUris" {
			s.NamespaceURIs = append(s.NamespaceURIs, x.URIs...)
		} else {
			s.ServerURIs = append(s.ServerURIs, x.URIs...)
		}
	case "Models":
		var x struct {
			Models []xmlModel `xml:"Model"`
		}
		if err := dec.DecodeElement(&x, se); err != nil {
			return err
		}
		for _, m := range x.Models {
			s.Models = append(s.Models, m.model())
		}
	case "Aliases":
		var x struct {
			Aliases []struct {
				Alias  string `xml:"Alias,attr"`
				NodeID string `xml:",chardata"`
			} `xml:"Alias"`
		}
		if err := dec.DecodeElement(&x, se); err != nil {
			return err
		}
		for _, a := range x.Aliases {
			s.Aliases = append(s.Aliases, Alias{Alias: a.Alias, NodeID: a.NodeID})
		}
	case "Extensions":
		var x struct {
			Extensions []xmlInner `xml:"Extension"`
		}
		if err := dec.DecodeElement(&x, se); err != nil {
			return err
		}
		for _, e := range x.Extensions {
			s.Extensions = append(s.Extensions, e.XML)
		}
	default:
		return dec.Skip()
	}
	return nil
}

func (s *Set) index() {
	for _, a := range s.Aliases {
		s.aliases[a.Alias] = strings.TrimSpace(a.NodeID)
	}
	for _, n := range s.Nodes {
		s.classes[n.Class] = append(s.classes[n.Class], n)
	}
}

// texts and perms hand the slices decoded for one element to the model;
// the decoder allocates them anew for every element.
func texts(x []xmlText) []LocalizedText {
	if len(x) == 0 {
		return nil
	}
	return x
}

func perms(x []xmlPerm) []RolePermission {
	if len(x) == 0 {
		return nil
	}
	return x
}

func (x xmlModel) model() Model {
	m := Model{
		ModelURI: x.ModelURI, XMLSchemaURI: x.XMLSchemaURI, Version: x.Version, ModelVersion: x.ModelVersion,
		PublicationDate: x.PublicationDate, AccessRestrictions: x.AccessRestrictions, RolePermissions: perms(x.RolePermissions),
	}
	for _, r := range x.RequiredModels {
		m.RequiredModels = append(m.RequiredModels, r.model())
	}
	return m
}

func orInt(p *int64, def int64) int64 {
	if p == nil {
		return def
	}
	return *p
}

func orBool(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// DefaultDataType is the DataType of a Variable, VariableType or Field
// without a DataType attribute (UANodeSet.xsd): BaseDataType.
const DefaultDataType = "i=24"

// The other defaults of UANodeSet.xsd.
const (
	defaultValueRank   = -1 // Scalar
	defaultAccessLevel = 1  // CurrentRead
	defaultFieldValue  = -1
)

func (x *xmlNode) node(class NodeClass) *Node {
	n := &Node{
		Class:              class,
		NodeID:             x.NodeID,
		BrowseName:         x.BrowseName,
		SymbolicName:       x.SymbolicName,
		WriteMask:          x.WriteMask,
		UserWriteMask:      x.UserWriteMask,
		AccessRestrictions: x.AccessRestrictions,
		HasNoPermissions:   x.HasNoPermissions,
		ReleaseStatus:      x.ReleaseStatus,
		DisplayName:        texts(x.DisplayName),
		Description:        texts(x.Description),
		Category:           x.Category,
		Documentation:      x.Documentation,
		RolePermissions:    perms(x.RolePermissions),
	}
	if n.ReleaseStatus == "" {
		n.ReleaseStatus = "Released"
	}
	if len(x.References) > 0 {
		n.References = make([]Reference, len(x.References))
		for i, r := range x.References {
			n.References[i] = Reference{Type: r.Type, IsForward: orBool(r.IsForward, true), Target: r.Target}
		}
	}
	for _, e := range x.Extensions {
		n.Extensions = append(n.Extensions, e.XML)
	}
	switch class {
	case Object, Variable, Method, View:
		n.ParentNodeID = x.ParentNodeID
		n.DesignToolOnly = x.DesignToolOnly
	default:
		n.IsAbstract = x.IsAbstract
	}
	switch class {
	case Object:
		n.EventNotifier = x.EventNotifier
	case View:
		n.EventNotifier = x.EventNotifier
		n.ContainsNoLoops = x.ContainsNoLoops
	case Variable, VariableType:
		n.DataType = x.DataType
		n.ValueRank = orInt(x.ValueRank, defaultValueRank)
		n.ArrayDimensions = x.ArrayDimensions
		if x.Value != nil {
			n.Value = &Value{XML: x.Value.XML}
		}
		if class == Variable {
			n.AccessLevel = defaultAccessLevel
			if x.AccessLevel != nil {
				n.AccessLevel = *x.AccessLevel
			}
			n.UserAccessLevel = defaultAccessLevel
			if x.UserAccessLevel != nil {
				n.UserAccessLevel = *x.UserAccessLevel
			}
			n.MinimumSamplingInterval = x.MinimumSamplingInterval
			n.Historizing = x.Historizing
			for _, t := range x.Translation {
				tr := Translation{Text: texts(t.Text)}
				for _, f := range t.Fields {
					tr.Fields = append(tr.Fields, FieldTranslation{Name: f.Name, Text: texts(f.Text)})
				}
				n.Translation = append(n.Translation, tr)
			}
		}
	case Method:
		n.Executable = orBool(x.Executable, true)
		n.UserExecutable = orBool(x.UserExecutable, true)
		n.MethodDeclarationID = x.MethodDeclarationID
		for _, a := range x.ArgumentDescription {
			n.ArgumentDescription = append(n.ArgumentDescription, ArgumentDescription{Name: a.Name, Description: texts(a.Description)})
		}
	case DataType:
		n.Purpose = x.Purpose
		if n.Purpose == "" {
			n.Purpose = "Normal"
		}
		if d := x.Definition; d != nil {
			n.Definition = &Definition{Name: d.Name, SymbolicName: d.SymbolicName, IsUnion: d.IsUnion, IsOptionSet: d.IsOptionSet, BaseType: d.BaseType}
			for _, f := range d.Fields {
				n.Definition.Fields = append(n.Definition.Fields, Field{
					Name:            f.Name,
					SymbolicName:    f.SymbolicName,
					DataType:        f.DataType,
					ValueRank:       orInt(f.ValueRank, defaultValueRank),
					ArrayDimensions: f.ArrayDimensions,
					MaxStringLength: f.MaxStringLength,
					Value:           orInt(f.Value, defaultFieldValue),
					IsOptional:      f.IsOptional,
					AllowSubTypes:   f.AllowSubTypes,
					DisplayName:     texts(f.DisplayName),
					Description:     texts(f.Description),
				})
			}
		}
	case ObjectType:
		// No attributes beyond those of UAType, set above (§F.5).
	case ReferenceType:
		n.Symmetric = x.Symmetric
		n.InverseName = texts(x.InverseName)
	}
	return n
}
