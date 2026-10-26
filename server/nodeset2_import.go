// SPDX-License-Identifier: MIT

package server

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/schema"
	"github.com/otfabric/go-opcua/ua"
)

// ImportNodeSetXML parses OPC UA NodeSet2 XML data and imports the nodes,
// references, and namespaces into the server's address space.
//
// This is the primary public API for loading custom NodeSet data. Users
// do not need to import the schema package directly.
func (s *Server) ImportNodeSetXML(data []byte) error {
	var nodes schema.UANodeSet
	if err := xml.Unmarshal(data, &nodes); err != nil {
		return fmt.Errorf("server: unmarshal NodeSet XML: %w", err)
	}
	return s.importNodeSet(&nodes)
}

// isForward returns the value of the IsForward attribute, defaulting to true
// when absent. This avoids mutating the source schema struct so that a cached
// UANodeSet can be shared safely across calls.
func isForward(ref *schema.Reference) bool {
	return ref.IsForwardAttr == nil || *ref.IsForwardAttr
}

// importBrowseName converts the BrowseName attribute of a NodeSet2 node into a
// QualifiedName. The attribute has the form "Name" or "<nsIndex>:Name"; the
// numeric prefix is the namespace index and not part of the name. Without a
// prefix the name belongs to the namespace of the node.
func importBrowseName(nid *ua.NodeID, attr string) *ua.QualifiedName {
	if i := strings.IndexByte(attr, ':'); i > 0 {
		if ns, err := strconv.ParseUint(attr[:i], 10, 16); err == nil {
			return &ua.QualifiedName{NamespaceIndex: uint16(ns), Name: attr[i+1:]}
		}
	}
	return &ua.QualifiedName{NamespaceIndex: nid.Namespace(), Name: attr}
}

// importRef adds a reference a nodeset declares on node: node -typ-> target
// when forward. As with AddRef, both ends record it, once: NodeSet2 files
// commonly declare a reference on both of its ends (forward on the parent
// and inverse on the child), and the address space may hold it already
// (from an earlier import or from AddRef). A symmetric ReferenceType means
// the same in both directions (Part 3 §5.3.3.2), so a reference the other
// end declared forward as well is the same reference.
func importRef(node, target *Node, typ *ua.NodeID, forward, symmetric bool) {
	if symmetric && node.holdsRef(target, typ, !forward) {
		return
	}
	node.addRef(target, typ, forward)
}

func (s *Server) importNodeSet(nodes *schema.UANodeSet) error {
	err := s.namespacesImportNodeSet(nodes)
	if err != nil {
		return fmt.Errorf("opcua: problem creating namespaces: %w", err)
	}
	err = s.nodesImportNodeSet(nodes)
	if err != nil {
		return fmt.Errorf("opcua: problem creating nodes: %w", err)
	}
	err = s.refsImportNodeSet(nodes)
	if err != nil {
		return fmt.Errorf("opcua: problem creating references: %w", err)
	}
	return nil
}

func (s *Server) namespacesImportNodeSet(nodes *schema.UANodeSet) error { //nolint:unparam
	if nodes.NamespaceUris == nil {
		return nil
	}
	for i := range nodes.NamespaceUris.URI {
		_ = NewNodeNameSpace(s, nodes.NamespaceUris.URI[i])
	}
	return nil
}

func (s *Server) nodesImportNodeSet(nodes *schema.UANodeSet) error {

	s.cfg.logger.Debug("new node set", "last_modified", nodes.LastModifiedAttr)

	reftypes := make(map[string]*schema.UAReferenceType)

	// the first thing we have to do is go thorugh and define all the nodes.
	// set up the reference types.
	for i := range nodes.UAReferenceType {
		rt := nodes.UAReferenceType[i]
		reftypes[rt.BrowseNameAttr] = rt // sometimes they use browse name
		reftypes[rt.NodeIDAttr] = rt     // sometimes they use node id

		nid, err := ua.ParseNodeID(rt.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: reference type: parse node id %q: %w", rt.NodeIDAttr, err)
		}

		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(rt.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(importBrowseName(nid, rt.BrowseNameAttr))
		attrs[ua.AttributeIDIsAbstract] = DataValueFromValue(rt.IsAbstractAttr)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(rt.UserWriteMaskAttr)
		attrs[ua.AttributeIDSymmetric] = DataValueFromValue(rt.SymmetricAttr)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(rt.WriteMaskAttr)
		if len(rt.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(rt.DisplayName[0].Value))
		}
		if len(rt.InverseName) > 0 {
			attrs[ua.AttributeIDInverseName] = DataValueFromValue(ua.NewLocalizedText(rt.InverseName[0].Value))
		} else {
			attrs[ua.AttributeIDInverseName] = DataValueFromValue(ua.NewLocalizedText(""))
		}
		if len(rt.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(rt.Description[0].Value))
		}
		attrs[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassReferenceType))

		var refs References = make([]*ua.ReferenceDescription, 0)

		n := NewNode(nid, attrs, refs, nil)
		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			// This namespace doesn't exist.
			s.cfg.logger.Warn("could not find namespace", "namespace", nid.Namespace())
			return err
		}
		ns.AddNode(n)
	}

	// set up the data types.
	for i := range nodes.UADataType {
		dt := nodes.UADataType[i]
		nid, err := ua.ParseNodeID(dt.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: data type: parse node id %q: %w", dt.NodeIDAttr, err)
		}

		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(dt.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(importBrowseName(nid, dt.BrowseNameAttr))
		attrs[ua.AttributeIDIsAbstract] = DataValueFromValue(dt.IsAbstractAttr)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(dt.UserWriteMaskAttr)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(dt.WriteMaskAttr)
		if len(dt.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(dt.DisplayName[0].Value))
		}
		if len(dt.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(dt.Description[0].Value))
		}
		attrs[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassDataType))

		var refs References = make([]*ua.ReferenceDescription, 0)

		n := NewNode(nid, attrs, refs, nil)
		n.rolePermissions = resolveRolePermissions(dt.RolePermissions, nid)

		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			// This namespace doesn't exist.
			s.cfg.logger.Warn("could not find namespace", "namespace", nid.Namespace())
			return err
		}
		ns.AddNode(n)
	}

	// set up the object types
	for i := range nodes.UAObjectType {
		ot := nodes.UAObjectType[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: object type: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(importBrowseName(nid, ot.BrowseNameAttr))
		attrs[ua.AttributeIDIsAbstract] = DataValueFromValue(ot.IsAbstractAttr)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMaskAttr)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMaskAttr)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Value))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Value))
		}
		attrs[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassObjectType))

		var refs References = make([]*ua.ReferenceDescription, 0)

		n := NewNode(nid, attrs, refs, nil)
		n.rolePermissions = resolveRolePermissions(ot.RolePermissions, nid)
		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			// This namespace doesn't exist.
			s.cfg.logger.Warn("could not find namespace", "namespace", nid.Namespace())
			return err
		}
		ns.AddNode(n)
	}

	// set up the variable Types
	for i := range nodes.UAVariableType {
		ot := nodes.UAVariableType[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: variable type: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(importBrowseName(nid, ot.BrowseNameAttr))
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMaskAttr)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMaskAttr)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Value))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Value))
		}
		attrs[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassVariableType))

		var refs References = make([]*ua.ReferenceDescription, 0)

		n := NewNode(nid, attrs, refs, nil)
		n.rolePermissions = resolveRolePermissions(ot.RolePermissions, nid)
		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			// This namespace doesn't exist.
			s.cfg.logger.Warn("could not find namespace", "namespace", nid.Namespace())
			return err
		}
		ns.AddNode(n)
	}

	// set up the variables
	aliases := nodeSetAliases(nodes)
	for i := range nodes.UAVariable {
		ot := nodes.UAVariable[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: variable: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(importBrowseName(nid, ot.BrowseNameAttr))
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMaskAttr)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMaskAttr)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Value))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Value))
		}
		attrs[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassVariable))
		s.importVariableAttributes(attrs, ot, aliases)

		var refs References = make([]*ua.ReferenceDescription, 0)

		n := NewNode(nid, attrs, refs, s.importVariableValue(ot))
		n.rolePermissions = resolveRolePermissions(ot.RolePermissions, nid)
		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			// This namespace doesn't exist.
			s.cfg.logger.Warn("could not find namespace", "namespace", nid.Namespace())
			return err
		}
		ns.AddNode(n)
	}

	// set up the methods
	for i := range nodes.UAMethod {
		ot := nodes.UAMethod[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: method: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(importBrowseName(nid, ot.BrowseNameAttr))
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMaskAttr)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMaskAttr)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Value))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Value))
		}
		attrs[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassMethod))

		var refs References = make([]*ua.ReferenceDescription, 0)

		n := NewNode(nid, attrs, refs, nil)
		n.rolePermissions = resolveRolePermissions(ot.RolePermissions, nid)
		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			// This namespace doesn't exist.
			s.cfg.logger.Warn("could not find namespace", "namespace", nid.Namespace())
			return err
		}
		ns.AddNode(n)
	}

	// set up the objects
	for i := range nodes.UAObject {
		ot := nodes.UAObject[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: object: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		if ot.NodeIDAttr == "i=85" {
			s.cfg.logger.Debug("doing objects")
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(importBrowseName(nid, ot.BrowseNameAttr))
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMaskAttr)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMaskAttr)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Value))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Value))
		}

		attrs[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassObject))

		var refs References = make([]*ua.ReferenceDescription, 0)

		n := NewNode(nid, attrs, refs, nil)
		n.rolePermissions = resolveRolePermissions(ot.RolePermissions, nid)
		ns, err := s.Namespace(int(nid.Namespace()))
		if err != nil {
			// This namespace doesn't exist.
			s.cfg.logger.Warn("could not find namespace", "namespace", nid.Namespace())
			return err
		}
		ns.AddNode(n)
	}

	return nil
}

// nodeSetAliases returns the alias table of a node set (Alias -> NodeId).
func nodeSetAliases(nodes *schema.UANodeSet) map[string]string {
	aliases := make(map[string]string)
	if nodes.Aliases != nil {
		for _, alias := range nodes.Aliases.Alias {
			aliases[alias.AliasAttr] = alias.Value
		}
	}
	return aliases
}

// importVariableAttributes applies the DataType, ValueRank, ArrayDimensions,
// AccessLevel and UserAccessLevel attributes of a UAVariable.
//
// DataType and ValueRank get the defaults of the NodeSet schema (BaseDataType
// and Scalar) when the attribute is absent. The access levels are only set
// when the attribute is present: a variable without them stays readable and
// writable, as imported variables have always been, instead of becoming
// read-only through the schema default of CurrentRead.
func (s *Server) importVariableAttributes(attrs Attributes, v *schema.UAVariable, aliases map[string]string) {
	dataType := ua.NewNumericNodeID(0, id.BaseDataType)
	if v.DataTypeAttr != "" {
		text := v.DataTypeAttr
		if target, ok := aliases[text]; ok {
			text = target
		}
		// ParseNodeID reads anything without a type prefix as a String
		// NodeId, which an unresolved alias must not become.
		if parsed, err := ua.ParseNodeID(text); err == nil && strings.Contains(text, "=") {
			dataType = parsed
		} else {
			s.cfg.logger.Warn("nodeset import: unknown data type", "node_id", v.NodeIDAttr, "data_type", v.DataTypeAttr)
		}
	}
	attrs[ua.AttributeIDDataType] = DataValueFromValue(ua.NewExpandedNodeID(dataType, "", 0))

	valueRank := int32(-1) // Scalar
	if v.ValueRankAttr != nil {
		valueRank = int32(*v.ValueRankAttr)
	}
	attrs[ua.AttributeIDValueRank] = DataValueFromValue(valueRank)

	if v.ArrayDimensionsAttr != "" {
		var dims []uint32
		for _, part := range strings.Split(v.ArrayDimensionsAttr, ",") {
			d, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
			if err != nil {
				s.cfg.logger.Warn("nodeset import: invalid array dimensions", "node_id", v.NodeIDAttr, "array_dimensions", v.ArrayDimensionsAttr)
				dims = nil
				break
			}
			dims = append(dims, uint32(d))
		}
		if dims != nil {
			attrs[ua.AttributeIDArrayDimensions] = DataValueFromValue(dims)
		}
	}
	if v.AccessLevelAttr != nil {
		attrs[ua.AttributeIDAccessLevel] = DataValueFromValue(byte(*v.AccessLevelAttr))
	}
	if v.UserAccessLevelAttr != nil {
		attrs[ua.AttributeIDUserAccessLevel] = DataValueFromValue(byte(*v.UserAccessLevelAttr))
	}
}

// importVariableValue decodes the <Value> element of a UAVariable, which
// holds the value in the OPC UA XML DataEncoding, and returns the function
// the node serves its Value attribute from. It returns nil if the variable
// has no (decodable) value.
func (s *Server) importVariableValue(v *schema.UAVariable) ValueFunc {
	if v.Value == nil || strings.TrimSpace(v.Value.XML) == "" {
		return nil
	}
	if proto, builtin := builtinNodeSetValues[v.Value]; builtin {
		if proto == nil {
			s.cfg.logger.Warn("nodeset import: cannot decode value", "node_id", v.NodeIDAttr)
			return nil
		}
		// The built-in node set is parsed once per process and imported
		// into every server. Its decoded values must not be: an array
		// or a structure handed to one server is memory that the user
		// of that server can write to (a slice element, a field of an
		// Argument), and every other server - also one created later -
		// would serve the result. Each node therefore decodes a value
		// of its own, when it is read for the first time; decoding all
		// of them for every server is what the shared parse avoids.
		src := v.Value
		return sync.OnceValue(func() *ua.DataValue {
			val := decodeNodeSetValue(src)
			if val == nil { // cannot happen: the same text decoded before
				return &ua.DataValue{EncodingMask: ua.DataValueStatusCode, Status: ua.StatusBadDecodingError}
			}
			return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: val}
		})
	}
	val := decodeNodeSetValue(v.Value)
	if val == nil {
		s.cfg.logger.Warn("nodeset import: cannot decode value", "node_id", v.NodeIDAttr)
		return nil
	}
	dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: val}
	return func() *ua.DataValue { return dv }
}

// decodeNodeSetValue returns the Variant held by a <Value> element, or nil if
// it is empty or cannot be decoded.
func decodeNodeSetValue(v *schema.Value) *ua.Variant {
	val := new(ua.Variant)
	if err := ua.DecodeXML([]byte("<Value>"+v.XML+"</Value>"), val); err != nil || val.Type() == ua.TypeIDNull {
		return nil
	}
	return val
}

func (s *Server) refsImportNodeSet(nodes *schema.UANodeSet) error {

	s.cfg.logger.Debug("new node set", "last_modified", nodes.LastModifiedAttr)

	failures := 0
	reftypes := make(map[string]*schema.UAReferenceType)
	for i := range nodes.UAReferenceType {
		rt := nodes.UAReferenceType[i]
		reftypes[rt.BrowseNameAttr] = rt // sometimes they use browse name
		reftypes[rt.NodeIDAttr] = rt     // sometimes they use node id
	}

	aliases := nodeSetAliases(nodes)

	// any of the aliases could be reference types, so we have to check them all and add them to the reftypes map
	// if they are.
	for alias := range aliases {
		aliasValue := aliases[alias]
		aliasID, err := ua.ParseNodeID(aliasValue)
		if err != nil {
			return fmt.Errorf("nodeset import: alias %q: parse node id %q: %w", alias, aliasValue, err)
		}
		refnode := s.Node(aliasID)
		if refnode == nil {
			s.cfg.logger.Warn("error loading alias", "alias", alias)
			continue
		}
		rt := new(schema.UAReferenceType)
		rt.UAType = new(schema.UAType)
		rt.UANode = new(schema.UANode)
		rt.BrowseNameAttr = alias
		rt.NodeIDAttr = aliasValue
		isSymmetricValue, err := refnode.Attribute(ua.AttributeIDSymmetric)
		if err == nil {
			rt.SymmetricAttr = isSymmetricValue.Value.Value.Value().(bool)
		}

		_, ok := reftypes[alias]
		if !ok {
			reftypes[alias] = rt // sometimes they use browse name
		} else {
			s.cfg.logger.Debug("duplicate reference type", "alias", alias)
			continue
		}

		_, ok = reftypes[aliasValue]
		if !ok {
			reftypes[aliasValue] = rt // sometimes they use node id
		} else {
			s.cfg.logger.Debug("duplicate reference type", "alias", aliasValue)
			continue
		}

	}

	// the first thing we have to do is go thorugh and define all the nodes.
	// set up the reference types.
	for i := range nodes.UAReferenceType {
		rt := nodes.UAReferenceType[i]

		nodeid, err := ua.ParseNodeID(rt.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: reference type refs: parse node id %q: %w", rt.NodeIDAttr, err)
		}
		node := s.Node(nodeid)
		if node == nil {
			s.cfg.logger.Warn("error loading node", "node_id", rt.NodeIDAttr)
			continue
		}

		if rt.References == nil {
			continue
		}
		for rid := range rt.References.Reference {
			ref := rt.References.Reference[rid]
			refnodeid, err := ua.ParseNodeID(ref.Value)
			if err != nil {
				return fmt.Errorf("nodeset import: reference type %q: parse reference target %q: %w", rt.NodeIDAttr, ref.Value, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Value, "ref_type", ref.ReferenceTypeAttr, "browse_name", rt.BrowseNameAttr)
				failures++
				continue
			}

			fwd := isForward(ref)
			refTypeEntry, ok := reftypes[ref.ReferenceTypeAttr]
			if !ok {
				return fmt.Errorf("nodeset import: reference type %q: unknown reference type %q", rt.NodeIDAttr, ref.ReferenceTypeAttr)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeIDAttr)
			if err != nil {
				return fmt.Errorf("nodeset import: reference type %q: parse reference type id %q: %w", rt.NodeIDAttr, refTypeEntry.NodeIDAttr, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.SymmetricAttr)
		}

	}

	// set up the data types.
	for i := range nodes.UADataType {
		dt := nodes.UADataType[i]
		nid, err := ua.ParseNodeID(dt.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: data type refs: parse node id %q: %w", dt.NodeIDAttr, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading data type node", "node_id", dt.NodeIDAttr)
			continue
		}

		if nid.IntID() == 24 {
			s.cfg.logger.Debug("doing BaseDataType")
		}

		if dt.References == nil {
			continue
		}
		for rid := range dt.References.Reference {
			ref := dt.References.Reference[rid]
			refnodeid, err := ua.ParseNodeID(ref.Value)
			if err != nil {
				return fmt.Errorf("nodeset import: data type %q: parse reference target %q: %w", dt.NodeIDAttr, ref.Value, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Value, "ref_type", ref.ReferenceTypeAttr, "browse_name", dt.BrowseNameAttr)
				failures++
				continue
			}

			fwd := isForward(ref)
			refTypeEntry, ok := reftypes[ref.ReferenceTypeAttr]
			if !ok {
				return fmt.Errorf("nodeset import: data type %q: unknown reference type %q", dt.NodeIDAttr, ref.ReferenceTypeAttr)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeIDAttr)
			if err != nil {
				return fmt.Errorf("nodeset import: data type %q: parse reference type id %q: %w", dt.NodeIDAttr, refTypeEntry.NodeIDAttr, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.SymmetricAttr)

		}

	}

	// set up the object types
	for i := range nodes.UAObjectType {
		ot := nodes.UAObjectType[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: object type refs: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading object type node", "node_id", ot.NodeIDAttr)
			continue
		}

		if ot.References == nil {
			continue
		}
		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid, err := ua.ParseNodeID(ref.Value)
			if err != nil {
				return fmt.Errorf("nodeset import: object type %q: parse reference target %q: %w", ot.NodeIDAttr, ref.Value, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Value, "ref_type", ref.ReferenceTypeAttr, "browse_name", ot.BrowseNameAttr)
				failures++
				continue
			}
			fwd := isForward(ref)
			refTypeEntry, ok := reftypes[ref.ReferenceTypeAttr]
			if !ok {
				return fmt.Errorf("nodeset import: object type %q: unknown reference type %q", ot.NodeIDAttr, ref.ReferenceTypeAttr)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeIDAttr)
			if err != nil {
				return fmt.Errorf("nodeset import: object type %q: parse reference type id %q: %w", ot.NodeIDAttr, refTypeEntry.NodeIDAttr, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.SymmetricAttr)
		}
	}

	// set up the variable Types
	for i := range nodes.UAVariableType {
		ot := nodes.UAVariableType[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: variable type refs: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading variable type node", "node_id", ot.NodeIDAttr)
			continue
		}

		if ot.References == nil {
			continue
		}
		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid, err := ua.ParseNodeID(ref.Value)
			if err != nil {
				return fmt.Errorf("nodeset import: variable type %q: parse reference target %q: %w", ot.NodeIDAttr, ref.Value, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Value, "ref_type", ref.ReferenceTypeAttr, "browse_name", ot.BrowseNameAttr)
				failures++
				continue
			}
			fwd := isForward(ref)
			refTypeEntry, ok := reftypes[ref.ReferenceTypeAttr]
			if !ok {
				return fmt.Errorf("nodeset import: variable type %q: unknown reference type %q", ot.NodeIDAttr, ref.ReferenceTypeAttr)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeIDAttr)
			if err != nil {
				return fmt.Errorf("nodeset import: variable type %q: parse reference type id %q: %w", ot.NodeIDAttr, refTypeEntry.NodeIDAttr, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.SymmetricAttr)

		}

	}

	// set up the variables
	for i := range nodes.UAVariable {
		ot := nodes.UAVariable[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: variable refs: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading variable node", "node_id", ot.NodeIDAttr)
			continue
		}

		if ot.References == nil {
			continue
		}
		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid, err := ua.ParseNodeID(ref.Value)
			if err != nil {
				return fmt.Errorf("nodeset import: variable %q: parse reference target %q: %w", ot.NodeIDAttr, ref.Value, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Value, "ref_type", ref.ReferenceTypeAttr, "browse_name", ot.BrowseNameAttr)
				failures++
				continue
			}
			fwd := isForward(ref)
			refTypeEntry, ok := reftypes[ref.ReferenceTypeAttr]
			if !ok {
				return fmt.Errorf("nodeset import: variable %q: unknown reference type %q", ot.NodeIDAttr, ref.ReferenceTypeAttr)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeIDAttr)
			if err != nil {
				return fmt.Errorf("nodeset import: variable %q: parse reference type id %q: %w", ot.NodeIDAttr, refTypeEntry.NodeIDAttr, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.SymmetricAttr)

		}

	}

	// set up the methods
	for i := range nodes.UAMethod {
		ot := nodes.UAMethod[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: method refs: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading method node", "node_id", ot.NodeIDAttr)
			continue
		}

		if ot.References == nil {
			continue
		}
		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid, err := ua.ParseNodeID(ref.Value)
			if err != nil {
				return fmt.Errorf("nodeset import: method %q: parse reference target %q: %w", ot.NodeIDAttr, ref.Value, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Value, "ref_type", ref.ReferenceTypeAttr, "browse_name", ot.BrowseNameAttr)
				failures++
				continue
			}
			fwd := isForward(ref)
			refTypeEntry, ok := reftypes[ref.ReferenceTypeAttr]
			if !ok {
				return fmt.Errorf("nodeset import: method %q: unknown reference type %q", ot.NodeIDAttr, ref.ReferenceTypeAttr)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeIDAttr)
			if err != nil {
				return fmt.Errorf("nodeset import: method %q: parse reference type id %q: %w", ot.NodeIDAttr, refTypeEntry.NodeIDAttr, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.SymmetricAttr)
		}

	}

	// set up the objects
	for i := range nodes.UAObject {
		ot := nodes.UAObject[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: object refs: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading object node", "node_id", ot.NodeIDAttr)
			continue
		}
		if ot.NodeIDAttr == "i=84" {
			s.cfg.logger.Debug("doing root")
		}

		if ot.References == nil {
			continue
		}
		for rid := range ot.References.Reference {
			ref := ot.References.Reference[rid]
			refnodeid, err := ua.ParseNodeID(ref.Value)
			if err != nil {
				return fmt.Errorf("nodeset import: object %q: parse reference target %q: %w", ot.NodeIDAttr, ref.Value, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Value, "ref_type", ref.ReferenceTypeAttr, "browse_name", ot.BrowseNameAttr)
				failures++
				continue
			}
			fwd := isForward(ref)
			refTypeEntry, ok := reftypes[ref.ReferenceTypeAttr]
			if !ok {
				return fmt.Errorf("nodeset import: object %q: unknown reference type %q", ot.NodeIDAttr, ref.ReferenceTypeAttr)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeIDAttr)
			if err != nil {
				return fmt.Errorf("nodeset import: object %q: parse reference type id %q: %w", ot.NodeIDAttr, refTypeEntry.NodeIDAttr, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.SymmetricAttr)

		}

	}

	return nil
}

// resolveRolePermissions returns the role permissions for a node.
// It first tries the XML-provided permissions. If none are present and the
// node is in namespace 0, it falls back to the generated defaults from the
// OPC UA specification.
func resolveRolePermissions(rp *schema.ListOfRolePermissions, nid *ua.NodeID) []*ua.RolePermissionType {
	var perms []*ua.RolePermissionType

	if rp != nil && len(rp.RolePermission) > 0 {
		for _, p := range rp.RolePermission {
			// The role is a NodeId ("i=15704", "ns=1;i=1661"), as a NodeSet
			// writes it, or the name of a well-known role.
			var roleID *ua.NodeID
			if role, ok := ua.RoleByName[p.Value]; ok {
				roleID = role.NodeID()
			} else if v := strings.TrimSpace(p.Value); strings.Contains(v, "=") {
				n, err := ua.ParseNodeID(v)
				if err != nil {
					continue
				}
				roleID = n
			} else {
				continue
			}
			perms = append(perms, &ua.RolePermissionType{
				RoleID:      roleID,
				Permissions: ua.PermissionType(p.PermissionsAttr),
			})
		}
	}

	if len(perms) == 0 && nid.Namespace() == 0 {
		if def, ok := DefaultNodePermissions[nid.IntID()]; ok {
			for i := range def.RolePermissions {
				rp := def.RolePermissions[i]
				perms = append(perms, &ua.RolePermissionType{
					RoleID:      rp.RoleID,
					Permissions: rp.Permissions,
				})
			}
		}
	}

	return perms
}
