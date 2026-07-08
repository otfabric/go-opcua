// SPDX-License-Identifier: MIT

package server

import (
	"encoding/xml"
	"fmt"

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
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nid.Namespace(), Name: rt.BrowseNameAttr})
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
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nid.Namespace(), Name: dt.BrowseNameAttr})
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
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nid.Namespace(), Name: ot.BrowseNameAttr})
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
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nid.Namespace(), Name: ot.BrowseNameAttr})
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
	for i := range nodes.UAVariable {
		ot := nodes.UAVariable[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: variable: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nid.Namespace(), Name: ot.BrowseNameAttr})
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMaskAttr)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMaskAttr)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Value))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Value))
		}
		attrs[ua.AttributeIDNodeClass] = DataValueFromValue(uint32(ua.NodeClassVariable))

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

	// set up the methods
	for i := range nodes.UAMethod {
		ot := nodes.UAMethod[i]
		nid, err := ua.ParseNodeID(ot.NodeIDAttr)
		if err != nil {
			return fmt.Errorf("nodeset import: method: parse node id %q: %w", ot.NodeIDAttr, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictionsAttr)
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nid.Namespace(), Name: ot.BrowseNameAttr})
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
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(&ua.QualifiedName{NamespaceIndex: nid.Namespace(), Name: ot.BrowseNameAttr})
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
func (s *Server) refsImportNodeSet(nodes *schema.UANodeSet) error {

	s.cfg.logger.Debug("new node set", "last_modified", nodes.LastModifiedAttr)

	failures := 0
	reftypes := make(map[string]*schema.UAReferenceType)
	for i := range nodes.UAReferenceType {
		rt := nodes.UAReferenceType[i]
		reftypes[rt.BrowseNameAttr] = rt // sometimes they use browse name
		reftypes[rt.NodeIDAttr] = rt     // sometimes they use node id
	}

	aliases := make(map[string]string)
	if nodes.Aliases != nil {
		for i := range nodes.Aliases.Alias {
			alias := nodes.Aliases.Alias[i]
			aliases[alias.AliasAttr] = alias.Value
		}
	}

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
			node.AddRef(n, RefType(reftypeid.IntID()), fwd)
			if !refTypeEntry.SymmetricAttr {
				n.AddRef(node, RefType(reftypeid.IntID()), !fwd)
			}
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
			node.AddRef(n, RefType(reftypeid.IntID()), fwd)
			if !refTypeEntry.SymmetricAttr {
				n.AddRef(node, RefType(reftypeid.IntID()), !fwd)
			}

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
			node.AddRef(n, RefType(reftypeid.IntID()), fwd)
			if !refTypeEntry.SymmetricAttr {
				n.AddRef(node, RefType(reftypeid.IntID()), !fwd)
			}
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
			node.AddRef(n, RefType(reftypeid.IntID()), fwd)
			if !refTypeEntry.SymmetricAttr {
				n.AddRef(node, RefType(reftypeid.IntID()), !fwd)
			}

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
			node.AddRef(n, RefType(reftypeid.IntID()), fwd)
			if !refTypeEntry.SymmetricAttr {
				n.AddRef(node, RefType(reftypeid.IntID()), !fwd)
			}

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
			node.AddRef(n, RefType(reftypeid.IntID()), fwd)
			if !refTypeEntry.SymmetricAttr {
				n.AddRef(node, RefType(reftypeid.IntID()), !fwd)
			}
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
			node.AddRef(n, RefType(reftypeid.IntID()), fwd)
			if !refTypeEntry.SymmetricAttr {
				n.AddRef(node, RefType(reftypeid.IntID()), !fwd)
			}

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
			role, ok := ua.RoleByName[p.Value]
			if !ok {
				continue
			}
			perms = append(perms, &ua.RolePermissionType{
				RoleID:      role.NodeID(),
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
