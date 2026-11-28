// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/internal/nodeset"
	"github.com/otfabric/go-opcua/ua"
)

// ImportNodeSetXML parses OPC UA NodeSet2 XML data and imports the nodes,
// references, and namespaces into the server's address space.
//
// The NamespaceIndexes of the NodeIds, ExpandedNodeIds and QualifiedNames
// of a NodeSet identify an element of its NamespaceUris, "The first index
// is always 1 (0 is always the OPC UA namespace)" (Part 6 §F.2). Each URI
// of the document gets the index the server has for it, or a new namespace
// on the server when it has none, and the document's indexes are rewritten
// to those of the server: a NodeSet can be imported into a server whose
// namespace table differs from the document's. A document whose indexes
// already are those of the server, or that has no NamespaceUris, is
// imported as it is.
//
// A BrowseName without a namespace prefix is a name in the OPC UA
// namespace, 0, whatever the namespace of its node: "The form without a
// prefix ... shall only be used for QualifiedNames in the OPC UA
// Namespace" (Part 6 §5.1.12). A companion model writes InputArguments,
// for one, for the 0:InputArguments Property of its Methods. A prefix that
// names no namespace of the document (or, for a document without
// NamespaceUris, of the server) fails the import.
//
// This is the primary public API for loading custom NodeSet data. Users
// do not need to import the schema package directly.
func (s *Server) ImportNodeSetXML(data []byte) error {
	nodes, err := nodeset.Parse(data)
	if err != nil {
		return fmt.Errorf("server: unmarshal NodeSet XML: %w", err)
	}
	if len(nodes.NamespaceURIs) == 0 {
		return s.importNodeSet(nodes)
	}
	identity, err := s.planNamespaces(nodes.NamespaceURIs)
	if err != nil {
		return err
	}
	if identity {
		return s.importNodeSet(nodes)
	}
	out, err := nodeset.Remap(data, s.namespaceIndex)
	if err != nil {
		return fmt.Errorf("server: map the namespaces of the NodeSet: %w", err)
	}
	// The rewritten document has no NamespaceUris: it is imported as it is.
	return s.ImportNodeSetXML(out)
}

// namespaceLookup returns the index of the first namespace of the server
// named uri.
func (s *Server) namespaceLookup(uri string) (uint16, bool) {
	for i, ns := range s.Namespaces() {
		if ns.Name() == uri {
			return uint16(i), true // a server has at most maxNamespaces
		}
	}
	return 0, false
}

// namespaceIndex returns the index of the namespace uri on the server,
// adding a NodeNameSpace for it when the server has none.
func (s *Server) namespaceIndex(uri string) (uint16, error) {
	if idx, ok := s.namespaceLookup(uri); ok {
		return idx, nil
	}
	ns := NewNodeNameSpace(s, uri)
	if idx, ok := s.namespaceLookup(uri); ok && idx == ns.ID() {
		return idx, nil
	}
	return 0, fmt.Errorf("the server has no namespace index left for %q", uri)
}

// planNamespaces works out the server index of each namespace of the
// NamespaceUris uris of a document, without adding any: the index the
// server has for the URI, or the index a new namespace would get. It
// reports whether every URI keeps its index in the document (the k-th URI,
// index k, has index k on the server), and refuses a document whose new
// namespaces would not fit a UInt16 index (Part 3 §8.2.2) before any is
// added.
func (s *Server) planNamespaces(uris []string) (identity bool, err error) {
	have := len(s.Namespaces())
	next := have // the index of the next new namespace
	planned := map[string]int{}
	identity = true
	for k, uri := range uris {
		idx, ok := planned[uri]
		if !ok {
			if i, found := s.namespaceLookup(uri); found {
				idx = int(i)
			} else {
				idx = next
				next++
			}
			planned[uri] = idx
		}
		if idx != k+1 {
			identity = false
		}
	}
	if next > maxNamespaces {
		return false, fmt.Errorf("nodeset import: %d namespaces do not fit the %d namespace indexes (%d in use)", next-have, maxNamespaces, have)
	}
	return identity, nil
}

// importBrowseName converts the BrowseName attribute of the NodeSet2 node
// nid into a QualifiedName: "<NamespaceIndex>:<Name>", or "<Name>" for a
// name in namespace 0 (Part 6 §5.1.12, [nodeset.ParseQualifiedName]). The
// namespace must exist on the server.
func (s *Server) importBrowseName(nid *ua.NodeID, attr string) (*ua.QualifiedName, error) {
	ns, name, err := nodeset.ParseQualifiedName(attr)
	if err != nil {
		return nil, fmt.Errorf("nodeset import: node %s: %w", nid, err)
	}
	if int(ns) >= len(s.Namespaces()) {
		return nil, fmt.Errorf("nodeset import: node %s: BrowseName %q: the server has no namespace %d", nid, attr, ns)
	}
	return &ua.QualifiedName{NamespaceIndex: ns, Name: name}, nil
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

func (s *Server) importNodeSet(nodes *nodeset.Set) error {
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
	// The DataTypeDefinitions need the HasSubtype and HasEncoding
	// References of the DataTypes.
	s.importDataTypeDefinitions(nodes)
	return nil
}

func (s *Server) namespacesImportNodeSet(nodes *nodeset.Set) error {
	// A URI the server has keeps its namespace; the others become new
	// namespaces. ImportNodeSetXML has checked that they fit
	// (planNamespaces).
	for _, uri := range nodes.NamespaceURIs {
		if _, ok := s.namespaceLookup(uri); !ok {
			_ = NewNodeNameSpace(s, uri)
		}
	}
	return nil
}

func (s *Server) nodesImportNodeSet(nodes *nodeset.Set) error {

	s.cfg.logger.Debug("new node set", "last_modified", nodes.LastModified)

	reftypes := make(map[string]*nodeset.Node)

	// the first thing we have to do is go thorugh and define all the nodes.
	// set up the reference types.
	for _, rt := range nodes.OfClass(nodeset.ReferenceType) {
		reftypes[rt.BrowseName] = rt // sometimes they use browse name
		reftypes[rt.NodeID] = rt     // sometimes they use node id

		nid, err := ua.ParseNodeID(rt.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: reference type: parse node id %q: %w", rt.NodeID, err)
		}

		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(rt.AccessRestrictions)
		bn, err := s.importBrowseName(nid, rt.BrowseName)
		if err != nil {
			return err
		}
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(bn)
		attrs[ua.AttributeIDIsAbstract] = DataValueFromValue(rt.IsAbstract)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(rt.UserWriteMask)
		attrs[ua.AttributeIDSymmetric] = DataValueFromValue(rt.Symmetric)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(rt.WriteMask)
		if len(rt.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(rt.DisplayName[0].Text))
		}
		if len(rt.InverseName) > 0 {
			attrs[ua.AttributeIDInverseName] = DataValueFromValue(ua.NewLocalizedText(rt.InverseName[0].Text))
		} else {
			attrs[ua.AttributeIDInverseName] = DataValueFromValue(ua.NewLocalizedText(""))
		}
		if len(rt.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(rt.Description[0].Text))
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
	for _, dt := range nodes.OfClass(nodeset.DataType) {
		nid, err := ua.ParseNodeID(dt.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: data type: parse node id %q: %w", dt.NodeID, err)
		}

		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(dt.AccessRestrictions)
		bn, err := s.importBrowseName(nid, dt.BrowseName)
		if err != nil {
			return err
		}
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(bn)
		attrs[ua.AttributeIDIsAbstract] = DataValueFromValue(dt.IsAbstract)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(dt.UserWriteMask)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(dt.WriteMask)
		if len(dt.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(dt.DisplayName[0].Text))
		}
		if len(dt.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(dt.Description[0].Text))
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
	for _, ot := range nodes.OfClass(nodeset.ObjectType) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: object type: parse node id %q: %w", ot.NodeID, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictions)
		bn, err := s.importBrowseName(nid, ot.BrowseName)
		if err != nil {
			return err
		}
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(bn)
		attrs[ua.AttributeIDIsAbstract] = DataValueFromValue(ot.IsAbstract)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMask)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMask)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Text))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Text))
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
	for _, ot := range nodes.OfClass(nodeset.VariableType) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: variable type: parse node id %q: %w", ot.NodeID, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictions)
		bn, err := s.importBrowseName(nid, ot.BrowseName)
		if err != nil {
			return err
		}
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(bn)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMask)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMask)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Text))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Text))
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
	for _, ot := range nodes.OfClass(nodeset.Variable) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: variable: parse node id %q: %w", ot.NodeID, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictions)
		bn, err := s.importBrowseName(nid, ot.BrowseName)
		if err != nil {
			return err
		}
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(bn)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMask)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMask)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Text))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Text))
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
	for _, ot := range nodes.OfClass(nodeset.Method) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: method: parse node id %q: %w", ot.NodeID, err)
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictions)
		bn, err := s.importBrowseName(nid, ot.BrowseName)
		if err != nil {
			return err
		}
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(bn)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMask)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMask)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Text))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Text))
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
	for _, ot := range nodes.OfClass(nodeset.Object) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: object: parse node id %q: %w", ot.NodeID, err)
		}
		if ot.NodeID == "i=85" {
			s.cfg.logger.Debug("doing objects")
		}
		var attrs Attributes = make(map[ua.AttributeID]*ua.DataValue)
		attrs[ua.AttributeIDAccessRestrictions] = DataValueFromValue(ot.AccessRestrictions)
		bn, err := s.importBrowseName(nid, ot.BrowseName)
		if err != nil {
			return err
		}
		attrs[ua.AttributeIDBrowseName] = DataValueFromValue(bn)
		attrs[ua.AttributeIDUserWriteMask] = DataValueFromValue(ot.UserWriteMask)
		attrs[ua.AttributeIDWriteMask] = DataValueFromValue(ot.WriteMask)
		if len(ot.DisplayName) > 0 {
			attrs[ua.AttributeIDDisplayName] = DataValueFromValue(ua.NewLocalizedText(ot.DisplayName[0].Text))
		}
		if len(ot.Description) > 0 {
			attrs[ua.AttributeIDDescription] = DataValueFromValue(ua.NewLocalizedText(ot.Description[0].Text))
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
func nodeSetAliases(nodes *nodeset.Set) map[string]string {
	aliases := make(map[string]string)
	for _, alias := range nodes.Aliases {
		aliases[alias.Alias] = alias.NodeID
	}
	return aliases
}

// importVariableAttributes applies the DataType, ValueRank, ArrayDimensions,
// AccessLevel and UserAccessLevel attributes of a UAVariable.
//
// DataType and ValueRank get the defaults of the NodeSet schema (BaseDataType
// and Scalar) when the attribute is absent, and so do AccessLevel and
// UserAccessLevel: CurrentRead (UANodeSet.xsd UAVariable, default="1"). Both
// are mandatory Attributes of a Variable (Part 3 §5.6.2); a variable whose
// NodeSet does not make it writable is read-only.
func (s *Server) importVariableAttributes(attrs Attributes, v *nodeset.Node, aliases map[string]string) {
	dataType := ua.NewNumericNodeID(0, id.BaseDataType)
	if v.DataType != "" {
		text := v.DataType
		if target, ok := aliases[text]; ok {
			text = target
		}
		// ParseNodeID reads anything without a type prefix as a String
		// NodeId, which an unresolved alias must not become.
		if parsed, err := ua.ParseNodeID(text); err == nil && strings.Contains(text, "=") {
			dataType = parsed
		} else {
			s.cfg.logger.Warn("nodeset import: unknown data type", "node_id", v.NodeID, "data_type", v.DataType)
		}
	}
	attrs[ua.AttributeIDDataType] = DataValueFromValue(ua.NewExpandedNodeID(dataType, "", 0))

	valueRank := int32(-1) // Scalar
	// ValueRank is an Int32 of at least -3, ScalarOrOneDimension (Part 3
	// §5.6.2); anything else is not truncated but ignored.
	if r := v.ValueRank; r >= -3 && r <= math.MaxInt32 {
		valueRank = int32(r)
	} else {
		s.cfg.logger.Warn("nodeset import: invalid value rank", "node_id", v.NodeID, "value_rank", r)
	}
	attrs[ua.AttributeIDValueRank] = DataValueFromValue(valueRank)

	if v.ArrayDimensions != "" {
		var dims []uint32
		for _, part := range strings.Split(v.ArrayDimensions, ",") {
			d, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
			if err != nil {
				s.cfg.logger.Warn("nodeset import: invalid array dimensions", "node_id", v.NodeID, "array_dimensions", v.ArrayDimensions)
				dims = nil
				break
			}
			dims = append(dims, uint32(d))
		}
		if dims != nil {
			attrs[ua.AttributeIDArrayDimensions] = DataValueFromValue(dims)
		}
	}
	// AccessLevel and UserAccessLevel are a Byte (Part 3 §5.6.2): a
	// larger value is ignored rather than cut to its low byte, which could
	// grant access the file does not describe.
	for _, a := range []struct {
		id    ua.AttributeID
		value uint32
		name  string
	}{
		{ua.AttributeIDAccessLevel, v.AccessLevel, "access_level"},
		{ua.AttributeIDUserAccessLevel, v.UserAccessLevel, "user_access_level"},
	} {
		level := byte(ua.AccessLevelTypeCurrentRead)
		if a.value > math.MaxUint8 {
			s.cfg.logger.Warn("nodeset import: invalid access level", "node_id", v.NodeID, a.name, a.value)
		} else {
			level = byte(a.value)
		}
		attrs[a.id] = DataValueFromValue(level)
	}
}

// importVariableValue decodes the <Value> element of a UAVariable, which
// holds the value in the OPC UA XML DataEncoding, and returns the function
// the node serves its Value attribute from. It returns nil if the variable
// has no (decodable) value.
func (s *Server) importVariableValue(v *nodeset.Node) ValueFunc {
	if v.Value == nil || strings.TrimSpace(v.Value.XML) == "" {
		return nil
	}
	if proto, builtin := builtinNodeSetValues[v.Value]; builtin {
		if proto == nil {
			s.cfg.logger.Warn("nodeset import: cannot decode value", "node_id", v.NodeID)
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
		s.cfg.logger.Warn("nodeset import: cannot decode value", "node_id", v.NodeID)
		return nil
	}
	dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: val}
	return func() *ua.DataValue { return dv }
}

// decodeNodeSetValue returns the Variant held by a <Value> element, or nil if
// it is empty or cannot be decoded.
func decodeNodeSetValue(v *nodeset.Value) *ua.Variant {
	val := new(ua.Variant)
	if err := ua.DecodeXML([]byte("<Value>"+v.XML+"</Value>"), val); err != nil || val.Type() == ua.TypeIDNull {
		return nil
	}
	return val
}

func (s *Server) refsImportNodeSet(nodes *nodeset.Set) error {

	s.cfg.logger.Debug("new node set", "last_modified", nodes.LastModified)

	failures := 0
	reftypes := make(map[string]*nodeset.Node)
	for _, rt := range nodes.OfClass(nodeset.ReferenceType) {
		reftypes[rt.BrowseName] = rt // sometimes they use browse name
		reftypes[rt.NodeID] = rt     // sometimes they use node id
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
		rt := &nodeset.Node{Class: nodeset.ReferenceType, BrowseName: alias, NodeID: aliasValue}
		isSymmetricValue, err := refnode.Attribute(ua.AttributeIDSymmetric)
		if err == nil {
			rt.Symmetric = isSymmetricValue.Value.Value.Value().(bool)
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
	for _, rt := range nodes.OfClass(nodeset.ReferenceType) {

		nodeid, err := ua.ParseNodeID(rt.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: reference type refs: parse node id %q: %w", rt.NodeID, err)
		}
		node := s.Node(nodeid)
		if node == nil {
			s.cfg.logger.Warn("error loading node", "node_id", rt.NodeID)
			continue
		}

		if len(rt.References) == 0 {
			continue
		}
		for _, ref := range rt.References {
			refnodeid, err := ua.ParseNodeID(ref.Target)
			if err != nil {
				return fmt.Errorf("nodeset import: reference type %q: parse reference target %q: %w", rt.NodeID, ref.Target, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Target, "ref_type", ref.Type, "browse_name", rt.BrowseName)
				failures++
				continue
			}

			fwd := ref.IsForward
			refTypeEntry, ok := reftypes[ref.Type]
			if !ok {
				return fmt.Errorf("nodeset import: reference type %q: unknown reference type %q", rt.NodeID, ref.Type)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeID)
			if err != nil {
				return fmt.Errorf("nodeset import: reference type %q: parse reference type id %q: %w", rt.NodeID, refTypeEntry.NodeID, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.Symmetric)
		}

	}

	// set up the data types.
	for _, dt := range nodes.OfClass(nodeset.DataType) {
		nid, err := ua.ParseNodeID(dt.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: data type refs: parse node id %q: %w", dt.NodeID, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading data type node", "node_id", dt.NodeID)
			continue
		}

		if nid.IntID() == 24 {
			s.cfg.logger.Debug("doing BaseDataType")
		}

		if len(dt.References) == 0 {
			continue
		}
		for _, ref := range dt.References {
			refnodeid, err := ua.ParseNodeID(ref.Target)
			if err != nil {
				return fmt.Errorf("nodeset import: data type %q: parse reference target %q: %w", dt.NodeID, ref.Target, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Target, "ref_type", ref.Type, "browse_name", dt.BrowseName)
				failures++
				continue
			}

			fwd := ref.IsForward
			refTypeEntry, ok := reftypes[ref.Type]
			if !ok {
				return fmt.Errorf("nodeset import: data type %q: unknown reference type %q", dt.NodeID, ref.Type)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeID)
			if err != nil {
				return fmt.Errorf("nodeset import: data type %q: parse reference type id %q: %w", dt.NodeID, refTypeEntry.NodeID, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.Symmetric)

		}

	}

	// set up the object types
	for _, ot := range nodes.OfClass(nodeset.ObjectType) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: object type refs: parse node id %q: %w", ot.NodeID, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading object type node", "node_id", ot.NodeID)
			continue
		}

		if len(ot.References) == 0 {
			continue
		}
		for _, ref := range ot.References {
			refnodeid, err := ua.ParseNodeID(ref.Target)
			if err != nil {
				return fmt.Errorf("nodeset import: object type %q: parse reference target %q: %w", ot.NodeID, ref.Target, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Target, "ref_type", ref.Type, "browse_name", ot.BrowseName)
				failures++
				continue
			}
			fwd := ref.IsForward
			refTypeEntry, ok := reftypes[ref.Type]
			if !ok {
				return fmt.Errorf("nodeset import: object type %q: unknown reference type %q", ot.NodeID, ref.Type)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeID)
			if err != nil {
				return fmt.Errorf("nodeset import: object type %q: parse reference type id %q: %w", ot.NodeID, refTypeEntry.NodeID, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.Symmetric)
		}
	}

	// set up the variable Types
	for _, ot := range nodes.OfClass(nodeset.VariableType) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: variable type refs: parse node id %q: %w", ot.NodeID, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading variable type node", "node_id", ot.NodeID)
			continue
		}

		if len(ot.References) == 0 {
			continue
		}
		for _, ref := range ot.References {
			refnodeid, err := ua.ParseNodeID(ref.Target)
			if err != nil {
				return fmt.Errorf("nodeset import: variable type %q: parse reference target %q: %w", ot.NodeID, ref.Target, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Target, "ref_type", ref.Type, "browse_name", ot.BrowseName)
				failures++
				continue
			}
			fwd := ref.IsForward
			refTypeEntry, ok := reftypes[ref.Type]
			if !ok {
				return fmt.Errorf("nodeset import: variable type %q: unknown reference type %q", ot.NodeID, ref.Type)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeID)
			if err != nil {
				return fmt.Errorf("nodeset import: variable type %q: parse reference type id %q: %w", ot.NodeID, refTypeEntry.NodeID, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.Symmetric)

		}

	}

	// set up the variables
	for _, ot := range nodes.OfClass(nodeset.Variable) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: variable refs: parse node id %q: %w", ot.NodeID, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading variable node", "node_id", ot.NodeID)
			continue
		}

		if len(ot.References) == 0 {
			continue
		}
		for _, ref := range ot.References {
			refnodeid, err := ua.ParseNodeID(ref.Target)
			if err != nil {
				return fmt.Errorf("nodeset import: variable %q: parse reference target %q: %w", ot.NodeID, ref.Target, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Target, "ref_type", ref.Type, "browse_name", ot.BrowseName)
				failures++
				continue
			}
			fwd := ref.IsForward
			refTypeEntry, ok := reftypes[ref.Type]
			if !ok {
				return fmt.Errorf("nodeset import: variable %q: unknown reference type %q", ot.NodeID, ref.Type)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeID)
			if err != nil {
				return fmt.Errorf("nodeset import: variable %q: parse reference type id %q: %w", ot.NodeID, refTypeEntry.NodeID, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.Symmetric)

		}

	}

	// set up the methods
	for _, ot := range nodes.OfClass(nodeset.Method) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: method refs: parse node id %q: %w", ot.NodeID, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading method node", "node_id", ot.NodeID)
			continue
		}

		if len(ot.References) == 0 {
			continue
		}
		for _, ref := range ot.References {
			refnodeid, err := ua.ParseNodeID(ref.Target)
			if err != nil {
				return fmt.Errorf("nodeset import: method %q: parse reference target %q: %w", ot.NodeID, ref.Target, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Target, "ref_type", ref.Type, "browse_name", ot.BrowseName)
				failures++
				continue
			}
			fwd := ref.IsForward
			refTypeEntry, ok := reftypes[ref.Type]
			if !ok {
				return fmt.Errorf("nodeset import: method %q: unknown reference type %q", ot.NodeID, ref.Type)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeID)
			if err != nil {
				return fmt.Errorf("nodeset import: method %q: parse reference type id %q: %w", ot.NodeID, refTypeEntry.NodeID, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.Symmetric)
		}

	}

	// set up the objects
	for _, ot := range nodes.OfClass(nodeset.Object) {
		nid, err := ua.ParseNodeID(ot.NodeID)
		if err != nil {
			return fmt.Errorf("nodeset import: object refs: parse node id %q: %w", ot.NodeID, err)
		}
		node := s.Node(nid)
		if node == nil {
			s.cfg.logger.Warn("error loading object node", "node_id", ot.NodeID)
			continue
		}
		if ot.NodeID == "i=84" {
			s.cfg.logger.Debug("doing root")
		}

		if len(ot.References) == 0 {
			continue
		}
		for _, ref := range ot.References {
			refnodeid, err := ua.ParseNodeID(ref.Target)
			if err != nil {
				return fmt.Errorf("nodeset import: object %q: parse reference target %q: %w", ot.NodeID, ref.Target, err)
			}
			n := s.Node(refnodeid)
			if n == nil {
				s.cfg.logger.Warn("can't find node", "node_id", ref.Target, "ref_type", ref.Type, "browse_name", ot.BrowseName)
				failures++
				continue
			}
			fwd := ref.IsForward
			refTypeEntry, ok := reftypes[ref.Type]
			if !ok {
				return fmt.Errorf("nodeset import: object %q: unknown reference type %q", ot.NodeID, ref.Type)
			}
			reftypeid, err := ua.ParseNodeID(refTypeEntry.NodeID)
			if err != nil {
				return fmt.Errorf("nodeset import: object %q: parse reference type id %q: %w", ot.NodeID, refTypeEntry.NodeID, err)
			}
			importRef(node, n, reftypeid, fwd, refTypeEntry.Symmetric)

		}

	}

	return nil
}

// resolveRolePermissions returns the role permissions for a node.
// It first tries the XML-provided permissions. If none are present and the
// node is in namespace 0, it falls back to the generated defaults from the
// OPC UA specification.
func resolveRolePermissions(rp []nodeset.RolePermission, nid *ua.NodeID) []*ua.RolePermissionType {
	var perms []*ua.RolePermissionType

	if len(rp) > 0 {
		for _, p := range rp {
			// The role is a NodeId ("i=15704", "ns=1;i=1661"), as a NodeSet
			// writes it, or the name of a well-known role.
			var roleID *ua.NodeID
			if role, ok := ua.RoleByName[p.Role]; ok {
				roleID = role.NodeID()
			} else if v := strings.TrimSpace(p.Role); strings.Contains(v, "=") {
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
				Permissions: ua.PermissionType(p.Permissions),
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
