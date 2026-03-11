// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package opcua

import (
	"context"
	"iter"
	"strings"

	"github.com/otfabric/opcua/id"
	"github.com/otfabric/opcua/ua"
)

// nodeIDKey returns a string key for deduplication. Returns "" if id is nil.
func nodeIDKey(id *ua.ExpandedNodeID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// Node is a high-level object to interact with a node in the
// address space. It provides common convenience functions to
// access and manipulate the common attributes of a node.
type Node struct {
	// ID is the node id of the node.
	ID *ua.NodeID

	c *Client
}

func (n *Node) String() string {
	return n.ID.String()
}

// WalkResult contains a reference description along with its tree depth.
type WalkResult struct {
	Depth int
	Ref   *ua.ReferenceDescription
}

// Walk returns an iterator that recursively descends through the node's
// hierarchical references, yielding each discovered reference along with
// its depth. The walk uses BrowseAll to automatically follow continuation
// points. For a depth limit, use WalkLimit.
func (n *Node) Walk(ctx context.Context) iter.Seq2[WalkResult, error] {
	return n.WalkLimit(ctx, -1)
}

// WalkLimit is like Walk but stops recursing when depth reaches maxDepth.
// The node at depth maxDepth is still yielded. If maxDepth < 0, depth is unlimited.
// Use this for "find node", "find type", or "browse tree" style tools to avoid
// unbounded traversal (e.g. pass a -depth flag from the CLI).
//
// The same node may be yielded more than once if it is reachable via multiple
// hierarchical paths. Use WalkLimitDedup to yield each node at most once.
func (n *Node) WalkLimit(ctx context.Context, maxDepth int) iter.Seq2[WalkResult, error] {
	return func(yield func(WalkResult, error) bool) {
		n.walkRecursive(ctx, 0, maxDepth, nil, yield)
	}
}

// WalkLimitDedup is like WalkLimit but yields each node at most once, keyed by
// NodeID. When a node is reachable via multiple hierarchical paths, only the
// first occurrence (by traversal order) is yielded. Use this to avoid duplicate
// nodes without implementing a visited set in the caller.
func (n *Node) WalkLimitDedup(ctx context.Context, maxDepth int) iter.Seq2[WalkResult, error] {
	return func(yield func(WalkResult, error) bool) {
		visited := make(map[string]struct{})
		if n.ID != nil {
			visited[n.ID.String()] = struct{}{}
		}
		n.walkRecursive(ctx, 0, maxDepth, visited, yield)
	}
}

// BrowseWithDepthOptions configures [Node.BrowseWithDepth]. Zero values use
// defaults: MaxDepth -1 (unlimited), RefType HierarchicalReferences, Direction
// Forward, NodeClassMask All, IncludeSubtypes true.
type BrowseWithDepthOptions struct {
	MaxDepth        int           // stop recursing after this depth; -1 = unlimited
	RefType         uint32        // reference type to follow; 0 = HierarchicalReferences
	Direction       ua.BrowseDirection
	NodeClassMask   ua.NodeClass
	IncludeSubtypes bool
}

// BrowseWithDepthResult is one reference returned by [Node.BrowseWithDepth],
// with the depth at which it was found (0 = direct children of the start node).
type BrowseWithDepthResult struct {
	Ref   *ua.ReferenceDescription
	Depth int
}

// BrowseWithDepth performs a client-side recursive browse from this node up to
// opts.MaxDepth, using the given reference type, direction, and node class filter.
// It returns a flat slice of references with their depth. Standard OPC UA Browse
// is single-level; this method implements recursion by issuing multiple Browse
// calls (same as [Node.WalkLimit] but returns a slice instead of an iterator).
func (n *Node) BrowseWithDepth(ctx context.Context, opts BrowseWithDepthOptions) ([]BrowseWithDepthResult, error) {
	refType := opts.RefType
	if refType == 0 {
		refType = id.HierarchicalReferences
	}
	dir := opts.Direction
	if dir == 0 {
		dir = ua.BrowseDirectionForward
	}
	mask := opts.NodeClassMask
	if mask == 0 {
		mask = ua.NodeClassAll
	}
	includeSubtypes := opts.IncludeSubtypes
	// default when not set is true for backward compatibility with BrowseAll
	// (we don't have a sentinel; zero value false is explicit)
	maxDepth := opts.MaxDepth
	if maxDepth < 0 {
		maxDepth = -1
	}
	var out []BrowseWithDepthResult
	err := n.browseWithDepthRec(ctx, 0, maxDepth, refType, dir, mask, includeSubtypes, &out)
	return out, err
}

func (n *Node) browseWithDepthRec(ctx context.Context, depth, maxDepth int, refType uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool, out *[]BrowseWithDepthResult) error {
	for ref, err := range n.BrowseAll(ctx, refType, dir, mask, includeSubtypes) {
		if err != nil {
			return err
		}
		*out = append(*out, BrowseWithDepthResult{Ref: ref, Depth: depth})
		if maxDepth >= 0 && depth+1 > maxDepth {
			continue
		}
		child := n.c.NodeFromExpandedNodeID(ref.NodeID)
		if err := child.browseWithDepthRec(ctx, depth+1, maxDepth, refType, dir, mask, includeSubtypes, out); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) walkRecursive(ctx context.Context, depth int, maxDepth int, visited map[string]struct{}, yield func(WalkResult, error) bool) bool {
	for ref, err := range n.BrowseAll(ctx, id.HierarchicalReferences, ua.BrowseDirectionForward, ua.NodeClassAll, true) {
		if err != nil {
			return yield(WalkResult{}, err)
		}
		key := nodeIDKey(ref.NodeID)
		if visited != nil {
			if _, seen := visited[key]; seen {
				continue
			}
			if key != "" {
				visited[key] = struct{}{}
			}
		}
		if !yield(WalkResult{Depth: depth, Ref: ref}, nil) {
			return false
		}
		if maxDepth >= 0 && depth+1 > maxDepth {
			continue
		}
		child := n.c.NodeFromExpandedNodeID(ref.NodeID)
		if !child.walkRecursive(ctx, depth+1, maxDepth, visited, yield) {
			return false
		}
	}
	return true
}

// NodeClass returns the node class attribute.
func (n *Node) NodeClass(ctx context.Context) (ua.NodeClass, error) {
	v, err := n.Attribute(ctx, ua.AttributeIDNodeClass)
	if err != nil {
		return 0, err
	}
	return ua.NodeClass(v.Int()), nil
}

// BrowseName returns the browse name of the node.
func (n *Node) BrowseName(ctx context.Context) (*ua.QualifiedName, error) {
	v, err := n.Attribute(ctx, ua.AttributeIDBrowseName)
	if err != nil {
		return nil, err
	}
	return v.Value().(*ua.QualifiedName), nil
}

// Description returns the description of the node.
func (n *Node) Description(ctx context.Context) (*ua.LocalizedText, error) {
	v, err := n.Attribute(ctx, ua.AttributeIDDescription)
	if err != nil {
		return nil, err
	}
	return v.Value().(*ua.LocalizedText), nil
}

// DisplayName returns the display name of the node.
func (n *Node) DisplayName(ctx context.Context) (*ua.LocalizedText, error) {
	v, err := n.Attribute(ctx, ua.AttributeIDDisplayName)
	if err != nil {
		return nil, err
	}
	return v.Value().(*ua.LocalizedText), nil
}

// AccessLevel returns the access level of the node.
// The returned value is a mask where multiple values can be
// set, e.g. read and write.
func (n *Node) AccessLevel(ctx context.Context) (ua.AccessLevelType, error) {
	v, err := n.Attribute(ctx, ua.AttributeIDAccessLevel)
	if err != nil {
		return 0, err
	}
	return ua.AccessLevelType(v.Value().(uint8)), nil
}

// HasAccessLevel returns true if all bits from mask are
// set in the access level mask of the node.
func (n *Node) HasAccessLevel(ctx context.Context, mask ua.AccessLevelType) (bool, error) {
	v, err := n.AccessLevel(ctx)
	if err != nil {
		return false, err
	}
	return (v & mask) == mask, nil
}

// UserAccessLevel returns the access level of the node.
func (n *Node) UserAccessLevel(ctx context.Context) (ua.AccessLevelType, error) {
	v, err := n.Attribute(ctx, ua.AttributeIDUserAccessLevel)
	if err != nil {
		return 0, err
	}
	return ua.AccessLevelType(v.Value().(uint8)), nil
}

// HasUserAccessLevel returns true if all bits from mask are
// set in the user access level mask of the node.
func (n *Node) HasUserAccessLevel(ctx context.Context, mask ua.AccessLevelType) (bool, error) {
	v, err := n.UserAccessLevel(ctx)
	if err != nil {
		return false, err
	}
	return (v & mask) == mask, nil
}

// Value returns the value of the node.
func (n *Node) Value(ctx context.Context) (*ua.Variant, error) {
	return n.Attribute(ctx, ua.AttributeIDValue)
}

// TypeDefinition returns the NodeID of the type definition for this node
// by following the HasTypeDefinition reference.
func (n *Node) TypeDefinition(ctx context.Context) (*ua.NodeID, error) {
	refs, err := n.References(ctx, id.HasTypeDefinition, ua.BrowseDirectionForward, ua.NodeClassAll, false)
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	return refs[0].NodeID.NodeID, nil
}

// DataType returns the NodeID of the data type of this node.
func (n *Node) DataType(ctx context.Context) (*ua.NodeID, error) {
	v, err := n.Attribute(ctx, ua.AttributeIDDataType)
	if err != nil {
		return nil, err
	}
	return v.NodeID(), nil
}

// NodeSummary contains the common attributes of a node, read in a single
// round-trip via [Node.Summary].
type NodeSummary struct {
	NodeID          *ua.NodeID
	NodeClass       ua.NodeClass
	BrowseName      *ua.QualifiedName
	DisplayName     *ua.LocalizedText
	Description     *ua.LocalizedText
	DataType        *ua.NodeID
	Value           *ua.DataValue
	AccessLevel     ua.AccessLevelType
	UserAccessLevel ua.AccessLevelType
	TypeDefinition  *ua.NodeID
}

// Summary reads the common attributes of the node in a single Read call
// and follows the HasTypeDefinition reference. This is the most efficient
// way to gather all display-relevant information about a node.
func (n *Node) Summary(ctx context.Context) (*NodeSummary, error) {
	attrs := []ua.AttributeID{
		ua.AttributeIDNodeClass,
		ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName,
		ua.AttributeIDDescription,
		ua.AttributeIDValue,
		ua.AttributeIDDataType,
		ua.AttributeIDAccessLevel,
		ua.AttributeIDUserAccessLevel,
	}

	results, err := n.Attributes(ctx, attrs...)
	if err != nil {
		return nil, err
	}

	s := &NodeSummary{NodeID: n.ID}

	// NodeClass
	if v := results[0]; v.Status == ua.StatusOK && v.Value != nil {
		s.NodeClass = ua.NodeClass(v.Value.Int())
	}

	// BrowseName
	if v := results[1]; v.Status == ua.StatusOK && v.Value != nil {
		if qn, ok := v.Value.Value().(*ua.QualifiedName); ok {
			s.BrowseName = qn
		}
	}

	// DisplayName
	if v := results[2]; v.Status == ua.StatusOK && v.Value != nil {
		if lt, ok := v.Value.Value().(*ua.LocalizedText); ok {
			s.DisplayName = lt
		}
	}

	// Description
	if v := results[3]; v.Status == ua.StatusOK && v.Value != nil {
		if lt, ok := v.Value.Value().(*ua.LocalizedText); ok {
			s.Description = lt
		}
	}

	// Value
	if results[4].Status == ua.StatusOK {
		s.Value = results[4]
	}

	// DataType
	if v := results[5]; v.Status == ua.StatusOK && v.Value != nil {
		s.DataType = v.Value.NodeID()
	}

	// AccessLevel
	if v := results[6]; v.Status == ua.StatusOK && v.Value != nil {
		if al, ok := v.Value.Value().(uint8); ok {
			s.AccessLevel = ua.AccessLevelType(al)
		}
	}

	// UserAccessLevel
	if v := results[7]; v.Status == ua.StatusOK && v.Value != nil {
		if al, ok := v.Value.Value().(uint8); ok {
			s.UserAccessLevel = ua.AccessLevelType(al)
		}
	}

	// TypeDefinition — separate browse call
	s.TypeDefinition, _ = n.TypeDefinition(ctx)

	return s, nil
}

// Attribute returns the attribute of the node. with the given id.
func (n *Node) Attribute(ctx context.Context, attrID ua.AttributeID) (*ua.Variant, error) {
	rv := &ua.ReadValueID{NodeID: n.ID, AttributeID: attrID}
	req := &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{rv}}
	res, err := n.c.Read(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(res.Results) == 0 {
		// #188: we return StatusBadUnexpectedError because it is unclear, under what
		// circumstances the server would return no error and no results in the response
		return nil, ua.StatusBadUnexpectedError
	}
	value := res.Results[0].Value
	if res.Results[0].Status != ua.StatusOK {
		return value, res.Results[0].Status
	}
	return value, nil
}

// Attributes returns the given node attributes.
func (n *Node) Attributes(ctx context.Context, attrID ...ua.AttributeID) ([]*ua.DataValue, error) {
	req := &ua.ReadRequest{}
	for _, id := range attrID {
		rv := &ua.ReadValueID{NodeID: n.ID, AttributeID: id}
		req.NodesToRead = append(req.NodesToRead, rv)
	}
	res, err := n.c.Read(ctx, req)
	if err != nil {
		return nil, err
	}
	return res.Results, nil
}

// Children returns the child nodes which match the node class mask.
func (n *Node) Children(ctx context.Context, refs uint32, mask ua.NodeClass) ([]*Node, error) {
	if refs == 0 {
		refs = id.HierarchicalReferences
	}
	return n.ReferencedNodes(ctx, refs, ua.BrowseDirectionForward, mask, true)
}

// ReferencedNodes returns the nodes referenced by this node.
func (n *Node) ReferencedNodes(ctx context.Context, refs uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) ([]*Node, error) {
	if refs == 0 {
		refs = id.References
	}
	var nodes []*Node
	res, err := n.References(ctx, refs, dir, mask, includeSubtypes)
	if err != nil {
		return nil, err
	}
	for _, r := range res {
		nodes = append(nodes, n.c.NodeFromExpandedNodeID(r.NodeID))
	}
	return nodes, nil
}

// References returns all references for the node, automatically
// following continuation points for large result sets.
func (n *Node) References(ctx context.Context, refType uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) ([]*ua.ReferenceDescription, error) {
	if refType == 0 {
		refType = id.References
	}
	if mask == 0 {
		mask = ua.NodeClassAll
	}

	desc := &ua.BrowseDescription{
		NodeID:          n.ID,
		BrowseDirection: dir,
		ReferenceTypeID: ua.NewNumericNodeID(0, refType),
		IncludeSubtypes: includeSubtypes,
		NodeClassMask:   uint32(mask),
		ResultMask:      uint32(ua.BrowseResultMaskAll),
	}

	req := &ua.BrowseRequest{
		View: &ua.ViewDescription{
			ViewID: ua.NewTwoByteNodeID(0),
		},
		RequestedMaxReferencesPerNode: 0,
		NodesToBrowse:                 []*ua.BrowseDescription{desc},
	}

	resp, err := n.c.Browse(ctx, req)
	if err != nil {
		return nil, err
	}
	return n.browseNext(ctx, resp.Results)
}

func (n *Node) browseNext(ctx context.Context, results []*ua.BrowseResult) ([]*ua.ReferenceDescription, error) {
	refs := results[0].References
	for len(results[0].ContinuationPoint) > 0 {
		req := &ua.BrowseNextRequest{
			ContinuationPoints:        [][]byte{results[0].ContinuationPoint},
			ReleaseContinuationPoints: false,
		}
		resp, err := n.c.BrowseNext(ctx, req)
		if err != nil {
			return nil, err
		}
		results = resp.Results
		refs = append(refs, results[0].References...)
	}
	return refs, nil
}

// BrowseAll returns an iterator over all references for the node,
// automatically following continuation points. Results are streamed
// without accumulating in memory.
func (n *Node) BrowseAll(ctx context.Context, refType uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) iter.Seq2[*ua.ReferenceDescription, error] {
	return func(yield func(*ua.ReferenceDescription, error) bool) {
		if refType == 0 {
			refType = id.References
		}
		if mask == 0 {
			mask = ua.NodeClassAll
		}

		desc := &ua.BrowseDescription{
			NodeID:          n.ID,
			BrowseDirection: dir,
			ReferenceTypeID: ua.NewNumericNodeID(0, refType),
			IncludeSubtypes: includeSubtypes,
			NodeClassMask:   uint32(mask),
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}

		req := &ua.BrowseRequest{
			View: &ua.ViewDescription{
				ViewID: ua.NewTwoByteNodeID(0),
			},
			RequestedMaxReferencesPerNode: 0,
			NodesToBrowse:                 []*ua.BrowseDescription{desc},
		}

		resp, err := n.c.Browse(ctx, req)
		if err != nil {
			yield(nil, err)
			return
		}

		result := resp.Results[0]
		for _, ref := range result.References {
			if !yield(ref, nil) {
				return
			}
		}

		for len(result.ContinuationPoint) > 0 {
			nextReq := &ua.BrowseNextRequest{
				ContinuationPoints:        [][]byte{result.ContinuationPoint},
				ReleaseContinuationPoints: false,
			}
			nextResp, err := n.c.BrowseNext(ctx, nextReq)
			if err != nil {
				yield(nil, err)
				return
			}
			result = nextResp.Results[0]
			for _, ref := range result.References {
				if !yield(ref, nil) {
					return
				}
			}
		}
	}
}

// TranslateBrowsePathsToNodeIDs resolves a path of browse name segments to a single NodeID using the TranslateBrowsePathsToNodeIDs service.
//
// Start node: the receiver node n (StartingNode in the request).
// Namespace: each segment can specify its own namespace via pathNames[i].NamespaceIndex.
// Path format: slice of QualifiedName; traversal uses HierarchicalReferences.
// Error behavior: returns (nil, err) if the path does not resolve (no targets or non-OK status), the service fails, or the client is not connected. err may be a ua.StatusCode (e.g. StatusBadNotFound).
// For a dot-separated path string with one namespace for all segments, use TranslateBrowsePathInNamespaceToNodeID.
func (n *Node) TranslateBrowsePathsToNodeIDs(ctx context.Context, pathNames []*ua.QualifiedName) (*ua.NodeID, error) {
	req := ua.TranslateBrowsePathsToNodeIDsRequest{
		BrowsePaths: []*ua.BrowsePath{
			{
				StartingNode: n.ID,
				RelativePath: &ua.RelativePath{
					Elements: []*ua.RelativePathElement{},
				},
			},
		}}

	for _, name := range pathNames {
		req.BrowsePaths[0].RelativePath.Elements = append(req.BrowsePaths[0].RelativePath.Elements,
			&ua.RelativePathElement{ReferenceTypeID: ua.NewTwoByteNodeID(id.HierarchicalReferences),
				IsInverse:       false,
				IncludeSubtypes: true,
				TargetName:      name,
			},
		)
	}

	var nodeID *ua.NodeID
	err := n.c.Send(ctx, &req, func(i ua.Response) error {
		if resp, ok := i.(*ua.TranslateBrowsePathsToNodeIDsResponse); ok {
			if len(resp.Results) == 0 {
				return ua.StatusBadUnexpectedError
			}

			if resp.Results[0].StatusCode != ua.StatusOK {
				return resp.Results[0].StatusCode
			}

			if len(resp.Results[0].Targets) == 0 {
				return ua.StatusBadUnexpectedError
			}
			nodeID = resp.Results[0].Targets[0].TargetID.NodeID
			return nil
		}
		return ua.StatusBadUnexpectedError
	})
	return nodeID, err
}

// TranslateBrowsePathInNamespaceToNodeID resolves a dot-separated browse path to a NodeID, with all segments in one namespace.
//
// Start node: the receiver node n.
// Namespace: every path segment uses the given namespace index ns.
// Path format: dot-separated browse names (e.g. "Server.ServerStatus" or "Sensors.Temperature"); split on "." and each segment becomes a QualifiedName{NamespaceIndex: ns, Name: segment}.
// Error behavior: returns (nil, err) if the path does not resolve, the TranslateBrowsePathsToNodeIDs service fails, or the client is not connected. err may be a ua.StatusCode.
// For paths from the server's Objects folder, Client.NodeFromPath or Client.NodeFromPathInNamespace are simpler. For per-segment namespaces, use TranslateBrowsePathsToNodeIDs with a []*ua.QualifiedName.
func (n *Node) TranslateBrowsePathInNamespaceToNodeID(ctx context.Context, ns uint16, browsePath string) (*ua.NodeID, error) {
	segments := strings.Split(browsePath, ".")
	var names []*ua.QualifiedName
	for _, segment := range segments {
		qn := &ua.QualifiedName{NamespaceIndex: ns, Name: segment}
		names = append(names, qn)
	}
	return n.TranslateBrowsePathsToNodeIDs(ctx, names)
}
