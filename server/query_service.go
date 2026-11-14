// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// QueryService implements the Query Service Set. It is only served when the
// server is created WithQuery(true); otherwise QueryFirst and QueryNext
// answer Bad_ServiceUnsupported.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9
type QueryService struct {
	srv *Server

	// cps holds the QueryDataSets that did not fit within a client's
	// MaxDataSetsToReturn limit, to be retrieved via QueryNext.
	cps *cpStore[[]*ua.QueryDataSet]
}

// WithQuery enables the Query service set (QueryFirst, QueryNext, Part 4
// §5.9). It is off by default: Query is an optional facet, and a query
// scans the whole address space. When it is off, QueryFirst and QueryNext
// answer Bad_ServiceUnsupported.
//
// A query only returns nodes the session may browse and attribute values
// it may read: the AccessController, the diagnostics access rules and the
// AccessRestrictions of the nodes apply as for Browse and Read.
func WithQuery(enabled bool) Option {
	return func(s *serverConfig) error {
		s.query = enabled
		return nil
	}
}

// store returns the continuation point store, creating it for a
// QueryService that was built without one.
func (s *QueryService) store() *cpStore[[]*ua.QueryDataSet] {
	if s.cps == nil {
		s.cps = newCPStore[[]*ua.QueryDataSet]()
	}
	return s.cps
}

// queryScope is what one query may see: the session and channel it runs
// for.
type queryScope struct {
	ctx  context.Context
	sess *session
	sc   *uasc.SecureChannel
}

// QueryFirst implements the OPC UA QueryFirst service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.3
func (s *QueryService) QueryFirst(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.QueryFirstRequest](r)
	if err != nil {
		return nil, err
	}
	if !s.srv.cfg.query {
		return nil, ua.StatusBadServiceUnsupported
	}
	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)
	scope := &queryScope{ctx: ctx, sess: sess, sc: sc}

	// Views are not maintained by this server. A null/absent view means the
	// whole address space; any specific view is unknown.
	if req.View != nil && req.View.ViewID != nil && !req.View.ViewID.Equal(ua.NewTwoByteNodeID(0)) {
		return nil, ua.StatusBadViewIDUnknown
	}

	if len(req.NodeTypes) == 0 {
		return nil, ua.StatusBadNothingToDo
	}

	// Validate the filter structurally before scanning any nodes.
	filterResult, filterOK := validateFilter(req.Filter)
	if !filterOK {
		return &ua.QueryFirstResponse{
			ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusBadContentFilterInvalid),
			FilterResult:   filterResult,
			QueryDataSets:  []*ua.QueryDataSet{},
			ParsingResults: []*ua.ParsingResult{},
		}, nil
	}

	// Validate each NodeTypeDescription and build the parsing results.
	parsing := make([]*ua.ParsingResult, len(req.NodeTypes))
	for k, ntd := range req.NodeTypes {
		pr := &ua.ParsingResult{
			StatusCode:          ua.StatusGood,
			DataStatusCodes:     []ua.StatusCode{},
			DataDiagnosticInfos: []*ua.DiagnosticInfo{},
		}
		if ntd == nil || ntd.TypeDefinitionNode == nil || ntd.TypeDefinitionNode.NodeID == nil ||
			ntd.TypeDefinitionNode.NodeID.Equal(ua.NewTwoByteNodeID(0)) || !s.isTypeNode(ntd.TypeDefinitionNode.NodeID) {
			// Part 4 §5.9.3: the NodeId does not reference an
			// appropriate type node (none, or not an ObjectType or
			// VariableType).
			pr.StatusCode = ua.StatusBadTypeDefinitionInvalid
		} else {
			pr.DataStatusCodes = make([]ua.StatusCode, len(ntd.DataToReturn))
			for d := range ntd.DataToReturn {
				pr.DataStatusCodes[d] = ua.StatusGood
			}
		}
		parsing[k] = pr
	}

	sets := s.scan(scope, req, parsing)

	resp := &ua.QueryFirstResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		ParsingResults:  parsing,
		FilterResult:    filterResult,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	// Apply MaxDataSetsToReturn and spill the overflow into a continuation.
	// A limit above the largest int is no limit, where int has 32 bits
	// too.
	max := intOfUint32(req.MaxDataSetsToReturn)
	if max > 0 && len(sets) > max {
		cp, ok := s.storeContinuation(sess, sets[max:])
		if !ok {
			// Part 4 §7.9: all continuation points of the session are
			// in use.
			return nil, ua.StatusBadNoContinuationPoints
		}
		resp.QueryDataSets = sets[:max]
		resp.ContinuationPoint = cp
	} else {
		resp.QueryDataSets = sets
	}

	return resp, nil
}

// isTypeNode reports whether id is an ObjectType or VariableType of the
// address space.
func (s *QueryService) isTypeNode(id *ua.NodeID) bool {
	n := s.srv.Node(id)
	if n == nil {
		return false
	}
	c := n.NodeClass()
	return c == ua.NodeClassObjectType || c == ua.NodeClassVariableType
}

// scan enumerates candidate nodes, applies type matching and the filter, and
// builds the resulting QueryDataSets.
func (s *QueryService) scan(scope *queryScope, req *ua.QueryFirstRequest, parsing []*ua.ParsingResult) []*ua.QueryDataSet {
	var sets []*ua.QueryDataSet

	for _, ns := range s.srv.Namespaces() {
		en, ok := ns.(nodeEnumerator)
		if !ok {
			continue
		}
		for _, node := range en.Nodes() {
			td := nodeTypeDefinition(node)
			if td == nil {
				continue
			}

			k := s.matchNodeType(req.NodeTypes, parsing, td)
			if k < 0 {
				continue
			}

			// A node the session may not browse is not part of the
			// result.
			if s.srv.checkBrowse(scope.ctx, scope.sess, node.ID()) != ua.StatusOK ||
				checkAccessRestrictionsForBrowse(scope.sc, node) != ua.StatusOK {
				continue
			}

			if evalFilterFor(s.srv, node, req.Filter, scope.canRead(s.srv)) != tvlTrue {
				continue
			}

			sets = append(sets, s.buildDataSet(scope, node, td, req.NodeTypes[k]))
		}
	}

	return sets
}

// matchNodeType returns the index of the first NodeTypeDescription whose type
// (honoring IncludeSubTypes) matches td, or -1 if none match.
func (s *QueryService) matchNodeType(ntds []*ua.NodeTypeDescription, parsing []*ua.ParsingResult, td *ua.NodeID) int {
	for k, ntd := range ntds {
		if parsing[k].StatusCode != ua.StatusGood {
			continue
		}
		want := ntd.TypeDefinitionNode.NodeID
		if ntd.IncludeSubTypes {
			if s.srv.isSubtypeOf(td, want) {
				return k
			}
		} else if td.Equal(want) {
			return k
		}
	}
	return -1
}

// buildDataSet resolves the requested attributes for a matched node.
func (s *QueryService) buildDataSet(scope *queryScope, node *Node, td *ua.NodeID, ntd *ua.NodeTypeDescription) *ua.QueryDataSet {
	ds := &ua.QueryDataSet{
		NodeID:             ua.NewExpandedNodeID(node.ID(), "", 0),
		TypeDefinitionNode: ua.NewExpandedNodeID(td, "", 0),
		Values:             make([]*ua.Variant, len(ntd.DataToReturn)),
	}

	for i, dd := range ntd.DataToReturn {
		ds.Values[i] = s.readDataDescription(scope, node, dd)
	}
	return ds
}

// canRead returns the read check of the scope for the filter evaluator.
func (q *queryScope) canRead(srv *Server) func(*ua.NodeID) bool {
	return func(id *ua.NodeID) bool { return q.readStatus(srv, id) == ua.StatusOK }
}

// readStatus is the status of reading node id in the scope: the read check
// of the server and the AccessRestrictions of the node.
func (q *queryScope) readStatus(srv *Server, id *ua.NodeID) ua.StatusCode {
	if st := srv.checkRead(q.ctx, q.sess, id); st != ua.StatusOK {
		return st
	}
	if n := srv.Node(id); n != nil {
		if st := checkAccessRestrictions(q.sc, n); st != ua.StatusOK {
			return st
		}
	}
	return ua.StatusOK
}

// readDataDescription resolves one QueryDataDescription of a node. A value
// the session may not read is returned as the StatusCode of the denied read.
func (s *QueryService) readDataDescription(scope *queryScope, node *Node, dd *ua.QueryDataDescription) *ua.Variant {
	target := node.ID()
	if dd.RelativePath != nil && len(dd.RelativePath.Elements) > 0 {
		resolved, st := s.srv.resolveRelativePath(node.ID(), dd.RelativePath)
		if st != ua.StatusGood {
			return &ua.Variant{}
		}
		target = resolved
	}

	attr := dd.AttributeID
	if attr == 0 {
		attr = ua.AttributeIDValue
	}

	if st := scope.readStatus(s.srv, target); st != ua.StatusOK {
		return ua.MustVariant(st)
	}

	ns, err := s.srv.Namespace(int(target.Namespace()))
	if err != nil {
		return &ua.Variant{}
	}
	dv := ns.Attribute(target, attr)
	if dv == nil || dv.Value == nil {
		return &ua.Variant{}
	}
	return dv.Value
}

// storeContinuation saves overflow data sets for sess and returns a
// continuation token, or false when sess holds all the continuation points
// it may (Part 4 §7.9).
func (s *QueryService) storeContinuation(sess *session, sets []*ua.QueryDataSet) ([]byte, bool) {
	stored := make([]*ua.QueryDataSet, len(sets))
	copy(stored, sets)
	return s.store().store(sessionKey(sess), s.srv.cfg.queryContinuationPointLimit(), stored)
}

// QueryNext implements the OPC UA QueryNext service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.4
func (s *QueryService) QueryNext(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.QueryNextRequest](r)
	if err != nil {
		return nil, err
	}

	if !s.srv.cfg.query {
		return nil, ua.StatusBadServiceUnsupported
	}

	if len(req.ContinuationPoint) == 0 {
		return nil, ua.StatusBadContinuationPointInvalid
	}

	// A continuation point belongs to the session that created it (Part 4
	// §7.9): for any other session it is Bad_ContinuationPointInvalid.
	owner := sessionKey(s.srv.sb.Session(req.RequestHeader.AuthenticationToken))
	sets, ok := s.store().take(owner, req.ContinuationPoint)
	if !ok {
		return nil, ua.StatusBadContinuationPointInvalid
	}

	if req.ReleaseContinuationPoint {
		return &ua.QueryNextResponse{
			ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
			QueryDataSets:  []*ua.QueryDataSet{},
		}, nil
	}

	// Return all remaining data sets and retire the continuation point. This
	// server does not re-paginate a QueryNext batch.
	return &ua.QueryNextResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		QueryDataSets:  sets,
	}, nil
}
