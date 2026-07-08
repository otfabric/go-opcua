// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// queryContinuation stores the QueryDataSets that did not fit within a
// client's MaxDataSetsToReturn limit, to be retrieved via QueryNext.
type queryContinuation struct {
	sets []*ua.QueryDataSet
}

// QueryService implements the Query Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9
type QueryService struct {
	srv *Server

	mu  sync.Mutex
	cps map[string]*queryContinuation // keyed by hex-encoded token
}

// QueryFirst implements the OPC UA QueryFirst service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.3
func (s *QueryService) QueryFirst(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.QueryFirstRequest](r)
	if err != nil {
		return nil, err
	}

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
			ntd.TypeDefinitionNode.NodeID.Equal(ua.NewTwoByteNodeID(0)) {
			pr.StatusCode = ua.StatusBadTypeDefinitionInvalid
		} else {
			pr.DataStatusCodes = make([]ua.StatusCode, len(ntd.DataToReturn))
			for d := range ntd.DataToReturn {
				pr.DataStatusCodes[d] = ua.StatusGood
			}
		}
		parsing[k] = pr
	}

	sets := s.scan(req, parsing)

	resp := &ua.QueryFirstResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		ParsingResults:  parsing,
		FilterResult:    filterResult,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}

	// Apply MaxDataSetsToReturn and spill the overflow into a continuation.
	max := int(req.MaxDataSetsToReturn)
	if max > 0 && len(sets) > max {
		resp.QueryDataSets = sets[:max]
		resp.ContinuationPoint = s.storeContinuation(sets[max:])
	} else {
		resp.QueryDataSets = sets
	}

	return resp, nil
}

// scan enumerates candidate nodes, applies type matching and the filter, and
// builds the resulting QueryDataSets.
func (s *QueryService) scan(req *ua.QueryFirstRequest, parsing []*ua.ParsingResult) []*ua.QueryDataSet {
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

			if evalFilter(s.srv, node, req.Filter) != tvlTrue {
				continue
			}

			sets = append(sets, s.buildDataSet(node, td, req.NodeTypes[k]))
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
func (s *QueryService) buildDataSet(node *Node, td *ua.NodeID, ntd *ua.NodeTypeDescription) *ua.QueryDataSet {
	ds := &ua.QueryDataSet{
		NodeID:             ua.NewExpandedNodeID(node.ID(), "", 0),
		TypeDefinitionNode: ua.NewExpandedNodeID(td, "", 0),
		Values:             make([]*ua.Variant, len(ntd.DataToReturn)),
	}

	for i, dd := range ntd.DataToReturn {
		ds.Values[i] = s.readDataDescription(node, dd)
	}
	return ds
}

func (s *QueryService) readDataDescription(node *Node, dd *ua.QueryDataDescription) *ua.Variant {
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

// storeContinuation saves overflow data sets and returns a continuation token.
func (s *QueryService) storeContinuation(sets []*ua.QueryDataSet) []byte {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	token := hex.EncodeToString(buf[:])

	stored := make([]*ua.QueryDataSet, len(sets))
	copy(stored, sets)

	s.mu.Lock()
	if s.cps == nil {
		s.cps = make(map[string]*queryContinuation)
	}
	s.cps[token] = &queryContinuation{sets: stored}
	s.mu.Unlock()
	return []byte(token)
}

// QueryNext implements the OPC UA QueryNext service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.4
func (s *QueryService) QueryNext(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.QueryNextRequest](r)
	if err != nil {
		return nil, err
	}

	if len(req.ContinuationPoint) == 0 {
		return nil, ua.StatusBadContinuationPointInvalid
	}

	token := string(req.ContinuationPoint)

	s.mu.Lock()
	defer s.mu.Unlock()

	cp, ok := s.cps[token]
	if !ok {
		return nil, ua.StatusBadContinuationPointInvalid
	}

	if req.ReleaseContinuationPoint {
		delete(s.cps, token)
		return &ua.QueryNextResponse{
			ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
			QueryDataSets:  []*ua.QueryDataSet{},
		}, nil
	}

	// Return all remaining data sets and retire the continuation point. This
	// server does not re-paginate a QueryNext batch.
	delete(s.cps, token)
	return &ua.QueryNextResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		QueryDataSets:  cp.sets,
	}, nil
}
