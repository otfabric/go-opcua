// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

var (
	hasSubtype = ua.NewNumericNodeID(0, id.HasSubtype)
)

// continuationPoint stores remaining references for a BrowseNext call.
type continuationPoint struct {
	refs []*ua.ReferenceDescription
}

// ViewService implements the View Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.8
type ViewService struct {
	srv *Server
	mu  sync.Mutex
	cps map[string]*continuationPoint // keyed by hex-encoded token
}

// Browse implements the OPC UA Browse service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.8.2
func (s *ViewService) Browse(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {

	req, err := safeReq[*ua.BrowseRequest](r)
	if err != nil {
		return nil, err
	}
	s.srv.cfg.logger.Debug("browse incoming")

	resp := &ua.BrowseResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results: make([]*ua.BrowseResult, len(req.NodesToBrowse)),

		DiagnosticInfos: []*ua.DiagnosticInfo{{}},
	}

	maxRefs := req.RequestedMaxReferencesPerNode

	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)
	ac := s.srv.cfg.accessController

	for i := range req.NodesToBrowse {
		br := req.NodesToBrowse[i]
		s.srv.cfg.logger.Debug("browse", "node_id", br.NodeID)

		if sc := ac.CheckBrowse(context.Background(), sess, br.NodeID); sc != ua.StatusOK {
			resp.Results[i] = &ua.BrowseResult{StatusCode: sc}
			continue
		}

		ns, err := s.srv.Namespace(int(br.NodeID.Namespace()))
		if err != nil {
			resp.Results[i] = &ua.BrowseResult{StatusCode: ua.StatusBad}
			continue
		}

		if node := ns.Node(br.NodeID); node != nil {
			if st := checkAccessRestrictionsForBrowse(sc, node); st != ua.StatusOK {
				resp.Results[i] = &ua.BrowseResult{StatusCode: st}
				continue
			}
		}

		result := ns.Browse(br)

		// Apply continuation point logic when maxRefs > 0 and there are more refs.
		if maxRefs > 0 && uint32(len(result.References)) > maxRefs {
			cp := s.storeContinuation(result.References[maxRefs:])
			result.ContinuationPoint = cp
			result.References = result.References[:maxRefs]
		}
		resp.Results[i] = result
	}

	return resp, nil
}

// storeContinuation saves remaining references and returns a continuation point token.
func (s *ViewService) storeContinuation(refs []*ua.ReferenceDescription) []byte {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	token := hex.EncodeToString(buf[:])

	stored := make([]*ua.ReferenceDescription, len(refs))
	copy(stored, refs)

	s.mu.Lock()
	if s.cps == nil {
		s.cps = make(map[string]*continuationPoint)
	}
	s.cps[token] = &continuationPoint{refs: stored}
	s.mu.Unlock()
	return []byte(token)
}

// BrowseNext implements the OPC UA BrowseNext service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.8.3
func (s *ViewService) BrowseNext(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.BrowseNextRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]*ua.BrowseResult, len(req.ContinuationPoints))

	s.mu.Lock()
	defer s.mu.Unlock()

	for i, cpBytes := range req.ContinuationPoints {
		token := string(cpBytes)
		cp, ok := s.cps[token]
		if !ok {
			results[i] = &ua.BrowseResult{StatusCode: ua.StatusBadContinuationPointInvalid}
			continue
		}

		if req.ReleaseContinuationPoints {
			delete(s.cps, token)
			results[i] = &ua.BrowseResult{StatusCode: ua.StatusGood}
			continue
		}

		// Return all remaining references (no further pagination for simplicity).
		delete(s.cps, token)
		results[i] = &ua.BrowseResult{
			StatusCode: ua.StatusGood,
			References: cp.refs,
		}
	}

	return &ua.BrowseNextResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

func suitableRef(srv *Server, desc *ua.BrowseDescription, ref *ua.ReferenceDescription) bool {
	if !suitableDirection(desc.BrowseDirection, ref.IsForward) {
		srv.cfg.logger.Debug("not suitable because of direction", "ref", ref)
		return false
	}
	if !suitableRefType(srv, desc.ReferenceTypeID, ref.ReferenceTypeID, desc.IncludeSubtypes) {
		srv.cfg.logger.Debug("not suitable because of ref type", "ref", ref)
		return false
	}
	if desc.NodeClassMask > 0 && desc.NodeClassMask&uint32(ref.NodeClass) == 0 {
		srv.cfg.logger.Debug("not suitable because of node class", "ref", ref)
		return false
	}
	return true
}

func suitableDirection(bd ua.BrowseDirection, isForward bool) bool {
	switch {
	case bd == ua.BrowseDirectionBoth:
		return true
	case bd == ua.BrowseDirectionForward && isForward:
		return true
	case bd == ua.BrowseDirectionInverse && !isForward:
		return true
	default:
		return false
	}
}

func suitableRefType(srv *Server, ref1, ref2 *ua.NodeID, subtypes bool) bool {
	if ref1.Equal(ua.NewNumericNodeID(0, 0)) {
		// refType is not specified in browse description. Return all types
		return true
	}
	if ref1.Equal(ref2) {
		return true
	}
	hasRef2Fn := func(nid *ua.NodeID) bool { return nid.Equal(ref2) }
	hasSubtypeFn := func(nid *ua.NodeID) bool { return nid.Equal(hasSubtype) }
	oktypes := getSubRefs(srv, ref1)
	if !subtypes && slices.ContainsFunc(oktypes, hasSubtypeFn) {
		for n := slices.IndexFunc(oktypes, hasSubtypeFn); n > 0; {
			oktypes = slices.Delete(oktypes, n, n+1)
		}
	}
	return slices.ContainsFunc(oktypes, hasRef2Fn)
}

func getSubRefs(srv *Server, nid *ua.NodeID) []*ua.NodeID {
	return getSubRefsVisited(srv, nid, make(map[string]bool))
}

func getSubRefsVisited(srv *Server, nid *ua.NodeID, visited map[string]bool) []*ua.NodeID {
	key := nid.String()
	if visited[key] {
		return nil
	}
	visited[key] = true

	ns, err := srv.Namespace(int(nid.Namespace()))
	if err != nil {
		// Namespace lookup failure is non-fatal here; the caller already filtered
		// to known reference type IDs, so an empty result is acceptable.
		return nil
	}
	node := ns.Node(nid)
	if node == nil {
		return nil
	}
	var refs []*ua.NodeID
	for _, ref := range node.refs {
		if ref.ReferenceTypeID.Equal(hasSubtype) && ref.IsForward && ref.NodeID != nil {
			refs = append(refs, ref.NodeID.NodeID)
			refs = append(refs, getSubRefsVisited(srv, ref.NodeID.NodeID, visited)...)
		}
	}
	return refs
}

// TranslateBrowsePathsToNodeIDs implements the OPC UA TranslateBrowsePathsToNodeIDs service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.8.4
func (s *ViewService) TranslateBrowsePathsToNodeIDs(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.TranslateBrowsePathsToNodeIDsRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]*ua.BrowsePathResult, len(req.BrowsePaths))
	for i, bp := range req.BrowsePaths {
		results[i] = s.translatePath(bp)
	}

	return &ua.TranslateBrowsePathsToNodeIDsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil
}

func (s *ViewService) translatePath(bp *ua.BrowsePath) *ua.BrowsePathResult {
	if bp == nil {
		return &ua.BrowsePathResult{StatusCode: ua.StatusBadBrowseNameInvalid}
	}

	target, st := s.srv.resolveRelativePath(bp.StartingNode, bp.RelativePath)
	if st != ua.StatusGood {
		return &ua.BrowsePathResult{StatusCode: st}
	}

	return &ua.BrowsePathResult{
		StatusCode: ua.StatusGood,
		Targets: []*ua.BrowsePathTarget{
			{
				TargetID:           ua.NewExpandedNodeID(target, "", 0),
				RemainingPathIndex: 0xFFFFFFFF, // indicates complete resolution
			},
		},
	}
}

// RegisterNodes implements the OPC UA RegisterNodes service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.8.5
func (s *ViewService) RegisterNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.RegisterNodesRequest](r)
	if err != nil {
		return nil, err
	}

	// Per OPC-UA spec, RegisterNodes is a performance hint. The server may
	// create optimised handles but is not required to. Our implementation
	// validates that the requested nodes exist and returns the same NodeIDs.
	registered := make([]*ua.NodeID, len(req.NodesToRegister))
	for i, nid := range req.NodesToRegister {
		if nid == nil {
			continue
		}
		ns, nsErr := s.srv.Namespace(int(nid.Namespace()))
		if nsErr != nil {
			continue
		}
		n := ns.Node(nid)
		if n == nil {
			continue
		}
		registered[i] = nid
	}

	return &ua.RegisterNodesResponse{
		ResponseHeader:    responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		RegisteredNodeIDs: registered,
	}, nil
}

// UnregisterNodes implements the OPC UA UnregisterNodes service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.8.6
func (s *ViewService) UnregisterNodes(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

	req, err := safeReq[*ua.UnregisterNodesRequest](r)
	if err != nil {
		return nil, err
	}

	// Per OPC-UA spec, UnregisterNodes releases any optimised handles
	// created by RegisterNodes. Since our RegisterNodes does not create
	// special handles, this is a no-op that always succeeds.
	_ = req.NodesToUnregister

	return &ua.UnregisterNodesResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
	}, nil
}
