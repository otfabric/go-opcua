package server

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// MethodHandler is the callback signature for server-side method implementations.
//
// Register handlers with [Server.RegisterMethod]. The handler receives the
// object and method NodeIDs along with the input arguments, and returns
// output arguments and a status code.
type MethodHandler func(ctx context.Context, objectID, methodID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)

// MethodService implements the Method Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.11
type MethodService struct {
	srv *Server
}

// Call implements the OPC UA Call service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.11.2
func (s *MethodService) Call(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debugf("handling request type=%T", r)

	req, err := safeReq[*ua.CallRequest](r)
	if err != nil {
		return nil, err
	}

	results := make([]*ua.CallMethodResult, len(req.MethodsToCall))

	sess := s.srv.sb.Session(req.RequestHeader.AuthenticationToken)
	ac := s.srv.cfg.accessController

	for i, m := range req.MethodsToCall {
		if m.MethodID != nil {
			if sc := ac.CheckCall(ctx, sess, m.MethodID); sc != ua.StatusOK {
				results[i] = &ua.CallMethodResult{StatusCode: sc}
				continue
			}
			if node := s.srv.Node(m.MethodID); node != nil {
				if st := checkAccessRestrictions(sc, node); st != ua.StatusOK {
					results[i] = &ua.CallMethodResult{StatusCode: st}
					continue
				}
			}
		}
		results[i] = s.callMethod(ctx, m)
	}

	return &ua.CallResponse{
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

func (s *MethodService) callMethod(ctx context.Context, m *ua.CallMethodRequest) *ua.CallMethodResult {
	if m.ObjectID == nil || m.MethodID == nil {
		return &ua.CallMethodResult{StatusCode: ua.StatusBadMethodInvalid}
	}

	// Check that the object node exists.
	objNode := s.srv.Node(m.ObjectID)
	if objNode == nil {
		return &ua.CallMethodResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}

	// Look up the registered handler.
	s.srv.mu.Lock()
	h, ok := s.srv.methods[methodKey(m.ObjectID, m.MethodID)]
	s.srv.mu.Unlock()

	if !ok {
		return &ua.CallMethodResult{StatusCode: ua.StatusBadMethodInvalid}
	}

	outputs, status := h(ctx, m.ObjectID, m.MethodID, m.InputArguments)

	inputResults := make([]ua.StatusCode, len(m.InputArguments))
	for j := range inputResults {
		inputResults[j] = ua.StatusOK
	}

	return &ua.CallMethodResult{
		StatusCode:                   status,
		InputArgumentResults:         inputResults,
		InputArgumentDiagnosticInfos: []*ua.DiagnosticInfo{},
		OutputArguments:              outputs,
	}
}
