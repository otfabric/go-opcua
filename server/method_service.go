// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/otfabric/go-opcua/id"
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
	s.srv.cfg.logger.Debug("handling request", "type", fmt.Sprintf("%T", r))

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

	// Validate input arguments against the method's InputArguments property
	// when declared (IEC 62541-4 Call Service).
	if result := validateMethodInputs(s.srv, m.MethodID, m.InputArguments); result != nil {
		return result
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

// validateMethodInputs checks argument count and built-in type compatibility
// against the method node's InputArguments property. Returns nil when
// validation passes (or when no InputArguments property is declared and
// zero arguments were supplied).
func validateMethodInputs(srv *Server, methodID *ua.NodeID, inputs []*ua.Variant) *ua.CallMethodResult {
	expected := declaredInputArguments(srv, methodID)
	// No InputArguments property: treat as zero-argument method.
	if expected == nil {
		if len(inputs) > 0 {
			return &ua.CallMethodResult{
				StatusCode:           ua.StatusBadTooManyArguments,
				InputArgumentResults: allStatusOK(len(inputs)),
			}
		}
		return nil
	}

	if len(inputs) < len(expected) {
		results := make([]ua.StatusCode, len(expected))
		for i := range results {
			if i < len(inputs) {
				results[i] = ua.StatusOK
			} else {
				results[i] = ua.StatusBadArgumentsMissing
			}
		}
		return &ua.CallMethodResult{
			StatusCode:           ua.StatusBadArgumentsMissing,
			InputArgumentResults: results,
		}
	}

	if len(inputs) > len(expected) {
		return &ua.CallMethodResult{
			StatusCode:           ua.StatusBadTooManyArguments,
			InputArgumentResults: allStatusOK(len(inputs)),
		}
	}

	results := make([]ua.StatusCode, len(inputs))
	mismatch := false
	for i, arg := range expected {
		if !variantMatchesArgument(inputs[i], arg) {
			results[i] = ua.StatusBadTypeMismatch
			mismatch = true
		} else {
			results[i] = ua.StatusOK
		}
	}
	if mismatch {
		return &ua.CallMethodResult{
			StatusCode:           ua.StatusBadTypeMismatch,
			InputArgumentResults: results,
		}
	}
	return nil
}

func allStatusOK(n int) []ua.StatusCode {
	out := make([]ua.StatusCode, n)
	for i := range out {
		out[i] = ua.StatusOK
	}
	return out
}

// declaredInputArguments reads the InputArguments property of a method node.
// Returns nil when the property is absent (zero declared inputs).
func declaredInputArguments(srv *Server, methodID *ua.NodeID) []*ua.Argument {
	methodNode := srv.Node(methodID)
	if methodNode == nil {
		return nil
	}
	methodNode.mu.RLock()
	defer methodNode.mu.RUnlock()

	for _, ref := range methodNode.refs {
		if ref == nil || ref.BrowseName == nil || ref.NodeID == nil || ref.NodeID.NodeID == nil {
			continue
		}
		if ref.ReferenceTypeID == nil || ref.ReferenceTypeID.IntID() != id.HasProperty {
			continue
		}
		if ref.BrowseName.Name != "InputArguments" {
			continue
		}
		prop := srv.Node(ref.NodeID.NodeID)
		if prop == nil {
			return nil
		}
		dv := prop.Value()
		if dv == nil || dv.Value == nil {
			return nil
		}
		eos, ok := dv.Value.Value().([]*ua.ExtensionObject)
		if !ok {
			return nil
		}
		args := make([]*ua.Argument, 0, len(eos))
		for _, eo := range eos {
			if eo == nil {
				continue
			}
			if a, ok := eo.Value.(*ua.Argument); ok {
				args = append(args, a)
			}
		}
		return args
	}
	return nil
}

// variantMatchesArgument reports whether v is compatible with the declared
// Argument DataType / ValueRank for built-in types in namespace 0.
func variantMatchesArgument(v *ua.Variant, arg *ua.Argument) bool {
	if v == nil || arg == nil || arg.DataType == nil {
		return true
	}
	// Built-in DataType NodeIDs in ns=0 use the TypeID numeric identifier.
	if arg.DataType.Namespace() != 0 {
		return true // cannot validate custom types here
	}
	want := ua.TypeID(arg.DataType.IntID())
	if v.Type() != want {
		return false
	}
	// ValueRank -1 = scalar; 1 = one-dimensional array.
	isArray := v.ArrayLength() > 0
	switch arg.ValueRank {
	case -1:
		return !isArray
	case 1:
		return isArray
	default:
		return true
	}
}
