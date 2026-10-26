// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"sync"
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
		m = s.srv.instanceMethod(m)
		if m.MethodID != nil {
			if sc := ac.CheckCall(ctx, sess.handle(), m.MethodID); sc != ua.StatusOK {
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
		mctx := withMethodCaller(ctx, sess, sc)
		if caller, ok := MethodCallerFromContext(mctx); ok && req.RequestHeader != nil {
			caller.AuditEntryID = req.RequestHeader.AuditEntryID
		}
		results[i] = s.callMethod(mctx, m)
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

// instanceMethod returns the call of the Method of the Object when the
// MethodId of m is the InstanceDeclaration of that Method: a Method of the
// ObjectType of the Object, or of one of its supertypes, with the
// BrowseName of a Method of the Object that has a handler (Part 4
// §5.11.2.2; UA-.NETStandard calls the FileType methods of a TrustList that
// way). Otherwise, or when the pair has a handler itself, it returns m.
func (s *Server) instanceMethod(m *ua.CallMethodRequest) *ua.CallMethodRequest {
	if m == nil || m.ObjectID == nil || m.MethodID == nil {
		return m
	}
	s.mu.Lock()
	_, ok := s.methods[methodKey(m.ObjectID, m.MethodID)]
	s.mu.Unlock()
	if ok {
		return m
	}
	obj, decl := s.Node(m.ObjectID), s.Node(m.MethodID)
	if obj == nil || decl == nil || decl.NodeClass() != ua.NodeClassMethod {
		return m
	}
	declared := false
	seen := map[string]bool{}
	for t := nodeTypeDefinition(obj); t != nil && !declared && !seen[t.String()]; t = s.superType(t) {
		seen[t.String()] = true
		declared = hasComponent(s.Node(t), m.MethodID)
	}
	if !declared {
		return m
	}
	name := decl.BrowseName()
	for _, r := range obj.refsSnapshot() {
		if r == nil || !r.IsForward || r.ReferenceTypeID == nil || r.ReferenceTypeID.IntID() != id.HasComponent || r.NodeID == nil {
			continue
		}
		target := s.Node(r.NodeID.NodeID)
		if target == nil || target.NodeClass() != ua.NodeClassMethod {
			continue
		}
		if bn := target.BrowseName(); bn == nil || name == nil || bn.Name != name.Name || bn.NamespaceIndex != name.NamespaceIndex {
			continue
		}
		s.mu.Lock()
		_, ok := s.methods[methodKey(m.ObjectID, target.ID())]
		s.mu.Unlock()
		if ok {
			out := *m
			out.MethodID = target.ID()
			return &out
		}
	}
	return m
}

// hasComponent reports whether n has a forward HasComponent reference to
// target.
func hasComponent(n *Node, target *ua.NodeID) bool {
	if n == nil {
		return false
	}
	for _, r := range n.refsSnapshot() {
		if r != nil && r.IsForward && r.ReferenceTypeID != nil && r.ReferenceTypeID.IntID() == id.HasComponent &&
			r.NodeID != nil && r.NodeID.NodeID.Equal(target) {
			return true
		}
	}
	return false
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
		if !variantMatchesArgument(srv, inputs[i], arg) {
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
		// The forward HasProperty of the method; the inverse one leads to
		// the parent of a Property.
		if !ref.IsForward || ref.ReferenceTypeID == nil || ref.ReferenceTypeID.IntID() != id.HasProperty {
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
// Argument DataType / ValueRank for data types in namespace 0. A subtype of
// a built-in type (IntegerId, Duration, UtcTime, ...) takes the encoding of
// the built-in type it derives from; BaseDataType and the abstract types
// below it accept any value.
func variantMatchesArgument(srv *Server, v *ua.Variant, arg *ua.Argument) bool {
	if v == nil || arg == nil || arg.DataType == nil {
		return true
	}
	// Built-in DataType NodeIDs in ns=0 use the TypeID numeric identifier.
	if arg.DataType.Namespace() != 0 {
		return true // cannot validate custom types here
	}
	want, ok := builtinTypeOf(srv, arg.DataType)
	if !ok {
		return true
	}
	if v.Type() != want {
		return false
	}
	// ValueRank -1 = scalar; 1 = one-dimensional array (possibly empty).
	switch arg.ValueRank {
	case -1:
		return !v.IsArray()
	case 1:
		return v.IsArray()
	default:
		return true
	}
}

// builtinTypeOf returns the built-in type a namespace 0 DataType is encoded
// as: the type itself or the built-in type it is a subtype of. It returns
// false for BaseDataType, for the abstract types below it that are not
// subtypes of a built-in type (Number, Integer, Enumeration) and for
// unknown types. The standard type tree does not change, so the results
// are cached.
func builtinTypeOf(srv *Server, dt *ua.NodeID) (ua.TypeID, bool) {
	if dt == nil || dt.Namespace() != 0 || dt.Type() != ua.NodeIDTypeNumeric {
		return 0, false
	}
	n := dt.IntID()
	if n == id.BaseDataType {
		return 0, false
	}
	if n >= 1 && n <= id.DiagnosticInfo {
		return ua.TypeID(n), true
	}
	if t, ok := builtinTypeCache.Load(n); ok {
		return t.(ua.TypeID), t.(ua.TypeID) != 0
	}
	if srv == nil || srv.Node(dt) == nil {
		return 0, false
	}
	var found ua.TypeID
	for b := uint32(1); b <= id.DiagnosticInfo; b++ {
		if b != id.BaseDataType && srv.isSubtypeOf(dt, ua.NewNumericNodeID(0, b)) {
			found = ua.TypeID(b)
			break
		}
	}
	builtinTypeCache.Store(n, found)
	return found, found != 0
}

// builtinTypeCache maps namespace 0 DataType ids to their built-in type
// (0: none).
var builtinTypeCache sync.Map
