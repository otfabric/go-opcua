// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// Annotations of HistoricalDataNodes (Part 11 §5.1.2, §6.6.6).
//
// A Variable or Object whose history supports Annotations has the
// Annotations Property ([Server.EnableAnnotations]). Its Annotations are
// read with HistoryRead, ReadAnnotationDataDetails on the node (Part 11
// §6.5.6) or ReadRawModifiedDetails on the Annotations Property (§5.1.2),
// and changed with HistoryUpdate UpdateStructureDataDetails (§6.9.3). The
// server hands both to the [AnnotationHistoryProvider] of the server with
// the NodeId of the node that has the Annotations Property.
//
// Choices of this implementation, where Part 11 leaves them open:
//   - The nodeId of UpdateStructureDataDetails, "Node id of the Object to
//     be updated" (§6.9.3.1), may be the node or its Annotations Property;
//     ReadAnnotationDataDetails takes either as well. A node in the address
//     space without an Annotations Property supports no Annotations
//     (Bad_HistoryOperationUnsupported): "A Server may add the Annotations
//     Property to a HistoricalDataNode only if it also supports
//     Annotations on that node" (§5.1.2). A node the address space does not
//     hold is left to the provider, as other history is.
//   - Each Annotation is a DataValue whose Value is the Annotation and
//     whose SourceTimestamp is the time of the value it annotates; the
//     timestamp is what makes an Annotation unique (§6.9.3.2 lets the Server
//     choose, a timestamp being one of its examples).
//   - An Annotation without an annotationTime, "The time the Annotation was
//     added" (§6.6.6), gets the time of the HistoryUpdate; one without a
//     userName, "The user that added the Annotation" (§6.6.6), gets the user
//     of the session, unless the session is anonymous.
//   - The Value of the Annotations Property is null: Part 11 gives it no
//     value of its own, and "The presence of the Annotations Property does
//     not indicate the presence of Annotations" (§5.1.2).

// annotationsName is the BrowseName of the Annotations Property (Part 11
// §5.1.2, Table 2), in namespace 0 as its declaration i=11214.
const annotationsName = "Annotations"

// EnableAnnotations gives the Variable or Object nodeID the Annotations
// Property (Part 11 §5.1.2): "Any HistoricalDataNode that supports
// changing, deleting, or adding Annotations shall have the Annotations
// Property". The Property has the DataType Annotation and the HistoryRead
// and HistoryWrite bits; its history is the Annotations of the node, kept
// by the [AnnotationHistoryProvider] of the server (the default
// [*Historian] keeps them for the nodes of its EnableNode). A node that
// has the Property already is left as it is.
//
// The errors are Bad_NodeIdInvalid for a nil nodeID, Bad_NodeIdUnknown for
// a node the address space does not hold and Bad_NodeClassInvalid for a
// node other than a Variable or Object, or a Property: "Since Properties
// cannot have Properties, the Annotations Property can only exist on
// DataVariables or Objects" (§5.1.2).
func (s *Server) EnableAnnotations(nodeID *ua.NodeID) error {
	if nodeID == nil {
		return ua.StatusBadNodeIDInvalid
	}
	ns, err := s.Namespace(int(nodeID.Namespace()))
	if err != nil {
		return ua.StatusBadNodeIDUnknown
	}
	n := s.Node(nodeID)
	if n == nil {
		return ua.StatusBadNodeIDUnknown
	}
	if nodeID.Namespace() == 0 {
		// Namespace 0 nodes are shared between servers.
		if own := s.ownNode(nodeID.IntID()); own != nil {
			n = own
		}
	}
	if nc := n.NodeClass(); nc != ua.NodeClassObject && nc != ua.NodeClassVariable || isProperty(n) {
		return ua.StatusBadNodeClassInvalid
	}
	if s.annotationsProperty(n) != nil {
		return nil
	}
	access := byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeHistoryRead | ua.AccessLevelTypeHistoryWrite)
	p := NewNode(childPropertyID(n.ID(), annotationsName), Attributes{
		ua.AttributeIDNodeClass:   DataValueFromValue(uint32(ua.NodeClassVariable)),
		ua.AttributeIDBrowseName:  DataValueFromValue(&ua.QualifiedName{Name: annotationsName}),
		ua.AttributeIDDisplayName: DataValueFromValue(attrs.DisplayName(annotationsName, "")),
		ua.AttributeIDDescription: DataValueFromValue(&ua.LocalizedText{}),
		ua.AttributeIDDataType:    DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Annotation)),
		// Any (-2), the ValueRank of the declaration i=11214.
		ua.AttributeIDValueRank:       DataValueFromValue(int32(-2)),
		ua.AttributeIDAccessLevel:     DataValueFromValue(access),
		ua.AttributeIDUserAccessLevel: DataValueFromValue(access),
		ua.AttributeIDHistorizing:     DataValueFromValue(false),
	}, nil, func() *ua.DataValue {
		return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(nil)}
	})
	p = ns.AddNode(p)
	if tn := s.Node(ua.NewNumericNodeID(0, id.PropertyType)); tn != nil {
		p.AddRef(tn, RefType(id.HasTypeDefinition), true)
	}
	linkChild(n, p, id.HasProperty)
	return nil
}

// isProperty reports whether n is a Property: a Variable of PropertyType.
func isProperty(n *Node) bool {
	for _, r := range n.refsSnapshot() {
		if r != nil && r.IsForward && r.ReferenceTypeID != nil && r.ReferenceTypeID.IntID() == id.HasTypeDefinition &&
			r.NodeID != nil && r.NodeID.NodeID != nil && r.NodeID.NodeID.Namespace() == 0 && r.NodeID.NodeID.IntID() == id.PropertyType {
			return true
		}
	}
	return false
}

// annotationsProperty returns the Annotations Property of n, nil if it has
// none.
func (s *Server) annotationsProperty(n *Node) *Node {
	for _, r := range n.refsSnapshot() {
		if r == nil || !r.IsForward || r.ReferenceTypeID == nil || r.ReferenceTypeID.IntID() != id.HasProperty ||
			r.NodeID == nil || r.NodeID.NodeID == nil {
			continue
		}
		if p := s.Node(r.NodeID.NodeID); p != nil && isAnnotationsName(p.BrowseName()) {
			return p
		}
	}
	return nil
}

func isAnnotationsName(q *ua.QualifiedName) bool {
	return q != nil && q.NamespaceIndex == 0 && q.Name == annotationsName
}

// annotationsOwner returns the node whose Annotations Property p is, nil
// when p is no Annotations Property.
func (s *Server) annotationsOwner(p *Node) *Node {
	if p.NodeClass() != ua.NodeClassVariable || !isAnnotationsName(p.BrowseName()) {
		return nil
	}
	for _, r := range p.refsSnapshot() {
		if r == nil || r.IsForward || r.ReferenceTypeID == nil || r.ReferenceTypeID.IntID() != id.HasProperty ||
			r.NodeID == nil || r.NodeID.NodeID == nil {
			continue
		}
		if n := s.Node(r.NodeID.NodeID); n != nil {
			return n
		}
	}
	return nil
}

// annotationsTarget returns the NodeId the Annotations of a HistoryRead or
// HistoryUpdate on nodeID belong to and authorizes the operation on it as
// on nodeID (checkDataHistory): the node itself when it has the Annotations
// Property, the node that has the Property when nodeID is one, nodeID for a
// node the address space does not hold. Bad_HistoryOperationUnsupported
// for a node of the address space without Annotations.
func (s *Server) annotationsTarget(ctx context.Context, sc *uasc.SecureChannel, sess *session, nodeID *ua.NodeID, write bool) (*ua.NodeID, ua.StatusCode) {
	if st := s.checkDataHistory(ctx, sc, sess, nodeID, write); st != ua.StatusOK {
		return nil, st
	}
	n := s.Node(nodeID)
	if n == nil {
		return nodeID, ua.StatusOK
	}
	if s.annotationsProperty(n) != nil {
		return nodeID, ua.StatusOK
	}
	owner := s.annotationsOwner(n)
	if owner == nil {
		return nil, ua.StatusBadHistoryOperationUnsupported
	}
	if st := s.checkDataHistory(ctx, sc, sess, owner.ID(), write); st != ua.StatusOK {
		return nil, st
	}
	return owner.ID(), ua.StatusOK
}

// annotationsPropertyOwner returns the node whose Annotations Property
// nodeID is, nil when nodeID is none, for the ReadRawModifiedDetails of the
// Property (Part 11 §5.1.2).
func (s *Server) annotationsPropertyOwner(nodeID *ua.NodeID) *ua.NodeID {
	if nodeID == nil {
		return nil
	}
	p := s.Node(nodeID)
	if p == nil {
		return nil
	}
	if owner := s.annotationsOwner(p); owner != nil {
		return owner.ID()
	}
	return nil
}

// annotationReadDetails returns the ReadAnnotationDataDetails of HistoryRead
// details, nil for other details.
func annotationReadDetails(v any) *ua.ReadAnnotationDataDetails {
	switch d := v.(type) {
	case *ua.ReadAnnotationDataDetails:
		return d
	case ua.ReadAnnotationDataDetails:
		return &d
	}
	return nil
}

// annotationOf returns the Annotation a DataValue of UpdateStructureData
// carries, nil if it carries none.
func annotationOf(dv *ua.DataValue) *ua.Annotation {
	if dv == nil || dv.Value == nil {
		return nil
	}
	eo, ok := dv.Value.Value().(*ua.ExtensionObject)
	if !ok || eo == nil {
		return nil
	}
	switch a := eo.Value.(type) {
	case *ua.Annotation:
		return a
	case ua.Annotation:
		return &a
	}
	return nil
}

// annotationValue is the DataValue of an Annotation at ts.
func annotationValue(a *ua.Annotation, ts time.Time) *ua.DataValue {
	return &ua.DataValue{
		EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp,
		Value:           ua.MustVariant(ua.NewExtensionObject(a)),
		SourceTimestamp: ts,
	}
}

// annotationUser is the userName the server gives an Annotation without
// one: the user of the session; empty for an anonymous session.
func annotationUser(sess *session) string {
	if sess == nil {
		return ""
	}
	switch sess.identityToken.(type) {
	case *ua.UserNameIdentityToken, *ua.X509IdentityToken, *ua.IssuedIdentityToken:
		return auditUserID(sess.identityToken)
	}
	return ""
}

// updateAnnotations serves UpdateStructureDataDetails (Part 11 §6.9.3) for
// the Annotations of a node. The details are checked before the provider
// is called: a PerformUpdateType that is none of Insert, Replace, Update
// and Remove is Bad_InvalidArgument for the details; each value needs a
// SourceTimestamp (else Bad_InvalidArgument) and, but for Remove, an
// Annotation (else Bad_TypeMismatch). The provider is called with the
// values that pass, an Annotation and its timestamp each; old holds the
// Annotations they replace or remove, read before when the update is
// audited (see auditHistoryUpdate).
func (s *AttributeService) updateAnnotations(ctx context.Context, sc *uasc.SecureChannel, sess *session, h HistoryProvider, d *ua.UpdateStructureDataDetails) (res *ua.HistoryUpdateResult, newValues, oldValues []*ua.DataValue) {
	p, ok := h.(AnnotationHistoryProvider)
	if !ok {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil, nil
	}
	target, st := s.srv.annotationsTarget(ctx, sc, sess, d.NodeID, true)
	if st != ua.StatusOK {
		return &ua.HistoryUpdateResult{StatusCode: st}, nil, nil
	}
	perform := d.PerformInsertReplace
	switch perform {
	case ua.PerformUpdateTypeInsert, ua.PerformUpdateTypeReplace, ua.PerformUpdateTypeUpdate, ua.PerformUpdateTypeRemove:
	default:
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadInvalidArgument}, nil, nil
	}
	now := time.Now().UTC()
	user := annotationUser(sess)
	ops := make([]ua.StatusCode, len(d.UpdateValues))
	var values []*ua.DataValue
	var index []int
	for i, dv := range d.UpdateValues {
		if dv == nil || dv.SourceTimestamp.IsZero() {
			ops[i] = ua.StatusBadInvalidArgument
			continue
		}
		var a *ua.Annotation
		if perform != ua.PerformUpdateTypeRemove {
			if a = annotationOf(dv); a == nil {
				ops[i] = ua.StatusBadTypeMismatch
				continue
			}
			c := *a
			if c.AnnotationTime.IsZero() {
				c.AnnotationTime = now
			}
			if c.UserName == "" {
				c.UserName = user
			}
			a = &c
		}
		v := annotationValue(a, dv.SourceTimestamp)
		if a == nil {
			v = &ua.DataValue{EncodingMask: ua.DataValueSourceTimestamp, SourceTimestamp: dv.SourceTimestamp}
		}
		values = append(values, v)
		index = append(index, i)
	}
	if len(values) == 0 {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusOK, OperationResults: ops}, nil, nil
	}
	if perform != ua.PerformUpdateTypeInsert && s.srv.auditsChanges() {
		oldValues = s.srv.oldAnnotations(p, target, values)
	}
	r := p.UpdateAnnotations(target, perform, values)
	if r == nil {
		return &ua.HistoryUpdateResult{StatusCode: ua.StatusBadInternalError}, values, oldValues
	}
	if isBad(r.StatusCode) {
		return &ua.HistoryUpdateResult{StatusCode: r.StatusCode}, values, oldValues
	}
	for j, i := range index {
		op := ua.StatusBadInternalError
		if j < len(r.OperationResults) {
			op = r.OperationResults[j]
		}
		ops[i] = op
	}
	return &ua.HistoryUpdateResult{StatusCode: r.StatusCode, OperationResults: ops}, values, oldValues
}

// oldAnnotations returns the Annotations the provider holds at the times
// of values, for the OldValues of an audit event.
func (s *Server) oldAnnotations(p AnnotationHistoryProvider, nodeID *ua.NodeID, values []*ua.DataValue) []*ua.DataValue {
	times := make([]time.Time, len(values))
	for i, v := range values {
		times[i] = v.SourceTimestamp
	}
	res, err := p.ReadAnnotations(nodeID, times)
	if err != nil {
		return nil
	}
	var out []*ua.DataValue
	for _, dv := range historyDataValues(res) {
		if dv != nil && !isBad(dv.Status) && annotationOf(dv) != nil {
			out = append(out, dv)
		}
	}
	return out
}

// readAnnotations serves ReadAnnotationDataDetails (Part 11 §6.5.6): the
// Annotations of a node at the reqTimes, in their order.
func (s *AttributeService) readAnnotations(ctx context.Context, sc *uasc.SecureChannel, sess *session, h HistoryProvider, d *ua.ReadAnnotationDataDetails, nodeID *ua.NodeID) (*ua.HistoryReadResult, error) {
	p, ok := h.(AnnotationHistoryProvider)
	if !ok {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}, nil
	}
	target, st := s.srv.annotationsTarget(ctx, sc, sess, nodeID, false)
	if st != ua.StatusOK {
		return &ua.HistoryReadResult{StatusCode: st}, nil
	}
	return p.ReadAnnotations(target, d.ReqTimes)
}

// readAnnotationRange reads the Annotations of nodeID from from to to,
// following the continuation points of the provider, for AnnotationCount.
func readAnnotationRange(p AnnotationHistoryProvider, h HistoryProvider, nodeID *ua.NodeID, from, to time.Time) ([]*ua.DataValue, ua.StatusCode, error) {
	return readPages(h, func(cp []byte) (*ua.HistoryReadResult, error) {
		return p.ReadRawAnnotations(nodeID, from, to, 0, cp)
	})
}
