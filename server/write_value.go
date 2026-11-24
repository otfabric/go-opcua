// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// WriteValue writes value to the Value of the Variable nodeID for the
// session of the Method call in ctx, with the checks the Write service
// makes for that session (Part 4 §5.10.4): the AccessController
// (CheckWrite), the AccessRestrictions of the node, and the CurrentWrite
// bit of AccessLevel and UserAccessLevel (Part 3 §5.6.2). A ValueWriter of
// the node takes the value as with Write. It lets a Method of a companion
// specification write what its caller asks for, such as the
// ConfigurationData of EstablishConnections (OPC 10000-81 §6.2.4.3.7),
// with the caller's rights instead of those of the server.
//
// It returns Bad_SessionIDInvalid outside a Method call with a session and
// Bad_NodeIDUnknown for a node the server does not have.
func (s *Server) WriteValue(ctx context.Context, nodeID *ua.NodeID, value *ua.Variant) ua.StatusCode {
	caller, sess, ns, node, st := s.callerNode(ctx, nodeID)
	if st != ua.StatusOK {
		return st
	}
	st, done := s.checkWrite(ctx, sess, nodeID)
	defer done()
	if st != ua.StatusOK {
		return st
	}
	if st := accessRestrictionsFor(caller.SecurityMode, node); st != ua.StatusOK {
		return st
	}
	if st := node.AccessStatus(ua.AccessLevelTypeCurrentWrite); st != ua.StatusOK {
		return st
	}
	dv := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: value}
	if w := node.ValueWriter(); w != nil {
		return s.callValueWriter(ctx, valueWriteJob{writer: w, write: &ValueWrite{Session: sess.handle(), NodeID: nodeID, Value: dv}})
	}
	return ns.SetAttribute(nodeID, ua.AttributeIDValue, stampWritten(dv, time.Now()))
}

// ReadValue reads the Value of the Variable nodeID for the session of the
// Method call in ctx, with the checks the Read service makes for that
// session (Part 4 §5.10.2): the AccessController (CheckRead) and the access
// rules of the diagnostics and certificate nodes, the AccessRestrictions of
// the node, and the CurrentRead bit of AccessLevel and UserAccessLevel (Part
// 3 §5.6.2). It lets a Method of a companion specification compare what its
// caller supplies with a value, such as the Verify of OPC 10000-81 §6.4.3,
// with the caller's rights instead of those of the server, so that a caller
// cannot learn a value it may not read.
//
// It returns the DataValue and Good, or a Bad status: Bad_SessionIDInvalid
// outside a Method call with a session, Bad_NodeIDUnknown for a node the
// server does not have, or the status of the refused read.
func (s *Server) ReadValue(ctx context.Context, nodeID *ua.NodeID) (*ua.DataValue, ua.StatusCode) {
	caller, sess, ns, node, st := s.callerNode(ctx, nodeID)
	if st != ua.StatusOK {
		return nil, st
	}
	if st := s.checkRead(ctx, sess, nodeID); st != ua.StatusOK {
		return nil, st
	}
	if st := accessRestrictionsFor(caller.SecurityMode, node); st != ua.StatusOK {
		return nil, st
	}
	dv := ns.Attribute(nodeID, ua.AttributeIDValue)
	if dv == nil {
		return nil, ua.StatusBadAttributeIDInvalid
	}
	if dv.Status.Uint32()&0x80000000 != 0 {
		return nil, dv.Status
	}
	cp := *dv
	return &cp, ua.StatusOK
}

// callerNode returns the caller and session of the Method call in ctx and
// the namespace and node of nodeID.
func (s *Server) callerNode(ctx context.Context, nodeID *ua.NodeID) (*MethodCaller, *session, NameSpace, *Node, ua.StatusCode) {
	caller, ok := MethodCallerFromContext(ctx)
	if !ok || caller.SessionID == nil {
		return nil, nil, nil, nil, ua.StatusBadSessionIDInvalid
	}
	var sess *session
	for _, x := range s.sb.all() {
		if x.ID.Equal(caller.SessionID) {
			sess = x
			break
		}
	}
	if sess == nil {
		return nil, nil, nil, nil, ua.StatusBadSessionIDInvalid
	}
	if nodeID == nil {
		return nil, nil, nil, nil, ua.StatusBadNodeIDInvalid
	}
	ns, err := s.Namespace(int(nodeID.Namespace()))
	if err != nil {
		return nil, nil, nil, nil, ua.StatusBadNodeIDUnknown
	}
	node := ns.Node(nodeID)
	if node == nil {
		return nil, nil, nil, nil, ua.StatusBadNodeIDUnknown
	}
	return caller, sess, ns, node, ua.StatusOK
}
