// SPDX-License-Identifier: MIT

package server

import (
	"context"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// checkDataHistory authorizes one data history operation (HistoryRead of
// raw, modified, at-time or processed values; HistoryUpdate of data) on
// nodeID for the session, as Read and Write authorize the Value and
// eventHistoryNode authorizes event history:
//
//   - the AccessController and the diagnostics rules (checkRead, or
//     checkWrite for an update);
//   - the AccessRestrictions of the node (Part 3 §5.2.11);
//   - the HistoryRead or HistoryWrite bit of AccessLevel (Bad_NotReadable,
//     Bad_NotWritable) and UserAccessLevel (Bad_UserAccessDenied) when the
//     node carries them (Part 3 §5.6.2, §8.57). A node without these
//     attributes, as built with the Go API, is not restricted by them.
//
// A node the address space does not hold is left to the HistoryProvider,
// which may serve history of nodes of its own, once the AccessController
// has allowed it.
func (s *Server) checkDataHistory(ctx context.Context, sc *uasc.SecureChannel, sess *session, nodeID *ua.NodeID, write bool) ua.StatusCode {
	if nodeID == nil {
		return ua.StatusBadNodeIDInvalid
	}
	check := s.checkRead
	if write {
		check = s.checkWrite
	}
	if st := check(ctx, sess, nodeID); st != ua.StatusOK {
		return st
	}
	n := s.Node(nodeID)
	if n == nil {
		return ua.StatusOK
	}
	if st := checkAccessRestrictions(sc, n); st != ua.StatusOK {
		return st
	}
	return historyAccessStatus(n, write)
}

// historyAccessStatus checks the HistoryRead (or HistoryWrite) bit of the
// AccessLevel and UserAccessLevel attributes of n, where present.
func historyAccessStatus(n *Node, write bool) ua.StatusCode {
	flag, refused := ua.AccessLevelTypeHistoryRead, ua.StatusBadNotReadable
	if write {
		flag, refused = ua.AccessLevelTypeHistoryWrite, ua.StatusBadNotWritable
	}
	if bits, ok := accessLevelByte(n, ua.AttributeIDAccessLevel); ok && bits&byte(flag) == 0 {
		return refused
	}
	if bits, ok := accessLevelByte(n, ua.AttributeIDUserAccessLevel); ok && bits&byte(flag) == 0 {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

// accessLevelByte returns an AccessLevel or UserAccessLevel attribute of n
// and whether n has it as a Byte.
func accessLevelByte(n *Node, attr ua.AttributeID) (byte, bool) {
	a, err := n.Attribute(attr)
	if err != nil || a == nil || a.Value == nil || a.Value.Value == nil {
		return 0, false
	}
	b, ok := a.Value.Value.Value().(byte)
	return b, ok
}

// historyUpdateNodeID returns the NodeId of data HistoryUpdate details, nil
// for other details.
func historyUpdateNodeID(v any) (*ua.NodeID, bool) {
	switch d := v.(type) {
	case *ua.UpdateDataDetails:
		return d.NodeID, true
	case ua.UpdateDataDetails:
		return d.NodeID, true
	case *ua.DeleteRawModifiedDetails:
		return d.NodeID, true
	case ua.DeleteRawModifiedDetails:
		return d.NodeID, true
	case *ua.DeleteAtTimeDetails:
		return d.NodeID, true
	case ua.DeleteAtTimeDetails:
		return d.NodeID, true
	}
	return nil, false
}
