// SPDX-License-Identifier: MIT

package server

import (
	"github.com/otfabric/go-opcua/ua"
)

// AccessLevel, UserAccessLevel and Historizing are Mandatory Attributes of
// every Variable, and AccessLevelEx "is made mandatory in Profiles starting
// with version 1.04" (OPC 10000-3 §5.6.2, Table 13). A Variable made with
// NewVariableNode, or by code that builds the attribute map itself, need
// not store them; a Read of a Variable of a NodeNameSpace reports them all
// the same (variableAttribute), with the values the server applies to it.

// defaultVariableAccessLevel is the AccessLevel of a Variable that stores
// none: the server lets every client read and write its Value
// (Node.access, which grants what no AccessLevel restricts). The history
// bits are not set: the server does not keep the history of a Variable (a
// HistoryProvider of the application does), and the Status and Timestamp
// bits are not set because the server answers Bad_WriteNotSupported to a
// written StatusCode or timestamp of a Value it stores (Part 4 §5.11.4).
const defaultVariableAccessLevel = byte(ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite)

// servedAccessLevelExBits are the bits of AccessLevelExType above the
// AccessLevel (OPC 10000-3 §8.58, Table 42) a stored AccessLevelEx
// Attribute sets in the AccessLevelEx a Read reports:
//
//   - NonatomicRead and NonatomicWrite (bits 8 and 9), "0 means that
//     atomicity is assured". The Value a Variable stores is read and
//     replaced as one: a Write, also of an IndexRange, builds the new value
//     and swaps it in under the lock of the Node, and a Read gets the old or
//     the new value whole. A Value of a ValueFunc or a ValueWriter is the
//     application's, which sets the bits when it cannot ensure that;
//   - WriteFullArrayOnly (bit 10), "0 means Write of IndexRange is
//     supported": the Write service refuses an IndexRange on a Variable that
//     sets it (writeFullArrayOnly).
//
// NoSubDataTypes, NonVolatile and Constant (bits 11 to 13) state what the
// server does not do: refuse subtypes, persist the Value, change the
// ConfigurationVersion of the namespace with it. They read as 0 whatever
// is stored; the reserved bits 14 to 31 "Shall always be zero".
const servedAccessLevelExBits = uint32(ua.AccessLevelExTypeNonatomicRead | ua.AccessLevelExTypeNonatomicWrite | ua.AccessLevelExTypeWriteFullArrayOnly)

// variableAttribute returns the value a Read reports for an AccessLevel,
// UserAccessLevel, Historizing or AccessLevelEx Attribute of the Variable n,
// and false for any other Attribute or Node:
//
//   - AccessLevel: the stored one, else defaultVariableAccessLevel;
//   - UserAccessLevel: the stored one, else the AccessLevel, which alone
//     restricts the session then (Node.access): "If the OPC UA Server does
//     not have the ability to get any user access rights related
//     information from the underlying system then it should use the same
//     bit mask as used in the AccessLevel Attribute" (OPC 10000-3 §5.6.2);
//   - Historizing: the stored one, else false, "the Server is not actively
//     collecting data" (the Historizing default of §5.6.2 is FALSE);
//   - AccessLevelEx: "the 8 bits of the AccessLevel attribute as the first 8
//     bits" (§8.58), with servedAccessLevelExBits of the stored one.
func variableAttribute(n *Node, attr ua.AttributeID) (*ua.DataValue, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.NodeClass() != ua.NodeClassVariable {
		return nil, false
	}
	switch attr {
	case ua.AttributeIDAccessLevel:
		return DataValueFromValue(n.accessLevelLocked()), true
	case ua.AttributeIDUserAccessLevel:
		if dv := n.attr[ua.AttributeIDUserAccessLevel]; dv != nil {
			return dv, true
		}
		return DataValueFromValue(n.accessLevelLocked()), true
	case ua.AttributeIDHistorizing:
		if dv := n.attr[ua.AttributeIDHistorizing]; dv != nil {
			return dv, true
		}
		return DataValueFromValue(false), true
	case ua.AttributeIDAccessLevelEx:
		return DataValueFromValue(uint32(n.accessLevelLocked()) | n.accessLevelExLocked()&servedAccessLevelExBits), true
	default:
		return nil, false
	}
}

// accessLevelLocked returns the AccessLevel of a Variable: the stored Byte,
// 0 for a stored value of another type (Node.access then grants nothing),
// defaultVariableAccessLevel when there is none. Caller holds n.mu.
func (n *Node) accessLevelLocked() byte {
	dv := n.attr[ua.AttributeIDAccessLevel]
	if dv == nil {
		return defaultVariableAccessLevel
	}
	if dv.Value == nil {
		return 0
	}
	b, _ := dv.Value.Value().(byte)
	return b
}

// accessLevelExLocked returns the stored AccessLevelEx Attribute, 0 when
// there is none or it is not a UInt32. Caller holds n.mu.
func (n *Node) accessLevelExLocked() uint32 {
	dv := n.attr[ua.AttributeIDAccessLevelEx]
	if dv == nil || dv.Value == nil {
		return 0
	}
	v, _ := dv.Value.Value().(uint32)
	return v
}

// writeFullArrayOnly reports whether the Variable n sets the
// WriteFullArrayOnly bit of its AccessLevelEx: "Indicates if Write of
// IndexRange is supported" (OPC 10000-3 §8.58), and "A Server shall return
// a Bad_WriteNotSupported error if an indexRange is provided and writing of
// indexRange is not possible for the Node" (OPC 10000-4 §5.11.4.2).
func (n *Node) writeFullArrayOnly() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.accessLevelExLocked()&uint32(ua.AccessLevelExTypeWriteFullArrayOnly) != 0
}
