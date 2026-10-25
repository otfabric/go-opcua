// SPDX-License-Identifier: MIT

package ua

import (
	"strconv"
	"strings"

	"github.com/otfabric/go-opcua/id"
)

// browsePath splits a "/"-separated BrowsePath into its BrowseNames. A
// segment "<index>:<name>" (e.g. "2:Temperature") is a BrowseName of
// namespace <index>, as QualifiedNames are written elsewhere (Part 6
// §5.4.2.14); any other segment is a BrowseName of namespace 0. A name of
// namespace 0 that itself starts with "<digits>:" is written "0:<name>".
func browsePath(path string) []*QualifiedName {
	parts := strings.Split(path, "/")
	out := make([]*QualifiedName, len(parts))
	for i, p := range parts {
		out[i] = browseName(p)
	}
	return out
}

// browseName parses one segment of a BrowsePath.
func browseName(s string) *QualifiedName {
	if i := strings.IndexByte(s, ':'); i > 0 {
		if n, err := strconv.ParseUint(s[:i], 10, 16); err == nil {
			return &QualifiedName{NamespaceIndex: uint16(n), Name: s[i+1:]}
		}
	}
	return &QualifiedName{NamespaceIndex: 0, Name: s}
}

// SelectPaths adds fields given as "/"-separated BrowsePaths, e.g.
// "AckedState/Id" for the Id of a condition's AckedState (Part 4 §7.7.4).
// A segment "<index>:<name>" names a BrowseName of another namespace, e.g.
// "2:Temperature" or "2:Pump/2:Speed"; other segments are namespace 0
// BrowseNames. A plain name without "/" is the same as
// [EventFilterBuilder.Select].
func (b *EventFilterBuilder) SelectPaths(paths ...string) *EventFilterBuilder {
	for _, p := range paths {
		b.selects = append(b.selects, &SimpleAttributeOperand{
			TypeDefinitionID: b.typeID,
			BrowsePath:       browsePath(p),
			AttributeID:      AttributeIDValue,
		})
	}
	return b
}

// SelectConditionID adds the ConditionId of condition events: the NodeId of
// the condition, selected with an empty BrowsePath and AttributeId NodeId on
// ConditionType (Part 9 §5.5.2).
func (b *EventFilterBuilder) SelectConditionID() *EventFilterBuilder {
	b.selects = append(b.selects, &SimpleAttributeOperand{
		TypeDefinitionID: NewNumericNodeID(0, id.ConditionType),
		BrowsePath:       []*QualifiedName{},
		AttributeID:      AttributeIDNodeID,
	})
	return b
}

// FieldPath creates a FieldOperand for a "/"-separated BrowsePath, e.g.
// FieldPath("ActiveState/Id").Equals(true). Segments are parsed as in
// [EventFilterBuilder.SelectPaths]: "2:Temperature" is a BrowseName of
// namespace 2.
func FieldPath(path string) *FieldOperand {
	return &FieldOperand{name: path, typeID: NewNumericNodeID(0, id.BaseEventType), path: true}
}
