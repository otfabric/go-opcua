// SPDX-License-Identifier: MIT

package ua

import (
	"strings"

	"github.com/otfabric/go-opcua/id"
)

// browsePath splits a "/"-separated path of namespace 0 BrowseNames.
func browsePath(path string) []*QualifiedName {
	parts := strings.Split(path, "/")
	out := make([]*QualifiedName, len(parts))
	for i, p := range parts {
		out[i] = &QualifiedName{NamespaceIndex: 0, Name: p}
	}
	return out
}

// SelectPaths adds fields given as "/"-separated BrowsePaths, e.g.
// "AckedState/Id" for the Id of a condition's AckedState (Part 4 §7.7.4).
// A path without "/" is the same as [EventFilterBuilder.Select].
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
// FieldPath("ActiveState/Id").Equals(true).
func FieldPath(path string) *FieldOperand {
	return &FieldOperand{name: path, typeID: NewNumericNodeID(0, id.BaseEventType), path: true}
}
