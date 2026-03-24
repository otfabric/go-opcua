package ua

import (
	"github.com/otfabric/go-opcua/id"
)

// EventFilterBuilder provides a fluent API for constructing EventFilter objects.
//
// Example:
//
//	filter := ua.NewEventFilter().
//	    Select("EventType", "SourceName", "Message", "Severity", "Time").
//	    Where(ua.Field("Severity").GreaterThanOrEqual(uint16(500))).
//	    Build()
type EventFilterBuilder struct {
	selects []*SimpleAttributeOperand
	wheres  []*ContentFilterElement
	typeID  *NodeID
}

// NewEventFilter returns a new EventFilterBuilder with the default type
// definition set to BaseEventType (i=2041).
func NewEventFilter() *EventFilterBuilder {
	return &EventFilterBuilder{
		typeID: NewNumericNodeID(0, id.BaseEventType),
	}
}

// TypeDefinition sets the type definition node ID used for Select clauses.
// Defaults to BaseEventType (i=2041).
func (b *EventFilterBuilder) TypeDefinition(typeID *NodeID) *EventFilterBuilder {
	b.typeID = typeID
	return b
}

// Select adds fields to the SelectClauses of the event filter.
// Each name corresponds to a property browse name on the event type.
func (b *EventFilterBuilder) Select(names ...string) *EventFilterBuilder {
	for _, name := range names {
		b.selects = append(b.selects, &SimpleAttributeOperand{
			TypeDefinitionID: b.typeID,
			BrowsePath:       []*QualifiedName{{NamespaceIndex: 0, Name: name}},
			AttributeID:      AttributeIDValue,
		})
	}
	return b
}

// SelectOperand adds a custom SimpleAttributeOperand to the SelectClauses.
func (b *EventFilterBuilder) SelectOperand(op *SimpleAttributeOperand) *EventFilterBuilder {
	b.selects = append(b.selects, op)
	return b
}

// Where adds a filter condition to the WhereClause.
func (b *EventFilterBuilder) Where(cond *ContentFilterElement) *EventFilterBuilder {
	if cond != nil {
		b.wheres = append(b.wheres, cond)
	}
	return b
}

// Build constructs the final EventFilter.
func (b *EventFilterBuilder) Build() *EventFilter {
	f := &EventFilter{
		SelectClauses: b.selects,
	}
	if len(b.wheres) > 0 {
		f.WhereClause = &ContentFilter{Elements: b.wheres}
	} else {
		f.WhereClause = &ContentFilter{}
	}
	return f
}

// FieldOperand is a helper for constructing filter conditions on event fields.
type FieldOperand struct {
	name   string
	typeID *NodeID
}

// Field creates a FieldOperand for building WhereClause filter elements.
// The field name corresponds to a property browse name on BaseEventType.
func Field(name string) *FieldOperand {
	return &FieldOperand{
		name:   name,
		typeID: NewNumericNodeID(0, id.BaseEventType),
	}
}

// TypeDefinition sets a custom type definition for this field operand.
func (f *FieldOperand) TypeDefinition(typeID *NodeID) *FieldOperand {
	f.typeID = typeID
	return f
}

func (f *FieldOperand) toExtensionObject() *ExtensionObject {
	return &ExtensionObject{
		EncodingMask: ExtensionObjectBinary,
		TypeID: &ExpandedNodeID{
			NodeID: NewNumericNodeID(0, id.SimpleAttributeOperand_Encoding_DefaultBinary),
		},
		Value: SimpleAttributeOperand{
			TypeDefinitionID: f.typeID,
			BrowsePath:       []*QualifiedName{{NamespaceIndex: 0, Name: f.name}},
			AttributeID:      AttributeIDValue,
		},
	}
}

func literalOperand(value interface{}) *ExtensionObject {
	return &ExtensionObject{
		EncodingMask: ExtensionObjectBinary,
		TypeID: &ExpandedNodeID{
			NodeID: NewNumericNodeID(0, id.LiteralOperand_Encoding_DefaultBinary),
		},
		Value: LiteralOperand{
			Value: MustVariant(value),
		},
	}
}

func (f *FieldOperand) compare(op FilterOperator, value interface{}) *ContentFilterElement {
	return &ContentFilterElement{
		FilterOperator: op,
		FilterOperands: []*ExtensionObject{
			f.toExtensionObject(),
			literalOperand(value),
		},
	}
}

// Equals creates a filter element: field == value.
func (f *FieldOperand) Equals(value interface{}) *ContentFilterElement {
	return f.compare(FilterOperatorEquals, value)
}

// GreaterThan creates a filter element: field > value.
func (f *FieldOperand) GreaterThan(value interface{}) *ContentFilterElement {
	return f.compare(FilterOperatorGreaterThan, value)
}

// LessThan creates a filter element: field < value.
func (f *FieldOperand) LessThan(value interface{}) *ContentFilterElement {
	return f.compare(FilterOperatorLessThan, value)
}

// GreaterThanOrEqual creates a filter element: field >= value.
func (f *FieldOperand) GreaterThanOrEqual(value interface{}) *ContentFilterElement {
	return f.compare(FilterOperatorGreaterThanOrEqual, value)
}

// LessThanOrEqual creates a filter element: field <= value.
func (f *FieldOperand) LessThanOrEqual(value interface{}) *ContentFilterElement {
	return f.compare(FilterOperatorLessThanOrEqual, value)
}

// Like creates a filter element: field LIKE value.
func (f *FieldOperand) Like(value string) *ContentFilterElement {
	return f.compare(FilterOperatorLike, value)
}

// OfType creates a filter element: field OfType typeNodeID.
func OfType(typeNodeID *NodeID) *ContentFilterElement {
	return &ContentFilterElement{
		FilterOperator: FilterOperatorOfType,
		FilterOperands: []*ExtensionObject{
			literalOperand(typeNodeID),
		},
	}
}
