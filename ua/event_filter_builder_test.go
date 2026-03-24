package ua

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
)

func TestEventFilterBuilder(t *testing.T) {
	t.Run("basic select", func(t *testing.T) {
		filter := NewEventFilter().
			Select("EventType", "SourceName", "Message").
			Build()

		if got := len(filter.SelectClauses); got != 3 {
			t.Fatalf("SelectClauses: got %d, want 3", got)
		}
		for i, name := range []string{"EventType", "SourceName", "Message"} {
			sc := filter.SelectClauses[i]
			if len(sc.BrowsePath) != 1 || sc.BrowsePath[0].Name != name {
				t.Errorf("SelectClause[%d]: got %q, want %q", i, sc.BrowsePath[0].Name, name)
			}
			if sc.AttributeID != AttributeIDValue {
				t.Errorf("SelectClause[%d].AttributeID: got %d, want %d", i, sc.AttributeID, AttributeIDValue)
			}
			if sc.TypeDefinitionID.IntID() != id.BaseEventType {
				t.Errorf("SelectClause[%d].TypeDefinitionID: got %d, want %d", i, sc.TypeDefinitionID.IntID(), id.BaseEventType)
			}
		}
		if filter.WhereClause == nil {
			t.Fatal("WhereClause should not be nil")
		}
		if len(filter.WhereClause.Elements) != 0 {
			t.Errorf("WhereClause.Elements: got %d, want 0", len(filter.WhereClause.Elements))
		}
	})

	t.Run("custom type definition", func(t *testing.T) {
		customType := NewNumericNodeID(0, 12345)
		filter := NewEventFilter().
			TypeDefinition(customType).
			Select("Property1").
			Build()

		sc := filter.SelectClauses[0]
		if sc.TypeDefinitionID.IntID() != 12345 {
			t.Errorf("TypeDefinitionID: got %d, want 12345", sc.TypeDefinitionID.IntID())
		}
	})

	t.Run("select with where", func(t *testing.T) {
		filter := NewEventFilter().
			Select("Severity").
			Where(Field("Severity").GreaterThanOrEqual(uint16(500))).
			Build()

		if len(filter.SelectClauses) != 1 {
			t.Fatalf("SelectClauses: got %d, want 1", len(filter.SelectClauses))
		}
		if len(filter.WhereClause.Elements) != 1 {
			t.Fatalf("WhereClause.Elements: got %d, want 1", len(filter.WhereClause.Elements))
		}
		elem := filter.WhereClause.Elements[0]
		if elem.FilterOperator != FilterOperatorGreaterThanOrEqual {
			t.Errorf("FilterOperator: got %d, want %d", elem.FilterOperator, FilterOperatorGreaterThanOrEqual)
		}
		if len(elem.FilterOperands) != 2 {
			t.Fatalf("FilterOperands: got %d, want 2", len(elem.FilterOperands))
		}
	})

	t.Run("multiple where clauses", func(t *testing.T) {
		filter := NewEventFilter().
			Select("Severity", "Message").
			Where(Field("Severity").GreaterThan(uint16(100))).
			Where(Field("Severity").LessThan(uint16(900))).
			Build()

		if len(filter.WhereClause.Elements) != 2 {
			t.Fatalf("WhereClause.Elements: got %d, want 2", len(filter.WhereClause.Elements))
		}
		if filter.WhereClause.Elements[0].FilterOperator != FilterOperatorGreaterThan {
			t.Error("first where should be GreaterThan")
		}
		if filter.WhereClause.Elements[1].FilterOperator != FilterOperatorLessThan {
			t.Error("second where should be LessThan")
		}
	})

	t.Run("nil where is skipped", func(t *testing.T) {
		filter := NewEventFilter().
			Select("EventType").
			Where(nil).
			Build()

		if len(filter.WhereClause.Elements) != 0 {
			t.Errorf("nil Where should be skipped, got %d elements", len(filter.WhereClause.Elements))
		}
	})

	t.Run("select operand", func(t *testing.T) {
		op := &SimpleAttributeOperand{
			TypeDefinitionID: NewNumericNodeID(0, 999),
			BrowsePath:       []*QualifiedName{{NamespaceIndex: 0, Name: "Custom"}},
			AttributeID:      AttributeIDNodeID,
		}
		filter := NewEventFilter().
			SelectOperand(op).
			Build()

		if len(filter.SelectClauses) != 1 {
			t.Fatalf("SelectClauses: got %d, want 1", len(filter.SelectClauses))
		}
		if filter.SelectClauses[0].AttributeID != AttributeIDNodeID {
			t.Error("custom operand should preserve AttributeID")
		}
	})
}

func TestFieldOperand(t *testing.T) {
	t.Run("equals", func(t *testing.T) {
		elem := Field("SourceName").Equals("Server")
		if elem.FilterOperator != FilterOperatorEquals {
			t.Errorf("got %d, want %d", elem.FilterOperator, FilterOperatorEquals)
		}
	})

	t.Run("greater than", func(t *testing.T) {
		elem := Field("Severity").GreaterThan(uint16(100))
		if elem.FilterOperator != FilterOperatorGreaterThan {
			t.Errorf("got %d, want %d", elem.FilterOperator, FilterOperatorGreaterThan)
		}
	})

	t.Run("less than", func(t *testing.T) {
		elem := Field("Severity").LessThan(uint16(900))
		if elem.FilterOperator != FilterOperatorLessThan {
			t.Errorf("got %d, want %d", elem.FilterOperator, FilterOperatorLessThan)
		}
	})

	t.Run("less than or equal", func(t *testing.T) {
		elem := Field("Severity").LessThanOrEqual(uint16(500))
		if elem.FilterOperator != FilterOperatorLessThanOrEqual {
			t.Errorf("got %d, want %d", elem.FilterOperator, FilterOperatorLessThanOrEqual)
		}
	})

	t.Run("like", func(t *testing.T) {
		elem := Field("SourceName").Like("Server*")
		if elem.FilterOperator != FilterOperatorLike {
			t.Errorf("got %d, want %d", elem.FilterOperator, FilterOperatorLike)
		}
	})

	t.Run("custom type definition", func(t *testing.T) {
		customType := NewNumericNodeID(0, 12345)
		elem := Field("Prop").TypeDefinition(customType).Equals("val")
		eo := elem.FilterOperands[0]
		sao, ok := eo.Value.(SimpleAttributeOperand)
		if !ok {
			t.Fatalf("expected SimpleAttributeOperand, got %T", eo.Value)
		}
		if sao.TypeDefinitionID.IntID() != 12345 {
			t.Errorf("TypeDefinitionID: got %d, want 12345", sao.TypeDefinitionID.IntID())
		}
	})
}

func TestOfType(t *testing.T) {
	typeID := NewNumericNodeID(0, 1000)
	elem := OfType(typeID)
	if elem.FilterOperator != FilterOperatorOfType {
		t.Errorf("got %d, want %d", elem.FilterOperator, FilterOperatorOfType)
	}
	if len(elem.FilterOperands) != 1 {
		t.Fatalf("FilterOperands: got %d, want 1", len(elem.FilterOperands))
	}
}
