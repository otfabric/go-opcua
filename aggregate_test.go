package opcua

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
)

func TestAggregateType(t *testing.T) {
	tests := []struct {
		name   string
		wantID uint32
	}{
		{"Average", id.AggregateFunctionAverage},
		{"Minimum", id.AggregateFunctionMinimum},
		{"Maximum", id.AggregateFunctionMaximum},
		{"Count", id.AggregateFunctionCount},
		{"Total", id.AggregateFunctionTotal},
		{"Interpolative", id.AggregateFunctionInterpolative},
		{"Start", id.AggregateFunctionStart},
		{"End", id.AggregateFunctionEnd},
		{"Delta", id.AggregateFunctionDelta},
		{"Range", id.AggregateFunctionRange},
		{"PercentGood", id.AggregateFunctionPercentGood},
		{"PercentBad", id.AggregateFunctionPercentBad},
		{"DurationGood", id.AggregateFunctionDurationGood},
		{"DurationBad", id.AggregateFunctionDurationBad},
		{"WorstQuality", id.AggregateFunctionWorstQuality},
		{"TimeAverage", id.AggregateFunctionTimeAverage},
		{"AnnotationCount", id.AggregateFunctionAnnotationCount},
		{"MinimumActualTime", id.AggregateFunctionMinimumActualTime},
		{"MaximumActualTime", id.AggregateFunctionMaximumActualTime},
		{"NumberOfTransitions", id.AggregateFunctionNumberOfTransitions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nid := AggregateType(tt.name)
			if nid == nil {
				t.Fatalf("AggregateType(%q) returned nil", tt.name)
			}
			if nid.IntID() != tt.wantID {
				t.Errorf("got %d, want %d", nid.IntID(), tt.wantID)
			}
		})
	}
}

func TestAggregateTypeCaseInsensitive(t *testing.T) {
	tests := []string{"average", "AVERAGE", "Average", "aVeRaGe"}
	for _, name := range tests {
		nid := AggregateType(name)
		if nid == nil {
			t.Fatalf("AggregateType(%q) returned nil", name)
		}
		if nid.IntID() != id.AggregateFunctionAverage {
			t.Errorf("AggregateType(%q): got %d, want %d", name, nid.IntID(), id.AggregateFunctionAverage)
		}
	}
}

func TestAggregateTypeUnknown(t *testing.T) {
	nid := AggregateType("NonExistent")
	if nid != nil {
		t.Errorf("AggregateType(NonExistent) should return nil, got %v", nid)
	}
}
